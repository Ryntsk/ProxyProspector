package executive

// Package executive implements an aggressive proxy scoring engine
// for selecting the best-performing MTProto proxies.
//
// It reads pre-measured proxy statistics from JSON, applies
// a sophisticated scoring algorithm focused on real-world latency
// stability and DPI resistance, ranks the proxies, and outputs
// the top results both to console and clipboard (Windows only).
import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// scorerInput is the path to the input file with raw scored proxies.
	scorerInput = "json/scored.json"
	// outputTop is the path where the fully ranked proxy list is saved.
	outputTop = "json/top_proxies.json"

	// topN defines how many best proxies are shown in the console
	// and copied to the clipboard.
	topN = 10
)

//
// Score helpers
//

// clamp restricts a value to the range [0, 100].
func clamp(v float64) float64 {
	return math.Max(0, math.Min(100, v))
}

// applySecretModifier applies a multiplier based on the proxy secret type.
//
//   ee     — FakeTLS (best DPI resistance) → +15%
//   plain  — no obfuscation (easiest to block) → −15%
//   others — neutral
func applySecretModifier(score float64, secretType string) float64 {
	switch secretType {
	case "ee":
		return score * 1.15
	case "plain":
		return score * 0.85
	default:
		return score
	}
}

// applyThrottlePenalty penalizes proxies affected by DPI throttling.
//
// throttleRate is the fraction of pings that were delayed.
// The penalty is linear: 0.0 → ×1.00, 0.5 → ×0.50, 1.0 → ×0.00.
func applyThrottlePenalty(score float64, throttleRate float64) float64 {
	if throttleRate <= 0 {
		return score
	}

	tr := math.Min(1.0, throttleRate)
	return score * (1.0 - tr)
}

// scoreProxy calculates GeneralScore for a single proxy using
// an aggressive strategy optimized for production use.
//
// Design goals:
//   • Strong differentiation between high-quality proxies
//   • Smooth latency penalties (no hard cutoffs)
//   • Heavy focus on tail latency (P95) stability
//   • CV already captures jitter → no redundant jitter term
//
// Key differences from classic scoring:
//   • Exponential decay for P95 latency
//   • Increased weight on coefficient of variation (CV)
//   • Quadratic penalty on SuccessRate (sr²)
//   • Drift and throttle modifiers
func scoreProxy(sp *ScoredProxy) {
	// Basic validation
	if sp.MedianRTT <= 0 {
		sp.GeneralScore = 0
		return
	}

	sr := normalizeSR(sp.SuccessRate)
	if sr <= 0 {
		sp.GeneralScore = 0
		return
	}

	// Hard latency limits (anything beyond these is unusable)
	if sp.MedianRTT > 400 {
		sp.GeneralScore = 0
		return
	}
	if sp.P95 > 600 {
		sp.GeneralScore = 0
		return
	}

	// Component scores
	rttScore := clamp(100 - sp.MedianRTT/4.0)                    // median latency
	p95Score := clamp(100 * math.Exp(-sp.P95/180.0))            // exponential tail-latency decay
	cvScore := clamp(100 - sp.CV*120.0)                          // stability (lower CV = better)

	// Weighted base score
	base := rttScore*0.15 + p95Score*0.50 + cvScore*0.35

	// Drift penalty: if latency increased during the test, reduce confidence
	if !sp.SustainedStable {
		base *= 0.60
	}

	// Reliability penalty: quadratic SuccessRate strongly punishes flaky proxies
	score := base * sr * sr

	// Network-level modifiers
	score = applySecretModifier(score, sp.SecretType)
	score = applyThrottlePenalty(score, sp.ThrottleRate)

	sp.GeneralScore = math.Round(clamp(score)*10) / 10
}

//
// Utilities
//

// normalizeSR converts SuccessRate to a fraction in [0, 1].
// Accepts both raw fractions (0.95) and percentages (95).
func normalizeSR(sr float64) float64 {
	if sr <= 0 {
		return -1
	}

	// Accept percentage input
	if sr > 1 {
		sr /= 100.0
	}
	if sr > 1 {
		sr = 1
	}

	return sr
}

// TGLink returns a Telegram MTProto deep link for this proxy.
func (sp ScoredProxy) TGLink() string {
	return fmt.Sprintf(
		"tg://proxy?server=%s&port=%s&secret=%s",
		sp.Server,
		sp.Port,
		sp.Secret,
	)
}

//
// Output helpers
//

// printTopN prints the top N proxies to stdout with colored
// diagnostics for unstable or throttled entries.
func printTopN(proxies []ScoredProxy) {
	sep := strings.Repeat("═", 72)

	fmt.Printf(
		"\n%s\n   TOP-%d PROXIES\n%s\n",
		sep,
		topN,
		sep,
	)

	for i := 0; i < topN && i < len(proxies); i++ {
		sp := proxies[i]

		fmt.Printf("#%-2d  %s\n", i+1, sp.TGLink())

		stableFlag := ""
		if !sp.SustainedStable {
			stableFlag = Yellow + " 📈drift" + Reset
		}

		throttleStr := ""
		if sp.ThrottleRate > 0.05 {
			throttleStr = fmt.Sprintf(
				"  \033[31mthrottle=%.0f%%%s",
				sp.ThrottleRate*100,
				Reset,
			)
		}

		fmt.Printf(
			"    score=%-5.1f  rtt=%.0fms  cv=%.2f  p95=%.0fms%s%s\n",
			sp.GeneralScore,
			sp.MedianRTT,
			sp.CV,
			sp.P95,
			stableFlag,
			throttleStr,
		)
	}
}

// buildPlainText generates a plain-text list of the top proxies
// (with Russian timestamp for the target audience) suitable for clipboard.
func buildPlainText(list []ScoredProxy) string {
	var b strings.Builder

	now := time.Now().Format("02.01.2006 15:04:05")

	b.WriteString(fmt.Sprintf("Проверены %s\n\n", now))

	for i := 0; i < topN && i < len(list); i++ {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, list[i].TGLink()))
	}

	return b.String()
}

// copyToClipboard copies text to the Windows clipboard.
// Does nothing on other operating systems.
func copyToClipboard(text string) {
	if runtime.GOOS != "windows" {
		return
	}

	cmd := exec.Command("cmd.exe", "/c", "clip")
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}

//
// Main entry point
//

// RunScorer is the main function of the scoring pipeline.
// It loads proxies, scores them, sorts, saves JSON, prints results,
// and copies the top list to the clipboard.
func RunScorer() {
	raw, err := os.ReadFile(scorerInput)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}

	var proxies []ScoredProxy
	if err := json.Unmarshal(raw, &proxies); err != nil {
		fmt.Printf("JSON error: %v\n", err)
		return
	}

	if len(proxies) == 0 {
		fmt.Println("No proxies found.")
		return
	}

	fmt.Printf(
		"%sLoaded %d proxies. Running scoring...%s\n",
		Cyan,
		len(proxies),
		Reset,
	)

	// Score every proxy
	for i := range proxies {
		scoreProxy(&proxies[i])
	}

	// Sort descending by GeneralScore
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].GeneralScore > proxies[j].GeneralScore
	})

	// Save full ranked list
	data, _ := json.MarshalIndent(proxies, "", "  ")
	WriteJSONAtomic(outputTop, data)

	printTopN(proxies)
	copyToClipboard(buildPlainText(proxies))

	fmt.Printf("\n%sScoring complete.%s\n", Green, Reset)
}