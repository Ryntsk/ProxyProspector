package executive

// Package executive implements a comprehensive MTProto proxy analyzer.
//
// It performs deep RTT profiling on alive proxies (from alive.json):
//   • Exactly 30 TCP pings per proxy with adaptive inter-ping gaps
//   • Detailed latency statistics: Median, Avg, Min, Max, P95, P99, Jitter, CV
//   • DPI throttling detection (ThrottleRate)
//   • Linear degradation detection (SustainedStable flag)
//   • Secret type classification (plain / dd / ee)
//
// No final scoring is done here — the output (scored.json) is consumed
// by scorer.go for aggressive ranking.
//
// All network operations respect context cancellation and use strict
// concurrency limits to avoid overwhelming any single host.
import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Reset  = "\033[0m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"

	// maxPings is the fixed number of ping attempts per proxy.
	// SuccessRate is always calculated against this base (Fix A).
	maxPings = 30
)

//
// Reusable resources
//

var dialer = &net.Dialer{
	Timeout:   5 * time.Second,
	KeepAlive: 30 * time.Second,
	DualStack: true,
}

//
// Math helpers
//

// mean returns the arithmetic mean of a slice of float64 values.
func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

// stdev returns the population standard deviation.
func stdev(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	m := mean(v)
	sum := 0.0
	for _, x := range v {
		d := x - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(v)))
}

// sortedCopy returns a sorted copy of the input slice.
func sortedCopy(v []float64) []float64 {
	c := make([]float64, len(v))
	copy(c, v)
	sort.Float64s(c)
	return c
}

// median returns the median value of a pre-sorted slice.
func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

//
// Secret classification
//

// classifySecret determines the MTProto secret type based on its prefix.
func classifySecret(secret string) string {
	s := strings.ToLower(strings.TrimSpace(secret))
	switch {
	case strings.HasPrefix(s, "ee"):
		return "ee"
	case strings.HasPrefix(s, "dd"):
		return "dd"
	default:
		return "plain"
	}
}

//
// Stability detection
//

// isSustainedStable returns true if the RTT series does not show
// significant linear degradation (proxy is stable under load).
func isSustainedStable(rtts []float64) bool {
	n := len(rtts)
	if n < 4 {
		return true
	}

	var sumX, sumY, sumXY, sumX2 float64
	for i, y := range rtts {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}
	fn := float64(n)
	denom := fn*sumX2 - sumX*sumX
	if denom == 0 {
		return true
	}
	slope := (fn*sumXY - sumX*sumY) / denom

	avg := sumY / fn
	if avg <= 0 {
		return true
	}

	normalizedSlope := slope / avg
	return normalizedSlope < 0.01
}

//
// RTT splitting (DPI throttling detection)
//

// splitRTTs separates successful RTT measurements into "fast" (normal)
// and "throttled" (DPI-slow) buckets.
//
// Threshold = max(300ms, min(2000ms, median×8)).
// Only fastRTTs are used for P95, Jitter, CV and stability calculations.
// ThrottleRate shows the fraction of DPI-delayed pings.
func splitRTTs(rtts []float64) (fastRTTs []float64, throttled int) {
	if len(rtts) == 0 {
		return nil, 0
	}

	sorted := sortedCopy(rtts)
	med := median(sorted)

	thresh := math.Max(300, math.Min(2000, med*8))

	for _, r := range rtts {
		if r <= thresh {
			fastRTTs = append(fastRTTs, r)
		} else {
			throttled++
		}
	}
	return fastRTTs, throttled
}

//
// TCP ping helpers
//

// tcpPing performs a single TCP connection attempt with context support
// and dial semaphore limiting.
func tcpPing(ctx context.Context, addr string, timeout time.Duration, dialSem chan struct{}) (float64, bool) {
	select {
	case dialSem <- struct{}{}:
	case <-ctx.Done():
		return 0, false
	}
	defer func() { <-dialSem }()

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t0 := time.Now()
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	conn.Close()

	return float64(time.Since(t0).Microseconds()) / 1000.0, true
}

//
// Ping series
//

// pingResult holds the outcome of a full ping series.
type pingResult struct {
	rtts       []float64 // all successful RTTs (including DPI-slow)
	earlyAbort bool      // stopped due to 3 consecutive timeouts
}

// pingSeriesRTTs executes exactly maxPings-1 additional TCP pings
// (seed RTT is provided from Level 2). Gap adapts to current median RTT.
// Early abort on 3 consecutive timeouts or very high latency.
func pingSeriesRTTs(
	ctx context.Context,
	addr string,
	timeout time.Duration,
	seedRTT float64,
	dialSem chan struct{},
) pingResult {

	res := pingResult{}
	rtts := make([]float64, 0, maxPings)

	// Adaptive gap based on seed RTT from Level 2
	gap := 100 * time.Millisecond
	if seedRTT > 50 {
		rawGap := time.Duration(math.Max(50, math.Min(200, seedRTT*1.2)))
		gap = rawGap * time.Millisecond
	}

	consecutiveTimeouts := 0

	// Fixed loop — SuccessRate is always relative to maxPings (Fix A)
	for i := 0; i < maxPings-1; i++ {
		select {
		case <-time.After(gap):
		case <-ctx.Done():
			res.rtts = rtts
			return res
		}

		rtt, ok := tcpPing(ctx, addr, timeout, dialSem)

		if ok {
			rtts = append(rtts, rtt)
			consecutiveTimeouts = 0

			if len(rtts) >= 3 {
				med := median(sortedCopy(rtts))
				rawGap := time.Duration(math.Max(50, math.Min(200, med*1.2)))
				gap = rawGap * time.Millisecond
			}
		} else {
			consecutiveTimeouts++
		}

		if consecutiveTimeouts >= 3 {
			res.earlyAbort = true
			break
		}

		// Early stop for obviously dead proxies
		if len(rtts) == 5 && median(sortedCopy(rtts)) > 1500 {
			break
		}
	}

	res.rtts = rtts
	return res
}

//
// Core measurement
//

// measureProxy performs a full RTT profiling session for a single proxy
// and returns a fully populated ScoredProxy (ready for scoring).
func measureProxy(
	ctx context.Context,
	p InProxy,
	timeout time.Duration,
	dialSem chan struct{},
) ScoredProxy {

	sp := ScoredProxy{
		Server:     p.Server,
		Port:       p.Port,
		Secret:     p.Secret,
		MeasuredAt: time.Now(),
		SecretType: classifySecret(p.Secret),
	}

	addr := net.JoinHostPort(p.Server, p.Port)

	res := pingSeriesRTTs(ctx, addr, timeout, p.TCPLatencyMs, dialSem)
	allRTTs := res.rtts

	// SuccessRate is always relative to the fixed maxPings base (Fix A)
	sp.SuccessRate = float64(len(allRTTs)) / float64(maxPings)

	if len(allRTTs) > 0 {
		// Split normal vs DPI-throttled RTTs (Fix B)
		fastRTTs, throttled := splitRTTs(allRTTs)

		if len(allRTTs) > 0 {
			sp.ThrottleRate = float64(throttled) / float64(len(allRTTs))
		}

		// Use fastRTTs for all quality metrics; fallback to allRTTs if everything was throttled
		computeOn := fastRTTs
		if len(computeOn) == 0 {
			computeOn = allRTTs
		}

		sorted := sortedCopy(computeOn)

		sp.MedianRTT = median(sorted)
		sp.AvgRTT = mean(computeOn)
		sp.MinRTT = sorted[0]
		sp.MaxRTT = sorted[len(sorted)-1]
		sp.P95 = PercentileFloat(sorted, 95)
		sp.P99 = PercentileFloat(sorted, 99)
		sp.Jitter = stdev(computeOn)

		if sp.AvgRTT > 0 {
			sp.CV = sp.Jitter / sp.AvgRTT
		}

		// Stability check also uses cleaned RTTs
		sp.SustainedStable = isSustainedStable(computeOn)
		if res.earlyAbort {
			sp.SustainedStable = false
		}
	}

	return sp
}

//
// Main entry point
//

// RunAnalyzer runs the deep RTT profiling pipeline on all alive proxies.
// It produces scored.json with full latency statistics for the scorer.
func RunAnalyzer() {
	input := "json/alive.json"
	output := "json/scored.json"

	workers := int(math.Min(float64(runtime.NumCPU()*5), 128))
	maxDials := int(math.Min(float64(runtime.NumCPU()*4), 80))
	timeout := 5 * time.Second

	start := time.Now()

	raw, err := os.ReadFile(input)
	if err != nil {
		fmt.Printf("Ошибка чтения файла: %v\n", err)
		return
	}

	var proxies []InProxy
	if err := json.Unmarshal(raw, &proxies); err != nil {
		fmt.Printf("Ошибка разбора JSON: %v\n", err)
		return
	}

	if len(proxies) == 0 {
		fmt.Println("Список пуст.")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Heartbeat spinner until first result arrives
	hbCtx, hbCancel := context.WithCancel(ctx)
	go func() {
		spinner := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
		i := 0
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				fmt.Printf("\r%s %c Initializing workers...%s\033[K", Cyan, spinner[i%len(spinner)], Reset)
				i++
			}
		}
	}()



	// Worker pool
	dialSem := make(chan struct{}, maxDials)
	jobs := make(chan InProxy)
	results := make(chan ScoredProxy)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				results <- measureProxy(ctx, p, timeout, dialSem)
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, p := range proxies {
			select {
			case <-ctx.Done():
				goto closed
			case jobs <- p:
			}
		}
	closed:
		close(jobs)
	}()

	// Close results channel when all workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display live progress
	var out []ScoredProxy
	total := len(proxies)
	var completed, success, stable int

	sampleSize := 8
	var sampleTimes []float64
	var muSample sync.Mutex
	updateInterval := 300 * time.Millisecond
	lastUpdate := time.Now().Add(-updateInterval)

	fmt.Printf("%sDeep RTT profiling: %d workers, %d pings/proxy...%s\n\n", Cyan, workers, maxPings, Reset)

	for r := range results {
		if completed == 0 {
			hbCancel()
		}

		out = append(out, r)
		completed++

		if r.MedianRTT > 0 {
			success++
		}
		if r.SustainedStable {
			stable++
		}

		elapsed := time.Since(start).Seconds()
		per := elapsed / float64(completed)

		muSample.Lock()
		if len(sampleTimes) < sampleSize {
			sampleTimes = append(sampleTimes, per)
		}
		perEstimate := per
		if len(sampleTimes) > 0 {
			perEstimate = median(sortedCopy(sampleTimes))
		}
		muSample.Unlock()

		remaining := float64(total-completed) * perEstimate
		eta := (time.Duration(remaining) * time.Second).Round(time.Second).String()

		if time.Since(lastUpdate) >= updateInterval || completed == total {
			lastUpdate = time.Now()

			pct := float64(completed) / float64(total) * 100
			barLen := 32
			doneLen := int(float64(barLen) * (float64(completed) / float64(total)))
			bar := strings.Repeat("█", doneLen) + strings.Repeat("░", barLen-doneLen)

			fmt.Printf("\r\033[K %s[%s]%s %3.0f%% | %d/%d | %sOK:%d%s %sStb:%d%s | ETA: %s | %s:%s",
				Blue, bar, Reset, pct, completed, total,
				Green, success, Reset,
				Cyan, stable, Reset,
				eta, r.Server, r.Port)
		}
	}

	fmt.Printf("\r\033[K\n\n")
	fmt.Printf("%s  └── Analysis complete. Measured: %d | Responsive: %d | Sustained-stable: %d%s\n",
		Green, completed, success, stable, Reset)

	data, _ := json.MarshalIndent(out, "", "  ")
	WriteJSONAtomic(output, data)
}