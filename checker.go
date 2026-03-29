package executive

// Package executive implements a high-performance, two-stage MTProto proxy checker.
//
// It validates proxies in two levels:
//
//   Level 1 (fast filter)
//     • DNS resolution check
//     • Single TCP connection test
//     • Extremely high concurrency with per-host limiting
//
//   Level 2 (stability test)
//     • Multiple TCP connection attempts with exponential backoff
//     • Success rate and median latency analysis
//     • Rejects unstable or high-latency proxies
//
// All rejected proxies are saved with a detailed reason and error description.
// The final alive list is written to alive.json and is ready for the scoring stage.
import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type RejectedOut struct {
	Proxy  Proxy  `json:"proxy"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

const progressStep = 25

//
// Progress reporting
//

// printProgress shows current checking statistics on one line (live progress bar).
func printProgress(done, total, alive, dead int) {
	fmt.Printf(
		"\rChecked %d/%d | alive: %d | dead: %d",
		done,
		total,
		alive,
		dead,
	)
}

// maybePrintProgress prints progress only every `progressStep` items
// or when the check is complete to avoid flooding the terminal.
func maybePrintProgress(done, total, alive, dead int) {
	if done%progressStep == 0 || done == total {
		printProgress(done, total, alive, dead)
	}
}

//
// Level 1: DNS + TCP connectivity (fast filter)
//

// runLevel1 performs the first quick validation pass.
// It checks DNS resolution and a single TCP connection for each proxy.
// High global concurrency + per-host semaphore prevents overwhelming any single server.
func runLevel1(
	in []Proxy,
	dnsTimeout time.Duration,
	tcpTimeout time.Duration,
	globalConcurrency int,
	perHostLimit int,
	resolver Resolver,
	dialer Dialer,
) (passed []Proxy, rejected []RejectedOut, metrics LevelMetrics) {

	var done int

	if resolver == nil {
		resolver = NewDefaultResolver()
	}
	if dialer == nil {
		dialer = &defaultDialer{timeout: tcpTimeout}
	}

	metrics.Errors = make(map[string]int)
	metrics.Total = len(in)

	sem := make(chan struct{}, globalConcurrency)

	var hostMu sync.Mutex
	hostSems := make(map[string]chan struct{})

	getHostSem := func(host string) chan struct{} {
		hostMu.Lock()
		defer hostMu.Unlock()

		if _, ok := hostSems[host]; !ok {
			hostSems[host] = make(chan struct{}, perHostLimit)
		}
		return hostSems[host]
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range in {
		wg.Add(1)

		go func(px Proxy) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(px.Server, px.Port)

			// DNS resolution
			dnsStart := time.Now()
			dnsCtx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
			_, dnsErr := resolver.LookupHost(dnsCtx, px.Server)
			cancel()

			dnsMs := time.Since(dnsStart).Milliseconds()

			if dnsErr != nil {
				reason := "dns_fail"

				mu.Lock()
				rejected = append(rejected, RejectedOut{
					Proxy:  px,
					Reason: reason,
					Detail: dnsErr.Error(),
				})

				metrics.DNSLatencies = append(metrics.DNSLatencies, dnsMs)
				metrics.Errors[reason]++
				metrics.Rejected++
				done++

				maybePrintProgress(done, metrics.Total, metrics.Passed, metrics.Rejected)
				mu.Unlock()
				return
			}

			mu.Lock()
			metrics.DNSLatencies = append(metrics.DNSLatencies, dnsMs)
			mu.Unlock()

			// TCP connection (single attempt)
			hostSem := getHostSem(px.Server)
			hostSem <- struct{}{}
			defer func() { <-hostSem }()

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), tcpTimeout)
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			cancel()

			tcpMs := time.Since(start).Milliseconds()

			if err != nil {
				reason := classifyTCPErr(err)

				mu.Lock()
				rejected = append(rejected, RejectedOut{
					Proxy:  px,
					Reason: reason,
					Detail: err.Error(),
				})

				metrics.TCPLatencies = append(metrics.TCPLatencies, tcpMs)
				metrics.Errors[reason]++
				metrics.Rejected++
				done++

				maybePrintProgress(done, metrics.Total, metrics.Passed, metrics.Rejected)
				mu.Unlock()
				return
			}

			conn.Close()

			mu.Lock()
			passed = append(passed, px)
			metrics.TCPLatencies = append(metrics.TCPLatencies, tcpMs)
			metrics.Passed++
			done++

			maybePrintProgress(done, metrics.Total, metrics.Passed, metrics.Rejected)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	fmt.Println()

	return
}

//
// Level 2: Stability & latency quality check
//

// runLevel2 performs the second, more thorough stability test.
// Each proxy is tested with multiple connection attempts using exponential backoff.
// It evaluates success rate and median latency to filter out flaky or slow proxies.
func runLevel2(
	in []Proxy,
	attempts int,
	timeout time.Duration,
	backoffBase time.Duration,
	medianThreshold time.Duration,
	globalConcurrency int,
	perHostLimit int,
	dialer Dialer,
) (passed []Proxy, rejected []RejectedOut, metrics LevelMetrics) {

	var done int

	if dialer == nil {
		dialer = &defaultDialer{timeout: timeout}
	}

	metrics.Errors = make(map[string]int)
	metrics.Total = len(in)

	sem := make(chan struct{}, globalConcurrency)

	var hostMu sync.Mutex
	hostSems := make(map[string]chan struct{})

	getHostSem := func(host string) chan struct{} {
		hostMu.Lock()
		defer hostMu.Unlock()

		if _, ok := hostSems[host]; !ok {
			hostSems[host] = make(chan struct{}, perHostLimit)
		}
		return hostSems[host]
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range in {
		wg.Add(1)

		go func(px Proxy) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			hostSem := getHostSem(px.Server)
			hostSem <- struct{}{}
			defer func() { <-hostSem }()

			addr := net.JoinHostPort(px.Server, px.Port)

			var latencies []int64
			successCount := 0

			for i := 0; i < attempts; i++ {
				if i > 0 {
					// Exponential backoff: 1×, 2×, 4×, 8× …
					time.Sleep(backoffBase * time.Duration(1<<uint(i-1)))
				}

				start := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				cancel()

				elapsed := time.Since(start).Milliseconds()

				if err != nil {
					mu.Lock()
					metrics.Errors[classifyTCPErr(err)]++
					mu.Unlock()
					continue
				}

				conn.Close()
				latencies = append(latencies, elapsed)
				successCount++
			}

			successRate := float64(successCount) / float64(attempts)
			medianMs := medianI64(latencies)

			var reason, detail string

			switch {
			case successCount == 0:
				reason = "all_timeouts"
				detail = fmt.Sprintf("0/%d successes", attempts)

			case successRate < 0.5:
				reason = "low_success_rate"
				detail = fmt.Sprintf("%d/%d successes", successCount, attempts)

			case time.Duration(medianMs)*time.Millisecond > medianThreshold:
				reason = "median_latency_high"
				detail = fmt.Sprintf("median %dms > %dms", medianMs, medianThreshold.Milliseconds())
			}

			mu.Lock()

			if successCount > 0 {
				metrics.MedianLatencies = append(metrics.MedianLatencies, medianMs)
			}
			metrics.SuccessRates = append(metrics.SuccessRates, successRate)

			if reason != "" {
				rejected = append(rejected, RejectedOut{
					Proxy:  px,
					Reason: reason,
					Detail: detail,
				})
				metrics.Errors[reason]++
				metrics.Rejected++
			} else {
				passed = append(passed, px)
				metrics.Passed++
			}

			done++
			maybePrintProgress(done, metrics.Total, metrics.Passed, metrics.Rejected)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	fmt.Println()

	return
}

//
// Final summary & helpers
//

// printFinalReasons prints a sorted list of rejection reasons and their counts.
func printFinalReasons(dead []RejectedOut) {
	reasonCounts := make(map[string]int)
	for _, d := range dead {
		reasonCounts[d.Reason]++
	}

	fmt.Println("\nCauses:")

	type kv struct {
		k string
		v int
	}

	var list []kv
	for k, v := range reasonCounts {
		list = append(list, kv{k, v})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].v > list[j].v
	})

	for _, item := range list {
		fmt.Printf("  %-25s %d\n", item.k, item.v)
	}
}

// classifyTCPErr converts a network error into a short, human-readable reason code.
func classifyTCPErr(err error) string {
	if err == nil {
		return ""
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "tcp_timeout"
	}

	if opErr, ok := err.(*net.OpError); ok && opErr.Err != nil {
		s := opErr.Err.Error()

		if strings.Contains(s, "connection refused") || strings.Contains(s, "refused") {
			return "tcp_refused"
		}
		if strings.Contains(s, "no route") || strings.Contains(s, "unreachable") || strings.Contains(s, "network") {
			return "tcp_network"
		}
	}

	return "tcp_error"
}

// medianI64 returns the median of a slice of int64 values.
// Returns a very large number if the slice is empty.
func medianI64(vals []int64) int64 {
	if len(vals) == 0 {
		return 1<<62 - 1
	}

	s := append([]int64(nil), vals...)
	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})

	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

//
// Main entry point
//

// StartChecker runs the complete two-stage proxy validation pipeline
// using the parameters tuned for real-world MTProto proxy lists.
func StartChecker() {
	// ── Input / Output paths ─────────────────────────────────────
	inPath := "json/proxies_tg.json"
	aliveOut := "json/alive.json"
	deadOut := "json/dead.json"

	// ── Level 1 parameters (DNS + TCP) ───────────────────────────
	dnsTimeoutMs := 10000
	tcpTimeoutMs := 2000

	workers1 := 500
	perHost1 := 2

	// ── Level 2 parameters (stability test) ──────────────────────
	attempts := 5          // more attempts = smoother success rate
	timeoutMs := 2000      // must be ≥ Level 1 timeout
	backoffMs := 200       // base for exponential backoff
	medianThreshMs := 1500 // realistic threshold for good proxies

	workers2 := 400
	perHost2 := 2

	// ── Load proxies ─────────────────────────────────────────────
	proxies, err := ReadProxies(inPath)
	if err != nil {
		fmt.Println("✗")
		fmt.Printf("Ошибка чтения %s: %v\n", inPath, err)
		return
	}

	// ── Level 1: DNS + TCP ───────────────────────────────────────
	fmt.Print("Проверка DNS и TCP... ")

	dnsTimeout := time.Duration(dnsTimeoutMs) * time.Millisecond
	tcpTimeout := time.Duration(tcpTimeoutMs) * time.Millisecond

	passed1, dead1, m1 := runLevel1(
		proxies,
		dnsTimeout,
		tcpTimeout,
		workers1,
		perHost1,
		nil,
		nil,
	)

	// ── Level 2: Stability check ─────────────────────────────────
	fmt.Print("Проверка стабильности... ")

	timeout := time.Duration(timeoutMs) * time.Millisecond
	backoffBase := time.Duration(backoffMs) * time.Millisecond
	medianThresh := time.Duration(medianThreshMs) * time.Millisecond

	passed2, dead2, m2 := runLevel2(
		passed1,
		attempts,
		timeout,
		backoffBase,
		medianThresh,
		workers2,
		perHost2,
		nil,
	)

	// ── Save results ─────────────────────────────────────────────
	fmt.Print("Saving... ")

	if err = os.MkdirAll("json", 0755); err != nil {
		fmt.Println("✗")
		fmt.Printf("Не могу создать json/: %v\n", err)
		return
	}

	if err = WriteJSON(aliveOut, passed2); err != nil {
		fmt.Println("✗")
		fmt.Printf("Ошибка записи alive: %v\n", err)
		return
	}

	allDead := append(dead1, dead2...)

	if err = WriteJSON(deadOut, allDead); err != nil {
		fmt.Println("✗")
		fmt.Printf("Ошибка записи dead: %v\n", err)
		return
	}

	fmt.Println("✓")

	// ── Final statistics ─────────────────────────────────────────
	total := m1.Total
	dead := m1.Rejected + m2.Rejected
	alive := m2.Passed

	fmt.Printf(
		"\nReceived: %d | dead: %d | alive: %d\n",
		total,
		dead,
		alive,
	)

	printFinalReasons(allDead)
}