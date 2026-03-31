// Package executive implements a single-stage MTProto proxy checker.
//
// It loads proxies from proxies_tg.json, performs multi-attempt handshake
// tests with configurable concurrency and per-host limits, measures real
// latency and success rate, classifies failures, and produces clean output:
//
//   • alive.json   — only healthy proxies that passed all checks
//   • dead.json    — rejected proxies with reason and details
//
// The checker is built for high-throughput, production-grade operation while
// remaining safe for public proxy lists.
package executive

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)


// RejectedOut represents a proxy that failed validation together
// with a machine-readable reason and optional human-readable detail.
type RejectedOut struct {
	Proxy  Proxy  `json:"proxy"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

const progressStep = 25

// printProgress shows a compact live status line during checking.
func printProgress(done, total, alive, dead int) {
	fmt.Printf("\rChecked %d/%d | alive: %d | dead: %d", done, total, alive, dead)
}

// maybePrintProgress prints progress only every N checks or on final iteration
// to avoid flooding the terminal.
func maybePrintProgress(done, total, alive, dead int) {
	if done%progressStep == 0 || done == total {
		printProgress(done, total, alive, dead)
	}
}

type secretKind uint8

const (
	kindPlain secretKind = iota
	kindDD
	kindEE
)

//
// Secret parsing
//

// parseSecret decodes a proxy secret and determines its type (plain, dd, or ee).
func parseSecret(s string) (kind secretKind, raw []byte, err error) {
	low := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(low, "ee"):
		kind = kindEE
		raw, err = hex.DecodeString(low[2:])
	case strings.HasPrefix(low, "dd"):
		kind = kindDD
		raw, err = hex.DecodeString(low[2:])
	default:
		kind = kindPlain
		raw, err = hex.DecodeString(low)
	}
	if err != nil {
		err = fmt.Errorf("hex decode: %w", err)
	}
	return
}

//
// Obfuscation helpers
//

// buildObfs2Init creates the initial obfuscated frame for MTProto 2.0
// handshake (including optional dd-key derivation).
func buildObfs2Init(kind secretKind, secret []byte) ([]byte, error) {
	frame := make([]byte, 64)
	for {
		if _, err := cryptoRand.Read(frame); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		b0 := frame[0]
		if b0 == 0xef || b0 == 0x44 || b0 == 0x48 || b0 == 0x47 || b0 == 0x50 {
			continue
		}
		if frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == 0 {
			continue
		}
		break
	}

	copy(frame[56:60], []byte{0xef, 0xef, 0xef, 0xef})

	encKey := make([]byte, 32)
	copy(encKey, frame[8:40])
	encIV := make([]byte, 16)
	copy(encIV, frame[40:56])

	if kind == kindDD && len(secret) >= 16 {
		sum := sha256.Sum256(append(frame[8:40], secret[:16]...))
		copy(encKey, sum[:])
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	out := make([]byte, 64)
	cipher.NewCTR(block, encIV).XORKeyStream(out, frame)
	return out, nil
}

//
// Handshake checks
//

// doObfs2Check performs a lightweight obfs2-style handshake and returns
// the connection latency (in milliseconds) on success.
func doObfs2Check(ctx context.Context, dialer Dialer, addr string, kind secretKind, secret []byte) (int64, error) {
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	frame, err := buildObfs2Init(kind, secret)
	if err != nil {
		return 0, fmt.Errorf("build_frame: %w", err)
	}

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	start := time.Now()

	// 1. Send the obfuscated initialization frame
	if _, err = conn.Write(frame); err != nil {
		return 0, fmt.Errorf("write frame: %w", err)
	}

	// 2. Perform a lenient read (1500 ms timeout). A timeout here is
	//    considered SUCCESS for MTProto proxies because they often stay
	//    silent until a real client request arrives.
	checkWait := 1500 * time.Millisecond
	conn.SetReadDeadline(time.Now().Add(checkWait))

	tmp := make([]byte, 1)
	_, err = conn.Read(tmp)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is expected and indicates a live proxy.
			return time.Since(start).Milliseconds(), nil
		}
		if err == io.EOF {
			return 0, fmt.Errorf("proxy closed connection immediately (EOF)")
		}
		return 0, fmt.Errorf("read error: %w", err)
	}

	// Any data received also confirms the proxy is alive.
	return time.Since(start).Milliseconds(), nil
}

// doFakeTLSCheck performs a FakeTLS (ee) handshake using the real server name.
func doFakeTLSCheck(ctx context.Context, dialer Dialer, addr, sni string) (int64, error) {
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if dl, ok := ctx.Deadline(); ok {
		tlsConn.SetDeadline(dl)
	}

	start := time.Now()
	if err = tlsConn.Handshake(); err != nil {
		return 0, fmt.Errorf("tls: %w", err)
	}
	return time.Since(start).Milliseconds(), nil
}

// checkProxyOnce runs a single handshake attempt for the given proxy.
func checkProxyOnce(ctx context.Context, dialer Dialer, px Proxy) (int64, error) {
	addr := net.JoinHostPort(px.Server, px.Port)

	kind, secret, err := parseSecret(px.Secret)
	if err != nil {
		return 0, fmt.Errorf("secret: %w", err)
	}

	switch kind {
	case kindEE:
		return doFakeTLSCheck(ctx, dialer, addr, px.Server)
	default:
		return doObfs2Check(ctx, dialer, addr, kind, secret)
	}
}

//
// Core checker routine
//

// runChecker executes the full multi-attempt check pipeline on a slice of proxies.
func runChecker(
	in []Proxy,
	attempts int,
	handshakeTimeout time.Duration,
	medianThreshold time.Duration,
	globalConcurrency int,
	perHostLimit int,
	dialer Dialer,
	minSuccessRate float64,
) (passed []Proxy, rejected []RejectedOut, metrics LevelMetrics) {

	if dialer == nil {
		dialer = &defaultDialer{timeout: handshakeTimeout}
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

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		done int
	)

	for _, p := range in {
		wg.Add(1)

		go func(px Proxy) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			hostSem := getHostSem(px.Server)
			hostSem <- struct{}{}
			defer func() { <-hostSem }()

			var latencies []int64
			successCount := 0

			for i := 0; i < attempts; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
				latMs, err := checkProxyOnce(ctx, dialer, px)
				cancel()

				if err != nil {
					mu.Lock()
					metrics.Errors[classifyHandshakeErr(err)]++
					mu.Unlock()
					continue
				}

				latencies = append(latencies, latMs)
				successCount++
			}

			successRate := float64(successCount) / float64(attempts)
			medianMs := medianI64(latencies)

			var reason, detail string

			switch {
			case successCount == 0:
				reason = "handshake_failed"
				detail = fmt.Sprintf("0/%d attempts", attempts)

			case successRate < minSuccessRate:
				reason = "low_success_rate"
				detail = fmt.Sprintf("%d/%d (%.0f%%)", successCount, attempts, successRate*100)

			case medianMs >= 0 && time.Duration(medianMs)*time.Millisecond > medianThreshold:
				reason = "high_latency"
				detail = fmt.Sprintf("median %dms > %dms", medianMs, medianThreshold.Milliseconds())
			}

			mu.Lock()
			defer mu.Unlock()

			if successCount > 0 {
				metrics.MedianLatencies = append(metrics.MedianLatencies, medianMs)
			}
			metrics.SuccessRates = append(metrics.SuccessRates, successRate)

			done++
			if reason != "" {
				rejected = append(rejected, RejectedOut{Proxy: px, Reason: reason, Detail: detail})
				metrics.Errors[reason]++
				metrics.Rejected++
			} else {
				passed = append(passed, px)
				metrics.Passed++
			}

			maybePrintProgress(done, metrics.Total, metrics.Passed, metrics.Rejected)
		}(p)
	}

	wg.Wait()
	fmt.Println()
	return
}

//
// Error classification
//

// classifyHandshakeErr returns a short string category for the given handshake error.
func classifyHandshakeErr(err error) string {
	if err == nil {
		return ""
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "handshake_timeout"
	}
	msg := err.Error()
	if strings.Contains(msg, "tls:") {
		return "protocol_error"
	}
	if strings.Contains(msg, "read:") || strings.Contains(msg, "write:") {
		return "handshake_failed"
	}
	return classifyTCPErr(err)
}

// classifyTCPErr returns a short string category for TCP-level errors.
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
// Returns -1 if the slice is empty.
func medianI64(vals []int64) int64 {
	if len(vals) == 0 {
		return -1
	}

	s := append([]int64(nil), vals...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })

	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

//
// Output helpers
//

// printFinalReasons prints a sorted summary of rejection reasons.
func printFinalReasons(dead []RejectedOut) {
	counts := make(map[string]int)
	for _, d := range dead {
		counts[d.Reason]++
	}

	fmt.Println("\nCauses of rejection:")

	type kv struct {
		k string
		v int
	}

	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{k, v})
	}

	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })

	for _, item := range list {
		fmt.Printf("  %-25s %d\n", item.k, item.v)
	}
}

//
// Main entry point
//

// StartChecker loads proxies_tg.json, runs the full MTProto handshake test,
// and saves alive / dead results.
func StartChecker() {
	const (
		inPath      = "json/proxies_tg.json"
		aliveOut    = "json/alive.json"
		deadOut     = "json/dead.json"

		attempts       = 5
		handshakeMs    = 5500
		medianThreshMs = 3500
		workers        = 400
		perHost        = 1

		minSuccessRate = 0.30
	)

	proxies, err := ReadProxies(inPath)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", inPath, err)
		return
	}

	fmt.Print("MTProto handshake check... ")

	// Heartbeat spinner that runs for the entire duration of the check.
	hbCtx, hbCancel := context.WithCancel(context.Background())
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
				fmt.Printf("\r%s %c Checking MTProto proxies...%s\033[K", Cyan, spinner[i%len(spinner)], Reset)
				i++
			}
		}
	}()

	passed, dead, _ := runChecker(
		proxies,
		attempts,
		time.Duration(handshakeMs)*time.Millisecond,
		time.Duration(medianThreshMs)*time.Millisecond,
		workers,
		perHost,
		nil,
		minSuccessRate,
	)

	hbCancel() // stop the spinner

	fmt.Print("Saving... ")

	if err = os.MkdirAll("json", 0755); err != nil {
		fmt.Printf("Cannot create json/ directory: %v\n", err)
		return
	}

	if err = WriteJSON(aliveOut, passed); err != nil {
		fmt.Printf("Error writing alive proxies: %v\n", err)
		return
	}

	if err = WriteJSON(deadOut, dead); err != nil {
		fmt.Printf("Error writing dead proxies: %v\n", err)
		return
	}

	fmt.Println("✓")
	printFinalReasons(dead)
}
