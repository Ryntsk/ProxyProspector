package executive

// Package executive implements a high-performance MTProto proxy fetcher.
//
// It reads a list of public sources (sources.txt), downloads them in parallel,
// parses Telegram proxy deep links, validates MTProto secrets (including
// FakeTLS "ee" and "dd" prefixes), filters out suspicious or malformed entries,
// deduplicates everything globally, and saves two clean JSON files:
//   • proxies_tg.json      — valid, ready-to-use proxies
//   • proxies_rejected.json — everything that was filtered out
//
// The fetcher is designed for continuous, unattended operation and
// produces clean, production-ready proxy lists for the scoring pipeline.
import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// sourcesFile contains one URL per line with public proxy lists.
	sourcesFile = "sources.txt"

	// outputRejected stores all proxies that failed validation or parsing.
	outputRejected = "json/proxies_rejected.json"
	// outputTG stores only fully valid MTProto proxies ready for scoring.
	outputTG = "json/proxies_tg.json"
)

var (
	httpClient = &http.Client{Timeout: 15 * time.Second}

	// Regex patterns for extracting proxy components from raw text lines.
	serverRegex = regexp.MustCompile(`server=([0-9A-Za-z.\-_]+)`)
	portRegex   = regexp.MustCompile(`port=([0-9]+)`)
	secretRegex = regexp.MustCompile(`secret\s*=\s*([0-9a-fA-F]{16,})`)
)

// ProxyEntry represents a single MTProto proxy (server:port:secret).
type ProxyEntry struct {
	Server string `json:"server"`
	Port   string `json:"port"`
	Secret string `json:"secret"`
}

// key returns a unique identifier for deduplication.
func (p ProxyEntry) key() string {
	return p.Server + ":" + p.Port + ":" + p.Secret
}

// sourceResult holds the outcome of scanning one source URL.
type sourceResult struct {
	scanned int               // total non-empty lines processed
	tgRaw   []ProxyEntry      // valid proxies
	rejRaw  []ProxyEntry      // rejected or malformed entries
}

//
// Network & Parsing
//

// fetchSource downloads the given URL and parses every line for proxy data.
func fetchSource(rawURL string) sourceResult {
	var res sourceResult

	resp, err := httpClient.Get(rawURL)
	if err != nil {
		log.Printf("Ошибка загрузки [%s]: %v\n", rawURL, err)
		return res
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	// Large buffer to handle big proxy lists efficiently
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		res.scanned++
		parseProxyLine(line, &res)
	}

	return res
}

// parseProxyLine extracts server, port and secret from a single line
// using regex and routes the entry to either tgRaw or rejRaw.
func parseProxyLine(line string, res *sourceResult) {
	sm := serverRegex.FindStringSubmatch(line)
	if len(sm) < 2 {
		return
	}
	server := sm[1]

	pm := portRegex.FindStringSubmatch(line)
	if len(pm) < 2 {
		res.rejRaw = append(res.rejRaw, ProxyEntry{Server: server})
		return
	}
	port := pm[1]

	scm := secretRegex.FindStringSubmatch(line)
	if len(scm) < 2 {
		res.rejRaw = append(res.rejRaw, ProxyEntry{Server: server, Port: port})
		return
	}

	// Normalize secret early so deduplication works correctly
	// and secretType detection later is consistent.
	secret := strings.ToLower(strings.ReplaceAll(scm[1], " ", ""))

	entry := ProxyEntry{Server: server, Port: port, Secret: secret}

	if !isValidMTProtoSecret(secret) {
		res.rejRaw = append(res.rejRaw, entry)
		return
	}

	res.tgRaw = append(res.tgRaw, entry)
}

//
// Validation
//

// isValidMTProtoSecret performs comprehensive validation of an MTProto secret.
//
// It rejects:
//   • empty or non-hex strings
//   • secrets that are too short
//   • suspicious patterns commonly used in low-quality or blocked proxies
func isValidMTProtoSecret(secret string) bool {
	secret = strings.TrimSpace(strings.ToLower(secret))
	if secret == "" {
		return false
	}

	if isSuspiciousSecret(secret) {
		return false
	}

	decoded, err := hex.DecodeString(secret)
	if err != nil {
		return false
	}

	if len(decoded) < 16 {
		return false
	}

	switch len(decoded) {
	case 16:
		return true
	default:
		// ee/dd prefixes are allowed for extended (FakeTLS) secrets
		prefix := secret[:2]
		if prefix == "dd" || prefix == "ee" {
			return len(decoded) >= 17
		}
		return false
	}
}

// isSuspiciousSecret applies several heuristics to detect low-quality
// or fake secrets that are likely to be blocked or perform poorly.
func isSuspiciousSecret(secret string) bool {
	// Remove known valid prefixes for analysis of the payload
	cleanSecret := secret
	if strings.HasPrefix(secret, "ee") || strings.HasPrefix(secret, "dd") {
		cleanSecret = secret[2:]
	}

	if len(cleanSecret) < 32 {
		return false // too short for meaningful pattern analysis
	}

	// Detect known FakeTLS header patterns that are not truly random
	if strings.HasPrefix(secret, "ee1603") {
		if strings.Contains(secret, "00010001") || strings.Contains(secret, "030386e2") {
			return true
		}
	}

	// Reject secrets with long runs of identical hex characters
	// (cryptographically random data almost never has 8+ repeats)
	if containsLongRepeats(cleanSecret, 8) {
		return true
	}

	// Frequency analysis: if any single character dominates (>40%),
	// the secret is almost certainly not random.
	counts := make(map[rune]int)
	maxRepeat := 0
	for _, char := range cleanSecret {
		counts[char]++
		if counts[char] > maxRepeat {
			maxRepeat = counts[char]
		}
	}
	if float64(maxRepeat)/float64(len(cleanSecret)) > 0.4 {
		return true
	}

	return false
}

// containsLongRepeats returns true if the string contains `limit`
// or more identical characters in a row.
func containsLongRepeats(s string, limit int) bool {
	if len(s) < limit {
		return false
	}

	counter := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			counter++
			if counter >= limit {
				return true
			}
		} else {
			counter = 1
		}
	}
	return false
}

//
// Helpers
//

// dedup removes duplicate ProxyEntry items based on their key.
// Empty entries are also filtered out.
func dedup(list []ProxyEntry) []ProxyEntry {
	seen := make(map[string]struct{}, len(list))
	out := make([]ProxyEntry, 0, len(list))

	for _, e := range list {
		if e.Server == "" && e.Port == "" && e.Secret == "" {
			continue
		}
		k := e.key()
		if _, exists := seen[k]; !exists {
			seen[k] = struct{}{}
			out = append(out, e)
		}
	}
	return out
}

// readURLs loads all non-empty lines from sources.txt as URLs.
func readURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть %s: %w", filename, err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if u := strings.TrimSpace(scanner.Text()); u != "" {
			urls = append(urls, u)
		}
	}
	return urls, scanner.Err()
}

// saveJSON writes a slice of ProxyEntry to a pretty-printed JSON file.
func saveJSON(filename string, list []ProxyEntry) {
	if list == nil {
		list = []ProxyEntry{}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(filename, data, 0644); err != nil {
		panic(err)
	}
}

//
// Main entry point
//

// RunFetcher orchestrates the entire fetching pipeline:
//   1. Reads source URLs
//   2. Downloads and parses them concurrently
//   3. Prints per-source statistics
//   4. Globally deduplicates and saves results
func RunFetcher() {
	urls, err := readURLs(sourcesFile)
	if err != nil {
		fmt.Printf("Ошибка чтения источников: %v\n", err)
		return
	}
	if len(urls) == 0 {
		fmt.Println("Файл источников пуст или не содержит валидных ссылок.")
		return
	}

	// Parallel fetching
	results := make([]sourceResult, len(urls))
	var wg sync.WaitGroup

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, urlLine string) {
			defer wg.Done()
			results[idx] = fetchSource(urlLine)
		}(i, u)
	}
	wg.Wait()

	// Per-source statistics
	for i, u := range urls {
		res := results[i]
		rejDedup := dedup(res.rejRaw)
		tgDedup := dedup(res.tgRaw)

		totalRaw := make([]ProxyEntry, 0, len(res.tgRaw)+len(res.rejRaw))
		totalRaw = append(totalRaw, res.tgRaw...)
		totalRaw = append(totalRaw, res.rejRaw...)
		totalDedup := dedup(totalRaw)

		fmt.Printf("%s\n└──Total = %d, unic = %d, rejected = %d, correct = %d\n\n",
			u, res.scanned, len(totalDedup), len(rejDedup), len(tgDedup))
	}

	// Global aggregation + final deduplication
	var allTgRaw, allRejRaw []ProxyEntry
	for _, res := range results {
		allTgRaw = append(allTgRaw, res.tgRaw...)
		allRejRaw = append(allRejRaw, res.rejRaw...)
	}

	allTg := dedup(allTgRaw)
	allRejected := dedup(allRejRaw)

	saveJSON(outputTG, allTg)
	saveJSON(outputRejected, allRejected)

	fmt.Printf("Collected: %d\n", len(allTg))
}