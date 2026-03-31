package executive

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"os"
	"time"
)


type Proxy struct {
	Server string `json:"server"`
	Port   string `json:"port"`
	Secret string `json:"secret"`
}

type InProxy struct {
	Server       string  `json:"server"`
	Port         string  `json:"port"`
	Secret       string  `json:"secret"`
	TCPLatencyMs float64 `json:"tcp_latency_ms"`
	HSLatencyMs  float64 `json:"hs_latency_ms"`
}

type ScoredProxy struct {
	Server string `json:"server"`
	Port   string `json:"port"`
	Secret string `json:"secret"`

	TCPLatencyMs float64 `json:"tcp_latency_ms"`
	HSLatencyMs  float64 `json:"hs_latency_ms"`
	ThrottleRate float64 `json:"throttle_rate,omitempty"`

	MedianRTT   float64  `json:"median_rtt_ms"`
	AvgRTT      float64  `json:"avg_rtt_ms"`
	CleanAvg    *float64 `json:"clean_avg_ms"`
	MinRTT      float64  `json:"min_rtt_ms"`
	MaxRTT      float64  `json:"max_rtt_ms"`
	P95         float64  `json:"p95_ms"`
	P99         float64  `json:"p99_ms"`
	Jitter      float64  `json:"jitter_ms"`
	CleanJitter *float64 `json:"clean_jitter_ms"`

	HasOutliers bool      `json:"has_outliers"`
	Outliers    []float64 `json:"outliers"`

	SustainedAvg   float64 `json:"sustained_avg_ms"`
	SustainedStdev float64 `json:"sustained_stdev_ms"`
	SustainedDrift float64 `json:"sustained_drift_ms"`
	SustainedStable bool    `json:"sustained_stable"`

	ThroughputMbps *float64 `json:"throughput_mbps"`
	ThroughputNote string   `json:"throughput_note"`
	ThroughputKB   int      `json:"throughput_sent_kb"`
	DownloadMbps   *float64 `json:"download_mbps"`
	DownloadNote   string   `json:"download_note"`

	MeasuredAt time.Time `json:"measured_at"`
	Score      int       `json:"score"`

	RankOverall *int `json:"rank_overall"`
	RankMedia   *int `json:"rank_media"`
	RankUpload  *int `json:"rank_upload"`
	ChatScore    float64 `json:"chat_score"`
	MediaScore   float64 `json:"media_score"`
	GeneralScore float64 `json:"general_score"`

	CV              float64   `json:"cv,omitempty"`
	SuccessRate     float64   `json:"success_rate"`
	SecretType      string    `json:"secret_type"`


	UploadScore float64 `json:"-"`
}

type Rejected struct {
	Proxy  Proxy  `json:"proxy"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
	FilterLevel string `json:"filter level"`
}

type LevelMetrics struct {
	Total           int
	Passed          int
	Rejected        int
	DNSLatencies    []int64
	TCPLatencies    []int64
	SuccessRates    []float64
	MedianLatencies []int64
	Errors          map[string]int
}

// --- Net ---

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type defaultResolver struct {
	r *net.Resolver
}

func NewDefaultResolver() *defaultResolver {
	return &defaultResolver{r: &net.Resolver{PreferGo: true}}
}

func (d *defaultResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return d.r.LookupHost(ctx, host)
}

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type defaultDialer struct {
	timeout time.Duration
}

func (d *defaultDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	nd := &net.Dialer{Timeout: d.timeout}
	return nd.DialContext(ctx, network, addr)
}


func ReadProxies(path string) ([]Proxy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var proxies []Proxy
	return proxies, json.Unmarshal(data, &proxies)
}

func WriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func WriteJSONAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func PercentileFloat(sorted []float64, p float64) float64 {
	if len(sorted) == 0 { return 0 }
	idx := p / 100.0 * float64(len(sorted)-1)
	lo, hi := int(math.Floor(idx)), int(math.Ceil(idx))
	if lo == hi { return sorted[lo] }
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func PercentileInt(sorted []int64, p float64) int64 {
	if len(sorted) == 0 { return 0 }
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}
