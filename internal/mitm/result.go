package mitm

import "github.com/kyungw00k/proxytap/internal/fetcher"

type Layer string

const (
	LayerTLSFingerprint Layer = "tls_fingerprint"
	LayerPlainBody      Layer = "plain_body"
	LayerHeaderLeak     Layer = "header_leak"
)

type ProbeResult struct {
	Layer    Layer  `json:"layer"`
	Pass     bool   `json:"pass"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type Verdict struct {
	Proxy  fetcher.Proxy `json:"proxy"`
	Clean  bool          `json:"clean"`
	Score  int           `json:"score"`
	Probes []ProbeResult `json:"probes"`
}
