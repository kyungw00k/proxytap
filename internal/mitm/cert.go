package mitm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"
)

func (e *Engine) DiscoverPins(ctx context.Context) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		next = map[string]Pin{}
	)
	for _, hp := range e.pinHosts {
		wg.Add(1)
		go func(hp string) {
			defer wg.Done()
			snap, err := snapshotTLS(ctx, e.directDialer.DialContext, hp, e.timeout)
			if err != nil {
				return
			}
			if snap.LeafSPKI == "" {
				return
			}
			mu.Lock()
			next[hp] = Pin{LeafSPKI: snap.LeafSPKI, IssuerSPKI: snap.IssuerSPKI}
			mu.Unlock()
		}(hp)
	}
	wg.Wait()
	if len(next) == 0 {
		return errors.New("no pin host reachable directly")
	}
	e.mu.Lock()
	e.pins = next
	e.mu.Unlock()
	return nil
}

type tlsSnapshot struct {
	LeafSPKI    string
	IssuerSPKI  string
	Version     uint16
	CipherSuite uint16
}

func snapshotTLS(ctx context.Context, dial DialFunc, hostPort string, timeout time.Duration) (tlsSnapshot, error) {
	rawConn, err := dial(ctx, "tcp", hostPort)
	if err != nil {
		return tlsSnapshot{}, err
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         splitHost(hostPort),
		MinVersion:         tls.VersionTLS10,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return tlsSnapshot{}, err
	}
	state := tlsConn.ConnectionState()
	snap := tlsSnapshot{
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
	}
	certs := state.PeerCertificates
	if len(certs) > 0 {
		snap.LeafSPKI = spkiHash(certs[0])
	}
	if len(certs) > 1 {
		snap.IssuerSPKI = spkiHash(certs[1])
	}
	return snap, nil
}

func spkiHash(c *x509.Certificate) string {
	if c == nil || len(c.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func splitHost(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}

var weakCiphers = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_SHA:                true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         true,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            true,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     true,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: true,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   true,
}

func isWeakVersion(v uint16) bool { return v < tls.VersionTLS12 }
func isWeakCipher(c uint16) bool  { return weakCiphers[c] }

func (e *Engine) probeTLS(ctx context.Context, dial DialFunc) ProbeResult {
	e.mu.RLock()
	pins := e.pins
	e.mu.RUnlock()
	if len(pins) == 0 {
		return ProbeResult{
			Layer:  LayerTLSFingerprint,
			Pass:   false,
			Reason: "pins not discovered yet; run DiscoverPins first",
		}
	}

	type pinProbe struct {
		leafPass bool
		verdict  ProbeResult
		done     bool
	}

	results := make([]pinProbe, len(pins))
	var wg sync.WaitGroup
	idx := 0
	for hp, want := range pins {
		i := idx
		idx++
		wg.Add(1)
		go func(i int, hp string, want Pin) {
			defer wg.Done()
			snap, err := snapshotTLS(ctx, dial, hp, e.timeout)
			if err != nil {
				results[i] = pinProbe{verdict: ProbeResult{
					Layer: LayerTLSFingerprint, Pass: false,
					Reason: "snapshot failed for " + hp + ": " + err.Error(),
				}}
				return
			}
			if isWeakVersion(snap.Version) {
				results[i] = pinProbe{verdict: ProbeResult{
					Layer: LayerTLSFingerprint, Pass: false,
					Reason: "upstream forced weak TLS version",
					Evidence: tlsVersionName(snap.Version),
				}}
				return
			}
			if isWeakCipher(snap.CipherSuite) {
				results[i] = pinProbe{verdict: ProbeResult{
					Layer: LayerTLSFingerprint, Pass: false,
					Reason: "upstream negotiated weak cipher suite",
					Evidence: tlsCipherName(snap.CipherSuite),
				}}
				return
			}
			if snap.LeafSPKI == "" {
				results[i] = pinProbe{verdict: ProbeResult{
					Layer: LayerTLSFingerprint, Pass: false,
					Reason: "no leaf cert presented",
				}}
				return
			}
			if pinMatches(want, snap) {
				results[i] = pinProbe{
					leafPass: true,
					verdict:  ProbeResult{Layer: LayerTLSFingerprint, Pass: true},
				}
				return
			}
			results[i] = pinProbe{verdict: ProbeResult{
				Layer:  LayerTLSFingerprint,
				Pass:   false,
				Reason: "SPKI mismatch — possible MITM (leaf rotated AND issuer changed)",
				Evidence: "host=" + hp + " got leaf=" + shortHash(snap.LeafSPKI) +
					" issuer=" + shortHash(snap.IssuerSPKI),
			}}
		}(i, hp, want)
	}
	wg.Wait()

	for _, r := range results {
		if r.leafPass {
			return r.verdict
		}
	}
	for _, r := range results {
		if r.verdict.Layer != "" {
			return r.verdict
		}
	}
	return ProbeResult{
		Layer:  LayerTLSFingerprint,
		Pass:   false,
		Reason: "no pin host produced a verdict",
	}
}

func shortHash(h string) string {
	if len(h) < 12 {
		return h
	}
	return h[:12] + "..."
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return "unknown"
	}
}

func tlsCipherName(c uint16) string { return tls.CipherSuiteName(c) }
