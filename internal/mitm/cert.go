package mitm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"
)

func (e *Engine) DiscoverPins(ctx context.Context) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		next = map[string]string{}
	)
	for _, hp := range e.pinHosts {
		wg.Add(1)
		go func(hp string) {
			defer wg.Done()
			fp, err := fingerprint(ctx, e.directDialer.DialContext, hp, e.timeout, true)
			if err != nil || fp == "" {
				return
			}
			mu.Lock()
			next[hp] = fp
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

func (e *Engine) directFingerprint(ctx context.Context, hostPort string) (string, error) {
	return fingerprint(ctx, e.directDialer.DialContext, hostPort, e.timeout, true)
}

func fingerprint(ctx context.Context, dial DialFunc, hostPort string, timeout time.Duration, verify bool) (string, error) {
	rawConn, err := dial(ctx, "tcp", hostPort)
	if err != nil {
		return "", err
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		InsecureSkipVerify: !verify,
		ServerName:         splitHost(hostPort),
		MinVersion:         tls.VersionTLS10,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no peer cert")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

type tlsSnapshot struct {
	Fingerprint string
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
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		snap.Fingerprint = hex.EncodeToString(sum[:])
	}
	return snap, nil
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

func isWeakVersion(v uint16) bool {
	return v < tls.VersionTLS12
}

func isWeakCipher(c uint16) bool {
	return weakCiphers[c]
}

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

	for hp, want := range pins {
		snap, err := snapshotTLS(ctx, dial, hp, e.timeout)
		if err != nil {
			continue
		}
		if isWeakVersion(snap.Version) {
			return ProbeResult{
				Layer:    LayerTLSFingerprint,
				Pass:     false,
				Reason:   "upstream forced weak TLS version",
				Evidence: tlsVersionName(snap.Version),
			}
		}
		if isWeakCipher(snap.CipherSuite) {
			return ProbeResult{
				Layer:    LayerTLSFingerprint,
				Pass:     false,
				Reason:   "upstream negotiated weak cipher suite",
				Evidence: tlsCipherName(snap.CipherSuite),
			}
		}
		if snap.Fingerprint == "" {
			return ProbeResult{
				Layer:  LayerTLSFingerprint,
				Pass:   false,
				Reason: "no leaf cert presented",
			}
		}
		if snap.Fingerprint != want {
			return ProbeResult{
				Layer:    LayerTLSFingerprint,
				Pass:     false,
				Reason:   "cert fingerprint mismatch — possible MITM",
				Evidence: "got " + snap.Fingerprint[:16] + "... want " + want[:16] + "...",
			}
		}
		return ProbeResult{Layer: LayerTLSFingerprint, Pass: true}
	}
	return ProbeResult{
		Layer:  LayerTLSFingerprint,
		Pass:   false,
		Reason: "no pin host reachable via proxy",
	}
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

func tlsCipherName(c uint16) string {
	return tls.CipherSuiteName(c)
}
