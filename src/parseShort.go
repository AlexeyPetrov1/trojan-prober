package main

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromShort(cfg Config, tlsConn *tls.Conn, start time.Time) ProbeResult {
	pr := ProbeResult{
		Name:               "Short-ALPN-h2",
		Status:             ProbeInconclusive,
		Decisive:           false,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}

	shortTimeout := 150 * time.Second
	timer := time.NewTimer(shortTimeout)
	defer timer.Stop()

	readDone := make(chan struct {
		data  string
		err   error
		hasData bool
	}, 1)

	go func() {
		response := make([]byte, 4096)
		n, err := tlsConn.Read(response)
		readDone <- struct {
			data    string
			err     error
			hasData bool
		}{data: string(response[:n]), err: err, hasData: n > 0}
	}()

	select {
	case <-timer.C:
		log.Info("No response within 150 seconds (supporting evidence only)")
		setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Trojan-GFW", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Trojan-R", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StatePossible)
		pr.Reason = "Long silence on Short-ALPN-h2; supporting evidence for Trojan variants with Caddy backend"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr

	case res := <-readDone:
		if res.err != nil {
			log.Debug("Error reading from server: %v", res.err)
			pr.Error = res.err.Error()
		}
		if !res.hasData {
			pr.Reason = "Empty or error response on Short-ALPN-h2"
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr
		}

		log.Info("Response from server:%s", res.data)
		if !strings.HasPrefix(res.data, "HTTP/") {
			markAllTrojan(pr.AffectedCandidates, StateExcluded)
			pr.Status = ProbeExcluded
			pr.Reason = "Non-HTTP response; excludes Trojan server behavior on this probe"
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr
		}

		setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StateExcluded)
		backendType := extractBackendType(res.data)
		markHTTPSFromBackend(pr.AffectedHTTPS, backendType, StatePossible, StateExcluded)
		pr.AlternativeHTTPS = possibleHTTPSFromMap(pr.AffectedHTTPS)

		if backendType == "caddy" || backendType == "iis" {
			pr.TrojanFamilyHit = true
			pr.Reason = "HTTP/1.x over h2 with " + backendType + " signature; supporting evidence for Trojan family"
		} else {
			pr.Reason = "Response within 150s; ALPN supporting evidence only"
		}
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}
}
