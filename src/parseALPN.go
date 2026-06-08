package main

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromALPN(cfg Config, tlsConn *tls.Conn, start time.Time) ProbeResult {
	pr := ProbeResult{
		Name:               "H1-ALPN-h2",
		Status:             ProbeInconclusive,
		Decisive:           false,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(cfg.ProbeTimeout))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		log.Debug("Error reading from server: %v", err)
		pr.Error = err.Error()
		pr.Reason = "Read error on ALPN probe"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	responseStr := string(response[:n])
	log.Info("Response from server:\n%s", responseStr)

	if !strings.HasPrefix(responseStr, "HTTP/") {
		log.Info("Response doesn't contain HTTP prefix.")
		setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StatePossible)
		markAllTrojanExcept(pr.AffectedCandidates, "Caddy-Trojan", StateExcluded)
		pr.Reason = "Non-HTTP response over h2 ALPN; supporting evidence for Caddy-Trojan"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	log.Info("Response is in HTTP/1.x format.")
	setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StateExcluded)
	setTrojanMap(pr.AffectedCandidates, "Trojan-GFW", StatePossible)
	setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StatePossible)
	setTrojanMap(pr.AffectedCandidates, "Trojan-R", StatePossible)
	setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StatePossible)

	backendType := extractBackendType(responseStr)
	markHTTPSFromBackend(pr.AffectedHTTPS, backendType, StatePossible, StateExcluded)

	pr.AlternativeHTTPS = possibleHTTPSFromMap(pr.AffectedHTTPS)
	pr.Reason = "ALPN behavior compatible with Trojan-Go, nginx, or lighttpd (supporting evidence only)"
	if backendType == "caddy" || backendType == "iis" {
		pr.Reason = "HTTP/1.x over h2 ALPN with " + backendType + " backend signature; supporting evidence for Trojan family"
		pr.TrojanFamilyHit = true
	}
	pr.DurationMs = time.Since(start).Milliseconds()
	return pr
}

func possibleHTTPSFromMap(m map[string]CandidateState) []string {
	var names []string
	for _, n := range allHTTPServerNames {
		if m[n] == StatePossible {
			names = append(names, n)
		}
	}
	return names
}
