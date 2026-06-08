package main

import (
	"crypto/tls"
	"io"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromClose(cfg Config, tlsConn *tls.Conn, finSess *finSession, start time.Time) ProbeResult {
	pr := ProbeResult{
		Name:               "H1-Close",
		Status:             ProbeInconclusive,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(cfg.ProbeTimeout))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	responseTime := time.Now()

	if err != nil && err != io.EOF {
		log.Info("Error reading from server: %v", err)
		pr.Reason = "Failed to read HTTP response before FIN timing"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	responseStr := string(response[:n])
	backendType := extractBackendType(responseStr)
	if n > 0 {
		log.Info("Response from server:\n%s", responseStr)
	}
	log.Info("Capture response at: %s", responseTime)

	if finSess == nil {
		pr.Reason = "FIN capture not available"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	finSess.mu.Lock()
	captureStart := finSess.startTime
	finSess.mu.Unlock()

	if captureStart.IsZero() {
		pr.Reason = "FIN capture did not start; timing inconclusive"
		pr.DurationMs = time.Since(start).Milliseconds()
		markHTTPSFromBackend(pr.AffectedHTTPS, backendType, StatePossible, StateExcluded)
		return pr
	}

	responseDuration := responseTime.Sub(captureStart)
	_, finDuration, captured, finErr := finSess.waitForFIN(cfg.FinTimeout)

	if finErr != nil {
		pr.Status = ProbeError
		pr.Error = finErr.Error()
		pr.Reason = "FIN capture failed"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	if !captured {
		pr.Reason = "FIN not captured within timeout; Trojan-GFW timing inconclusive"
		pr.DurationMs = time.Since(start).Milliseconds()
		markHTTPSFromBackend(pr.AffectedHTTPS, backendType, StatePossible, StateExcluded)
		return pr
	}

	timeDiff := finDuration - responseDuration
	if timeDiff < 0 {
		pr.Reason = "Invalid negative response-to-FIN interval; timing inconclusive"
		pr.ObservedBehavior = "negative_time_diff"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	pr.ObservedBehavior = "time_diff_seconds"
	log.Info("Time difference: %f seconds", timeDiff.Seconds())

	if timeDiff >= 29*time.Second && timeDiff <= 31*time.Second {
		setTrojanMap(pr.AffectedCandidates, "Trojan-GFW", StateDefinite)
		pr.Status = ProbeDetected
		pr.Decisive = true
		pr.Reason = "Response-to-FIN interval 29-31s indicates Trojan-GFW"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	pr.Reason = "Response-to-FIN interval outside Trojan-GFW window; supporting evidence only"
	setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StatePossible)
	setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StatePossible)
	setTrojanMap(pr.AffectedCandidates, "Trojan-R", StatePossible)
	setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StatePossible)
	markHTTPSFromBackend(pr.AffectedHTTPS, backendType, StatePossible, StateExcluded)
	pr.DurationMs = time.Since(start).Milliseconds()
	return pr
}
