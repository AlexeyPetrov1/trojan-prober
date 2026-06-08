package main

import (
	"crypto/tls"
	"io"
	"strings"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromOver(cfg Config, tlsConn *tls.Conn, start time.Time) ProbeResult {
	pr := ProbeResult{
		Name:               "Overbuffer-Incomplete",
		Status:             ProbeInconclusive,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}

	response := make([]byte, 4096)
	timer := time.NewTimer(cfg.OverbufferTimeout)
	defer timer.Stop()

	readDone := make(chan struct {
		received bool
		err      error
	}, 1)
	exitChan := make(chan struct{})

	go func() {
		n, err := tlsConn.Read(response)
		select {
		case <-exitChan:
			return
		default:
			readDone <- struct {
				received bool
				err      error
			}{received: n > 0, err: err}
		}
	}()

	select {
	case <-timer.C:
		close(exitChan)
		log.Info("No response received within %s after successful TLS", cfg.OverbufferTimeout)
		setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StateDefinite)
		pr.Status = ProbeDetected
		pr.Decisive = true
		pr.Reason = "No HTTP response within timeout after successful TLS connection and request sent"
		pr.ObservedBehavior = "clean_timeout"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr

	case res := <-readDone:
		if res.err != nil && res.err != io.EOF {
			log.Debug("Error reading from server: %v", res.err)
			pr.Status = ProbeError
			pr.Error = res.err.Error()
			pr.Reason = "Read error after request; not evidence for Trojan-Go"
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr
		}
		if res.received {
			return handleResponseFromOver(response, start)
		}
		pr.Reason = "No data received before channel closed"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}
}

func handleResponseFromOver(response []byte, start time.Time) ProbeResult {
	pr := ProbeResult{
		Name:               "Overbuffer-Incomplete",
		Status:             ProbeInconclusive,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}
	responseStr := string(response)

	if strings.HasPrefix(responseStr, "HTTP/") {
		log.Info("Response from server:\n%s", responseStr)
		log.Info("Received HTTP response. Excludes Trojan-Go.")
		setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StateExcluded)
		setTrojanMap(pr.AffectedCandidates, "Trojan-GFW", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Trojan-R", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StatePossible)
		pr.Status = ProbeExcluded
		pr.Reason = "HTTP response received; excludes Trojan-Go"
		backendType := extractBackendType(responseStr)
		markHTTPSFromBackend(pr.AffectedHTTPS, backendType, StatePossible, StateExcluded)
	} else {
		log.Info("Response from server:\n%s", responseStr)
		setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StateDefinite)
		pr.Status = ProbeDetected
		pr.Decisive = true
		pr.Reason = "Non-HTTP response; indicative of Trojan-RS"
	}
	pr.DurationMs = time.Since(start).Milliseconds()
	return pr
}
