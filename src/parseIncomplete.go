package main

import (
	"crypto/tls"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func parseResponseFromIncomplete(cfg Config, tlsConn *tls.Conn, finSess *finSession, start time.Time) ProbeResult {
	pr := ProbeResult{
		Name:               "H1-Incomplete",
		Status:             ProbeInconclusive,
		Decisive:           false,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}

	timer150 := time.NewTimer(150 * time.Second)
	timerTotal := time.NewTimer(cfg.IncompleteTimeout)
	defer timer150.Stop()
	defer timerTotal.Stop()

	responseChan := make(chan bool, 1)
	go func() {
		response := make([]byte, 4096)
		n, err := tlsConn.Read(response)
		if err != nil {
			log.Debug("Error reading from server: %v", err)
			responseChan <- false
			return
		}
		log.Info("Response from server:%s", string(response[:n]))
		responseChan <- true
	}()

	select {
	case <-timer150.C:
		setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StatePossible)
		setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StatePossible)
		log.Info("No response within 150s; continuing H1-Incomplete wait")
		pr.Reason = "No response within 150s; supporting evidence for Trojan-Go or Caddy-Trojan"

		select {
		case <-timerTotal.C:
			log.Info("No response within incomplete timeout")
			setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StateExcluded)
			pr.Reason = "No response within full incomplete timeout; excludes Trojan-RS"
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr

		case gotResponse := <-responseChan:
			if gotResponse {
				return incompleteLateResponse(pr, finSess, cfg, start)
			}
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr

		case <-responseChan:
			setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StateExcluded)
			setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StateExcluded)
			pr.Reason = "Response between 150s and full timeout; excludes Trojan-Go and Caddy-Trojan"
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr
		}

	case gotResponse := <-responseChan:
		if gotResponse {
			setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StateExcluded)
			setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StateExcluded)
			pr.Reason = "Response before 150s; excludes Trojan-Go and Caddy-Trojan"
		} else {
			pr.Reason = "Read error before 150s"
		}
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr

	case <-timerTotal.C:
		pr.Reason = "H1-Incomplete total timeout reached"
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}
}

func incompleteLateResponse(pr ProbeResult, finSess *finSession, cfg Config, start time.Time) ProbeResult {
	if finSess != nil {
		time.Sleep(2 * time.Second)
		finSess.mu.Lock()
		fd := finSess.finDuration
		captured := finSess.captured
		finSess.mu.Unlock()

		if captured && fd >= 595*time.Second && fd <= 605*time.Second {
			setTrojanMap(pr.AffectedCandidates, "Trojan-RS", StateDefinite)
			pr.Status = ProbeDetected
			pr.Decisive = true
			pr.Reason = "Response with FIN timing 595-605s indicates Trojan-RS"
			pr.DurationMs = time.Since(start).Milliseconds()
			return pr
		}
	}
	setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StateExcluded)
	setTrojanMap(pr.AffectedCandidates, "Caddy-Trojan", StateExcluded)
	pr.Reason = "Late response without Trojan-RS FIN timing"
	pr.DurationMs = time.Since(start).Milliseconds()
	return pr
}
