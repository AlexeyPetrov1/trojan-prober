package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liuylv/trojan-prober/src/log"
)

func runAll(cfg Config) FinalReport {
	probes := buildProbeSet(cfg)
	var results []ProbeResult
	startedAt := time.Now()

	for i, probe := range probes {
		log.PrintColoredMessage("----------Executing probe: %s----------", probe)
		pr := runProbeWithRetries(cfg, probe)
		results = append(results, pr)

		partial := aggregateResults(cfg, results)
		partial.StartedAt = startedAt
		if shouldStopEarly(cfg, partial) {
			partial.Probes = results
			return partial
		}

		if i < len(probes)-1 {
			time.Sleep(cfg.DelayBetweenProbes)
		}
	}

	report := aggregateResults(cfg, results)
	report.StartedAt = startedAt
	return report
}

func runProbeWithRetries(cfg Config, probe string) ProbeResult {
	var last ProbeResult
	for attempt := 0; attempt < cfg.Retries; attempt++ {
		if attempt > 0 {
			log.Info("Retry %d/%d for probe %s", attempt+1, cfg.Retries, probe)
		}
		last = runProbe(cfg, probe)
		if last.Status != ProbeError {
			return last
		}
	}
	return last
}

func runProbe(cfg Config, probe string) ProbeResult {
	start := time.Now()
	base := ProbeResult{
		Name:               probe,
		Status:             ProbeInconclusive,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
	}

	probeData, err := loadProbeData(probe, cfg.OverbufferRepeatNum)
	if err != nil {
		base.Status = ProbeError
		base.Error = err.Error()
		base.Reason = "Failed to load probe definition"
		base.DurationMs = time.Since(start).Milliseconds()
		return base
	}

	portInt, _ := strconv.Atoi(cfg.TargetPort)
	var finSess *finSession
	var finCancel context.CancelFunc

	needsFIN := probe == "H1-Close" || probe == "H1-Incomplete"
	if needsFIN {
		finSess = &finSession{}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.FinTimeout)
		finCancel = cancel
		startFINCapture(ctx, cfg, finSess, cfg.TargetServer, uint16(portInt))
		defer finCancel()
	}

	dialer := &net.Dialer{Timeout: cfg.ProbeTimeout}
	tcpConn, err := dialer.Dial("tcp", cfg.ServerAddr)
	if err != nil {
		return finishProbe(base, start, ProbeError, false, "", err.Error(), "TCP connection failed")
	}
	defer tcpConn.Close()

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         cfg.TargetServer,
		NextProtos:         []string{probeData.ALPN},
	})
	_ = tcpConn.SetDeadline(time.Now().Add(cfg.ProbeTimeout))

	if err := tlsConn.Handshake(); err != nil {
		pr := probeResultFromTLSHandshake(probe, err)
		pr.DurationMs = time.Since(start).Milliseconds()
		return pr
	}

	probeContent := buildRequest(probeData)
	requestBytes := len(probeContent)
	log.Info("Probe %s: sending %d bytes", probe, requestBytes)

	var wg sync.WaitGroup
	wg.Add(1)
	writeErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := tlsConn.Write([]byte(probeContent))
		writeErr <- err
	}()
	wg.Wait()

	select {
	case err := <-writeErr:
		if err != nil {
			if strings.Contains(err.Error(), "broken pipe") {
				log.Debug("Server closed connection after write: %v", err)
			} else {
				return finishProbe(base, start, ProbeError, false, "", err.Error(), "Failed to send probe request")
			}
		}
	default:
	}

	switch probe {
	case "H1-Close":
		return parseResponseFromClose(cfg, tlsConn, finSess, start)
	case "Overbuffer-Incomplete":
		pr := parseResponseFromOver(cfg, tlsConn, start)
		pr.RequestBytes = requestBytes
		return pr
	case "H1-Incomplete":
		return parseResponseFromIncomplete(cfg, tlsConn, finSess, start)
	case "Short-ALPN-h2":
		return parseResponseFromShort(cfg, tlsConn, start)
	case "H1-ALPN-h2":
		return parseResponseFromALPN(cfg, tlsConn, start)
	default:
		return finishProbe(base, start, ProbeError, false, "", "", fmt.Sprintf("unknown probe: %s", probe))
	}
}

func finishProbe(base ProbeResult, start time.Time, status ProbeStatus, decisive bool, observed, errStr, reason string) ProbeResult {
	base.Status = status
	base.Decisive = decisive
	base.ObservedBehavior = observed
	base.Error = errStr
	base.Reason = reason
	base.DurationMs = time.Since(start).Milliseconds()
	return base
}

func probeResultFromTLSHandshake(probe string, err error) ProbeResult {
	pr := ProbeResult{
		Name:               probe,
		Status:             ProbeInconclusive,
		AffectedCandidates: make(map[string]CandidateState),
		AffectedHTTPS:      make(map[string]CandidateState),
		Error:              err.Error(),
		Reason:             "TLS handshake failed",
		Decisive:           false,
	}
	markAllTrojan(pr.AffectedCandidates, StateExcluded)

	msg := err.Error()
	if strings.Contains(msg, "no application protocol") {
		setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StatePossible)
		setHTTPSMap(pr.AffectedHTTPS, "Nginx", StatePossible)
		setHTTPSMap(pr.AffectedHTTPS, "Lighttpd", StatePossible)
		pr.Reason = "TLS handshake failed with no application protocol; compatible with Trojan-Go, nginx, or lighttpd"
		pr.AlternativeHTTPS = []string{"Nginx", "Lighttpd"}
	} else if strings.Contains(msg, "server selected unadvertised ALPN protocol") {
		setTrojanMap(pr.AffectedCandidates, "Trojan-Go", StateExcluded)
		setHTTPSMap(pr.AffectedHTTPS, "Apache", StatePossible)
		pr.Reason = "TLS handshake: unadvertised ALPN; Apache possible"
	} else {
		pr.Status = ProbeError
		pr.Reason = "TLS handshake error"
	}
	return pr
}
