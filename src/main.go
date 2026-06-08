package main

import (
	"os"
	"time"
)

func main() {
	cfg := parseConfig()
	startedAt := time.Now()

	var report FinalReport
	if cfg.Probe == "all" {
		report = runAll(cfg)
	} else {
		pr := runProbeWithRetries(cfg, cfg.Probe)
		report = aggregateResults(cfg, []ProbeResult{pr})
		report.StartedAt = startedAt
	}

	emitReport(cfg, report)
	os.Exit(report.ExitCode)
}
