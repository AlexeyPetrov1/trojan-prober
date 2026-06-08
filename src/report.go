package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/liuylv/trojan-prober/src/log"
)

func emitReport(cfg Config, report FinalReport) {
	switch cfg.OutputFormat {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			log.Crucial("Failed to encode JSON: %v", err)
			os.Exit(30)
		}
		if cfg.OutputPath != "" {
			if err := os.WriteFile(cfg.OutputPath, data, 0644); err != nil {
				log.Crucial("Failed to write output file: %v", err)
				os.Exit(30)
			}
		}
		fmt.Println(string(data))
	default:
		printTextReport(report)
		if cfg.OutputPath != "" {
			data, _ := json.MarshalIndent(report, "", "  ")
			_ = os.WriteFile(cfg.OutputPath, data, 0644)
		}
	}
}

func printTextReport(report FinalReport) {
	log.Crucial("Status: %s", report.FinalStatus)
	if report.DetectedType != nil {
		log.Crucial("Detected type: %s", *report.DetectedType)
	}
	if report.DetectedFamily != nil {
		log.Crucial("Detected family: %s", *report.DetectedFamily)
	}
	if report.FinalStatus == StatusInconclusive {
		log.Crucial("Prediction mode: %s (candidates are not detections)", report.PredictionMode)
		possibleTrojans := namesWithState(report.TrojanCandidates, StatePossible)
		possibleHTTPS := namesWithState(report.HTTPServerCandidates, StatePossible)
		if len(possibleTrojans) > 0 {
			log.Crucial("Candidate Trojan types: %s", strings.Join(possibleTrojans, ", "))
		}
		if len(possibleHTTPS) > 0 {
			log.Crucial("Alternative HTTPS servers: %s", strings.Join(possibleHTTPS, ", "))
		}
	}
	log.Crucial("--- Trojan candidates ---")
	for _, name := range allTrojanNames {
		e := report.TrojanCandidates[name]
		log.Crucial("  %s: %s", name, e.State)
	}
	log.Crucial("--- HTTPS server candidates ---")
	for _, name := range allHTTPServerNames {
		e := report.HTTPServerCandidates[name]
		log.Crucial("  %s: %s", name, e.State)
	}
	for _, pr := range report.Probes {
		log.Crucial("Probe %s: %s — %s (%dms)", pr.Name, pr.Status, pr.Reason, pr.DurationMs)
	}
}

func namesWithState(m map[string]CandidateEntry, state CandidateState) []string {
	var names []string
	for _, n := range allTrojanNames {
		if e, ok := m[n]; ok && e.State == state {
			names = append(names, n)
		}
	}
	for _, n := range allHTTPServerNames {
		if e, ok := m[n]; ok && e.State == state {
			names = append(names, n)
		}
	}
	return names
}
