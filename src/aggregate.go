package main

import "strings"

func applyProbeToMatrix(trojan map[string]CandidateEntry, https map[string]CandidateEntry, pr ProbeResult) {
	evidence := pr.Name + ": " + pr.Reason
	for name, state := range pr.AffectedCandidates {
		entry := trojan[name]
		entry.State = mergeCandidateState(entry.State, state)
		appendEvidence(&entry, evidence)
		trojan[name] = entry
	}
	for name, state := range pr.AffectedHTTPS {
		entry := https[name]
		entry.State = mergeCandidateState(entry.State, state)
		appendEvidence(&entry, evidence)
		https[name] = entry
	}
}

func aggregateResults(cfg Config, results []ProbeResult) FinalReport {
	trojan, https := newEmptyCandidateMatrix()
	technicalError := false
	hasProbeError := false

	for _, pr := range results {
		if pr.Status == ProbeError {
			hasProbeError = true
			if pr.Error != "" && !strings.Contains(pr.Error, "broken pipe") {
				technicalError = true
			}
		}
		applyProbeToMatrix(trojan, https, pr)
	}

	report := FinalReport{
		Target:               cfg.ServerAddr,
		PredictionMode:       string(cfg.PredictionMode),
		IncludeH1Incomplete:  cfg.IncludeH1Incomplete,
		StopOnDetected:       cfg.StopOnDetected,
		TrojanCandidates:     trojan,
		HTTPServerCandidates: https,
		Probes:               results,
		TechnicalError:       technicalError,
	}

	definiteTypes := definiteTrojanTypes(trojan)
	decisiveFamily := hasDecisiveTrojanFamily(results)

	switch cfg.PredictionMode {
	case PredictionSpecific:
		report.FinalStatus, report.DetectedType, report.DetectedFamily = verdictSpecific(definiteTypes, decisiveFamily, results, trojan)
	case PredictionAnyTrojan:
		report.FinalStatus, report.DetectedType, report.DetectedFamily = verdictAnyTrojan(definiteTypes, decisiveFamily, results, trojan)
	}

	if report.FinalStatus == StatusNotDetected && allTrojanExcluded(trojan) {
		// keep NOT_DETECTED
	} else if report.FinalStatus == StatusNotDetected && !allTrojanExcluded(trojan) {
		report.FinalStatus = StatusInconclusive
	}

	if hasProbeError && len(results) == 0 {
		report.FinalStatus = StatusInconclusive
		report.TechnicalError = true
	}

	report.ExitCode = exitCodeForReport(report)
	return report
}

func definiteTrojanTypes(trojan map[string]CandidateEntry) []string {
	var types []string
	for _, name := range allTrojanNames {
		if trojan[name].State == StateDefinite {
			types = append(types, name)
		}
	}
	return types
}

func hasDecisiveTrojanFamily(results []ProbeResult) bool {
	for _, pr := range results {
		if pr.Decisive && pr.Status == ProbeDetected {
			return true
		}
	}
	return false
}

func verdictSpecific(definiteTypes []string, decisiveFamily bool, results []ProbeResult, trojan map[string]CandidateEntry) (FinalStatus, *string, *string) {
	switch len(definiteTypes) {
	case 1:
		t := definiteTypes[0]
		return StatusDetected, &t, nil
	case 0:
		if decisiveFamily {
			return StatusInconclusive, nil, nil
		}
		if allTrojanExcluded(trojan) {
			return StatusNotDetected, nil, nil
		}
		return StatusInconclusive, nil, nil
	default:
		return StatusInconclusive, nil, nil
	}
}

func verdictAnyTrojan(definiteTypes []string, decisiveFamily bool, results []ProbeResult, trojan map[string]CandidateEntry) (FinalStatus, *string, *string) {
	if len(definiteTypes) == 1 {
		t := definiteTypes[0]
		family := "Trojan"
		return StatusDetected, &t, &family
	}
	if len(definiteTypes) > 1 {
		family := "Trojan"
		return StatusDetected, nil, &family
	}
	if decisiveFamily {
		family := "Trojan"
		return StatusDetected, nil, &family
	}
	if allTrojanExcluded(trojan) {
		return StatusNotDetected, nil, nil
	}
	return StatusInconclusive, nil, nil
}

func allTrojanExcluded(trojan map[string]CandidateEntry) bool {
	for _, name := range allTrojanNames {
		if trojan[name].State != StateExcluded {
			return false
		}
	}
	return true
}

func exitCodeForReport(report FinalReport) int {
	if report.TechnicalError {
		return 30
	}
	switch report.FinalStatus {
	case StatusDetected:
		return 10
	case StatusNotDetected:
		return 0
	default:
		return 20
	}
}

func shouldStopEarly(cfg Config, report FinalReport) bool {
	if !cfg.StopOnDetected {
		return false
	}
	return report.FinalStatus == StatusDetected
}
