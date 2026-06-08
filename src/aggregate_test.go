package main

import (
	"testing"
	"time"
)

func TestAggregateMatrixContainsAllCandidates(t *testing.T) {
	cfg := Config{
		Probe:          "all",
		ServerAddr:     "test:443",
		PredictionMode: PredictionSpecific,
	}
	report := aggregateResults(cfg, nil)
	if len(report.TrojanCandidates) != 5 {
		t.Fatalf("expected 5 trojan candidates, got %d", len(report.TrojanCandidates))
	}
	if len(report.HTTPServerCandidates) != 6 {
		t.Fatalf("expected 6 https candidates, got %d", len(report.HTTPServerCandidates))
	}
	for _, name := range allTrojanNames {
		if _, ok := report.TrojanCandidates[name]; !ok {
			t.Fatalf("missing trojan candidate %s", name)
		}
	}
	for _, name := range allHTTPServerNames {
		if _, ok := report.HTTPServerCandidates[name]; !ok {
			t.Fatalf("missing https candidate %s", name)
		}
	}
}

func TestSpecificDetectedSingleType(t *testing.T) {
	cfg := Config{PredictionMode: PredictionSpecific, ServerAddr: "h:443"}
	results := []ProbeResult{{
		Name:     "Overbuffer-Incomplete",
		Status:   ProbeDetected,
		Decisive: true,
		AffectedCandidates: map[string]CandidateState{
			"Trojan-Go": StateDefinite,
		},
		Reason: "timeout",
	}}
	report := aggregateResults(cfg, results)
	if report.FinalStatus != StatusDetected {
		t.Fatalf("expected DETECTED, got %s", report.FinalStatus)
	}
	if report.DetectedType == nil || *report.DetectedType != "Trojan-Go" {
		t.Fatal("expected detected Trojan-Go")
	}
	if report.ExitCode != 10 {
		t.Fatalf("expected exit 10, got %d", report.ExitCode)
	}
}

func TestSpecificConflictTwoTypes(t *testing.T) {
	cfg := Config{PredictionMode: PredictionSpecific, ServerAddr: "h:443"}
	results := []ProbeResult{
		{
			Name:     "p1",
			Status:   ProbeDetected,
			Decisive: true,
			AffectedCandidates: map[string]CandidateState{
				"Trojan-Go": StateDefinite,
			},
		},
		{
			Name:     "p2",
			Status:   ProbeDetected,
			Decisive: true,
			AffectedCandidates: map[string]CandidateState{
				"Trojan-GFW": StateDefinite,
			},
		},
	}
	report := aggregateResults(cfg, results)
	if report.FinalStatus != StatusInconclusive {
		t.Fatalf("expected INCONCLUSIVE on conflict, got %s", report.FinalStatus)
	}
}

func TestAnyTrojanDetectedWithoutConcreteType(t *testing.T) {
	cfg := Config{PredictionMode: PredictionAnyTrojan, ServerAddr: "h:443"}
	results := []ProbeResult{
		{
			Name:     "p1",
			Status:   ProbeDetected,
			Decisive: true,
			AffectedCandidates: map[string]CandidateState{
				"Trojan-Go":  StateDefinite,
				"Trojan-GFW": StateDefinite,
			},
		},
	}
	report := aggregateResults(cfg, results)
	if report.FinalStatus != StatusDetected {
		t.Fatalf("expected DETECTED, got %s", report.FinalStatus)
	}
	if report.DetectedFamily == nil || *report.DetectedFamily != "Trojan" {
		t.Fatal("expected detected_family Trojan")
	}
}

func TestAggregateOrderIndependent(t *testing.T) {
	cfg := Config{PredictionMode: PredictionSpecific, ServerAddr: "h:443"}
	a := []ProbeResult{
		{Name: "H1-Close", AffectedCandidates: map[string]CandidateState{"Trojan-GFW": StatePossible}, Reason: "a"},
		{Name: "Overbuffer-Incomplete", AffectedCandidates: map[string]CandidateState{"Trojan-Go": StateDefinite}, Status: ProbeDetected, Decisive: true, Reason: "b"},
	}
	b := []ProbeResult{a[1], a[0]}
	r1 := aggregateResults(cfg, a)
	r2 := aggregateResults(cfg, b)
	if r1.FinalStatus != r2.FinalStatus {
		t.Fatalf("order changed status: %s vs %s", r1.FinalStatus, r2.FinalStatus)
	}
	if r1.TrojanCandidates["Trojan-Go"].State != r2.TrojanCandidates["Trojan-Go"].State {
		t.Fatal("order changed trojan-go state")
	}
}

func TestBuildProbeSetFourCombinations(t *testing.T) {
	base := Config{Probe: "all"}
	noInc := buildProbeSet(base)
	if len(noInc) != 4 {
		t.Fatalf("expected 4 probes without incomplete, got %d", len(noInc))
	}
	withInc := buildProbeSet(Config{Probe: "all", IncludeH1Incomplete: true})
	if len(withInc) != 5 {
		t.Fatalf("expected 5 probes with incomplete, got %d", len(withInc))
	}
	_ = time.Now()
}
