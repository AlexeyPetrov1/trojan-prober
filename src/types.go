package main

import "time"

// CandidateState is the aggregated state for a Trojan type or HTTPS server.
type CandidateState string

const (
	StateUnknown  CandidateState = "UNKNOWN"
	StatePossible CandidateState = "POSSIBLE"
	StateDefinite CandidateState = "DEFINITE"
	StateExcluded CandidateState = "EXCLUDED"
)

// FinalStatus is the top-level verdict.
type FinalStatus string

const (
	StatusDetected     FinalStatus = "DETECTED"
	StatusNotDetected  FinalStatus = "NOT_DETECTED"
	StatusInconclusive FinalStatus = "INCONCLUSIVE"
)

// ProbeStatus describes a single probe outcome.
type ProbeStatus string

const (
	ProbeDetected     ProbeStatus = "DETECTED"
	ProbeExcluded     ProbeStatus = "EXCLUDED"
	ProbeInconclusive ProbeStatus = "INCONCLUSIVE"
	ProbeError        ProbeStatus = "ERROR"
)

// PredictionMode selects how the final verdict is derived.
type PredictionMode string

const (
	PredictionSpecific  PredictionMode = "specific"
	PredictionAnyTrojan PredictionMode = "any-trojan"
)

var (
	allTrojanNames = []string{
		"Trojan-GFW",
		"Trojan-Go",
		"Trojan-R",
		"Trojan-RS",
		"Caddy-Trojan",
	}
	allHTTPServerNames = []string{
		"Nginx",
		"Apache",
		"Caddy",
		"Tomcat",
		"Lighttpd",
		"IIS",
	}
)

// CandidateEntry holds state and evidence for one candidate.
type CandidateEntry struct {
	State    CandidateState `json:"state"`
	Evidence []string       `json:"evidence"`
}

// ProbeResult is the outcome of one probe run.
type ProbeResult struct {
	Name               string                     `json:"name"`
	Status             ProbeStatus                `json:"status"`
	Decisive           bool                       `json:"decisive"`
	ObservedBehavior   string                     `json:"observed_behavior,omitempty"`
	AffectedCandidates map[string]CandidateState  `json:"affected_candidates,omitempty"`
	AffectedHTTPS      map[string]CandidateState  `json:"affected_https,omitempty"`
	AlternativeHTTPS   []string                   `json:"alternative_https,omitempty"`
	Reason             string                     `json:"reason"`
	DurationMs         int64                      `json:"duration_ms"`
	Error              string                     `json:"error,omitempty"`
	RequestBytes       int                        `json:"request_bytes,omitempty"`
	TrojanFamilyHit    bool                       `json:"trojan_family_hit,omitempty"`
}

// FinalReport is the complete run output.
type FinalReport struct {
	Target                string                    `json:"target"`
	StartedAt             time.Time                 `json:"started_at"`
	PredictionMode        string                    `json:"prediction_mode"`
	IncludeH1Incomplete   bool                      `json:"include_h1_incomplete"`
	StopOnDetected        bool                      `json:"stop_on_detected"`
	FinalStatus           FinalStatus               `json:"final_status"`
	DetectedType          *string                   `json:"detected_type"`
	DetectedFamily        *string                   `json:"detected_family"`
	TrojanCandidates      map[string]CandidateEntry `json:"trojan_candidates"`
	HTTPServerCandidates  map[string]CandidateEntry `json:"http_server_candidates"`
	Probes                []ProbeResult             `json:"probes"`
	ExitCode              int                       `json:"exit_code"`
	TechnicalError        bool                      `json:"technical_error"`
}

func newEmptyCandidateMatrix() (map[string]CandidateEntry, map[string]CandidateEntry) {
	trojan := make(map[string]CandidateEntry, len(allTrojanNames))
	https := make(map[string]CandidateEntry, len(allHTTPServerNames))
	for _, name := range allTrojanNames {
		trojan[name] = CandidateEntry{State: StateUnknown, Evidence: []string{}}
	}
	for _, name := range allHTTPServerNames {
		https[name] = CandidateEntry{State: StateUnknown, Evidence: []string{}}
	}
	return trojan, https
}

func mergeCandidateState(current, incoming CandidateState) CandidateState {
	if incoming == StateDefinite || current == StateDefinite {
		return StateDefinite
	}
	if incoming == StateExcluded {
		if current == StatePossible {
			return StatePossible
		}
		if current == StateUnknown {
			return StateExcluded
		}
	}
	if incoming == StatePossible {
		if current == StateExcluded {
			return StatePossible
		}
		if current == StateUnknown {
			return StatePossible
		}
	}
	return current
}

func appendEvidence(entry *CandidateEntry, evidence string) {
	if evidence == "" {
		return
	}
	for _, e := range entry.Evidence {
		if e == evidence {
			return
		}
	}
	entry.Evidence = append(entry.Evidence, evidence)
}
