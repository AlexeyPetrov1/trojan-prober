package main

import "testing"

func TestMergeCandidateState(t *testing.T) {
	if got := mergeCandidateState(StateUnknown, StatePossible); got != StatePossible {
		t.Fatalf("unknown+possible = %s", got)
	}
	if got := mergeCandidateState(StateExcluded, StatePossible); got != StatePossible {
		t.Fatalf("excluded+possible = %s", got)
	}
	if got := mergeCandidateState(StatePossible, StateDefinite); got != StateDefinite {
		t.Fatalf("possible+definite = %s", got)
	}
}
