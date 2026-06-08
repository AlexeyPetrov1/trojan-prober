package main

import (
	"testing"
	"time"
)

func TestHandleResponseFromOverHTTP431(t *testing.T) {
	body := "HTTP/1.1 431 Request Header Fields Too Large\r\nServer: Caddy\r\n\r\n"
	pr := handleResponseFromOver([]byte(body), time.Now())
	if pr.Status != ProbeExcluded {
		t.Fatalf("expected EXCLUDED, got %s", pr.Status)
	}
	if pr.AffectedCandidates["Trojan-Go"] != StateExcluded {
		t.Fatalf("expected Trojan-Go EXCLUDED, got %s", pr.AffectedCandidates["Trojan-Go"])
	}
	if pr.AffectedHTTPS["Caddy"] != StatePossible {
		t.Fatalf("expected Caddy POSSIBLE, got %s", pr.AffectedHTTPS["Caddy"])
	}
}

func TestHandleResponseFromOverNonHTTP(t *testing.T) {
	pr := handleResponseFromOver([]byte("binary"), time.Now())
	if pr.Status != ProbeDetected || !pr.Decisive {
		t.Fatalf("expected decisive DETECTED for non-HTTP, got %s decisive=%v", pr.Status, pr.Decisive)
	}
	if pr.AffectedCandidates["Trojan-RS"] != StateDefinite {
		t.Fatal("expected Trojan-RS DEFINITE")
	}
}
