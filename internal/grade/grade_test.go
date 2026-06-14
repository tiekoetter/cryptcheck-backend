package grade

import (
	"testing"

	"github.com/tiekoetter/cryptcheck-backend/internal/state"
)

func TestCalculateInvalidIdentity(t *testing.T) {
	if got := Calculate(false, true, state.Empty()); got != "V" {
		t.Fatalf("grade = %q, want V", got)
	}
}

func TestCalculateUntrusted(t *testing.T) {
	if got := Calculate(true, false, state.Empty()); got != "T" {
		t.Fatalf("grade = %q, want T", got)
	}
}

func TestCalculateWithTLS10Error(t *testing.T) {
	states := state.Empty()
	states[state.Error]["tlsv1_0"] = true
	if got := Calculate(true, true, states); got != "F" {
		t.Fatalf("grade = %q, want F", got)
	}
}

func TestCalculateAllBest(t *testing.T) {
	states := state.Empty()
	states[state.Good]["aead"] = true
	states[state.Great]["hsts"] = true
	states[state.Best]["foo"] = true
	if got := Calculate(true, true, states); got != "A+" {
		t.Fatalf("grade = %q, want A+", got)
	}
}

func TestCalculateSomeBest(t *testing.T) {
	states := state.Empty()
	states[state.Good]["aead"] = true
	states[state.Great]["hsts"] = true
	states[state.Best]["foo"] = true
	states[state.Best]["bar"] = false
	if got := Calculate(true, true, states); got != "A" {
		t.Fatalf("grade = %q, want A", got)
	}
}
