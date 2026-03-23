package hmmr

import (
	"bytes"
	"testing"
	"time"
)

func fixedEvent(deviceID, decision string, weight float64, ts time.Time) Event {
	return Event{
		DeviceID:  deviceID,
		Decision:  decision,
		Weight:    weight,
		Timestamp: ts.UTC(),
	}
}

func TestAddEvent(t *testing.T) {
	tree, err := New(DefaultOptions)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	event := fixedEvent("dev-1", "authenticated", 91.5, time.Unix(1710000000, 0))
	leafIndex, root, err := tree.AddEvent(event)
	if err != nil {
		t.Fatalf("AddEvent: %v", err)
	}

	if leafIndex != 0 {
		t.Fatalf("leafIndex = %d, want 0", leafIndex)
	}
	if len(root) != hashSize {
		t.Fatalf("root size = %d, want %d", len(root), hashSize)
	}
	if bytes.Equal(root, make([]byte, hashSize)) {
		t.Fatal("root should not be zero after first insertion")
	}
}

func TestMultipleInsertionsAndDeviceIndex(t *testing.T) {
	tree, err := New(DefaultOptions)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := time.Unix(1710000000, 0)
	events := []Event{
		fixedEvent("dev-a", "registered", 80, ts),
		fixedEvent("dev-b", "authenticated", 81, ts.Add(time.Second)),
		fixedEvent("dev-a", "rejected", 82, ts.Add(2*time.Second)),
	}

	for i, event := range events {
		leafIndex, _, err := tree.AddEvent(event)
		if err != nil {
			t.Fatalf("AddEvent(%d): %v", i, err)
		}
		if leafIndex != i {
			t.Fatalf("leafIndex = %d, want %d", leafIndex, i)
		}
	}

	if tree.LeafCount() != len(events) {
		t.Fatalf("LeafCount = %d, want %d", tree.LeafCount(), len(events))
	}

	indexed := tree.EventsByDevice("dev-a")
	if len(indexed) != 2 {
		t.Fatalf("EventsByDevice count = %d, want 2", len(indexed))
	}
	if indexed[0].LeafIndex != 0 || indexed[1].LeafIndex != 2 {
		t.Fatalf("unexpected device indices: %+v", indexed)
	}
}

func TestGenerateProof(t *testing.T) {
	tree, err := New(DefaultOptions)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := time.Unix(1710000000, 0)
	for i := 0; i < 8; i++ {
		_, _, err := tree.AddEvent(fixedEvent("dev", "authenticated", float64(70+i), ts.Add(time.Duration(i)*time.Second)))
		if err != nil {
			t.Fatalf("AddEvent(%d): %v", i, err)
		}
	}

	proof, err := tree.GenerateProof(6)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if proof.LeafIndex != 6 {
		t.Fatalf("proof leaf index = %d, want 6", proof.LeafIndex)
	}
	if len(proof.Steps) == 0 {
		t.Fatal("expected proof steps")
	}
	for i, step := range proof.Steps {
		if len(step.Siblings) != BranchFactor-1 {
			t.Fatalf("step %d sibling count = %d, want %d", i, len(step.Siblings), BranchFactor-1)
		}
	}
}

func TestVerifyProof(t *testing.T) {
	tree, err := New(DefaultOptions)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := time.Unix(1710000000, 0)
	events := []Event{
		fixedEvent("dev-1", "registered", 70, ts),
		fixedEvent("dev-2", "authenticated", 71, ts.Add(time.Second)),
		fixedEvent("dev-3", "rejected", 72, ts.Add(2*time.Second)),
	}

	for _, event := range events {
		if _, _, err := tree.AddEvent(event); err != nil {
			t.Fatalf("AddEvent: %v", err)
		}
	}

	proof, err := tree.GenerateProof(1)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if !tree.VerifyProof(events[1], proof, tree.GetRoot()) {
		t.Fatal("VerifyProof returned false for valid event")
	}
}

func TestVerifyProofFailsForTamperedEvent(t *testing.T) {
	tree, err := New(DefaultOptions)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := time.Unix(1710000000, 0)
	event := fixedEvent("dev-9", "authenticated", 99, ts)
	if _, _, err := tree.AddEvent(event); err != nil {
		t.Fatalf("AddEvent: %v", err)
	}

	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	tampered := event
	tampered.Decision = "rejected"
	if tree.VerifyProof(tampered, proof, tree.GetRoot()) {
		t.Fatal("VerifyProof returned true for tampered event")
	}
}
