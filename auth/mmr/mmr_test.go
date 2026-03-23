package mmr

import (
	"bytes"
	"testing"
	"time"
)

func testEvent(deviceID, decision string, weight float64, ts time.Time) Event {
	return Event{
		DeviceID:  deviceID,
		Decision:  decision,
		Weight:    weight,
		Timestamp: ts.UTC(),
	}
}

func TestAddEvent(t *testing.T) {
	tree := New()
	event := testEvent("dev-1", "registered", 87, time.Unix(1710000000, 0))

	leafIndex, root, err := tree.AddEvent(event)
	if err != nil {
		t.Fatalf("AddEvent: %v", err)
	}
	if leafIndex != 0 {
		t.Fatalf("leafIndex = %d, want 0", leafIndex)
	}
	if len(root) != hashSize {
		t.Fatalf("root len = %d, want %d", len(root), hashSize)
	}
	if bytes.Equal(root, make([]byte, hashSize)) {
		t.Fatal("root should not be zero")
	}
}

func TestMultipleInsertionsAndDeviceIndex(t *testing.T) {
	tree := New()
	ts := time.Unix(1710000000, 0)
	events := []Event{
		testEvent("dev-a", "registered", 80, ts),
		testEvent("dev-b", "authenticated", 81, ts.Add(time.Second)),
		testEvent("dev-a", "rejected", 82, ts.Add(2*time.Second)),
		testEvent("dev-c", "authenticated", 83, ts.Add(3*time.Second)),
	}

	for i, event := range events {
		index, _, err := tree.AddEvent(event)
		if err != nil {
			t.Fatalf("AddEvent(%d): %v", i, err)
		}
		if index != i {
			t.Fatalf("leaf index = %d, want %d", index, i)
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
		t.Fatalf("unexpected leaf indices: %+v", indexed)
	}
}

func TestGenerateAndVerifyProof(t *testing.T) {
	tree := New()
	ts := time.Unix(1710000000, 0)
	events := []Event{
		testEvent("dev-1", "registered", 70, ts),
		testEvent("dev-2", "authenticated", 71, ts.Add(time.Second)),
		testEvent("dev-3", "rejected", 72, ts.Add(2*time.Second)),
		testEvent("dev-4", "authenticated", 73, ts.Add(3*time.Second)),
		testEvent("dev-5", "registered", 74, ts.Add(4*time.Second)),
	}

	for _, event := range events {
		if _, _, err := tree.AddEvent(event); err != nil {
			t.Fatalf("AddEvent: %v", err)
		}
	}

	proof, err := tree.GenerateProof(3)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if proof.LeafIndex != 3 {
		t.Fatalf("proof leaf index = %d, want 3", proof.LeafIndex)
	}
	if proof.PeakCount == 0 {
		t.Fatal("expected at least one peak")
	}
	if !VerifyProof(events[3], proof, tree.GetRoot()) {
		t.Fatal("VerifyProof returned false for valid proof")
	}
}

func TestVerifyProofFailsForTamperedEvent(t *testing.T) {
	tree := New()
	ts := time.Unix(1710000000, 0)
	event := testEvent("dev-9", "authenticated", 99, ts)

	if _, _, err := tree.AddEvent(event); err != nil {
		t.Fatalf("AddEvent: %v", err)
	}

	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	tampered := event
	tampered.Decision = "rejected"
	if VerifyProof(tampered, proof, tree.GetRoot()) {
		t.Fatal("VerifyProof returned true for tampered event")
	}
}
