package mmr

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	hashSize = 32
)

// DefaultStorePath is the default persisted MMR event log.
const DefaultStorePath = "mmr_events.json"

// Event represents a registration/authentication decision stored in the MMR.
type Event struct {
	DeviceID  string    `json:"device_id"`
	Decision  string    `json:"decision"`
	Weight    float64   `json:"weight"`
	Timestamp time.Time `json:"timestamp"`
}

// IndexedEvent couples a stored event with its append-only leaf index.
type IndexedEvent struct {
	LeafIndex int   `json:"leaf_index"`
	Event     Event `json:"event"`
}

// VerifiedEvent contains one device event plus its proof-verification result.
type VerifiedEvent struct {
	IndexedEvent
	Proof    Proof `json:"proof"`
	Verified bool  `json:"verified"`
}

// ProofStep captures one binary Merkle proof step inside a mountain.
type ProofStep struct {
	SiblingHash []byte `json:"sibling_hash"`
	IsLeft      bool   `json:"is_left"`
}

// Proof contains the proof for one leaf plus the bagged peak context.
type Proof struct {
	LeafIndex  int         `json:"leaf_index"`
	PeakIndex  int         `json:"peak_index"`
	PeakCount  int         `json:"peak_count"`
	Steps      []ProofStep `json:"steps"`
	OtherPeaks [][]byte    `json:"other_peaks"`
}

// Tree stores append-only event leaves in a real Merkle Mountain Range.
type Tree struct {
	events      []Event
	deviceIndex map[string][]int
	leafHashes  [][]byte
}

type persistedStore struct {
	Events []Event `json:"events"`
}

// New creates an empty MMR-backed event store.
func New() *Tree {
	return &Tree{
		deviceIndex: make(map[string][]int),
	}
}

// LoadEventStore rebuilds a tree from persisted events.
func LoadEventStore(path string) (*Tree, error) {
	tree := New()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return tree, nil
		}
		return nil, err
	}

	var stored persistedStore
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	for _, event := range stored.Events {
		if _, _, err := tree.AddEvent(event); err != nil {
			return nil, err
		}
	}
	return tree, nil
}

// Save writes persisted events to disk.
func (t *Tree) Save(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(persistedStore{Events: t.events}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// AddEvent appends one event, returning the leaf index and new MMR root.
func (t *Tree) AddEvent(event Event) (int, []byte, error) {
	event = normalizeEvent(event)
	hash, err := hashEvent(event)
	if err != nil {
		return -1, nil, err
	}

	leafIndex := len(t.leafHashes)
	t.events = append(t.events, event)
	t.leafHashes = append(t.leafHashes, hash)
	t.deviceIndex[event.DeviceID] = append(t.deviceIndex[event.DeviceID], leafIndex)

	return leafIndex, t.GetRoot(), nil
}

// GetRoot returns the bagged-peaks MMR root.
func (t *Tree) GetRoot() []byte {
	peaks := t.Peaks()
	return bagPeaks(peaks)
}

// LeafCount returns the number of leaves in the MMR.
func (t *Tree) LeafCount() int {
	return len(t.leafHashes)
}

// EventsByDevice returns all events stored for one device.
func (t *Tree) EventsByDevice(deviceID string) []IndexedEvent {
	indices := t.deviceIndex[deviceID]
	out := make([]IndexedEvent, 0, len(indices))
	for _, idx := range indices {
		if idx >= 0 && idx < len(t.events) {
			out = append(out, IndexedEvent{
				LeafIndex: idx,
				Event:     t.events[idx],
			})
		}
	}
	return out
}

// VerifyDeviceEvents generates and verifies proofs for all events stored for one device.
func (t *Tree) VerifyDeviceEvents(deviceID string) ([]VerifiedEvent, []byte, error) {
	events := t.EventsByDevice(deviceID)
	root := t.GetRoot()
	if len(events) == 0 {
		return nil, root, nil
	}

	verified := make([]VerifiedEvent, 0, len(events))
	for _, indexed := range events {
		proof, err := t.GenerateProof(indexed.LeafIndex)
		if err != nil {
			return nil, nil, err
		}
		verified = append(verified, VerifiedEvent{
			IndexedEvent: indexed,
			Proof:        proof,
			Verified:     VerifyProof(indexed.Event, proof, root),
		})
	}
	return verified, root, nil
}

// Peaks returns the current MMR mountain roots from left to right.
func (t *Tree) Peaks() [][]byte {
	if len(t.leafHashes) == 0 {
		return nil
	}

	var peaks [][]byte
	offset := 0
	remaining := len(t.leafHashes)
	for remaining > 0 {
		size := largestPowerOfTwoLE(remaining)
		peak := merkleRoot(t.leafHashes[offset : offset+size])
		peaks = append(peaks, peak)
		offset += size
		remaining -= size
	}
	return peaks
}

// GenerateProof builds a membership proof for one leaf.
func (t *Tree) GenerateProof(leafIndex int) (Proof, error) {
	if leafIndex < 0 || leafIndex >= len(t.leafHashes) {
		return Proof{}, errors.New("mmr: invalid leaf index")
	}

	mountains := t.mountains()
	var target mountain
	found := false
	for _, m := range mountains {
		if leafIndex >= m.start && leafIndex < m.end {
			target = m
			found = true
			break
		}
	}
	if !found {
		return Proof{}, errors.New("mmr: leaf index not found in mountains")
	}

	localIndex := leafIndex - target.start
	steps, err := merkleProof(target.leaves, localIndex)
	if err != nil {
		return Proof{}, err
	}

	otherPeaks := make([][]byte, 0, len(mountains)-1)
	for i, m := range mountains {
		if i == target.index {
			continue
		}
		otherPeaks = append(otherPeaks, cloneBytes(m.root))
	}

	return Proof{
		LeafIndex:  leafIndex,
		PeakIndex:  target.index,
		PeakCount:  len(mountains),
		Steps:      steps,
		OtherPeaks: otherPeaks,
	}, nil
}

// VerifyProof validates an event proof against the expected MMR root.
func VerifyProof(event Event, proof Proof, root []byte) bool {
	event = normalizeEvent(event)
	leafHash, err := hashEvent(event)
	if err != nil {
		return false
	}
	if proof.PeakIndex < 0 || proof.PeakIndex >= proof.PeakCount {
		return false
	}
	if len(proof.OtherPeaks) != proof.PeakCount-1 {
		return false
	}

	current := leafHash
	for _, step := range proof.Steps {
		if len(step.SiblingHash) != hashSize {
			return false
		}
		if step.IsLeft {
			current = hashPair(step.SiblingHash, current)
		} else {
			current = hashPair(current, step.SiblingHash)
		}
	}

	peaks := make([][]byte, 0, proof.PeakCount)
	otherIdx := 0
	for i := 0; i < proof.PeakCount; i++ {
		if i == proof.PeakIndex {
			peaks = append(peaks, current)
			continue
		}
		peaks = append(peaks, proof.OtherPeaks[otherIdx])
		otherIdx++
	}

	return bytes.Equal(bagPeaks(peaks), root)
}

type mountain struct {
	index  int
	start  int
	end    int
	leaves [][]byte
	root   []byte
}

func (t *Tree) mountains() []mountain {
	var mountains []mountain
	offset := 0
	remaining := len(t.leafHashes)
	for mountainIdx := 0; remaining > 0; mountainIdx++ {
		size := largestPowerOfTwoLE(remaining)
		leaves := cloneHashes(t.leafHashes[offset : offset+size])
		mountains = append(mountains, mountain{
			index:  mountainIdx,
			start:  offset,
			end:    offset + size,
			leaves: leaves,
			root:   merkleRoot(leaves),
		})
		offset += size
		remaining -= size
	}
	return mountains
}

func normalizeEvent(event Event) Event {
	event.DeviceID = strings.TrimSpace(event.DeviceID)
	event.Decision = strings.TrimSpace(event.Decision)
	event.Timestamp = event.Timestamp.UTC()
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return event
}

func hashEvent(event Event) ([]byte, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

func hashPair(left, right []byte) []byte {
	buf := make([]byte, 0, len(left)+len(right))
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, hashSize)
	}
	if len(leaves) == 1 {
		return cloneBytes(leaves[0])
	}

	level := cloneHashes(leaves)
	for len(level) > 1 {
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

func merkleProof(leaves [][]byte, leafIndex int) ([]ProofStep, error) {
	if leafIndex < 0 || leafIndex >= len(leaves) {
		return nil, fmt.Errorf("mmr: invalid mountain leaf index %d", leafIndex)
	}
	if len(leaves) == 1 {
		return nil, nil
	}

	level := cloneHashes(leaves)
	index := leafIndex
	steps := make([]ProofStep, 0)
	for len(level) > 1 {
		siblingIndex := index ^ 1
		if siblingIndex < 0 || siblingIndex >= len(level) {
			return nil, errors.New("mmr: invalid sibling index")
		}
		steps = append(steps, ProofStep{
			SiblingHash: cloneBytes(level[siblingIndex]),
			IsLeft:      siblingIndex < index,
		})

		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
		index /= 2
	}
	return steps, nil
}

func bagPeaks(peaks [][]byte) []byte {
	if len(peaks) == 0 {
		return make([]byte, hashSize)
	}
	root := cloneBytes(peaks[len(peaks)-1])
	for i := len(peaks) - 2; i >= 0; i-- {
		root = hashPair(peaks[i], root)
	}
	return root
}

func largestPowerOfTwoLE(n int) int {
	size := 1
	for size<<1 <= n {
		size <<= 1
	}
	return size
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func cloneHashes(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes(in[i])
	}
	return out
}
