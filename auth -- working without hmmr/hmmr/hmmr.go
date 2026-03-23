package hmmr

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// BranchFactor defines the fixed K-ary fanout requested for the accumulator.
	BranchFactor = 6
	hashSize     = 32
)

// DefaultStorePath is the default event-log file shared by registration/auth flows.
const DefaultStorePath = "hmmr_events.json"

// Options controls hashing and optional metrics collection.
type Options struct {
	HashAlgorithm  string
	CollectMetrics bool
}

// DefaultOptions defines the default configuration used when options are omitted.
var DefaultOptions = Options{HashAlgorithm: "sha256", CollectMetrics: false}

// Metrics captures timing and resource usage gathered during tree construction.
type Metrics struct {
	LeafCount       int
	BuildTimeMs     float64
	ProofTimeMs     float64
	ProofSizeBytes  int
	Depth           int
	MemoryUsedBytes uint64
}

// Event represents a registration/authentication decision stored in the HMMR.
type Event struct {
	DeviceID  string    `json:"device_id"`
	Decision  string    `json:"decision"`
	Weight    float64   `json:"weight"`
	Timestamp time.Time `json:"timestamp"`
}

// IndexedEvent couples an event with its append-only leaf index.
type IndexedEvent struct {
	LeafIndex int   `json:"leaf_index"`
	Event     Event `json:"event"`
}

// ProofStep holds the sibling hashes needed for one tree level.
type ProofStep struct {
	Position int      `json:"position"`
	Siblings [][]byte `json:"siblings"`
}

// Proof is a membership proof for one leaf/event.
type Proof struct {
	LeafIndex int         `json:"leaf_index"`
	Steps     []ProofStep `json:"steps"`
}

type hashAdapter struct {
	fn func([]byte) []byte
}

// Tree stores append-only event leaves and supports Merkle-style proofs with K=6.
type Tree struct {
	hashAdapter hashAdapter
	events      []Event
	deviceIndex map[string][]int
	leafHashes  [][]byte
	levels      [][][]byte
	peaks       [][]byte
}

type persistedStore struct {
	Events []Event `json:"events"`
}

func selectHashAdapter(name string) (hashAdapter, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "sha256":
		return hashAdapter{
			fn: func(data []byte) []byte {
				sum := sha256.Sum256(data)
				out := make([]byte, len(sum))
				copy(out, sum[:])
				return out
			},
		}, nil
	default:
		return hashAdapter{}, fmt.Errorf("hmmr: unknown hash algorithm %q", name)
	}
}

// New creates an empty Tree based on the provided options.
func New(opts Options) (*Tree, error) {
	if opts.HashAlgorithm == "" {
		opts.HashAlgorithm = DefaultOptions.HashAlgorithm
	}
	adapter, err := selectHashAdapter(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	return &Tree{
		hashAdapter: adapter,
		deviceIndex: make(map[string][]int),
	}, nil
}

// LoadEventStore rebuilds an event tree from a persisted JSON file.
func LoadEventStore(path string, opts Options) (*Tree, error) {
	tree, err := New(opts)
	if err != nil {
		return nil, err
	}

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

// Save writes the event log to disk. Raw block-only leaves are intentionally not persisted.
func (t *Tree) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	payload := persistedStore{Events: append([]Event(nil), t.events...)}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// AddEvent hashes and stores an event, returning the new leaf index and root.
func (t *Tree) AddEvent(event Event) (int, []byte, error) {
	event = normalizeEvent(event)
	hash, err := t.hashEvent(event)
	if err != nil {
		return -1, nil, err
	}

	leafIndex := len(t.leafHashes)
	t.events = append(t.events, event)
	t.deviceIndex[event.DeviceID] = append(t.deviceIndex[event.DeviceID], leafIndex)
	t.leafHashes = append(t.leafHashes, hash)
	t.rebuild()

	return leafIndex, t.GetRoot(), nil
}

// EventsByDevice returns all stored events for one device in insertion order.
func (t *Tree) EventsByDevice(deviceID string) []IndexedEvent {
	indices := t.deviceIndex[deviceID]
	out := make([]IndexedEvent, 0, len(indices))
	for _, idx := range indices {
		if idx >= 0 && idx < len(t.events) {
			out = append(out, IndexedEvent{LeafIndex: idx, Event: t.events[idx]})
		}
	}
	return out
}

// GetRoot returns the current accumulator root.
func (t *Tree) GetRoot() []byte {
	if len(t.levels) == 0 || len(t.levels[len(t.levels)-1]) == 0 {
		return t.zeroHash()
	}
	return cloneBytes(t.levels[len(t.levels)-1][0])
}

// Root preserves compatibility with the existing block-builder usage.
func (t *Tree) Root() []byte {
	return t.GetRoot()
}

// Peaks returns the current rightmost nodes per level.
func (t *Tree) Peaks() [][]byte {
	out := make([][]byte, len(t.peaks))
	for i := range t.peaks {
		out[i] = cloneBytes(t.peaks[i])
	}
	return out
}

// AddLeaf ingests raw data, hashes it, and updates the accumulator.
func (t *Tree) AddLeaf(data []byte) []byte {
	return t.AddLeafHash(t.hashAdapter.fn(data))
}

// AddLeafHash ingests a pre-hashed leaf and updates the accumulator.
func (t *Tree) AddLeafHash(hash []byte) []byte {
	if len(hash) != hashSize {
		panic("hmmr: invalid leaf hash size")
	}
	t.leafHashes = append(t.leafHashes, cloneBytes(hash))
	t.rebuild()
	return t.GetRoot()
}

// LeafCount returns the number of leaves currently present.
func (t *Tree) LeafCount() int {
	return len(t.leafHashes)
}

// Depth returns the current tree depth, excluding the leaf level.
func (t *Tree) Depth() int {
	if len(t.levels) == 0 {
		return 0
	}
	return len(t.levels) - 1
}

// GenerateProof returns the proof for the leaf at the provided index.
func (t *Tree) GenerateProof(leafIndex int) (Proof, error) {
	if leafIndex < 0 || leafIndex >= len(t.leafHashes) {
		return Proof{}, errors.New("hmmr: invalid leaf index")
	}
	if len(t.levels) == 0 {
		return Proof{LeafIndex: leafIndex}, nil
	}

	proof := Proof{
		LeafIndex: leafIndex,
		Steps:     make([]ProofStep, 0, len(t.levels)-1),
	}
	index := leafIndex

	for levelIdx := 0; levelIdx < len(t.levels)-1; levelIdx++ {
		level := t.levels[levelIdx]
		groupStart := (index / BranchFactor) * BranchFactor
		position := index % BranchFactor
		siblings := make([][]byte, 0, BranchFactor-1)

		for i := 0; i < BranchFactor; i++ {
			nodeIndex := groupStart + i
			hash := t.zeroHash()
			if nodeIndex < len(level) {
				hash = level[nodeIndex]
			}
			if i == position {
				continue
			}
			siblings = append(siblings, cloneBytes(hash))
		}

		proof.Steps = append(proof.Steps, ProofStep{
			Position: position,
			Siblings: siblings,
		})
		index /= BranchFactor
	}

	return proof, nil
}

// VerifyProof validates an event membership proof against the supplied root.
func (t *Tree) VerifyProof(event Event, proof Proof, root []byte) bool {
	hash, err := t.hashEvent(normalizeEvent(event))
	if err != nil {
		return false
	}

	current := hash
	for _, step := range proof.Steps {
		if step.Position < 0 || step.Position >= BranchFactor || len(step.Siblings) != BranchFactor-1 {
			return false
		}

		children := make([][]byte, BranchFactor)
		siblingIdx := 0
		for i := 0; i < BranchFactor; i++ {
			if i == step.Position {
				children[i] = current
				continue
			}
			if siblingIdx >= len(step.Siblings) || len(step.Siblings[siblingIdx]) != hashSize {
				return false
			}
			children[i] = step.Siblings[siblingIdx]
			siblingIdx++
		}
		current = t.hashChildren(children)
	}

	return bytes.Equal(current, root)
}

// BuildTree constructs a tree from the provided leaves and optionally collects metrics.
func BuildTree(leaves [][]byte, opts Options) (*Tree, *Metrics, error) {
	tree, err := New(opts)
	if err != nil {
		return nil, nil, err
	}
	if len(leaves) == 0 {
		return tree, &Metrics{LeafCount: 0}, nil
	}

	buildStart := time.Now()
	for _, leaf := range leaves {
		tree.AddLeaf(leaf)
	}
	buildDuration := time.Since(buildStart)

	if !opts.CollectMetrics {
		return tree, nil, nil
	}

	runtime.GC()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metrics := &Metrics{
		LeafCount:       len(leaves),
		BuildTimeMs:     float64(buildDuration.Nanoseconds()) / 1e6,
		MemoryUsedBytes: memStats.Alloc,
		Depth:           tree.Depth(),
	}

	mid := len(leaves) / 2
	proofStart := time.Now()
	proof, err := tree.GenerateProof(mid)
	proofDuration := time.Since(proofStart)
	if err == nil {
		metrics.ProofTimeMs = float64(proofDuration.Nanoseconds()) / 1e6
		for _, step := range proof.Steps {
			for _, sibling := range step.Siblings {
				metrics.ProofSizeBytes += len(sibling)
			}
		}
	}

	return tree, metrics, nil
}

func (t *Tree) rebuild() {
	if len(t.leafHashes) == 0 {
		t.levels = nil
		t.peaks = nil
		return
	}

	levels := make([][][]byte, 0, 8)
	current := cloneHashes(t.leafHashes)
	levels = append(levels, current)

	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+BranchFactor-1)/BranchFactor)
		for i := 0; i < len(current); i += BranchFactor {
			children := make([][]byte, BranchFactor)
			for j := 0; j < BranchFactor; j++ {
				idx := i + j
				if idx < len(current) {
					children[j] = current[idx]
				} else {
					children[j] = t.zeroHash()
				}
			}
			next = append(next, t.hashChildren(children))
		}
		levels = append(levels, next)
		current = next
	}

	t.levels = levels
	t.peaks = make([][]byte, 0, len(levels))
	for _, level := range levels {
		t.peaks = append(t.peaks, cloneBytes(level[len(level)-1]))
	}
}

func (t *Tree) hashEvent(event Event) ([]byte, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return t.hashAdapter.fn(data), nil
}

func (t *Tree) hashChildren(children [][]byte) []byte {
	xor := make([]byte, hashSize)
	for i := 0; i < BranchFactor; i++ {
		child := children[i]
		for j := 0; j < hashSize; j++ {
			xor[j] ^= child[j]
		}
	}
	return t.hashAdapter.fn(xor)
}

func (t *Tree) zeroHash() []byte {
	return make([]byte, hashSize)
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
