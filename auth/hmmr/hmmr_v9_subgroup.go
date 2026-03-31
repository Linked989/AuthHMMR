package hmmr

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultSubgroupStorePath is the default persisted auth-event store for subgroup HMMR.
const DefaultSubgroupStorePath = "hmmr_events.json"

type subgroupNodeInfo struct {
	Hash        []byte
	ActualArity int
}

// SubgroupProofStep captures one proof step in the subgroup-compressed HMMR.
type SubgroupProofStep struct {
	Level            int      `json:"level"`
	GroupIndex       int      `json:"group_index"`
	PositionInGroup  int      `json:"position_in_group"`
	ActualArity      int      `json:"actual_arity"`
	SubgroupSize     int      `json:"subgroup_size"`
	SubgroupIndex    int      `json:"subgroup_index"`
	PositionInSub    int      `json:"position_in_sub"`
	ActualInSubgroup int      `json:"actual_in_subgroup"`
	LocalSiblings    [][]byte `json:"local_siblings"`
	SubgroupSiblings [][]byte `json:"subgroup_siblings"`
}

// SubgroupProof is a membership proof for one leaf.
type SubgroupProof struct {
	LeafIndex int                 `json:"leaf_index"`
	LeafHash  []byte              `json:"leaf_hash"`
	Steps     []SubgroupProofStep `json:"steps"`
}

// SubgroupHMMR is the library adaptation of work/hmmr_v9_subgroup.go.
type SubgroupHMMR struct {
	Arity      int
	Subgroup   int
	HashName   string
	NewHasher  func() hash.Hash
	Levels     [][]subgroupNodeInfo
	Root       *subgroupNodeInfo
	NullHashes map[string][]byte
}

// VerifiedSubgroupEvent contains one event and the proof verification outcome.
type VerifiedSubgroupEvent struct {
	IndexedEvent
	Proof    *SubgroupProof `json:"proof"`
	Verified bool           `json:"verified"`
}

// ProofGenerationMetric captures proof generation timing for one recorded event.
type ProofGenerationMetric struct {
	EventID               string    `json:"event_id"`
	LeafIndex             int       `json:"leaf_index"`
	ProofGenerationTimeMs float64   `json:"proof_generation_time_ms"`
	TotalRecordedEvents   int       `json:"total_number_of_recorded_events"`
	ProofSizeBytes        int       `json:"proof_size_bytes"`
	TimestampUTC          time.Time `json:"timestamp_utc"`
}

// SubgroupEventStore keeps events and builds proofs from the subgroup HMMR.
type SubgroupEventStore struct {
	Arity    int
	Subgroup int
	HashName string

	events      []Event
	leafData    [][]byte
	deviceIndex map[string][]int
	engine      *SubgroupHMMR
}

type persistedSubgroupStore struct {
	Arity    int     `json:"arity"`
	Subgroup int     `json:"subgroup"`
	HashName string  `json:"hash_name"`
	Events   []Event `json:"events"`
}

// NewSubgroupHMMR creates the subgroup-compressed HMMR.
func NewSubgroupHMMR(arity int, subgroup int, hashName string) *SubgroupHMMR {
	if arity < 2 {
		panic("arity must be >= 2")
	}
	if subgroup < 2 || subgroup > arity {
		panic("subgroup must be between 2 and arity")
	}
	if arity%subgroup != 0 {
		panic("arity must be divisible by subgroup")
	}

	h := &SubgroupHMMR{
		Arity:      arity,
		Subgroup:   subgroup,
		HashName:   strings.ToLower(hashName),
		NullHashes: make(map[string][]byte),
	}
	switch h.HashName {
	case "sha512":
		h.NewHasher = sha512.New
	default:
		h.HashName = "sha256"
		h.NewHasher = sha256.New
	}
	return h
}

// NewSubgroupEventStore initializes an empty store with the provided parameters.
func NewSubgroupEventStore(arity int, subgroup int, hashName string) *SubgroupEventStore {
	return &SubgroupEventStore{
		Arity:       arity,
		Subgroup:    subgroup,
		HashName:    hashName,
		deviceIndex: make(map[string][]int),
		engine:      NewSubgroupHMMR(arity, subgroup, hashName),
	}
}

// LoadSubgroupEventStore loads and rebuilds a subgroup HMMR event store.
func LoadSubgroupEventStore(path string, arity int, subgroup int, hashName string) (*SubgroupEventStore, error) {
	store := NewSubgroupEventStore(arity, subgroup, hashName)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}

	var persisted persistedSubgroupStore
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, err
	}

	if persisted.Arity > 0 {
		store.Arity = persisted.Arity
	}
	if persisted.Subgroup > 0 {
		store.Subgroup = persisted.Subgroup
	}
	if strings.TrimSpace(persisted.HashName) != "" {
		store.HashName = persisted.HashName
	}
	store.engine = NewSubgroupHMMR(store.Arity, store.Subgroup, store.HashName)

	for _, event := range persisted.Events {
		if _, _, err := store.AddEvent(event); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// Save persists events and HMMR parameters.
func (s *SubgroupEventStore) Save(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	payload := persistedSubgroupStore{
		Arity:    s.Arity,
		Subgroup: s.Subgroup,
		HashName: s.engine.HashName,
		Events:   append([]Event(nil), s.events...),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// AddEvent appends one device interaction to subgroup HMMR and returns index/root.
func (s *SubgroupEventStore) AddEvent(event Event) (int, []byte, error) {
	event = normalizeEvent(event)
	payload, err := json.Marshal(event)
	if err != nil {
		return -1, nil, err
	}

	leafIndex := len(s.leafData)
	s.events = append(s.events, event)
	s.leafData = append(s.leafData, payload)
	s.deviceIndex[event.DeviceID] = append(s.deviceIndex[event.DeviceID], leafIndex)

	s.engine.Build(s.leafData)
	return leafIndex, s.GetRoot(), nil
}

// GetRoot returns the current subgroup HMMR root.
func (s *SubgroupEventStore) GetRoot() []byte {
	return s.engine.RootHash()
}

// RootHex returns a hex encoded root hash.
func (s *SubgroupEventStore) RootHex() string {
	return hex.EncodeToString(s.GetRoot())
}

// TotalRecordedEvents returns the number of events stored in HMMR.
func (s *SubgroupEventStore) TotalRecordedEvents() int {
	return len(s.events)
}

// EventsByDevice returns stored events for one device.
func (s *SubgroupEventStore) EventsByDevice(deviceID string) []IndexedEvent {
	indices := s.deviceIndex[deviceID]
	out := make([]IndexedEvent, 0, len(indices))
	for _, idx := range indices {
		if idx >= 0 && idx < len(s.events) {
			out = append(out, IndexedEvent{
				LeafIndex: idx,
				Event:     s.events[idx],
			})
		}
	}
	return out
}

// VerifyDeviceEvents verifies all proofs for one device against current root.
func (s *SubgroupEventStore) VerifyDeviceEvents(deviceID string) ([]VerifiedSubgroupEvent, []byte, error) {
	indexed := s.EventsByDevice(deviceID)
	root := s.GetRoot()
	if len(indexed) == 0 {
		return nil, root, nil
	}

	out := make([]VerifiedSubgroupEvent, 0, len(indexed))
	for _, item := range indexed {
		proof := s.engine.Proof(item.LeafIndex)
		if proof == nil {
			return nil, nil, fmt.Errorf("cannot generate proof for leaf %d", item.LeafIndex)
		}
		payload, err := json.Marshal(item.Event)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, VerifiedSubgroupEvent{
			IndexedEvent: item,
			Proof:        proof,
			Verified:     s.engine.Verify(payload, proof),
		})
	}
	return out, root, nil
}

// GenerateProofByLeafIndex returns the proof for a leaf index.
func (s *SubgroupEventStore) GenerateProofByLeafIndex(leafIdx int) (*SubgroupProof, error) {
	if leafIdx < 0 || leafIdx >= len(s.leafData) {
		return nil, fmt.Errorf("invalid leaf index %d", leafIdx)
	}
	proof := s.engine.Proof(leafIdx)
	if proof == nil {
		return nil, fmt.Errorf("proof generation failed for leaf index %d", leafIdx)
	}
	return proof, nil
}

// MeasureProofGenerationByLeafIndex measures proof generation time for one recorded event.
func (s *SubgroupEventStore) MeasureProofGenerationByLeafIndex(leafIdx int) (*ProofGenerationMetric, error) {
	start := time.Now()
	proof, err := s.GenerateProofByLeafIndex(leafIdx)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)
	return &ProofGenerationMetric{
		EventID:               fmt.Sprintf("leaf:%d", leafIdx),
		LeafIndex:             leafIdx,
		ProofGenerationTimeMs: float64(elapsed.Nanoseconds()) / 1e6,
		TotalRecordedEvents:   len(s.events),
		ProofSizeBytes:        subgroupProofSizeBytes(proof),
		TimestampUTC:          time.Now().UTC(),
	}, nil
}

func (h *SubgroupHMMR) digest(parts ...[]byte) []byte {
	x := h.NewHasher()
	for _, p := range parts {
		_, _ = x.Write(p)
	}
	return x.Sum(nil)
}

func hU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func hI64(v int) []byte {
	return hU64(uint64(v))
}

func hMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (h *SubgroupHMMR) nullHash(kind string, level int, idx int) []byte {
	key := fmt.Sprintf("%s|%d|%d", kind, level, idx)
	if x, ok := h.NullHashes[key]; ok {
		return x
	}
	d := h.digest(
		[]byte("null|"),
		[]byte(kind),
		hI64(level),
		hI64(idx),
		hI64(h.Arity),
		hI64(h.Subgroup),
		[]byte(h.HashName),
	)
	h.NullHashes[key] = d
	return d
}

func (h *SubgroupHMMR) leafNode(data []byte, idx int) subgroupNodeInfo {
	return subgroupNodeInfo{
		Hash: h.digest(
			[]byte("leaf|"),
			hI64(idx),
			hI64(len(data)),
			data,
		),
		ActualArity: 1,
	}
}

func (h *SubgroupHMMR) subgroupRoot(level int, groupIdx int, subgroupIdx int, children []subgroupNodeInfo, actual int) []byte {
	parts := make([][]byte, 0, 5+h.Subgroup*2)
	parts = append(parts,
		[]byte("subgroup|"),
		hI64(level),
		hI64(groupIdx),
		hI64(subgroupIdx),
		hI64(actual),
	)
	for pos := 0; pos < h.Subgroup; pos++ {
		parts = append(parts, hI64(pos))
		if pos < len(children) {
			parts = append(parts, children[pos].Hash)
		} else {
			parts = append(parts, h.nullHash("slot", level-1, pos))
		}
	}
	return h.digest(parts...)
}

func (h *SubgroupHMMR) parentNode(level int, groupIdx int, children []subgroupNodeInfo) subgroupNodeInfo {
	numSubgroups := h.Arity / h.Subgroup
	parts := make([][]byte, 0, 6+numSubgroups*2)
	parts = append(parts,
		[]byte("cell|"),
		hI64(level),
		hI64(groupIdx),
		hI64(len(children)),
		hI64(h.Arity),
		hI64(h.Subgroup),
	)

	for sg := 0; sg < numSubgroups; sg++ {
		start := sg * h.Subgroup
		if start >= len(children) {
			parts = append(parts, hI64(sg), h.nullHash("subgroup", level, sg))
			continue
		}
		end := hMin(start+h.Subgroup, len(children))
		root := h.subgroupRoot(level, groupIdx, sg, children[start:end], end-start)
		parts = append(parts, hI64(sg), root)
	}

	return subgroupNodeInfo{
		Hash:        h.digest(parts...),
		ActualArity: len(children),
	}
}

// Build rebuilds levels from raw leaf payloads.
func (h *SubgroupHMMR) Build(datas [][]byte) {
	h.Levels = h.Levels[:0]
	h.Root = nil

	level0 := make([]subgroupNodeInfo, len(datas))
	for i, d := range datas {
		level0[i] = h.leafNode(d, i)
	}
	h.Levels = append(h.Levels, level0)

	current := level0
	level := 1
	for len(current) > 1 {
		nextCap := (len(current) + h.Arity - 1) / h.Arity
		next := make([]subgroupNodeInfo, 0, nextCap)
		for i := 0; i < len(current); i += h.Arity {
			j := i + h.Arity
			if j > len(current) {
				j = len(current)
			}
			next = append(next, h.parentNode(level, len(next), current[i:j]))
		}
		h.Levels = append(h.Levels, next)
		current = next
		level++
	}

	if len(current) == 1 {
		root := current[0]
		h.Root = &root
	}
}

// RootHash returns a copy of the current root hash.
func (h *SubgroupHMMR) RootHash() []byte {
	if h.Root == nil {
		return nil
	}
	out := make([]byte, len(h.Root.Hash))
	copy(out, h.Root.Hash)
	return out
}

// Depth returns tree depth.
func (h *SubgroupHMMR) Depth() int {
	if h.Root == nil {
		return 0
	}
	return len(h.Levels) - 1
}

// Proof generates a proof for the given leaf index.
func (h *SubgroupHMMR) Proof(leafIdx int) *SubgroupProof {
	if leafIdx < 0 || len(h.Levels) == 0 || leafIdx >= len(h.Levels[0]) {
		return nil
	}

	p := &SubgroupProof{
		LeafIndex: leafIdx,
		LeafHash:  append([]byte(nil), h.Levels[0][leafIdx].Hash...),
	}

	pos := leafIdx
	for level := 1; level < len(h.Levels); level++ {
		parentIdx := pos / h.Arity
		parent := h.Levels[level][parentIdx]
		groupStart := parentIdx * h.Arity
		position := pos % h.Arity

		subgroupIdx := position / h.Subgroup
		positionInSub := position % h.Subgroup
		subgroupStart := subgroupIdx * h.Subgroup

		actualInSubgroup := 0
		if subgroupStart < parent.ActualArity {
			actualInSubgroup = hMin(h.Subgroup, parent.ActualArity-subgroupStart)
		}

		localSiblings := make([][]byte, 0, hMax(0, actualInSubgroup-1))
		for off := 0; off < actualInSubgroup; off++ {
			if off == positionInSub {
				continue
			}
			childIdx := groupStart + subgroupStart + off
			localSiblings = append(localSiblings, append([]byte(nil), h.Levels[level-1][childIdx].Hash...))
		}

		numSubgroups := h.Arity / h.Subgroup
		subgroupSiblings := make([][]byte, 0, hMax(0, numSubgroups-1))
		for sg := 0; sg < numSubgroups; sg++ {
			if sg == subgroupIdx {
				continue
			}
			sgStart := sg * h.Subgroup
			if sgStart >= parent.ActualArity {
				subgroupSiblings = append(subgroupSiblings, append([]byte(nil), h.nullHash("subgroup", level, sg)...))
				continue
			}
			sgEnd := hMin(sgStart+h.Subgroup, parent.ActualArity)
			sgChildren := make([]subgroupNodeInfo, sgEnd-sgStart)
			for i := sgStart; i < sgEnd; i++ {
				sgChildren[i-sgStart] = h.Levels[level-1][groupStart+i]
			}
			root := h.subgroupRoot(level, parentIdx, sg, sgChildren, sgEnd-sgStart)
			subgroupSiblings = append(subgroupSiblings, root)
		}

		p.Steps = append(p.Steps, SubgroupProofStep{
			Level:            level,
			GroupIndex:       parentIdx,
			PositionInGroup:  position,
			ActualArity:      parent.ActualArity,
			SubgroupSize:     h.Subgroup,
			SubgroupIndex:    subgroupIdx,
			PositionInSub:    positionInSub,
			ActualInSubgroup: actualInSubgroup,
			LocalSiblings:    localSiblings,
			SubgroupSiblings: subgroupSiblings,
		})

		pos = parentIdx
	}

	return p
}

// Verify checks proof validity for the given leaf payload.
func (h *SubgroupHMMR) Verify(leafData []byte, p *SubgroupProof) bool {
	if h.Root == nil || p == nil {
		return false
	}

	cur := h.leafNode(leafData, p.LeafIndex)
	if !bytes.Equal(cur.Hash, p.LeafHash) {
		return false
	}

	for _, step := range p.Steps {
		subParts := make([][]byte, 0, 5+h.Subgroup*2)
		subParts = append(subParts,
			[]byte("subgroup|"),
			hI64(step.Level),
			hI64(step.GroupIndex),
			hI64(step.SubgroupIndex),
			hI64(step.ActualInSubgroup),
		)

		localPos := 0
		for pos := 0; pos < h.Subgroup; pos++ {
			subParts = append(subParts, hI64(pos))
			switch {
			case pos == step.PositionInSub:
				subParts = append(subParts, cur.Hash)
			case pos < step.ActualInSubgroup:
				subParts = append(subParts, step.LocalSiblings[localPos])
				localPos++
			default:
				subParts = append(subParts, h.nullHash("slot", step.Level-1, pos))
			}
		}
		thisSubgroupRoot := h.digest(subParts...)

		cellParts := make([][]byte, 0, 6+(h.Arity/h.Subgroup)*2)
		cellParts = append(cellParts,
			[]byte("cell|"),
			hI64(step.Level),
			hI64(step.GroupIndex),
			hI64(step.ActualArity),
			hI64(h.Arity),
			hI64(h.Subgroup),
		)

		sgPos := 0
		numSubgroups := h.Arity / h.Subgroup
		for sg := 0; sg < numSubgroups; sg++ {
			cellParts = append(cellParts, hI64(sg))
			if sg == step.SubgroupIndex {
				cellParts = append(cellParts, thisSubgroupRoot)
			} else {
				cellParts = append(cellParts, step.SubgroupSiblings[sgPos])
				sgPos++
			}
		}

		cur = subgroupNodeInfo{
			Hash:        h.digest(cellParts...),
			ActualArity: step.ActualArity,
		}
	}

	return bytes.Equal(cur.Hash, h.Root.Hash)
}

func subgroupProofSizeBytes(p *SubgroupProof) int {
	if p == nil {
		return 0
	}
	size := len(p.LeafHash) + 8
	for _, s := range p.Steps {
		size += 8 * 8
		for _, h := range s.LocalSiblings {
			size += len(h)
		}
		for _, h := range s.SubgroupSiblings {
			size += len(h)
		}
	}
	return size
}
