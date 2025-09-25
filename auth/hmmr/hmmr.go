package hmmr

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"time"
)

// Options controls how a Tree is constructed and whether metrics are collected.
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

type hashAdapter struct {
	fn       func([]byte) []byte
	hashSize int
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
			hashSize: 32,
		}, nil
	default:
		return hashAdapter{}, fmt.Errorf("hmmr: unknown hash algorithm %q", name)
	}
}

// Node represents a node within the HMMR structure.
type Node struct {
	Position int
	Hash     []byte
	Height   int
}

// Tree implements the dynamic grouped HMMR accumulator.
type Tree struct {
	hashAdapter hashAdapter
	nodes       []Node
	leafIndices []int
	peaks       []Node
	nodeCount   int
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
		nodes:       make([]Node, 0),
		leafIndices: make([]int, 0),
		peaks:       make([]Node, 0),
	}, nil
}

// AddLeaf ingests raw data, hashes it, and updates the accumulator.
func (t *Tree) AddLeaf(data []byte) []byte {
	digest := t.hashAdapter.fn(data)
	return t.AddLeafHash(digest)
}

// AddLeafHash ingests a pre-hashed leaf and updates the accumulator.
func (t *Tree) AddLeafHash(hash []byte) []byte {
	if len(hash) != t.hashAdapter.hashSize {
		panic("hmmr: invalid leaf hash size")
	}
	t.nodeCount++
	position := t.nodeCount
	node := Node{Position: position, Hash: cloneBytes(hash), Height: 0}
	t.nodes = append(t.nodes, node)
	t.leafIndices = append(t.leafIndices, position)
	t.peaks = append(t.peaks, node)
	t.mergePeaks()
	return t.Root()
}

// Root returns the current accumulator root.
func (t *Tree) Root() []byte {
	if len(t.peaks) == 0 {
		return make([]byte, t.hashAdapter.hashSize)
	}
	combined := make([][]byte, len(t.peaks))
	for i, peak := range t.peaks {
		combined[i] = peak.Hash
	}
	root := xorHashGroup(combined)
	digest := t.hashAdapter.fn(root)
	return digest
}

// Depth returns the highest level currently present in the tree.
func (t *Tree) Depth() int {
	max := 0
	for _, peak := range t.peaks {
		if peak.Height > max {
			max = peak.Height
		}
	}
	return max
}

// LeafCount returns the number of leaves currently present.
func (t *Tree) LeafCount() int {
	return len(t.leafIndices)
}

// GenerateProof returns the HMMR proof for the leaf at the provided index.
func (t *Tree) GenerateProof(leafIndex int) ([][]byte, error) {
	if leafIndex < 0 || leafIndex >= len(t.leafIndices) {
		return nil, errors.New("hmmr: invalid leaf index")
	}
	leaves := make([][]byte, len(t.leafIndices))
	for i, pos := range t.leafIndices {
		leaves[i] = t.nodes[pos-1].Hash
	}
	proof := make([][]byte, 0)
	level := leaves
	index := leafIndex

	for len(level) > 1 {
		groupSize := dynamicGroupSize(len(level))
		groupIndex := index / groupSize
		groupStart := groupIndex * groupSize
		groupEnd := groupStart + groupSize
		if groupEnd > len(level) {
			groupEnd = len(level)
		}
		for i := groupStart; i < groupEnd; i++ {
			if i == index {
				continue
			}
			proof = append(proof, cloneBytes(level[i]))
		}
		nextLevel := make([][]byte, 0, int(math.Ceil(float64(len(level))/float64(groupSize))))
		for i := 0; i < len(level); i += groupSize {
			end := i + groupSize
			if end > len(level) {
				end = len(level)
			}
			group := append([][]byte(nil), level[i:end]...)
			for len(group) < groupSize {
				group = append(group, cloneBytes(group[len(group)-1]))
			}
			parent := xorHashGroup(group)
			nextLevel = append(nextLevel, parent)
		}
		index = index / groupSize
		level = nextLevel
	}
	return proof, nil
}

func (t *Tree) mergePeaks() {
	for {
		groupSize := dynamicGroupSize(len(t.peaks))
		if len(t.peaks) < groupSize {
			return
		}
		lastHeight := t.peaks[len(t.peaks)-1].Height
		count := 0
		for i := len(t.peaks) - 1; i >= 0; i-- {
			if t.peaks[i].Height == lastHeight {
				count++
			} else {
				break
			}
		}
		if count < groupSize {
			return
		}
		group := t.peaks[len(t.peaks)-groupSize:]
		t.peaks = t.peaks[:len(t.peaks)-groupSize]
		hashes := make([][]byte, groupSize)
		for i, node := range group {
			hashes[i] = node.Hash
		}
		mergedHash := xorHashGroup(hashes)
		t.nodeCount++
		mergedNode := Node{Position: t.nodeCount, Hash: mergedHash, Height: lastHeight + 1}
		t.nodes = append(t.nodes, mergedNode)
		t.peaks = append(t.peaks, mergedNode)
	}
}

func dynamicGroupSize(pending int) int {
	if pending < 1 {
		return 2
	}
	k := int(math.Floor(math.Log2(float64(pending)))) + 2
	if k < 2 {
		k = 2
	}
	return k
}

func xorHashGroup(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return nil
	}
	result := make([]byte, len(hashes[0]))
	copy(result, hashes[0])
	for i := 1; i < len(hashes); i++ {
		for j := range result {
			result[j] ^= hashes[i][j]
		}
	}
	return result
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
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
		if len(proof) > 0 {
			metrics.ProofSizeBytes = len(proof) * len(proof[0])
		}
	}

	return tree, metrics, nil
}
