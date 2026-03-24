package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type nodeInfo struct {
	Hash        []byte
	ActualArity int
}

type proofStep struct {
	Level            int
	GroupIndex       int
	PositionInGroup  int
	ActualArity      int
	SubgroupSize     int
	SubgroupIndex    int
	PositionInSub    int
	ActualInSubgroup int
	LocalSiblings    [][]byte // siblings inside the local subgroup
	SubgroupSiblings [][]byte // sibling subgroup roots inside the parent cell
}

type proof struct {
	LeafIndex int
	LeafHash  []byte
	Steps     []proofStep
}

type HMMR struct {
	Arity      int
	Subgroup   int
	HashName   string
	NewHasher  func() hash.Hash
	Levels     [][]nodeInfo
	Root       *nodeInfo
	NullHashes map[string][]byte
}

func NewHMMR(arity int, subgroup int, hashName string) *HMMR {
	if arity < 2 {
		panic("arity must be >= 2")
	}
	if subgroup < 2 || subgroup > arity {
		panic("subgroup must be between 2 and arity")
	}
	if arity%subgroup != 0 {
		panic("arity must be divisible by subgroup")
	}

	h := &HMMR{
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

func (h *HMMR) digest(parts ...[]byte) []byte {
	x := h.NewHasher()
	for _, p := range parts {
		_, _ = x.Write(p)
	}
	return x.Sum(nil)
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func i64(v int) []byte {
	return u64(uint64(v))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (h *HMMR) nullHash(kind string, level int, idx int) []byte {
	key := fmt.Sprintf("%s|%d|%d", kind, level, idx)
	if x, ok := h.NullHashes[key]; ok {
		return x
	}
	d := h.digest(
		[]byte("null|"),
		[]byte(kind),
		i64(level),
		i64(idx),
		i64(h.Arity),
		i64(h.Subgroup),
		[]byte(h.HashName),
	)
	h.NullHashes[key] = d
	return d
}

func (h *HMMR) leafNode(data []byte, idx int) nodeInfo {
	return nodeInfo{
		Hash: h.digest(
			[]byte("leaf|"),
			i64(idx),
			i64(len(data)),
			data,
		),
		ActualArity: 1,
	}
}

func (h *HMMR) subgroupRoot(level int, groupIdx int, subgroupIdx int, children []nodeInfo, actual int) []byte {
	parts := make([][]byte, 0, 5+h.Subgroup*2)
	parts = append(parts,
		[]byte("subgroup|"),
		i64(level),
		i64(groupIdx),
		i64(subgroupIdx),
		i64(actual),
	)
	for pos := 0; pos < h.Subgroup; pos++ {
		parts = append(parts, i64(pos))
		if pos < len(children) {
			parts = append(parts, children[pos].Hash)
		} else {
			parts = append(parts, h.nullHash("slot", level-1, pos))
		}
	}
	return h.digest(parts...)
}

func (h *HMMR) parentNode(level int, groupIdx int, children []nodeInfo) nodeInfo {
	numSubgroups := h.Arity / h.Subgroup
	parts := make([][]byte, 0, 6+numSubgroups*2)
	parts = append(parts,
		[]byte("cell|"),
		i64(level),
		i64(groupIdx),
		i64(len(children)),
		i64(h.Arity),
		i64(h.Subgroup),
	)

	for sg := 0; sg < numSubgroups; sg++ {
		start := sg * h.Subgroup
		if start >= len(children) {
			parts = append(parts, i64(sg), h.nullHash("subgroup", level, sg))
			continue
		}
		end := min(start+h.Subgroup, len(children))
		root := h.subgroupRoot(level, groupIdx, sg, children[start:end], end-start)
		parts = append(parts, i64(sg), root)
	}

	return nodeInfo{
		Hash:        h.digest(parts...),
		ActualArity: len(children),
	}
}

func (h *HMMR) Build(datas [][]byte) {
	h.Levels = h.Levels[:0]
	h.Root = nil

	level0 := make([]nodeInfo, len(datas))
	for i, d := range datas {
		level0[i] = h.leafNode(d, i)
	}
	h.Levels = append(h.Levels, level0)

	current := level0
	level := 1
	for len(current) > 1 {
		nextCap := (len(current) + h.Arity - 1) / h.Arity
		next := make([]nodeInfo, 0, nextCap)
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

func (h *HMMR) Depth() int {
	if h.Root == nil {
		return 0
	}
	return len(h.Levels) - 1
}

func (h *HMMR) Proof(leafIdx int) *proof {
	if leafIdx < 0 || len(h.Levels) == 0 || leafIdx >= len(h.Levels[0]) {
		return nil
	}

	p := &proof{
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
			actualInSubgroup = min(h.Subgroup, parent.ActualArity-subgroupStart)
		}

		localSiblings := make([][]byte, 0, max(0, actualInSubgroup-1))
		for off := 0; off < actualInSubgroup; off++ {
			if off == positionInSub {
				continue
			}
			childIdx := groupStart + subgroupStart + off
			localSiblings = append(localSiblings, append([]byte(nil), h.Levels[level-1][childIdx].Hash...))
		}

		numSubgroups := h.Arity / h.Subgroup
		subgroupSiblings := make([][]byte, 0, max(0, numSubgroups-1))
		for sg := 0; sg < numSubgroups; sg++ {
			if sg == subgroupIdx {
				continue
			}
			sgStart := sg * h.Subgroup
			if sgStart >= parent.ActualArity {
				subgroupSiblings = append(subgroupSiblings, append([]byte(nil), h.nullHash("subgroup", level, sg)...))
				continue
			}
			sgEnd := min(sgStart+h.Subgroup, parent.ActualArity)
			sgChildren := make([]nodeInfo, sgEnd-sgStart)
			for i := sgStart; i < sgEnd; i++ {
				sgChildren[i-sgStart] = h.Levels[level-1][groupStart+i]
			}
			root := h.subgroupRoot(level, parentIdx, sg, sgChildren, sgEnd-sgStart)
			subgroupSiblings = append(subgroupSiblings, root)
		}

		p.Steps = append(p.Steps, proofStep{
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

func (h *HMMR) Verify(leafData []byte, p *proof) bool {
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
			i64(step.Level),
			i64(step.GroupIndex),
			i64(step.SubgroupIndex),
			i64(step.ActualInSubgroup),
		)

		localPos := 0
		for pos := 0; pos < h.Subgroup; pos++ {
			subParts = append(subParts, i64(pos))
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
			i64(step.Level),
			i64(step.GroupIndex),
			i64(step.ActualArity),
			i64(h.Arity),
			i64(h.Subgroup),
		)

		sgPos := 0
		numSubgroups := h.Arity / h.Subgroup
		for sg := 0; sg < numSubgroups; sg++ {
			cellParts = append(cellParts, i64(sg))
			if sg == step.SubgroupIndex {
				cellParts = append(cellParts, thisSubgroupRoot)
			} else {
				cellParts = append(cellParts, step.SubgroupSiblings[sgPos])
				sgPos++
			}
		}

		cur = nodeInfo{
			Hash:        h.digest(cellParts...),
			ActualArity: step.ActualArity,
		}
	}

	return bytes.Equal(cur.Hash, h.Root.Hash)
}

func proofSizeBytes(p *proof) int {
	if p == nil {
		return 0
	}
	size := len(p.LeafHash) + 8 // leaf index
	for _, s := range p.Steps {
		size += 8 * 8 // compact step metadata
		for _, h := range s.LocalSiblings {
			size += len(h)
		}
		for _, h := range s.SubgroupSiblings {
			size += len(h)
		}
	}
	return size
}

func syntheticData(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 32)
		binary.BigEndian.PutUint64(buf[0:8], uint64(i))
		binary.BigEndian.PutUint64(buf[8:16], uint64(i*2654435761))
		binary.BigEndian.PutUint64(buf[16:24], uint64(i)^0x9e3779b97f4a7c15)
		binary.BigEndian.PutUint64(buf[24:32], uint64(i*1315423911))
		out[i] = buf
	}
	return out
}

func avgProofAndVerify(h *HMMR, data [][]byte, samples int) (time.Duration, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	if samples > len(data) {
		samples = len(data)
	}
	rng := rand.New(rand.NewSource(42))

	start := time.Now()
	var last *proof
	for i := 0; i < samples; i++ {
		idx := rng.Intn(len(data))
		last = h.Proof(idx)
		if !h.Verify(data[idx], last) {
			return 0, 0, false
		}
	}
	elapsed := time.Since(start)
	avg := elapsed / time.Duration(samples)
	return avg, proofSizeBytes(last), true
}

func fmtMs(d time.Duration) string {
	return fmt.Sprintf("%.3f", float64(d.Nanoseconds())/1e6)
}

func fmtUs(d time.Duration) string {
	return fmt.Sprintf("%.3f", float64(d.Nanoseconds())/1e3)
}

func fmtBytesMB(b uint64) string {
	return fmt.Sprintf("%d (%.3f MB)", b, float64(b)/(1024.0*1024.0))
}

func fmtSize(b int) string {
	return fmt.Sprintf("%d (%.6f MB)", b, float64(b)/(1024.0*1024.0))
}

func printHeader() {
	fmt.Printf("%-10s |%-24s |%-24s |%-24s |%-27s |%-6s |\n",
		"NumLeaves", "BuildTimeMs (us)", "MemoryUsed (MB)", "ProofTimeMs (us)", "ProofSizeBytes (MB)", "Depth")
	fmt.Println(strings.Repeat("-", 132))
}

func runTests(hashName string, arity int, subgroup int, counts []int, proofSamples int) int {
	fmt.Printf("Plain HMMR with subgroup compression: arity=%d, subgroup=%d\n", arity, subgroup)
	printHeader()

	for _, n := range counts {
		data := syntheticData(n)

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		h := NewHMMR(arity, subgroup, hashName)
		buildStart := time.Now()
		h.Build(data)
		buildDur := time.Since(buildStart)

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		var memUsed uint64
		if after.Alloc >= before.Alloc {
			memUsed = after.Alloc - before.Alloc
		}

		proofDur, proofSize, ok := avgProofAndVerify(h, data, proofSamples)
		if !ok {
			fmt.Fprintf(os.Stderr, "verification failed for n=%d\n", n)
			return 1
		}

		fmt.Printf("%-10d |%-24s |%-24s |%-24s |%-27s |%-6d |\n",
			n,
			fmt.Sprintf("%s (%s)", fmtMs(buildDur), fmtUs(buildDur)),
			fmtBytesMB(memUsed),
			fmt.Sprintf("%s (%s)", fmtMs(proofDur), fmtUs(proofDur)),
			fmtSize(proofSize),
			h.Depth(),
		)
	}
	return 0
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  go run hmmr_v9_subgroup.go -hash sha256 -arity 16 -subgroup 4 -samples 1024 test 4000 8000 16000 32000 64000 128000 512000")
	fmt.Println("")
	fmt.Println("Recommended:")
	fmt.Println("  -arity 16 -subgroup 4   -> reduces flat 15-sibling proofs to 3 local + 3 subgroup-root siblings")
	fmt.Println("  -arity 8  -subgroup 4   -> balanced option")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	hashName := flag.String("hash", "sha256", "hash function: sha256 or sha512")
	arity := flag.Int("arity", 16, "branching factor / cell capacity")
	subgroup := flag.Int("subgroup", 4, "internal subgroup size; must divide arity")
	samples := flag.Int("samples", 1024, "number of random proof+verify samples per test")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 || strings.ToLower(args[0]) != "test" {
		usage()
		os.Exit(2)
	}
	if *arity < 2 {
		fmt.Fprintln(os.Stderr, "arity must be >= 2")
		os.Exit(2)
	}
	if *subgroup < 2 || *subgroup > *arity || *arity%*subgroup != 0 {
		fmt.Fprintln(os.Stderr, "subgroup must be between 2 and arity, and arity must be divisible by subgroup")
		os.Exit(2)
	}
	if *samples < 1 {
		fmt.Fprintln(os.Stderr, "samples must be >= 1")
		os.Exit(2)
	}

	counts := make([]int, 0, len(args)-1)
	for _, a := range args[1:] {
		n, err := strconv.Atoi(a)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "invalid leaf count: %s\n", a)
			os.Exit(2)
		}
		counts = append(counts, n)
	}
	sort.Ints(counts)

	os.Exit(runTests(*hashName, *arity, *subgroup, counts, *samples))
}
