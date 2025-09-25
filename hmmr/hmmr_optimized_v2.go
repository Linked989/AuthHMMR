// hmmr_offline.go
// ################################################################################################
// ################################################################################################
// -- THIS IS THE GOOD VERSION FOR HMMR
// ################################################################################################
// ################################################################################################
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// ---------------------------
// Global Hash Function Setup
// ---------------------------
var (
	selectedHashAlgorithm string
	hashFunc              func([]byte) []byte
)

func initHashFunction() {
	switch strings.ToLower(selectedHashAlgorithm) {
	case "sha256":
		hashFunc = func(data []byte) []byte {
			sum := sha256.Sum256(data)
			return sum[:]
		}
	case "blake2b":
		hashFunc = func(data []byte) []byte {
			// Using blake2b with 256-bit digest.
			hasher, err := blake2b.New256(nil)
			if err != nil {
				log.Fatalf("Error initializing blake2b: %v", err)
			}
			hasher.Write(data)
			return hasher.Sum(nil)
		}
	case "blake3":
		hashFunc = func(data []byte) []byte {
			sum := blake3.Sum256(data)
			return sum[:]
		}
	case "keccak256":
		hashFunc = func(data []byte) []byte {
			h := sha3.NewLegacyKeccak256()
			h.Write(data)
			return h.Sum(nil)
		}
	default:
		log.Fatalf("Unknown hash algorithm: %s", selectedHashAlgorithm)
	}
}

// ---------------------------
// Configuration
// ---------------------------
const (
	LEAF_DATA_SIZE = 256 // Each leaf uses 256 bytes of random data.
)

// dynamicGroupSize computes the branching factor (K) dynamically.
// Here we use: K = floor(log2(pending)) + 2, with a minimum of 2.
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

// ---------------------------
// Helper: XOR-Combine Hashes
// ---------------------------
// xorHashGroup returns the XOR of all provided hashes.
// (Assumes all hashes are the same length.)
func xorHashGroup(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return nil
	}
	result := make([]byte, len(hashes[0]))
	copy(result, hashes[0])
	for i := 1; i < len(hashes); i++ {
		for j := 0; j < len(result); j++ {
			result[j] ^= hashes[i][j]
		}
	}
	return result
}

// ---------------------------
// HMMR Off-Chain Structure
// ---------------------------
type Node struct {
	Position int
	Hash     []byte
	Height   int
}

type HMMR struct {
	Nodes       []Node
	LeafIndices []int // positions (1-indexed) of leaves in Nodes
	Peaks       []Node
	NodeCount   int
}

func NewHMMR() *HMMR {
	return &HMMR{
		Nodes:       make([]Node, 0),
		LeafIndices: make([]int, 0),
		Peaks:       make([]Node, 0),
		NodeCount:   0,
	}
}

// hashLeaf computes the digest of data using the selected hash function.
func (h *HMMR) hashLeaf(data []byte) []byte {
	return hashFunc(data)
}

// mergePeaks performs the incremental merging of peaks using XOR-based hashing.
func (h *HMMR) mergePeaks() {
	for {
		groupSize := dynamicGroupSize(len(h.Peaks))
		if len(h.Peaks) < groupSize {
			break
		}
		// Check if the last group of peaks have the same height.
		lastHeight := h.Peaks[len(h.Peaks)-1].Height
		count := 0
		for i := len(h.Peaks) - 1; i >= 0; i-- {
			if h.Peaks[i].Height == lastHeight {
				count++
			} else {
				break
			}
		}
		if count < groupSize {
			break
		}
		// Remove the last groupSize peaks and merge them.
		group := h.Peaks[len(h.Peaks)-groupSize:]
		h.Peaks = h.Peaks[:len(h.Peaks)-groupSize]
		hashes := make([][]byte, groupSize)
		for i, node := range group {
			hashes[i] = node.Hash
		}
		// Use XOR-based incremental update.
		mergedHash := xorHashGroup(hashes)
		h.NodeCount++
		mergedNode := Node{Position: h.NodeCount, Hash: mergedHash, Height: lastHeight + 1}
		h.Nodes = append(h.Nodes, mergedNode)
		h.Peaks = append(h.Peaks, mergedNode)
	}
}

// AddLeaf adds a new leaf node using raw data.
// It computes the leaf hash and then delegates to AddLeafHash.
func (h *HMMR) AddLeaf(data []byte) []byte {
	leafHash := h.hashLeaf(data)
	return h.AddLeafHash(leafHash)
}

// AddLeafHash adds a new leaf node using a precomputed leaf hash.
// This function uses incremental XOR merging.
func (h *HMMR) AddLeafHash(leafHash []byte) []byte {
	h.NodeCount++
	position := h.NodeCount
	leafNode := Node{Position: position, Hash: leafHash, Height: 0}
	h.Nodes = append(h.Nodes, leafNode)
	h.LeafIndices = append(h.LeafIndices, position)
	h.Peaks = append(h.Peaks, leafNode)

	// Incrementally merge peaks.
	h.mergePeaks()

	return h.GetRoot()
}

// GetRoot computes the H‑MMR root by XOR‑combining all peak hashes and then hashing the result.
func (h *HMMR) GetRoot() []byte {
	if len(h.Peaks) == 0 {
		return make([]byte, 32)
	}
	combined := make([][]byte, len(h.Peaks))
	for i, peak := range h.Peaks {
		combined[i] = peak.Hash
	}
	// For consistency, we hash the XOR of all peak hashes.
	return hashFunc(xorHashGroup(combined))
}

// Depth returns the maximum height among the current peaks.
func (h *HMMR) Depth() int {
	max := 0
	for _, peak := range h.Peaks {
		if peak.Height > max {
			max = peak.Height
		}
	}
	return max
}

// GenerateProof computes a Merkle-style proof for the leaf at index leafIndex using dynamic grouping.
func (h *HMMR) GenerateProof(leafIndex int) ([][]byte, time.Duration) {
	start := time.Now()
	leaves := make([][]byte, len(h.LeafIndices))
	for i, pos := range h.LeafIndices {
		leaves[i] = h.Nodes[pos-1].Hash
	}
	if leafIndex < 0 || leafIndex >= len(leaves) {
		return nil, time.Since(start)
	}
	proof := [][]byte{}
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
		// Append sibling hashes (all in the group except the current node).
		for i := groupStart; i < groupEnd; i++ {
			if i == index {
				continue
			}
			proof = append(proof, level[i])
		}
		// Build the next level with dynamic grouping.
		nextLevel := [][]byte{}
		for i := 0; i < len(level); i += groupSize {
			end := i + groupSize
			if end > len(level) {
				end = len(level)
			}
			group := level[i:end]
			// If the group is incomplete, duplicate the last element until its size equals groupSize.
			for len(group) < groupSize {
				group = append(group, group[len(group)-1])
			}
			// Use XOR-based merge for consistency.
			parentHash := xorHashGroup(group)
			nextLevel = append(nextLevel, parentHash)
		}
		index = index / groupSize
		level = nextLevel
	}
	return proof, time.Since(start)
}

// ---------------------------
// Utility Functions
// ---------------------------

// generateRandomData creates a random byte slice of given size.
func generateRandomData(numBytes int) []byte {
	data := make([]byte, numBytes)
	_, err := rand.Read(data)
	if err != nil {
		log.Fatalf("Error generating random data: %v", err)
	}
	return data
}

// saveSummaryMetricsToCSV writes the summary metrics (multiple rows) into a CSV file.
func saveSummaryMetricsToCSV(filename string, rows [][]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Error creating CSV file: %v", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, record := range rows {
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("Error writing record to CSV: %v", err)
		}
	}
	return nil
}

// ---------------------------
// Main Execution for Offline HMMR Testing with Dynamic Branching
// ---------------------------
func main() {
	// Define and parse command-line flags.
	flag.StringVar(&selectedHashAlgorithm, "hash", "blake3", "Hash algorithm to use: sha256, blake2b, blake3, or keccak256")
	flag.Parse()

	// Initialize the selected hash function.
	initHashFunction()

	// Usage: go run hmmr_offline.go test <num_leaves1> <num_leaves2> ...
	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: go run hmmr_offline.go test <num_leaves1> <num_leaves2> ...")
		os.Exit(1)
	}
	mode := strings.ToLower(args[0])
	if mode != "test" {
		log.Fatalf("Only test mode is implemented. Use 'test' as the first argument.")
	}

	// Parse all the leaf counts provided as arguments.
	leafArgs := args[1:]
	results := [][]string{
		{"NumLeaves", "BuildTimeMs", "MemoryUsed", "ProofTimeMs", "ProofSizeBytes", "Depth"},
	}

	// Prepare a tab writer for ASCII table output.
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	// Print header.
	fmt.Fprintln(tw, "NumLeaves\tBuildTimeMs\tMemoryUsed\tProofTimeMs\tProofSizeBytes\tDepth\t")

	for _, arg := range leafArgs {
		numLeaves, err := strconv.Atoi(arg)
		if err != nil {
			log.Fatalf("Error parsing number of leaves '%s': %v", arg, err)
		}
		fmt.Printf("Running test for %d leaves using %s with dynamic branching...\n", numLeaves, selectedHashAlgorithm)

		// Create a new HMMR structure for each test run.
		hmmr := NewHMMR()

		// Sequentially compute and insert leaf hashes.
		leafHashes := make([][]byte, numLeaves)
		for i := 0; i < numLeaves; i++ {
			data := generateRandomData(LEAF_DATA_SIZE)
			leafHashes[i] = hashFunc(data)
		}

		// Measure time to sequentially insert leaves (using precomputed hashes).
		startBuild := time.Now()
		for i := 0; i < numLeaves; i++ {
			hmmr.AddLeafHash(leafHashes[i])
		}
		buildLeavesTime := time.Since(startBuild)

		// Force GC and measure memory usage after building leaves.
		runtime.GC()
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		memoryUsed := memStats.Alloc

		// Measure proof generation time and proof size for a specific leaf (use the middle leaf).
		proofLeafIndex := numLeaves / 2
		proof, proofTime := hmmr.GenerateProof(proofLeafIndex)
		proofSize := len(proof) * 32 // each hash is 32 bytes

		// Convert times to milliseconds.
		buildTimeMs := float64(buildLeavesTime.Nanoseconds()) / 1e6
		proofTimeMs := float64(proofTime.Nanoseconds()) / 1e6

		// Collect results in a row.
		row := []string{
			strconv.Itoa(numLeaves),
			fmt.Sprintf("%.3f", buildTimeMs),
			strconv.FormatUint(memoryUsed, 10),
			fmt.Sprintf("%.3f", proofTimeMs),
			strconv.Itoa(proofSize),
			strconv.Itoa(hmmr.Depth()),
		}
		results = append(results, row)

		// Print the row in the ASCII table.
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t\n", row[0], row[1], row[2], row[3], row[4], row[5])
	}
	tw.Flush()

	// Save summary metrics into a CSV file.
	csvFilename := "hmmr_summary_metrics_dynamic.csv"
	if err := saveSummaryMetricsToCSV(csvFilename, results); err != nil {
		log.Fatalf("Error saving summary metrics to CSV: %v", err)
	} else {
		fmt.Printf("Summary metrics saved to %s\n", csvFilename)
	}
}
