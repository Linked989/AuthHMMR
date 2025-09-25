package blockchain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"auth/hmmr"
)

const (
	blockVersion uint16 = 1
	hashSize            = 32
	maxUint32           = (1 << 32) - 1
)

// Transaction models a minimal transaction embedded into a block.
type Transaction struct {
	ID        [hashSize]byte
	Type      string
	Payload   []byte
	Timestamp int64
}

// BlockHeader captures metadata describing a block.
type BlockHeader struct {
	Version   uint16
	Height    uint64
	Timestamp int64
	PrevHash  [hashSize]byte
	HMMRRoot  [hashSize]byte
	TxCount   uint32
}

// Block encapsulates the header and transactions persisted on disk.
type Block struct {
	Header       BlockHeader
	Transactions []Transaction
}

// BuildBlock assembles a block from the provided transactions, calculating the HMMR root.
func BuildBlock(prev *Block, txs []Transaction, leaves [][]byte, leafSize int, opts hmmr.Options) (*Block, *hmmr.Metrics, error) {
	if len(txs) == 0 {
		return nil, nil, errors.New("blockchain: cannot create block with no transactions")
	}

	if leafSize <= 0 {
		return nil, nil, errors.New("blockchain: leafSize must be > 0")
	}

	var normalized [][]byte
	if len(leaves) == 0 {
		normalized = make([][]byte, len(txs))
		for i := range txs {
			normalized[i] = NormalizeLeaf(txBytesForHash(&txs[i]), leafSize)
		}
	} else {
		normalized = make([][]byte, len(leaves))
		for i := range leaves {
			normalized[i] = NormalizeLeaf(leaves[i], leafSize)
		}
	}

	tree, metrics, err := hmmr.BuildTree(normalized, opts)
	if err != nil {
		return nil, nil, err
	}

	root := tree.Root()
	if len(root) != hashSize {
		return nil, nil, fmt.Errorf("blockchain: unexpected HMMR root size %d", len(root))
	}
	var rootArr [hashSize]byte
	copy(rootArr[:], root)

	header := BlockHeader{
		Version:   blockVersion,
		Height:    0,
		Timestamp: time.Now().UnixNano(),
		HMMRRoot:  rootArr,
		TxCount:   uint32(len(txs)),
	}

	if prev != nil {
		header.Height = prev.Header.Height + 1
		header.PrevHash = hashBlock(prev)
	}

	return &Block{Header: header, Transactions: txs}, metrics, nil
}

// NormalizeLeaf returns a copy of data exactly leafSize bytes long.
func NormalizeLeaf(data []byte, leafSize int) []byte {
	if leafSize <= 0 {
		leafSize = hashSize
	}
	digest := sha256.Sum256(data)
	buf := make([]byte, leafSize)
	offset := 0
	for offset < leafSize {
		offset += copy(buf[offset:], digest[:])
	}
	return buf
}

// NewTransaction constructs a transaction with a deterministic identifier.
func NewTransaction(txType string, payload []byte, ts time.Time) Transaction {
	if txType == "" {
		txType = "generic"
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	timestamp := ts.UnixNano()
	id := computeTxID(txType, payload, timestamp)
	return Transaction{ID: id, Type: txType, Payload: append([]byte(nil), payload...), Timestamp: timestamp}
}

// hashBlock computes a hash over the block header for linking.
func hashBlock(block *Block) [hashSize]byte {
	buf := make([]byte, 0, 2+8+8+hashSize+hashSize+4)
	tmp := make([]byte, 8)

	versionBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBuf, block.Header.Version)
	buf = append(buf, versionBuf...)

	binary.BigEndian.PutUint64(tmp, block.Header.Height)
	buf = append(buf, tmp...)

	binary.BigEndian.PutUint64(tmp, uint64(block.Header.Timestamp))
	buf = append(buf, tmp...)

	buf = append(buf, block.Header.PrevHash[:]...)
	buf = append(buf, block.Header.HMMRRoot[:]...)

	countBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(countBuf, block.Header.TxCount)
	buf = append(buf, countBuf...)

	sum := sha256.Sum256(buf)
	return sum
}

func computeTxID(txType string, payload []byte, timestamp int64) [hashSize]byte {
	typeBytes := []byte(txType)
	buf := make([]byte, 0, len(typeBytes)+len(payload)+16)
	buf = append(buf, typeBytes...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(timestamp))
	buf = append(buf, tmp...)
	buf = append(buf, payload...)
	sum := sha256.Sum256(buf)
	return sum
}

func txBytesForHash(tx *Transaction) []byte {
	buf := make([]byte, 0, len(tx.Type)+len(tx.Payload)+8)
	buf = append(buf, tx.Type...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(tx.Timestamp))
	buf = append(buf, tmp...)
	buf = append(buf, tx.Payload...)
	return buf
}

// Persist writes the block to disk inside the provided directory.
func Persist(dir string, block *Block) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("blockchain: ensure dir: %w", err)
	}
	filename := filepath.Join(dir, fmt.Sprintf("block_%010d.dat", block.Header.Height))
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("blockchain: create file: %w", err)
	}
	defer file.Close()

	if err := writeBlock(file, block); err != nil {
		return "", fmt.Errorf("blockchain: write block: %w", err)
	}
	return filename, nil
}

// LoadLatest reads the highest-height block from disk if present.
func LoadLatest(dir string) (*Block, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("blockchain: read dir: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "block_") && strings.HasSuffix(name, ".dat") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	sort.Strings(files)
	latest := files[len(files)-1]
	return readBlock(latest)
}

func writeBlock(w io.Writer, block *Block) error {
	header := block.Header

	if err := binary.Write(w, binary.BigEndian, header.Version); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, header.Height); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, header.Timestamp); err != nil {
		return err
	}
	if _, err := w.Write(header.PrevHash[:]); err != nil {
		return err
	}
	if _, err := w.Write(header.HMMRRoot[:]); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, header.TxCount); err != nil {
		return err
	}

	for _, tx := range block.Transactions {
		if _, err := w.Write(tx.ID[:]); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, tx.Timestamp); err != nil {
			return err
		}
		if err := writeBytes(w, []byte(tx.Type)); err != nil {
			return err
		}
		if err := writeBytes(w, tx.Payload); err != nil {
			return err
		}
	}
	return nil
}

func readBlock(path string) (*Block, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var header BlockHeader
	if err := binary.Read(file, binary.BigEndian, &header.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(file, binary.BigEndian, &header.Height); err != nil {
		return nil, err
	}
	if err := binary.Read(file, binary.BigEndian, &header.Timestamp); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(file, header.PrevHash[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(file, header.HMMRRoot[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(file, binary.BigEndian, &header.TxCount); err != nil {
		return nil, err
	}

	txs := make([]Transaction, header.TxCount)
	for i := range txs {
		if _, err := io.ReadFull(file, txs[i].ID[:]); err != nil {
			return nil, err
		}
		if err := binary.Read(file, binary.BigEndian, &txs[i].Timestamp); err != nil {
			return nil, err
		}
		typeBytes, err := readBytes(file)
		if err != nil {
			return nil, err
		}
		payload, err := readBytes(file)
		if err != nil {
			return nil, err
		}
		txs[i].Type = string(typeBytes)
		txs[i].Payload = payload
	}

	return &Block{Header: header, Transactions: txs}, nil
}

func writeBytes(w io.Writer, data []byte) error {
	if len(data) > maxUint32 {
		return errors.New("blockchain: data too large")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func readBytes(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
