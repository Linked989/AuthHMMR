package metrics

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
)

const (
	HonestVoterTrackingFilename    = "voter_trust_weight_honest.csv"
	MaliciousVoterTrackingFilename = "voter_trust_weight_malicious.csv"
)

type VoterInteractionRecord struct {
	VoterIsMalicious    bool
	TrustScoreAfterVote float64
	WeightAfterVote     uint
}

func AppendVoterInteractionCSV(dir string, record VoterInteractionRecord) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	filename := HonestVoterTrackingFilename
	if record.VoterIsMalicious {
		filename = MaliciousVoterTrackingFilename
	}
	path := filepath.Join(dir, filename)

	newFile := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		newFile = true
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if newFile {
		header := []string{
			"trust_score_after_vote",
			"weight_after_vote",
		}
		if err := w.Write(header); err != nil {
			return "", err
		}
	}

	row := []string{
		strconv.FormatFloat(record.TrustScoreAfterVote, 'f', 6, 64),
		strconv.FormatUint(uint64(record.WeightAfterVote), 10),
	}
	if err := w.Write(row); err != nil {
		return "", err
	}
	if err := w.Error(); err != nil {
		return "", err
	}
	return path, nil
}
