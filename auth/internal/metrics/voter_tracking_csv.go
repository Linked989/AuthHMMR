package metrics

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	HonestVoterTrackingFilename    = "voter_trust_weight_honest.csv"
	MaliciousVoterTrackingFilename = "voter_trust_weight_malicious.csv"
)

type VoterInteractionRecord struct {
	TimestampUTC          time.Time
	RunID                 string
	InteractionIndex      int
	CandidateDeviceUUID   string
	VoterUUID             string
	VoterIsMalicious      bool
	Vote                  string
	VoterTrustScore       float64
	VoterWeight           uint
	SelectedVoterPosition int
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
			"timestamp_utc",
			"run_id",
			"interaction_index",
			"candidate_device_uuid",
			"voter_uuid",
			"voter_is_malicious",
			"vote",
			"voter_trust_score",
			"voter_weight",
			"selected_voter_position",
		}
		if err := w.Write(header); err != nil {
			return "", err
		}
	}

	ts := record.TimestampUTC
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if record.RunID == "" {
		record.RunID = ts.Format("20060102T150405Z")
	}

	row := []string{
		ts.Format(time.RFC3339),
		record.RunID,
		fmt.Sprintf("%d", record.InteractionIndex),
		record.CandidateDeviceUUID,
		record.VoterUUID,
		fmt.Sprintf("%t", record.VoterIsMalicious),
		record.Vote,
		fmt.Sprintf("%.6f", record.VoterTrustScore),
		fmt.Sprintf("%d", record.VoterWeight),
		fmt.Sprintf("%d", record.SelectedVoterPosition),
	}
	if err := w.Write(row); err != nil {
		return "", err
	}
	if err := w.Error(); err != nil {
		return "", err
	}

	return path, nil
}
