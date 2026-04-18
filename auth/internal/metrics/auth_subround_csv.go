package metrics

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const AuthSubroundMetricsFilename = "auth_subround_metrics.csv"

type AuthSubroundMetricRecord struct {
	TimestampUTC        time.Time
	RunID               string
	CandidateDeviceUUID string
	SubroundIndex       int
	TotalSubrounds      int
	SelectedVoters      int
	SubroundLatencyMs   float64
	SubroundFinalVote   string
	SubroundVoteRatio   float64
	TotalRoundLatencyMs float64
	TotalRoundFinalVote string
}

func AppendAuthSubroundMetricsCSV(dir string, records []AuthSubroundMetricRecord) (string, error) {
	if len(records) == 0 {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, AuthSubroundMetricsFilename)
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
			"candidate_device_uuid",
			"subround_index",
			"total_subrounds",
			"selected_voters",
			"subround_latency_ms",
			"subround_final_vote",
			"subround_vote_ratio",
			"total_round_latency_ms",
			"total_round_final_vote",
		}
		if err := w.Write(header); err != nil {
			return "", err
		}
	}

	for _, r := range records {
		ts := r.TimestampUTC
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		row := []string{
			ts.Format(time.RFC3339),
			r.RunID,
			r.CandidateDeviceUUID,
			fmt.Sprintf("%d", r.SubroundIndex),
			fmt.Sprintf("%d", r.TotalSubrounds),
			fmt.Sprintf("%d", r.SelectedVoters),
			fmt.Sprintf("%.6f", r.SubroundLatencyMs),
			r.SubroundFinalVote,
			fmt.Sprintf("%.6f", r.SubroundVoteRatio),
			fmt.Sprintf("%.6f", r.TotalRoundLatencyMs),
			r.TotalRoundFinalVote,
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	if err := w.Error(); err != nil {
		return "", err
	}

	return path, nil
}
