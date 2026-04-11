package metrics

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const FinalMetricsFilename = "final_metrics.csv"

type FinalMetricsRecord struct {
	TimestampUTC                 time.Time
	MetricSource                 string
	CandidateDevicesX            int
	TotalNetworkSize             int
	SelectedEvaluatorsK          int
	AdmissionLatencyMs           float64
	ThroughputDevicesPerSec      float64
	CommunicationCostBytesAvg    float64
	CommunicationCostKBAvg       float64
	CommunicationOverheadMsgsAvg float64
	ProofGenerationTimeMs        float64
	ProofSizeBytes               int
	VerificationTimeMs           float64
	TotalRecordedEvents          int
}

func AppendFinalMetricsCSV(dir string, record FinalMetricsRecord) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, FinalMetricsFilename)
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
			"metric_source",
			"candidate_devices_x",
			"total_network_size",
			"selected_evaluators_k",
			"admission_latency_ms",
			"throughput_devices_per_sec",
			"communication_cost_bytes_avg",
			"communication_cost_kb_avg",
			"communication_overhead_messages_avg",
			"proof_generation_time_ms",
			"proof_size_bytes",
			"verification_time_ms",
			"total_number_of_recorded_events",
		}
		if err := w.Write(header); err != nil {
			return "", err
		}
	}

	ts := record.TimestampUTC
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	row := []string{
		ts.Format(time.RFC3339),
		record.MetricSource,
		fmt.Sprintf("%d", record.CandidateDevicesX),
		fmt.Sprintf("%d", record.TotalNetworkSize),
		fmt.Sprintf("%d", record.SelectedEvaluatorsK),
		fmt.Sprintf("%.6f", record.AdmissionLatencyMs),
		fmt.Sprintf("%.6f", record.ThroughputDevicesPerSec),
		fmt.Sprintf("%.6f", record.CommunicationCostBytesAvg),
		fmt.Sprintf("%.6f", record.CommunicationCostKBAvg),
		fmt.Sprintf("%.6f", record.CommunicationOverheadMsgsAvg),
		fmt.Sprintf("%.6f", record.ProofGenerationTimeMs),
		fmt.Sprintf("%d", record.ProofSizeBytes),
		fmt.Sprintf("%.6f", record.VerificationTimeMs),
		fmt.Sprintf("%d", record.TotalRecordedEvents),
	}
	if err := w.Write(row); err != nil {
		return "", err
	}
	if err := w.Error(); err != nil {
		return "", err
	}
	return path, nil
}
