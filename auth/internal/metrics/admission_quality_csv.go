package metrics

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

const (
	AdmissionAccuracyFilename  = "admission_accuracy.csv"
	DecisionConsistencyCSVName = "decision_consistency.csv"
	DecisionConsistencyState   = "decision_consistency_state.json"
)

type AdmissionAccuracyRecord struct {
	TimestampUTC      time.Time
	CandidateDevicesX int
	TP                int
	TN                int
	FP                int
	FN                int
	Accuracy          float64
}

func AppendAdmissionAccuracyCSV(dir string, record AdmissionAccuracyRecord) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, AdmissionAccuracyFilename)
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
			"candidate_devices_x",
			"tp_legit_accepted",
			"tn_malicious_rejected",
			"fp_malicious_accepted",
			"fn_legit_rejected",
			"accuracy",
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
		fmt.Sprintf("%d", record.CandidateDevicesX),
		fmt.Sprintf("%d", record.TP),
		fmt.Sprintf("%d", record.TN),
		fmt.Sprintf("%d", record.FP),
		fmt.Sprintf("%d", record.FN),
		fmt.Sprintf("%.6f", record.Accuracy),
	}
	if err := w.Write(row); err != nil {
		return "", err
	}
	if err := w.Error(); err != nil {
		return "", err
	}
	return path, nil
}

type DecisionConsistencyObservation struct {
	DeviceUUID     string
	SystemDecision string
	PFinal         float64
}

type DecisionConsistencyResult struct {
	DeviceUUID          string
	SystemDecision      string
	AcceptCount         int
	RejectCount         int
	RunsSeen            int
	DominantDecision    string
	DecisionConsistency float64
	PFinal              float64
	PFinalStdDev        float64
}

type decisionConsistencyState struct {
	Version int                            `json:"version"`
	Devices map[string]deviceDecisionState `json:"devices"`
}

type deviceDecisionState struct {
	AcceptCount    int     `json:"accept_count"`
	RejectCount    int     `json:"reject_count"`
	PRuns          int     `json:"p_runs"`
	PFinalSum      float64 `json:"p_final_sum"`
	PFinalSumSq    float64 `json:"p_final_sum_sq"`
	TotalRunsCount int     `json:"total_runs_count"`
}

func AppendDecisionConsistencyCSV(
	dir string,
	runID string,
	observations []DecisionConsistencyObservation,
) (string, []DecisionConsistencyResult, error) {
	if len(observations) == 0 {
		return "", nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}

	statePath := filepath.Join(dir, DecisionConsistencyState)
	state, err := loadDecisionConsistencyState(statePath)
	if err != nil {
		return "", nil, err
	}
	if state.Devices == nil {
		state.Devices = make(map[string]deviceDecisionState)
	}

	csvPath := filepath.Join(dir, DecisionConsistencyCSVName)
	newFile := false
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		newFile = true
	}

	f, err := os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if newFile {
		header := []string{
			"timestamp_utc",
			"run_id",
			"device_uuid",
			"system_decision",
			"accept_count",
			"reject_count",
			"runs_seen",
			"dominant_decision",
			"decision_consistency",
			"p_final",
			"p_final_stddev",
		}
		if err := w.Write(header); err != nil {
			return "", nil, err
		}
	}

	if runID == "" {
		runID = time.Now().UTC().Format("20060102T150405Z")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	results := make([]DecisionConsistencyResult, 0, len(observations))

	for _, obs := range observations {
		devState := state.Devices[obs.DeviceUUID]
		if obs.SystemDecision == "accept" {
			devState.AcceptCount++
		} else {
			devState.RejectCount++
		}
		devState.TotalRunsCount++
		devState.PRuns++
		devState.PFinalSum += obs.PFinal
		devState.PFinalSumSq += obs.PFinal * obs.PFinal
		state.Devices[obs.DeviceUUID] = devState

		dominantDecision := "accept"
		dominantCount := devState.AcceptCount
		if devState.RejectCount > dominantCount {
			dominantDecision = "reject"
			dominantCount = devState.RejectCount
		}
		consistency := 0.0
		if devState.TotalRunsCount > 0 {
			consistency = float64(dominantCount) / float64(devState.TotalRunsCount)
		}

		mean := 0.0
		if devState.PRuns > 0 {
			mean = devState.PFinalSum / float64(devState.PRuns)
		}
		variance := 0.0
		if devState.PRuns > 0 {
			variance = (devState.PFinalSumSq / float64(devState.PRuns)) - (mean * mean)
		}
		if variance < 0 {
			variance = 0
		}
		stddev := math.Sqrt(variance)

		row := []string{
			now,
			runID,
			obs.DeviceUUID,
			obs.SystemDecision,
			fmt.Sprintf("%d", devState.AcceptCount),
			fmt.Sprintf("%d", devState.RejectCount),
			fmt.Sprintf("%d", devState.TotalRunsCount),
			dominantDecision,
			fmt.Sprintf("%.6f", consistency),
			fmt.Sprintf("%.6f", obs.PFinal),
			fmt.Sprintf("%.6f", stddev),
		}
		if err := w.Write(row); err != nil {
			return "", nil, err
		}

		results = append(results, DecisionConsistencyResult{
			DeviceUUID:          obs.DeviceUUID,
			SystemDecision:      obs.SystemDecision,
			AcceptCount:         devState.AcceptCount,
			RejectCount:         devState.RejectCount,
			RunsSeen:            devState.TotalRunsCount,
			DominantDecision:    dominantDecision,
			DecisionConsistency: consistency,
			PFinal:              obs.PFinal,
			PFinalStdDev:        stddev,
		})
	}

	if err := w.Error(); err != nil {
		return "", nil, err
	}
	if err := saveDecisionConsistencyState(statePath, state); err != nil {
		return "", nil, err
	}
	return csvPath, results, nil
}

func loadDecisionConsistencyState(path string) (decisionConsistencyState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return decisionConsistencyState{
				Version: 1,
				Devices: map[string]deviceDecisionState{},
			}, nil
		}
		return decisionConsistencyState{}, err
	}
	var state decisionConsistencyState
	if err := json.Unmarshal(data, &state); err != nil {
		return decisionConsistencyState{}, err
	}
	if state.Version == 0 {
		state.Version = 1
	}
	if state.Devices == nil {
		state.Devices = map[string]deviceDecisionState{}
	}
	return state, nil
}

func saveDecisionConsistencyState(path string, state decisionConsistencyState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
