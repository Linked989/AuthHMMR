package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"auth/hmmr"
	internalmetrics "auth/internal/metrics"
)

const registeredDevicesFn = "sc_devices.json"

type SCDevice struct {
	UUID           string  `json:"uuid"`
	TrustScore     float64 `json:"trustScore"`
	HardwareScore  float64 `json:"hardwareScore"`
	SecurityScore  float64 `json:"securityScore"`
	Weight         float64 `json:"weight"`
	Authenticated  bool    `json:"authenticated"`
	LastActive     int64   `json:"lastActive"`
	CorrectVotes   uint    `json:"correctVotes"`
	IncorrectVotes uint    `json:"incorrectVotes"`
}

func main() {
	deviceID := flag.String("device", "", "device ID to inspect in the authentication subgroup-HMMR")
	hmmrStorePath := flag.String("hmmr-store", hmmr.DefaultSubgroupStorePath, "path to the persisted subgroup-HMMR event log")
	hmmrEventArity := flag.Int("hmmr-event-arity", 16, "subgroup-HMMR event branching factor")
	hmmrEventSubgroup := flag.Int("hmmr-event-subgroup", 4, "subgroup-HMMR event subgroup size")
	hmmrEventHash := flag.String("hmmr-event-hash", "sha256", "subgroup-HMMR event hash: sha256 or sha512")
	devicesPath := flag.String("devices", registeredDevicesFn, "path to registered devices JSON for current device state")
	leafIndex := flag.Int("leaf-index", -1, "recorded event leaf index used for proof-generation metric")
	eventID := flag.String("event-id", "", "recorded event ID used for proof-generation metric (supported: leaf:<index>)")
	metricsDir := flag.String("metrics-dir", "metrics", "directory where proof-generation metrics CSV is written")
	flag.Parse()

	if strings.TrimSpace(*deviceID) == "" && *leafIndex < 0 && strings.TrimSpace(*eventID) == "" {
		log.Fatal("device ID is required; use -device <ID>")
	}

	tree, err := hmmr.LoadSubgroupEventStore(*hmmrStorePath, *hmmrEventArity, *hmmrEventSubgroup, *hmmrEventHash)
	if err != nil {
		log.Fatalf("load subgroup hmmr store: %v", err)
	}
	if *leafIndex >= 0 || strings.TrimSpace(*eventID) != "" {
		targetLeafIndex := *leafIndex
		if targetLeafIndex < 0 {
			parsed, err := parseLeafIndexFromEventID(*eventID)
			if err != nil {
				log.Fatalf("parse event-id: %v", err)
			}
			targetLeafIndex = parsed
		}

		metric, err := tree.MeasureProofGenerationByLeafIndex(targetLeafIndex)
		if err != nil {
			log.Fatalf("measure proof generation: %v", err)
		}
		metricPath, err := internalmetrics.AppendFinalMetricsCSV(*metricsDir, internalmetrics.FinalMetricsRecord{
			TimestampUTC:          metric.TimestampUTC,
			MetricSource:          "hmmr_proof_metric",
			ProofGenerationTimeMs: metric.ProofGenerationTimeMs,
			ProofSizeBytes:        metric.ProofSizeBytes,
			VerificationTimeMs:    metric.VerificationTimeMs,
			TotalRecordedEvents:   metric.TotalRecordedEvents,
		})
		if err != nil {
			log.Fatalf("save proof-generation metric csv: %v", err)
		}

		fmt.Printf("Proof Generation Metric\n")
		fmt.Printf("EventID: %s\n", metric.EventID)
		fmt.Printf("LeafIndex: %d\n", metric.LeafIndex)
		fmt.Printf("ProofGenerationTimeMs: %.6f\n", metric.ProofGenerationTimeMs)
		fmt.Printf("VerificationTimeMs: %.6f\n", metric.VerificationTimeMs)
		fmt.Printf("TotalNumberOfRecordedEvents: %d\n", metric.TotalRecordedEvents)
		fmt.Printf("ProofSizeBytes: %d\n", metric.ProofSizeBytes)
		fmt.Printf("ProofVerified: %t\n", metric.ProofVerified)
		fmt.Printf("Metrics CSV written to: %s\n", metricPath)
		return
	}

	verifiedEvents, root, err := tree.VerifyDeviceEvents(*deviceID)
	if err != nil {
		log.Fatalf("verify device events: %v", err)
	}
	if len(verifiedEvents) == 0 {
		log.Fatalf("device %s has no authentication events in %s", *deviceID, *hmmrStorePath)
	}

	currentDevice, err := loadDevice(*devicesPath, *deviceID)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("load registered device state: %v", err)
	}

	allVerified := true
	for _, item := range verifiedEvents {
		allVerified = allVerified && item.Verified
	}

	latest := verifiedEvents[len(verifiedEvents)-1]
	latestAdmitted := strings.EqualFold(latest.Event.Decision, "authenticated")
	legitimate := latestAdmitted && allVerified

	evolution := summarizeWeightEvolution(verifiedEvents, currentDevice)

	fmt.Printf("Device: %s\n", *deviceID)
	fmt.Printf("HMMR Root: %s\n", hex.EncodeToString(root))
	fmt.Printf("Authentication Events Found: %d\n", len(verifiedEvents))
	fmt.Printf("All Event Proofs Verified: %t\n", allVerified)
	fmt.Printf("Latest Decision: %s\n", latest.Event.Decision)
	fmt.Printf("Was device %s admitted legitimately? %t\n", *deviceID, legitimate)

	fmt.Println("\nDecision History:")
	for _, item := range verifiedEvents {
		fmt.Printf(
			"- leaf=%d time=%s decision=%s weight=%.2f proof_verified=%t\n",
			item.LeafIndex,
			item.Event.Timestamp.UTC().Format(time.RFC3339),
			item.Event.Decision,
			item.Event.Weight,
			item.Verified,
		)
	}

	fmt.Println("\nTrust/Weight Evolution Check:")
	fmt.Printf("- Timestamps in non-decreasing order: %t\n", evolution.TimestampsOrdered)
	fmt.Printf("- All stored weights are non-negative: %t\n", evolution.NonNegativeWeights)
	fmt.Printf("- Weight changed across history: %t\n", evolution.WeightChanged)
	fmt.Printf("- First recorded weight: %.2f\n", evolution.FirstWeight)
	fmt.Printf("- Latest recorded weight: %.2f\n", evolution.LastWeight)
	if evolution.CurrentDeviceFound {
		fmt.Printf("- Current device weight in %s: %.2f\n", *devicesPath, evolution.CurrentDeviceWeight)
		fmt.Printf("- Latest HMMR weight matches current device record: %t\n", evolution.MatchesCurrentWeight)
		fmt.Printf("- Current device authenticated flag: %t\n", evolution.CurrentAuthenticated)
	} else {
		fmt.Printf("- Current device state not found in %s\n", *devicesPath)
	}
}

func parseLeafIndexFromEventID(eventID string) (int, error) {
	id := strings.TrimSpace(eventID)
	if id == "" {
		return -1, fmt.Errorf("empty event-id")
	}

	if strings.HasPrefix(id, "leaf:") {
		return strconv.Atoi(strings.TrimPrefix(id, "leaf:"))
	}
	if strings.HasPrefix(id, "leaf-") {
		return strconv.Atoi(strings.TrimPrefix(id, "leaf-"))
	}
	return strconv.Atoi(id)
}

type evolutionSummary struct {
	TimestampsOrdered    bool
	NonNegativeWeights   bool
	WeightChanged        bool
	FirstWeight          float64
	LastWeight           float64
	CurrentDeviceFound   bool
	CurrentDeviceWeight  float64
	MatchesCurrentWeight bool
	CurrentAuthenticated bool
}

func summarizeWeightEvolution(events []hmmr.VerifiedSubgroupEvent, current *SCDevice) evolutionSummary {
	summary := evolutionSummary{
		TimestampsOrdered:  true,
		NonNegativeWeights: true,
	}

	if len(events) == 0 {
		return summary
	}

	summary.FirstWeight = events[0].Event.Weight
	summary.LastWeight = events[len(events)-1].Event.Weight

	prevTime := events[0].Event.Timestamp
	prevWeight := events[0].Event.Weight
	if prevWeight < 0 {
		summary.NonNegativeWeights = false
	}

	for i := 1; i < len(events); i++ {
		event := events[i].Event
		if event.Timestamp.Before(prevTime) {
			summary.TimestampsOrdered = false
		}
		if event.Weight < 0 {
			summary.NonNegativeWeights = false
		}
		if event.Weight != prevWeight {
			summary.WeightChanged = true
		}
		prevTime = event.Timestamp
		prevWeight = event.Weight
	}

	if current != nil {
		summary.CurrentDeviceFound = true
		summary.CurrentDeviceWeight = current.Weight
		summary.MatchesCurrentWeight = current.Weight == summary.LastWeight
		summary.CurrentAuthenticated = current.Authenticated
	}

	return summary
}

func loadDevice(path, deviceID string) (*SCDevice, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var devices []SCDevice
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, err
	}

	for i := range devices {
		if devices[i].UUID == deviceID {
			return &devices[i], nil
		}
	}
	return nil, nil
}
