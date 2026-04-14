package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	mr "math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"auth/hmmr"
	"auth/internal/besu"
	"auth/internal/blockchain"
	internalmetrics "auth/internal/metrics"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
)

const (
	MinAcceptableTotal    = 225.0
	FinalConsensus        = 0.60
	IoTDevicesJSON        = "iot_devices.json"
	RegisteredDevicesJSON = "sc_devices.json"
	BlocksDirectory       = "blocks"
	SensorLeavesFile      = "sensor_leaves.b64"
	MetricsDirectory      = "metrics"
)

// IoTDevice represents an off-chain voter.
type IoTDevice struct {
	UUID                     string  `json:"uuid"`
	Weight                   uint    `json:"weight"`
	TrustScore               float64 `json:"trustScore"`
	LastVoteOutcome          bool    `json:"lastVoteOutcome"`
	IncorrectVoteStreak      uint    `json:"incorrectVoteStreak"`
	TotalVotesCast           uint    `json:"totalVotesCast"`
	CorrectVoteCount         uint    `json:"correctVoteCount"`
	IncorrectVoteCount       uint    `json:"incorrectVoteCount"`
	LastAuthenticationResult string  `json:"lastAuthenticationResult"`
	ConfidenceLevel          float64 `json:"confidenceLevel"`
	LastInteraction          string  `json:"lastInteraction"`
	SuspensionPeriod         uint    `json:"suspensionPeriod"`
	IsMalicious              bool    `json:"IsMalicious"`
}

// SCDevice holds the device metadata previously fetched from-chain, now local.
type SCDevice struct {
	UUID                            string  `json:"uuid"`
	TrustScore                      float64 `json:"trustScore"`
	HardwareScore                   float64 `json:"hardwareScore"`
	SecurityScore                   float64 `json:"securityScore"`
	DataIntegrityScore              float64 `json:"dataIntegrityScore,omitempty"`
	ManufacturerCertScore           float64 `json:"manufacturerCertScore,omitempty"`
	PerformanceScore                float64 `json:"performanceScore,omitempty"`
	NetworkCompatibilityScore       float64 `json:"networkCompatibilityScore,omitempty"`
	TrustUncertainty                float64 `json:"trustUncertainty,omitempty"`
	HardwareUncertainty             float64 `json:"hardwareUncertainty,omitempty"`
	SecurityUncertainty             float64 `json:"securityUncertainty,omitempty"`
	DataIntegrityUncertainty        float64 `json:"dataIntegrityUncertainty,omitempty"`
	ManufacturerCertUncertainty     float64 `json:"manufacturerCertUncertainty,omitempty"`
	PerformanceUncertainty          float64 `json:"performanceUncertainty,omitempty"`
	NetworkCompatibilityUncertainty float64 `json:"networkCompatibilityUncertainty,omitempty"`
	Weight                          float64 `json:"weight"`
	Authenticated                   bool    `json:"authenticated"`
	LastActive                      int64   `json:"lastActive"`
	CorrectVotes                    uint    `json:"correctVotes"`
	IncorrectVotes                  uint    `json:"incorrectVotes"`
	VotesReceivedYes                uint    `json:"votesReceivedYes"`
	VotesReceivedNo                 uint    `json:"votesReceivedNo"`
	VotesReceivedTotal              uint    `json:"votesReceivedTotal"`
	IsMalicious                     bool    `json:"isMalicious,omitempty"`
}

// DeviceHistory tracks reputational progression for IoT devices.
type DeviceHistory struct {
	UUID                string
	AuthSpeed           []float64
	VoteOutcome         []int
	WeightHistory       []uint
	VoteAccuracyHistory []float64
	TrustScoreHistory   []float64
}

type admissionDecisionObservation struct {
	DeviceUUID     string
	GroundTruth    string
	SystemDecision string
	PFinal         float64
}

var deviceHistories = make(map[string]*DeviceHistory)

func main() {
	_ = godotenv.Load()
	hmmrMetricsEnabled := flag.Bool("hmmr-metrics", false, "collect HMMR metrics while building blocks")
	hmmrHashAlgorithm := flag.String("hmmr-hash", "sha256", "hash algorithm for HMMR leaves (sha256)")
	hmmrStorePath := flag.String("hmmr-store", hmmr.DefaultSubgroupStorePath, "path to the persisted subgroup-HMMR event log")
	hmmrEventArity := flag.Int("hmmr-event-arity", 16, "subgroup-HMMR event branching factor")
	hmmrEventSubgroup := flag.Int("hmmr-event-subgroup", 4, "subgroup-HMMR event subgroup size")
	hmmrEventHash := flag.String("hmmr-event-hash", "sha256", "subgroup-HMMR event hash: sha256 or sha512")
	devicesPath := flag.String("devices", RegisteredDevicesJSON, "path to registered devices JSON")
	blocksDir := flag.String("blocks-dir", BlocksDirectory, "directory where blocks are stored")
	sensorLeavesTarget := flag.Int("sensor-leaves", 0, "desired number of sensor-data leaves per block (0 = auto)")
	leafMode := flag.String("leaf-mode", "block", "leaf accumulation mode: 'block' (per block) or 'accumulate'")
	sensorEnabled := flag.Bool("sensor-enabled", true, "include synthetic sensor payloads as additional leaves")
	leafSize := flag.Int("leaf-size", 256, "leaf size in bytes (e.g., 32 to mimic transaction hashes)")
	authAsync := flag.Bool("auth-async", false, "submit auth txs without waiting for mining")
	authWait := flag.Bool("auth-wait", false, "wait for auth txs after submitting (requires -auth-async)")
	continueOnBesuError := flag.Bool("continue-on-besu-error", true, "continue processing other devices if one Besu authentication call fails")
	besuRetries := flag.Int("besu-retries", 3, "number of retries for Besu auth submission/receipt wait")
	besuRetryDelayMs := flag.Int("besu-retry-delay-ms", 250, "delay between Besu retries in milliseconds")
	voterFormulaA := flag.Float64("voter-formula-a", 2.0, "voter selection formula coefficient 'a' in k = a * log_b(N)")
	voterFormulaBase := flag.Float64("voter-formula-b", 10.0, "voter selection formula base 'b' in k = a * log_b(N), must be > 1")
	countEventRecordingMessage := flag.Bool("count-event-recording-message", false, "count event recording submission as a separate protocol message")
	consistencyRunID := flag.String("consistency-run-id", "", "optional run identifier for decision consistency records (default: auto timestamp)")
	trackedVoterUUID := flag.String("tracked-voter-uuid", "", "track trust/weight CSV only for this voter UUID (default: first IoT voter in file)")
	weightOmegaHardware := flag.Float64("weight-omega-hardware", 1.0, "omega for hardwareScore in candidate weight formula")
	weightOmegaSecurity := flag.Float64("weight-omega-security", 1.0, "omega for securityScore in candidate weight formula")
	weightOmegaDataIntegrity := flag.Float64("weight-omega-data-integrity", 1.0, "omega for dataIntegrityScore in candidate weight formula")
	weightOmegaManufacturerCert := flag.Float64("weight-omega-manufacturer-cert", 1.0, "omega for manufacturerCertScore in candidate weight formula")
	weightOmegaPerformance := flag.Float64("weight-omega-performance", 1.0, "omega for performanceScore in candidate weight formula")
	weightOmegaNetworkCompatibility := flag.Float64("weight-omega-network-compatibility", 1.0, "omega for networkCompatibilityScore in candidate weight formula")
	weightLambda := flag.Float64("weight-lambda", 1.0, "lambda uncertainty penalty in candidate weight formula")
	flag.Parse()

	mr.Seed(time.Now().UnixNano())

	mode := strings.ToLower(strings.TrimSpace(*leafMode))
	if mode != "block" && mode != "accumulate" {
		log.Fatalf("invalid leaf-mode %q; use 'block' or 'accumulate'", *leafMode)
	}
	if *leafSize <= 0 {
		log.Fatalf("leaf-size must be greater than zero")
	}

	iotDevs, err := loadIoTDevices(IoTDevicesJSON)
	if err != nil {
		log.Fatalf("loadIoTDevices: %v", err)
	}
	log.Printf("Loaded %d IoT voters", len(iotDevs))
	if len(iotDevs) == 0 {
		log.Fatalf("no IoT voters available")
	}

	trackedVoter := strings.TrimSpace(*trackedVoterUUID)
	if trackedVoter == "" {
		trackedVoter = iotDevs[0].UUID
	}
	log.Printf("Tracking trust/weight for single voter UUID: %s", trackedVoter)

	scDevices, err := loadRegisteredDevices(*devicesPath)
	if err != nil {
		log.Fatalf("loadRegisteredDevices: %v", err)
	}
	log.Printf("Registered devices available: %d", len(scDevices))

	eventStore, err := hmmr.LoadSubgroupEventStore(*hmmrStorePath, *hmmrEventArity, *hmmrEventSubgroup, *hmmrEventHash)
	if err != nil {
		log.Fatalf("load subgroup hmmr store: %v", err)
	}

	besuClient, err := besu.NewClientFromEnv()
	if err != nil {
		log.Fatalf("init besu client: %v", err)
	}
	if besuClient != nil {
		log.Printf("Besu enabled: skipping on-chain registration in auth; use cmd/reg to register devices")
	}

	indexByUUID := make(map[string]int, len(scDevices))
	var unauth []SCDevice
	for i, dev := range scDevices {
		indexByUUID[dev.UUID] = i
		if !dev.Authenticated {
			unauth = append(unauth, dev)
		}
	}
	if len(unauth) == 0 {
		log.Println("Nothing to do – all devices are authenticated")
		return
	}
	if *voterFormulaA <= 0 {
		log.Fatalf("voter-formula-a must be > 0")
	}
	if *voterFormulaBase <= 1 {
		log.Fatalf("voter-formula-b must be > 1")
	}

	nTargets := len(unauth)
	rawK := *voterFormulaA * (math.Log(float64(nTargets)) / math.Log(*voterFormulaBase))
	voterCount := int(math.Ceil(rawK))
	if voterCount < 1 {
		voterCount = 1
	}
	if voterCount > len(iotDevs) {
		voterCount = len(iotDevs)
	}
	log.Printf(
		"Voter selection math: k = a * log_b(N), a=%.4f, b=%.4f, N=%d => raw=%.6f, ceil(raw)=%d, capped_to_available=%d",
		*voterFormulaA,
		*voterFormulaBase,
		nTargets,
		rawK,
		int(math.Ceil(rawK)),
		voterCount,
	)

	offChainTimesMs := make([]float64, 0, len(unauth))
	offChainTimesNs := make([]int64, 0, len(unauth))
	commCostBytes := make([]int, 0, len(unauth))
	admissionLatenciesNs := make([]int64, 0, len(unauth))
	scoreCalculationMs := make([]float64, 0, len(unauth))
	voteComputationMs := make([]float64, 0, len(unauth))
	scoreUpdateMs := make([]float64, 0, len(unauth))
	totalLocalComputationMs := make([]float64, 0, len(unauth))
	protocolMessagesTotal := make([]int, 0, len(unauth))
	admissionObservations := make([]admissionDecisionObservation, 0, len(unauth))
	transactions := make([]blockchain.Transaction, 0, len(unauth))
	successCount := 0
	tpCount := 0
	tnCount := 0
	fpCount := 0
	fnCount := 0
	var newlyAuthenticated []SCDevice

	latestBlock, err := blockchain.LoadLatest(*blocksDir)
	if err != nil {
		log.Fatalf("LoadLatest block: %v", err)
	}

	var authTxs []common.Hash
	authSubmitFailed := make([]string, 0)
	authReceiptFailed := make([]string, 0)
	authLoopStart := time.Now()
	trackedVoterHonestCSVPath := ""
	trackedVoterMaliciousCSVPath := ""
	for _, dev := range unauth {
		deviceAdmissionStart := time.Now()
		log.Printf("\n=== Device %s =========================================", dev.UUID)

		eligibleVoters := filterEligibleVotersByMinWeight(iotDevs, 10)
		effectiveVoterCount := voterCount
		if len(eligibleVoters) < voterCount {
			effectiveVoterCount = voterCount - 1
		}
		if effectiveVoterCount > len(eligibleVoters) {
			effectiveVoterCount = len(eligibleVoters)
		}
		if effectiveVoterCount < 0 {
			effectiveVoterCount = 0
		}
		voters := randomSubset(eligibleVoters, effectiveVoterCount)
		voterIDs := make([]string, len(voters))
		for i := range voters {
			voterIDs[i] = voters[i].UUID
		}
		log.Printf("Selected voters for %s (k=%d, eligible_weight_gt_10=%d): %s", dev.UUID, len(voters), len(eligibleVoters), strings.Join(voterIDs, ", "))
		if len(voters) < 3 {
			log.Printf("Not enough eligible voters for %s: selected=%d, minimum required=3; admission decision will be REJECT", dev.UUID, len(voters))
		} else if len(voters) == voterCount-1 {
			log.Printf("Using fallback voter count for %s: requested_k=%d, used_k=%d", dev.UUID, voterCount, len(voters))
		}

		t0 := time.Now()
		yesCnt, tot, yesWeight, totalWeight, candidateWeight, yesMap, scoreCalcDur, voteCompDur := doOffChainVoting(
			voters,
			dev,
			*weightOmegaHardware,
			*weightOmegaSecurity,
			*weightOmegaDataIntegrity,
			*weightOmegaManufacturerCert,
			*weightOmegaPerformance,
			*weightOmegaNetworkCompatibility,
			*weightLambda,
		)
		offChainDur := time.Since(t0)
		offChainTimesMs = append(offChainTimesMs, float64(offChainDur.Milliseconds()))
		offChainTimesNs = append(offChainTimesNs, offChainDur.Nanoseconds())
		scoreCalculationMs = append(scoreCalculationMs, float64(scoreCalcDur.Nanoseconds())/1e6)
		voteComputationMs = append(voteComputationMs, float64(voteCompDur.Nanoseconds())/1e6)

		yesPct := 0.0
		if totalWeight > 0 {
			yesPct = yesWeight / totalWeight
		}
		authenticate := tot > 2 && yesPct >= FinalConsensus
		trackedVoterParticipated := false
		for _, v := range voters {
			if v.UUID == trackedVoter {
				trackedVoterParticipated = true
				break
			}
		}
		groundTruth := groundTruthLabel(dev)
		systemDecision := "reject"
		if authenticate {
			systemDecision = "accept"
		}
		admissionObservations = append(admissionObservations, admissionDecisionObservation{
			DeviceUUID:     dev.UUID,
			GroundTruth:    groundTruth,
			SystemDecision: systemDecision,
			PFinal:         yesPct,
		})
		switch {
		case groundTruth == "legit" && authenticate:
			tpCount++
		case groundTruth == "malicious" && !authenticate:
			tnCount++
		case groundTruth == "malicious" && authenticate:
			fpCount++
		case groundTruth == "legit" && !authenticate:
			fnCount++
		}

		if authenticate {
			successCount++
		}
		log.Printf(
			"Weighted voting for %s: yes_weight=%.2f total_weight=%.2f ratio=%.4f candidate_weight=%.2f threshold=%.2f",
			dev.UUID,
			yesWeight,
			totalWeight,
			yesPct,
			candidateWeight,
			MinAcceptableTotal,
		)

		scIdx := indexByUUID[dev.UUID]
		scDevices[scIdx].VotesReceivedYes += uint(yesCnt)
		scDevices[scIdx].VotesReceivedNo += uint(tot - yesCnt)
		scDevices[scIdx].VotesReceivedTotal += uint(tot)
		scDevices[scIdx].LastActive = time.Now().UnixNano()
		if authenticate {
			scDevices[scIdx].Authenticated = true
			scDevices[scIdx].CorrectVotes++
			newlyAuthenticated = append(newlyAuthenticated, scDevices[scIdx])
		} else {
			scDevices[scIdx].IncorrectVotes++
		}

		scoreUpdateStart := time.Now()
		updateDevicesWeight(iotDevs, voters, yesMap, authenticate)
		scoreUpdateDur := time.Since(scoreUpdateStart)
		if trackedVoterParticipated {
			updatedTrackedVoter, ok := getIoTVoterByUUID(iotDevs, trackedVoter)
			if ok {
				csvPath, err := internalmetrics.AppendVoterInteractionCSV(MetricsDirectory, internalmetrics.VoterInteractionRecord{
					VoterIsMalicious:    updatedTrackedVoter.IsMalicious,
					TrustScoreAfterVote: updatedTrackedVoter.TrustScore,
					WeightAfterVote:     updatedTrackedVoter.Weight,
				})
				if err != nil {
					log.Fatalf("save tracked-voter trust/weight csv: %v", err)
				}
				if updatedTrackedVoter.IsMalicious {
					trackedVoterMaliciousCSVPath = csvPath
				} else {
					trackedVoterHonestCSVPath = csvPath
				}
			}
		}
		scoreUpdateMs = append(scoreUpdateMs, float64(scoreUpdateDur.Nanoseconds())/1e6)
		totalLocalMs := float64(scoreCalcDur.Nanoseconds()+voteCompDur.Nanoseconds()+scoreUpdateDur.Nanoseconds()) / 1e6
		totalLocalComputationMs = append(totalLocalComputationMs, totalLocalMs)

		payload := buildTransactionPayload(dev.UUID, authenticate, yesCnt, tot-yesCnt, yesMap)
		commCostBytes = append(commCostBytes, len(payload))
		transactions = append(transactions, blockchain.NewTransaction("auth_result", payload, time.Now()))
		admissionRequestCount := 1
		evaluatorSelectionCount := tot
		votesSentCount := tot
		finalDecisionCount := 1
		eventRecordingCount := 0
		if *countEventRecordingMessage {
			eventRecordingCount = 1
		}
		totalProtocolMessages := admissionRequestCount + evaluatorSelectionCount + votesSentCount + finalDecisionCount + eventRecordingCount
		protocolMessagesTotal = append(protocolMessagesTotal, totalProtocolMessages)

		decision := "rejected"
		if authenticate {
			decision = "authenticated"
		}
		if _, _, err := eventStore.AddEvent(hmmr.Event{
			DeviceID:  dev.UUID,
			Decision:  decision,
			Weight:    candidateWeight,
			Timestamp: time.Now().UTC(),
		}); err != nil {
			log.Fatalf("append auth event to subgroup hmmr: %v", err)
		}

		if besuClient != nil {
			if *authAsync {
				txHash, err := authenticateDeviceAsyncWithRetry(
					besuClient,
					dev.UUID,
					authenticate,
					*besuRetries,
					time.Duration(*besuRetryDelayMs)*time.Millisecond,
				)
				if err != nil {
					if *continueOnBesuError {
						log.Printf("besu authenticate device %s failed: %v", dev.UUID, err)
						authSubmitFailed = append(authSubmitFailed, dev.UUID)
					} else {
						log.Fatalf("besu authenticate device %s: %v", dev.UUID, err)
					}
				} else {
					authTxs = append(authTxs, txHash)
					log.Printf("Submitted auth %s (tx %s)", dev.UUID, txHash.Hex())
				}
			} else {
				err := authenticateDeviceWithRetry(
					besuClient,
					dev.UUID,
					authenticate,
					*besuRetries,
					time.Duration(*besuRetryDelayMs)*time.Millisecond,
				)
				if err != nil {
					if *continueOnBesuError {
						log.Printf("besu authenticate device %s failed: %v", dev.UUID, err)
						authSubmitFailed = append(authSubmitFailed, dev.UUID)
					} else {
						log.Fatalf("besu authenticate device %s: %v", dev.UUID, err)
					}
				}
			}
		}

		admissionLatenciesNs = append(admissionLatenciesNs, time.Since(deviceAdmissionStart).Nanoseconds())
	}
	authLoopDuration := time.Since(authLoopStart)

	if besuClient != nil && *authAsync && *authWait && len(authTxs) > 0 {
		log.Printf("Waiting for %d auth transaction(s)...", len(authTxs))
		for _, hash := range authTxs {
			err := waitReceiptWithRetry(
				besuClient,
				hash,
				*besuRetries,
				time.Duration(*besuRetryDelayMs)*time.Millisecond,
			)
			if err != nil {
				if *continueOnBesuError {
					log.Printf("wait for auth tx %s failed: %v", hash.Hex(), err)
					authReceiptFailed = append(authReceiptFailed, hash.Hex())
				} else {
					log.Fatalf("wait for auth tx %s: %v", hash.Hex(), err)
				}
			}
		}
	}

	if err := saveRegisteredDevices(*devicesPath, scDevices); err != nil {
		log.Fatalf("saveRegisteredDevices: %v", err)
	}
	if err := saveIoTDevices(IoTDevicesJSON, iotDevs); err != nil {
		log.Fatalf("saveIoTDevices: %v", err)
	}
	if err := eventStore.Save(*hmmrStorePath); err != nil {
		log.Fatalf("save subgroup hmmr store: %v", err)
	}

	if len(transactions) == 0 {
		log.Println("No transactions produced; skipping block creation")
		return
	}

	sensorTarget := *sensorLeavesTarget
	if !*sensorEnabled {
		sensorTarget = 0
	} else if sensorTarget <= 0 {
		sensorTarget = len(newlyAuthenticated)
	}

	var newLeafPayloads [][]byte
	if *sensorEnabled && sensorTarget > 0 {
		var sensorTxs []blockchain.Transaction
		newLeafPayloads, sensorTxs = generateSensorPayloads(newlyAuthenticated, sensorTarget, *leafSize)
		transactions = append(transactions, sensorTxs...)
	}

	leafPayloads := blockchain.LeavesFromTransactions(transactions, *leafSize)
	leafPayloads = append(leafPayloads, newLeafPayloads...)

	if *sensorEnabled && mode == "accumulate" {
		persisted, err := loadAccumulatedLeaves(filepath.Join(*blocksDir, SensorLeavesFile), *leafSize)
		if err != nil {
			log.Fatalf("load accumulated leaves: %v", err)
		}
		if len(persisted) > 0 {
			leafPayloads = append(persisted, leafPayloads...)
		}
	}

	blockOpts := hmmr.Options{HashAlgorithm: *hmmrHashAlgorithm, CollectMetrics: *hmmrMetricsEnabled}

	block, hmmrMetrics, buildDuration, err := blockchain.BuildBlock(latestBlock, transactions, leafPayloads, *leafSize, blockOpts)
	if err != nil {
		log.Fatalf("BuildBlock: %v", err)
	}

	persistStart := time.Now()
	path, err := blockchain.Persist(*blocksDir, block)
	if err != nil {
		log.Fatalf("Persist block: %v", err)
	}
	persistDuration := time.Since(persistStart)

	perTxBlockTime := float64(buildDuration.Nanoseconds()+persistDuration.Nanoseconds()) / 1e6
	perTxBlockTime /= float64(len(transactions))
	onChainTimesMs := make([]float64, len(transactions))
	for i := range onChainTimesMs {
		onChainTimesMs[i] = perTxBlockTime
	}
	avgAdmissionMs, avgAdmissionNs := averageLatency(admissionLatenciesNs)
	totalThroughput := 0.0
	if authLoopDuration > 0 {
		totalThroughput = float64(len(unauth)) / authLoopDuration.Seconds()
	}
	avgProtocolMessages := averageInt(protocolMessagesTotal)
	avgCommBytes := averageInt(commCostBytes)
	avgCommKB := avgCommBytes / 1024.0
	totalDecisions := tpCount + tnCount + fpCount + fnCount
	admissionAccuracy := 0.0
	if totalDecisions > 0 {
		admissionAccuracy = float64(tpCount+tnCount) / float64(totalDecisions)
	}

	finalMetricsPath, err := internalmetrics.AppendFinalMetricsCSV(MetricsDirectory, internalmetrics.FinalMetricsRecord{
		TimestampUTC:                 time.Now().UTC(),
		MetricSource:                 "auth_run",
		CandidateDevicesX:            len(unauth),
		TotalNetworkSize:             len(iotDevs),
		SelectedEvaluatorsK:          voterCount,
		AdmissionLatencyMs:           avgAdmissionMs,
		ThroughputDevicesPerSec:      totalThroughput,
		CommunicationCostBytesAvg:    avgCommBytes,
		CommunicationCostKBAvg:       avgCommKB,
		CommunicationOverheadMsgsAvg: avgProtocolMessages,
	})
	if err != nil {
		log.Fatalf("save final metrics csv: %v", err)
	}
	admissionAccuracyCSVPath, err := internalmetrics.AppendAdmissionAccuracyCSV(MetricsDirectory, internalmetrics.AdmissionAccuracyRecord{
		TimestampUTC:      time.Now().UTC(),
		CandidateDevicesX: len(unauth),
		TP:                tpCount,
		TN:                tnCount,
		FP:                fpCount,
		FN:                fnCount,
		Accuracy:          admissionAccuracy,
	})
	if err != nil {
		log.Fatalf("save admission accuracy csv: %v", err)
	}
	consistencyObservations := make([]internalmetrics.DecisionConsistencyObservation, 0, len(admissionObservations))
	for _, item := range admissionObservations {
		consistencyObservations = append(consistencyObservations, internalmetrics.DecisionConsistencyObservation{
			DeviceUUID:     item.DeviceUUID,
			SystemDecision: item.SystemDecision,
			PFinal:         item.PFinal,
		})
	}
	decisionConsistencyCSVPath, decisionConsistencyResults, err := internalmetrics.AppendDecisionConsistencyCSV(
		MetricsDirectory,
		*consistencyRunID,
		consistencyObservations,
	)
	if err != nil {
		log.Fatalf("save decision consistency csv: %v", err)
	}

	fmt.Printf("\nBlock %d written to %s (%d tx, build %.2f ms, persist %.2f ms)\n",
		block.Header.Height,
		path,
		len(transactions),
		float64(buildDuration.Nanoseconds())/1e6,
		float64(persistDuration.Nanoseconds())/1e6,
	)
	fmt.Printf("Leaf size in use: %d bytes\n", *leafSize)

	if *sensorEnabled && mode == "accumulate" && len(newLeafPayloads) > 0 {
		if err := appendAccumulatedLeaves(filepath.Join(*blocksDir, SensorLeavesFile), newLeafPayloads, *leafSize); err != nil {
			log.Fatalf("append accumulated leaves: %v", err)
		}
	}

	if hmmrMetrics != nil {
		fmt.Printf("HMMR Metrics — Leaves: %d, BuildTime: %.3f ms, ProofTime: %.3f ms, ProofSize: %d bytes, Depth: %d, MemoryUsed: %d bytes\n",
			hmmrMetrics.LeafCount,
			hmmrMetrics.BuildTimeMs,
			hmmrMetrics.ProofTimeMs,
			hmmrMetrics.ProofSizeBytes,
			hmmrMetrics.Depth,
			hmmrMetrics.MemoryUsedBytes,
		)
	}

	fmt.Printf("Sensor leaves generated this run: %d (target %d, mode %s, enabled %t)\n", len(newLeafPayloads), sensorTarget, mode, *sensorEnabled)
	if *sensorEnabled && mode == "accumulate" {
		fmt.Printf("Total leaves used for block: %d\n", len(leafPayloads))
	}
	fmt.Printf("Final metrics CSV written to: %s\n", finalMetricsPath)
	fmt.Printf("Admission accuracy CSV written to: %s\n", admissionAccuracyCSVPath)
	if decisionConsistencyCSVPath != "" {
		fmt.Printf("Decision consistency CSV (append) written to: %s\n", decisionConsistencyCSVPath)
	}
	if trackedVoterHonestCSVPath != "" {
		fmt.Printf("Tracked-voter trust/weight CSV (honest) written to: %s\n", trackedVoterHonestCSVPath)
	}
	if trackedVoterMaliciousCSVPath != "" {
		fmt.Printf("Tracked-voter trust/weight CSV (malicious) written to: %s\n", trackedVoterMaliciousCSVPath)
	}

	fmt.Println("\n====================  METRIC SUMMARY  ====================")
	fmt.Printf("Authentication-success rate: %.2f %%\n\n",
		100*float64(successCount)/float64(len(unauth)))

	for i := range offChainTimesMs {
		fmt.Printf("• Device #%d  ComputationalCost: %.3f ms (%d ns)   "+
			"BlockProcessing: %.2f ms   CommunicationCost: %d bytes   ProtocolMessages: %d\n",
			i+1,
			offChainTimesMs[i],
			offChainTimesNs[i],
			onChainTimesMs[i],
			commCostBytes[i],
			protocolMessagesTotal[i],
		)
	}
	totalThroughput = 0.0
	authenticatedThroughput := 0.0
	if authLoopDuration > 0 {
		totalThroughput = float64(len(unauth)) / authLoopDuration.Seconds()
		authenticatedThroughput = float64(successCount) / authLoopDuration.Seconds()
	}
	fmt.Printf("Auth Throughput: %.6f devices/sec (processed=%d, window=%.6f sec)\n",
		totalThroughput, len(unauth), authLoopDuration.Seconds())
	fmt.Printf("Authenticated Throughput: %.6f devices/sec (authenticated=%d, window=%.6f sec)\n",
		authenticatedThroughput, successCount, authLoopDuration.Seconds())
	fmt.Printf("Scalability point: X=%d candidate devices, Y=%.6f ms average admission latency (%.0f ns)\n",
		len(unauth), avgAdmissionMs, avgAdmissionNs)
	fmt.Printf("Evaluator Count Scaling: network_size=%d, selected_evaluators=%d, candidates=%d\n",
		len(iotDevs), voterCount, len(unauth))
	fmt.Printf("Communication Overhead: average %.6f protocol messages per admission decision\n", avgProtocolMessages)
	fmt.Printf("Message model used: request=1, selection=%d, votes=%d, final=1, event_recording=%t\n",
		voterCount, voterCount, *countEventRecordingMessage)
	fmt.Printf("Admission Accuracy: %.6f (TP=%d, TN=%d, FP=%d, FN=%d)\n",
		admissionAccuracy, tpCount, tnCount, fpCount, fnCount)
	if len(decisionConsistencyResults) > 0 {
		fmt.Printf("Decision Consistency (run-level average): %.6f\n", averageDecisionConsistency(decisionConsistencyResults))
	}
	if besuClient != nil {
		fmt.Printf("Besu auth submission failures: %d\n", len(authSubmitFailed))
		fmt.Printf("Besu auth receipt failures: %d\n", len(authReceiptFailed))
	}
	fmt.Printf("Local Computation Averages: score_calculation=%.6f ms, vote_computation=%.6f ms, score_update=%.6f ms, total=%.6f ms\n",
		averageFloat64(scoreCalculationMs),
		averageFloat64(voteComputationMs),
		averageFloat64(scoreUpdateMs),
		averageFloat64(totalLocalComputationMs),
	)
	fmt.Println("==========================================================\n")
}

func loadIoTDevices(filename string) ([]IoTDevice, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var devs []IoTDevice
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, err
	}
	return devs, nil
}

func loadRegisteredDevices(filename string) ([]SCDevice, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var devices []SCDevice
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, err
	}
	return devices, nil
}

func scoreToUint(score float64) *big.Int {
	rounded := int64(math.Round(score))
	if rounded < 0 {
		rounded = 0
	}
	return big.NewInt(rounded)
}

func saveRegisteredDevices(filename string, devices []SCDevice) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0o644)
}

func saveIoTDevices(filename string, devices []IoTDevice) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0o644)
}

func randomSubset(devices []IoTDevice, count int) []IoTDevice {
	n := len(devices)
	if count < 0 {
		count = 0
	}
	if count > n {
		count = n
	}
	subset := make([]IoTDevice, n)
	copy(subset, devices)
	mr.Shuffle(n, func(i, j int) {
		subset[i], subset[j] = subset[j], subset[i]
	})
	return subset[:count]
}

func filterEligibleVotersByMinWeight(devices []IoTDevice, minExclusiveWeight uint) []IoTDevice {
	eligible := make([]IoTDevice, 0, len(devices))
	for _, d := range devices {
		if d.Weight > minExclusiveWeight {
			eligible = append(eligible, d)
		}
	}
	return eligible
}

func doOffChainVoting(
	voters []IoTDevice,
	rd SCDevice,
	omegaHardware float64,
	omegaSecurity float64,
	omegaDataIntegrity float64,
	omegaManufacturerCert float64,
	omegaPerformance float64,
	omegaNetworkCompatibility float64,
	lambda float64,
) (int, int, float64, float64, float64, map[string]bool, time.Duration, time.Duration) {
	votes := make(map[string]bool)
	totalVotes := len(voters)
	yesCount := 0
	yesWeight := 0.0
	totalWeight := 0.0

	scoreCalcStart := time.Now()
	candidateWeight := calculateCandidateWeight(
		rd,
		omegaHardware,
		omegaSecurity,
		omegaDataIntegrity,
		omegaManufacturerCert,
		omegaPerformance,
		omegaNetworkCompatibility,
		lambda,
	)
	scoreCalcDur := time.Since(scoreCalcStart)
	log.Printf("Registered Device %s computed weight = %.2f (Minimum required: %.2f)", rd.UUID, candidateWeight, MinAcceptableTotal)

	voteCompStart := time.Now()
	var wg sync.WaitGroup
	type voteResult struct {
		uuid        string
		isMalicious bool
		vote        bool
		reason      string
	}
	resultsChan := make(chan voteResult, totalVotes)

	for _, d := range voters {
		wg.Add(1)
		go func(v IoTDevice) {
			defer wg.Done()
			var vote bool
			reason := "score_based"
			if !v.IsMalicious && (rd.HardwareScore < 30 ||
				rd.SecurityScore < 30 ||
				rd.DataIntegrityScore < 30 ||
				rd.ManufacturerCertScore < 30 ||
				rd.PerformanceScore < 30 ||
				rd.NetworkCompatibilityScore < 30) {
				vote = false
				parts := make([]string, 0, 6)
				if rd.HardwareScore < 30 {
					parts = append(parts, "hardware<30")
				}
				if rd.SecurityScore < 30 {
					parts = append(parts, "security<30")
				}
				if rd.DataIntegrityScore < 30 {
					parts = append(parts, "data_integrity<30")
				}
				if rd.ManufacturerCertScore < 30 {
					parts = append(parts, "manufacturer_cert<30")
				}
				if rd.PerformanceScore < 30 {
					parts = append(parts, "performance<30")
				}
				if rd.NetworkCompatibilityScore < 30 {
					parts = append(parts, "network_compatibility<30")
				}
				reason = "fails_min_thresholds: " + strings.Join(parts, ",")
			} else {
				vote = candidateWeight >= MinAcceptableTotal
				if v.IsMalicious && candidateWeight < MinAcceptableTotal {
					vote = true
					reason = "malicious_override_yes"
				}
				if v.IsMalicious && candidateWeight >= MinAcceptableTotal {
					vote = false
					reason = "malicious_override_no"
				}
			}
			resultsChan <- voteResult{uuid: v.UUID, isMalicious: v.IsMalicious, vote: vote, reason: reason}
		}(d)
	}

	wg.Wait()
	close(resultsChan)

	resultsByUUID := make(map[string]voteResult, totalVotes)
	for res := range resultsChan {
		votes[res.uuid] = res.vote
		resultsByUUID[res.uuid] = res
		voterWeight := voterWeightByUUID(voters, res.uuid)
		totalWeight += voterWeight
		if res.vote {
			yesCount++
			yesWeight += voterWeight
		}
	}
	voteCompDur := time.Since(voteCompStart)

	log.Printf("Voting details for %s:", rd.UUID)
	for _, voter := range voters {
		res, ok := resultsByUUID[voter.UUID]
		if !ok {
			continue
		}
		voteText := "NO"
		if res.vote {
			voteText = "YES"
		}
		log.Printf("  - voter=%s malicious=%t vote=%s reason=%s", res.uuid, res.isMalicious, voteText, res.reason)
	}
	log.Printf("Voting summary for %s: yes=%d no=%d consensus=%.2f%% threshold=%.2f%%",
		rd.UUID,
		yesCount,
		totalVotes-yesCount,
		100.0*float64(yesCount)/math.Max(float64(totalVotes), 1),
		100.0*FinalConsensus,
	)

	return yesCount, totalVotes, yesWeight, totalWeight, candidateWeight, votes, scoreCalcDur, voteCompDur
}

func updateDevicesWeight(global []IoTDevice, subset []IoTDevice, yesMap map[string]bool, outcome bool) {
	const (
		maxWeight               = 100.0
		minWeight               = 10.0
		LTrust                  = 100.0
		bTrust                  = 1.0
		cTrust                  = 0.02302585093 // calibrated so trust reaches ~99.999 around ~500 correct interactions
		trustPromotionThreshold = 99.999
		penalty                 = 10.0
	)
	const weightIncrement = 2.0

	nowStr := time.Now().Format(time.RFC3339)
	for _, sub := range subset {
		for i := range global {
			if global[i].UUID == sub.UUID {
				global[i].TotalVotesCast++
				global[i].LastInteraction = nowStr

				if yesMap[sub.UUID] == outcome {
					global[i].CorrectVoteCount++
					global[i].IncorrectVoteStreak = 0
					global[i].LastVoteOutcome = true
					global[i].LastAuthenticationResult = "Authenticated"

					newTrust := LTrust * math.Exp(-bTrust*math.Exp(-cTrust*float64(global[i].CorrectVoteCount)))
					if newTrust >= trustPromotionThreshold {
						newWeight := float64(global[i].Weight) + weightIncrement
						if newWeight > maxWeight {
							newWeight = maxWeight
						}
						global[i].Weight = uint(newWeight + 0.5)
						newTrust = 0.0
						global[i].CorrectVoteCount = 0
					}
					global[i].TrustScore = newTrust
				} else {
					global[i].IncorrectVoteCount++
					global[i].IncorrectVoteStreak++
					global[i].LastVoteOutcome = false
					global[i].LastAuthenticationResult = "Rejected"
					newTrust := global[i].TrustScore - penalty
					if newTrust < 1.0 {
						newTrust = 1.0
					}
					global[i].TrustScore = newTrust
					if global[i].IncorrectVoteCount > 5 {
						newWeight := float64(global[i].Weight) * 0.7
						if newWeight < minWeight {
							newWeight = minWeight
						}
						global[i].Weight = uint(newWeight + 0.5)
						global[i].IncorrectVoteCount = 0
					}
				}
				updateDeviceHistory(&global[i])
			}
		}
	}
}

func updateDeviceHistory(dev *IoTDevice) {
	history, ok := deviceHistories[dev.UUID]
	if !ok {
		history = &DeviceHistory{
			UUID:                dev.UUID,
			AuthSpeed:           []float64{},
			VoteOutcome:         []int{},
			WeightHistory:       []uint{},
			VoteAccuracyHistory: []float64{},
			TrustScoreHistory:   []float64{},
		}
		deviceHistories[dev.UUID] = history
	}
	history.WeightHistory = append(history.WeightHistory, dev.Weight)
	history.TrustScoreHistory = append(history.TrustScoreHistory, dev.TrustScore)
	if dev.LastVoteOutcome {
		history.VoteOutcome = append(history.VoteOutcome, 1)
	} else {
		history.VoteOutcome = append(history.VoteOutcome, 0)
	}
	var accuracy float64
	if dev.TotalVotesCast > 0 {
		accuracy = (float64(dev.CorrectVoteCount) / float64(dev.TotalVotesCast)) * 100.0
	}
	history.VoteAccuracyHistory = append(history.VoteAccuracyHistory, accuracy)
}

type authTxPayload struct {
	DeviceUUID string          `json:"device_uuid"`
	Outcome    string          `json:"outcome"`
	YesVotes   int             `json:"yes_votes"`
	NoVotes    int             `json:"no_votes"`
	Timestamp  time.Time       `json:"timestamp"`
	VoterVotes map[string]bool `json:"voter_votes"`
}

func buildTransactionPayload(uuid string, outcome bool, yesVotes, noVotes int, votes map[string]bool) []byte {
	payload := authTxPayload{
		DeviceUUID: uuid,
		Outcome:    map[bool]string{true: "authenticated", false: "rejected"}[outcome],
		YesVotes:   yesVotes,
		NoVotes:    noVotes,
		Timestamp:  time.Now().UTC(),
		VoterVotes: votes,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("marshal auth transaction: %v", err)
	}
	return data
}

type sensorReading struct {
	DeviceUUID  string    `json:"device_uuid"`
	Timestamp   time.Time `json:"timestamp"`
	Temperature float64   `json:"temperature"`
	Humidity    float64   `json:"humidity"`
	Battery     float64   `json:"battery"`
	Sequence    int       `json:"sequence"`
}

func generateSensorPayloads(devices []SCDevice, target int, leafSize int) ([][]byte, []blockchain.Transaction) {
	if len(devices) == 0 || target <= 0 {
		return nil, nil
	}
	if target < len(devices) {
		target = len(devices)
	}

	perDevice := target / len(devices)
	remainder := target % len(devices)
	if perDevice == 0 {
		perDevice = 1
		remainder = 0
	}

	leaves := make([][]byte, 0, target)
	txs := make([]blockchain.Transaction, 0, target)
	sequence := 1

	for _, dev := range devices {
		count := perDevice
		if remainder > 0 {
			count++
			remainder--
		}
		for i := 0; i < count; i++ {
			reading := sensorReading{
				DeviceUUID:  dev.UUID,
				Timestamp:   time.Now().UTC(),
				Temperature: roundFloat(15 + mr.Float64()*15),
				Humidity:    roundFloat(40 + mr.Float64()*40),
				Battery:     roundFloat(20 + mr.Float64()*80),
				Sequence:    sequence,
			}
			sequence++
			payload, err := json.Marshal(reading)
			if err != nil {
				log.Fatalf("marshal sensor payload: %v", err)
			}
			leaf := blockchain.NormalizeLeaf(payload, leafSize)
			leaves = append(leaves, leaf)
			txs = append(txs, blockchain.NewTransaction("sensor_data", payload, time.Now()))
		}
	}
	return leaves, txs
}

func roundFloat(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func loadAccumulatedLeaves(path string, leafSize int) ([][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	leaves := make([][]byte, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("decode leaf: %w", err)
		}
		leaves = append(leaves, blockchain.NormalizeLeaf(data, leafSize))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return leaves, nil
}

func appendAccumulatedLeaves(path string, leaves [][]byte, leafSize int) error {
	if len(leaves) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, leaf := range leaves {
		norm := blockchain.NormalizeLeaf(leaf, leafSize)
		if _, err := writer.WriteString(base64.StdEncoding.EncodeToString(norm) + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func averageLatency(samplesNs []int64) (float64, float64) {
	if len(samplesNs) == 0 {
		return 0, 0
	}

	var totalNs int64
	for _, sample := range samplesNs {
		totalNs += sample
	}
	avgNs := float64(totalNs) / float64(len(samplesNs))
	avgMs := avgNs / 1e6
	return avgMs, avgNs
}

func saveEvaluatorCountScalingCSV(
	dir string,
	totalNetworkSize int,
	candidateDevices int,
	selectedEvaluators int,
	formulaA float64,
	formulaBase float64,
	rawK float64,
) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, "evaluator_count_scaling.csv")
	newFile := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		newFile = true
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if newFile {
		header := []string{
			"timestamp_utc",
			"total_network_size",
			"candidate_devices_n",
			"selected_evaluators_k",
			"formula_a",
			"formula_base_b",
			"raw_k",
		}
		if err := writer.Write(header); err != nil {
			return "", err
		}
	}

	record := []string{
		time.Now().UTC().Format(time.RFC3339),
		fmt.Sprintf("%d", totalNetworkSize),
		fmt.Sprintf("%d", candidateDevices),
		fmt.Sprintf("%d", selectedEvaluators),
		fmt.Sprintf("%.6f", formulaA),
		fmt.Sprintf("%.6f", formulaBase),
		fmt.Sprintf("%.6f", rawK),
	}
	if err := writer.Write(record); err != nil {
		return "", err
	}
	if err := writer.Error(); err != nil {
		return "", err
	}
	return path, nil
}

func authenticateDeviceWithRetry(client *besu.Client, uuid string, status bool, retries int, retryDelay time.Duration) error {
	if retries < 1 {
		retries = 1
	}
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := client.AuthenticateDevice(ctx, uuid, status)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < retries {
			time.Sleep(retryDelay)
		}
	}
	return lastErr
}

func authenticateDeviceAsyncWithRetry(client *besu.Client, uuid string, status bool, retries int, retryDelay time.Duration) (common.Hash, error) {
	if retries < 1 {
		retries = 1
	}
	var (
		lastErr error
		hash    common.Hash
	)
	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		h, err := client.AuthenticateDeviceAsync(ctx, uuid, status)
		cancel()
		if err == nil {
			return h, nil
		}
		lastErr = err
		hash = h
		if attempt < retries {
			time.Sleep(retryDelay)
		}
	}
	return hash, lastErr
}

func waitReceiptWithRetry(client *besu.Client, txHash common.Hash, retries int, retryDelay time.Duration) error {
	if retries < 1 {
		retries = 1
	}
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := client.WaitForReceipt(ctx, txHash)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < retries {
			time.Sleep(retryDelay)
		}
	}
	return lastErr
}

func saveCommunicationOverheadCSV(
	dir string,
	deviceIDs []string,
	admissionRequest []int,
	evaluatorSelection []int,
	votesSent []int,
	finalDecision []int,
	eventRecording []int,
	total []int,
) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("communication_overhead_%s.csv", time.Now().UTC().Format("20060102_150405"))
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"device_uuid",
		"admission_request_messages",
		"evaluator_selection_notification_messages",
		"evaluator_vote_messages",
		"final_decision_notification_messages",
		"event_recording_submission_messages",
		"total_protocol_messages_per_decision",
	}
	if err := writer.Write(header); err != nil {
		return "", err
	}

	for i := range total {
		uuid := ""
		if i < len(deviceIDs) {
			uuid = deviceIDs[i]
		}
		record := []string{
			uuid,
			fmt.Sprintf("%d", admissionRequest[i]),
			fmt.Sprintf("%d", evaluatorSelection[i]),
			fmt.Sprintf("%d", votesSent[i]),
			fmt.Sprintf("%d", finalDecision[i]),
			fmt.Sprintf("%d", eventRecording[i]),
			fmt.Sprintf("%d", total[i]),
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}
	if err := writer.Error(); err != nil {
		return "", err
	}
	return path, nil
}

func averageFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func averageInt(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum int
	for _, v := range values {
		sum += v
	}
	return float64(sum) / float64(len(values))
}

func groundTruthLabel(dev SCDevice) string {
	if dev.IsMalicious {
		return "malicious"
	}
	if dev.Weight >= MinAcceptableTotal {
		return "legit"
	}
	return "malicious"
}

func averageDecisionConsistency(results []internalmetrics.DecisionConsistencyResult) float64 {
	if len(results) == 0 {
		return 0
	}
	var sum float64
	for _, item := range results {
		sum += item.DecisionConsistency
	}
	return sum / float64(len(results))
}

func calculateCandidateWeight(
	dev SCDevice,
	omegaHardware float64,
	omegaSecurity float64,
	omegaDataIntegrity float64,
	omegaManufacturerCert float64,
	omegaPerformance float64,
	omegaNetworkCompatibility float64,
	lambda float64,
) float64 {
	weightedUtility := (omegaHardware * dev.HardwareScore) +
		(omegaSecurity * dev.SecurityScore) +
		(omegaDataIntegrity * dev.DataIntegrityScore) +
		(omegaManufacturerCert * dev.ManufacturerCertScore) +
		(omegaPerformance * dev.PerformanceScore) +
		(omegaNetworkCompatibility * dev.NetworkCompatibilityScore)
	uncertaintyPenalty := lambda * (dev.HardwareUncertainty +
		dev.SecurityUncertainty +
		dev.DataIntegrityUncertainty +
		dev.ManufacturerCertUncertainty +
		dev.PerformanceUncertainty +
		dev.NetworkCompatibilityUncertainty)
	return weightedUtility - uncertaintyPenalty
}

func voterWeightByUUID(voters []IoTDevice, uuid string) float64 {
	for _, v := range voters {
		if v.UUID == uuid {
			return float64(v.Weight)
		}
	}
	return 0
}

func getIoTVoterByUUID(voters []IoTDevice, uuid string) (IoTDevice, bool) {
	for _, v := range voters {
		if v.UUID == uuid {
			return v, true
		}
	}
	return IoTDevice{}, false
}
