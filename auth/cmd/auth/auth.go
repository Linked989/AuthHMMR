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
	UUID               string  `json:"uuid"`
	TrustScore         float64 `json:"trustScore"`
	HardwareScore      float64 `json:"hardwareScore"`
	SecurityScore      float64 `json:"securityScore"`
	Weight             float64 `json:"weight"`
	Authenticated      bool    `json:"authenticated"`
	LastActive         int64   `json:"lastActive"`
	CorrectVotes       uint    `json:"correctVotes"`
	IncorrectVotes     uint    `json:"incorrectVotes"`
	VotesReceivedYes   uint    `json:"votesReceivedYes"`
	VotesReceivedNo    uint    `json:"votesReceivedNo"`
	VotesReceivedTotal uint    `json:"votesReceivedTotal"`
	IsMalicious        bool    `json:"isMalicious,omitempty"`
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
	evaluatorScalingCSVPath, err := saveEvaluatorCountScalingCSV(
		MetricsDirectory,
		len(iotDevs),
		nTargets,
		voterCount,
		*voterFormulaA,
		*voterFormulaBase,
		rawK,
	)
	if err != nil {
		log.Fatalf("save evaluator count scaling csv: %v", err)
	}

	offChainTimesMs := make([]float64, 0, len(unauth))
	offChainTimesNs := make([]int64, 0, len(unauth))
	commCostBytes := make([]int, 0, len(unauth))
	metricDeviceIDs := make([]string, 0, len(unauth))
	admissionLatenciesNs := make([]int64, 0, len(unauth))
	scoreCalculationMs := make([]float64, 0, len(unauth))
	voteComputationMs := make([]float64, 0, len(unauth))
	scoreUpdateMs := make([]float64, 0, len(unauth))
	totalLocalComputationMs := make([]float64, 0, len(unauth))
	protocolMessagesTotal := make([]int, 0, len(unauth))
	msgAdmissionRequest := make([]int, 0, len(unauth))
	msgEvaluatorSelection := make([]int, 0, len(unauth))
	msgVotesSent := make([]int, 0, len(unauth))
	msgFinalDecision := make([]int, 0, len(unauth))
	msgEventRecording := make([]int, 0, len(unauth))
	transactions := make([]blockchain.Transaction, 0, len(unauth))
	successCount := 0
	var newlyAuthenticated []SCDevice

	latestBlock, err := blockchain.LoadLatest(*blocksDir)
	if err != nil {
		log.Fatalf("LoadLatest block: %v", err)
	}

	var authTxs []common.Hash
	authSubmitFailed := make([]string, 0)
	authReceiptFailed := make([]string, 0)
	authLoopStart := time.Now()
	for _, dev := range unauth {
		deviceAdmissionStart := time.Now()
		log.Printf("\n=== Device %s =========================================", dev.UUID)

		voters := randomSubset(iotDevs, voterCount)
		voterIDs := make([]string, len(voters))
		for i := range voters {
			voterIDs[i] = voters[i].UUID
		}
		log.Printf("Selected voters for %s (k=%d): %s", dev.UUID, len(voters), strings.Join(voterIDs, ", "))

		t0 := time.Now()
		yesCnt, tot, yesMap, scoreCalcDur, voteCompDur := doOffChainVoting(voters, dev)
		offChainDur := time.Since(t0)
		offChainTimesMs = append(offChainTimesMs, float64(offChainDur.Milliseconds()))
		offChainTimesNs = append(offChainTimesNs, offChainDur.Nanoseconds())
		metricDeviceIDs = append(metricDeviceIDs, dev.UUID)
		scoreCalculationMs = append(scoreCalculationMs, float64(scoreCalcDur.Nanoseconds())/1e6)
		voteComputationMs = append(voteComputationMs, float64(voteCompDur.Nanoseconds())/1e6)

		yesPct := float64(yesCnt) / float64(tot)
		authenticate := yesPct >= FinalConsensus

		if authenticate {
			successCount++
		}

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
		msgAdmissionRequest = append(msgAdmissionRequest, admissionRequestCount)
		msgEvaluatorSelection = append(msgEvaluatorSelection, evaluatorSelectionCount)
		msgVotesSent = append(msgVotesSent, votesSentCount)
		msgFinalDecision = append(msgFinalDecision, finalDecisionCount)
		msgEventRecording = append(msgEventRecording, eventRecordingCount)
		protocolMessagesTotal = append(protocolMessagesTotal, totalProtocolMessages)

		decision := "rejected"
		if authenticate {
			decision = "authenticated"
		}
		if _, _, err := eventStore.AddEvent(hmmr.Event{
			DeviceID:  dev.UUID,
			Decision:  decision,
			Weight:    dev.Weight,
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
	metricsPath, err := saveAuthMetricsCSV(MetricsDirectory, metricDeviceIDs, offChainTimesMs, offChainTimesNs, onChainTimesMs, commCostBytes)
	if err != nil {
		log.Fatalf("save auth metrics csv: %v", err)
	}
	throughputCSVPath, err := saveAuthThroughputCSV(MetricsDirectory, len(unauth), successCount, authLoopDuration)
	if err != nil {
		log.Fatalf("save auth throughput csv: %v", err)
	}
	commOverheadCSVPath, err := saveCommunicationOverheadCSV(
		MetricsDirectory,
		metricDeviceIDs,
		msgAdmissionRequest,
		msgEvaluatorSelection,
		msgVotesSent,
		msgFinalDecision,
		msgEventRecording,
		protocolMessagesTotal,
	)
	if err != nil {
		log.Fatalf("save communication overhead csv: %v", err)
	}
	localComputationCSVPath, err := saveLocalComputationMetricsCSV(
		MetricsDirectory,
		metricDeviceIDs,
		scoreCalculationMs,
		voteComputationMs,
		scoreUpdateMs,
		totalLocalComputationMs,
	)
	if err != nil {
		log.Fatalf("save local computation metrics csv: %v", err)
	}
	avgAdmissionMs, avgAdmissionNs := averageLatency(admissionLatenciesNs)
	scalabilityCSVPath, err := saveScalabilityAdmissionLatencyCSV(MetricsDirectory, len(unauth), avgAdmissionMs, avgAdmissionNs)
	if err != nil {
		log.Fatalf("save scalability admission latency csv: %v", err)
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
	fmt.Printf("Metrics CSV written to: %s\n", metricsPath)
	fmt.Printf("Throughput CSV written to: %s\n", throughputCSVPath)
	fmt.Printf("Communication overhead CSV written to: %s\n", commOverheadCSVPath)
	fmt.Printf("Local computation CSV written to: %s\n", localComputationCSVPath)
	fmt.Printf("Scalability CSV written to: %s\n", scalabilityCSVPath)
	fmt.Printf("Evaluator scaling CSV written to: %s\n", evaluatorScalingCSVPath)

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
	totalThroughput := 0.0
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
	avgProtocolMessages := 0.0
	if len(protocolMessagesTotal) > 0 {
		var sumMsgs int
		for _, n := range protocolMessagesTotal {
			sumMsgs += n
		}
		avgProtocolMessages = float64(sumMsgs) / float64(len(protocolMessagesTotal))
	}
	fmt.Printf("Communication Overhead: average %.6f protocol messages per admission decision\n", avgProtocolMessages)
	fmt.Printf("Message model used: request=1, selection=%d, votes=%d, final=1, event_recording=%t\n",
		voterCount, voterCount, *countEventRecordingMessage)
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

func randomSubset(devices []IoTDevice, count int) []IoTDevice {
	n := len(devices)
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

func doOffChainVoting(voters []IoTDevice, rd SCDevice) (int, int, map[string]bool, time.Duration, time.Duration) {
	votes := make(map[string]bool)
	totalVotes := len(voters)
	yesCount := 0

	scoreCalcStart := time.Now()
	trustVal := rd.TrustScore
	hardwareVal := rd.HardwareScore
	securityVal := rd.SecurityScore
	rdTotal := trustVal + hardwareVal + securityVal
	scoreCalcDur := time.Since(scoreCalcStart)
	log.Printf("Registered Device %s total score = %.2f (Minimum required: %.2f)", rd.UUID, rdTotal, MinAcceptableTotal)

	voteCompStart := time.Now()
	var wg sync.WaitGroup
	type voteResult struct {
		uuid string
		vote bool
	}
	resultsChan := make(chan voteResult, totalVotes)

	for _, d := range voters {
		wg.Add(1)
		go func(v IoTDevice) {
			defer wg.Done()
			var vote bool
			if !v.IsMalicious && (trustVal < 30 || hardwareVal < 30 || securityVal < 30) {
				if trustVal < 30 {
					log.Printf("Registered Device %s: TrustScore %.0f is below threshold (30) for voter %s", rd.UUID, trustVal, v.UUID)
				}
				if hardwareVal < 30 {
					log.Printf("Registered Device %s: HardwareScore %.0f is below threshold (30) for voter %s", rd.UUID, hardwareVal, v.UUID)
				}
				if securityVal < 30 {
					log.Printf("Registered Device %s: SecurityScore %.0f is below threshold (30) for voter %s", rd.UUID, securityVal, v.UUID)
				}
				vote = false
			} else {
				vote = rdTotal >= MinAcceptableTotal
				if v.IsMalicious && rdTotal < MinAcceptableTotal {
					vote = true
					log.Printf("Malicious voter %s overrides vote: YES (despite RD_total < %.2f)", v.UUID, MinAcceptableTotal)
				}
				if v.IsMalicious && rdTotal >= MinAcceptableTotal {
					vote = false
					log.Printf("Malicious voter %s overrides vote: NO (despite RD_total >= %.2f)", v.UUID, MinAcceptableTotal)
				}
			}
			resultsChan <- voteResult{uuid: v.UUID, vote: vote}
		}(d)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		votes[res.uuid] = res.vote
		if res.vote {
			yesCount++
		}
	}
	voteCompDur := time.Since(voteCompStart)

	return yesCount, totalVotes, votes, scoreCalcDur, voteCompDur
}

func updateDevicesWeight(global []IoTDevice, subset []IoTDevice, yesMap map[string]bool, outcome bool) {
	const (
		maxWeight = 100.0
		minWeight = 10.0
		LTrust    = 100.0
		bTrust    = 1.0
		cTrust    = 0.5
		penalty   = 10.0
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
					if newTrust >= LTrust {
						newWeight := float64(global[i].Weight) + weightIncrement
						if newWeight > maxWeight {
							newWeight = maxWeight
						}
						global[i].Weight = uint(newWeight + 0.5)
						newTrust = 1.0
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

func saveAuthMetricsCSV(
	dir string,
	deviceIDs []string,
	computationalMs []float64,
	computationalNs []int64,
	blockProcessingMs []float64,
	communicationBytes []int,
) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("auth_metrics_%s.csv", time.Now().UTC().Format("20060102_150405"))
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
		"computational_cost_ms",
		"computational_cost_ns",
		"block_processing_ms",
		"block_processing_ns",
		"communication_cost_bytes",
		"communication_cost_kb",
	}
	if err := writer.Write(header); err != nil {
		return "", err
	}

	rows := len(computationalMs)
	for i := 0; i < rows; i++ {
		uuid := ""
		if i < len(deviceIDs) {
			uuid = deviceIDs[i]
		}

		blockMs := 0.0
		if i < len(blockProcessingMs) {
			blockMs = blockProcessingMs[i]
		}

		commBytes := 0
		if i < len(communicationBytes) {
			commBytes = communicationBytes[i]
		}

		record := []string{
			uuid,
			fmt.Sprintf("%.3f", computationalMs[i]),
			fmt.Sprintf("%d", computationalNs[i]),
			fmt.Sprintf("%.3f", blockMs),
			fmt.Sprintf("%d", int64(math.Round(blockMs*1e6))),
			fmt.Sprintf("%d", commBytes),
			fmt.Sprintf("%.6f", float64(commBytes)/1024.0),
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

func saveAuthThroughputCSV(dir string, processedDevices int, authenticatedDevices int, authWindow time.Duration) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("auth_throughput_%s.csv", time.Now().UTC().Format("20060102_150405"))
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"processed_devices",
		"authenticated_devices",
		"auth_window_seconds",
		"throughput_devices_per_sec",
		"authenticated_throughput_devices_per_sec",
	}
	if err := writer.Write(header); err != nil {
		return "", err
	}

	windowSeconds := authWindow.Seconds()
	throughput := 0.0
	authenticatedThroughput := 0.0
	if windowSeconds > 0 {
		throughput = float64(processedDevices) / windowSeconds
		authenticatedThroughput = float64(authenticatedDevices) / windowSeconds
	}

	record := []string{
		fmt.Sprintf("%d", processedDevices),
		fmt.Sprintf("%d", authenticatedDevices),
		fmt.Sprintf("%.6f", windowSeconds),
		fmt.Sprintf("%.6f", throughput),
		fmt.Sprintf("%.6f", authenticatedThroughput),
	}
	if err := writer.Write(record); err != nil {
		return "", err
	}
	if err := writer.Error(); err != nil {
		return "", err
	}

	return path, nil
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

func saveScalabilityAdmissionLatencyCSV(dir string, candidateDevices int, avgAdmissionMs float64, avgAdmissionNs float64) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, "scalability_admission_latency.csv")
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
			"candidate_devices_x",
			"average_admission_latency_ms",
			"average_admission_latency_ns",
		}
		if err := writer.Write(header); err != nil {
			return "", err
		}
	}

	record := []string{
		time.Now().UTC().Format(time.RFC3339),
		fmt.Sprintf("%d", candidateDevices),
		fmt.Sprintf("%.6f", avgAdmissionMs),
		fmt.Sprintf("%.0f", avgAdmissionNs),
	}
	if err := writer.Write(record); err != nil {
		return "", err
	}
	if err := writer.Error(); err != nil {
		return "", err
	}
	return path, nil
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

func saveLocalComputationMetricsCSV(
	dir string,
	deviceIDs []string,
	scoreCalculationMs []float64,
	voteComputationMs []float64,
	scoreUpdateMs []float64,
	totalLocalComputationMs []float64,
) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	filename := fmt.Sprintf("local_computation_metrics_%s.csv", time.Now().UTC().Format("20060102_150405"))
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
		"score_calculation_ms",
		"vote_computation_ms",
		"score_update_ms",
		"total_local_computation_ms",
	}
	if err := writer.Write(header); err != nil {
		return "", err
	}

	for i := range totalLocalComputationMs {
		uuid := ""
		if i < len(deviceIDs) {
			uuid = deviceIDs[i]
		}

		record := []string{
			uuid,
			fmt.Sprintf("%.6f", scoreCalculationMs[i]),
			fmt.Sprintf("%.6f", voteComputationMs[i]),
			fmt.Sprintf("%.6f", scoreUpdateMs[i]),
			fmt.Sprintf("%.6f", totalLocalComputationMs[i]),
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	avgRow := []string{
		"AVERAGE",
		fmt.Sprintf("%.6f", averageFloat64(scoreCalculationMs)),
		fmt.Sprintf("%.6f", averageFloat64(voteComputationMs)),
		fmt.Sprintf("%.6f", averageFloat64(scoreUpdateMs)),
		fmt.Sprintf("%.6f", averageFloat64(totalLocalComputationMs)),
	}
	if err := writer.Write(avgRow); err != nil {
		return "", err
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
