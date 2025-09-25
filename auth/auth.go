package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	mr "math/rand"
	"os"
	"sync"
	"time"

	"auth/blockchain"
	"auth/hmmr"
)

const (
	NumberOfVoters        = 10
	MinAcceptableTotal    = 225.0
	FinalConsensus        = 0.60
	IoTDevicesJSON        = "iot_devices.json"
	RegisteredDevicesJSON = "sc_devices.json"
	BlocksDirectory       = "blocks"
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
	UUID           string  `json:"uuid"`
	TrustScore     float64 `json:"trustScore"`
	HardwareScore  float64 `json:"hardwareScore"`
	SecurityScore  float64 `json:"securityScore"`
	Weight         float64 `json:"weight"`
	Authenticated  bool    `json:"authenticated"`
	LastActive     int64   `json:"lastActive"`
	CorrectVotes   uint    `json:"correctVotes"`
	IncorrectVotes uint    `json:"incorrectVotes"`
	IsMalicious    bool    `json:"isMalicious,omitempty"`
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
	hmmrMetricsEnabled := flag.Bool("hmmr-metrics", false, "collect HMMR metrics while building blocks")
	hmmrHashAlgorithm := flag.String("hmmr-hash", "sha256", "hash algorithm for HMMR leaves (sha256)")
	devicesPath := flag.String("devices", RegisteredDevicesJSON, "path to registered devices JSON")
	blocksDir := flag.String("blocks-dir", BlocksDirectory, "directory where blocks are stored")
	flag.Parse()

	mr.Seed(time.Now().UnixNano())

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

	offChainTimesMs := make([]float64, 0, len(unauth))
	offChainTimesNs := make([]int64, 0, len(unauth))
	commCostBytes := make([]int, 0, len(unauth))
	transactions := make([]blockchain.Transaction, 0, len(unauth))
	successCount := 0

	latestBlock, err := blockchain.LoadLatest(*blocksDir)
	if err != nil {
		log.Fatalf("LoadLatest block: %v", err)
	}

	for _, dev := range unauth {
		log.Printf("\n=== Device %s =========================================", dev.UUID)

		voters := randomSubset(iotDevs, NumberOfVoters)

		t0 := time.Now()
		yesCnt, tot, yesMap := doOffChainVoting(voters, dev)
		offChainDur := time.Since(t0)
		offChainTimesMs = append(offChainTimesMs, float64(offChainDur.Milliseconds()))
		offChainTimesNs = append(offChainTimesNs, offChainDur.Nanoseconds())

		yesPct := float64(yesCnt) / float64(tot)
		authenticate := yesPct >= FinalConsensus

		if authenticate {
			successCount++
		}

		scIdx := indexByUUID[dev.UUID]
		scDevices[scIdx].LastActive = time.Now().UnixNano()
		if authenticate {
			scDevices[scIdx].Authenticated = true
			scDevices[scIdx].CorrectVotes++
		} else {
			scDevices[scIdx].IncorrectVotes++
		}

		updateDevicesWeight(iotDevs, voters, yesMap, authenticate)

		payload := buildTransactionPayload(dev.UUID, authenticate, yesCnt, tot-yesCnt, yesMap)
		commCostBytes = append(commCostBytes, len(payload))
		transactions = append(transactions, blockchain.NewTransaction("auth_result", payload, time.Now()))
	}

	if err := saveRegisteredDevices(*devicesPath, scDevices); err != nil {
		log.Fatalf("saveRegisteredDevices: %v", err)
	}

	if len(transactions) == 0 {
		log.Println("No transactions produced; skipping block creation")
		return
	}

	blockOpts := hmmr.Options{HashAlgorithm: *hmmrHashAlgorithm, CollectMetrics: *hmmrMetricsEnabled}

	blockStart := time.Now()
	block, hmmrMetrics, err := blockchain.BuildBlock(latestBlock, transactions, blockOpts)
	if err != nil {
		log.Fatalf("BuildBlock: %v", err)
	}
	buildDuration := time.Since(blockStart)

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

	fmt.Printf("\nBlock %d written to %s (%d tx, build %.2f ms, persist %.2f ms)\n",
		block.Header.Height,
		path,
		len(transactions),
		float64(buildDuration.Nanoseconds())/1e6,
		float64(persistDuration.Nanoseconds())/1e6,
	)

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

	fmt.Println("\n====================  METRIC SUMMARY  ====================")
	fmt.Printf("Authentication-success rate: %.2f %%\n\n",
		100*float64(successCount)/float64(len(unauth)))

	for i := range offChainTimesMs {
		fmt.Printf("• Device #%d  ComputationalCost: %.3f ms (%d ns)   "+
			"BlockProcessing: %.2f ms   CommunicationCost: %d bytes\n",
			i+1,
			offChainTimesMs[i],
			offChainTimesNs[i],
			onChainTimesMs[i],
			commCostBytes[i])
	}
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

func doOffChainVoting(voters []IoTDevice, rd SCDevice) (int, int, map[string]bool) {
	votes := make(map[string]bool)
	totalVotes := len(voters)
	yesCount := 0

	trustVal := rd.TrustScore
	hardwareVal := rd.HardwareScore
	securityVal := rd.SecurityScore
	rdTotal := trustVal + hardwareVal + securityVal
	log.Printf("Registered Device %s total score = %.2f (Minimum required: %.2f)", rd.UUID, rdTotal, MinAcceptableTotal)

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

	return yesCount, totalVotes, votes
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
