package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	mr "math/rand" // standard math/rand for shuffling
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// -----------------------------------------------------------------------------
// Configuration Variables
// -----------------------------------------------------------------------------
const (
	SmartContractAddress = "0xEC60ab6e4Ce6B9C0EFB5A5cC9869A9BF5775202b" // Deployed contract address
	NumberOfVoters       = 10                                           // Number of IoT device voters per SC device
	PrivateKeyHex        = "0x3b98505875102bcec9095f5cc443abb14e576f50aa40dbd30cc0c3f1b16f35b4"
	RPCURL               = "http://127.0.0.1:8545" // RPC endpoint (Ganache)
	ABIFilePath          = "abi.json"              // Path to smart contract ABI

	// New individual voting logic:
	// Each registered device (RD) has a total score:
	//    RD_total = TrustScore + HardwareScore + SecurityScore
	// The maximum possible total is 300. For a device to be “acceptable” its score must be at least
	// 75% of 300, i.e. 225.
	// Then, if at least 60% of the ad devices (IoT voters) vote YES, the RD is authenticated.
	MinAcceptableTotal = 225.0
	FinalConsensus     = 0.60

	// Gas price multiplier.
	GasPriceMultiplier = 50.0

	// JSON file containing IoT devices (voters).
	IoTDevicesJSON = "iot_devices.json"
)

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------
type IoTDevice struct {
	UUID                     string  `json:"uuid"`
	Weight                   uint    `json:"weight"`          // Inherent reputation (fixed until trust reset)
	TrustScore               float64 `json:"trustScore"`      // Dynamic trust score (starts at 1)
	LastVoteOutcome          bool    `json:"lastVoteOutcome"` // Whether the last vote was correct
	IncorrectVoteStreak      uint    `json:"incorrectVoteStreak"`
	TotalVotesCast           uint    `json:"totalVotesCast"`
	CorrectVoteCount         uint    `json:"correctVoteCount"`
	IncorrectVoteCount       uint    `json:"incorrectVoteCount"`
	LastAuthenticationResult string  `json:"lastAuthenticationResult"` // "Authenticated", "Rejected", etc.
	ConfidenceLevel          float64 `json:"confidenceLevel"`          // (Not used in new scheme)
	LastInteraction          string  `json:"lastInteraction"`          // Timestamp (RFC3339)
	SuspensionPeriod         uint    `json:"suspensionPeriod"`
	// New flag to simulate malicious behavior.
	IsMalicious bool `json:"IsMalicious"`
}

type SCDevice struct {
	UUID           string
	TrustScore     *big.Int
	HardwareScore  *big.Int
	SecurityScore  *big.Int
	Weight         *big.Int // not used in our new final decision
	Authenticated  bool
	LastActive     *big.Int
	CorrectVotes   *big.Int
	IncorrectVotes *big.Int
	// Optionally, a flag for malicious behavior (if needed)
	IsMalicious bool
}

type SCResult struct {
	DeviceUUID      string
	Outcome         string // "Yes" or "No"
	VotersInfo      string
	YesVotes        int // Number of IoT voters that voted Yes
	NoVotes         int // Number of IoT voters that voted No
	RemainingUnauth int
}

type DeviceHistory struct {
	UUID                string
	AuthSpeed           []float64 // Processing times (seconds)
	VoteOutcome         []int     // 1 if correct vote, 0 if incorrect
	WeightHistory       []uint    // Weight values over time
	VoteAccuracyHistory []float64 // Vote accuracy (%) over time
	TrustScoreHistory   []float64 // Trust score values over time
}

var deviceHistories = make(map[string]*DeviceHistory)

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------
func loadIoTDevices(filename string) ([]IoTDevice, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var devs []IoTDevice
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, err
	}
	return devs, nil
}

func randomSubset(devices []IoTDevice, count int) []IoTDevice {
	n := len(devices)
	if count > n {
		count = n
	}
	subset := make([]IoTDevice, n)
	copy(subset, devices)
	mr.Seed(time.Now().UnixNano())
	mr.Shuffle(n, func(i, j int) {
		subset[i], subset[j] = subset[j], subset[i]
	})
	return subset[:count]
}

// -----------------------------------------------------------------------------
// New Individual Voting Logic
// -----------------------------------------------------------------------------
//
// For each registered device (RD), its total score is computed as:
//
//	RD_total = TrustScore + HardwareScore + SecurityScore
//
// Before casting a vote, each ad device (IoT voter) first checks that each individual
// score is at least 30. If any score is below 30, that ad device votes NO immediately and logs the reason.
// Otherwise, if RD_total is at least the minimum acceptable (225), the standard vote is YES; if not, it is NO.
// However, if an ad device is marked as malicious (IsMalicious == true) and the RD_total is below 225,
// it overrides the normal decision and votes YES.
func doOffChainVoting(voters []IoTDevice, rd SCDevice) (int, int, map[string]bool) {
	votes := make(map[string]bool)
	totalVotes := len(voters)
	yesCount := 0

	// Prepare a wait group and a channel to collect vote results.
	var wg sync.WaitGroup
	type voteResult struct {
		uuid string
		vote bool
	}
	resultsChan := make(chan voteResult, totalVotes)

	// Convert the SCDevice scores to float64.
	trustVal := rd.TrustScore.Int64()
	hardwareVal := rd.HardwareScore.Int64()
	securityVal := rd.SecurityScore.Int64()
	rdTotal := float64(trustVal + hardwareVal + securityVal)
	log.Printf("Registered Device %s total score = %.2f (Minimum required: %.2f)", rd.UUID, rdTotal, MinAcceptableTotal)

	// For each IoT device in the voters slice, spawn a goroutine to decide its vote.
	for _, d := range voters {
		wg.Add(1)
		go func(v IoTDevice) {
			defer wg.Done()
			var vote bool
			// Check if any individual score is below 30.
			if !v.IsMalicious && (trustVal < 30 || hardwareVal < 30 || securityVal < 30) {
				// For a non-malicious voter, if any score is below 30, vote NO.
				if trustVal < 30 {
					log.Printf("Registered Device %s: TrustScore %d is below threshold (30) for voter %s", rd.UUID, trustVal, v.UUID)
				}
				if hardwareVal < 30 {
					log.Printf("Registered Device %s: HardwareScore %d is below threshold (30) for voter %s", rd.UUID, hardwareVal, v.UUID)
				}
				if securityVal < 30 {
					log.Printf("Registered Device %s: SecurityScore %d is below threshold (30) for voter %s", rd.UUID, securityVal, v.UUID)
				}
				vote = false
			} else {
				// Standard vote: vote YES if the RD_total meets or exceeds the minimum acceptable.
				vote = rdTotal >= MinAcceptableTotal
				// If the ad device is malicious and the RD_total is below the threshold, force a YES vote.
				if v.IsMalicious && rdTotal < MinAcceptableTotal {
					vote = true
					log.Printf("Malicious voter %s overrides vote: YES (despite RD_total < %.2f)", v.UUID, MinAcceptableTotal)
				}
				// Conversely, if a malicious voter sees an RD_total above the threshold, it may force a NO.
				if v.IsMalicious && rdTotal >= MinAcceptableTotal {
					vote = false
					log.Printf("Malicious voter %s overrides vote: NO (despite RD_total >= %.2f)", v.UUID, MinAcceptableTotal)
				}
			}
			resultsChan <- voteResult{uuid: v.UUID, vote: vote}
		}(d)
	}

	// Wait for all goroutines to complete.
	wg.Wait()
	close(resultsChan)

	// Collect votes from the channel.
	for res := range resultsChan {
		votes[res.uuid] = res.vote
		if res.vote {
			yesCount++
		}
	}

	return yesCount, totalVotes, votes
}

// -----------------------------------------------------------------------------
// Modified Reputation & Trust Update Logic for IoT Devices
// -----------------------------------------------------------------------------
//
// After each authentication event, each IoT device (ad device) updates its reputation as follows:
//   - If its vote was correct, update its TrustScore using a Gompertz function:
//     newTrust = L_trust * exp(-b_trust * exp(-c_trust * correctVoteCount))
//     If newTrust reaches or exceeds 100, then the device’s inherent Weight is increased by 2 points (capped at 100),
//     and the TrustScore is reset to 1 (with the correct vote count also reset).
//   - If its vote was incorrect, its TrustScore is reduced by 10 (but not below 1).
//     Additionally, if its IncorrectVoteCount exceeds 5, then 30% of its Weight is deducted (but not below 10).
func updateDevicesWeight(global []IoTDevice, subset []IoTDevice, yesMap map[string]bool, outcome bool) {
	const (
		maxWeight = 100.0 // Upper bound for inherent Weight
		minWeight = 10.0  // Lower bound for inherent Weight
	)
	const (
		L_trust = 100.0 // Maximum trust score
		b_trust = 1.0   // Scale parameter for trust update
		c_trust = 0.5   // Growth rate for trust update (applied to correct vote count)
		penalty = 10.0  // Fixed penalty for an incorrect vote
	)
	const weightIncrement = 2.0 // Increase Weight by 2 points when TrustScore reaches 100

	nowStr := time.Now().Format(time.RFC3339)
	for _, sub := range subset {
		for i := range global {
			if global[i].UUID == sub.UUID {
				global[i].TotalVotesCast++
				global[i].LastInteraction = nowStr

				if yesMap[sub.UUID] == outcome {
					// Correct vote.
					global[i].CorrectVoteCount++
					global[i].IncorrectVoteStreak = 0
					global[i].LastVoteOutcome = true
					global[i].LastAuthenticationResult = "Authenticated"

					newTrust := L_trust * math.Exp(-b_trust*math.Exp(-c_trust*float64(global[i].CorrectVoteCount)))
					if newTrust >= L_trust {
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
					// Incorrect vote.
					global[i].IncorrectVoteCount++
					global[i].IncorrectVoteStreak++
					global[i].LastVoteOutcome = false
					global[i].LastAuthenticationResult = "Rejected"
					newTrust := global[i].TrustScore - penalty
					if newTrust < 1.0 {
						newTrust = 1.0
					}
					global[i].TrustScore = newTrust
					// Apply weight penalty if more than 5 incorrect votes.
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

// -----------------------------------------------------------------------------
// Device History Update
// -----------------------------------------------------------------------------
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
	} else {
		accuracy = 0.0
	}
	history.VoteAccuracyHistory = append(history.VoteAccuracyHistory, accuracy)
}

// -----------------------------------------------------------------------------
// On-chain Call (authenticateDevice)
// -----------------------------------------------------------------------------
func authenticateDeviceOnSC(
	ethClt *ethclient.Client,
	rpcClt *rpc.Client,
	contractABI abi.ABI,
	fromAddr common.Address,
	nonce *uint64,
	chainID *big.Int,
	privateKey *ecdsa.PrivateKey,
	deviceUUID string,
	status bool,
) error {
	fn, ok := contractABI.Methods["authenticateDevice"]
	if !ok {
		return fmt.Errorf("ABI missing authenticateDevice")
	}
	inData, err := fn.Inputs.Pack(deviceUUID, status)
	if err != nil {
		return fmt.Errorf("pack authenticateDevice: %v", err)
	}
	calldata := append(fn.ID, inData...)
	scAddr := common.HexToAddress(SmartContractAddress)

	// Estimate gas limit and add a safety margin (e.g., 50% extra)
	gasLimit, err := ethClt.EstimateGas(context.Background(), ethereum.CallMsg{
		From: fromAddr,
		To:   &scAddr,
		Data: calldata,
	})
	if err != nil {
		return fmt.Errorf("estimateGas authenticateDevice: %v", err)
	}
	gasLimit = gasLimit + gasLimit/2

	suggested, err := ethClt.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("suggestGasPrice authenticateDevice: %v", err)
	}
	mulPrice := new(big.Int).Mul(suggested, big.NewInt(int64(GasPriceMultiplier)))
	tx := types.NewTransaction(
		*nonce,
		scAddr,
		big.NewInt(0),
		gasLimit,
		mulPrice,
		calldata,
	)
	signer := types.NewEIP155Signer(chainID)
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return fmt.Errorf("SignTx authenticateDevice: %v", err)
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalBin authenticateDevice: %v", err)
	}
	var txHash common.Hash
	err = rpcClt.CallContext(context.Background(), &txHash, "eth_sendRawTransaction", hexutil.Encode(rawTx))
	if err != nil {
		return fmt.Errorf("eth_sendRawTransaction authenticateDevice: %v", err)
	}
	log.Printf("authenticateDevice => TxHash=%s\n", txHash.Hex())
	*nonce = *nonce + 1
	return nil
}

// -----------------------------------------------------------------------------
// Blockchain Initialization and Fetch Helpers
// -----------------------------------------------------------------------------
func initChain() (abi.ABI, *ethclient.Client, *rpc.Client, common.Address, *big.Int, uint64) {
	abiBytes, err := ioutil.ReadFile(ABIFilePath)
	if err != nil {
		log.Fatalf("Failed reading ABI file %s: %v", ABIFilePath, err)
	}
	contractABI, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		log.Fatalf("Failed parse contract ABI: %v", err)
	}
	ethClt, err := ethclient.Dial(RPCURL)
	if err != nil {
		log.Fatalf("Failed ethclient dial: %v", err)
	}
	rpcClt, err := rpc.DialContext(context.Background(), RPCURL)
	if err != nil {
		log.Fatalf("Failed rpc dial: %v", err)
	}
	privHex := strings.TrimPrefix(PrivateKeyHex, "0x")
	key, err := crypto.HexToECDSA(privHex)
	if err != nil {
		log.Fatalf("Failed parse private key: %v", err)
	}
	pubKey := key.Public()
	pubKeyECDSA, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("public key is not ecdsa.PublicKey")
	}
	fromAddr := crypto.PubkeyToAddress(*pubKeyECDSA)
	chainID, err := ethClt.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("Failed get chainID: %v", err)
	}
	nonce, err := ethClt.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		log.Fatalf("Failed get nonce: %v", err)
	}
	log.Printf("Connected: fromAddr=%s, chainID=%s, nonce=%d\n", fromAddr.Hex(), chainID.String(), nonce)
	return contractABI, ethClt, rpcClt, fromAddr, chainID, nonce
}

func fetchSCDevices(contractABI abi.ABI, ethClt *ethclient.Client) ([]SCDevice, error) {
	scAddr := common.HexToAddress(SmartContractAddress)
	fn, ok := contractABI.Methods["getAllDevices"]
	if !ok {
		return nil, fmt.Errorf("ABI missing getAllDevices")
	}
	callData := fn.ID
	raw, err := ethClt.CallContract(context.Background(), ethereum.CallMsg{
		To:   &scAddr,
		Data: callData,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("CallContract getAllDevices: %v", err)
	}
	var devs []SCDevice
	if err := contractABI.UnpackIntoInterface(&devs, "getAllDevices", raw); err != nil {
		return nil, fmt.Errorf("Unpack getAllDevices: %v", err)
	}
	return devs, nil
}

func loadPrivKeyOrPanic() *ecdsa.PrivateKey {
	privHex := strings.TrimPrefix(PrivateKeyHex, "0x")
	key, err := crypto.HexToECDSA(privHex)
	if err != nil {
		panic(fmt.Sprintf("failed to parse private key: %v", err))
	}
	return key
}

// -----------------------------------------------------------------------------
// Main Execution  (console-only metrics printing)
// -----------------------------------------------------------------------------
func main() {
	/* ---------- metric containers ---------------------------------------- */
	var offChainTimesMs []float64 // ms  – Computational Cost
	var offChainTimesNs []int64   // ns  – Computational Cost (high-res)
	var onChainTimesMs []float64  // “Authentication Delay”
	var commCostBytes []int       // “Communication Cost”
	var results []SCResult
	var successCount int
	/* --------------------------------------------------------------------- */

	// 1. Load IoT devices ---------------------------------------------------
	iotDevs, err := loadIoTDevices(IoTDevicesJSON)
	if err != nil {
		log.Fatalf("loadIoTDevices: %v", err)
	}
	log.Printf("Loaded %d IoT devices\n", len(iotDevs))

	// 2. Chain init ---------------------------------------------------------
	contractABI, ethClt, rpcClt, from, chainID, nonce := initChain()

	// 3. Fetch SC devices ---------------------------------------------------
	scDevices, err := fetchSCDevices(contractABI, ethClt)
	if err != nil {
		log.Fatalf("fetchSCDevices: %v", err)
	}
	log.Printf("Total SC devices on-chain: %d", len(scDevices))

	// Keep only unauthenticated ones
	var unauth []SCDevice
	for _, d := range scDevices {
		if !d.Authenticated {
			unauth = append(unauth, d)
		}
	}
	if len(unauth) == 0 {
		log.Println("Nothing to do – all devices are authenticated")
		return
	}

	// ----------------------------------------------------------------------
	for idx, dev := range unauth {
		log.Printf("\n=== Device %s ==================================================", dev.UUID)

		voters := randomSubset(iotDevs, NumberOfVoters)

		/* --------------- OFF-CHAIN VOTING (computational cost) ------------- */
		t0 := time.Now()
		yesCnt, tot, yesMap := doOffChainVoting(voters, dev)
		offChainDur := time.Since(t0)
		offChainTimesMs = append(offChainTimesMs, float64(offChainDur.Milliseconds()))
		offChainTimesNs = append(offChainTimesNs, offChainDur.Nanoseconds())

		// ---------------- decision ------------------------------------------
		yesPct := float64(yesCnt) / float64(tot)
		authenticate := yesPct >= FinalConsensus

		var onChainDur time.Duration
		var bytesSent int
		if authenticate {
			successCount++
			// ---- ON-CHAIN call (measure delay & comm cost) -----------------
			chainStart := time.Now()
			// capture rawTx size by wrapping authenticateDeviceOnSC
			rawSz, err := authenticateDeviceWithSize(
				ethClt, rpcClt, contractABI, from, &nonce, chainID,
				loadPrivKeyOrPanic(), dev.UUID, true)
			if err != nil {
				log.Printf("❌ on-chain auth failed: %v", err)
				authenticate = false
			}
			onChainDur = time.Since(chainStart)
			bytesSent = rawSz
		}

		// store per-metric arrays
		onChainTimesMs = append(onChainTimesMs, float64(onChainDur.Milliseconds()))
		commCostBytes = append(commCostBytes, bytesSent)

		// -------------- update reputation etc. ------------------------------
		updateDevicesWeight(iotDevs, voters, yesMap, authenticate)

		// gather pretty result line
		outcomeStr := map[bool]string{true: "Yes", false: "No"}[authenticate]
		remain := len(unauth) - (idx + 1)
		results = append(results, SCResult{
			DeviceUUID:      dev.UUID,
			Outcome:         outcomeStr,
			VotersInfo:      fmt.Sprintf("%d voters, %.0f%% yes", tot, yesPct*100),
			YesVotes:        yesCnt,
			NoVotes:         tot - yesCnt,
			RemainingUnauth: remain,
		})
	}

	/* ===================== PRINT METRIC SUMMARY ========================= */
	fmt.Println("\n====================  METRIC SUMMARY  ====================")
	fmt.Printf("Authentication-success rate: %.2f %%\n\n",
		100*float64(successCount)/float64(len(unauth)))

	for i := range offChainTimesMs {
		fmt.Printf("• Device #%d  ComputationalCost: %.3f ms (%d ns)   "+
			"AuthenticationDelay: %.2f ms   CommunicationCost: %d bytes\n",
			i+1,
			offChainTimesMs[i],
			offChainTimesNs[i],
			onChainTimesMs[i],
			commCostBytes[i])
	}
	fmt.Println("==========================================================\n")

	// printSummaryTable(results, len(scDevices), len(unauth)-len(results))

	// // optional: persist IoT device state
	// if err := saveIoTDevices("iot_devices.json", iotDevs); err != nil {
	// 	log.Fatalf("saveIoTDevices: %v", err)
	// }
}

/*
	--------------------------------------------------------------------------

authenticateDeviceWithSize is a tiny wrapper that calls your existing
authenticateDeviceOnSC() and returns the size of the raw transaction that
was broadcast (for communication-cost metric).
---------------------------------------------------------------------------
*/
func authenticateDeviceWithSize(
	ethClt *ethclient.Client, rpcClt *rpc.Client, abi abi.ABI,
	from common.Address, nonce *uint64, chainID *big.Int,
	key *ecdsa.PrivateKey, uuid string, status bool) (int, error) {

	// Build calldata exactly as authenticateDeviceOnSC does
	fn := abi.Methods["authenticateDevice"]
	in, _ := fn.Inputs.Pack(uuid, status)
	calldata := append(fn.ID, in...)

	// Estimate gas etc. just to get rawTx size
	gasLimit, _ := ethClt.EstimateGas(context.Background(), ethereum.CallMsg{
		From: from, To: &common.Address{}, Data: calldata,
	})
	gasLimit += gasLimit / 2
	suggested, _ := ethClt.SuggestGasPrice(context.Background())
	tx := types.NewTransaction(
		*nonce, common.HexToAddress(SmartContractAddress),
		big.NewInt(0), gasLimit, suggested, calldata)

	signed, err := types.SignTx(tx, types.NewEIP155Signer(chainID), key)
	if err != nil {
		return 0, err
	}

	raw, _ := signed.MarshalBinary() // <-- raw tx bytes
	if err := authenticateDeviceOnSC(
		ethClt, rpcClt, abi, from, nonce, chainID, key, uuid, status); err != nil {
		return 0, err
	}
	return len(raw), nil
}
