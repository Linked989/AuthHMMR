package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
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

// ---------------------------
// Configuration Variables
// ---------------------------
const (
	SmartContractAddress = "0xEC60ab6e4Ce6B9C0EFB5A5cC9869A9BF5775202b"                         // Ganache-deployed contract address
	NumberOfDevices      = 10                                                                   // Number of devices to register
	Alpha                = 1                                                                    // Example alpha coefficient
	Beta                 = 1                                                                    // Example beta coefficient
	Gamma                = 1                                                                    // Example gamma coefficient
	PrivateKeyHex        = "0x3b98505875102bcec9095f5cc443abb14e576f50aa40dbd30cc0c3f1b16f35b4" // Private key in hex (no '0x' prefix)
	RPCURL               = "http://127.0.0.1:8545"                                              // Ganache RPC URL
	ABIFilePath          = "abi.json"                                                           // Path to contract ABI
	UUIDLength           = 8                                                                    // UUID length (8 chars)
	MaxConcurrency       = 1                                                                    // Number of concurrent goroutines
)

// ---------------------------
// Device Struct
// ---------------------------
type Device struct {
	UUID          string
	TrustScore    *big.Int
	HardwareScore *big.Int
	SecurityScore *big.Int
	Weight        uint
	Authenticated bool
}

// ---------------------------
// Utility Functions
// ---------------------------

// generateUUID creates a random alphanumeric string of length `length`
func generateUUID(length int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	for i := 0; i < length; i++ {
		bytes[i] = letters[bytes[i]%byte(len(letters))]
	}
	return string(bytes), nil
}

// randUint generates a random integer in [min, max]
func randUint(min, max uint) (uint, error) {
	if min > max {
		return 0, fmt.Errorf("invalid range: min=%d > max=%d", min, max)
	}
	diff := max - min + 1
	bigDiff := big.NewInt(int64(diff))

	n, err := rand.Int(rand.Reader, bigDiff)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}
	return min + uint(n.Int64()), nil
}

func main() {
	// -------------------------
	// 1. Load Contract ABI
	// -------------------------
	abiData, err := ioutil.ReadFile(ABIFilePath)
	if err != nil {
		log.Fatalf("Failed to read ABI file (%s): %v", ABIFilePath, err)
	}
	contractABI, err := abi.JSON(strings.NewReader(string(abiData)))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	// -------------------------
	// 2. Connect to Ganache (both ethclient and RPC)
	// -------------------------
	ethClt, err := ethclient.Dial(RPCURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum node: %v", err)
	}
	defer ethClt.Close()

	rpcClt, err := rpc.DialContext(context.Background(), RPCURL)
	if err != nil {
		log.Fatalf("Failed to create raw RPC client: %v", err)
	}
	defer rpcClt.Close()

	fmt.Println("Connected to Ganache via both ethclient and rpc.Client")

	// -------------------------
	// 3. Load Private Key & Determine Sender Address
	// -------------------------
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(PrivateKeyHex, "0x"))
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	fromAddr := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Printf("Using sender address: %s\n", fromAddr.Hex())

	// -------------------------
	// 4. Get Starting Nonce, Chain ID
	// -------------------------
	nonce, err := ethClt.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}
	chainID, err := ethClt.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}
	fmt.Printf("Starting Nonce: %d, Chain ID: %s\n", nonce, chainID.String())

	// -------------------------
	// 5. Prepare Devices
	// -------------------------
	devices := make([]Device, NumberOfDevices)
	for i := 0; i < NumberOfDevices; i++ {
		uuid, err := generateUUID(UUIDLength)
		if err != nil {
			log.Fatalf("Failed to generate UUID: %v", err)
		}
		trustScoreValue, err := randUint(70, 80)
		if err != nil {
			log.Fatalf("Failed to generate Trust Score: %v", err)
		}
		hardwareScoreValue, err := randUint(70, 90)
		if err != nil {
			log.Fatalf("Failed to generate Hardware Score: %v", err)
		}
		securityScoreValue, err := randUint(86, 90)
		if err != nil {
			log.Fatalf("Failed to generate Security Score: %v", err)
		}

		weight := Alpha*trustScoreValue + Beta*hardwareScoreValue + Gamma*securityScoreValue
		devices[i] = Device{
			UUID:          uuid,
			TrustScore:    big.NewInt(int64(trustScoreValue)),
			HardwareScore: big.NewInt(int64(hardwareScoreValue)),
			SecurityScore: big.NewInt(int64(securityScoreValue)),
			Weight:        weight,
			Authenticated: false,
		}
	}
	fmt.Printf("Prepared %d devices\n", NumberOfDevices)

	// -------------------------
	// 6. Concurrency Setup
	// -------------------------
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, MaxConcurrency)
	contractAddr := common.HexToAddress(SmartContractAddress)
	var nonceMutex sync.Mutex

	// -------------------------
	// 7. Register Each Device with Timeout
	// -------------------------
	// Using index iteration so we can pass a pointer to each device.
	for i := range devices {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(dev *Device) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Create a context with a 5-second timeout for the registration process.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// ABI pack for "registerDevice"
			input, err := contractABI.Pack("registerDevice",
				dev.UUID,
				dev.TrustScore,
				dev.HardwareScore,
				dev.SecurityScore,
			)
			if err != nil {
				log.Printf("Failed to pack parameters (UUID=%s): %v", dev.UUID, err)
				return
			}
			// Removed: log.Printf("Packed input (UUID=)")

			// Estimate Gas using our timeout context.
			msg := ethereum.CallMsg{
				From: fromAddr,
				To:   &contractAddr,
				Data: input,
			}
			gasLimit, err := ethClt.EstimateGas(ctx, msg)
			if err != nil {
				log.Printf("Gas estimate failed (UUID=%s): %v", dev.UUID, err)
				return
			}

			// Suggest Gas Price using context.
			gasPrice, err := ethClt.SuggestGasPrice(ctx)
			if err != nil {
				log.Printf("Gas price suggestion failed (UUID=%s): %v", dev.UUID, err)
				return
			}

			// Lock & increment nonce safely.
			nonceMutex.Lock()
			currentNonce := nonce
			nonce++
			nonceMutex.Unlock()

			// Create a Legacy Tx.
			tx := types.NewTransaction(
				currentNonce,
				contractAddr,
				big.NewInt(0),
				gasLimit,
				gasPrice,
				input,
			)

			// Sign the Tx (using legacy EIP-155).
			signer := types.NewEIP155Signer(chainID)
			signedTx, err := types.SignTx(tx, signer, privateKey)
			if err != nil {
				log.Printf("SignTx failed (UUID=%s): %v", dev.UUID, err)
				return
			}
			// Removed: log.Printf("Signed Tx Hash (UUID=%s): %s", dev.UUID, signedTx.Hash().Hex())

			// Serialize the Tx.
			rawTxBytes, err := signedTx.MarshalBinary()
			if err != nil {
				log.Printf("MarshalBinary failed (UUID=%s): %v", dev.UUID, err)
				return
			}

			// Broadcast via RPC using our timeout context.
			var txHash common.Hash
			err = rpcClt.CallContext(ctx, &txHash, "eth_sendRawTransaction", hexutil.Encode(rawTxBytes))
			if err != nil {
				log.Printf("Raw Tx send failed (UUID=%s): %v", dev.UUID, err)
				return
			}

			// Mark device as authenticated if registration is successful.
			dev.Authenticated = true
		}(&devices[i])
	}

	wg.Wait()
	fmt.Println("All devices attempted registration.")

	// -------------------------
	// 8. Print Device Details in Tabular Format
	// -------------------------
	// Using plain ASCII (dashes and vertical bars) for the table.
	fmt.Println("----------------------------------------------------------")
	fmt.Printf("| %-10s | %-5s | %-8s | %-8s | %-6s |\n", "UUID", "Trust", "Hardware", "Security", "Weight")
	fmt.Println("----------------------------------------------------------")
	for _, dev := range devices {
		// Convert big.Int scores to int64 for printing.
		trust := dev.TrustScore.Int64()
		hardware := dev.HardwareScore.Int64()
		security := dev.SecurityScore.Int64()
		fmt.Printf("| %-10s | %-5d | %-8d | %-8d | %-6d |\n", dev.UUID, trust, hardware, security, dev.Weight)
	}
	fmt.Println("----------------------------------------------------------")
}
