package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"

	"auth/internal/besu"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
)

const (
	defaultDeviceCount  = 10
	defaultUUIDLength   = 8
	registeredDevicesFn = "sc_devices.json"
)

type Device struct {
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
}

func main() {
	_ = godotenv.Load()
	count := flag.Int("n", defaultDeviceCount, "number of devices to generate")
	uuidLen := flag.Int("uuid-length", defaultUUIDLength, "length of generated UUIDs")
	outPath := flag.String("out", registeredDevicesFn, "output JSON for registered devices")
	async := flag.Bool("async", false, "submit on-chain registrations without waiting for mining")
	continueOnBesuError := flag.Bool("continue-on-besu-error", true, "continue processing other devices if one Besu registration fails")
	besuRetries := flag.Int("besu-retries", 3, "number of retries for Besu registration submission")
	besuRetryDelayMs := flag.Int("besu-retry-delay-ms", 250, "delay between Besu registration retries in milliseconds")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	devices := make([]Device, *count)
	for i := 0; i < *count; i++ {
		uuid := mustGenerateUUID(*uuidLen)
		trust := float64(randIntRange(70, 80))
		hardware := float64(randIntRange(70, 90))
		security := float64(randIntRange(86, 95))
		weight := trust + hardware + security

		devices[i] = Device{
			UUID:          uuid,
			TrustScore:    trust,
			HardwareScore: hardware,
			SecurityScore: security,
			Weight:        weight,
			Authenticated: false,
			LastActive:    0,
		}
	}

	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		log.Fatalf("marshal devices: %v", err)
	}

	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		log.Fatalf("write devices: %v", err)
	}

	fmt.Printf("Generated %d registered devices into %s\n", len(devices), *outPath)

	besuClient, err := besu.NewClientFromEnv()
	if err != nil {
		log.Fatalf("init besu client: %v", err)
	}
	if besuClient == nil {
		return
	}

	failed := make([]string, 0)
	submitted := 0
	for i := range devices {
		txHash, err := addDeviceWithRetry(
			besuClient,
			devices[i],
			*async,
			*besuRetries,
			time.Duration(*besuRetryDelayMs)*time.Millisecond,
		)
		if err != nil {
			if *continueOnBesuError {
				log.Printf("register device %s on besu failed: %v", devices[i].UUID, err)
				failed = append(failed, devices[i].UUID)
				continue
			}
			log.Fatalf("register device %s on besu: %v", devices[i].UUID, err)
		}
		submitted++
		fmt.Printf("Submitted registration %s (tx %s)\n", devices[i].UUID, txHash.Hex())
	}
	if len(failed) > 0 {
		log.Printf("Registration summary: submitted=%d failed=%d", submitted, len(failed))
		log.Printf("Failed UUIDs: %s", strings.Join(failed, ", "))
	} else {
		log.Printf("Registration summary: submitted=%d failed=0", submitted)
	}
}

func mustGenerateUUID(length int) string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		length = defaultUUIDLength
	}
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = letters[rand.Intn(len(letters))]
	}
	return string(buf)
}

func randIntRange(min, max int) int {
	if min >= max {
		return min
	}
	return rand.Intn(max-min+1) + min
}

func scoreToUint(score float64) *big.Int {
	rounded := int64(math.Round(score))
	if rounded < 0 {
		rounded = 0
	}
	return big.NewInt(rounded)
}

func addDeviceWithRetry(client *besu.Client, dev Device, async bool, retries int, retryDelay time.Duration) (common.Hash, error) {
	if retries < 1 {
		retries = 1
	}
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var (
			txHash common.Hash
			err    error
		)
		if async {
			txHash, err = client.AddDeviceAsync(
				ctx,
				dev.UUID,
				scoreToUint(dev.TrustScore),
				scoreToUint(dev.HardwareScore),
				scoreToUint(dev.SecurityScore),
			)
		} else {
			txHash, err = client.AddDevice(
				ctx,
				dev.UUID,
				scoreToUint(dev.TrustScore),
				scoreToUint(dev.HardwareScore),
				scoreToUint(dev.SecurityScore),
			)
		}
		cancel()
		if err == nil {
			return txHash, nil
		}
		lastErr = err
		if attempt < retries {
			time.Sleep(retryDelay)
		}
	}
	return common.Hash{}, lastErr
}
