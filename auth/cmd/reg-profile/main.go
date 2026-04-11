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
	"strconv"
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
	profile := flag.String("profile", "70 30", "device profile split as '<legit_pct> <reject_pct>' (example: '70 30')")
	continueOnBesuError := flag.Bool("continue-on-besu-error", true, "continue processing other devices if one Besu registration fails")
	besuRetries := flag.Int("besu-retries", 3, "number of retries for Besu registration submission")
	besuRetryDelayMs := flag.Int("besu-retry-delay-ms", 250, "delay between Besu registration retries in milliseconds")
	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	legitPct, rejectPct, err := parseProfile(*profile)
	if err != nil {
		log.Fatalf("invalid -profile value: %v", err)
	}
	if legitPct+rejectPct != 100 {
		log.Fatalf("profile percentages must sum to 100, got %d + %d", legitPct, rejectPct)
	}

	legitCount := int(math.Round(float64(*count) * float64(legitPct) / 100.0))
	if legitCount < 0 {
		legitCount = 0
	}
	if legitCount > *count {
		legitCount = *count
	}
	rejectCount := *count - legitCount

	devices := make([]Device, 0, *count)
	for i := 0; i < legitCount; i++ {
		devices = append(devices, generateLegitDevice(*uuidLen))
	}
	for i := 0; i < rejectCount; i++ {
		devices = append(devices, generateRejectedDevice(*uuidLen))
	}

	rand.Shuffle(len(devices), func(i, j int) {
		devices[i], devices[j] = devices[j], devices[i]
	})

	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		log.Fatalf("marshal devices: %v", err)
	}
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		log.Fatalf("write devices: %v", err)
	}

	fmt.Printf("Generated %d registered devices into %s\n", len(devices), *outPath)
	fmt.Printf("Profile split used: legit=%d%% (%d devices), reject=%d%% (%d devices)\n", legitPct, legitCount, rejectPct, rejectCount)

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

func parseProfile(raw string) (int, int, error) {
	normalized := strings.NewReplacer(",", " ", ";", " ", ":", " ").Replace(strings.TrimSpace(raw))
	parts := strings.Fields(normalized)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected exactly 2 values like '70 30', got %q", raw)
	}
	a, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid legit percentage %q", parts[0])
	}
	b, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid reject percentage %q", parts[1])
	}
	if a < 0 || a > 100 || b < 0 || b > 100 {
		return 0, 0, fmt.Errorf("percentages must be in [0, 100]")
	}
	return a, b, nil
}

func generateLegitDevice(uuidLen int) Device {
	trust := float64(randIntRange(76, 85))
	hardware := float64(randIntRange(75, 90))
	security := float64(randIntRange(90, 100))
	weight := trust + hardware + security
	return Device{
		UUID:          mustGenerateUUID(uuidLen),
		TrustScore:    trust,
		HardwareScore: hardware,
		SecurityScore: security,
		Weight:        weight,
		Authenticated: false,
		LastActive:    0,
	}
}

func generateRejectedDevice(uuidLen int) Device {
	trust := float64(randIntRange(10, 25))
	hardware := float64(randIntRange(10, 25))
	security := float64(randIntRange(10, 25))
	weight := trust + hardware + security
	return Device{
		UUID:          mustGenerateUUID(uuidLen),
		TrustScore:    trust,
		HardwareScore: hardware,
		SecurityScore: security,
		Weight:        weight,
		Authenticated: false,
		LastActive:    0,
	}
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
