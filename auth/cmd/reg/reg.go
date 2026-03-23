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
	_ = godotenv.Load()
	count := flag.Int("n", defaultDeviceCount, "number of devices to generate")
	uuidLen := flag.Int("uuid-length", defaultUUIDLength, "length of generated UUIDs")
	outPath := flag.String("out", registeredDevicesFn, "output JSON for registered devices")
	async := flag.Bool("async", false, "submit on-chain registrations without waiting for mining")
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

	for i := range devices {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var (
			txHash common.Hash
			err    error
		)
		if *async {
			txHash, err = besuClient.AddDeviceAsync(
				ctx,
				devices[i].UUID,
				scoreToUint(devices[i].TrustScore),
				scoreToUint(devices[i].HardwareScore),
				scoreToUint(devices[i].SecurityScore),
			)
		} else {
			txHash, err = besuClient.AddDevice(
				ctx,
				devices[i].UUID,
				scoreToUint(devices[i].TrustScore),
				scoreToUint(devices[i].HardwareScore),
				scoreToUint(devices[i].SecurityScore),
			)
		}
		cancel()
		if err != nil {
			log.Fatalf("register device %s on besu: %v", devices[i].UUID, err)
		}
		fmt.Printf("Submitted registration %s (tx %s)\n", devices[i].UUID, txHash.Hex())
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
