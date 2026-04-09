package main

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"time"
)

// IoTDevice models the off-chain voter metadata.
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

func main() {
	const deviceCount = 30
	mrand.Seed(time.Now().UnixNano())

	devices := make([]IoTDevice, deviceCount)
	for i := 0; i < deviceCount; i++ {
		uuid, err := generateUUID(8)
		if err != nil {
			log.Fatalf("generate UUID: %v", err)
		}

		weight, err := randUint(70, 95)
		if err != nil {
			log.Fatalf("generate weight: %v", err)
		}

		trust := rounded(mrand.Float64()*40 + 60) // 60.000000 - 100.000000
		totalVotes := randInt(15, 45)
		incorrectVotes := randInt(0, totalVotes/4+1)
		correctVotes := totalVotes - incorrectVotes
		lastOutcome := incorrectVotes == 0
		lastResult := "Authenticated"
		if !lastOutcome {
			lastResult = "Rejected"
		}

		confidence := rounded(mrand.Float64()*0.2 + 0.8) // 0.800000 - 1.000000

		devices[i] = IoTDevice{
			UUID:                     uuid,
			Weight:                   weight,
			TrustScore:               trust,
			LastVoteOutcome:          lastOutcome,
			IncorrectVoteStreak:      uint(randInt(0, 3)),
			TotalVotesCast:           uint(totalVotes),
			CorrectVoteCount:         uint(correctVotes),
			IncorrectVoteCount:       uint(incorrectVotes),
			LastAuthenticationResult: lastResult,
			ConfidenceLevel:          confidence,
			LastInteraction:          time.Now().Format(time.RFC3339),
			SuspensionPeriod:         0,
			IsMalicious:              mrand.Intn(4) == 0,
		}
	}

	if err := writeDevices("iot_devices.json", devices); err != nil {
		log.Fatalf("write devices: %v", err)
	}
	log.Printf("Generated %d IoT devices and saved to iot_devices.json\n", len(devices))
}

func generateUUID(length int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := crand.Read(bytes); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	for i := range bytes {
		bytes[i] = letters[bytes[i]%byte(len(letters))]
	}
	return string(bytes), nil
}

func randUint(min, max uint) (uint, error) {
	if min > max {
		return 0, fmt.Errorf("invalid range %d-%d", min, max)
	}
	diff := max - min + 1
	n, err := crand.Int(crand.Reader, big.NewInt(int64(diff)))
	if err != nil {
		return 0, err
	}
	return min + uint(n.Int64()), nil
}

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	return mrand.Intn(max-min) + min
}

func rounded(v float64) float64 {
	return float64(int(v*1_000_000)) / 1_000_000
}

func writeDevices(path string, devices []IoTDevice) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(devices)
}
