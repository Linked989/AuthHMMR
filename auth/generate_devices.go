package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// IoTDevice holds off-chain data about a device (voter)
type IoTDevice struct {
	UUID                     string  `json:"uuid"`                     // Unique identifier
	Weight                   uint    `json:"weight"`                   // Reputation/weight, influences voting power
	TrustScore               uint    `json:"trustScore"`               // Composite trust score (initially set to 50)
	LastVoteOutcome          bool    `json:"lastVoteOutcome"`          // Outcome of the last vote (true if correct)
	IncorrectVoteStreak      uint    `json:"incorrectVoteStreak"`      // Number of consecutive incorrect votes
	TotalVotesCast           uint    `json:"totalVotesCast"`           // Total votes cast by this device
	CorrectVoteCount         uint    `json:"correctVoteCount"`         // Count of correct votes
	IncorrectVoteCount       uint    `json:"incorrectVoteCount"`       // Count of incorrect votes
	LastAuthenticationResult string  `json:"lastAuthenticationResult"` // Result of last authentication ("Authenticated", "Rejected", etc.)
	ConfidenceLevel          float64 `json:"confidenceLevel"`          // Confidence in its vote (e.g., 1.0 means maximum confidence)
	LastInteraction          string  `json:"lastInteraction"`          // Timestamp of last interaction (RFC3339 format)
	SuspensionPeriod         uint    `json:"suspensionPeriod"`         // Suspension period (e.g., number of rounds suspended)
	IsMalicious              bool    `json:"isMalicious"`              // Flag to indicate if the device is malicious
}

// generateUUID creates a random alphanumeric string of specified length.
func generateUUID(length int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	for i := 0; i < length; i++ {
		bytes[i] = letters[bytes[i]%byte(len(letters))]
	}
	return string(bytes), nil
}

// randWeight returns a random uint in [min..max].
func randWeight(min, max uint) (uint, error) {
	if min > max {
		return 0, fmt.Errorf("invalid range: min=%d > max=%d", min, max)
	}
	diff := max - min + 1
	bdiff := big.NewInt(int64(diff))
	n, err := rand.Int(rand.Reader, bdiff)
	if err != nil {
		return 0, err
	}
	return min + uint(n.Int64()), nil
}

func main() {
	// Number of IoT devices to generate
	const numDevices = 4

	// We'll store them in a slice
	devices := make([]IoTDevice, numDevices)

	// For each device: random UUID, random weight [10..100], initial trust=50 and other attributes
	for i := 0; i < numDevices; i++ {
		uid, err := generateUUID(8)
		if err != nil {
			log.Fatalf("Failed to generate UUID: %v", err)
		}

		// Random weight in [10..100]
		w, err := randWeight(75, 99)
		if err != nil {
			log.Fatalf("Failed to generate weight: %v", err)

		}

		// Random trust score in [1..100]
		t, err := randWeight(1, 99)
		if err != nil {
			log.Fatalf(("Failed to generate trustL %v"), err)
		}
		// Randomly assign malicious flag: For example, 50% chance of being malicious
		isMalicious := false // Alternate between true/false, can be modified for more randomness

		// Use current time as the last interaction timestamp
		currentTime := time.Now().Format(time.RFC3339)

		devices[i] = IoTDevice{
			UUID:                     uid,
			Weight:                   w,
			TrustScore:               t,    // initial trust
			LastVoteOutcome:          true, // default: assume correct for first vote
			IncorrectVoteStreak:      0,
			TotalVotesCast:           0,
			CorrectVoteCount:         0,
			IncorrectVoteCount:       0,
			LastAuthenticationResult: "NotAttempted", // no authentication yet
			ConfidenceLevel:          1.0,            // maximum confidence initially
			LastInteraction:          currentTime,
			SuspensionPeriod:         0,
			IsMalicious:              isMalicious, // Set the isMalicious flag
		}
	}

	// Write the generated devices to a JSON file.
	f, err := os.Create("iot_devices.json")
	if err != nil {
		log.Fatalf("Failed to create iot_devices.json: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(devices); err != nil {
		log.Fatalf("Failed to encode JSON: %v", err)
	}

	log.Printf("Generated %d IoT devices and saved to iot_devices.json\n", numDevices)
}
