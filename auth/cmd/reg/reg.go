package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
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
	count := flag.Int("n", defaultDeviceCount, "number of devices to generate")
	uuidLen := flag.Int("uuid-length", defaultUUIDLength, "length of generated UUIDs")
	outPath := flag.String("out", registeredDevicesFn, "output JSON for registered devices")
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
