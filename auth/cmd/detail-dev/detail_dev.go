package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

const registeredDevicesFn = "sc_devices.json"

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
}

func main() {
	devicesPath := flag.String("devices", registeredDevicesFn, "path to registered devices JSON")
	flag.Parse()

	devices, err := loadDevices(*devicesPath)
	if err != nil {
		log.Fatalf("load devices: %v", err)
	}

	total := len(devices)
	authCount := 0
	for _, dev := range devices {
		if dev.Authenticated {
			authCount++
		}
	}

	fmt.Printf("Total Registered Devices: %d\n", total)
	fmt.Println("List of Devices:")
	for i, dev := range devices {
		lastActive := "never"
		if dev.LastActive != 0 {
			lastActive = time.Unix(0, dev.LastActive).UTC().Format(time.RFC3339)
		}
		fmt.Printf("%d. UUID: %s, Weight: %.2f, Authenticated: %t, LastActive: %s, CorrectVotes: %d, IncorrectVotes: %d\n",
			i+1, dev.UUID, dev.Weight, dev.Authenticated, lastActive, dev.CorrectVotes, dev.IncorrectVotes)
	}

	fmt.Println("\nSummary:")
	fmt.Printf("Authenticated Devices: %d\n", authCount)
	fmt.Printf("Unauthenticated Devices: %d\n", total-authCount)
}

func loadDevices(path string) ([]SCDevice, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var devices []SCDevice
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, err
	}
	return devices, nil
}
