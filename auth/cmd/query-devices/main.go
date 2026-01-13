package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"auth/internal/besu"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	authOnly := flag.Bool("authenticated", false, "show only authenticated devices")
	flag.Parse()

	client, err := besu.NewClientFromEnv()
	if err != nil {
		log.Fatalf("init besu client: %v", err)
	}
	if client == nil {
		log.Fatal("CONTRACT_ADDRESS is not set; cannot query on-chain devices")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	devices, err := client.GetAllDevices(ctx)
	if err != nil {
		log.Fatalf("get devices: %v", err)
	}

	count := 0
	for _, dev := range devices {
		if *authOnly && !dev.Authenticated {
			continue
		}
		count++
		fmt.Printf(
			"%d. UUID: %s, Trust: %s, Hardware: %s, Security: %s, Weight: %s, Authenticated: %t\n",
			count,
			dev.UUID,
			dev.TrustScore.String(),
			dev.HardwareScore.String(),
			dev.SecurityScore.String(),
			dev.Weight.String(),
			dev.Authenticated,
		)
	}

	if *authOnly {
		fmt.Printf("\nAuthenticated devices: %d\n", count)
	} else {
		fmt.Printf("\nRegistered devices: %d\n", count)
	}
}
