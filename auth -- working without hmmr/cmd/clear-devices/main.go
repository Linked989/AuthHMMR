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
	force := flag.Bool("force", false, "do not prompt before deleting")
	onlyUUID := flag.String("uuid", "", "remove a single device by UUID")
	flag.Parse()

	client, err := besu.NewClientFromEnv()
	if err != nil {
		log.Fatalf("init besu client: %v", err)
	}
	if client == nil {
		log.Fatal("CONTRACT_ADDRESS is not set; cannot clear devices")
	}

	var devices []besu.Device
	if *onlyUUID != "" {
		devices = []besu.Device{{UUID: *onlyUUID}}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		allDevices, err := client.GetAllDevices(ctx)
		cancel()
		if err != nil {
			log.Fatalf("get devices: %v", err)
		}
		if len(allDevices) == 0 {
			fmt.Println("No devices to remove.")
			return
		}
		devices = allDevices
	}

	if !*force {
		fmt.Printf("About to remove %d device(s). Continue? (y/N): ", len(devices))
		var resp string
		if _, err := fmt.Scanln(&resp); err != nil {
			log.Fatalf("read response: %v", err)
		}
		if resp != "y" && resp != "Y" {
			fmt.Println("Aborted.")
			return
		}
	}

	for _, dev := range devices {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		txHash, err := client.RemoveDevice(ctx, dev.UUID)
		cancel()
		if err != nil {
			log.Fatalf("remove device %s: %v", dev.UUID, err)
		}
		fmt.Printf("Submitted removal %s (tx %s)\n", dev.UUID, txHash.Hex())
	}

	fmt.Println("Done.")
}
