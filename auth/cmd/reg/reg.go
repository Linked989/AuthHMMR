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
	UUID                            string  `json:"uuid"`
	TrustScore                      float64 `json:"trustScore"`
	HardwareScore                   float64 `json:"hardwareScore"`
	SecurityScore                   float64 `json:"securityScore"`
	DataIntegrityScore              float64 `json:"dataIntegrityScore,omitempty"`
	ManufacturerCertScore           float64 `json:"manufacturerCertScore,omitempty"`
	PerformanceScore                float64 `json:"performanceScore,omitempty"`
	NetworkCompatibilityScore       float64 `json:"networkCompatibilityScore,omitempty"`
	TrustUncertainty                float64 `json:"trustUncertainty,omitempty"`
	HardwareUncertainty             float64 `json:"hardwareUncertainty,omitempty"`
	SecurityUncertainty             float64 `json:"securityUncertainty,omitempty"`
	DataIntegrityUncertainty        float64 `json:"dataIntegrityUncertainty,omitempty"`
	ManufacturerCertUncertainty     float64 `json:"manufacturerCertUncertainty,omitempty"`
	PerformanceUncertainty          float64 `json:"performanceUncertainty,omitempty"`
	NetworkCompatibilityUncertainty float64 `json:"networkCompatibilityUncertainty,omitempty"`
	Weight                          float64 `json:"weight"`
	Authenticated                   bool    `json:"authenticated"`
	LastActive                      int64   `json:"lastActive"`
	CorrectVotes                    uint    `json:"correctVotes"`
	IncorrectVotes                  uint    `json:"incorrectVotes"`
	VotesReceivedYes                uint    `json:"votesReceivedYes"`
	VotesReceivedNo                 uint    `json:"votesReceivedNo"`
	VotesReceivedTotal              uint    `json:"votesReceivedTotal"`
}

func main() {
	_ = godotenv.Load()
	count := flag.Int("n", defaultDeviceCount, "number of devices to generate")
	uuidLen := flag.Int("uuid-length", defaultUUIDLength, "length of generated UUIDs")
	outPath := flag.String("out", registeredDevicesFn, "output JSON for registered devices")
	async := flag.Bool("async", false, "submit on-chain registrations without waiting for mining")
	weightOmegaHardware := flag.Float64("weight-omega-hardware", 1.0, "omega for hardwareScore in candidate weight formula")
	weightOmegaSecurity := flag.Float64("weight-omega-security", 1.0, "omega for securityScore in candidate weight formula")
	weightOmegaDataIntegrity := flag.Float64("weight-omega-data-integrity", 1.0, "omega for dataIntegrityScore in candidate weight formula")
	weightOmegaManufacturerCert := flag.Float64("weight-omega-manufacturer-cert", 1.0, "omega for manufacturerCertScore in candidate weight formula")
	weightOmegaPerformance := flag.Float64("weight-omega-performance", 1.0, "omega for performanceScore in candidate weight formula")
	weightOmegaNetworkCompatibility := flag.Float64("weight-omega-network-compatibility", 1.0, "omega for networkCompatibilityScore in candidate weight formula")
	weightLambda := flag.Float64("weight-lambda", 1.0, "lambda uncertainty penalty in candidate weight formula")
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
		dataIntegrity := float64(randIntRange(70, 95))
		manufacturerCert := float64(randIntRange(70, 95))
		performance := float64(randIntRange(70, 95))
		networkCompatibility := float64(randIntRange(70, 95))
		trustSigma := float64(randIntRange(1, 4))
		hardwareSigma := float64(randIntRange(1, 4))
		securitySigma := float64(randIntRange(1, 4))
		dataIntegritySigma := float64(randIntRange(1, 4))
		manufacturerCertSigma := float64(randIntRange(1, 4))
		performanceSigma := float64(randIntRange(1, 4))
		networkCompatibilitySigma := float64(randIntRange(1, 4))
		weight := calculateRegistrationWeight(
			hardware, security, dataIntegrity, manufacturerCert, performance, networkCompatibility,
			hardwareSigma, securitySigma, dataIntegritySigma, manufacturerCertSigma, performanceSigma, networkCompatibilitySigma,
			*weightOmegaHardware, *weightOmegaSecurity, *weightOmegaDataIntegrity, *weightOmegaManufacturerCert, *weightOmegaPerformance, *weightOmegaNetworkCompatibility,
			*weightLambda,
		)

		devices[i] = Device{
			UUID:                            uuid,
			TrustScore:                      trust,
			HardwareScore:                   hardware,
			SecurityScore:                   security,
			DataIntegrityScore:              dataIntegrity,
			ManufacturerCertScore:           manufacturerCert,
			PerformanceScore:                performance,
			NetworkCompatibilityScore:       networkCompatibility,
			TrustUncertainty:                trustSigma,
			HardwareUncertainty:             hardwareSigma,
			SecurityUncertainty:             securitySigma,
			DataIntegrityUncertainty:        dataIntegritySigma,
			ManufacturerCertUncertainty:     manufacturerCertSigma,
			PerformanceUncertainty:          performanceSigma,
			NetworkCompatibilityUncertainty: networkCompatibilitySigma,
			Weight:                          weight,
			Authenticated:                   false,
			LastActive:                      0,
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

func calculateRegistrationWeight(
	hardware float64,
	security float64,
	dataIntegrity float64,
	manufacturerCert float64,
	performance float64,
	networkCompatibility float64,
	hardwareSigma float64,
	securitySigma float64,
	dataIntegritySigma float64,
	manufacturerCertSigma float64,
	performanceSigma float64,
	networkCompatibilitySigma float64,
	omegaHardware float64,
	omegaSecurity float64,
	omegaDataIntegrity float64,
	omegaManufacturerCert float64,
	omegaPerformance float64,
	omegaNetworkCompatibility float64,
	lambda float64,
) float64 {
	weightedUtility := (omegaHardware * hardware) +
		(omegaSecurity * security) +
		(omegaDataIntegrity * dataIntegrity) +
		(omegaManufacturerCert * manufacturerCert) +
		(omegaPerformance * performance) +
		(omegaNetworkCompatibility * networkCompatibility)
	uncertaintyPenalty := lambda * (hardwareSigma +
		securitySigma +
		dataIntegritySigma +
		manufacturerCertSigma +
		performanceSigma +
		networkCompatibilitySigma)
	return weightedUtility - uncertaintyPenalty
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
