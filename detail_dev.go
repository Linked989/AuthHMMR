package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// SCDevice represents the Device struct from the Solidity contract
type SCDevice struct {
	UUID          string
	Weight        *big.Int
	Authenticated bool
}

func main() {
	// -----------------------------------------------------------------------------
	// Configuration Variables
	// -----------------------------------------------------------------------------
	const (
		SmartContractAddress = "0x048fB5fB2Ab72016CD561870b041cC5E97595C92" // Replace with your deployed contract address
		RPCURL               = "http://127.0.0.1:8545"                      // Your RPC endpoint (Ganache)
		ABIFilePath          = "abi.json"                                   // Path to your smart contract ABI
	)

	// -----------------------------------------------------------------------------
	// 1. Load Smart Contract ABI
	// -----------------------------------------------------------------------------
	abiData, err := ioutil.ReadFile(ABIFilePath)
	if err != nil {
		log.Fatalf("Failed to read ABI file (%s): %v", ABIFilePath, err)
	}
	contractABI, err := abi.JSON(strings.NewReader(string(abiData)))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	// -----------------------------------------------------------------------------
	// 2. Connect to Ethereum Node
	// -----------------------------------------------------------------------------
	client, err := ethclient.Dial(RPCURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum node: %v", err)
	}
	defer client.Close()
	log.Println("Connected to Ethereum node.")

	// -----------------------------------------------------------------------------
	// 3. Prepare the Call Data for getAllDevices()
	// -----------------------------------------------------------------------------
	getAllDevicesFn, exists := contractABI.Methods["getAllDevices"]
	if !exists {
		log.Fatalf("ABI does not contain getAllDevices function")
	}
	callData := getAllDevicesFn.ID // Method ID for getAllDevices()

	// -----------------------------------------------------------------------------
	// 4. Create Call Message
	// -----------------------------------------------------------------------------
	scAddr := common.HexToAddress(SmartContractAddress)
	msg := ethereum.CallMsg{
		To:   &scAddr,
		Data: callData,
	}

	// -----------------------------------------------------------------------------
	// 5. Call the Contract
	// -----------------------------------------------------------------------------
	raw, err := client.CallContract(context.Background(), msg, nil)
	if err != nil {
		log.Fatalf("Failed to call getAllDevices: %v", err)
	}

	// -----------------------------------------------------------------------------
	// 6. Unpack the Returned Data
	// -----------------------------------------------------------------------------
	var scDevices []SCDevice
	err = contractABI.UnpackIntoInterface(&scDevices, "getAllDevices", raw)
	if err != nil {
		log.Fatalf("Failed to unpack getAllDevices return: %v", err)
	}

	// -----------------------------------------------------------------------------
	// 7. Display Device Information
	// -----------------------------------------------------------------------------
	totalDevices := len(scDevices)
	unauthenticatedDevices := 0
	authenticatedDevices := 0

	fmt.Printf("Total Registered Devices: %d\n", totalDevices)
	fmt.Println("List of Devices:")
	for i, dev := range scDevices {
		fmt.Printf("%d. UUID: %s, Weight: %s, Authenticated: %t\n",
			i+1, dev.UUID, dev.Weight.String(), dev.Authenticated)
		if dev.Authenticated {
			authenticatedDevices++
		} else {
			unauthenticatedDevices++
		}
	}

	// -----------------------------------------------------------------------------
	// 8. Summary
	// -----------------------------------------------------------------------------
	fmt.Println("\nSummary:")
	fmt.Printf("Total Devices: %d\n", totalDevices)
	fmt.Printf("Authenticated Devices: %d\n", authenticatedDevices)
	fmt.Printf("Unauthenticated Devices: %d\n", unauthenticatedDevices)
}
