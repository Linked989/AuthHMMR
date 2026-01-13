package besu

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const deviceRegistryABI = `[
  {"inputs":[{"internalType":"uint256","name":"_alpha","type":"uint256"},{"internalType":"uint256","name":"_beta","type":"uint256"},{"internalType":"uint256","name":"_gamma","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},
  {"inputs":[{"internalType":"string","name":"_uuid","type":"string"},{"internalType":"uint256","name":"_trustScore","type":"uint256"},{"internalType":"uint256","name":"_hardwareScore","type":"uint256"},{"internalType":"uint256","name":"_securityScore","type":"uint256"}],"name":"addDevice","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"string","name":"_uuid","type":"string"},{"internalType":"bool","name":"_status","type":"bool"}],"name":"authenticateDevice","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"string","name":"_uuid","type":"string"}],"name":"getDeviceDetails","outputs":[{"internalType":"string","name":"","type":"string"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"getAllDevices","outputs":[{"components":[{"internalType":"string","name":"uuid","type":"string"},{"internalType":"uint256","name":"trustScore","type":"uint256"},{"internalType":"uint256","name":"hardwareScore","type":"uint256"},{"internalType":"uint256","name":"securityScore","type":"uint256"},{"internalType":"uint256","name":"weight","type":"uint256"},{"internalType":"bool","name":"authenticated","type":"bool"}],"internalType":"struct DeviceRegistry.Device[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"string","name":"_uuid","type":"string"}],"name":"removeDevice","outputs":[],"stateMutability":"nonpayable","type":"function"}
]`

type Client struct {
	client   *ethclient.Client
	contract *bind.BoundContract
	txOpts   *bind.TransactOpts
	callOpts *bind.CallOpts
}

type Device struct {
	UUID          string
	TrustScore    *big.Int
	HardwareScore *big.Int
	SecurityScore *big.Int
	Weight        *big.Int
	Authenticated bool
}

func NewClientFromEnv() (*Client, error) {
	contractAddr := strings.TrimSpace(os.Getenv("CONTRACT_ADDRESS"))
	if contractAddr == "" {
		return nil, nil
	}
	rpcURL := strings.TrimSpace(os.Getenv("BESU_RPC_URL"))
	if rpcURL == "" {
		return nil, errors.New("BESU_RPC_URL must be set when CONTRACT_ADDRESS is set")
	}
	privKeyHex := strings.TrimSpace(os.Getenv("PRIVATE_KEY"))
	if privKeyHex == "" {
		return nil, errors.New("PRIVATE_KEY must be set when CONTRACT_ADDRESS is set")
	}
	privKey, err := parsePrivateKey(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("parse PRIVATE_KEY: %w", err)
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial besu rpc: %w", err)
	}

	chainID, err := resolveChainID(client)
	if err != nil {
		return nil, err
	}
	txOpts, err := bind.NewKeyedTransactorWithChainID(privKey, chainID)
	if err != nil {
		return nil, fmt.Errorf("new transactor: %w", err)
	}
	txOpts.Context = context.Background()

	parsedABI, err := abi.JSON(strings.NewReader(deviceRegistryABI))
	if err != nil {
		return nil, fmt.Errorf("parse contract abi: %w", err)
	}
	addr := common.HexToAddress(contractAddr)
	contract := bind.NewBoundContract(addr, parsedABI, client, client, client)

	callOpts := &bind.CallOpts{
		From:    txOpts.From,
		Context: context.Background(),
	}

	log.Printf("Besu enabled: contract %s rpc %s", addr.Hex(), rpcURL)
	return &Client{
		client:   client,
		contract: contract,
		txOpts:   txOpts,
		callOpts: callOpts,
	}, nil
}

func parsePrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	trimmed := strings.TrimPrefix(hexKey, "0x")
	return crypto.HexToECDSA(trimmed)
}

func resolveChainID(client *ethclient.Client) (*big.Int, error) {
	if envID := strings.TrimSpace(os.Getenv("CHAIN_ID")); envID != "" {
		id := new(big.Int)
		if _, ok := id.SetString(envID, 10); !ok {
			return nil, fmt.Errorf("invalid CHAIN_ID %q", envID)
		}
		return id, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch chain id: %w", err)
	}
	return id, nil
}

func (c *Client) AddDevice(ctx context.Context, uuid string, trust, hardware, security *big.Int) (common.Hash, error) {
	c.txOpts.Context = ctx
	tx, err := c.contract.Transact(c.txOpts, "addDevice", uuid, trust, hardware, security)
	if err != nil {
		return common.Hash{}, err
	}
	_, err = bind.WaitMined(ctx, c.client, tx)
	if err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

func (c *Client) AddDeviceAsync(ctx context.Context, uuid string, trust, hardware, security *big.Int) (common.Hash, error) {
	c.txOpts.Context = ctx
	tx, err := c.contract.Transact(c.txOpts, "addDevice", uuid, trust, hardware, security)
	if err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

func (c *Client) AuthenticateDevice(ctx context.Context, uuid string, status bool) error {
	c.txOpts.Context = ctx
	tx, err := c.contract.Transact(c.txOpts, "authenticateDevice", uuid, status)
	if err != nil {
		return err
	}
	_, err = bind.WaitMined(ctx, c.client, tx)
	return err
}

func (c *Client) GetAllDevices(ctx context.Context) ([]Device, error) {
	c.callOpts.Context = ctx
	var out []interface{}
	if err := c.contract.Call(c.callOpts, &out, "getAllDevices"); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}

	switch items := out[0].(type) {
	case []struct {
		Uuid          string   `json:"uuid"`
		TrustScore    *big.Int `json:"trustScore"`
		HardwareScore *big.Int `json:"hardwareScore"`
		SecurityScore *big.Int `json:"securityScore"`
		Weight        *big.Int `json:"weight"`
		Authenticated bool     `json:"authenticated"`
	}:
		devices := make([]Device, 0, len(items))
		for _, item := range items {
			devices = append(devices, Device{
				UUID:          item.Uuid,
				TrustScore:    item.TrustScore,
				HardwareScore: item.HardwareScore,
				SecurityScore: item.SecurityScore,
				Weight:        item.Weight,
				Authenticated: item.Authenticated,
			})
		}
		return devices, nil
	case []struct {
		UUID          string
		TrustScore    *big.Int
		HardwareScore *big.Int
		SecurityScore *big.Int
		Weight        *big.Int
		Authenticated bool
	}:
		devices := make([]Device, 0, len(items))
		for _, item := range items {
			devices = append(devices, Device{
				UUID:          item.UUID,
				TrustScore:    item.TrustScore,
				HardwareScore: item.HardwareScore,
				SecurityScore: item.SecurityScore,
				Weight:        item.Weight,
				Authenticated: item.Authenticated,
			})
		}
		return devices, nil
	default:
		return nil, fmt.Errorf("unexpected getAllDevices type %T", out[0])
	}
}

func (c *Client) RemoveDevice(ctx context.Context, uuid string) (common.Hash, error) {
	c.txOpts.Context = ctx
	tx, err := c.contract.Transact(c.txOpts, "removeDevice", uuid)
	if err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}
