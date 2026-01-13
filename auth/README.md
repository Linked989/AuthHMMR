AuthHMMR (auth)

Overview
- Simulates IoT device authentication using off-chain voting.
- Builds local blocks with an HMMR root and optional sensor-data leaves.
- Stores results in JSON files and block files on disk.

Prereqs
- Go 1.22.5+ (module requires 1.22.5)

Quickstart
1) Generate off-chain voter devices.
   go run ./cmd/generate-devices
2) Generate registered devices.
   go run ./cmd/reg
3) Run authentication and build a block.
   go run ./cmd/auth
4) Optional: show device summary.
   go run ./cmd/detail-dev
5) Query devices from the smart contract.
   go run ./cmd/query-devices
   go run ./cmd/query-devices -authenticated
6) Clear all devices from the smart contract.
   go run ./cmd/clear-devices
   go run ./cmd/clear-devices -force

Alternative runner
- python3 scripts/run_all.py

Outputs
- iot_devices.json: off-chain voters
- sc_devices.json: registered devices (updated after auth)
- blocks/block_*.dat: local block files
- blocks/sensor_leaves.b64: accumulated sensor leaves (when leaf-mode=accumulate)

Besu integration
- Set CONTRACT_ADDRESS to enable on-chain writes.
- Required when enabled: BESU_RPC_URL, PRIVATE_KEY. Optional: CHAIN_ID.
- When enabled, auth will ensure registered devices are added on-chain and each authentication result is submitted.
- You can store these in `.env` and `auth` will auto-load them at startup.
- `cmd/reg` will also register devices on-chain when CONTRACT_ADDRESS is set.

Comand:
npx hardhat run scripts/deploy_auth_hmmr.js --network besu

auth.go flags
- -devices: path to registered devices JSON (default: sc_devices.json)
- -blocks-dir: output directory for block files (default: blocks)
- -leaf-mode: block or accumulate (default: block)
- -sensor-enabled: include synthetic sensor payloads (default: true)
- -sensor-leaves: number of sensor leaves per block (0 = auto)
- -leaf-size: leaf size in bytes (default: 256)
- -hmmr-metrics: emit HMMR build/proof metrics
- -hmmr-hash: hash algorithm for leaves (default: sha256)

Makefile
- make run: generate devices, register devices, authenticate, build a block
- make generate: generate off-chain voters (iot_devices.json)
- make register: generate registered devices (sc_devices.json)
- make auth: run authentication and block build
- make detail: show registered device summary
