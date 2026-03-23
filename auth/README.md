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
   go run ./cmd/reg -async
3) Run authentication and build a block.
   go run ./cmd/auth
   go run ./cmd/auth -auth-async
   go run ./cmd/auth -auth-async -auth-wait
4) Optional: show device summary.
   go run ./cmd/detail-dev
5) Query devices from the smart contract.
   go run ./cmd/query-devices
   go run ./cmd/query-devices -authenticated
6) Clear all devices from the smart contract.
   go run ./cmd/clear-devices
   go run ./cmd/clear-devices -force
   go run ./cmd/clear-devices -uuid PJLIZV5O

HMMR event log
- Registration and authentication decisions are now appended to a local HMMR event store.
- Default file: `hmmr_events.json`
- Registration writes `registered` events.
- Authentication writes `authenticated` or `rejected` events.
- Both commands support `-hmmr-store` to override the file path.

Run with HMMR
1) Generate registrations and write registration events into the default HMMR store.
   go run ./cmd/reg
2) Run authentication and append auth decision events into the same HMMR store.
   go run ./cmd/auth
3) Use a custom HMMR store path if needed.
   go run ./cmd/reg -hmmr-store custom_hmmr_events.json
   go run ./cmd/auth -hmmr-store custom_hmmr_events.json

Alternative runner
- python3 scripts/run_all.py

Outputs
- iot_devices.json: off-chain voters
- sc_devices.json: registered devices (updated after auth)
- hmmr_events.json: persisted HMMR registration/auth event log
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
