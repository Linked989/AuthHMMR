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
   go run ./cmd/auth -auth-async && go run ./cmd/verify-device -leaf-index 10
   go run ./cmd/auth -auth-async -auth-wait
4) Optional: show device summary.
   go run ./cmd/detail-dev
5) Verify one device against the authentication subgroup-HMMR.
   go run ./cmd/verify-device -device D_102
   go run ./cmd/verify-device -device D_102 -hmmr-store custom_hmmr_events.json
   go run ./cmd/verify-device -leaf-index 10 # test proof generation time
6) Query devices from the smart contract.
   go run ./cmd/query-devices
   go run ./cmd/query-devices -authenticated
7) Clear all devices from the smart contract.
   go run ./cmd/clear-devices
   go run ./cmd/clear-devices -force
   go run ./cmd/clear-devices -uuid PJLIZV5O


united commands
go run ./cmd/clear-devices -force && go run ./cmd/reg -async && go run ./cmd/auth -auth-async && go run ./cmd/verify-device -leaf-index 10 && go run ./cmd/clear-devices -force

HMMR event log
- Authentication decisions are appended to the subgroup-compressed HMMR event store from `work/hmmr_v9_subgroup.go`.
- Default file: `hmmr_events.json`
- Authentication writes `authenticated` or `rejected` events.
- `cmd/auth` supports `-hmmr-store` to override the file path.
- `cmd/auth` also supports `-hmmr-event-arity`, `-hmmr-event-subgroup`, and `-hmmr-event-hash`.

Run with HMMR
1) Generate registrations normally.
   go run ./cmd/reg
2) Run authentication and append auth decision events into the HMMR store.
   go run ./cmd/auth
3) Use a custom HMMR store path if needed.
   go run ./cmd/auth -hmmr-store custom_hmmr_events.json

MMR website viewer
- Static viewer directory: `mmr-viewer/`
- Open `mmr-viewer/index.html` in a browser and upload `hmmr_events.json`, or paste the JSON directly.
- For a local server, from the project root run:
  `python3 -m http.server 8000`
  then open `http://localhost:8000/mmr-viewer/`
- The page renders MMR mountains, peaks, leaf ordering, and the bagged root.

HMMR verification CLI
- Command: `go run ./cmd/verify-device -device <DEVICE_ID>`
- It answers:
  Was this device admitted legitimately according to the recorded HMMR-authenticated history?
  What is its decision history?
  Do the stored weight values evolve consistently and match the current device record?
- It verifies each device event proof against the current HMMR root before reporting results.
- Proof generation timing metric:
  `go run ./cmd/verify-device -leaf-index 10`
  `go run ./cmd/verify-device -event-id leaf:10`
  This records `event_id`, `proof_generation_time_ms`, `verification_time_ms`, `proof_size_bytes`, and `total_number_of_recorded_events` into `metrics/hmmr_proof_generation_time.csv`.

Alternative runner
- python3 scripts/run_all.py

Outputs
- iot_devices.json: off-chain voters
- sc_devices.json: registered devices (updated after auth)
- hmmr_events.json: persisted HMMR authentication event log
- metrics/auth_metrics_*.csv: per-device auth metrics (computational cost, block processing, communication cost)
- metrics/auth_throughput_*.csv: auth throughput summary (devices/sec over auth window)
- metrics/scalability_admission_latency.csv: scalability points (average admission latency vs candidate devices X)
- metrics/evaluator_count_scaling.csv: evaluator-count scaling points (selected evaluators vs network size)
- metrics/communication_overhead_*.csv: per-decision protocol message counts (communication overhead model)
- metrics/local_computation_metrics_*.csv: per-decision local computation timings (score calc, vote compute, score update, total)
- metrics/hmmr_proof_generation_time.csv: HMMR proof generation timing points by event ID or leaf index
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
- -voter-formula-a: coefficient `a` in `k = a * log_b(N)` for voter count (default: 2.0)
- -voter-formula-b: base `b` in `k = a * log_b(N)` for voter count (default: 10.0)
- -count-event-recording-message: include event-recording submission as a separate protocol message in communication-overhead metrics (default: false)
- -continue-on-besu-error: continue processing other devices on Besu failures (default: true)
- -besu-retries: retries for Besu submit/receipt operations (default: 3)
- -besu-retry-delay-ms: delay between Besu retries in milliseconds (default: 250)

Makefile
- make run: generate devices, register devices, authenticate, build a block
- make generate: generate off-chain voters (iot_devices.json)
- make register: generate registered devices (sc_devices.json)
- make auth: run authentication and block build
- make detail: show registered device summary
