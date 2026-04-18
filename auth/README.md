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
   go run ./cmd/reg-profile -n 1000 -profile "70 30"
   go run ./cmd/reg-profile -n 600 -profile "100 0" -async
   go run ./cmd/reg-profile -n 1000 -profile "70 30" -weight-omega-hardware 1.0 -weight-omega-security 1.0 -weight-omega-data-integrity 1.0 -weight-omega-manufacturer-cert 1.0 -weight-omega-performance 1.0 -weight-omega-network-compatibility 1.0 -weight-lambda 1.0
3) Run authentication and build a block.
   go run ./cmd/auth
   go run ./cmd/auth -auth-async
   go run ./cmd/auth -auth-async -auth-subrounds-enabled -auth-subrounds 3
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
  This appends proof metrics (`proof_generation_time_ms`, `verification_time_ms`, `proof_size_bytes`) into `metrics/final_metrics.csv`.

Alternative runner
- python3 scripts/run_all.py

Outputs
- iot_devices.json: off-chain voters
- sc_devices.json: registered devices (updated after auth)
- hmmr_events.json: persisted HMMR authentication event log
- metrics/final_metrics.csv: consolidated metrics CSV (admission latency, throughput, communication cost, communication overhead, evaluator count scaling, proof generation time, proof size, verification time)
- metrics/admission_accuracy.csv: TP/TN/FP/FN + admission accuracy per auth run
- metrics/decision_consistency.csv: per-device decision consistency across repeated auth runs (append mode)
- metrics/decision_consistency_state.json: persistent state used to compute running consistency and `p_final` stddev
- metrics/auth_subround_metrics.csv: subround latency/vote metrics and total-round latency/final vote (append mode, when subround mode is enabled)
- metrics/voter_trust_weight_honest.csv: tracked single honest voter, 2 columns per vote (`trust_score_after_vote`, `weight_after_vote`)
- metrics/voter_trust_weight_malicious.csv: tracked single malicious voter, 2 columns per vote (`trust_score_after_vote`, `weight_after_vote`)
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
- -auth-subrounds-enabled: enable multi-subround voting per candidate device
- -auth-subrounds: number of subrounds when `-auth-subrounds-enabled` is true (default: 3)
- -hmmr-metrics: emit HMMR build/proof metrics
- -hmmr-hash: hash algorithm for leaves (default: sha256)
- -voter-formula-a: coefficient `a` in `k = a * log_b(N)` for voter count (default: 2.0)
- -voter-formula-b: base `b` in `k = a * log_b(N)` for voter count (default: 10.0)
- -count-event-recording-message: include event-recording submission as a separate protocol message in communication-overhead metrics (default: false)
- -consistency-run-id: optional label used when appending decision consistency rows (default: auto UTC timestamp)
- -tracked-voter-uuid: track trust/weight CSV for only one voter UUID (default: first voter from `iot_devices.json`)
- -weight-omega-hardware / -weight-omega-security / -weight-omega-data-integrity / -weight-omega-manufacturer-cert / -weight-omega-performance / -weight-omega-network-compatibility: ω coefficients for candidate weight formula
- -weight-lambda: λ uncertainty penalty coefficient
- -continue-on-besu-error: continue processing other devices on Besu failures (default: true)
- -besu-retries: retries for Besu submit/receipt operations (default: 3)
- -besu-retry-delay-ms: delay between Besu retries in milliseconds (default: 250)

Weighted admission model
- Candidate weight:
  `Σ(ωᵢ·μᵢ) - λ·Σσᵢ`
- μ features: `hardwareScore`, `securityScore`, `dataIntegrityScore`, `manufacturerCertScore`, `performanceScore`, `networkCompatibilityScore`
- σ indicators: `hardwareUncertainty`, `securityUncertainty`, `dataIntegrityUncertainty`, `manufacturerCertUncertainty`, `performanceUncertainty`, `networkCompatibilityUncertainty`
- Final admission consensus in `cmd/auth` uses voter `weight` as voting power (`weighted_yes / weighted_total`)

Admission Accuracy and Decision Consistency
- `Admission Accuracy` compares `ground_truth` vs `system_decision`:
  `TP` legit accepted, `TN` malicious rejected, `FP` malicious accepted, `FN` legit rejected.
  `accuracy = (TP + TN) / (TP + TN + FP + FN)`.
- Ground truth used by auth:
  `malicious` if `isMalicious=true`, otherwise fallback by score threshold (`weight >= 225 => legit`, else malicious).
- `Decision Consistency` is stored in append mode in `metrics/decision_consistency.csv`.
  Each auth run adds rows; for each device the file keeps running accept/reject counts, dominant decision frequency, and `p_final` standard deviation.

Makefile
- make run: generate devices, register devices, authenticate, build a block
- make generate: generate off-chain voters (iot_devices.json)
- make register: generate registered devices (sc_devices.json)
- make auth: run authentication and block build
- make detail: show registered device summary
