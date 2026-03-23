Context:
- Existing project already handles reg/auth flows.
- What is missing is only the HMMR module and its integration points.
- There is already a folder: /hmmr with hmmr.go.
- Keep current architecture and naming style.

Task:
Implement an HMMR package in Go for storing and verifying admission/auth events.

Requirements:
1. Reuse existing project structure.
2. Implement inside /hmmr:
   - Event struct or adapter for existing auth/reg event data
   - AddEvent(event) -> leaf index, root
   - GetRoot() -> root hash
   - GenerateProof(leafIndex) -> proof
   - VerifyProof(event, proof, root) -> bool
3. Use branching factor K=6.
4. Each event is hashed first.
5. Merge rule:
   - XOR the 6 child hashes
   - hash the XOR result
6. Support append-only insertion and peak/root updates.
7. Add a device index:
   - map deviceID -> []leafIndex
   - query all stored events for one device
8. Integrate with existing reg/auth flow:
   - after a device is accepted/rejected, create an event and store it in HMMR
   - include at least: device ID, decision, weight, timestamp
9. Add a small CLI/demo command if useful, but prefer integration into existing commands.
10. Add tests for:
   - insertion
   - multiple insertions
   - proof generation
   - proof verification
   - tampered event failure

Important:
- Do not redesign my auth/reg system.
- Do not add blockchain/network/security protocol code.
- Only add the missing HMMR logic and clean integration hooks.
- If existing event structs already exist, adapt to them instead of inventing parallel models.

Output:
- show exactly which files you create/modify
- keep code production-style and minimal