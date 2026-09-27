# PRAMAAN — Cryptographic Decryption Attribution & Tamper-Evident Provenance
### SIH 2026 PS 26237 · Ministry of Defence — Indian Navy (WESEE) · Blockchain & Cybersecurity

**This system links a recovered copy to a cryptographically verified authorized
decryption event. It does not prove who physically transmitted or captured the leak.**

> Vocabulary used in this file is deliberate: *tamper-evident* (not tamper-proof),
> *independently witnessed* and *quorum-finalized* (not "immutable blockchain"),
> *offline distributed audit layer* (3 independent local custodian nodes, no network).
> Section 11 lists what is NOT proven. Section 12 lists prototype limits.

## 1. Problem

One sensitive file is encrypted once and shared with several recipients, each
decrypting with their own credentials. Every decrypted copy is identical, so a
leak leaves every recipient equally suspect.

## 2. Why ordinary watermarking is insufficient

A watermark stamped before distribution is identical for all recipients and
reproduces the attribution problem. A per-copy mark must be embedded **at the
moment of decryption**, be invisible, be unique per session — and, crucially,
be **cryptographically bound to that session's authorization**, or it can be
transplanted between documents (see `test_attested.py` ATTACK 6/7).

## 3. Why ordinary server logs are insufficient

Access logs and single-admin databases can be edited, truncated, or re-signed
by whoever holds the signing keys. If the application itself holds recipient
private keys, it can fabricate any recipient's "decryption event". That was
the v1 MVP's weakness and is fixed by the attested protocol below.

## Architecture (PRAMAAN v2: attested → derived → independently witnessed)

```
DOCUMENT
        ↓
ENCRYPTION ORIGIN (file SHA-256 fingerprint + stable PC-ID filed in registry)
        ↓
AES-256-GCM + per-recipient ML-KEM-768 envelopes (encrypt once)
        ↓
RECIPIENT ML-DSA AUTHORIZATION (single-use challenge, own private key;
server verifies FIRST, never holds the key)
        ↓
VERIFIED DECRYPTION (plaintext released only after authorization verifies)
        ↓
HKDF PROVENANCE FINGERPRINT (bound to signature, event, doc/version, key)
        ↓
INVISIBLE WATERMARK (PDF: text token + LatticeMark pixel lattice; TXT/MD: dual channel)
        ↓
PROVENANCE EVENT (PENDING block committing H(fingerprint) + copy_hash)
        ↓
┌──────────────┬──────────────┬──────────────┐
│ CUSTODIAN A  │ CUSTODIAN B  │ CUSTODIAN C  │
│ own dir/key/ │ own dir/key/ │ own dir/key/ │
│ state/snapshot│ state/snapshot│ state/snapshot│
└──────┬───────┴───────┬──────┴───────┬──────┘
       └───────────────┼───────────────┘
                       ↓
              2 OF 3 receipts → FINAL
   (each node validates auth + derivation + policy + duplicates
    against its OWN enrollment snapshot, signs receipt + checkpoint)
        ↓
LEAK INVESTIGATION (file bytes → binding check; screenshot → ANALOG-HOLE)
        ↓
VERIFIED PROVENANCE (+ portable evidence, clean-room re-verifiable)
```

PROTOTYPE vs FUTURE PRODUCTION HARDENING: nodes run as separate state +
passphrase boundaries in one offline process today (loopback relay or file
exchange); production places them on independent air-gapped hosts with
QR/USB witness exchange, HSM keys, military PKI enrollment and TSA time.
The quorum RULE, receipt formats and verification math are identical in both.

Modules: `core.py` (v1 legacy + v2 attested flow), `provenance.py` (challenge +
HKDF derivation), `recipient_client.py` (recipient device ONLY), `nodes.py`
(independent custodian nodes: validation, receipts, Merkle checkpoints,
file/loopback exchange, aggregation), `custodians.py` (legacy single-host
quorum, retained for compatibility), `evidence.py` (portable package +
clean-room verify, incl. node receipts/proofs), `device.py` (stable PC-ID),
`pqc.py` (ML-KEM/ML-DSA), `symcrypto.py` (AES-GCM/SHA-256), `watermark.py` /
`watermark_text.py` (carriers), `latticemark.py` (screenshot pixel lattice),
`ledger.py` (mixed v1/v2 hash chain + quorum checks), `store.py` (separated
vaults + per-node dirs), `app.py` (Flask UI, loopback only), `demo.py` /
`demo_attested.py` (demos), `test_mvp.py` (34 legacy checks),
`test_attested.py` (25 hostile checks), `test_distributed.py` (20 node checks),
`scripts/measure_robustness.py` + `docs_robustness.json` (216-run lattice matrix).

## PS26237 requirement status (brief §2/§3/§5)

| Requirement | Status |
|---|---|
| Encrypt once, decrypt per recipient with own key | IMPLEMENTED (v1 + v2) |
| Invisible unique mark at the moment of decryption, not before | IMPLEMENTED (PDF + txt/md carriers) |
| Mark tied to recipient identity via own private-key signature | IMPLEMENTED (v2: recipient-device authorization; v1 custodial path deprecated) |
| NIST-approved PQC (ML-KEM for key access, ML-DSA for records), no classical KEX/signatures | IMPLEMENTED |
| Tamper-evident ledger: single admin cannot secretly rewrite history | IMPLEMENTED (hash chain + 2-of-3 quorum; edits detected, 1-sig FINAL refused) |
| Independent witnessing (no single-host quorum pretense) | IMPLEMENTED (3 nodes: own dirs/keys/state/snapshots; per-node validation; Model B file exchange + Model A loopback relay; legacy single-host path retained for compatibility) |
| Signed checkpoints + state roots | IMPLEMENTED (per-node Merkle roots, monotonic checkpoints, rollback/conflict refusal, Merkle proofs in evidence) |
| Leaked file → extract mark → ledger lookup → proof of decryption event | IMPLEMENTED (binding-aware: transplant/modification rejected) |
| Screenshot leak → pixel-lattice decode → same signed event | IMPLEMENTED (LatticeMark; ANALOG-HOLE binding stated openly; measured matrix below) |
| Fully offline: no internet, no cloud services, no public blockchain, no cloud KMS | IMPLEMENTED (19-file network-free static scan; loopback UI only) |
| Simple dashboard running the whole flow end to end | IMPLEMENTED (attested release, node witness buttons, screenshot investigate, robustness matrix, revoke; one-click flagship demo runs the v2 ceremony) |
| Local key storage / offline identity setup | IMPLEMENTED (separated vaults: server KEM / recipient signing / per-node signing / custodians) |
| Multi-party threshold (2-of-3) sign-off on ledger records | IMPLEMENTED over independent nodes (rule enforced; production moves nodes to 3 air-gapped hosts) |
| Revocation | IMPLEMENTED (custodian-authorized; history stays verifiable; UI-wired) |
| Portable offline evidence package + clean-room verification | IMPLEMENTED (now bundles node receipts, checkpoints, Merkle proofs, node keys; anchor pins recipient + node keys) |
| Screenshot/compression-robust watermark + live screenshot demo | IMPLEMENTED for the measured envelope (JPEG q≥60, scale 0.5–1.0, full/half page ≈100% over 216 runs; quarter-crop/q40/rotation/print-scan/camera unproven — see Robustness) |
| Image/scanned-page watermarking, print+re-scan, Office files | FUTURE SCOPE (brief §7) |
| Real multi-machine air-gapped deployment, HSM, military PKI, TSA | FUTURE SCOPE (brief §7; node protocol is host-independent by design) |

## 4. Threat model

Adversaries: malicious recipient (leaks, strips, transplants, frames others);
privileged administrator / compromised application (forges events, rewrites or
replaces ledger, frames recipients); external investigator verifier (must not
need to trust the server). Out of scope: global passive adversary breaking
ML-KEM/ML-DSA/AES/SHA-256; physical coercion of key holders; 2-of-3 custodian
collusion.

## 5. Trust assumptions

- Recipient ML-DSA signing keys are held ONLY in `data/recipient_vault/` under
  per-recipient passphrases, touched ONLY by `recipient_client.py`. The server
  (`core.py`) receives signatures, never keys — statically enforced by
  `test_attested.py` ATTACK 2.
- Custodian keys are independent credentials; adversary controls fewer than 2
  of 3. **Single-machine deployment is a quorum simulation**: a root attacker
  could read all vaults. Production requires independent machines/domains.
- Challenges are single-use (nonce registry) and short-lived (15 min TTL).
- Clocks are approximately correct (no TSA anchor yet).

## 6. Recipient-attested architecture

`create_decrypt_challenge` (server) → `authorize_challenge` (recipient device)
→ `complete_attested_decryption` (server verifies FIRST: nonce unused/fresh,
recipient active, key/policy/document binding, ML-DSA authorization; only then
decapsulates). Replay, cross-signing, expiry, and revocation are all rejected
with explicit errors, each covered by a hostile test.

## 7. Provenance derivation

`fingerprint = HKDF-SHA256(IKM=auth_signature, salt=event_id,
info="PS26237-v2/fp"‖len-prefixed(document_hash, document_version, key_id))`.
128-bit opaque output reuses existing carriers. Order is acyclic: challenge →
signature → fingerprint → commitment → witnesses. The recipient never signs
anything derived from its own signature. Investigators re-derive and compare;
transplants and modifications fail the `copy_hash` binding check.

## 8. Independently witnessed 2-of-3 finality (`nodes.py`)

Each custodian node owns `data/custodian_nodes/<ID>/` (identity, encrypted
vault, receipt log, checkpoint, enrollment snapshot) plus a public entry in
`data/nodes.json`. To witness, a node independently checks: event structure,
event-ID shape, current policy vs its snapshot, recipient enrollment/activity/
key binding, the ML-DSA authorization itself, HKDF re-derivation vs the
commitment, token format, duplicate (replay), and prev-hash shape — then signs
a receipt `{custodian, event, event hash, prev hash, state root, seq, time}`
plus a checkpoint `{seq, count, Merkle root, tip, prev-checkpoint hash}` and a
Merkle inclusion proof. The originator aggregates: unknown/forged/mismatched/
duplicate/conflicting receipts are rejected; 0–1 valid → PENDING; 2 distinct
valid → FINAL. Exchange is deterministic signed JSON files (Model B) or a
loopback HTTP relay (Model A, same validation). No single node can mark FINAL
locally; the aggregator manufactures no signatures. The legacy single-host
`custodians.py` path is retained for compatibility only.

## 8b. Screenshot robustness (measured, `docs_robustness.json`)

LatticeMark tiles a near-invisible micro-dot lattice (same 128-bit fingerprint)
on every PDF page at release. Blind decode needs no original; a mis-decode
hashes to no ledger event, so errors are NOT VERIFIED, never wrong names.
216-run matrix (6 tokens, ~108dpi sim: crop → downscale → JPEG): q95–q60 at
scales 0.5–1.0 on full/half pages ≈100% (one honest outlier: q60/x0.75/full
2/6); quarter-crop fails below full scale (<2 surviving tiles — the documented
floor); JPEG q40 fails except full-page. Rotation >~2°, print-scan, and camera
photos are untested and unclaimed. Regenerate: `python scripts/measure_robustness.py`.

## 9. Offline verification

`evidence.build_evidence_package` bundles event, challenge, signatures, public
keys, FINAL block, checkpoint, policy. `verify_evidence_package` re-verifies
from package contents alone — no server state. v1 legacy flow
(`decrypt_for_recipient`) is preserved for compatibility but DEPRECATED.

## 10. What is cryptographically proven

Fingerprint→event commitment; authorization under enrolled key; HKDF
re-derivation; leaked-bytes equality; quorum; chain integrity.

## 11. What is NOT proven

Who physically leaked/transmitted the file; intent; ledger completeness
against whole-history replacement (checkpoint + quorum mitigate, colluding
quorum defeats); anything after watermark stripping (honest NOT VERIFIED).

## 12. Current limitations (honest)

Screenshot/text carriers: text layers die on rasterization (LatticeMark covers
PDF screenshots within the measured envelope); print-scan, rotation, camera
photos unproven. Nodes run as separate state/passphrase boundaries in one
offline process (prototype); production needs 3 air-gapped hosts. No HSM/PKI/
TSA; clocks unanchored; PC labels self-asserted. Legacy v1 custodial path
present in `core.py` for tests but retired at HTTP (410). Exact-byte
reconstruction by a holder of token+source is outside the threat model
(copy_hash binds transplant/modification, not exact rebuilds).

## 13. Production deployment architecture

Recipient HSM/smartcard signing; 3 air-gapped custodian hosts with QR/USB
witness exchange; published quorum checkpoints; TSA timestamps; military PKI
enrollment; v1 path removed.

## 14. SIH demo steps (2–3 min, `python3 demo_attested.py` or UI flagship button)

Fabricate Alice's auth → BLOCKED. Alice signs → released (+encryption origin
shown). Transplant → REJECTED. Node A validates+signs from its own state →
PENDING. Node B validates+signs → FINAL (+binding MISMATCH shown, honest copy
VERIFIED). Screenshot (JPEG q75) → blind decode → VERIFIED / ANALOG-HOLE.
Ledger edit → detected. Evidence (with node receipts+proofs) → clean-room
ANCHORED VERIFIED. Revoked Alice → BLOCKED. Closing: authorized event verified;
physical leak not established.

## Security primitives

| Use | Primitive | Standard |
|---|---|---|
| Document encryption | AES-256-GCM (random key + fresh 96-bit nonce per encryption) | NIST SP 800-38D |
| Per-recipient key access | ML-KEM-768 encaps/decaps, shared secret as KEK (KEM-DEM hybrid) | FIPS 203 |
| Event/authorization signatures | ML-DSA-65 over canonical JSON | FIPS 204 |
| Provenance derivation | HKDF-SHA256 (IKM=auth sig, salt=event_id, domain-separated info) | NIST SP 800-56C |
| Ledger / commitments | SHA-256 (hash chain + `watermark_token_hash` + `document_hash` + `copy_hash`) | FIPS 180-4 |
| Key-at-rest protection | scrypt → AES-256-GCM per-vault passphrases | NIST SP 800-132 / 800-38D |
| Randomness | `secrets` / `uuid4` / PQC reference RNG (OS entropy) | — |

No RSA/ECDSA/Diffie-Hellman anywhere. Canonical serialization (`sort_keys`, compact
separators) is used for every signed/hashed record. Server keys live in
`data/keys/` (KEM only in v2 mode); recipient signing keys live ONLY in
`data/recipient_vault/`; custodian keys in `data/custodians/`. No private key
is ever returned by any API. Fully offline — no network, no blockchain, no cloud.

## Installation

```
pip install -r requirements.txt
```

## Running the demos

```
python demo.py               # v1 legacy flow (compatibility only)
python3 demo_attested.py     # v2 HOSTILE + DISTRIBUTED flagship (judges)
python3 test_mvp.py          # 34 legacy checks
python3 test_attested.py     # 25 hostile v2 checks
python3 test_distributed.py  # 20 independent-node checks
python scripts/measure_robustness.py  # regenerate the lattice survival matrix
```

`demo_attested.py` runs 10 attack/defense steps (incl. node witnessing and a
screenshot attribution) and writes `demo_output_attested/evidence/`
(`evidence_package.json`, `trust_anchor.json`, `forensic_report.txt` —
no private keys).

## Running tests

```
python test_mvp.py         # 34 legacy checks (incl. 19-file network-free scan)
python3 test_attested.py   # 25 hostile v2 checks (fabrication, replay, transplant,
                           # quorum bypass, revocation, evidence tampering,
                           # traversal, checkpoint rollback, nonce races,
                           # trust-anchor forgery, clean-room wipe-and-verify, ...)
python3 test_distributed.py  # 20 node checks (validation, receipts, quorum,
                             # rollback/conflict, export/import, clean-room,
                             # compromise, auth/watermark/screenshot/revoke intact)
```

## Running the UI

```
python app.py
```

Open http://127.0.0.1:5000 — Dashboard (pipeline + live status cards including
quorum FINAL/PENDING + protocol), Encrypt (+PC label), Decrypt (attested
ceremony + per-node witness buttons + revoke), Ledger (FINAL/PENDING chips,
receipt/checkpoint detail), Investigate (file + screenshot/PNG/JPEG),
Robustness (measured matrix), How-it-works, and a **flagship demo** button
(runs the v2 hostile+distributed ceremony).
Loopback-only endpoints: `/api/attested-decrypt`, `/api/nodes`,
`/api/nodes/witness`, `/api/nodes/aggregate`, `/api/nodes/export-request`,
`/api/nodes/checkpoints/<id>`, `/api/challenge`, `/api/complete`,
`/api/witness`, `/api/demo-witness`, `/api/demo-revoke`, `/api/evidence`,
`/api/evidence/verify`, `/api/investigate`, `/api/investigate/v2`,
`/api/investigate/image`, `/api/robustness`, `/api/device`,
`/api/encryption-registry`, `/api/revoke`. `/api/decrypt` (custodial) is
retired: 410 Gone for valid requests (core function kept for tests only).

## Example investigation result

```
FORENSIC MATCH

Status: VERIFIED
Recipient: RECIPIENT-A
Event ID: 94cfeeb8349d46fc92c0c6d683c4bb5a
Document Hash: 973640df…
Timestamp: 2026-09-25T15:13:15.190456+00:00

Watermark: MATCHED
ML-DSA Signature: VALID
Ledger Integrity: VALID

Conclusion:
This document is cryptographically associated with RECIPIENT-A's authorized
decryption event.

Scope — cryptographic vs physical attribution:
- The leaked copy carries the watermark of RECIPIENT-A's signed decryption
  event (watermark match + valid ML-DSA signature + intact ledger).
- Not established. The system does not prove who physically transmitted or
  leaked the file — only which authorized decryption event this copy
  corresponds to.
```

## OFFLINE / AIR-GAPPED OPERATION

Everything runs locally in one Python process; the test suite statically
verifies no source file imports networking or references remote endpoints:

- All cryptography is local: `pqcrypto` (compiled NIST reference code for
  ML-KEM-768 / ML-DSA-65), `cryptography` (AES-256-GCM), `hashlib` (SHA-256),
  OS entropy via `secrets`.
- Pixel work is local too: Pillow/numpy/opencv (lattice decode), pymupdf
  (screenshot rendering for demo/harness) — all declared in requirements.txt,
  none touch the network.
- Storage is local files under `data/` (JSON + key files + PDF copies).
- The ledger is a local hash chain — no public blockchain, no cloud
  blockchain, no external DLT, no peers.
- No cloud KMS, no external auth, no external API, no online crypto service.
- The Flask UI binds to `127.0.0.1` only and loads no CDN resources.
- Dependencies are installed once (`pip install`); after that the demo,
  tests, and UI run with network access disabled.

## CURRENT SYSTEM (PRAMAAN v2 + distributed audit layer)

- PDF + txt/md documents; encrypt-once (AES-256-GCM) + per-recipient ML-KEM-768.
- Encryption origin filed per seal (SHA-256 fingerprint + stable PC-ID + label + time).
- v2: challenge → recipient-device ML-DSA-65 authorization → verified release.
- v2: HKDF-SHA256 provenance fingerprint bound to doc/version/session/key.
- PDF copies carry text token + LatticeMark pixel lattice; screenshot leaks verify as ANALOG-HOLE.
- v2: PENDING proposal → 2 independent node receipts → FINAL (Merkle-checkpointed).
- v2: binding-aware investigation + portable evidence (receipts/proofs) + clean-room verify.
- v1 legacy custodial flow in `core.py` for tests only; HTTP retired (410).

## Current limitations (honest)

- LatticeMark envelope measured (see §8b); outside it (q40, deep crops, rotation,
  print-scan, camera) attribution degrades to honest NOT VERIFIED.
- Nodes are separate state/passphrase boundaries in one offline process
  (prototype); OS-level tamper is detected, not prevented.
- 2-of-3 node-key collusion, whole-history replacement with stolen keys, and
  stripped watermarks defeat attribution (documented in §11).
- No HSM/PKI/TSA; clocks unanchored; PC labels self-asserted.

## FUTURE / PRODUCTION EXTENSIONS (not implemented)

- 3-machine air-gapped custodian deployment (node protocol already host-independent).
- Print-scan / camera-robust carriers; image / scanned-document support.
- Office document (Word/PowerPoint/Excel) support.
- HSM-backed key storage.
- Military PKI integration + TSA-anchored timestamps.
