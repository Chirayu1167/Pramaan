"""Independent offline custodian nodes (PRAMAAN distributed audit layer).

Why this module exists: the legacy quorum in `custodians.py` keeps all three
custodian keys on one filesystem behind one process. That enforces the 2-of-3
*RULE* but all witnesses still originate from a single trust domain. This
module gives each custodian a genuinely independent node:

  data/custodian_nodes/<CUSTODIAN-ID>/
    identity.json    public node identity (id, ML-DSA public key, ...)
    vault.sk         passphrase-encrypted ML-DSA *signing* key (this node only)
    receipts.json    this node's own witnessed-event log (node state)
    checkpoint.json  this node's latest signed checkpoint + history
    enrollment.json  enrollment snapshot this node validates against

  data/nodes.json    cross-node public registry {id: public key, ...}

A node validates a witness request using ONLY its enrollment snapshot plus
cryptography — never trusting the originator's live state — and returns a
signed receipt + signed checkpoint + Merkle inclusion proof. The originator
(Model B: file exchange, or Model A: loopback HTTP relay in app.py) merely
aggregates receipts; it cannot manufacture another node's signature.

Rule preserved: 0-1 valid witnesses -> PENDING, 2 distinct valid -> FINAL.

No networking in this module. No cloud. Fully offline.
"""
import copy
import re
from datetime import datetime, timezone

import ledger as ledger_mod
import pqc
import provenance as prov_mod
import store
import symcrypto

NODE_IDS = ["CUSTODIAN-1", "CUSTODIAN-2", "CUSTODIAN-3"]
PROTOCOL = "pramaan-nodes-v1"
LEDGER_ID = "pramaan-ledger-v1"
QUORUM = 2
GENESIS_ROOT = "0" * 64

REQUEST_FORMAT = "pramaan-witness-request-v1"
RECEIPT_FORMAT = "pramaan-witness-receipt-v1"

# Demo-only node passphrases, distinct per node and distinct from every other
# demo secret. Production: each custodian holds their own secret off-machine.
NODE_PASSPHRASES = {
    "CUSTODIAN-1": "pramaan-node-1-witness",
    "CUSTODIAN-2": "pramaan-node-2-witness",
    "CUSTODIAN-3": "pramaan-node-3-witness",
}

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_hex(s, n) -> bool:
    return isinstance(s, str) and len(s) == n and all(
        c in "0123456789abcdef" for c in s)


# ------------------------------------------------------------ Merkle ----
def merkle_root(leaves: list) -> str:
    """Root over ordered hex-leaf list. Empty log -> GENESIS_ROOT."""
    if not leaves:
        return GENESIS_ROOT
    level = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            pair = level[i] + (level[i + 1] if i + 1 < len(level) else level[i])
            nxt.append(bytes.fromhex(symcrypto.sha256_hex(pair)))
        level = nxt
    return level[0].hex()


def merkle_proof(leaves: list, index: int) -> list:
    """Inclusion proof: [{hash, left}...] from leaf to root."""
    if not (0 <= index < len(leaves)):
        raise ValueError("leaf index out of range")
    level = [bytes.fromhex(h) for h in leaves]
    idx, proof = index, []
    while len(level) > 1:
        sib = idx ^ 1
        sib_hash = level[sib] if sib < len(level) else level[idx]
        proof.append({"hash": sib_hash.hex(), "left": bool(sib < idx)})
        nxt = []
        for i in range(0, len(level), 2):
            pair = level[i] + (level[i + 1] if i + 1 < len(level) else level[i])
            nxt.append(bytes.fromhex(symcrypto.sha256_hex(pair)))
        level, idx = nxt, idx // 2
    return proof


def verify_merkle_proof(leaf_hex: str, proof: list, root_hex: str) -> bool:
    try:
        cur = bytes.fromhex(leaf_hex)
        for step in proof:
            sib = bytes.fromhex(step["hash"])
            cur = bytes.fromhex(symcrypto.sha256_hex(
                (sib + cur) if step["left"] else (cur + sib)))
        return cur.hex() == root_hex
    except Exception:
        return False


# ------------------------------------------------------- enrollment ----
def _enrollment_snapshot() -> dict:
    recips = store.load_recipients()
    return {
        "protocol": prov_mod.PROTOCOL_VERSION,
        "policy": {"version": prov_mod.POLICY_VERSION,
                   "hash": prov_mod.policy_hash()},
        "recipients": {
            rid: {"dsa_pk_hex": (r.get("dsa_pk_hex", "") if isinstance(r, dict) else ""),
                  "key_id": (r.get("key_id", "") if isinstance(r, dict) else ""),
                  "status": (r.get("status", "active") if isinstance(r, dict) else "active")}
            for rid, r in recips.items() if isinstance(r, dict)},
    }


def init_nodes(passphrases: dict | None = None) -> dict:
    """Create the 3 independent node identities (idempotent: keeps existing).

    Each node gets a FRESH ML-DSA keypair in its OWN vault file. No private
    key ever leaves its node directory.
    """
    passphrases = dict(NODE_PASSPHRASES) if passphrases is None else dict(passphrases)
    reg = store.load_nodes_registry()
    for cid in NODE_IDS:
        ident = store.load_node_identity(cid)
        if ident is not None and ident.get("dsa_pk_hex"):
            reg.setdefault(cid, {"dsa_pk_hex": ident["dsa_pk_hex"],
                                 "dsa_alg": pqc.DSA_ALGORITHM,
                                 "node_id": cid,
                                 "created_at": ident.get("created_at", utcnow_iso()),
                                 "protocol": PROTOCOL})
            continue
        dsa_pk, dsa_sk = pqc.dsa_generate_keypair()
        store.save_node_vault_key(cid, dsa_sk, passphrases[cid])
        ident = {"custodian_id": cid, "node_id": cid,
                 "dsa_pk_hex": dsa_pk.hex(), "dsa_alg": pqc.DSA_ALGORITHM,
                 "created_at": utcnow_iso(), "protocol": PROTOCOL,
                 "ledger_id": LEDGER_ID}
        store.save_node_identity(cid, ident)
        reg[cid] = {"dsa_pk_hex": dsa_pk.hex(), "dsa_alg": pqc.DSA_ALGORITHM,
                    "node_id": cid, "created_at": ident["created_at"],
                    "protocol": PROTOCOL}
        if store.load_node_enrollment(cid) is None:
            store.save_node_enrollment(cid, _enrollment_snapshot())
    store.save_nodes_registry(reg)
    return reg


def sync_enrollment(cid: str | None = None) -> None:
    """Refresh enrollment snapshot(s) from the current registry.

    Prototype ceremony stand-in for out-of-band enrollment distribution:
    run whenever recipients/policy change so every node validates against
    current public data. Nodes never pull silently during witnessing.
    """
    snap = _enrollment_snapshot()
    for target in ([cid] if cid else NODE_IDS):
        if store.load_node_identity(target) is None:
            raise ValueError(f"unknown custodian node {target!r}")
        store.save_node_enrollment(target, copy.deepcopy(snap))


# -------------------------------------------------- witness request ----
def build_witness_request(chain: list, index: int) -> dict:
    """Originator-side: assemble an untrusted validation package for a block.

    Carries everything a node needs; the node re-verifies all of it against
    its own enrollment snapshot, so nothing here is trusted on arrival.
    """
    if not (0 <= index < len(chain)):
        raise ValueError("block index out of range")
    block = chain[index]
    event = block.get("event")
    if not isinstance(event, dict) or not ledger_mod.is_v2_event(event):
        raise ValueError("node witnessing requires a ps26237-v2 event block")
    if block.get("status") == "FINAL":
        raise ValueError("block already FINAL: same event cannot be finalized twice")
    recips = store.load_recipients()
    entry = recips.get(event.get("recipient_id", ""))
    if not isinstance(entry, dict):
        raise ValueError("recipient record missing for witness request")
    return {
        "format": REQUEST_FORMAT,
        "protocol": PROTOCOL,
        "ledger_id": LEDGER_ID,
        "block_index": index,
        "block_prev_hash": block.get("prev_hash", ""),
        "event": copy.deepcopy(event),
        "recipient": {"id": event.get("recipient_id", ""),
                      "key_id": event.get("recipient_key_id", ""),
                      "dsa_pk_hex": entry.get("dsa_pk_hex", ""),
                      "status": entry.get("status", "active")},
        "policy": {"version": prov_mod.POLICY_VERSION,
                   "hash": prov_mod.policy_hash()},
    }


def _fail(reason: str) -> tuple:
    return False, reason, {}


def validate_request(pkg: dict, cid: str) -> tuple:
    """Node-side independent validation. Returns (ok, reason, ctx).

    Uses ONLY the node's enrollment snapshot + cryptography. Checks, in
    order: structure/protocol, policy currency, recipient enrollment +
    activity + key binding, authorization signature, derivation/commitment
    consistency, token format, duplicate (replay), prev-hash well-formedness.
    """
    if not isinstance(pkg, dict) or pkg.get("format") != REQUEST_FORMAT:
        return _fail("malformed witness request (bad format)")
    if pkg.get("protocol") != PROTOCOL or pkg.get("ledger_id") != LEDGER_ID:
        return _fail("protocol/ledger mismatch")
    event = pkg.get("event")
    if not isinstance(event, dict) or not ledger_mod.is_v2_event(event):
        return _fail("request carries no v2 provenance event")
    for f in ledger_mod.REQUIRED_EVENT_FIELDS + ledger_mod.V2_EVENT_FIELDS:
        if not isinstance(event.get(f), str):
            return _fail(f"event missing required field {f!r}")
    if not isinstance(event.get("derivation"), dict):
        return _fail("event missing derivation record")
    if not _is_hex(event.get("event_id", ""), 32):
        return _fail("malformed event_id")
    enr = store.load_node_enrollment(cid)
    if not isinstance(enr, dict):
        return _fail(f"node {cid} has no enrollment snapshot (run sync)")
    if pkg.get("policy") != enr.get("policy"):
        return _fail("stale/unknown policy: node enrollment disagrees")
    req_recip = pkg.get("recipient")
    if not isinstance(req_recip, dict):
        return _fail("request missing recipient record")
    enrolled = (enr.get("recipients", {}) or {}).get(event.get("recipient_id", ""))
    if not isinstance(enrolled, dict) or not enrolled.get("dsa_pk_hex"):
        return _fail("recipient not enrolled at this node")
    if enrolled.get("status", "active") != "active":
        return _fail("recipient revoked in node enrollment")
    for k in ("key_id", "dsa_pk_hex"):
        if req_recip.get(k) != enrolled.get(k) or event.get(
                "recipient_key_id", "") != enrolled.get("key_id", ""):
            return _fail("recipient key binding mismatch")
    try:
        challenge = ledger_mod.challenge_from_event(event)
        auth_sig = bytes.fromhex(event["authorization_signature_hex"])
        signer_pk = bytes.fromhex(enrolled["dsa_pk_hex"])
    except (KeyError, ValueError, TypeError):
        return _fail("malformed authorization fields")
    if not pqc.dsa_verify(signer_pk, ledger_mod.canonical(challenge), auth_sig):
        return _fail("invalid recipient authorization signature")
    expected = prov_mod.recompute_fingerprint(auth_sig, event)
    if symcrypto.sha256_hex(bytes.fromhex(expected)) != event.get("watermark_token_hash"):
        return _fail("derivation/commitment mismatch (transplant or tamper)")
    if not _is_hex(pkg.get("block_prev_hash", ""), 64):
        return _fail("malformed prev-hash reference")
    for entry in store.load_node_receipts(cid):
        if isinstance(entry, dict) and entry.get("event_id") == event.get("event_id"):
            return _fail("duplicate: this node already witnessed the event (replay)")
    event_hash = symcrypto.sha256_hex(ledger_mod.canonical(event))
    return True, "", {"event_hash": event_hash, "recipient": enrolled}


# ---------------------------------------------------------- witness ----
def witness_request(pkg: dict, cid: str, passphrase: str) -> dict:
    """Node-side: validate, append to node log, sign receipt + checkpoint.

    Returns the exportable receipt package {receipt, signature, checkpoint,
    Merkle proof, node public key}. Raises ValueError on any failure —
    a node never signs what it cannot independently verify.
    """
    if not passphrase:
        raise ValueError("node passphrase is required")
    target = pkg.get("custodian_id", cid) if isinstance(pkg, dict) else cid
    if target != cid:
        raise ValueError("request addressed to a different node")
    sk = store.load_node_vault_key(cid, passphrase)  # wrong secret -> error
    ok, reason, ctx = validate_request(pkg, cid)
    if not ok:
        raise ValueError(f"node {cid} refuses: {reason}")
    event, event_hash = pkg["event"], ctx["event_hash"]
    log = store.load_node_receipts(cid)
    seq = len(log)
    entry = {"seq": seq, "event_id": event.get("event_id"),
             "event_hash": event_hash,
             "block_prev_hash": pkg.get("block_prev_hash"),
             "witnessed_at": utcnow_iso()}
    log.append(entry)
    store.save_node_receipts(cid, log)
    leaves = [e.get("event_hash", "") for e in log]
    state_root = merkle_root(leaves)
    prev_cp = store.load_node_checkpoint(cid)
    body = {"protocol": PROTOCOL, "ledger_id": LEDGER_ID,
            "custodian_id": cid, "event_id": event.get("event_id"),
            "event_hash": event_hash,
            "block_prev_hash": pkg.get("block_prev_hash"),
            "state_root": state_root, "seq": seq,
            "timestamp": entry["witnessed_at"]}
    sig = pqc.dsa_sign(sk, ledger_mod.canonical(body)).hex()
    prev_hash = (prev_cp.get("checkpoint_hash", GENESIS_ROOT)
                 if isinstance(prev_cp, dict) else GENESIS_ROOT)
    cbody = {"protocol": PROTOCOL, "ledger_id": LEDGER_ID,
             "seq": seq, "event_count": len(log), "state_root": state_root,
             "tip_event_hash": event_hash, "tip_event_id": event.get("event_id"),
             "prev_checkpoint_hash": prev_hash, "timestamp": utcnow_iso(),
             "custodian_id": cid}
    cbody["checkpoint_hash"] = symcrypto.sha256_hex(ledger_mod.canonical(cbody))
    csig = pqc.dsa_sign(sk, ledger_mod.canonical(cbody)).hex()
    checkpoint = dict(cbody)
    checkpoint["signature_hex"] = csig
    hist = (prev_cp.get("history", []) if isinstance(prev_cp, dict) else []) + [
        {k: v for k, v in checkpoint.items() if k != "history"}]
    checkpoint["history"] = hist[-16:]  # bounded trailing history for clean-room
    store.save_node_checkpoint(cid, checkpoint)
    ident = store.load_node_identity(cid) or {}
    return {"format": RECEIPT_FORMAT, "protocol": PROTOCOL, "ledger_id": LEDGER_ID,
            "receipt": body, "signature_hex": sig,
            "checkpoint": checkpoint,
            "proof": merkle_proof(leaves, seq),
            "node": {"custodian_id": cid,
                     "dsa_pk_hex": ident.get("dsa_pk_hex", "")}}


def verify_receipt_package(rpkg: dict, event: dict | None = None) -> tuple:
    """Verify a receipt package standalone. Returns (ok, reason)."""
    if not isinstance(rpkg, dict) or rpkg.get("format") != RECEIPT_FORMAT:
        return False, "malformed receipt package (bad format)"
    if rpkg.get("protocol") != PROTOCOL or rpkg.get("ledger_id") != LEDGER_ID:
        return False, "protocol/ledger mismatch"
    body, sig_hex = rpkg.get("receipt"), rpkg.get("signature_hex")
    node = rpkg.get("node") or {}
    if not isinstance(body, dict) or not isinstance(sig_hex, str):
        return False, "malformed receipt"
    try:
        node_pk = bytes.fromhex(node.get("dsa_pk_hex", ""))
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError, AttributeError):
        return False, "malformed node key/signature"
    if body.get("custodian_id") != node.get("custodian_id"):
        return False, "receipt/node identity mismatch"
    if not pqc.dsa_verify(node_pk, ledger_mod.canonical(body), sig):
        return False, "INVALID node witness signature (forged witness)"
    if event is not None:
        if symcrypto.sha256_hex(ledger_mod.canonical(event)) != body.get("event_hash"):
            return False, "receipt binds a different event (mismatched event hash)"
    for f, n in (("event_hash", 64), ("block_prev_hash", 64), ("state_root", 64)):
        if not _is_hex(body.get(f, ""), n):
            return False, f"malformed receipt field {f!r}"
    if not isinstance(body.get("seq"), int) or body["seq"] < 0:
        return False, "malformed receipt sequence"
    cp = rpkg.get("checkpoint") or {}
    try:
        cp_sig = bytes.fromhex(cp.get("signature_hex", ""))
    except (ValueError, TypeError, AttributeError):
        return False, "malformed checkpoint signature"
    cp_body = {k: v for k, v in cp.items() if k not in ("signature_hex", "history")}
    if not pqc.dsa_verify(node_pk, ledger_mod.canonical(cp_body), cp_sig):
        return False, "INVALID checkpoint signature"
    if cp.get("tip_event_hash") != body.get("event_hash") \
            or cp.get("seq") != body.get("seq") \
            or cp.get("state_root") != body.get("state_root") \
            or cp.get("custodian_id") != body.get("custodian_id"):
        return False, "checkpoint inconsistent with receipt"
    if not verify_merkle_proof(body["event_hash"], rpkg.get("proof", []),
                               body["state_root"]):
        return False, "Merkle proof fails (altered historical root)"
    return True, ""


# -------------------------------------------------------- aggregate ----
def aggregate_receipts(chain: list, index: int, rpkgs: list) -> dict:
    """Originator-side: verify receipts and finalize the block (2-of-3).

    The aggregator checks everything but manufactures nothing: unknown
    custodians, forged signatures, mismatched events, duplicates, replays
    and conflicting roots are all rejected. A FINAL block cannot be
    finalized twice.
    """
    if not (0 <= index < len(chain)):
        raise ValueError("block index out of range")
    block = chain[index]
    event = block.get("event")
    if not isinstance(event, dict):
        raise ValueError("cannot finalize a malformed block")
    if block.get("status") == "FINAL":
        raise ValueError("block already FINAL: same event cannot be finalized twice")
    if not isinstance(rpkgs, list) or not rpkgs:
        raise ValueError("no witness receipts supplied")
    registry = store.load_nodes_registry()
    seen: dict = {}
    for rpkg in rpkgs:
        if not isinstance(rpkg, dict):
            raise ValueError("malformed receipt package (not an object)")
        cid = (rpkg.get("receipt") or {}).get("custodian_id") \
            if isinstance(rpkg.get("receipt"), dict) else None
        if not cid or cid not in registry:
            raise ValueError(f"unknown custodian {cid!r}")
        if cid in seen:
            raise ValueError(f"duplicate witness from {cid} (replay rejected)")
        # The receipt's node key must be the enrolled node key (key substitution).
        if (rpkg.get("node") or {}).get("dsa_pk_hex") != \
                registry[cid].get("dsa_pk_hex"):
            raise ValueError(f"node key for {cid!r} not enrolled (substitution)")
        ok, reason = verify_receipt_package(rpkg, event)
        if not ok:
            raise ValueError(f"receipt from {cid} rejected: {reason}")
        seen[cid] = rpkg
    if len(seen) < QUORUM:
        raise ValueError(f"quorum NOT reached ({len(seen)}-of-3, need 2): PENDING")
    witnesses = []
    for cid in sorted(seen):
        rpkg = seen[cid]
        witnesses.append({"custodian_id": cid,
                          "signature_hex": rpkg["signature_hex"],
                          "witnessed_at": rpkg["receipt"]["timestamp"],
                          "receipt": rpkg["receipt"],
                          "checkpoint": rpkg["checkpoint"],
                          "proof": rpkg["proof"],
                          "node_pk_hex": (rpkg.get("node") or {}).get("dsa_pk_hex", "")})
    block["witnesses"] = witnesses
    block["status"] = "FINAL"
    block["block_hash"] = ledger_mod.block_hash_of(
        {k: v for k, v in block.items() if k != "block_hash"})
    store.save_ledger(chain)
    store.advance_checkpoint_tip({"tip_hash": block["block_hash"],
                                  "index": block.get("index"),
                                  "status": "FINAL",
                                  "updated_at": utcnow_iso()})
    return block


def verify_block_receipts(block: dict) -> tuple:
    """Quorum check over node-receipt witness entries. Returns (ok, msg, n)."""
    witnesses = block.get("witnesses")
    if not isinstance(witnesses, list):
        return False, "no witnesses field", 0
    event = block.get("event")
    registry = store.load_nodes_registry()
    valid: set = set()
    for w in witnesses:
        if not isinstance(w, dict):
            return False, "malformed witness entry", 0
        if "receipt" not in w:
            return False, "mixed legacy/node witness entries", 0
        cid = w.get("custodian_id")
        if not cid or cid not in registry:
            return False, f"unknown witness {cid!r}", 0
        rpkg = {"format": RECEIPT_FORMAT, "protocol": PROTOCOL,
                "ledger_id": LEDGER_ID, "receipt": w["receipt"],
                "signature_hex": w.get("signature_hex", ""),
                "checkpoint": w.get("checkpoint", {}),
                "proof": w.get("proof", []),
                "node": {"custodian_id": cid,
                         "dsa_pk_hex": w.get("node_pk_hex",
                                             registry[cid].get("dsa_pk_hex", ""))}}
        if rpkg["node"]["dsa_pk_hex"] != registry[cid].get("dsa_pk_hex"):
            return False, f"node key for {cid!r} not enrolled", 0
        ok, reason = verify_receipt_package(rpkg, event)
        if not ok:
            return False, f"INVALID node witness from {cid}: {reason}", 0
        valid.add(cid)
    if len(valid) >= QUORUM:
        return True, f"quorum {len(valid)}-of-3 FINAL (independent nodes)", len(valid)
    return False, f"quorum NOT reached ({len(valid)}-of-3, need 2)", len(valid)


# -------------------------------------------------- checkpoint sync ----
def check_stale_or_conflict(cid: str, cp: dict) -> str:
    """Compare an incoming checkpoint against stored state.

    Returns "fresh" (applies cleanly), "stale" (older seq), "conflict"
    (same seq, different root/hash) or raises on malformed input.
    """
    if not isinstance(cp, dict) or not isinstance(cp.get("seq"), int):
        raise ValueError("malformed checkpoint")
    stored = store.load_node_checkpoint(cid)
    if not isinstance(stored, dict) or not isinstance(stored.get("seq"), int):
        return "fresh"
    if cp.get("seq", -1) < stored.get("seq", -1):
        return "stale"
    if cp.get("seq") == stored.get("seq") and (
            cp.get("state_root") != stored.get("state_root")
            or cp.get("checkpoint_hash") != stored.get("checkpoint_hash")):
        return "conflict"
    return "fresh"


def import_checkpoint(cid: str, cp: dict) -> str:
    """Verify + import a checkpoint (rollback refused by store guard)."""
    reg = store.load_nodes_registry()
    entry = reg.get(cid)
    if entry is None:
        raise ValueError(f"unknown custodian node {cid!r}")
    try:
        pk = bytes.fromhex(entry.get("dsa_pk_hex", ""))
        sig = bytes.fromhex(cp.get("signature_hex", ""))
    except (ValueError, TypeError, AttributeError) as e:
        raise ValueError("malformed checkpoint key/signature") from e
    body = {k: v for k, v in cp.items() if k not in ("signature_hex", "history")}
    if not pqc.dsa_verify(pk, ledger_mod.canonical(body), sig):
        raise ValueError("INVALID checkpoint signature")
    verdict = check_stale_or_conflict(cid, cp)
    if verdict == "stale":
        raise ValueError("stale checkpoint refused")
    if verdict == "conflict":
        raise ValueError("conflicting checkpoint root refused")
    store.save_node_checkpoint(cid, cp)  # monotonic guard inside
    return "imported"


def verify_checkpoint_history(cid: str) -> tuple:
    """Check stored checkpoint linkage + monotonicity for one node."""
    cp = store.load_node_checkpoint(cid)
    if not isinstance(cp, dict):
        return False, "no checkpoint stored"
    hist = cp.get("history", [])
    if not hist:
        return True, "genesis checkpoint (no history yet)"
    prev_hash, prev_seq = GENESIS_ROOT, -1
    for h in hist:
        if not isinstance(h, dict):
            return False, "malformed checkpoint history entry"
        if h.get("prev_checkpoint_hash") != prev_hash:
            return False, "checkpoint history linkage broken"
        if not isinstance(h.get("seq"), int) or h["seq"] <= prev_seq:
            return False, "checkpoint history not monotonic"
        prev_hash, prev_seq = h.get("checkpoint_hash", ""), h["seq"]
    if cp.get("checkpoint_hash") != prev_hash or cp.get("seq") != prev_seq:
        return False, "stored tip disagrees with history"
    return True, f"OK: {len(hist)} checkpoint(s) linked, tip seq {prev_seq}"


# ------------------------------------------------------ file export ----
def export_package(pkg: dict, path: str) -> bytes:
    """Write a deterministic canonical package file (Model B exchange)."""
    import os as _os
    raw = ledger_mod.canonical(pkg)
    with open(path, "wb") as f:
        f.write(raw)
    return raw


def import_package(path_or_bytes) -> dict:
    """Read + minimally validate an exchange package (file path or bytes)."""
    import json as _json
    import os as _os
    if isinstance(path_or_bytes, (bytes, bytearray)):
        raw = bytes(path_or_bytes)
    elif isinstance(path_or_bytes, str) and _os.path.exists(path_or_bytes):
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    else:
        raise ValueError("package path does not exist")
    try:
        pkg = _json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError("package is not valid JSON") from e
    if not isinstance(pkg, dict) or pkg.get("format") not in (
            REQUEST_FORMAT, RECEIPT_FORMAT):
        raise ValueError("unknown package format")
    return pkg


def node_status(cid: str) -> dict:
    """Public node state (no secrets): seq, tip, checkpoint linkage."""
    ident = store.load_node_identity(cid) or {}
    log = store.load_node_receipts(cid)
    cp = store.load_node_checkpoint(cid) or {}
    leaves = [e.get("event_hash", "") for e in log if isinstance(e, dict)]
    return {"custodian_id": cid, "node_id": ident.get("node_id", cid),
            "protocol": PROTOCOL, "witnessed_events": len(log),
            "state_root": merkle_root(leaves),
            "tip_event_id": (log[-1].get("event_id") if log else None),
            "checkpoint_seq": cp.get("seq"),
            "checkpoint_hash": cp.get("checkpoint_hash")}
