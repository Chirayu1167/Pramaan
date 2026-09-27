"""Local tamper-evident blockchain-style hash-chain ledger (offline).

This is a single-machine append-only audit log, NOT a distributed
blockchain: there is no consensus network, no peers, no cloud. Tamper
*evidence* comes from the SHA-256 hash chain plus an ML-DSA signature on
every block — any edit, reorder, truncation, or forgery is detected by
verify_ledger(). Tamper *prevention* at the OS/file level is out of scope.

Each block: {index, timestamp, event, signature, signer (recipient_id),
             prev_hash, block_hash}
block_hash = SHA256(canonical(block without 'block_hash')).
"""
import json
from datetime import datetime, timezone

import pqc
import symcrypto

GENESIS_PREV = "0" * 64


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def block_hash_of(block_without_hash: dict) -> str:
    return symcrypto.sha256_hex(canonical(block_without_hash))


REQUIRED_EVENT_FIELDS = ("event_id", "recipient_id", "document_id",
                           "document_hash", "watermark_token_hash", "timestamp")

# PS26237-v2 attested events carry these ADDITIONAL string fields (legacy
# REQUIRED_EVENT_FIELDS are still all present, so v1 checks keep working).
V2_EVENT_FIELDS = ("protocol_version", "document_version", "policy_hash",
                   "policy_version", "session_nonce", "recipient_key_id",
                   "authorization_signature_hex", "copy_hash",
                   "challenge_issued_at")

V2_BLOCK_FIELDS = {"index", "timestamp", "event", "signer", "witnesses",
                   "status", "prev_hash", "block_hash"}
V1_BLOCK_FIELDS = {"index", "timestamp", "event", "signature",
                   "signer", "prev_hash", "block_hash"}


def is_v2_event(event: dict) -> bool:
    return (isinstance(event, dict)
            and event.get("protocol_version") == "ps26237-v2")


def challenge_from_event(event: dict) -> dict:
    """Reconstruct the exact signed challenge bytes from a stored v2 event."""
    return {"protocol": event["protocol_version"],
            "event_id": event["event_id"],
            "doc_id": event["document_id"],
            "document_hash": event["document_hash"],
            "document_version": event["document_version"],
            "recipient_id": event["recipient_id"],
            "recipient_key_id": event["recipient_key_id"],
            "session_nonce": event["session_nonce"],
            "policy_hash": event["policy_hash"],
            "policy_version": event["policy_version"],
            "issued_at": event["challenge_issued_at"]}


def _event_ids(chain: list) -> tuple[set, set]:
    """Collect (event_ids, watermark_token_hashes) already on the chain."""
    eids, thashes = set(), set()
    for b in chain:
        ev = b.get("event") if isinstance(b, dict) else None
        if isinstance(ev, dict):
            if isinstance(ev.get("event_id"), str):
                eids.add(ev["event_id"])
            if isinstance(ev.get("watermark_token_hash"), str):
                thashes.add(ev["watermark_token_hash"])
    return eids, thashes


def append_event(chain: list, event: dict, signature_hex: str, signer_id: str) -> dict:
    """Append one block. Rejects malformed events and duplicates."""
    if not isinstance(event, dict) or \
            any(not isinstance(event.get(f), str) for f in REQUIRED_EVENT_FIELDS):
        raise ValueError("event must contain all required string fields: "
                         + ", ".join(REQUIRED_EVENT_FIELDS))
    if not isinstance(signature_hex, str) or not isinstance(signer_id, str):
        raise ValueError("signature and signer must be strings")
    eids, thashes = _event_ids(chain)
    if event["event_id"] in eids:
        raise ValueError(f"duplicate event_id {event['event_id']!r}: ledger is append-only")
    if event["watermark_token_hash"] in thashes:
        raise ValueError("duplicate watermark_token_hash: each decryption needs a fresh token")
    prev = chain[-1]["block_hash"] if chain else GENESIS_PREV
    block = {
        "index": len(chain),
        "timestamp": utcnow_iso(),
        "event": event,
        "signature": signature_hex,
        "signer": signer_id,
        "prev_hash": prev,
    }
    block["block_hash"] = block_hash_of(block)
    chain.append(block)
    return block


def _is_hex64(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def propose_event(chain: list, event: dict) -> dict:
    """Append a PS26237-v2 attested event as a PENDING proposal block.

    The block becomes FINAL only after 2-of-3 custodian witnesses
    (see custodians.witness_block). Rejects malformed events and duplicates,
    same as append_event.
    """
    if not isinstance(event, dict) or not is_v2_event(event):
        raise ValueError("propose_event requires a ps26237-v2 event dict")
    if any(not isinstance(event.get(f), str)
           for f in REQUIRED_EVENT_FIELDS + V2_EVENT_FIELDS):
        raise ValueError("v2 event must contain all required string fields: "
                         + ", ".join(REQUIRED_EVENT_FIELDS + V2_EVENT_FIELDS))
    if not isinstance(event.get("derivation"), dict):
        raise ValueError("v2 event must carry a derivation record")
    eids, thashes = _event_ids(chain)
    if event["event_id"] in eids:
        raise ValueError(f"duplicate event_id {event['event_id']!r}: ledger is append-only")
    if event["watermark_token_hash"] in thashes:
        raise ValueError("duplicate watermark_token_hash: each decryption needs a fresh token")
    prev = chain[-1]["block_hash"] if chain else GENESIS_PREV
    block = {
        "index": len(chain),
        "timestamp": utcnow_iso(),
        "event": event,
        "signer": event["recipient_id"],
        "witnesses": [],
        "status": "PENDING",
        "prev_hash": prev,
    }
    block["block_hash"] = block_hash_of(block)
    chain.append(block)
    return block


def _verify_v1_block(block: dict, i: int, recipients: dict,
                     expected_prev: str) -> tuple[bool, str, str]:
    """Legacy checks. Returns (ok, msg, prev_hash)."""
    if set(block) != V1_BLOCK_FIELDS:
        return False, f"block {i}: malformed block (bad fields)", ""
    if block.get("index") != i:
        return False, f"block {i}: bad index", ""
    if not isinstance(block.get("event"), dict):
        return False, f"block {i}: malformed event", ""
    if block.get("prev_hash") != expected_prev:
        return False, f"block {i}: prev_hash mismatch (chain broken)", ""
    recomputed = block_hash_of({k: v for k, v in block.items() if k != "block_hash"})
    if recomputed != block.get("block_hash"):
        return False, f"block {i}: block_hash mismatch (record modified)", ""
    if not _is_hex64(block.get("prev_hash") if i else GENESIS_PREV):
        return False, f"block {i}: malformed prev_hash", ""
    signer = block.get("signer")
    recip = recipients.get(signer)
    if recip is None:
        return False, f"block {i}: unknown signer {signer!r}", ""
    try:
        sig = bytes.fromhex(block["signature"])
        pk = bytes.fromhex(recip["dsa_pk_hex"])
    except Exception:
        return False, f"block {i}: malformed signature/public key", ""
    if not pqc.dsa_verify(pk, canonical(block["event"]), sig):
        return False, f"block {i}: ML-DSA signature INVALID", ""
    return True, "", block["block_hash"]


def _verify_v2_block(block: dict, i: int, recipients: dict,
                     custodians: dict | None,
                     expected_prev: str) -> tuple[bool, str, str]:
    """v2 structural + quorum checks. Authorization-signature and fingerprint
    derivation checks live in core.verify_attested_event (forensic level)."""
    if set(block) != V2_BLOCK_FIELDS:
        return False, f"block {i}: malformed v2 block (bad fields)", ""
    if block.get("index") != i:
        return False, f"block {i}: bad index", ""
    event = block.get("event")
    if not isinstance(event, dict) or not is_v2_event(event):
        return False, f"block {i}: malformed v2 event", ""
    if block.get("prev_hash") != expected_prev:
        return False, f"block {i}: prev_hash mismatch (chain broken)", ""
    if any(not isinstance(event.get(f), str)
           for f in REQUIRED_EVENT_FIELDS + V2_EVENT_FIELDS):
        return False, f"block {i}: v2 event missing required fields", ""
    if not isinstance(event.get("derivation"), dict):
        return False, f"block {i}: v2 event missing derivation record", ""
    if block.get("signer") != event.get("recipient_id"):
        return False, f"block {i}: signer/event recipient mismatch", ""
    if event.get("recipient_id") not in recipients:
        return False, f"block {i}: unknown recipient {event.get('recipient_id')!r}", ""
    if block.get("status") not in ("PENDING", "FINAL"):
        return False, f"block {i}: bad status", ""
    recomputed = block_hash_of({k: v for k, v in block.items() if k != "block_hash"})
    if recomputed != block.get("block_hash"):
        return False, f"block {i}: block_hash mismatch (record modified)", ""
    if not _is_hex64(block.get("prev_hash") if i else GENESIS_PREV):
        return False, f"block {i}: malformed prev_hash", ""
    if not isinstance(block.get("witnesses"), list):
        return False, f"block {i}: malformed witnesses", ""
    if custodians is None:
        return False, f"block {i}: custodian registry required for v2 quorum check", ""
    # Cryptographic quorum verification (distinct valid custodian sigs).
    import custodians as custodians_mod  # local import: avoid import cycle
    ok, detail = custodians_mod.verify_witnesses(block, custodians)
    claimed_final = block.get("status") == "FINAL"
    if claimed_final and not ok:
        return False, f"block {i}: claims FINAL but {detail}", ""
    if not claimed_final and ok:
        return False, f"block {i}: quorum reached but status not FINAL", ""
    return True, "", block["block_hash"]


def verify_ledger(chain: list, recipients: dict,
                  custodians: dict | None = None) -> tuple[bool, str]:
    """Recompute the hash chain and verify every block.

    v1 blocks: legacy ML-DSA event-signature check (unchanged).
    v2 blocks: structural checks + 2-of-3 custodian quorum verification.
    Mixed chains are supported. `custodians` is required iff the chain holds
    v2 blocks (fail-closed otherwise).
    """
    if not isinstance(chain, list):
        return False, "ledger must be a list of blocks"
    if not isinstance(recipients, dict):
        return False, "recipients must be a dict"
    prev = GENESIS_PREV
    v1_n = v2_n = final_n = 0
    for i, block in enumerate(chain):
        if not isinstance(block, dict):
            return False, f"block {i}: malformed block (not an object)"
        if "witnesses" in block:
            ok, msg, prev = _verify_v2_block(block, i, recipients, custodians, prev)
            if not ok:
                return False, msg
            v2_n += 1
            if block.get("status") == "FINAL":
                final_n += 1
        else:
            ok, msg, prev = _verify_v1_block(block, i, recipients, prev)
            if not ok:
                return False, msg
            v1_n += 1
    extra = f" ({v1_n} v1, {v2_n} v2/{final_n} FINAL)" if v2_n else ""
    return True, (f"OK: {len(chain)} block(s), hash chain + all signatures valid"
                  f"{extra}")
