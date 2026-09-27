"""2-of-3 custodian witness quorum (PS26237-v2, offline simulation).

Three independent ML-DSA-65 custodian keys. A ledger block becomes FINAL only
with >=2 distinct valid witness signatures over
  canonical({"index","event","prev_hash"}).

Honest label: on this demo everything shares one filesystem, so this is an
"offline 2-of-3 custodian quorum simulation", NOT a distributed blockchain.
Production requires independent machines/trust domains. The quorum RULE itself
(1 sig = PENDING/REJECTED, 2+ = FINAL) is genuinely enforced in code.

No networking. Fully offline.
"""
from datetime import datetime, timezone

import ledger as ledger_mod
import pqc
import store

CUSTODIAN_IDS = ["CUSTODIAN-1", "CUSTODIAN-2", "CUSTODIAN-3"]
QUORUM = 2

# Demo-only custodian passphrases, distinct from each other and from the server
# passphrase. Production: each custodian holds their own secret off-machine.
CUSTODIAN_PASSPHRASES = {
    "CUSTODIAN-1": "ps26237-custodian-1-witness",
    "CUSTODIAN-2": "ps26237-custodian-2-witness",
    "CUSTODIAN-3": "ps26237-custodian-3-witness",
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_custodians() -> dict:
    """Create the 3 custodian keypairs (idempotent: keeps existing keys)."""
    custodians = store.load_custodians()
    for cid in CUSTODIAN_IDS:
        if cid in custodians:
            continue
        dsa_pk, dsa_sk = pqc.dsa_generate_keypair()
        store.save_custodian_key(cid, dsa_sk, CUSTODIAN_PASSPHRASES[cid])
        custodians[cid] = {"dsa_pk_hex": dsa_pk.hex(),
                           "dsa_alg": pqc.DSA_ALGORITHM,
                           "created_at": utcnow_iso()}
    store.save_custodians(custodians)
    return custodians


def proposal_hash(block: dict) -> bytes:
    """Canonical bytes custodians witness: index + event + prev_hash only."""
    return ledger_mod.canonical({"index": block["index"], "event": block["event"],
                                 "prev_hash": block["prev_hash"]})


def witness_block(chain: list, index: int, custodian_id: str,
                  passphrase: str) -> dict:
    """Append one custodian witness signature to block[index]. Enforces:
    distinct custodians, valid custodian key, block linkage intact.
    Returns the updated block.
    """
    custodians = store.load_custodians()
    if custodian_id not in custodians:
        raise ValueError(f"unknown custodian {custodian_id!r}")
    if not (0 <= index < len(chain)):
        raise ValueError("block index out of range")
    block = chain[index]
    if not isinstance(block.get("event"), dict):
        raise ValueError("cannot witness a malformed block")
    seen = {w.get("custodian_id") for w in block.get("witnesses", [])
            if isinstance(w, dict)}
    if custodian_id in seen:
        raise ValueError(f"{custodian_id} already witnessed block {index}")
    sk = store.load_custodian_key(custodian_id, passphrase)
    sig = pqc.dsa_sign(sk, proposal_hash(block))
    block.setdefault("witnesses", []).append(
        {"custodian_id": custodian_id, "signature_hex": sig.hex(),
         "witnessed_at": utcnow_iso()})
    # Status BEFORE hashing: block_hash commits to witnesses + status together.
    block["status"] = "FINAL" if is_final(block, custodians) else "PENDING"
    block["block_hash"] = ledger_mod.block_hash_of(
        {k: v for k, v in block.items() if k != "block_hash"})
    store.save_ledger(chain)
    _update_checkpoint(chain)
    return block


def verify_witnesses(block: dict, custodians: dict) -> tuple[bool, str]:
    """Check witness signatures; returns (quorum_reached, detail).

    Two entry flavors: legacy single-host entries (signature over the
    proposal hash) and independent-node receipt entries (delegated to
    nodes.verify_block_receipts). Mixed blocks are rejected.
    """
    witnesses = block.get("witnesses")
    if isinstance(witnesses, list) and any(
            isinstance(w, dict) and "receipt" in w for w in witnesses):
        import nodes as nodes_mod  # local import: avoid hard cycle
        ok, msg, _ = nodes_mod.verify_block_receipts(block)
        return ok, msg
    if not isinstance(witnesses, list):
        return False, "no witnesses field"
    valid: set = set()
    for w in witnesses:
        if not isinstance(w, dict):
            return False, "malformed witness entry"
        cid = w.get("custodian_id")
        entry = custodians.get(cid)
        if entry is None:
            return False, f"unknown witness {cid!r}"
        try:
            sig = bytes.fromhex(w["signature_hex"])
            pk = bytes.fromhex(entry["dsa_pk_hex"])
        except Exception:
            return False, f"malformed witness key/signature for {cid!r}"
        if not pqc.dsa_verify(pk, proposal_hash(block), sig):
            return False, f"INVALID witness signature from {cid}"
        valid.add(cid)
    if len(valid) >= QUORUM:
        return True, f"quorum {len(valid)}-of-3 FINAL"
    return False, f"quorum NOT reached ({len(valid)}-of-3, need 2)"


def is_final(block: dict, custodians: dict | None = None) -> bool:
    custodians = store.load_custodians() if custodians is None else custodians
    ok, _ = verify_witnesses(block, custodians)
    return ok


def quorum_counts(chain: list) -> dict:
    """Summary for UI/status: {final, pending, total}."""
    final = sum(1 for b in chain
                if isinstance(b, dict) and b.get("status") == "FINAL")
    return {"final": final, "pending": len(chain) - final, "total": len(chain)}


def _update_checkpoint(chain: list) -> None:
    if not chain:
        return
    tip = chain[-1]
    store.advance_checkpoint_tip({"tip_hash": tip.get("block_hash"),
                                  "index": tip.get("index"),
                                  "status": tip.get("status", "UNKNOWN"),
                                  "updated_at": utcnow_iso()})
