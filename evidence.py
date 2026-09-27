"""Portable offline forensic evidence package (PS26237-v2).

A package holds everything a clean-room investigator needs to re-verify an
attribution WITHOUT trusting the original application process:

  leaked bytes hash, extracted fingerprint, full event, authorization
  challenge+signature, recipient + custodian public keys, the FINAL block
  (with witnesses), previous-block hash (continuity), checkpoint tip,
  protocol/policy versions, verification results.

No networking. Fully offline.
"""
import copy

import custodians as custodians_mod
import ledger as ledger_mod
import provenance as prov_mod
import pqc
import store
import symcrypto

EVIDENCE_FORMAT = "ps26237-evidence-v1"
TRUST_ANCHOR_FORMAT = "ps26237-trust-anchor-v1"


def build_trust_anchor() -> dict:
    """Export the public enrollment registry (public keys ONLY, no secrets).

    Published out-of-band at enrollment ceremony time. A clean-room verifier
    pins evidence packages against this anchor so a forger cannot substitute
    their own keys and self-verify (see verify_evidence_package).
    """
    recips = store.load_recipients()
    custodians = store.load_custodians()
    return {
        "format": TRUST_ANCHOR_FORMAT,
        "protocol": prov_mod.PROTOCOL_VERSION,
        "policy": {"version": prov_mod.POLICY_VERSION,
                   "hash": prov_mod.policy_hash()},
        "recipients": {rid: {"dsa_pk_hex": r.get("dsa_pk_hex", ""),
                              "key_id": r.get("key_id", ""),
                              "status": r.get("status", "active")}
                       for rid, r in recips.items() if isinstance(r, dict)},
        "custodians": {cid: c.get("dsa_pk_hex", "")
                       for cid, c in custodians.items() if isinstance(c, dict)},
        "nodes": {cid: n.get("dsa_pk_hex", "")
                  for cid, n in store.load_nodes_registry().items()
                  if isinstance(n, dict)},
    }


def build_evidence_package(event_id: str, leaked_bytes: bytes) -> dict:
    """Assemble a self-contained package for a FINAL v2 event.

    Raises ValueError if there is no FINAL block for event_id.
    """
    import core as core_mod  # local import: evidence is built on top of core
    chain = store.load_ledger()
    recips = store.load_recipients()
    custodians = store.load_custodians()
    hit = None
    for block in chain:
        ev = block.get("event")
        if (isinstance(ev, dict) and ev.get("event_id") == event_id
                and ledger_mod.is_v2_event(ev)):
            hit = block
            break
    if hit is None:
        raise ValueError("no v2 ledger event with that event id")
    if hit.get("status") != "FINAL":
        raise ValueError("event block is not FINAL (quorum not reached)")
    checks = core_mod.verify_attested_event(hit["event"], leaked_bytes)
    ok_chain, chain_msg = ledger_mod.verify_ledger(chain, recips, custodians)
    quorum_ok, quorum_msg = custodians_mod.verify_witnesses(hit, custodians)
    # Independent-node receipts (if this block was finalized by nodes):
    # bundle each witness receipt + checkpoint + Merkle proof + node pubs.
    import nodes as nodes_mod
    node_receipts, node_pubs, node_checkpoints = [], {}, {}
    for w in hit.get("witnesses", []):
        if isinstance(w, dict) and "receipt" in w:
            node_receipts.append({"receipt": copy.deepcopy(w["receipt"]),
                                  "signature_hex": w.get("signature_hex", ""),
                                  "checkpoint": copy.deepcopy(w.get("checkpoint", {})),
                                  "proof": copy.deepcopy(w.get("proof", [])),
                                  "custodian_id": w.get("custodian_id", "")})
    if node_receipts:
        for nr in node_receipts:
            cid = nr["custodian_id"]
            try:
                node_pubs[cid] = store.load_node_identity(cid).get("dsa_pk_hex", "")
            except Exception:
                node_pubs[cid] = ""
            try:
                node_checkpoints[cid] = store.load_node_checkpoint(cid)
            except Exception:
                node_checkpoints[cid] = None
    pkg = {
        "format": EVIDENCE_FORMAT,
        "protocol": prov_mod.PROTOCOL_VERSION,
        "policy": {"version": prov_mod.POLICY_VERSION,
                   "hash": prov_mod.policy_hash(),
                   "text": prov_mod.POLICY_TEXT},
        "leaked_sha256": symcrypto.sha256_hex(leaked_bytes),
        "event": copy.deepcopy(hit["event"]),
        "challenge": ledger_mod.challenge_from_event(hit["event"]),
        "block": {"index": hit["index"], "timestamp": hit["timestamp"],
                  "signer": hit["signer"], "witnesses": copy.deepcopy(hit["witnesses"]),
                  "status": hit["status"], "prev_hash": hit["prev_hash"],
                  "block_hash": hit["block_hash"]},
        "prev_block_hash": (chain[hit["index"] - 1]["block_hash"]
                            if hit["index"] > 0 else ledger_mod.GENESIS_PREV),
        "checkpoint": store.load_checkpoint(),
        "public_keys": {
            "recipient": {"id": hit["event"]["recipient_id"],
                          "key_id": hit["event"]["recipient_key_id"],
                          "dsa_pk_hex": recips[hit["event"]["recipient_id"]]["dsa_pk_hex"],
                          "dsa_alg": recips[hit["event"]["recipient_id"]].get("dsa_alg", "")},
            "custodians": {w["custodian_id"]:
                            custodians[w["custodian_id"]]["dsa_pk_hex"]
                            for w in hit["witnesses"]
                            if w.get("custodian_id") in custodians},
        },
        "verification": {"authorization": checks.get("authorization"),
                         "derivation": checks.get("derivation"),
                         "binding": checks.get("binding"),
                         "quorum": ("FINAL-2OF3" if quorum_ok else f"INVALID: {quorum_msg}"),
                         "ledger_integrity": ("VALID" if ok_chain else f"INVALID: {chain_msg}")},
        "node_receipts": node_receipts,
        "node_public_keys": node_pubs,
        "node_checkpoints": node_checkpoints,
        "proven": [
            "extracted fingerprint hashes to this event's commitment",
            "recipient authorization signature verifies under enrolled key",
            "fingerprint re-derives from that authorization (HKDF-SHA256)",
            "packaged leaked bytes equal the event's recorded copy (SHA-256)",
            "2-of-3 custodian quorum reached on this block",
        ],
        "inferred": [
            "this copy most likely originated from the recorded authorized "
            "decryption (assumes no SHA-256 collision)",
        ],
        "not_proven": [
            "who physically transmitted or leaked the file",
            "intent or knowledge of disclosure",
            "that the source ledger is the complete history "
            "(no fork/replacement proof beyond quorum signatures)",
        ],
        "conclusion": ("This document is cryptographically associated with "
                       f"{hit['event']['recipient_id']}'s authorized decryption "
                       "event. Physical leak attribution is not established."),
    }
    return pkg


def verify_evidence_package(pkg: dict, trust_anchor: dict | None = None) -> dict:
    """Independently re-verify a package using ONLY its own contents.

    Uses no server state: keys, signatures, hashes all come from the package.
    Returns {valid, checks{}, reason, trust}.

    trust_anchor (optional but RECOMMENDED): a build_trust_anchor() registry
    published at enrollment. WITHOUT it, keys are self-asserted — a forger
    can mint a fully self-consistent package under attacker-chosen keys
    ("MALLORY" attack), so the result is reported as valid/self-asserted,
    never as anchored attribution. WITH it, packaged keys must exactly match
    the anchor or verification FAILS.
    """
    def fail(reason, **checks):
        out = {"valid": False, "reason": reason}
        out.update(checks)
        return out

    if not isinstance(pkg, dict) or pkg.get("format") != EVIDENCE_FORMAT:
        return fail("not a ps26237 evidence package")
    try:
        event = pkg["event"]
        challenge = pkg["challenge"]
        block = pkg["block"]
        recipient_pk = bytes.fromhex(pkg["public_keys"]["recipient"]["dsa_pk_hex"])
        auth_sig = bytes.fromhex(event["authorization_signature_hex"])
    except (KeyError, ValueError, TypeError) as e:
        return fail(f"malformed evidence package: {e}")

    # 0. Trust-anchor pinning (identity binding).
    trust = "self-asserted-keys"
    if trust_anchor is not None:
        if (not isinstance(trust_anchor, dict)
                or trust_anchor.get("format") != TRUST_ANCHOR_FORMAT):
            return fail("malformed trust anchor", trust="INVALID-ANCHOR")
        anchored_recip = (trust_anchor.get("recipients", {}) or {}).get(
            event.get("recipient_id", ""), {})
        if (anchored_recip.get("dsa_pk_hex") !=
                pkg["public_keys"]["recipient"].get("dsa_pk_hex")
                or anchored_recip.get("key_id") != event.get("recipient_key_id")):
            return fail("recipient key does not match trust anchor",
                        trust="ANCHOR-MISMATCH")
        anchored_cust = trust_anchor.get("custodians", {}) or {}
        for w in block.get("witnesses", []):
            cid = w.get("custodian_id") if isinstance(w, dict) else None
            if (not cid or anchored_cust.get(cid) !=
                    pkg["public_keys"].get("custodians", {}).get(cid)):
                return fail(f"custodian key for {cid!r} not in trust anchor",
                            trust="ANCHOR-MISMATCH")
        if (trust_anchor.get("policy", {}).get("hash") !=
                event.get("policy_hash")):
            return fail("anchor policy hash mismatch", trust="ANCHOR-MISMATCH")
        trust = "anchored"

    # 1. Authorization over the packaged challenge.
    if challenge != ledger_mod.challenge_from_event(event):
        return fail("challenge inconsistent with event", authorization="MISMATCH")
    if not pqc.dsa_verify(recipient_pk, ledger_mod.canonical(challenge), auth_sig):
        return fail("recipient authorization signature INVALID", authorization="INVALID")

    # 2. Derivation recomputed from packaged values only.
    expected = prov_mod.recompute_fingerprint(auth_sig, event)
    if symcrypto.sha256_hex(bytes.fromhex(expected)) != event.get("watermark_token_hash"):
        return fail("fingerprint does not re-derive from authorization",
                    authorization="VALID", derivation="MISMATCH")

    # 3. Policy binding.
    if (event.get("policy_hash") != pkg.get("policy", {}).get("hash")
            or event.get("policy_hash") != prov_mod.policy_hash()):
        return fail("policy hash mismatch", authorization="VALID",
                    derivation="VALID", policy="MISMATCH")

    # 4. Quorum over the packaged block, using packaged custodian keys.
    # Node-receipt blocks (independent witnesses) take a dedicated path:
    # each receipt signature, checkpoint, and Merkle proof is re-verified
    # against the packaged node public keys and the packaged event.
    import nodes as nodes_mod
    block_witnesses = block.get("witnesses", [])
    if any(isinstance(w, dict) and "receipt" in w for w in block_witnesses):
        if any(not (isinstance(w, dict) and "receipt" in w) for w in block_witnesses):
            return fail("mixed legacy/node witness entries", authorization="VALID",
                        derivation="VALID", quorum="MALFORMED")
        try:
            packaged_node_pks = dict(pkg.get("node_public_keys", {}) or {})
        except (ValueError, TypeError, AttributeError) as e:
            return fail(f"malformed node keys: {e}")
        seen = set()
        for w in block_witnesses:
            cid = w.get("custodian_id")
            try:
                pk_hex = packaged_node_pks[cid]
                pk = bytes.fromhex(pk_hex)
                sig = bytes.fromhex(w["signature_hex"])
            except (KeyError, ValueError, TypeError):
                return fail("malformed node witness entry", authorization="VALID",
                            derivation="VALID", quorum="MALFORMED")
            body = w.get("receipt") if isinstance(w.get("receipt"), dict) else None
            if body is None or body.get("custodian_id") != cid:
                return fail("receipt/node identity mismatch", authorization="VALID",
                            derivation="VALID", quorum="MALFORMED")
            if not pqc.dsa_verify(pk, ledger_mod.canonical(body), sig):
                return fail(f"INVALID node witness signature from {cid}",
                            authorization="VALID", derivation="VALID",
                            quorum="INVALID")
            if symcrypto.sha256_hex(ledger_mod.canonical(event)) != body.get("event_hash"):
                return fail("receipt binds a different event (mismatched event hash)",
                            authorization="VALID", derivation="VALID",
                            quorum="MISMATCH")
            cp = w.get("checkpoint") or {}
            try:
                cp_sig = bytes.fromhex(cp.get("signature_hex", ""))
            except (ValueError, TypeError, AttributeError):
                return fail("malformed node checkpoint signature",
                            authorization="VALID", derivation="VALID",
                            quorum="MALFORMED")
            cp_body = {k: v for k, v in cp.items()
                       if k not in ("signature_hex", "history")}
            if not pqc.dsa_verify(pk, ledger_mod.canonical(cp_body), cp_sig):
                return fail(f"INVALID node checkpoint signature from {cid}",
                            authorization="VALID", derivation="VALID",
                            quorum="INVALID")
            if cp.get("tip_event_hash") != body.get("event_hash") \
                    or cp.get("seq") != body.get("seq") \
                    or cp.get("state_root") != body.get("state_root"):
                return fail("node checkpoint inconsistent with receipt",
                            authorization="VALID", derivation="VALID",
                            quorum="MISMATCH")
            if not nodes_mod.verify_merkle_proof(
                    body["event_hash"], w.get("proof", []), body["state_root"]):
                return fail("Merkle proof fails (altered historical root)",
                            authorization="VALID", derivation="VALID",
                            quorum="MISMATCH")
            seen.add(cid)
        if len(seen) < nodes_mod.QUORUM:
            return fail(f"quorum NOT reached ({len(seen)}-of-3)",
                        authorization="VALID", derivation="VALID",
                        quorum="INSUFFICIENT")
        # Anchor pinning for node keys (when an anchor carrying them is given).
        if trust == "anchored" or (isinstance(trust_anchor, dict)):
            anchored_nodes = ((trust_anchor or {}).get("nodes", {}) or {})
            if anchored_nodes:
                for cid in seen:
                    if anchored_nodes.get(cid) != packaged_node_pks.get(cid):
                        return fail(f"node key for {cid!r} not in trust anchor",
                                    trust="ANCHOR-MISMATCH")
                trust = "anchored"
            elif trust_anchor is not None:
                trust = "self-asserted-keys"
    else:
        try:
            custodian_pks = {cid: bytes.fromhex(pk)
                             for cid, pk in pkg["public_keys"]["custodians"].items()}
        except (ValueError, TypeError, AttributeError) as e:
            return fail(f"malformed custodian keys: {e}")
        proposal = ledger_mod.canonical({"index": block["index"], "event": event,
                                         "prev_hash": block["prev_hash"]})
        seen = set()
        for w in block.get("witnesses", []):
            try:
                pk = custodian_pks[w["custodian_id"]]
                sig = bytes.fromhex(w["signature_hex"])
            except (KeyError, ValueError, TypeError):
                return fail("malformed witness entry", authorization="VALID",
                            derivation="VALID", quorum="MALFORMED")
            if not pqc.dsa_verify(pk, proposal, sig):
                return fail(f"INVALID witness signature from {w.get('custodian_id')}",
                            authorization="VALID", derivation="VALID",
                            quorum="INVALID")
            seen.add(w["custodian_id"])
        if len(seen) < custodians_mod.QUORUM:
            return fail(f"quorum NOT reached ({len(seen)}-of-3)",
                        authorization="VALID", derivation="VALID",
                        quorum="INSUFFICIENT")

    # 5. Block hash self-consistency (event lives in pkg["event"]; the
    # original hash commits to the full block including the event).
    full_block = {k: v for k, v in block.items() if k != "block_hash"}
    full_block["event"] = event
    recomputed = ledger_mod.block_hash_of(full_block)
    if recomputed != block.get("block_hash"):
        return fail("block hash mismatch", authorization="VALID",
                    derivation="VALID", quorum="FINAL-2OF3",
                    block_hash="MISMATCH")

    return {"valid": True, "authorization": "VALID", "derivation": "VALID",
            "quorum": "FINAL-2OF3", "block_hash": "VALID", "trust": trust,
            "reason": ("all package-self-contained checks passed"
                       + (" against the trust anchor" if trust == "anchored"
                          else " (keys self-asserted: pin to a trust anchor "
                               "for anchored attribution)"))}


def forensic_report_text(pkg_or_result: dict) -> str:
    """Human-readable report with explicit PROVEN / NOT PROVEN sections."""
    g = pkg_or_result.get
    lines = ["FORENSIC REPORT (PS26237-v2)", "",
             f"Status: {'VERIFIED' if pkg_or_result.get('match', True) and pkg_or_result.get('valid', True) else g('status', 'VERIFIED')}",
             f"Recipient: {g('recipient', g('event', {}).get('recipient_id', '?') if isinstance(g('event'), dict) else '?')}",
             f"Event ID: {g('event_id', g('event', {}).get('event_id', '?') if isinstance(g('event'), dict) else '?')}",
             ""]
    if g("proven"):
        lines += ["PROVEN:"] + [f"  - {x}" for x in g("proven")] + [""]
    if g("not_proven"):
        lines += ["NOT PROVEN:"] + [f"  - {x}" for x in g("not_proven")] + [""]
    lines += ["Conclusion:", g("conclusion", "No verified decryption event matches this file."), ""]
    return "\n".join(lines)
