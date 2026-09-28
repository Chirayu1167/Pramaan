"""MVP business logic: recipients, encrypt-once, decrypt+watermark+sign, investigate."""
import secrets
import threading
import uuid
from datetime import datetime, timezone

import custodians as custodians_mod
import latticemark as lattice_mod
import ledger as ledger_mod
import pqc
import provenance as prov_mod
import store
import symcrypto
import watermark
import watermark_text

DEMO_RECIPIENTS = ["RECIPIENT-A", "RECIPIENT-B", "RECIPIENT-C"]
MAX_PDF_BYTES = 15 * 1024 * 1024
# --- .txt/.md leaked-document support (additive; PDF path above is untouched) ---
TEXT_EXTENSIONS = (".txt", ".md")
MAX_TEXT_BYTES = 5 * 1024 * 1024

# Passphrase protecting private keys at rest (data/keys/, see store.py).
# This MVP's demo flows (CLI demo, web UI, tests) run fully offline and
# non-interactively, so they rely on this fixed default; any caller doing
# its own key custody should pass an explicit passphrase instead.
DEMO_PASSPHRASE = "ps26237-demo-passphrase"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_pdf(data: bytes, field: str = "file") -> None:
    if not data:
        raise ValueError(f"{field}: empty file")
    if len(data) > MAX_PDF_BYTES:
        raise ValueError(f"{field}: exceeds {MAX_PDF_BYTES} bytes")
    if not data.startswith(b"%PDF"):
        raise ValueError(f"{field}: not a PDF (missing %PDF magic)")


# ---- .txt/.md validation (mirrors validate_pdf's shape; additive) ----
def is_text_document(filename: str) -> bool:
    """True if filename names a plain-text/.md document — i.e. it should go
    through the dual-channel text watermark path instead of the PDF one."""
    return (filename or "").lower().endswith(TEXT_EXTENSIONS)


def validate_text(data: bytes, field: str = "file") -> None:
    if not data:
        raise ValueError(f"{field}: empty file")
    if len(data) > MAX_TEXT_BYTES:
        raise ValueError(f"{field}: exceeds {MAX_TEXT_BYTES} bytes")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{field}: not valid UTF-8 text") from e


def validate_document(data: bytes, filename: str, field: str = "file") -> None:
    """Dispatch to the PDF or text validator by filename extension."""
    if is_text_document(filename):
        validate_text(data, field)
    else:
        validate_pdf(data, field)


# ---- recipients ----
def init_demo_recipients(passphrase: str = DEMO_PASSPHRASE) -> dict:
    """Create the 3 demo recipients with fresh ML-KEM + ML-DSA keypairs.

    LEGACY v1 mode: establishes server-custodial keys. Refuses when v2
    attested identities exist (mixed modes would orphan trust assumptions);
    reset state first, or use init_attested_identities instead.
    """
    if store.load_ledger():
        raise ValueError(
            "ledger already holds signed events: re-initializing keys would orphan "
            "existing signatures. Run the full demo (which resets state) instead.")
    if store.recipient_vault_has_keys():
        raise ValueError(
            "v2 attested identities exist: legacy init would orphan the separated "
            "signing vault. Reset state first, or use the attested flow.")
    recips = store.load_recipients()
    for rid in DEMO_RECIPIENTS:
        kem_pk, kem_sk = pqc.kem_generate_keypair()
        dsa_pk, dsa_sk = pqc.dsa_generate_keypair()
        store.save_private_keys(rid, kem_sk, dsa_sk, passphrase)
        recips[rid] = {
            "kem_pk_hex": kem_pk.hex(),
            "dsa_pk_hex": dsa_pk.hex(),
            "kem_alg": pqc.KEM_ALGORITHM,
            "dsa_alg": pqc.DSA_ALGORITHM,
            "created_at": utcnow_iso(),
        }
    store.save_recipients(recips)
    return public_recipients()


def public_recipients() -> dict:
    """Recipients safe for the UI (public keys only — never private keys)."""
    return store.load_recipients()


# ---- encrypt once ----
# Encryption provenance ("common DB"): every encryption records the file
# fingerprint (SHA-256 of the plaintext) plus the encrypting PC's id in the
# shared encryption registry (store.ENCRYPTION_REGISTRY_FILE). Leak
# investigations read that registry to report when/which-PC sealed the file.
def encrypt_document(pdf_bytes: bytes, filename: str,
                     pc_id: str | None = None,
                     pc_label: str | None = None) -> dict:
    validate_document(pdf_bytes, filename)
    recips = store.load_recipients()
    if not recips:
        raise ValueError("no recipients enrolled — initialize recipients first")
    import device as device_mod
    device = device_mod.resolve_device(pc_id, pc_label)
    doc_key = symcrypto.random_bytes(32)
    doc_nonce, doc_ct = symcrypto.aesgcm_encrypt(doc_key, pdf_bytes)
    doc_hash = symcrypto.sha256_hex(pdf_bytes)
    doc_id = uuid.uuid4().hex
    envelopes = {}
    for rid, r in recips.items():
        kem_ct, ss = pqc.kem_encaps(bytes.fromhex(r["kem_pk_hex"]))
        wrap_nonce, wrapped = symcrypto.aesgcm_encrypt(ss, doc_key)
        envelopes[rid] = {
            "kem_ct_hex": kem_ct.hex(),
            "wrap_nonce_hex": wrap_nonce.hex(),
            "wrapped_key_hex": wrapped.hex(),
            "kem_alg": pqc.KEM_ALGORITHM,
        }
    ct_file = store.save_blob(f"{doc_id}.bin", doc_ct)
    created_at = utcnow_iso()
    docs = store.load_documents()
    docs[doc_id] = {
        "doc_id": doc_id,
        "filename": filename,
        "document_hash": doc_hash,
        "doc_nonce_hex": doc_nonce.hex(),
        "ciphertext_file": ct_file,
        "envelopes": envelopes,
        "created_at": created_at,
        # Origin snapshot so the document entry itself carries provenance
        # even if the shared registry file is ever unavailable.
        "origin_pc_id": device["pc_id"],
        "origin_pc_label": device.get("pc_label", ""),
        "origin_encrypted_at": created_at,
    }
    store.save_documents(docs)
    record = {
        "doc_id": doc_id,
        "filename": filename,
        "fingerprint": doc_hash,
        "document_hash": doc_hash,
        "pc_id": device["pc_id"],
        "pc_label": device.get("pc_label", ""),
        "encrypted_at": created_at,
        "file_size": len(pdf_bytes),
        "protocol": prov_mod.PROTOCOL_VERSION,
    }
    try:
        record = store.append_encryption_record(record)
    except Exception:
        pass  # provenance bookkeeping must never break encryption itself
    return {"doc_id": doc_id, "filename": filename, "document_hash": doc_hash,
            "fingerprint": doc_hash,
            "recipients": sorted(envelopes),
            "pc_id": record.get("pc_id", device["pc_id"]),
            "pc_label": record.get("pc_label", device.get("pc_label", "")),
            "encrypted_at": record.get("encrypted_at", created_at)}


# ---- decrypt + watermark + sign + ledger ----
def decrypt_for_recipient(doc_id: str, recipient_id: str, passphrase: str = DEMO_PASSPHRASE) -> dict:
    docs = store.load_documents()
    doc = docs.get(doc_id)
    if doc is None:
        raise ValueError("unknown document")
    if recipient_id not in doc["envelopes"]:
        raise ValueError("recipient has no access to this document")
    kem_sk, dsa_sk = store.load_private_keys(recipient_id, passphrase)
    env = doc["envelopes"][recipient_id]
    ss = pqc.kem_decaps(kem_sk, bytes.fromhex(env["kem_ct_hex"]))
    doc_key = symcrypto.aesgcm_decrypt(
        ss, bytes.fromhex(env["wrap_nonce_hex"]), bytes.fromhex(env["wrapped_key_hex"]))
    pdf_plain = symcrypto.aesgcm_decrypt(
        doc_key, bytes.fromhex(doc["doc_nonce_hex"]), store.load_blob(doc["ciphertext_file"]))

    chain = store.load_ledger()
    known_hashes = {b["event"].get("watermark_token_hash")
                    for b in chain if isinstance(b.get("event"), dict)}
    event_id = uuid.uuid4().hex
    # 128-bit opaque token, no identity inside; regenerate on the
    # astronomically unlikely event of a token-hash collision (dup prevention).
    for _ in range(10):
        token_hex = secrets.token_hex(16)
        token_hash = symcrypto.sha256_hex(bytes.fromhex(token_hex))
        if token_hash not in known_hashes:
            break
    else:
        raise RuntimeError("could not mint a fresh watermark token")

    # Same token generation/ledger/signing flow either way; only *which*
    # watermarking function embeds the token differs, chosen by the
    # document's own filename extension (set once, at encrypt_document time).
    text_mode = is_text_document(doc["filename"])
    if text_mode:
        watermarked = watermark_text.embed_text_watermark(
            pdf_plain.decode("utf-8"), token_hex).encode("utf-8")
    else:
        watermarked = watermark.embed_token(pdf_plain, token_hex)
        # Analog-hole layer: the same token as a near-invisible micro-dot
        # lattice, so screenshots/JPEG/resize/crop stay attributable.
        # Text extraction and visibility are unaffected (vector dots, no text).
        watermarked = lattice_mod.embed_lattice(watermarked, token_hex)

    event = {
        "event_id": event_id,
        "recipient_id": recipient_id,
        "document_id": doc_id,
        "document_hash": symcrypto.sha256_hex(pdf_plain),
        "watermark_token_hash": token_hash,
        "timestamp": utcnow_iso(),
    }
    if text_mode:
        # Additive field only: carries the visible canary channel's prefix
        # so investigate_leak can look up a "canary-only" match (invisible
        # channel stripped) without ever needing the full token. ledger.py's
        # append_event/verify_ledger only require REQUIRED_EVENT_FIELDS and
        # otherwise pass any event dict through untouched, so this extra
        # field is included in — and covered by — the same ML-DSA signature
        # as everything else in `event`; no change to ledger.py itself.
        event["watermark_canary_prefix"] = token_hex[:watermark_text.CANARY_PREFIX_LEN]
    sig = pqc.dsa_sign(dsa_sk, ledger_mod.canonical(event))
    block = ledger_mod.append_event(chain, event, sig.hex(), recipient_id)
    store.save_ledger(chain)
    # NOTE: store.save_copy always writes under a ".pdf" filename regardless
    # of content type (store.py is intentionally left unmodified, per scope).
    # The bytes themselves are correct either way; only the on-disk filename
    # extension is cosmetically PDF-shaped for a .txt/.md copy.
    store.save_copy(event_id, watermarked)
    return {"event_id": event_id, "recipient_id": recipient_id, "doc_id": doc_id,
            "document_hash": event["document_hash"],
            "watermark_token_hash": event["watermark_token_hash"],
            "timestamp": event["timestamp"], "block_index": block["index"],
            "signature_hex": sig.hex(), "pdf_bytes": watermarked,
            "is_text": text_mode}


# ---- .txt/.md leak investigation (additive; PDF branch below is untouched) ----
# ---- encryption provenance lookup ("common DB") ----
def lookup_encryption_provenance(doc_id=None, document_hash=None, leaked_bytes=None):
    """Resolve *when / which-PC* a file was encrypted."""
    rec = None
    if doc_id:
        try:
            rec = store.find_encryption_record(doc_id=doc_id)
        except Exception:
            rec = None
    if rec is None and document_hash:
        try:
            rec = store.find_encryption_record(fingerprint=document_hash)
        except Exception:
            rec = None
    if rec is None and leaked_bytes:
        try:
            rec = store.find_encryption_record(
                fingerprint=symcrypto.sha256_hex(bytes(leaked_bytes)))
        except Exception:
            rec = None
    if rec is None and doc_id:
        try:
            doc = store.load_documents().get(doc_id) or {}
            if doc.get("document_hash"):
                rec = {
                    "doc_id": doc_id,
                    "filename": doc.get("filename", ""),
                    "fingerprint": doc.get("document_hash", ""),
                    "document_hash": doc.get("document_hash", ""),
                    "pc_id": doc.get("origin_pc_id", ""),
                    "pc_label": doc.get("origin_pc_label", ""),
                    "encrypted_at": doc.get(
                        "origin_encrypted_at", doc.get("created_at", "")),
                    "file_size": 0,
                    "protocol": doc.get("protocol", ""),
                }
                if not rec["fingerprint"]:
                    rec = None
        except Exception:
            rec = None
    if rec is None:
        return {"found": False,
                "conclusion": "No encryption record matches this file."}
    return {"found": True,
            "doc_id": rec.get("doc_id", ""),
            "filename": rec.get("filename", ""),
            "fingerprint": rec.get("fingerprint",
                                   rec.get("document_hash", "")),
            "document_hash": rec.get("document_hash",
                                     rec.get("fingerprint", "")),
            "pc_id": rec.get("pc_id", ""),
            "pc_label": rec.get("pc_label", ""),
            "encrypted_at": rec.get("encrypted_at", ""),
            "file_size": rec.get("file_size", 0),
            "source": "common-db"}


def _attach_encryption(result, leaked_bytes=None):
    """Enrich any investigation result with its encryption provenance."""
    try:
        doc_id = result.get("document_id") or result.get("doc_id")
        doc_hash = result.get("document_hash")
        event_id = result.get("event_id")
        if (not doc_id or not doc_hash) and event_id:
            try:
                for block in store.load_ledger():
                    ev = block.get("event") if isinstance(block, dict) else None
                    if isinstance(ev, dict) and ev.get("event_id") == event_id:
                        doc_id = doc_id or ev.get("document_id")
                        doc_hash = doc_hash or ev.get("document_hash")
                        break
            except Exception:
                pass
        result["encryption"] = lookup_encryption_provenance(
            doc_id, doc_hash, leaked_bytes)
    except Exception:
        result["encryption"] = {"found": False,
                                "conclusion": "Encryption lookup unavailable."}
    return result


def _looks_like_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _investigate_leak_text_core(leaked_bytes: bytes) -> dict:
    """Investigate a leaked .txt/.md file. Checks both watermark channels
    independently and reports one of three cases explicitly:
      a) invisible channel matches the ledger -> normal VERIFIED result
      b) invisible channel missing but the visible canary prefix matches a
         ledger event -> still VERIFIED, but flagged "channel: canary-only"
      c) both channels missing -> honest NOT VERIFIED, with a note that this
         is consistent with deliberate stripping or manual retyping and
         cannot be distinguished from an unrelated file
    """
    validate_text(leaked_bytes, field="leaked file")
    text = leaked_bytes.decode("utf-8")
    extracted = watermark_text.extract_text_watermark(text)
    invisible_token = extracted["invisible"]
    canary_prefix = extracted["canary"]
    chain = store.load_ledger()
    recips = store.load_recipients()

    def find_hit(matches):
        for block in chain:
            ev = block.get("event")
            if isinstance(ev, dict) and matches(ev):
                return block
        return None

    def report_for_hit(hit, token_hash):
        # _v2_text_route: v2 (attested) blocks carry no v1 signature/signer
        # fields, so they must be verified by the binding-aware v2 path
        # (same routing the PDF path already does).
        if ledger_mod.is_v2_event(hit.get("event")):
            if invisible_token is None:
                return {"match": False, "status": "NOT VERIFIED",
                        "reason": ("visible canary marker matches a v2 event, but v2 "
                                   "attribution needs the invisible fingerprint to "
                                   "verify the authorization signature"),
                        "watermark": "CANARY-ONLY-UNVERIFIABLE",
                        "channel": "canary-only",
                        "recipient": hit["event"].get("recipient_id"),
                        "event_id": hit["event"].get("event_id"),
                        "conclusion": "No verified decryption event matches this file."}
            return investigate_leak_v2_core(leaked_bytes)
        # Same signature/ledger verification as the PDF path (see below),
        # applied here to a hit found via either text channel.
        try:
            signer_pk = bytes.fromhex(recips[hit["signer"]]["dsa_pk_hex"])
            sig = bytes.fromhex(hit["signature"])
        except (KeyError, ValueError, TypeError):
            return {"match": False, "status": "NOT VERIFIED",
                    "reason": "matching event references unknown/malformed signer key",
                    "watermark": "MATCHED-UNVERIFIABLE", "watermark_token_hash": token_hash,
                    "conclusion": "No verified decryption event matches this file."}
        ok_sig = pqc.dsa_verify(signer_pk, ledger_mod.canonical(hit["event"]), sig)
        ok_chain, chain_msg = ledger_mod.verify_ledger(chain, recips)
        verified = bool(ok_sig and ok_chain)
        recipient = hit["event"]["recipient_id"]
        if not verified:
            return {"match": False, "status": "NOT VERIFIED",
                    "reason": "event found but cryptographic verification failed",
                    "recipient": recipient, "event_id": hit["event"]["event_id"],
                    "watermark": "MATCHED",
                    "mldsa_signature": "VALID" if ok_sig else "INVALID",
                    "ledger_integrity": "VALID" if ok_chain else f"INVALID: {chain_msg}",
                    "conclusion": "No verified decryption event matches this file."}
        return {
            "match": True,
            "status": "VERIFIED",
            "recipient": recipient,
            "event_id": hit["event"]["event_id"],
            "document_hash": hit["event"]["document_hash"],
            "timestamp": hit["event"]["timestamp"],
            "block_index": hit["index"],
            "watermark": "MATCHED",
            "watermark_token_hash": token_hash,
            "mldsa_signature": "VALID",
            "ledger_integrity": "VALID",
            "ledger_detail": chain_msg,
            "conclusion": (f"This document is cryptographically associated with "
                           f"{recipient}'s authorized decryption event."),
            "scope": {
                "cryptographic_attribution":
                    (f"The leaked copy carries the watermark of {recipient}'s signed "
                     "decryption event (watermark match + valid ML-DSA signature + "
                     "intact ledger). Identifies the authorized decryption event "
                     "associated with the leaked copy; does not establish who "
                     "physically transmitted the leak."),
                "physical_attribution":
                    ("Not established. The system does not prove who physically "
                     "transmitted or leaked the file — only which authorized "
                     "decryption event this copy corresponds to."),
            },
            "note": ("This proves the leaked copy corresponds to that recipient's "
                     "signed decryption event; it does not cryptographically prove "
                     "who physically transmitted the leak."),
        }

    # --- case (a): invisible channel present -> normal VERIFIED path ---
    if invisible_token is not None:
        token_hash = symcrypto.sha256_hex(bytes.fromhex(invisible_token))
        hit = find_hit(lambda ev: ev.get("watermark_token_hash") == token_hash)
        if hit is None:
            return {"match": False, "status": "NOT VERIFIED",
                    "reason": "watermark extracted but no ledger event matches",
                    "watermark": "EXTRACTED-NO-MATCH", "watermark_token_hash": token_hash,
                    "conclusion": "No verified decryption event matches this file."}
        return report_for_hit(hit, token_hash)

    # --- case (b): invisible channel missing, canary prefix present ---
    if canary_prefix is not None:
        hit = find_hit(lambda ev: ev.get("watermark_canary_prefix") == canary_prefix)
        if hit is None:
            return {"match": False, "status": "NOT VERIFIED",
                    "reason": "canary marker extracted but no ledger event matches",
                    "watermark": "EXTRACTED-NO-MATCH", "channel": "canary-only",
                    "canary_prefix": canary_prefix,
                    "conclusion": "No verified decryption event matches this file."}
        token_hash = hit["event"].get("watermark_token_hash")
        result = report_for_hit(hit, token_hash)
        if result.get("match"):
            result["channel"] = "canary-only"
            result["note"] = ("invisible watermark missing or stripped; visible canary "
                               "marker intact")
        return result

    # --- case (c): both channels missing ---
    return {"match": False, "status": "NOT VERIFIED",
            "reason": "no watermark extracted from leaked file",
            "watermark": "NOT FOUND",
            "note": ("no watermark channels found; consistent with deliberate stripping "
                      "or manual retyping — cannot distinguish from an unrelated file"),
            "conclusion": "No verified decryption event matches this file."}


def _investigate_leak_text(leaked_bytes: bytes) -> dict:
    """Wrapper: core text investigation + encryption provenance."""
    return _attach_encryption(
        _investigate_leak_text_core(leaked_bytes), leaked_bytes)


# ---- leak investigation ----
def investigate_leak_core(pdf_bytes: bytes) -> dict:
    # Auto-detected by content: '%PDF' magic bytes keep going through the
    # original PDF path unchanged below; anything else that decodes as UTF-8
    # text is routed to the new dual-channel .txt/.md investigation instead
    # of being rejected outright (this is the only behavior change for
    # previously-unsupported input; real PDFs and non-UTF-8 binary garbage
    # both behave exactly as before).
    if not pdf_bytes.startswith(b"%PDF") and _looks_like_text(pdf_bytes):
        return _attach_encryption(_investigate_leak_text_core(pdf_bytes), pdf_bytes)
    validate_pdf(pdf_bytes, field="leaked file")
    token_hex = watermark.extract_token(pdf_bytes)
    if token_hex is None:
        return {"match": False, "status": "NOT VERIFIED",
                "reason": "no watermark extracted from leaked file",
                "watermark": "NOT FOUND",
                "conclusion": "No verified decryption event matches this file."}
    token_hash = symcrypto.sha256_hex(bytes.fromhex(token_hex))
    chain = store.load_ledger()
    recips = store.load_recipients()
    hit = None
    for block in chain:
        if isinstance(block.get("event"), dict) and \
                block["event"].get("watermark_token_hash") == token_hash:
            hit = block
            break
    if hit is not None and ledger_mod.is_v2_event(hit["event"]):
        # v2-signed events carry no v1 `signature` field: verify them with
        # the binding-aware v2 path (FINAL/quorum/binding) instead of
        # failing as "unverifiable" here.
        return investigate_leak_v2_core(pdf_bytes)
    if hit is None:
        return {"match": False, "status": "NOT VERIFIED",
                "reason": "watermark extracted but no ledger event matches",
                "watermark": "EXTRACTED-NO-MATCH", "watermark_token_hash": token_hash,
                "conclusion": "No verified decryption event matches this file."}
    # A damaged/foreign ledger entry must yield "no verified match", never an exception.
    try:
        signer_pk = bytes.fromhex(recips[hit["signer"]]["dsa_pk_hex"])
        sig = bytes.fromhex(hit["signature"])
    except (KeyError, ValueError, TypeError):
        return {"match": False, "status": "NOT VERIFIED",
                "reason": "matching event references unknown/malformed signer key",
                "watermark": "MATCHED-UNVERIFIABLE", "watermark_token_hash": token_hash,
                "conclusion": "No verified decryption event matches this file."}
    ok_sig = pqc.dsa_verify(signer_pk, ledger_mod.canonical(hit["event"]), sig)
    ok_chain, chain_msg = ledger_mod.verify_ledger(chain, recips)
    verified = bool(ok_sig and ok_chain)
    recipient = hit["event"]["recipient_id"]
    if not verified:
        return {"match": False, "status": "NOT VERIFIED",
                "reason": "event found but cryptographic verification failed",
                "recipient": recipient, "event_id": hit["event"]["event_id"],
                "watermark": "MATCHED",
                "mldsa_signature": "VALID" if ok_sig else "INVALID",
                "ledger_integrity": "VALID" if ok_chain else f"INVALID: {chain_msg}",
                "conclusion": "No verified decryption event matches this file."}
    return {
        "match": True,
        "status": "VERIFIED",
        "recipient": recipient,
        "event_id": hit["event"]["event_id"],
        "document_hash": hit["event"]["document_hash"],
        "timestamp": hit["event"]["timestamp"],
        "block_index": hit["index"],
        "watermark": "MATCHED",
        "watermark_token_hash": token_hash,
        "mldsa_signature": "VALID",
        "ledger_integrity": "VALID",
        "ledger_detail": chain_msg,
        "conclusion": (f"This document is cryptographically associated with "
                       f"{recipient}'s authorized decryption event."),
        "scope": {
            "cryptographic_attribution":
                (f"The leaked copy carries the watermark of {recipient}'s signed "
                 "decryption event (watermark match + valid ML-DSA signature + "
                 "intact ledger). Identifies the authorized decryption event "
                 "associated with the leaked copy; does not establish who "
                 "physically transmitted the leak."),
            "physical_attribution":
                ("Not established. The system does not prove who physically "
                 "transmitted or leaked the file — only which authorized "
                 "decryption event this copy corresponds to."),
        },
        "note": ("This proves the leaked copy corresponds to that recipient's "
                 "signed decryption event; it does not cryptographically prove "
                 "who physically transmitted the leak."),
    }


def investigate_leak(pdf_bytes: bytes) -> dict:
    """Leak investigation enriched with encryption provenance."""
    return _attach_encryption(investigate_leak_core(pdf_bytes), pdf_bytes)


# ============================================================
# PS26237-v2: recipient-attested, authorization-derived, quorum-witnessed
# ============================================================
# Trust boundary (auditable): NOTHING below imports recipient_client or reads
# store.RECIPIENT_VAULT_DIR / store.load_recipient_signing_key. The server
# receives authorization *signatures* and verifies them; it never holds the
# recipient signing key. test_attested.py statically enforces this.
#
# The legacy v1 flow above (decrypt_for_recipient) is preserved byte-for-byte
# for backward compatibility but is DEPRECATED: it signs *as* the recipient
# with a server-held key. Production deployments must disable it and delete
# legacy `*_dsa.sk` files after migrating to this section.

# Demo-only recipient signing passphrases. Used by demo/tests THROUGH
# recipient_client.authorize_challenge (the simulated recipient device), NEVER
# by the server functions in this module. Production: each recipient holds
# their own secret on their own device.
RECIPIENT_SIGN_PASSPHRASES = {
    "RECIPIENT-A": "ps26237-recipient-A-sign",
    "RECIPIENT-B": "ps26237-recipient-B-sign",
    "RECIPIENT-C": "ps26237-recipient-C-sign",
}

DOCUMENT_VERSION_DEFAULT = "v1"

# Serializes attested completions within this process: the nonce
# check-and-consume must be atomic, otherwise two concurrent requests with the
# same authorization could both pass verification and double-release.
# (Cross-process races are out of scope for the single-process demo server;
# production needs a transactional session store.)
_COMPLETE_LOCK = threading.Lock()


def _attested_recipient_entry(recipient_id: str) -> dict:
    recips = store.load_recipients()
    entry = recips.get(recipient_id)
    if entry is None:
        raise ValueError(f"unknown recipient {recipient_id!r}")
    if entry.get("status", "active") != "active":
        raise ValueError(f"recipient {recipient_id!r} is revoked")
    if "dsa_pk_hex" not in entry:
        raise ValueError(f"recipient {recipient_id!r} has no enrolled signing key")
    return entry


def init_attested_identities(server_passphrase: str = DEMO_PASSPHRASE,
                             recipient_passphrases: dict | None = None) -> dict:
    """Enroll fresh recipient identities for the v2 attested flow.

    Fresh ML-KEM + ML-DSA keypairs per recipient. KEM decapsulation keys go to
    the server vault; DSA signing keys go ONLY to the separated recipient
    vault (no legacy custodial DSA copy is written). Also initializes the
    2-of-3 custodian quorum. Refuses when the ledger already holds events.
    """
    if store.load_ledger():
        raise ValueError(
            "ledger already holds events: re-initializing keys would orphan "
            "existing signatures. Reset state first.")
    # Establishing v2 mode: remove any legacy server-readable DSA copies so
    # the separated vault is the ONLY place signing keys exist afterwards.
    store.clear_legacy_signing_copies()
    recipient_passphrases = (dict(RECIPIENT_SIGN_PASSPHRASES)
                             if recipient_passphrases is None
                             else dict(recipient_passphrases))
    custodians_mod.init_custodians()
    recips = store.load_recipients()
    for rid in DEMO_RECIPIENTS:
        kem_pk, kem_sk = pqc.kem_generate_keypair()
        dsa_pk, dsa_sk = pqc.dsa_generate_keypair()
        store.save_server_kem_key(rid, kem_sk, server_passphrase)
        store.save_recipient_signing_key(
            rid, dsa_sk, recipient_passphrases[rid])
        recips[rid] = {
            "kem_pk_hex": kem_pk.hex(),
            "dsa_pk_hex": dsa_pk.hex(),
            "key_id": prov_mod.key_id_for_dsa_pk(dsa_pk),
            "kem_alg": pqc.KEM_ALGORITHM,
            "dsa_alg": pqc.DSA_ALGORITHM,
            "status": "active",
            "created_at": utcnow_iso(),
            "protocol": prov_mod.PROTOCOL_VERSION,
        }
    store.save_recipients(recips)
    store.save_sessions({"pending": {}, "used": {}})
    return public_recipients()


def create_decrypt_challenge(doc_id: str, recipient_id: str) -> dict:
    """Server step 1: mint a fresh single-use authorization challenge.

    The challenge must be signed by the recipient device (recipient_client)
    and returned to complete_attested_decryption. Rejects revoked recipients
    and unknown documents up front.
    """
    docs = store.load_documents()
    doc = docs.get(doc_id)
    if doc is None:
        raise ValueError("unknown document")
    if recipient_id not in doc["envelopes"]:
        raise ValueError("recipient has no access to this document")
    entry = _attested_recipient_entry(recipient_id)
    challenge = {
        "protocol": prov_mod.PROTOCOL_VERSION,
        "event_id": uuid.uuid4().hex,
        "doc_id": doc_id,
        "document_hash": doc["document_hash"],
        "document_version": doc.get("document_version",
                                    DOCUMENT_VERSION_DEFAULT),
        "recipient_id": recipient_id,
        "recipient_key_id": entry.get(
            "key_id", prov_mod.key_id_for_dsa_pk(
                bytes.fromhex(entry["dsa_pk_hex"]))),
        "session_nonce": secrets.token_hex(16),
        "policy_hash": prov_mod.policy_hash(),
        "policy_version": prov_mod.POLICY_VERSION,
        "issued_at": utcnow_iso(),
    }
    sess = store.load_sessions()
    sess["pending"][challenge["session_nonce"]] = challenge
    store.save_sessions(sess)
    return challenge


def _challenge_age_seconds(challenge: dict) -> float:
    try:
        issued = datetime.fromisoformat(challenge["issued_at"])
        now = datetime.now(timezone.utc)
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
        return (now - issued).total_seconds()
    except Exception:
        return float("inf")


def complete_attested_decryption(challenge: dict, auth_signature_hex: str,
                                 server_passphrase: str = DEMO_PASSPHRASE) -> dict:
    """Server step 2: verify recipient authorization, THEN release plaintext.

    Verifies (in order): challenge shape, single-use nonce (pending, unused,
    unexpired), recipient active, key/policy/document binding, ML-DSA
    authorization signature. Only then decapsulates, derives the HKDF-bound
    fingerprint, embeds it, and proposes a PENDING ledger block (needs 2-of-3
    witnesses to become FINAL).
    """
    if not isinstance(challenge, dict) or not isinstance(auth_signature_hex, str):
        raise ValueError("challenge and auth_signature_hex are required")
    for field in ("protocol", "event_id", "doc_id", "document_hash",
                  "document_version", "recipient_id", "recipient_key_id",
                  "session_nonce", "policy_hash", "policy_version", "issued_at"):
        if not isinstance(challenge.get(field), str):
            raise ValueError(f"challenge missing/invalid field {field!r}")
    if challenge.get("protocol") != prov_mod.PROTOCOL_VERSION:
        raise ValueError("unsupported challenge protocol")
    try:
        auth_sig = bytes.fromhex(auth_signature_hex)
    except ValueError as e:
        raise ValueError("malformed authorization signature") from e

    sess = store.load_sessions()
    nonce = challenge["session_nonce"]
    pending = sess["pending"].get(nonce)
    if pending is None or pending != challenge:
        raise ValueError("unknown or already-consumed session nonce (replay rejected)")
    if nonce in sess["used"]:
        raise ValueError("session nonce already used (replay rejected)")
    if _challenge_age_seconds(challenge) > prov_mod.CHALLENGE_TTL_SECONDS:
        raise ValueError("challenge expired")

    entry = _attested_recipient_entry(challenge["recipient_id"])
    expected_key_id = entry.get("key_id") or prov_mod.key_id_for_dsa_pk(
        bytes.fromhex(entry["dsa_pk_hex"]))
    if challenge["recipient_key_id"] != expected_key_id:
        raise ValueError("challenge key id does not match enrolled signing key")
    if (challenge["policy_hash"] != prov_mod.policy_hash()
            or challenge["policy_version"] != prov_mod.POLICY_VERSION):
        raise ValueError("challenge policy mismatch")

    docs = store.load_documents()
    doc = docs.get(challenge["doc_id"])
    if doc is None:
        raise ValueError("unknown document")
    if challenge["recipient_id"] not in doc["envelopes"]:
        raise ValueError("recipient has no access to this document")
    if challenge["document_hash"] != doc["document_hash"]:
        raise ValueError("challenge document hash mismatch")
    if challenge["document_version"] != doc.get("document_version",
                                                DOCUMENT_VERSION_DEFAULT):
        raise ValueError("challenge document version mismatch")

    signer_pk = bytes.fromhex(entry["dsa_pk_hex"])
    if not pqc.dsa_verify(signer_pk, ledger_mod.canonical(challenge), auth_sig):
        raise ValueError("invalid recipient authorization signature")

    # Authorization verified: consume the nonce BEFORE release (single-use),
    # atomically within this process (see _COMPLETE_LOCK).
    with _COMPLETE_LOCK:
        sess = store.load_sessions()
        if sess["pending"].get(nonce) != challenge or nonce in sess["used"]:
            raise ValueError("unknown or already-consumed session nonce (replay rejected)")
        del sess["pending"][nonce]
        sess["used"][nonce] = challenge["event_id"]
        store.save_sessions(sess)

    kem_sk = store.load_server_kem_key(challenge["recipient_id"],
                                       server_passphrase)
    env = doc["envelopes"][challenge["recipient_id"]]
    ss = pqc.kem_decaps(kem_sk, bytes.fromhex(env["kem_ct_hex"]))
    doc_key = symcrypto.aesgcm_decrypt(
        ss, bytes.fromhex(env["wrap_nonce_hex"]),
        bytes.fromhex(env["wrapped_key_hex"]))
    plain = symcrypto.aesgcm_decrypt(
        doc_key, bytes.fromhex(doc["doc_nonce_hex"]),
        store.load_blob(doc["ciphertext_file"]))

    event_id = challenge["event_id"]
    token_hex = prov_mod.derive_fingerprint(
        auth_sig, event_id, doc["document_hash"],
        doc.get("document_version", DOCUMENT_VERSION_DEFAULT),
        expected_key_id)
    token_hash = symcrypto.sha256_hex(bytes.fromhex(token_hex))
    chain = store.load_ledger()
    if any(isinstance(b.get("event"), dict)
           and b["event"].get("watermark_token_hash") == token_hash
           for b in chain):
        raise ValueError("fingerprint commitment already on ledger")

    text_mode = is_text_document(doc["filename"])
    if text_mode:
        watermarked = watermark_text.embed_text_watermark(
            plain.decode("utf-8"), token_hex).encode("utf-8")
    else:
        watermarked = watermark.embed_token(plain, token_hex)
        # Analog-hole layer (see v1 path note above).
        watermarked = lattice_mod.embed_lattice(watermarked, token_hex)

    event = {
        "event_id": event_id,
        "recipient_id": challenge["recipient_id"],
        "recipient_key_id": expected_key_id,
        "document_id": challenge["doc_id"],
        "document_hash": doc["document_hash"],
        "document_version": doc.get("document_version",
                                    DOCUMENT_VERSION_DEFAULT),
        "watermark_token_hash": token_hash,
        "copy_hash": symcrypto.sha256_hex(watermarked),
        "session_nonce": nonce,
        "policy_hash": challenge["policy_hash"],
        "policy_version": challenge["policy_version"],
        "protocol_version": prov_mod.PROTOCOL_VERSION,
        "authorization_signature_hex": auth_sig.hex(),
        "challenge_issued_at": challenge["issued_at"],
        "derivation": prov_mod.derivation_record(
            event_id, doc["document_hash"],
            doc.get("document_version", DOCUMENT_VERSION_DEFAULT),
            expected_key_id),
        "timestamp": utcnow_iso(),
    }
    if text_mode:
        event["watermark_canary_prefix"] = token_hex[:watermark_text.CANARY_PREFIX_LEN]
    block = ledger_mod.propose_event(chain, event)
    store.save_ledger(chain)
    store.save_copy(event_id, watermarked)
    return {"event_id": event_id, "recipient_id": event["recipient_id"],
            "doc_id": event["document_id"],
            "document_hash": event["document_hash"],
            "watermark_token_hash": token_hash,
            "copy_hash": event["copy_hash"],
            "timestamp": event["timestamp"],
            "block_index": block["index"], "status": block["status"],
            "pdf_bytes": watermarked, "is_text": text_mode}


def verify_attested_event(event: dict, leaked_bytes: bytes) -> dict:
    """Forensic re-verification of one v2 event against leaked bytes.

    Checks: (1) recipient authorization signature over the reconstructed
    challenge, (2) HKDF fingerprint re-derivation matches the commitment,
    (3) leaked-bytes binding (SHA-256 == copy_hash). Quorum/chain are checked
    by the caller at block level.
    """
    recips = store.load_recipients()
    entry = recips.get(event.get("recipient_id", ""))
    if entry is None:
        return {"ok": False, "reason": "unknown recipient",
                "authorization": "UNKNOWN", "derivation": "UNKNOWN",
                "binding": "UNKNOWN"}
    try:
        challenge = ledger_mod.challenge_from_event(event)
        auth_sig = bytes.fromhex(event["authorization_signature_hex"])
        signer_pk = bytes.fromhex(entry["dsa_pk_hex"])
    except (KeyError, ValueError, TypeError):
        return {"ok": False, "reason": "malformed v2 authorization fields",
                "authorization": "MALFORMED", "derivation": "UNKNOWN",
                "binding": "UNKNOWN"}
    if not pqc.dsa_verify(signer_pk, ledger_mod.canonical(challenge), auth_sig):
        return {"ok": False, "reason": "invalid recipient authorization signature",
                "authorization": "INVALID", "derivation": "NOT CHECKED",
                "binding": "NOT CHECKED"}
    expected = prov_mod.recompute_fingerprint(auth_sig, event)
    expected_hash = symcrypto.sha256_hex(bytes.fromhex(expected))
    if expected_hash != event.get("watermark_token_hash"):
        return {"ok": True, "authorization": "VALID", "derivation": "MISMATCH",
                "binding": "NOT CHECKED", "ok": False,
                "reason": "fingerprint does not re-derive from authorization"}
    if symcrypto.sha256_hex(leaked_bytes) != event.get("copy_hash"):
        return {"ok": False, "authorization": "VALID", "derivation": "VALID",
                "binding": "MISMATCH",
                "reason": ("fingerprint matches an authorized event but the "
                           "leaked bytes do not equal that event's copy "
                           "(transplant or modification)")}
    return {"ok": True, "authorization": "VALID", "derivation": "VALID",
            "binding": "VALID", "reason": ""}


def _extract_v2_token(leaked_bytes: bytes) -> tuple[str | None, bool]:
    """Extract the fingerprint hex. Returns (token_or_None, is_text)."""
    if not leaked_bytes.startswith(b"%PDF") and _looks_like_text(leaked_bytes):
        text = leaked_bytes.decode("utf-8")
        return watermark_text.extract_token_invisible(text), True
    validate_pdf(leaked_bytes, field="leaked file")
    return watermark.extract_token(leaked_bytes), False


def investigate_leak_v2_core(leaked_bytes: bytes) -> dict:
    """v2 forensic investigation: binding-aware, FINAL-blocks only.

    Never throws on adversarial bytes: unparseable input yields NOT VERIFIED.
    """
    try:
        token_hex, _ = _extract_v2_token(leaked_bytes)
    except Exception:
        return {"match": False, "status": "NOT VERIFIED", "protocol": "ps26237-v2",
                "reason": "leaked file could not be parsed for watermark extraction",
                "watermark": "UNREADABLE",
                "conclusion": "No verified decryption event matches this file."}
    if token_hex is None:
        return {"match": False, "status": "NOT VERIFIED", "protocol": "ps26237-v2",
                "reason": "no watermark extracted from leaked file",
                "watermark": "NOT FOUND",
                "conclusion": "No verified decryption event matches this file."}
    token_hash = symcrypto.sha256_hex(bytes.fromhex(token_hex))
    chain = store.load_ledger()
    recips = store.load_recipients()
    custodians = store.load_custodians()
    candidate = pending_only = None
    for block in chain:
        ev = block.get("event")
        if (isinstance(ev, dict) and ledger_mod.is_v2_event(ev)
                and ev.get("watermark_token_hash") == token_hash):
            if block.get("status") == "FINAL":
                candidate = block
                break
            pending_only = pending_only or block
    if candidate is None:
        if pending_only is not None:
            return {"match": False, "status": "NOT VERIFIED", "protocol": "ps26237-v2",
                    "reason": "fingerprint matches a PENDING proposal "
                              "(quorum not reached: needs 2-of-3 witnesses)",
                    "watermark": "MATCHED-PENDING",
                    "event_id": pending_only["event"]["event_id"],
                    "conclusion": "No verified decryption event matches this file."}
        return {"match": False, "status": "NOT VERIFIED", "protocol": "ps26237-v2",
                "reason": "watermark extracted but no ledger event matches",
                "watermark": "EXTRACTED-NO-MATCH",
                "watermark_token_hash": token_hash,
                "conclusion": "No verified decryption event matches this file."}
    ev = candidate["event"]
    checks = verify_attested_event(ev, leaked_bytes)
    ok_chain, chain_msg = ledger_mod.verify_ledger(chain, recips, custodians)
    quorum_ok, quorum_msg = custodians_mod.verify_witnesses(candidate, custodians)
    verified = bool(checks.get("ok") and ok_chain and quorum_ok)
    base = {
        "protocol": "ps26237-v2",
        "recipient": ev["recipient_id"],
        "event_id": ev["event_id"],
        "document_hash": ev["document_hash"],
        "timestamp": ev["timestamp"],
        "block_index": candidate["index"],
        "watermark": "MATCHED",
        "watermark_token_hash": token_hash,
        "authorization": checks.get("authorization", "UNKNOWN"),
        "derivation": checks.get("derivation", "UNKNOWN"),
        "binding": checks.get("binding", "UNKNOWN"),
        "quorum": ("FINAL-2OF3" if quorum_ok else f"INVALID: {quorum_msg}"),
        "ledger_integrity": "VALID" if ok_chain else f"INVALID: {chain_msg}",
    }
    if not verified:
        base.update({"match": False, "status": "NOT VERIFIED",
                     "reason": checks.get("reason")
                     or ("event found but cryptographic verification failed"
                         if checks.get("binding") != "MISMATCH"
                         else checks.get("reason")),
                     "conclusion": "No verified decryption event matches this file."})
        return base
    base.update({
        "match": True, "status": "VERIFIED",
        "conclusion": (f"This document is cryptographically associated with "
                       f"{ev['recipient_id']}'s authorized decryption event."),
        "proven": [
            "extracted fingerprint hashes to this event's commitment",
            "recipient authorization signature verifies under enrolled key",
            "fingerprint re-derives from that authorization (HKDF-SHA256)",
            "leaked bytes equal the event's recorded copy (SHA-256)",
            "2-of-3 custodian quorum reached on this block",
            "hash chain intact end to end",
        ],
        "inferred": [
            "this copy most likely originated from the recorded authorized "
            "decryption (assumes no copy-hash collision)",
        ],
        "not_proven": [
            "who physically transmitted or leaked the file",
            "intent or knowledge of disclosure",
            "that the presenter ledger is the complete history "
            "(no fork/replacement proof beyond quorum signatures)",
        ],
        "scope": {
            "cryptographic_attribution":
                (f"The leaked copy carries the provenance fingerprint of "
                 f"{ev['recipient_id']}'s authorized decryption event "
                 "(authorization VALID + derivation VALID + binding VALID + "
                 "quorum FINAL + intact ledger)."),
            "physical_attribution":
                ("Not established. The system does not prove who physically "
                 "transmitted or leaked the file — only which authorized "
                 "decryption event this copy corresponds to."),
        },
        "note": ("Authorized decryption event cryptographically verified. "
                 "Physical leak attribution is not established."),
    })
    return base


def investigate_leak_v2(leaked_bytes: bytes) -> dict:
    """v2 investigation enriched with encryption provenance."""
    return _attach_encryption(
        investigate_leak_v2_core(leaked_bytes), leaked_bytes)


# ---- screenshot / analog-hole leak investigation (LatticeMark pixels) ----
def investigate_screenshot(image_bytes: bytes) -> dict:
    """Attribute a screenshot/photo of a decrypted PDF page (analog hole).

    Pipeline: blind LatticeMark decode from pixels -> token hash -> ledger
    lookup (v1 events and FINAL v2 events) -> signature/chain/quorum
    verification. Byte-equality binding is SKIPPED BY DESIGN (a screenshot
    can never byte-match the PDF); the report says so explicitly and the
    verdict rests on fingerprint commitment + authorization + quorum instead.
    Never throws on adversarial bytes.
    """
    if not isinstance(image_bytes, (bytes, bytearray)) or not image_bytes:
        return {"match": False, "status": "NOT VERIFIED", "channel": "pixels",
                "reason": "empty upload",
                "watermark": "UNREADABLE",
                "conclusion": "No verified decryption event matches this file."}
    try:
        token_hex, diag = lattice_mod.extract_lattice_token(bytes(image_bytes))
    except Exception:
        return {"match": False, "status": "NOT VERIFIED", "channel": "pixels",
                "reason": "screenshot could not be decoded",
                "watermark": "UNREADABLE",
                "conclusion": "No verified decryption event matches this file."}
    if token_hex is None:
        stage = (diag or {}).get("stage", "decode-failed")
        return {"match": False, "status": "NOT VERIFIED", "channel": "pixels",
                "reason": f"no lattice mark decoded from pixels ({stage})",
                "watermark": "NOT FOUND",
                "conclusion": "No verified decryption event matches this file."}
    token_hash = symcrypto.sha256_hex(bytes.fromhex(token_hex))
    chain = store.load_ledger()
    recips = store.load_recipients()
    custodians = store.load_custodians()
    v1_hit = v2_hit = v2_pending = None
    for block in chain:
        ev = block.get("event") if isinstance(block, dict) else None
        if not isinstance(ev, dict):
            continue
        if ev.get("watermark_token_hash") != token_hash:
            continue
        if ledger_mod.is_v2_event(ev):
            if block.get("status") == "FINAL":
                v2_hit = v2_hit or block
            else:
                v2_pending = v2_pending or block
        else:
            v1_hit = v1_hit or block
    result = None
    if v2_hit is not None:
        ev = v2_hit["event"]
        checks = verify_attested_event(ev, b"")  # auth+derivation only; see below
        ok_chain, chain_msg = ledger_mod.verify_ledger(chain, recips, custodians)
        quorum_ok, quorum_msg = custodians_mod.verify_witnesses(v2_hit, custodians)
        auth_ok = checks.get("authorization") == "VALID"
        deriv_ok = checks.get("derivation") == "VALID"
        verified = bool(auth_ok and deriv_ok and ok_chain and quorum_ok)
        result = {
            "protocol": "ps26237-v2",
            "channel": "pixels-latticemark",
            "recipient": ev["recipient_id"],
            "event_id": ev["event_id"],
            "document_hash": ev["document_hash"],
            "timestamp": ev["timestamp"],
            "block_index": v2_hit["index"],
            "watermark": "MATCHED",
            "watermark_token_hash": token_hash,
            "authorization": checks.get("authorization", "UNKNOWN"),
            "derivation": checks.get("derivation", "UNKNOWN"),
            "binding": "ANALOG-HOLE",
            "quorum": ("FINAL-2OF3" if quorum_ok else f"INVALID: {quorum_msg}"),
            "ledger_integrity": "VALID" if ok_chain else f"INVALID: {chain_msg}",
            "lattice": {"tiles_voted": (diag or {}).get("winner_votes", 0),
                        "mean_header_agree": (diag or {}).get("mean_header_agree", 0)},
        }
        if not verified:
            result.update({"match": False, "status": "NOT VERIFIED",
                           "reason": "event found but cryptographic verification failed",
                           "conclusion": "No verified decryption event matches this file."})
        else:
            result.update({
                "match": True, "status": "VERIFIED",
                "conclusion": (f"This screenshot is cryptographically associated with "
                               f"{ev['recipient_id']}'s authorized decryption event."),
                "proven": [
                    "pixel lattice decodes to this event's fingerprint commitment",
                    "recipient authorization signature verifies under enrolled key",
                    "fingerprint re-derives from that authorization (HKDF-SHA256)",
                    "2-of-3 custodian quorum reached on this block",
                    "hash chain intact end to end",
                ],
                "binding_note": ("Byte-equality binding is not applicable: a screenshot "
                                 "never byte-matches the PDF by design. Attribution rests "
                                 "on the fingerprint commitment + authorization + quorum."),
                "not_proven": [
                    "pixel-exact copy equality (analog-hole copy)",
                    "who physically captured or transmitted the screenshot",
                ],
            })
    elif v1_hit is not None:
        ev = v1_hit["event"]
        try:
            signer_pk = bytes.fromhex(recips[v1_hit["signer"]]["dsa_pk_hex"])
            sig = bytes.fromhex(v1_hit["signature"])
            ok_sig = pqc.dsa_verify(signer_pk, ledger_mod.canonical(ev), sig)
        except (KeyError, ValueError, TypeError):
            ok_sig = False
        ok_chain, chain_msg = ledger_mod.verify_ledger(chain, recips)
        verified = bool(ok_sig and ok_chain)
        result = {
            "channel": "pixels-latticemark",
            "recipient": ev.get("recipient_id", v1_hit.get("signer", "")),
            "event_id": ev.get("event_id", ""),
            "document_hash": ev.get("document_hash", ""),
            "timestamp": ev.get("timestamp", v1_hit.get("timestamp", "")),
            "block_index": v1_hit.get("index", 0),
            "watermark": "MATCHED",
            "watermark_token_hash": token_hash,
            "mldsa_signature": "VALID" if ok_sig else "INVALID",
            "binding": "ANALOG-HOLE",
            "ledger_integrity": "VALID" if ok_chain else f"INVALID: {chain_msg}",
            "lattice": {"tiles_voted": (diag or {}).get("winner_votes", 0),
                        "mean_header_agree": (diag or {}).get("mean_header_agree", 0)},
        }
        if not verified:
            result.update({"match": False, "status": "NOT VERIFIED",
                           "reason": "event found but cryptographic verification failed",
                           "conclusion": "No verified decryption event matches this file."})
        else:
            result.update({
                "match": True, "status": "VERIFIED",
                "conclusion": ("This screenshot is cryptographically associated with "
                               f"{result['recipient']}'s authorized decryption event."),
                "binding_note": ("Byte-equality binding is not applicable: a screenshot "
                                 "never byte-matches the PDF by design."),
                "note": ("This proves the screenshot corresponds to that recipient's "
                         "signed decryption event; it does not cryptographically prove "
                         "who physically captured or transmitted it."),
            })
    elif v2_pending is not None:
        result = {"match": False, "status": "NOT VERIFIED", "protocol": "ps26237-v2",
                  "channel": "pixels-latticemark",
                  "reason": "fingerprint matches a PENDING proposal "
                            "(quorum not reached: needs 2-of-3 witnesses)",
                  "watermark": "MATCHED-PENDING",
                  "event_id": v2_pending["event"]["event_id"],
                  "conclusion": "No verified decryption event matches this file."}
    else:
        result = {"match": False, "status": "NOT VERIFIED", "channel": "pixels",
                  "reason": "pixel mark decoded but no ledger event matches",
                  "watermark": "EXTRACTED-NO-MATCH",
                  "watermark_token_hash": token_hash,
                  "conclusion": "No verified decryption event matches this file."}
    try:
        return _attach_encryption(result, None)
    except Exception:
        return result


def revoke_recipient(recipient_id: str, custodian_id: str,
                     custodian_passphrase: str) -> dict:
    """Revoke a recipient's future decryption authorization.

    Authority: one custodian witness key (loads only with the custodian's own
    passphrase). Revocation is checked at challenge creation AND completion.
    Historical events stay verifiable (keys are retained in the registry).
    """
    recips = store.load_recipients()
    entry = recips.get(recipient_id)
    if entry is None:
        raise ValueError(f"unknown recipient {recipient_id!r}")
    custodians = store.load_custodians()
    if custodian_id not in custodians:
        raise ValueError(f"unknown custodian {custodian_id!r}")
    # Possession of the custodian key = revocation authority.
    cust_sk = store.load_custodian_key(custodian_id, custodian_passphrase)
    record = {"action": "revoke", "recipient_id": recipient_id,
              "key_id": entry.get("key_id", ""),
              "revoked_by": custodian_id, "revoked_at": utcnow_iso(),
              "protocol": prov_mod.PROTOCOL_VERSION}
    sig = pqc.dsa_sign(cust_sk, ledger_mod.canonical(record))
    record["custodian_signature_hex"] = sig.hex()
    entry["status"] = "revoked"
    entry["revocation"] = record
    store.save_recipients(recips)
    # Drop any pending challenges for the revoked recipient.
    sess = store.load_sessions()
    sess["pending"] = {n: c for n, c in sess["pending"].items()
                       if c.get("recipient_id") != recipient_id}
    store.save_sessions(sess)
    return record