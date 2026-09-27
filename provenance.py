"""PS26237-v2 provenance: challenge canonicalization + HKDF-bound fingerprint.

No networking. Only local crypto (ML-DSA via pqc.py, HKDF-SHA256/SHA-256).

Protocol order (acyclic by construction):

  challenge C exists  ->  recipient signs S=ML-DSA(C)  ->  fp=HKDF(S,...)
  ->  H(fp) committed in event  ->  custodians witness event.

The recipient NEVER signs anything derived from its own signature.
"""
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import pqc

PROTOCOL_VERSION = "ps26237-v2"
POLICY_VERSION = "policy-v1"
# Human-readable policy whose SHA-256 is committed in every v2 challenge/event.
# Bumping the policy text requires bumping POLICY_VERSION.
POLICY_TEXT = (
    "PS26237-v2 policy-v1: recipient authorization is single-use and bound to "
    "one document hash + version; plaintext releases only after ML-DSA "
    "authorization verifies; provenance fingerprints derive via HKDF-SHA256 "
    "from the authorization signature; ledger blocks need 2-of-3 custodian "
    "witnesses; forensic reports attribute decryption events, never physical leaks."
)

CHALLENGE_TTL_SECONDS = 15 * 60

# Domain separation prefix for the HKDF info string (bytes, includes NUL).
_INFO_PREFIX = b"PS26237-v2/fp\x00"


def policy_hash() -> str:
    return hashlib.sha256(POLICY_TEXT.encode("utf-8")).hexdigest()


def key_id_for_dsa_pk(dsa_pk: bytes) -> str:
    """Short stable key identifier: first 16 hex chars of SHA-256(public key)."""
    return hashlib.sha256(bytes(dsa_pk)).hexdigest()[:16]


def hkdf_info(document_hash: str, document_version: str, recipient_key_id: str) -> bytes:
    """Domain-separated info binding fingerprint to document + version + key.

    Fixed layout (no ambiguous A||B||C): length-prefixed fields after prefix.
    """
    parts = []
    for field in (document_hash, document_version, recipient_key_id):
        raw = field.encode("utf-8")
        parts.append(len(raw).to_bytes(4, "big") + raw)
    return _INFO_PREFIX + b"".join(parts)


def derive_fingerprint(auth_signature: bytes, event_id_hex: str,
                       document_hash: str, document_version: str,
                       recipient_key_id: str) -> str:
    """Derive the 128-bit opaque fingerprint (32 hex chars).

    HKDF-SHA256(IKM=authorization signature, salt=event_id, info=bound context).
    Same 32-hex format as the legacy random token, so existing PDF/text
    carriers embed/extract it unchanged.
    """
    salt = bytes.fromhex(event_id_hex)  # 16 bytes, unique per event
    info = hkdf_info(document_hash, document_version, recipient_key_id)
    okm = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt,
               info=info).derive(bytes(auth_signature))
    return okm.hex()


def derivation_record(event_id_hex: str, document_hash: str,
                      document_version: str, recipient_key_id: str) -> dict:
    """Public derivation parameters stored in the event (no secrets)."""
    return {"kdf": "HKDF-SHA256", "length": 16,
            "salt_hex": event_id_hex,
            "info_hex": hkdf_info(document_hash, document_version,
                                  recipient_key_id).hex()}


def recompute_fingerprint(auth_signature: bytes, event: dict) -> str:
    """Re-derive the expected fingerprint from a stored v2 event's parameters."""
    return derive_fingerprint(auth_signature, event["event_id"],
                              event["document_hash"], event["document_version"],
                              event["recipient_key_id"])


def verify_authorization(dsa_pk: bytes, challenge: dict, signature: bytes) -> bool:
    """Verify a recipient authorization signature over the canonical challenge."""
    import ledger as ledger_mod  # local import: avoid hard cycle at import time
    return pqc.dsa_verify(bytes(dsa_pk), ledger_mod.canonical(challenge),
                          bytes(signature))
