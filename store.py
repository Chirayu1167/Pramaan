"""Local JSON persistence. Private keys live here, never leave the server."""
import json
import os
import secrets
import threading

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import symcrypto

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
DOCS_DIR = os.path.join(DATA_DIR, "docs")
COPIES_DIR = os.path.join(DATA_DIR, "copies")
RECIPIENTS_FILE = os.path.join(DATA_DIR, "recipients.json")
DOCUMENTS_FILE = os.path.join(DATA_DIR, "documents.json")
LEDGER_FILE = os.path.join(DATA_DIR, "ledger.json")

# ---- PS26237-v2 attested-protocol stores (additive; legacy files above untouched) ----
# Custody model: the application/server vault (KEYS_DIR) holds ML-KEM decapsulation
# keys needed to release plaintext. Recipient ML-DSA signing keys live in a
# SEPARATE vault (RECIPIENT_VAULT_DIR) under per-recipient passphrases that the
# server flow never reads — only recipient_client.py touches that directory.
# Custodian witness keys live in CUSTODIAN_DIR under per-custodian passphrases.
# NOTE (honest simulation label): on this single-machine demo all vaults share
# one filesystem, so a root attacker could read everything. The code enforces
# the trust boundary at the API level (server functions take signatures, never
# signing keys/passphrases), and production must place these vaults on
# independent machines/trust domains. See README "Trust model".
RECIPIENT_VAULT_DIR = os.path.join(DATA_DIR, "recipient_vault")
CUSTODIAN_DIR = os.path.join(DATA_DIR, "custodians")
CUSTODIANS_FILE = os.path.join(DATA_DIR, "custodians.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
CHECKPOINT_FILE = os.path.join(DATA_DIR, "checkpoint.json")
# ---- encryption provenance "common DB" ----
# One shared registry recording, at ENCRYPT time, the file fingerprint
# (SHA-256 of the plaintext) plus the encrypting PC's id. Leak
# investigations read this registry to report when/where a file was sealed.
# Offline deployment: this JSON file IS the common DB (copy/sync it across
# PCs to share provenance); no network, no cloud.
ENCRYPTION_REGISTRY_FILE = os.path.join(DATA_DIR, "encryption_registry.json")

# ---- private-key-at-rest encryption: passphrase -> scrypt -> AES-256-GCM ----
SCRYPT_SALT_LEN = 16
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LEN = 32  # AES-256


def ensure_dirs() -> None:
    for d in (DATA_DIR, KEYS_DIR, DOCS_DIR, COPIES_DIR,
              RECIPIENT_VAULT_DIR, CUSTODIAN_DIR):
        os.makedirs(d, exist_ok=True)


def _load_json(path: str, default):
    # Bounded retry: on Windows a concurrent writer's os.replace can make a
    # reader briefly see a locked or torn file (PermissionError / truncated
    # JSON). Readers retry instead of surfacing transient I/O as data errors.
    import time as _time
    for _ in range(50):
        try:
            if not os.path.exists(path):
                return default
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (PermissionError, json.JSONDecodeError):
            _time.sleep(0.005)
            continue
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Process-wide writer lock: every read-modify-write guard below (append-only
# ledger, session consume, monotonic checkpoint) must be atomic within this
# process, otherwise concurrent writers interleave guard-read and write
# ("last writer wins", silently dropping a witness or a nonce consume).
# Cross-process races remain out of scope for the single-process demo server.
_WRITE_LOCK = threading.Lock()


def _save_json(path: str, obj) -> None:
    # Unique tmp name per process+thread: concurrent writers must never share
    # (or PermissionError-collide on, e.g. Windows) a tmp file. os.replace
    # keeps each individual save atomic; multi-step read-modify-write
    # sequences are guarded by callers (see core._COMPLETE_LOCK) or by
    # content guards (see _is_witness_finalization_only).
    # Bounded retry on Windows replace races: two threads replacing DIFFERENT
    # tmp files onto the SAME destination can collide transiently; the loser
    # retries instead of surfacing a raw PermissionError.
    import time as _time
    tmp = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    for attempt in range(50):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 49:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
            _time.sleep(0.005)
    try:
        os.remove(tmp)
    except OSError:
        pass


# ---- recipients: {id: {kem_pk_hex, dsa_pk_hex, created_at}} (NO private keys) ----
def load_recipients() -> dict:
    ensure_dirs()
    return _load_json(RECIPIENTS_FILE, {})


def save_recipients(recips: dict) -> None:
    ensure_dirs()
    _save_json(RECIPIENTS_FILE, recips)


def _vault_path(base: str, name: str) -> str:
    # Flat filenames only — no subdirectories, no traversal.
    if not name or "/" in name or "\\" in name or ".." in name:
        raise ValueError(f"invalid vault name {name!r}")
    return os.path.join(base, name + ".sk")


# ---- private keys (server-side only, never returned by any API) ----
# Encrypted at rest: passphrase -> scrypt -> 32-byte key -> AES-256-GCM
# (symmetric only, same primitive as symcrypto's document encryption). Each
# key file is self-describing (kdf params + salt + nonce + ciphertext), so
# it can be decrypted from the passphrase alone with no other external state.
def _derive_key_from_passphrase(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=SCRYPT_KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_key_blob(plaintext: bytes, passphrase: str) -> dict:
    salt = secrets.token_bytes(SCRYPT_SALT_LEN)
    key = _derive_key_from_passphrase(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    nonce, ct = symcrypto.aesgcm_encrypt(key, plaintext)
    return {
        "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt_hex": salt.hex(), "nonce_hex": nonce.hex(), "ciphertext_hex": ct.hex(),
    }


def _decrypt_key_blob(blob: dict, passphrase: str) -> bytes:
    try:
        salt = bytes.fromhex(blob["salt_hex"])
        nonce = bytes.fromhex(blob["nonce_hex"])
        ct = bytes.fromhex(blob["ciphertext_hex"])
        key = _derive_key_from_passphrase(passphrase, salt, blob["n"], blob["r"], blob["p"])
    except (KeyError, ValueError) as e:
        raise ValueError("corrupted private-key file") from e
    try:
        return symcrypto.aesgcm_decrypt(key, nonce, ct)
    except Exception as e:
        # AES-GCM auth failure means the passphrase was wrong (or the file
        # was tampered with) — either way, surface one clear error.
        raise ValueError("incorrect passphrase or corrupted private-key file") from e


def save_private_keys(recipient_id: str, kem_sk: bytes, dsa_sk: bytes, passphrase: str) -> None:
    if not passphrase:
        raise ValueError("passphrase is required to encrypt private keys")
    ensure_dirs()
    _save_json(_vault_path(KEYS_DIR, f"{recipient_id}_kem"),
               _encrypt_key_blob(kem_sk, passphrase))
    _save_json(_vault_path(KEYS_DIR, f"{recipient_id}_dsa"),
               _encrypt_key_blob(dsa_sk, passphrase))


def load_private_keys(recipient_id: str, passphrase: str) -> tuple[bytes, bytes]:
    if not passphrase:
        raise ValueError("passphrase is required to decrypt private keys")
    kem_blob = _load_json(_vault_path(KEYS_DIR, f"{recipient_id}_kem"), None)
    dsa_blob = _load_json(_vault_path(KEYS_DIR, f"{recipient_id}_dsa"), None)
    if kem_blob is None or dsa_blob is None:
        raise FileNotFoundError(f"no private keys stored for {recipient_id}")
    kem_sk = _decrypt_key_blob(kem_blob, passphrase)
    dsa_sk = _decrypt_key_blob(dsa_blob, passphrase)
    return kem_sk, dsa_sk


def load_server_kem_key(recipient_id: str, passphrase: str) -> bytes:
    """Load ONLY the server-held ML-KEM decapsulation key.

    The v2 attested server flow uses this (never the recipient signing key).
    In v2 mode no legacy DSA file exists, so load_private_keys() would fail —
    this accessor is the correct one for plaintext release.
    """
    if not passphrase:
        raise ValueError("passphrase is required to decrypt server key")
    kem_blob = _load_json(_vault_path(KEYS_DIR, f"{recipient_id}_kem"), None)
    if kem_blob is None:
        raise FileNotFoundError(f"no server key stored for {recipient_id}")
    return _decrypt_key_blob(kem_blob, passphrase)


def save_server_kem_key(recipient_id: str, kem_sk: bytes, passphrase: str) -> None:
    """Store ONLY the server-held ML-KEM key (v2 mode: no custodial DSA copy)."""
    if not passphrase:
        raise ValueError("passphrase is required to encrypt server key")
    ensure_dirs()
    _save_json(_vault_path(KEYS_DIR, f"{recipient_id}_kem"),
               _encrypt_key_blob(kem_sk, passphrase))


# ---- documents: {doc_id: {filename, document_hash, doc_nonce_hex,
#                           doc_ciphertext_file, envelopes: {recip: {kem_ct_hex,
#                           wrap_nonce_hex, wrapped_key_hex}}, created_at}} ----
def load_documents() -> dict:
    ensure_dirs()
    return _load_json(DOCUMENTS_FILE, {})


def save_documents(docs: dict) -> None:
    ensure_dirs()
    _save_json(DOCUMENTS_FILE, docs)


def save_blob(filename: str, data: bytes) -> str:
    """Save bytes under DOCS_DIR, return the stored filename."""
    ensure_dirs()
    safe_name = os.path.basename(filename)
    if not safe_name or safe_name in (".", ".."):
        raise ValueError("invalid blob filename")
    path = os.path.join(DOCS_DIR, safe_name)
    with open(path, "wb") as f:
        f.write(data)
    return safe_name


def load_blob(filename: str) -> bytes:
    safe_name = os.path.basename(filename)
    path = os.path.join(DOCS_DIR, safe_name)
    with open(path, "rb") as f:
        return f.read()


# ---- watermarked copies: data/copies/<event_id>.pdf ----
def save_copy(event_id: str, data: bytes) -> None:
    ensure_dirs()
    safe_id = os.path.basename(event_id)
    with open(os.path.join(COPIES_DIR, f"{safe_id}.pdf"), "wb") as f:
        f.write(data)


def load_copy(event_id: str) -> bytes:
    safe_id = os.path.basename(event_id)
    with open(os.path.join(COPIES_DIR, f"{safe_id}.pdf"), "rb") as f:
        return f.read()


# ---- ledger ----
# The ledger file is append-only through this API: a save must extend the
# stored chain (same prefix), never rewrite or truncate history. Full resets
# happen only by deleting data/ (demo/test reset path). Note this guards the
# application path; OS-level file protection is out of scope — tampering is
# *detected* by ledger.verify_ledger(), not prevented here.
def load_ledger() -> list:
    ensure_dirs()
    return _load_json(LEDGER_FILE, [])


def save_ledger(chain: list) -> None:
    ensure_dirs()
    if not isinstance(chain, list):
        raise ValueError("ledger chain must be a list")
    with _WRITE_LOCK:
        stored = _load_json(LEDGER_FILE, [])
        if stored:
            if len(chain) < len(stored) or chain[:len(stored)] != stored:
                # v2 witness finalization is the ONLY allowed in-place update:
                # same length, identical events/linkage, witnesses only grow.
                if not _is_witness_finalization_only(stored, chain):
                    raise ValueError(
                        "ledger is append-only: refusing to rewrite or truncate stored history")
        _save_json(LEDGER_FILE, chain)


def _is_witness_finalization_only(stored: list, chain: list) -> bool:
    """True iff chain == stored except v2 blocks gained witness entries.

    Events, signers, linkage and length must be identical. v1 blocks must be
    byte-identical (never updatable); v2 blocks' witness lists may only grow
    (never shrink or mutate in place). At least one v2 block must actually
    gain a witness (callers only reach here when chain != stored).
    """
    if len(chain) != len(stored):
        return False
    grew = False
    for old, new in zip(stored, chain):
        if not isinstance(old, dict) or not isinstance(new, dict):
            return False
        for key in ("index", "event", "signer", "prev_hash", "timestamp"):
            if old.get(key) != new.get(key):
                return False
        if "witnesses" not in new:
            if old != new:
                return False  # v1 blocks are never updatable
            continue
        old_w, new_w = old.get("witnesses", []), new.get("witnesses", [])
        if not isinstance(old_w, list) or not isinstance(new_w, list):
            return False
        if len(new_w) < len(old_w) or new_w[:len(old_w)] != old_w:
            return False
        if len(new_w) > len(old_w):
            grew = True
        if new.get("status") not in ("PENDING", "FINAL"):
            return False
    # A status flip without any new witness is NOT a finalization: refuse,
    # so the API cannot be used to mark blocks FINAL without quorum.
    return grew


# ============================================================
# PS26237-v2: separated custody vaults, sessions, custodians
# ============================================================

def _vault_path(base: str, name: str) -> str:
    # Flat filenames only — no subdirectories, no traversal.
    if not name or "/" in name or "\\" in name or ".." in name:
        raise ValueError(f"invalid vault name {name!r}")
    return os.path.join(base, name + ".sk")


# ---- recipient signing vault (DSA only; server flow must NOT call these) ----
def save_recipient_signing_key(recipient_id: str, dsa_sk: bytes, passphrase: str) -> None:
    """Store a recipient's ML-DSA private key in the separated recipient vault."""
    if not passphrase:
        raise ValueError("passphrase is required to encrypt recipient signing key")
    ensure_dirs()
    _save_json(_vault_path(RECIPIENT_VAULT_DIR, f"{recipient_id}_dsa"),
               _encrypt_key_blob(dsa_sk, passphrase))


def load_recipient_signing_key(recipient_id: str, passphrase: str) -> bytes:
    """Load a recipient's ML-DSA private key. For recipient_client.py ONLY."""
    if not passphrase:
        raise ValueError("passphrase is required to decrypt recipient signing key")
    blob = _load_json(_vault_path(RECIPIENT_VAULT_DIR, f"{recipient_id}_dsa"), None)
    if blob is None:
        raise FileNotFoundError(f"no separated signing key for {recipient_id}")
    return _decrypt_key_blob(blob, passphrase)


def recipient_vault_has_keys() -> bool:
    """True if the separated recipient vault holds any signing keys."""
    ensure_dirs()
    try:
        return any(name.endswith(".sk") for name in os.listdir(RECIPIENT_VAULT_DIR))
    except OSError:
        return False


def clear_recipient_vault() -> None:
    """Remove all separated recipient signing keys (mode reset)."""
    ensure_dirs()
    try:
        names = os.listdir(RECIPIENT_VAULT_DIR)
    except OSError:
        return
    for name in names:
        if name.endswith(".sk"):
            os.remove(os.path.join(RECIPIENT_VAULT_DIR, name))


def clear_legacy_signing_copies() -> None:
    """Delete legacy server-readable `*_dsa.sk` files (v2 mode migration).

    Server KEM keys (`*_kem.sk`) are kept. After this, no recipient signing
    key exists outside the separated recipient vault.
    """
    ensure_dirs()
    try:
        names = os.listdir(KEYS_DIR)
    except OSError:
        return
    for name in names:
        if name.endswith("_dsa.sk"):
            os.remove(os.path.join(KEYS_DIR, name))


# ---- custodian witness vault (DSA only) ----
def save_custodian_key(custodian_id: str, dsa_sk: bytes, passphrase: str) -> None:
    if not passphrase:
        raise ValueError("passphrase is required to encrypt custodian key")
    ensure_dirs()
    _save_json(_vault_path(CUSTODIAN_DIR, custodian_id),
               _encrypt_key_blob(dsa_sk, passphrase))


def load_custodian_key(custodian_id: str, passphrase: str) -> bytes:
    if not passphrase:
        raise ValueError("passphrase is required to decrypt custodian key")
    blob = _load_json(_vault_path(CUSTODIAN_DIR, custodian_id), None)
    if blob is None:
        raise FileNotFoundError(f"no custodian key stored for {custodian_id}")
    return _decrypt_key_blob(blob, passphrase)


def load_custodians() -> dict:
    """{custodian_id: {dsa_pk_hex, dsa_alg, created_at}} — public halves only."""
    ensure_dirs()
    return _load_json(CUSTODIANS_FILE, {})


def save_custodians(custodians: dict) -> None:
    ensure_dirs()
    _save_json(CUSTODIANS_FILE, custodians)


# ---- attested sessions: pending challenges + consumed nonces (replay guard) ----
def load_sessions() -> dict:
    ensure_dirs()
    sess = _load_json(SESSIONS_FILE, None)
    if not isinstance(sess, dict):
        sess = {}
    sess.setdefault("pending", {})
    sess.setdefault("used", {})
    return sess


def save_sessions(sess: dict) -> None:
    ensure_dirs()
    if not isinstance(sess, dict):
        raise ValueError("sessions must be a dict")
    with _WRITE_LOCK:
        _save_json(SESSIONS_FILE, sess)


# ---- quorum checkpoint (ledger tip witnessed by custodians) ----
def load_checkpoint() -> dict | None:
    ensure_dirs()
    return _load_json(CHECKPOINT_FILE, None)


def save_checkpoint(checkpoint: dict) -> None:
    ensure_dirs()
    if not isinstance(checkpoint, dict):
        raise ValueError("checkpoint must be a dict")
    # Monotonic tip: a checkpoint may advance or re-assert the same tip, but
    # must never roll back to an older index (rollback = history hiding).
    with _WRITE_LOCK:
        prev = _load_json(CHECKPOINT_FILE, None)
        if (isinstance(prev, dict) and isinstance(prev.get("index"), int)
                and isinstance(checkpoint.get("index"), int)
                and checkpoint["index"] < prev["index"]):
            raise ValueError("checkpoint rollback refused: tip index moved backwards")
        _save_json(CHECKPOINT_FILE, checkpoint)


def advance_checkpoint_tip(checkpoint: dict) -> None:
    """Internal tip tracker: keep max(stored, new), never raise.

    Used by the witness path so ledger operations cannot break when the
    stored checkpoint is already ahead (e.g. restored from a newer backup).
    Direct external writes must go through save_checkpoint (strict).
    """
    ensure_dirs()
    if not isinstance(checkpoint, dict):
        raise ValueError("checkpoint must be a dict")
    with _WRITE_LOCK:
        prev = _load_json(CHECKPOINT_FILE, None)
        if (isinstance(prev, dict) and isinstance(prev.get("index"), int)
                and isinstance(checkpoint.get("index"), int)
                and checkpoint["index"] < prev["index"]):
            return
        _save_json(CHECKPOINT_FILE, checkpoint)


# ============================================================
# Encryption provenance registry ("common DB")
# ============================================================
# Record shape (all strings unless noted):
#   {doc_id, filename, fingerprint (= SHA-256 of plaintext),
#    document_hash (alias of fingerprint), pc_id, pc_label,
#    encrypted_at (ISO timestamp), file_size (int), protocol}
# Keyed by doc_id; lookups also succeed by fingerprint so an uploaded
# original file (no watermark) still resolves to its encryption record.

def load_encryption_registry() -> dict:
    """Return {doc_id: record}. Empty dict when nothing encrypted yet."""
    ensure_dirs()
    reg = _load_json(ENCRYPTION_REGISTRY_FILE, {})
    return reg if isinstance(reg, dict) else {}


def save_encryption_registry(reg: dict) -> None:
    ensure_dirs()
    if not isinstance(reg, dict):
        raise ValueError("encryption registry must be a dict")
    with _WRITE_LOCK:
        _save_json(ENCRYPTION_REGISTRY_FILE, reg)


def append_encryption_record(record: dict) -> dict:
    """Insert one encryption record (idempotent on doc_id)."""
    if not isinstance(record, dict) or not isinstance(record.get("doc_id"), str):
        raise ValueError("encryption record must contain a doc_id string")
    ensure_dirs()
    with _WRITE_LOCK:
        reg = _load_json(ENCRYPTION_REGISTRY_FILE, {})
        if not isinstance(reg, dict):
            reg = {}
        reg.setdefault(record["doc_id"], record)
        _save_json(ENCRYPTION_REGISTRY_FILE, reg)
        return reg[record["doc_id"]]


def find_encryption_record(doc_id: str | None = None,
                           fingerprint: str | None = None) -> dict | None:
    """Find a record by doc_id first, then by fingerprint/document_hash."""
    reg = load_encryption_registry()
    if doc_id and isinstance(reg.get(doc_id), dict):
        return reg[doc_id]
    if fingerprint:
        for rec in reg.values():
            if isinstance(rec, dict) and (
                    rec.get("fingerprint") == fingerprint
                    or rec.get("document_hash") == fingerprint):
                return rec
    return None

# ============================================================
# Independent custodian node storage (distributed audit layer)
# ============================================================
# Each custodian node owns a SEPARATE directory with its own identity,
# encrypted signing vault, witnessed-receipt log, checkpoint state, and
# enrollment snapshot. No two nodes ever share a private-key file.
#
#   data/custodian_nodes/<CUSTODIAN-ID>/
#     identity.json      {custodian_id, node_id, dsa_pk_hex, ...}  (public)
#     vault.sk           passphrase-encrypted ML-DSA signing key  (secret)
#     receipts.json      ordered witnessed-event log              (node state)
#     checkpoint.json    latest signed checkpoint + history       (node state)
#     enrollment.json    enrollment snapshot this node validates against
#
# The cross-node public registry lives at data/nodes.json:
#   {custodian_id: {dsa_pk_hex, dsa_alg, node_dir, created_at, protocol}}

NODE_BASE_DIR = os.path.join(DATA_DIR, "custodian_nodes")
NODES_FILE = os.path.join(DATA_DIR, "nodes.json")


def _node_id_ok(cid: str) -> str:
    if not isinstance(cid, str) or not cid or "/" in cid or "\\" in cid \
            or ".." in cid or not all(ch.isalnum() or ch in "-_" for ch in cid):
        raise ValueError(f"invalid custodian node id {cid!r}")
    return cid


def node_dir(cid: str) -> str:
    return os.path.join(NODE_BASE_DIR, _node_id_ok(cid))


def node_paths(cid: str) -> dict:
    d = node_dir(cid)
    return {"dir": d,
            "identity": os.path.join(d, "identity.json"),
            "vault": os.path.join(d, "vault.sk"),
            "receipts": os.path.join(d, "receipts.json"),
            "checkpoint": os.path.join(d, "checkpoint.json"),
            "enrollment": os.path.join(d, "enrollment.json")}


def ensure_node_dir(cid: str) -> dict:
    ensure_dirs()
    paths = node_paths(cid)
    os.makedirs(paths["dir"], exist_ok=True)
    return paths


def load_nodes_registry() -> dict:
    ensure_dirs()
    reg = _load_json(NODES_FILE, {})
    return reg if isinstance(reg, dict) else {}


def save_nodes_registry(reg: dict) -> None:
    ensure_dirs()
    if not isinstance(reg, dict):
        raise ValueError("nodes registry must be a dict")
    with _WRITE_LOCK:
        _save_json(NODES_FILE, reg)


def load_node_identity(cid: str) -> dict | None:
    paths = node_paths(cid)
    if not os.path.exists(paths["identity"]):
        return None
    return _load_json(paths["identity"], None)


def save_node_identity(cid: str, identity: dict) -> None:
    paths = ensure_node_dir(cid)
    if not isinstance(identity, dict):
        raise ValueError("node identity must be a dict")
    with _WRITE_LOCK:
        _save_json(paths["identity"], identity)


def save_node_vault_key(cid: str, dsa_sk: bytes, passphrase: str) -> None:
    if not passphrase:
        raise ValueError("passphrase is required to encrypt node signing key")
    paths = ensure_node_dir(cid)
    with _WRITE_LOCK:
        _save_json(paths["vault"], _encrypt_key_blob(dsa_sk, passphrase))


def load_node_vault_key(cid: str, passphrase: str) -> bytes:
    if not passphrase:
        raise ValueError("passphrase is required to decrypt node signing key")
    paths = node_paths(cid)
    blob = _load_json(paths["vault"], None)
    if blob is None:
        raise FileNotFoundError(f"no signing key stored for node {cid}")
    return _decrypt_key_blob(blob, passphrase)


def load_node_receipts(cid: str) -> list:
    paths = node_paths(cid)
    log = _load_json(paths["receipts"], [])
    return log if isinstance(log, list) else []


def save_node_receipts(cid: str, log: list) -> None:
    paths = ensure_node_dir(cid)
    if not isinstance(log, list):
        raise ValueError("node receipts must be a list")
    with _WRITE_LOCK:
        _save_json(paths["receipts"], log)


def load_node_checkpoint(cid: str) -> dict | None:
    paths = node_paths(cid)
    cp = _load_json(paths["checkpoint"], None)
    return cp if isinstance(cp, dict) else None


def save_node_checkpoint(cid: str, checkpoint: dict) -> None:
    """Monotonic guard: sequence must never move backwards (rollback refused).

    First checkpoint bootstraps from empty state. Re-asserting the identical
    checkpoint is allowed (idempotent re-import).
    """
    paths = ensure_node_dir(cid)
    if not isinstance(checkpoint, dict):
        raise ValueError("checkpoint must be a dict")
    with _WRITE_LOCK:
        prev = _load_json(paths["checkpoint"], None)
        if isinstance(prev, dict) and isinstance(prev.get("seq"), int) \
                and isinstance(checkpoint.get("seq"), int):
            if checkpoint == prev:
                return
            if checkpoint["seq"] < prev["seq"]:
                raise ValueError(
                    f"checkpoint rollback refused for {cid}: "
                    f"seq {checkpoint['seq']} < stored {prev['seq']}")
        _save_json(paths["checkpoint"], checkpoint)


def load_node_enrollment(cid: str) -> dict | None:
    paths = node_paths(cid)
    enr = _load_json(paths["enrollment"], None)
    return enr if isinstance(enr, dict) else None


def save_node_enrollment(cid: str, enrollment: dict) -> None:
    paths = ensure_node_dir(cid)
    if not isinstance(enrollment, dict):
        raise ValueError("enrollment snapshot must be a dict")
    with _WRITE_LOCK:
        _save_json(paths["enrollment"], enrollment)
