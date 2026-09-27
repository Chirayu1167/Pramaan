"""Symmetric document encryption (AES-256-GCM) + SHA-256 helpers."""
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOC_KEY_LEN = 32  # AES-256
NONCE_LEN = 12


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def aesgcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext+tag)."""
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)
