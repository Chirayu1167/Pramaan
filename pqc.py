"""Real post-quantum crypto wrappers (NIST FIPS 203 / FIPS 204).

Uses the `pqcrypto` package which ships compiled NIST reference code:
  - ML-KEM-768  (FIPS 203, key encapsulation)
  - ML-DSA-65   (FIPS 204, digital signatures)

No RSA/ECDSA/DH anywhere. All randomness comes from the OS (via pqcrypto /
`secrets`) — nothing is mocked.
"""
from pqcrypto.kem.ml_kem_768 import keygen as _kem_keygen, encaps as _encaps, decaps as _decaps
from pqcrypto.sign.ml_dsa_65 import keygen as _dsa_keygen, sign as _sign, verify as _verify

KEM_ALGORITHM = "ML-KEM-768 (FIPS 203)"
DSA_ALGORITHM = "ML-DSA-65 (FIPS 204)"


# ---- ML-KEM ----
def kem_generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) bytes."""
    pk, sk = _kem_keygen()
    return bytes(pk), bytes(sk)


def kem_encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to a public key. Returns (ciphertext, shared_secret 32B)."""
    ct, ss = _encaps(public_key)
    return bytes(ct), bytes(ss)


def kem_decaps(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate. Returns shared_secret bytes."""
    return bytes(_decaps(secret_key, ciphertext))


# ---- ML-DSA ----
def dsa_generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) bytes."""
    pk, sk = _dsa_keygen()
    return bytes(pk), bytes(sk)


def dsa_sign(secret_key: bytes, message: bytes) -> bytes:
    return bytes(_sign(secret_key, message))


def dsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if valid, False otherwise (pqcrypto raises on failure)."""
    try:
        _verify(public_key, message, signature)
        return True
    except Exception:
        return False
