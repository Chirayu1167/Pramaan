"""Recipient authorization client (PS26237-v2).

This is the ONLY module that reads the separated recipient signing vault
(`store.RECIPIENT_VAULT_DIR`). The server flow (`core.py`) never imports it
for signing — it only receives the finished authorization signature bytes.

In production this runs on the recipient's own device. In this single-machine
demo it is a separate module + separate passphrase boundary, explicitly
labelled as a custody simulation (see README "Trust model").

No networking. Fully offline.
"""
import ledger as ledger_mod
import pqc
import store


def authorize_challenge(challenge: dict, recipient_id: str,
                        recipient_sign_passphrase: str) -> bytes:
    """Sign a server-issued challenge with the recipient's separated DSA key.

    Raises FileNotFoundError/ValueError if the recipient vault or passphrase
    is wrong — the server cannot fabricate this without the recipient secret.
    """
    if not isinstance(challenge, dict):
        raise ValueError("challenge must be a dict")
    if challenge.get("recipient_id") != recipient_id:
        raise ValueError("challenge is not addressed to this recipient")
    dsa_sk = store.load_recipient_signing_key(recipient_id,
                                              recipient_sign_passphrase)
    return pqc.dsa_sign(dsa_sk, ledger_mod.canonical(challenge))
