"""MVP negative + positive checks (Tasks 2).

Self-contained: builds its own fresh state (init -> encrypt -> decrypt A/B),
so it is repeatable standalone AND after demo.py. Cryptographic randomness is
kept everywhere; assertions are on properties, not fixed values.
"""
import copy
import io
import json
import os
import re
import shutil

import core
import ledger as ledger_mod
import pqc
import store
import symcrypto
import watermark
import watermark_text
from demo import make_sample_pdf
from pypdf import PdfReader

PASS = []


def check(name, fn):
    fn()
    PASS.append(name)
    print(f"PASS: {name}")


def setup():
    shutil.rmtree(store.DATA_DIR, ignore_errors=True)
    store.ensure_dirs()
    recips = core.init_demo_recipients()
    assert sorted(recips) == ["RECIPIENT-A", "RECIPIENT-B", "RECIPIENT-C"]
    sample = make_sample_pdf()
    enc = core.encrypt_document(sample, "nightingale_memo.pdf")
    doc_id = enc["doc_id"]
    a = core.decrypt_for_recipient(doc_id, "RECIPIENT-A")
    b = core.decrypt_for_recipient(doc_id, "RECIPIENT-B")
    return {"recips": recips, "sample": sample, "doc_id": doc_id, "a": a, "b": b}


def visible_text(pdf_bytes: bytes) -> str:
    parts = [(p.extract_text() or "") for p in PdfReader(io.BytesIO(pdf_bytes)).pages]
    tok = watermark.extract_token(pdf_bytes) or ""
    return "\n".join(parts).replace(tok, "")


def kem_decaps_raw(recipient_id, kem_ct_hex):
    kem_sk, _ = store.load_private_keys(recipient_id, core.DEMO_PASSPHRASE)
    return pqc.kem_decaps(kem_sk, bytes.fromhex(kem_ct_hex))


def main() -> None:
    s = setup()
    doc_id, a, b = s["doc_id"], s["a"], s["b"]
    docs = store.load_documents()
    doc = docs[doc_id]
    chain = store.load_ledger()
    recips = store.load_recipients()

    # --- positive: copies identical except invisible token ---
    def t_identical():
        assert visible_text(a["pdf_bytes"]) == visible_text(b["pdf_bytes"])
    check("watermarked copies visually/textually identical (token invisible)", t_identical)

    # --- A/B differ in event, token, signature ---
    def t_differ():
        assert a["event_id"] != b["event_id"]
        assert watermark.extract_token(a["pdf_bytes"]) != watermark.extract_token(b["pdf_bytes"])
        assert a["signature_hex"] != b["signature_hex"]
    check("A and B have different event IDs, watermark tokens, signatures", t_differ)

    # --- one common ciphertext, not one copy per recipient ---
    def t_common_ciphertext():
        blobs = [f for f in os.listdir(store.DOCS_DIR) if f.endswith(".bin")]
        assert blobs == [doc["ciphertext_file"]], blobs
        ct = store.load_blob(doc["ciphertext_file"])
        seen = set()
        for rid in ("RECIPIENT-A", "RECIPIENT-B", "RECIPIENT-C"):
            env = doc["envelopes"][rid]
            ss = kem_decaps_raw(rid, env["kem_ct_hex"])
            key = symcrypto.aesgcm_decrypt(
                ss, bytes.fromhex(env["wrap_nonce_hex"]),
                bytes.fromhex(env["wrapped_key_hex"]))
            pt = symcrypto.aesgcm_decrypt(
                key, bytes.fromhex(doc["doc_nonce_hex"]), ct)
            seen.add(symcrypto.sha256_hex(pt))
        assert seen == {doc["document_hash"]}, "all envelopes must open the SAME document"
    check("single common ciphertext; all envelopes decrypt to same document", t_common_ciphertext)

    # --- A cannot use B's envelope ---
    def t_cross_envelope():
        env_b = doc["envelopes"]["RECIPIENT-B"]
        ss_wrong = kem_decaps_raw("RECIPIENT-A", env_b["kem_ct_hex"])
        try:
            symcrypto.aesgcm_decrypt(
                ss_wrong, bytes.fromhex(env_b["wrap_nonce_hex"]),
                bytes.fromhex(env_b["wrapped_key_hex"]))
        except Exception:
            return
        raise AssertionError("A decrypting B's envelope must fail authentication")
    check("RECIPIENT-A cannot decrypt RECIPIENT-B's envelope", t_cross_envelope)

    # --- wrong (fresh, unenrolled) private key fails ---
    def t_wrong_key():
        # fresh secret key, never enrolled: decaps yields an unrelated secret
        _, wrong_sk = pqc.kem_generate_keypair()
        env_a = doc["envelopes"]["RECIPIENT-A"]
        ss_bad = pqc.kem_decaps(wrong_sk, bytes.fromhex(env_a["kem_ct_hex"]))
        try:
            symcrypto.aesgcm_decrypt(
                ss_bad, bytes.fromhex(env_a["wrap_nonce_hex"]),
                bytes.fromhex(env_a["wrapped_key_hex"]))
        except Exception:
            return
        raise AssertionError("wrong private key must fail authentication")
    check("wrong private key fails to open envelope", t_wrong_key)

    # --- modified ciphertext fails AES-GCM ---
    def t_ct_tamper():
        env_a = doc["envelopes"]["RECIPIENT-A"]
        ss = kem_decaps_raw("RECIPIENT-A", env_a["kem_ct_hex"])
        wrapped = bytearray(bytes.fromhex(env_a["wrapped_key_hex"]))
        wrapped[0] ^= 0xFF
        try:
            symcrypto.aesgcm_decrypt(ss, bytes.fromhex(env_a["wrap_nonce_hex"]), bytes(wrapped))
        except Exception:
            return
        raise AssertionError("tampered wrapped key must fail authentication")
    check("modified ciphertext fails AES-GCM authentication", t_ct_tamper)

    # --- modified watermark token is not matched ---
    def t_token_tamper():
        ta = watermark.extract_token(a["pdf_bytes"])
        bad = ("0" if ta[0] != "0" else "1") + ta[1:]
        forged = watermark.embed_token(s["sample"], bad)
        res = core.investigate_leak(forged)
        assert res["match"] is False and res["watermark"] == "EXTRACTED-NO-MATCH", res
    check("modified watermark token yields no ledger match", t_token_tamper)

    # --- modified signed event fails ML-DSA ---
    def t_event_tamper():
        ev = dict(chain[0]["event"])
        sig = bytes.fromhex(chain[0]["signature"])
        pk = bytes.fromhex(recips["RECIPIENT-A"]["dsa_pk_hex"])
        assert pqc.dsa_verify(pk, ledger_mod.canonical(ev), sig) is True
        ev["recipient_id"] = "RECIPIENT-C"
        assert pqc.dsa_verify(pk, ledger_mod.canonical(ev), sig) is False
    check("modified signed event fails ML-DSA verification", t_event_tamper)

    # --- modified ledger block detected ---
    def t_block_tamper():
        bad = copy.deepcopy(chain)
        bad[0]["event"]["recipient_id"] = "RECIPIENT-C"
        ok, _ = ledger_mod.verify_ledger(bad, recips)
        assert ok is False
    check("modified ledger block is detected", t_block_tamper)

    # --- broken previous_hash detected ---
    def t_prev_tamper():
        bad = copy.deepcopy(chain)
        bad[1]["prev_hash"] = "f" * 64
        ok, msg = ledger_mod.verify_ledger(bad, recips)
        assert ok is False and "prev_hash" in msg, msg
    check("broken previous_hash is detected", t_prev_tamper)

    # --- fake event cannot produce a valid forensic match ---
    def t_fake_event():
        fake_tok = "ab" * 16
        forged = watermark.embed_token(s["sample"], fake_tok)
        res = core.investigate_leak(forged)
        assert res["match"] is False, res  # token never logged -> no match
        bad_chain = copy.deepcopy(chain)
        bad_chain.append({"index": len(bad_chain), "timestamp": chain[0]["timestamp"],
                          "event": dict(chain[0]["event"]), "signature": "00" * 64,
                          "signer": "RECIPIENT-A", "prev_hash": bad_chain[-1]["block_hash"],
                          "block_hash": "11" * 32})
        ok, _ = ledger_mod.verify_ledger(bad_chain, recips)
        assert ok is False  # forged block (bad sig/hash) rejected
    check("fake event cannot produce a valid forensic match", t_fake_event)

    # --- attribution correctness ---
    def t_attr_a():
        res = core.investigate_leak(a["pdf_bytes"])
        assert res["match"] is True and res["status"] == "VERIFIED", res
        assert res["recipient"] == "RECIPIENT-A" and res["event_id"] == a["event_id"], res
        assert res["mldsa_signature"] == "VALID" and res["ledger_integrity"] == "VALID", res
    check("investigation of A's copy identifies A's decryption event", t_attr_a)

    def t_attr_b():
        res = core.investigate_leak(b["pdf_bytes"])
        assert res["match"] is True and res["recipient"] == "RECIPIENT-B", res
    check("investigation of B's copy identifies B's decryption event", t_attr_b)

    def t_clean_pdf():
        res = core.investigate_leak(make_sample_pdf())
        assert res["match"] is False and res["watermark"] == "NOT FOUND", res
    check("clean PDF yields no watermark, no false attribution", t_clean_pdf)

    # --- wording: event attribution, never physical-leak proof ---
    def t_wording():
        res = core.investigate_leak(a["pdf_bytes"])
        scope = res.get("scope", {})
        blob = (res.get("conclusion", "") + " " + scope.get("physical_attribution", "")).lower()
        assert "decryption event" in blob
        assert "does not prove" in blob and "physically" in blob
        full = str(res).lower()
        assert "physically leaked" not in full and "physically transmitted the leak" not in full or \
            "does not" in full  # never an affirmative physical-leak claim
        assert "conclusion" in res and "scope" in res
    check("report attributes the decryption event, never claims physical leaking", t_wording)

    # --- ledger currently valid; public surface has no secrets ---
    def t_ledger_ok():
        ok, _ = ledger_mod.verify_ledger(chain, recips)
        assert ok
    check("ledger valid after demo flow", t_ledger_ok)

    def t_no_secrets():
        blob = str(core.public_recipients()) + str(chain)
        assert ".sk" not in blob and "secret" not in blob.lower()
        for r in core.public_recipients().values():
            assert set(r) == {"kem_pk_hex", "dsa_pk_hex", "kem_alg", "dsa_alg", "created_at"}
    check("public surfaces expose public keys only (no private keys)", t_no_secrets)

        # --- private keys are encrypted at rest (Task 1) ---
    def t_keys_encrypted_at_rest():
        kem_path = os.path.join(store.KEYS_DIR, "RECIPIENT-A_kem.sk")
        dsa_path = os.path.join(store.KEYS_DIR, "RECIPIENT-A_dsa.sk")
        kem_sk, dsa_sk = store.load_private_keys("RECIPIENT-A", core.DEMO_PASSPHRASE)
        with open(kem_path, "rb") as f:
            kem_on_disk = f.read()
        with open(dsa_path, "rb") as f:
            dsa_on_disk = f.read()
        assert kem_sk not in kem_on_disk and dsa_sk not in dsa_on_disk, \
            "raw private key bytes must not appear in the on-disk key file"
        blob = json.loads(kem_on_disk)
        assert set(blob) == {"kdf", "n", "r", "p", "salt_hex", "nonce_hex", "ciphertext_hex"}
        assert blob["kdf"] == "scrypt"
    check("private keys are encrypted at rest, self-describing (salt/nonce/kdf)",
          t_keys_encrypted_at_rest)

    # --- wrong passphrase must fail to decrypt stored private keys ---
    def t_wrong_passphrase_fails():
        try:
            store.load_private_keys("RECIPIENT-A", "definitely-the-wrong-passphrase")
        except ValueError:
            return
        raise AssertionError("wrong passphrase must fail to decrypt private keys")
    check("wrong passphrase fails to decrypt stored private keys", t_wrong_passphrase_fails)

    # --- correct passphrase round-trips; decrypt/signing keep working end to end ---
    def t_correct_passphrase_roundtrip_and_key_use():
        kem_pk, kem_sk = pqc.kem_generate_keypair()
        dsa_pk, dsa_sk = pqc.dsa_generate_keypair()
        passphrase = "a completely different test passphrase"
        store.save_private_keys("TEST-ROUNDTRIP", kem_sk, dsa_sk, passphrase)
        loaded_kem_sk, loaded_dsa_sk = store.load_private_keys("TEST-ROUNDTRIP", passphrase)
        assert loaded_kem_sk == kem_sk and loaded_dsa_sk == dsa_sk
        # end-to-end: KEM decapsulation and ML-DSA signing still work with
        # the round-tripped keys
        ct, ss = pqc.kem_encaps(kem_pk)
        assert pqc.kem_decaps(loaded_kem_sk, ct) == ss
        sig = pqc.dsa_sign(loaded_dsa_sk, b"round-trip check")
        assert pqc.dsa_verify(dsa_pk, b"round-trip check", sig) is True
        # the wrong passphrase must still fail for this freshly saved key
        try:
            store.load_private_keys("TEST-ROUNDTRIP", "not-the-right-one")
        except ValueError:
            pass
        else:
            raise AssertionError("wrong passphrase must fail even for a freshly saved key")
    check("correct passphrase round-trips keys; decrypt+signing still work end to end",
          t_correct_passphrase_roundtrip_and_key_use)

    # --- wrong recipient's key fails signature verification ---
    def t_wrong_recip_key():
        ev = chain[0]["event"]
        sig = bytes.fromhex(chain[0]["signature"])
        pk_b = bytes.fromhex(recips["RECIPIENT-B"]["dsa_pk_hex"])
        assert pqc.dsa_verify(pk_b, ledger_mod.canonical(ev), sig) is False
    check("wrong recipient key fails event signature verification", t_wrong_recip_key)

    # --- invalid signer detected ---
    def t_invalid_signer():
        # naive edit is caught by the hash; a re-hashed forgery must still
        # fail at the unknown-signer check
        bad = copy.deepcopy(chain)
        bad[0]["signer"] = "NOBODY"
        ok, _ = ledger_mod.verify_ledger(bad, recips)
        assert ok is False
        forged = copy.deepcopy(chain)
        ev = dict(chain[0]["event"], event_id="f" * 32,
                  watermark_token_hash="e" * 64)
        ledger_mod.append_event(forged, ev, chain[0]["signature"], "NOBODY")
        ok, msg = ledger_mod.verify_ledger(forged, recips)
        assert ok is False and "signer" in msg, msg
    check("invalid signer is detected", t_invalid_signer)

    # --- malformed ledger detected (non-dict block, bad fields, non-list) ---
    def t_malformed_ledger():
        ok, msg = ledger_mod.verify_ledger(["not-a-block"], recips)
        assert ok is False and "malformed" in msg, msg
        bad = copy.deepcopy(chain)
        del bad[0]["prev_hash"]
        ok, msg = ledger_mod.verify_ledger(bad, recips)
        assert ok is False and "malformed" in msg, msg
        ok, msg = ledger_mod.verify_ledger({"index": 0}, recips)
        assert ok is False, msg
    check("malformed ledger blocks are detected", t_malformed_ledger)

    # --- duplicate event / token-hash rejected at append ---
    def t_duplicates_rejected():
        dup = copy.deepcopy(chain)
        try:
            ledger_mod.append_event(dup, dict(chain[0]["event"]),
                                    chain[0]["signature"], chain[0]["signer"])
        except ValueError:
            return
        raise AssertionError("re-appending the same event must be rejected")
    check("duplicate event/token append is rejected", t_duplicates_rejected)

    # --- ledger file is append-only (truncate/rewrite refused) ---
    def t_append_only():
        try:
            store.save_ledger(chain[:-1])
        except ValueError:
            pass
        else:
            raise AssertionError("truncating stored history must be refused")
        store.save_ledger(chain)  # identical re-save (same prefix) is fine
        ok, _ = ledger_mod.verify_ledger(store.load_ledger(), recips)
        assert ok
    check("stored ledger history cannot be truncated/rewritten", t_append_only)

    # --- watermark is embedded at DECRYPTION, not in stored plaintext ---
    def t_not_in_plaintext():
        env = doc["envelopes"]["RECIPIENT-A"]
        ss = kem_decaps_raw("RECIPIENT-A", env["kem_ct_hex"])
        key = symcrypto.aesgcm_decrypt(
            ss, bytes.fromhex(env["wrap_nonce_hex"]), bytes.fromhex(env["wrapped_key_hex"]))
        plain = symcrypto.aesgcm_decrypt(
            key, bytes.fromhex(doc["doc_nonce_hex"]), store.load_blob(doc["ciphertext_file"]))
        assert watermark.extract_token(plain) is None
        assert watermark.extract_token(a["pdf_bytes"]) is not None
    check("stored plaintext carries no watermark (inserted at decryption)", t_not_in_plaintext)

    ##ney block
        # ============================================================
    # .txt/.md dual-channel text watermarking (additive; does not
    # touch any PDF fixture, flow, or assertion set up above)
    # ============================================================
    sample_text = ("This is a confidential .txt leaked-document watermarking test. "
                   "Project Nightingale distributes plain-text memos to recipients "
                   "alongside PDFs, and each decryption must carry its own dual-channel "
                   "watermark: an invisible zero-width copy every ~40 words, plus a "
                   "short visible canary line, so a partial leak, a stripped invisible "
                   "channel, or a stripped everything are each handled honestly. ") * 3
    text_enc = core.encrypt_document(sample_text.encode("utf-8"), "nightingale_memo.txt")
    text_doc_id = text_enc["doc_id"]
    text_a = core.decrypt_for_recipient(text_doc_id, "RECIPIENT-A")
    text_b = core.decrypt_for_recipient(text_doc_id, "RECIPIENT-B")

    def t_text_roundtrip():
        assert text_a["is_text"] is True and text_b["is_text"] is True
        body_a = text_a["pdf_bytes"].decode("utf-8")
        body_b = text_b["pdf_bytes"].decode("utf-8")
        ext_a = watermark_text.extract_text_watermark(body_a)
        ext_b = watermark_text.extract_text_watermark(body_b)
        assert ext_a["invisible"] is not None, "invisible channel missing on untouched .txt copy"
        assert ext_a["canary"] is not None, "canary channel missing on untouched .txt copy"
        assert ext_b["invisible"] is not None and ext_b["canary"] is not None
        assert ext_a["invisible"] != ext_b["invisible"], "A/B tokens must differ"
        assert ext_a["canary"] != ext_b["canary"], "A/B canary prefixes must differ"
        assert ext_a["canary"] == ext_a["invisible"][:watermark_text.CANARY_PREFIX_LEN], \
            "canary must be the invisible token's own prefix"
    check("untouched .txt copy round-trips on both channels (invisible + canary)",
          t_text_roundtrip)

    def t_text_encrypt_decrypt_investigate():
        res = core.investigate_leak(text_a["pdf_bytes"])
        assert res["match"] is True and res["status"] == "VERIFIED", res
        assert res["recipient"] == "RECIPIENT-A", res
        assert res["event_id"] == text_a["event_id"], res
        assert "channel" not in res, "full-match case must not be tagged canary-only"
    check("encrypt/decrypt/investigate a .txt file end to end (invisible channel intact)",
          t_text_encrypt_decrypt_investigate)

    def t_text_canary_only_after_stripping_invisible():
        body_a = text_a["pdf_bytes"].decode("utf-8")
        stripped = "".join(
            ch for ch in body_a
            if ch not in (watermark_text.ZW_ZERO, watermark_text.ZW_ONE))
        # invisible channel is gone, canary line is untouched
        assert watermark_text.extract_token_invisible(stripped) is None
        assert watermark_text.extract_canary(stripped) is not None
        res = core.investigate_leak(stripped.encode("utf-8"))
        assert res["match"] is True and res["status"] == "VERIFIED", res
        assert res["recipient"] == "RECIPIENT-A", res
        assert res["channel"] == "canary-only", res
        assert "invisible" in res["note"] and "canary" in res["note"], res
    check("stripping only the zero-width channel still verifies via canary-only match",
          t_text_canary_only_after_stripping_invisible)

    def t_text_both_channels_stripped_honest_not_verified():
        body_a = text_a["pdf_bytes"].decode("utf-8")
        stripped = "".join(
            ch for ch in body_a
            if ch not in (watermark_text.ZW_ZERO, watermark_text.ZW_ONE))
        no_canary = re.sub(r"\n\n---\nRef: [0-9a-f]{8}\n", "", stripped)
        assert watermark_text.extract_token_invisible(no_canary) is None
        assert watermark_text.extract_canary(no_canary) is None
        res = core.investigate_leak(no_canary.encode("utf-8"))
        assert res["match"] is False and res["status"] == "NOT VERIFIED", res
        assert "stripping" in res["note"] and "retyping" in res["note"], res
    check("stripping both channels yields honest NOT VERIFIED with a stripping note",
          t_text_both_channels_stripped_honest_not_verified)

    def t_text_partial_copy_paste_survives():
        # A copy-paste of just one ~40-word chunk (not the whole document)
        # must still carry at least one intact invisible copy of the token.
        body_a = text_a["pdf_bytes"].decode("utf-8")
        # take a slice roughly in the middle of the document
        mid = len(body_a) // 2
        snippet = body_a[max(0, mid - 400):mid + 400]
        assert watermark_text.extract_token_invisible(snippet) is not None, \
            "a mid-document snippet should still carry an intact invisible token copy"
    check("partial copy-paste of a document chunk still carries an intact invisible token",
          t_text_partial_copy_paste_survives)

    def t_text_unrelated_file_not_verified():
        res = core.investigate_leak(b"just some unrelated plain text with no watermark at all")
        assert res["match"] is False and res["status"] == "NOT VERIFIED", res
        assert res["watermark"] == "NOT FOUND", res
    check(".txt file with no watermark at all yields honest NOT VERIFIED", t_text_unrelated_file_not_verified)


    # --- HTTP/API surface: traversal, malformed fields ---
    def t_api_surface():
        from app import app as flask_app
        c = flask_app.test_client()
        assert c.get("/api/copy/..%2F..%2Fapp.py").status_code == 404
        assert c.get("/api/copy/nothex").status_code == 404
        assert c.get("/api/copy/" + "0" * 31).status_code == 404
        r = c.post("/api/decrypt", json={"doc_id": 123, "recipient_id": "RECIPIENT-A"})
        assert r.status_code == 400, r.get_json()
        r = c.post("/api/decrypt", data="not json", content_type="application/json")
        assert r.status_code == 400, r.get_json()
        r = c.post("/api/decrypt", json={"doc_id": "0" * 32, "recipient_id": "NOBODY"})
        assert r.status_code == 400, r.get_json()
        r = c.post("/api/encrypt")
        assert r.status_code == 400, r.get_json()
        r = c.post("/api/investigate")
        assert r.status_code == 400, r.get_json()
    check("API rejects traversal, malformed fields, missing files", t_api_surface)

    # --- offline static scan: our sources use no networking ---
    def t_offline_static():
        import re
        net_pat = re.compile(
            r"^\s*(import|from)\s+(socket|requests|urllib|http\.|ssl|asyncio|websockets|paramiko)",
            re.M)
        here = os.path.dirname(os.path.abspath(__file__))
        for fn in ("app.py", "core.py", "ledger.py", "store.py", "pqc.py",
                   "symcrypto.py", "watermark.py","watermark_text.py", "demo.py", "test_mvp.py",
                   "provenance.py", "custodians.py", "recipient_client.py",
                   "device.py", "latticemark.py", "evidence.py", "nodes.py",
                   "test_attested.py", "test_distributed.py"):
            with open(os.path.join(here, fn), encoding="utf-8") as f:
                src = f.read()
            assert not net_pat.search(src), f"{fn} imports networking"
            for m in re.finditer(r"https?://[^\s\"']+", src):
                assert m.group(0).startswith("http://127.0.0.1"), \
                    f"{fn} references remote endpoint {m.group(0)}"
    check("sources are network-free (offline/air-gapped capable)", t_offline_static)

    print(f"ALL {len(PASS)} MVP CHECKS PASSED")


if __name__ == "__main__":
    main()
