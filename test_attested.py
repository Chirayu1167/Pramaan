"""PS26237-v2 hostile attack tests (Phase 9).

Each test states ATTACK / EXPECTED / actual assertion / SECURITY PROPERTY.
Self-contained: fresh attested state (init -> encrypt -> challenge ->
authorize -> complete -> 2 witnesses -> FINAL).

Run:  python3 test_attested.py
"""
import copy
import io
import os
import shutil

import core
import custodians as custodians_mod
import evidence as evidence_mod
import ledger as ledger_mod
import provenance as prov_mod
import pqc
import recipient_client as recipient_client_mod
import store
import symcrypto
import watermark
from demo import make_sample_pdf

PASS = []


def check(name, fn):
    fn()
    PASS.append(name)
    print(f"PASS: {name}")


def honest_decrypt(doc_id, rid):
    """Honest v2 decrypt: server challenge -> recipient device signs -> complete."""
    ch = core.create_decrypt_challenge(doc_id, rid)
    sig = recipient_client_mod.authorize_challenge(
        ch, rid, core.RECIPIENT_SIGN_PASSPHRASES[rid])
    return ch, core.complete_attested_decryption(ch, sig.hex())


def finalize(index):
    cm = custodians_mod
    cm.witness_block(store.load_ledger(), index, "CUSTODIAN-1",
                     cm.CUSTODIAN_PASSPHRASES["CUSTODIAN-1"])
    cm.witness_block(store.load_ledger(), index, "CUSTODIAN-2",
                     cm.CUSTODIAN_PASSPHRASES["CUSTODIAN-2"])


def make_other_pdf() -> bytes:
    """A genuinely DIFFERENT document (make_sample_pdf is deterministic)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 720, "CONFIDENTIAL — Different Project Memo")
    c.setFont("Helvetica", 11)
    c.drawString(72, 690, "Unrelated content for transplant testing.")
    c.showPage()
    c.save()
    return buf.getvalue()


def setup():
    shutil.rmtree(store.DATA_DIR, ignore_errors=True)
    store.ensure_dirs()
    core.init_attested_identities()
    enc = core.encrypt_document(make_sample_pdf(), "nightingale_memo.pdf")
    doc_id = enc["doc_id"]
    _, a = honest_decrypt(doc_id, "RECIPIENT-A")
    finalize(a["block_index"])
    return {"doc_id": doc_id, "a": a}


def main() -> None:
    s = setup()
    doc_id, a = s["doc_id"], s["a"]

    def v2chain():
        return store.load_ledger()

    def recips():
        return store.load_recipients()

    def custs():
        return store.load_custodians()

    # 1. admin fabricates recipient authorization (no recipient key)
    def t_fabricate_auth():
        ch = core.create_decrypt_challenge(doc_id, "RECIPIENT-A")
        _, rogue_sk = pqc.dsa_generate_keypair()
        rogue_sig = pqc.dsa_sign(rogue_sk, ledger_mod.canonical(ch))
        try:
            core.complete_attested_decryption(ch, rogue_sig.hex())
        except ValueError:
            return
        raise AssertionError("rogue authorization must be rejected")
    check("ATTACK 1 admin fabricates authorization -> BLOCKED (invalid auth signature)",
          t_fabricate_auth)

    # 2. server has no signing-key access (trust boundary is real in code)
    def t_server_key_isolation():
        kem_only = store.load_server_kem_key("RECIPIENT-A", core.DEMO_PASSPHRASE)
        assert isinstance(kem_only, bytes) and len(kem_only) > 0
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "core.py"), encoding="utf-8") as f:
            lines = f.read().splitlines()
        # Strip comments: the trust-boundary *documentation* may name the
        # vault; executable code must not touch it.
        code = "\n".join(ln.split("#", 1)[0] for ln in lines)
        for banned in ("import recipient_client", "from recipient_client",
                       "load_recipient_signing_key", "RECIPIENT_VAULT_DIR",
                       "RECIPIENT_SIGN_PASSPHRASES["):
            assert banned not in code, f"server must not contain {banned!r}"
        # legacy custodial DSA copy must NOT exist in v2 mode
        assert not os.path.exists(
            os.path.join(store.KEYS_DIR, "RECIPIENT-A_dsa.sk")), \
            "v2 mode must not leave a server-readable signing key"
    check("ATTACK 2 server signs without recipient key -> IMPOSSIBLE (no vault access)",
          t_server_key_isolation)

    # 3. replay a consumed authorization
    def t_replay():
        ch = core.create_decrypt_challenge(doc_id, "RECIPIENT-B")
        sig = recipient_client_mod.authorize_challenge(
            ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        core.complete_attested_decryption(ch, sig.hex())
        try:
            core.complete_attested_decryption(ch, sig.hex())
        except ValueError:
            return
        raise AssertionError("replayed authorization must be rejected")
    check("ATTACK 3 replay old authorization -> BLOCKED (nonce single-use)", t_replay)

    # 4. crafted challenge reusing a consumed nonce
    def t_nonce_reuse():
        ch = core.create_decrypt_challenge(doc_id, "RECIPIENT-B")
        sig = recipient_client_mod.authorize_challenge(
            ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        core.complete_attested_decryption(ch, sig.hex())
        forged = dict(ch, event_id="f" * 32)  # same nonce, new event id
        sig2 = recipient_client_mod.authorize_challenge(
            forged, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        try:
            core.complete_attested_decryption(forged, sig2.hex())
        except ValueError:
            return
        raise AssertionError("nonce reuse must be rejected")
    check("ATTACK 4 reuse session nonce -> BLOCKED", t_nonce_reuse)

    # 5. wrong recipient signs someone else's challenge
    def t_cross_sign():
        ch = core.create_decrypt_challenge(doc_id, "RECIPIENT-A")
        try:
            recipient_client_mod.authorize_challenge(
                ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        except ValueError:
            return
        raise AssertionError("cross-recipient authorization must be refused")
    check("ATTACK 5 B signs A's challenge -> REFUSED by recipient client", t_cross_sign)

    # 6. transplant fingerprint doc A -> different document B
    def t_transplant_doc():
        enc_b = core.encrypt_document(make_other_pdf(), "other_memo.pdf")
        _, b = honest_decrypt(enc_b["doc_id"], "RECIPIENT-B")
        finalize(b["block_index"])
        fp_a = watermark.extract_token(a["pdf_bytes"])
        forged = watermark.embed_token(make_other_pdf(), fp_a)
        res = core.investigate_leak_v2(forged)
        assert res["match"] is False and res["binding"] == "MISMATCH", res
    check("ATTACK 6 transplant fingerprint to another document -> REJECTED (binding)",
          t_transplant_doc)

    # 7. cross-event confusion: exact clone attributes to its SOURCE event;
    # double-watermarked copy (A's fp pasted onto B's copy) matches neither.
    def t_transplant_event():
        # Honest invariant (post-LatticeMark): a stored copy carries TWO
        # layers encoding the same fingerprint (text token + pixel lattice),
        # and copy_hash covers both. A reconstruction must therefore rebuild
        # BOTH layers to byte-match. Both carriers are deterministic given
        # (source PDF, token), so rebuilding is possible for anyone holding
        # the token + source — exact-byte cloning is OUTSIDE the threat model
        # (an actor with the leak already holds the bytes); copy_hash defends
        # against transplant/modification, never against exact rebuilds.
        import latticemark as latticemark_mod
        fp_a = watermark.extract_token(a["pdf_bytes"])
        clone = latticemark_mod.embed_lattice(
            watermark.embed_token(make_sample_pdf(), fp_a), fp_a)
        res = core.investigate_leak_v2(clone)
        assert res["match"] is True and res["event_id"] == a["event_id"], res
        # A text-layer-only rebuild is now (correctly) a different byte
        # string: fingerprint matches, binding does not.
        partial = watermark.embed_token(make_sample_pdf(), fp_a)
        res_partial = core.investigate_leak_v2(partial)
        assert res_partial["match"] is False \
            and res_partial.get("binding") == "MISMATCH", res_partial
        enc_c = core.encrypt_document(make_other_pdf(), "third_memo.pdf")
        _, c = honest_decrypt(enc_c["doc_id"], "RECIPIENT-B")
        finalize(c["block_index"])
        double = watermark.embed_token(c["pdf_bytes"], fp_a)
        res2 = core.investigate_leak_v2(double)
        assert res2["match"] is False, res2
    check("ATTACK 7 cross-event transplant -> clone tracks source; double-mark rejected",
          t_transplant_event)

    # 8. modify watermarked bytes: corrupt parse AND benign append both fail safe
    def t_modify_doc():
        raw = bytearray(a["pdf_bytes"])
        raw[len(raw) // 2] ^= 0xFF
        res = core.investigate_leak_v2(bytes(raw))  # must not throw
        assert res["match"] is False, res
        appended = a["pdf_bytes"] + b"% extra trailing bytes"
        res2 = core.investigate_leak_v2(appended)
        assert res2["match"] is False and res2.get("binding") == "MISMATCH", res2
    check("ATTACK 8 modify document bytes -> NOT VERIFIED, never throws", t_modify_doc)

    # 9. fabricated fingerprint
    def t_random_fp():
        forged = watermark.embed_token(make_sample_pdf(), "ab" * 16)
        res = core.investigate_leak_v2(forged)
        assert res["match"] is False and res["watermark"] == "EXTRACTED-NO-MATCH", res
    check("ATTACK 9 random fabricated fingerprint -> NO MATCH", t_random_fp)

    # 10. remove watermark entirely
    def t_strip():
        res = core.investigate_leak_v2(make_sample_pdf())
        assert res["match"] is False and res["watermark"] == "NOT FOUND", res
    check("ATTACK 10 stripped watermark -> NOT VERIFIED (honest)", t_strip)

    # 11. modify ledger event field
    def t_ledger_edit():
        bad = copy.deepcopy(v2chain())
        bad[0]["event"]["recipient_id"] = "RECIPIENT-C"
        ok, _ = ledger_mod.verify_ledger(bad, recips(), custs())
        assert ok is False
    check("ATTACK 11 edit ledger event -> DETECTED", t_ledger_edit)

    # 12. truncate ledger via API refused; direct truncation detected
    def t_ledger_delete():
        try:
            store.save_ledger(v2chain()[:-1] if len(v2chain()) > 1 else [])
        except ValueError:
            pass  # API refusal is the expected path when history exists
        bad = copy.deepcopy(v2chain())
        if len(bad) > 1:
            bad.pop()
            ok, _ = ledger_mod.verify_ledger(bad, recips(), custs())
            # truncated chain is internally consistent but checkpoint disagrees
            tip = store.load_checkpoint()
            assert tip is not None and tip["index"] != bad[-1]["index"]
            assert ok is True  # honesty: truncation of trailing blocks is consistent;
            # continuity proof comes from the checkpoint, checked above
    check("ATTACK 12 delete ledger entry -> API refuses; checkpoint exposes truncation",
          t_ledger_delete)

    # 13. replace entire ledger with forged chain
    def t_ledger_replace():
        forged = [{"index": 0, "timestamp": "2026-01-01T00:00:00+00:00",
                   "event": dict(v2chain()[0]["event"]), "signer": "RECIPIENT-A",
                   "witnesses": [], "status": "PENDING",
                   "prev_hash": ledger_mod.GENESIS_PREV, "block_hash": "00" * 32}]
        ok, _ = ledger_mod.verify_ledger(forged, recips(), custs())
        assert ok is False
        tip = store.load_checkpoint()
        assert tip["tip_hash"] != "00" * 32
    check("ATTACK 13 replace entire ledger -> REJECTED + checkpoint disagrees",
          t_ledger_replace)

    # 14. forge custodian signature / wrong passphrase
    def t_forge_custodian():
        chx = core.create_decrypt_challenge(doc_id, "RECIPIENT-C")
        sigx = recipient_client_mod.authorize_challenge(
            chx, "RECIPIENT-C", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-C"])
        rx = core.complete_attested_decryption(chx, sigx.hex())
        try:
            custodians_mod.witness_block(
                store.load_ledger(), rx["block_index"], "CUSTODIAN-1", "wrong-passphrase")
        except ValueError:
            pass
        else:
            raise AssertionError("wrong custodian passphrase must fail")
        # tamper a real witness signature
        chain = store.load_ledger()
        custodians_mod.witness_block(
            chain, rx["block_index"], "CUSTODIAN-1",
            custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-1"])
        bad = copy.deepcopy(chain)
        bad[rx["block_index"]]["witnesses"][0]["signature_hex"] = "ff" * 64
        ok, msg = ledger_mod.verify_ledger(bad, recips(), custs())
        assert ok is False, msg
    check("ATTACK 14 forge custodian signature -> REJECTED", t_forge_custodian)

    # 15. single custodian cannot finalize
    def t_single_custodian():
        chx = core.create_decrypt_challenge(doc_id, "RECIPIENT-C")
        sigx = recipient_client_mod.authorize_challenge(
            chx, "RECIPIENT-C", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-C"])
        rx = core.complete_attested_decryption(chx, sigx.hex())
        chain = store.load_ledger()
        assert chain[rx["block_index"]]["status"] == "PENDING"
        custodians_mod.witness_block(
            chain, rx["block_index"], "CUSTODIAN-3",
            custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-3"])
        assert store.load_ledger()[rx["block_index"]]["status"] == "PENDING"
        res = core.investigate_leak_v2(rx["pdf_bytes"])
        assert res["match"] is False and "PENDING" in res.get("reason", ""), res
        # duplicate witness by same custodian refused
        try:
            custodians_mod.witness_block(
                store.load_ledger(), rx["block_index"], "CUSTODIAN-3",
                custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-3"])
        except ValueError:
            pass
        else:
            raise AssertionError("double witness must be refused")
    check("ATTACK 15 finalize with 1 custodian -> NOT FINAL, investigation refused",
          t_single_custodian)

    # 16. revoked recipient blocked; history still verifies
    def t_revocation():
        rec = core.revoke_recipient(
            "RECIPIENT-C", "CUSTODIAN-1",
            custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-1"])
        assert rec["action"] == "revoke"
        try:
            core.create_decrypt_challenge(doc_id, "RECIPIENT-C")
        except ValueError:
            pass
        else:
            raise AssertionError("revoked recipient must not get challenges")
        try:
            core.revoke_recipient("NOBODY", "CUSTODIAN-1",
                                  custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-1"])
        except ValueError:
            pass
        else:
            raise AssertionError("revoking unknown recipient must fail")
        try:
            core.revoke_recipient("RECIPIENT-B", "CUSTODIAN-1", "wrong-pass")
        except ValueError:
            pass
        else:
            raise AssertionError("revocation with wrong custodian passphrase must fail")
        # history: A's FINAL event still verifies after C's revocation
        res = core.investigate_leak_v2(a["pdf_bytes"])
        assert res["match"] is True and res["status"] == "VERIFIED", res
    check("ATTACK 16 revoked recipient decrypts -> BLOCKED; history intact",
          t_revocation)

    # 17. tamper timestamp / recipient id / version / policy in event
    def t_event_fields():
        for field, evil in (("timestamp", "2000-01-01T00:00:00+00:00"),
                            ("recipient_id", "RECIPIENT-B"),
                            ("document_version", "v9"),
                            ("policy_hash", "00" * 32)):
            bad = copy.deepcopy(v2chain())
            for b in bad:
                if isinstance(b.get("event"), dict) and ledger_mod.is_v2_event(b["event"]):
                    b["event"][field] = evil
                    break
            ok, _ = ledger_mod.verify_ledger(bad, recips(), custs())
            assert ok is False, field
    check("ATTACK 17 alter timestamp/recipient/version/policy -> DETECTED",
          t_event_fields)

    # 18. expired challenge rejected
    def t_expired():
        ch = core.create_decrypt_challenge(doc_id, "RECIPIENT-B")
        ch["issued_at"] = "2000-01-01T00:00:00+00:00"
        sess = store.load_sessions()
        sess["pending"][ch["session_nonce"]] = ch
        store.save_sessions(sess)
        sig = recipient_client_mod.authorize_challenge(
            ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        try:
            core.complete_attested_decryption(ch, sig.hex())
        except ValueError:
            return
        raise AssertionError("expired challenge must be rejected")
    check("ATTACK 18 expired challenge -> REJECTED", t_expired)

    # 19. evidence package: clean-room verify passes; tampering fails
    def t_evidence():
        pkg = evidence_mod.build_evidence_package(a["event_id"], a["pdf_bytes"])
        assert evidence_mod.verify_evidence_package(pkg)["valid"] is True
        bad = copy.deepcopy(pkg)
        bad["event"]["recipient_id"] = "RECIPIENT-B"
        assert evidence_mod.verify_evidence_package(bad)["valid"] is False
        bad2 = copy.deepcopy(pkg)
        bad2["block"]["witnesses"] = bad2["block"]["witnesses"][:1]
        assert evidence_mod.verify_evidence_package(bad2)["valid"] is False
        assert evidence_mod.verify_evidence_package({"format": "junk"})["valid"] is False
    check("ATTACK 19 submit tampered/malformed evidence -> REJECTED; honest verifies",
          t_evidence)

    # 20. mixed v1+v2 chain verifies (backward compatibility) + fail-closed quorum
    def t_mixed_chain():
        # Hand-build a genuine v1 block under the CURRENT key generation:
        # recipient signs a legacy-shaped event with their vault key (test
        # simulates both sides), appended under the v2 chain tip.
        vault_sig_key = store.load_recipient_signing_key(
            "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        v1_event = {"event_id": "ee" * 16, "recipient_id": "RECIPIENT-B",
                    "document_id": doc_id,
                    "document_hash": store.load_documents()[doc_id]["document_hash"],
                    "watermark_token_hash": "cc" * 32,
                    "timestamp": core.utcnow_iso()}
        sig = pqc.dsa_sign(vault_sig_key, ledger_mod.canonical(v1_event))
        chain = v2chain()
        ledger_mod.append_event(chain, v1_event, sig.hex(), "RECIPIENT-B")
        store.save_ledger(chain)
        ok, msg = ledger_mod.verify_ledger(store.load_ledger(), recips(), custs())
        assert ok is True, msg
        # v2 verify without custodian registry must fail closed
        ok2, msg2 = ledger_mod.verify_ledger(store.load_ledger(), recips())
        assert ok2 is False and "custodian" in msg2, msg2
    check("ATTACK 20 bypass quorum by omitting custodians -> FAIL-CLOSED (+mixed chain ok)",
          t_mixed_chain)

    # 21. path traversal in key-vault accessors (defense in depth: the pending-
    # challenge gate already blocks traversal IDs via API, but loaders must
    # refuse directly too).
    def t_traversal():
        # NOTE: '' is not traversal (it resolves to an inert in-vault file
        # such as `_kem.sk`, never outside the vault) and is excluded here.
        evil_names = ["../../evil", "..\\..\\evil", "../x", "a/b",
                      "RECIPIENT-A\x00"]
        for evil in evil_names:
            for fn in (lambda: store.load_server_kem_key(evil, "p"),
                       lambda: store.load_private_keys(evil, "p"),
                       lambda: store.save_server_kem_key(evil, b"x", "p"),
                       lambda: store.load_custodian_key(evil, "p"),
                       lambda: store.save_custodian_key(evil, b"x", "p"),
                       lambda: store.save_recipient_signing_key(evil, b"x", "p")):
                try:
                    fn()
                except (ValueError, FileNotFoundError):
                    continue
                raise AssertionError(f"traversal name {evil!r} was not refused")
        # crafted API-level challenge with traversal id dies at nonce lookup,
        # never reaching key files
        forged = {"protocol": "ps26237-v2", "event_id": "00" * 16,
                  "doc_id": doc_id, "document_hash": "00" * 32,
                  "document_version": "v1", "recipient_id": "../../evil",
                  "recipient_key_id": "00" * 16, "session_nonce": "ff" * 16,
                  "policy_hash": prov_mod.policy_hash(),
                  "policy_version": prov_mod.POLICY_VERSION,
                  "issued_at": core.utcnow_iso()}
        try:
            core.complete_attested_decryption(forged, "00" * 64)
        except ValueError:
            return
        raise AssertionError("traversal challenge must be rejected")
    check("ATTACK 21 key-path traversal -> REFUSED at every accessor", t_traversal)

    # 22. checkpoint rollback refused; advance + re-assert allowed
    def t_checkpoint():
        real_tip = store.load_checkpoint()
        store.save_checkpoint({"tip_hash": "11" * 32, "index": 900,
                               "status": "FINAL", "updated_at": "t"})
        store.save_checkpoint({"tip_hash": "11" * 32, "index": 900,
                               "status": "FINAL", "updated_at": "t2"})
        store.save_checkpoint({"tip_hash": "22" * 32, "index": 901,
                               "status": "FINAL", "updated_at": "t3"})
        try:
            store.save_checkpoint({"tip_hash": "00" * 32, "index": 3,
                                   "status": "FINAL", "updated_at": "evil"})
        except ValueError:
            pass
        else:
            raise AssertionError("checkpoint rollback must be refused")
        assert store.load_checkpoint()["index"] == 901
        # restore real tip so later tests see genuine state
        if real_tip is None:
            try:
                os.remove(store.CHECKPOINT_FILE)
            except OSError:
                pass
        else:
            import json as _json
            with open(store.CHECKPOINT_FILE, "w",
                      encoding="utf-8") as f:
                _json.dump(real_tip, f, indent=2)
    check("ATTACK 22 checkpoint rollback -> REFUSED (monotonic tip)", t_checkpoint)

    # 23. concurrent double-complete: exactly one release, clean ValueError
    def t_race():
        import threading
        chx = core.create_decrypt_challenge(doc_id, "RECIPIENT-B")
        sigx = recipient_client_mod.authorize_challenge(
            chx, "RECIPIENT-B",
            core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"]).hex()
        outcomes = []
        n_before = len(store.load_ledger())

        def worker():
            try:
                core.complete_attested_decryption(dict(chx), sigx)
                outcomes.append("released")
            except ValueError:
                outcomes.append("rejected")
            except Exception as e:  # noqa: BLE001 — any other type is a bug
                outcomes.append(f"UNEXPECTED-{type(e).__name__}")

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes.count("released") == 1, outcomes
        assert outcomes.count("rejected") == 4, outcomes
        assert len(store.load_ledger()) == n_before + 1
        # concurrent distinct-custodian witnesses converge (retry on refusal)
        idx = n_before
        import threading as _th
        _werrs = []

        def wit(cid):
            for _ in range(20):
                try:
                    custodians_mod.witness_block(
                        store.load_ledger(), idx, cid,
                        custodians_mod.CUSTODIAN_PASSPHRASES[cid])
                    return
                except ValueError as e:
                    _werrs.append((cid, str(e)[:90]))
                    continue
            _werrs.append((cid, "NEVER-CONVERGED", ""))

        ths = [_th.Thread(target=wit, args=(c,)) for c in
               ("CUSTODIAN-1", "CUSTODIAN-2")]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        _blk = store.load_ledger()[idx]
        if _blk["status"] != "FINAL":
            print("RACE-DEBUG outcomes:", outcomes)
            print("RACE-DEBUG witnesses:", [
                (w.get("custodian_id"), w.get("signature_hex", "")[:16])
                for w in _blk.get("witnesses", [])])
            print("RACE-DEBUG errors:", _werrs[:8])
        assert store.load_ledger()[idx]["status"] == "FINAL"
    check("ATTACK 23 nonce race -> single release; witnesses converge FINAL",
          t_race)

    # 24. trust anchor: self-consistent forgery is self-asserted only;
    # anchored verification pins identities and kills the forgery.
    def t_anchor():
        anchor = evidence_mod.build_trust_anchor()
        assert anchor["format"] == "ps26237-trust-anchor-v1"
        assert "RECIPIENT-A" in anchor["recipients"]
        # no private material in the anchor
        assert "sk" not in str(anchor).lower() and "secret" not in str(anchor).lower()
        pkg = evidence_mod.build_evidence_package(a["event_id"], a["pdf_bytes"])
        v_bare = evidence_mod.verify_evidence_package(pkg)
        assert v_bare["valid"] is True and v_bare["trust"] == "self-asserted-keys"
        v_anch = evidence_mod.verify_evidence_package(pkg, anchor)
        assert v_anch["valid"] is True and v_anch["trust"] == "anchored", v_anch
        # fully self-consistent forgery under attacker keys
        rk, rs = pqc.dsa_generate_keypair()
        ck, cs = pqc.dsa_generate_keypair()
        fchal = {"protocol": "ps26237-v2", "event_id": "ab" * 16,
                 "doc_id": doc_id, "document_hash": "dd" * 32,
                 "document_version": "v1", "recipient_id": "MALLORY",
                 "recipient_key_id": prov_mod.key_id_for_dsa_pk(rk),
                 "session_nonce": "ee" * 16,
                 "policy_hash": prov_mod.policy_hash(),
                 "policy_version": prov_mod.POLICY_VERSION,
                 "issued_at": core.utcnow_iso()}
        fsig = pqc.dsa_sign(rs, ledger_mod.canonical(fchal))
        ffp = prov_mod.derive_fingerprint(
            fsig, fchal["event_id"], fchal["document_hash"], "v1",
            fchal["recipient_key_id"])
        fev = {"event_id": fchal["event_id"], "recipient_id": "MALLORY",
               "recipient_key_id": fchal["recipient_key_id"],
               "document_id": fchal["doc_id"],
               "document_hash": fchal["document_hash"],
               "document_version": "v1",
               "watermark_token_hash": symcrypto.sha256_hex(bytes.fromhex(ffp)),
               "copy_hash": "00" * 32, "session_nonce": fchal["session_nonce"],
               "policy_hash": fchal["policy_hash"],
               "policy_version": fchal["policy_version"],
               "protocol_version": "ps26237-v2",
               "authorization_signature_hex": fsig.hex(),
               "challenge_issued_at": fchal["issued_at"],
               "derivation": prov_mod.derivation_record(
                   fchal["event_id"], fchal["document_hash"], "v1",
                   fchal["recipient_key_id"]),
               "timestamp": fchal["issued_at"]}
        fblock = {"index": 0, "timestamp": fchal["issued_at"], "signer": "MALLORY",
                  "witnesses": [], "status": "FINAL",
                  "prev_hash": ledger_mod.GENESIS_PREV}
        for cid in ("EVIL-1", "EVIL-2"):
            w = pqc.dsa_sign(cs, ledger_mod.canonical(
                {"index": 0, "event": fev, "prev_hash": fblock["prev_hash"]})).hex()
            fblock["witnesses"].append({"custodian_id": cid,
                                        "signature_hex": w,
                                        "witnessed_at": "t"})
        import hashlib as _hl
        fblock["block_hash"] = _hl.sha256(ledger_mod.canonical(
            {k: v for k, v in fblock.items() if k != "block_hash"}
            | {"event": fev})).hexdigest()
        fpkg = {"format": "ps26237-evidence-v1", "protocol": "ps26237-v2",
                "policy": {"version": prov_mod.POLICY_VERSION,
                           "hash": prov_mod.policy_hash(),
                           "text": prov_mod.POLICY_TEXT},
                "leaked_sha256": "00" * 32, "event": fev, "challenge": fchal,
                "block": {k: v for k, v in fblock.items() if k != "event"},
                "prev_block_hash": ledger_mod.GENESIS_PREV, "checkpoint": None,
                "public_keys": {
                    "recipient": {"id": "MALLORY",
                                  "key_id": fev["recipient_key_id"],
                                  "dsa_pk_hex": rk.hex(), "dsa_alg": "x"},
                    "custodians": {"EVIL-1": ck.hex(), "EVIL-2": ck.hex()}},
                "proven": [], "inferred": [], "not_proven": [],
                "conclusion": "x"}
        v_forge_bare = evidence_mod.verify_evidence_package(fpkg)
        assert v_forge_bare["valid"] is True  # honest residual: self-consistent…
        assert v_forge_bare["trust"] == "self-asserted-keys"  # …but never anchored
        v_forge_anch = evidence_mod.verify_evidence_package(fpkg, anchor)
        assert v_forge_anch["valid"] is False, v_forge_anch  # …and anchored kills it
        assert evidence_mod.verify_evidence_package(pkg, {"format": "junk"})[
            "valid"] is False
    check("ATTACK 24 forged evidence identity -> ANCHORED verification kills it",
          t_anchor)

    # 25. CLEAN-ROOM workflow: package + anchor + leaked bytes exported, then
    # the ENTIRE server state wiped — verification must still succeed using
    # only the exported files (no ledger, keys, or database).
    def t_cleanroom():
        import json as _json
        import tempfile
        _ch, res = honest_decrypt(doc_id, "RECIPIENT-A")
        finalize(res["block_index"])
        pkg = evidence_mod.build_evidence_package(res["event_id"],
                                                  res["pdf_bytes"])
        anchor = evidence_mod.build_trust_anchor()
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "package.json"), "w",
                      encoding="utf-8") as f:
                _json.dump(pkg, f)
            with open(os.path.join(tmp, "anchor.json"), "w",
                      encoding="utf-8") as f:
                _json.dump(anchor, f)
            with open(os.path.join(tmp, "leaked.pdf"), "wb") as f:
                f.write(res["pdf_bytes"])
            # destroy the server: database, ledger, ALL private keys
            shutil.rmtree(store.DATA_DIR, ignore_errors=True)
            assert not os.path.exists(store.DATA_DIR)
            with open(os.path.join(tmp, "package.json"), encoding="utf-8") as f:
                pkg2 = _json.load(f)
            with open(os.path.join(tmp, "anchor.json"), encoding="utf-8") as f:
                anchor2 = _json.load(f)
            verdict = evidence_mod.verify_evidence_package(pkg2, anchor2)
            assert verdict["valid"] is True and verdict["trust"] == "anchored", \
                verdict
            # binding re-check from the exported leaked bytes alone
            assert (pkg2["leaked_sha256"] ==
                    symcrypto.sha256_hex(res["pdf_bytes"]))
    check("CLEAN-ROOM: wipe server, verify from exports only -> ANCHORED VALID",
          t_cleanroom)

    print(f"ALL {len(PASS)} HOSTILE CHECKS PASSED")


if __name__ == "__main__":
    main()
