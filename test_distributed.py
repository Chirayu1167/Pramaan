"""Independent custodian-node tests (PRAMAAN distributed audit layer).

Each test states what it proves. Self-contained: fresh state
(init attested identities + independent nodes -> encrypt -> v2 release).

Run:  python3 test_distributed.py
"""
import copy
import io
import os
import shutil

import core
import evidence as evidence_mod
import ledger as ledger_mod
import nodes as nodes_mod
import recipient_client as recipient_client_mod
import store
import symcrypto

PASS = []


def check(name, fn):
    fn()
    PASS.append(name)
    print(f"PASS: {name}")


CTX = {}


def setup():
    shutil.rmtree(store.DATA_DIR, ignore_errors=True)
    store.ensure_dirs()
    core.init_attested_identities()
    nodes_mod.init_nodes()
    nodes_mod.sync_enrollment()
    from demo import make_sample_pdf
    CTX["sample"] = make_sample_pdf()
    enc = core.encrypt_document(CTX["sample"], "nightingale_memo.pdf")
    CTX["doc_id"] = enc["doc_id"]
    ch = core.create_decrypt_challenge(enc["doc_id"], "RECIPIENT-A")
    sig = recipient_client_mod.authorize_challenge(
        ch, "RECIPIENT-A", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-A"])
    res = core.complete_attested_decryption(ch, sig.hex())
    CTX["copy"] = res
    assert res["status"] == "PENDING"


def req_for(index, cid):
    req = nodes_mod.build_witness_request(store.load_ledger(), index)
    req["custodian_id"] = cid
    return req


def wit(cid, index=0):
    return nodes_mod.witness_request(
        req_for(index, cid), cid, nodes_mod.NODE_PASSPHRASES[cid])


def main() -> None:
    setup()
    A, B = "CUSTODIAN-1", "CUSTODIAN-2"

    # 1-2. each independent node validates + signs
    def t_node_a():
        r = wit(A)
        assert r["format"] == nodes_mod.RECEIPT_FORMAT
        assert r["receipt"]["custodian_id"] == A
        assert r["receipt"]["seq"] == 0
        assert len(r["proof"]) >= 0 and r["checkpoint"]["tip_event_hash"] == \
            r["receipt"]["event_hash"]
        CTX["r1"] = r
    check("1. node A independently validates event, signs receipt+checkpoint+proof",
          t_node_a)

    def t_node_b():
        r = wit(B)
        assert r["receipt"]["custodian_id"] == B
        assert r["signature_hex"] != CTX["r1"]["signature_hex"]
        CTX["r2"] = r
    check("2. node B validates the same event from its own state, distinct signature",
          t_node_b)

    # 3. unknown custodian rejected
    def t_unknown():
        try:
            nodes_mod.witness_request(req_for(0, "CUSTODIAN-X"), "CUSTODIAN-X",
                                      "nope")
        except (ValueError, FileNotFoundError):
            return
        raise AssertionError("unknown node must be rejected")
    check("3. unknown custodian node rejected", t_unknown)

    # 4. duplicate witness (replay) rejected by the node itself
    def t_dup():
        try:
            wit(A)
        except ValueError as e:
            assert "duplicate" in str(e).lower() or "replay" in str(e).lower(), e
            return
        raise AssertionError("duplicate witness must be rejected")
    check("4. same node cannot witness the same event twice (replay refused)",
          t_dup)

    # 5. forged witness signature rejected at aggregation
    def t_forged():
        bad = copy.deepcopy(CTX["r1"])
        raw = bytearray(bytes.fromhex(bad["signature_hex"]))
        raw[0] ^= 0xFF
        bad["signature_hex"] = bytes(raw).hex()
        try:
            nodes_mod.aggregate_receipts(store.load_ledger(), 0, [bad, CTX["r2"]])
        except ValueError as e:
            assert "forged" in str(e).lower() or "invalid" in str(e).lower(), e
            return
        raise AssertionError("forged witness must be rejected")
    check("5. forged witness signature rejected (no FINAL on forgery)", t_forged)

    # 6. one witness stays PENDING
    def t_single_pending():
        try:
            nodes_mod.aggregate_receipts(store.load_ledger(), 0, [CTX["r1"]])
        except ValueError as e:
            assert "PENDING" in str(e) or "quorum" in str(e).lower(), e
            assert store.load_ledger()[0]["status"] == "PENDING"
            return
        raise AssertionError("single witness must not finalize")
    check("6. one valid witness leaves the block PENDING", t_single_pending)

    # 7. two independent witnesses -> FINAL
    def t_final():
        blk = nodes_mod.aggregate_receipts(store.load_ledger(), 0,
                                            [CTX["r1"], CTX["r2"]])
        assert blk["status"] == "FINAL", blk
        ok, msg = ledger_mod.verify_ledger(store.load_ledger(),
                                           store.load_recipients(),
                                           store.load_custodians())
        assert ok, msg
    check("7. two independent node witnesses finalize the block (chain valid)",
          t_final)

    # 8. no double finalization
    def t_no_double():
        try:
            nodes_mod.aggregate_receipts(store.load_ledger(), 0,
                                         [CTX["r1"], CTX["r2"]])
        except ValueError as e:
            assert "twice" in str(e).lower() or "already FINAL" in str(e), e
            return
        raise AssertionError("double finalization must be refused")
    check("8. same event cannot be finalized twice", t_no_double)

    # 9. altered event invalidates witness
    def t_altered_event():
        ch = core.create_decrypt_challenge(CTX["doc_id"], "RECIPIENT-B")
        sig = recipient_client_mod.authorize_challenge(
            ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        res = core.complete_attested_decryption(ch, sig.hex())
        idx = res["block_index"]
        ra = nodes_mod.witness_request(
            req_for(idx, A), A, nodes_mod.NODE_PASSPHRASES[A])
        rb = nodes_mod.witness_request(
            req_for(idx, B), B, nodes_mod.NODE_PASSPHRASES[B])
        bad_chain = copy.deepcopy(store.load_ledger())
        bad_chain[idx]["event"]["timestamp"] = "2000-01-01T00:00:00+00:00"
        try:
            nodes_mod.aggregate_receipts(bad_chain, idx, [ra, rb])
        except ValueError as e:
            assert "mismatch" in str(e).lower() or "different event" in str(e).lower(), e
            # the honest receipts still finalize the untampered block
            blk = nodes_mod.aggregate_receipts(store.load_ledger(), idx, [ra, rb])
            assert blk["status"] == "FINAL"
            return
        raise AssertionError("altered event must invalidate witnesses")
    check("9. altered event invalidates node receipts (hash mismatch)", t_altered_event)

    # 10. altered checkpoint rejected
    def t_altered_cp():
        bad = copy.deepcopy(CTX["r1"])
        bad["checkpoint"]["tip_event_hash"] = "00" * 32
        ok, reason = nodes_mod.verify_receipt_package(bad)
        assert ok is False, reason
    check("10. altered checkpoint detected (receipt/checkpoint consistency)",
          t_altered_cp)

    # 11. rollback refused + conflict detected
    def t_rollback():
        cp_now = store.load_node_checkpoint(A)
        assert isinstance(cp_now, dict) and cp_now["seq"] >= 1
        # identical re-import is idempotent
        assert nodes_mod.import_checkpoint(A, copy.deepcopy(cp_now)) == "imported"
        # a genuinely-signed older checkpoint from history -> stale, refused
        older = None
        for h in cp_now.get("history", []):
            if isinstance(h, dict) and h.get("seq") == cp_now["seq"] - 1:
                older = copy.deepcopy(h)
        assert older is not None, "history must hold the prior checkpoint"
        assert nodes_mod.check_stale_or_conflict(A, older) == "stale"
        try:
            nodes_mod.import_checkpoint(A, older)
        except ValueError as e:
            assert "stale" in str(e).lower(), e
        else:
            raise AssertionError("rollback import must be refused")
        # same seq, different root -> conflict detector fires (unsigned
        # forgeries die earlier on signature; this tests the comparison)
        conflict = copy.deepcopy(cp_now)
        conflict["state_root"] = "ab" * 32
        assert nodes_mod.check_stale_or_conflict(A, conflict) == "conflict"
        ok, msg = nodes_mod.verify_checkpoint_history(A)
        assert ok, msg
    check("11. stale/conflicting checkpoints refused, history linkage holds",
          t_rollback)

    # 12. missing witness evidence detected
    def t_missing():
        try:
            nodes_mod.aggregate_receipts(store.load_ledger(), 0, [])
        except ValueError:
            pass
        else:
            raise AssertionError("empty receipts must be refused")
        try:
            evidence_mod.build_evidence_package(
                CTX["copy"]["event_id"], b"pending-bytes")
            # block 0 is FINAL now, so build with garbage bytes still works
            # structurally; the missing-witness case is the PENDING proposal:
            ch = core.create_decrypt_challenge(CTX["doc_id"], "RECIPIENT-B")
            sig = recipient_client_mod.authorize_challenge(
                ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
            pend = core.complete_attested_decryption(ch, sig.hex())
            CTX["pend_idx"] = pend["block_index"]
            try:
                evidence_mod.build_evidence_package(pend["event_id"],
                                                    pend["pdf_bytes"])
            except ValueError as e:
                assert "FINAL" in str(e), e
                return
            raise AssertionError("PENDING event must have no evidence package")
        except AssertionError:
            raise
    check("12. missing witness evidence detected (empty receipts, PENDING package refused)",
          t_missing)

    # 13. conflicting roots detected (covered in 11; here cross-node sanity)
    def t_roots():
        assert CTX["r1"]["receipt"]["state_root"] != "0" * 64
        assert CTX["r2"]["receipt"]["state_root"] != "0" * 64
        # each node's root is its own log: both witnessed 1 event each, so
        # roots are single-leaf hashes of the same event hash -> equal here,
        # but the aggregator never equates them; it verifies each receipt.
        ok1, _ = nodes_mod.verify_receipt_package(CTX["r1"])
        ok2, _ = nodes_mod.verify_receipt_package(CTX["r2"])
        assert ok1 and ok2
    check("13. per-node state roots verify independently (no forced equality)",
          t_roots)

    # 14. file export/import round-trip works offline
    def t_export():
        tmp = os.path.join(store.DATA_DIR, "xchg")
        os.makedirs(tmp, exist_ok=True)
        rq_path = os.path.join(tmp, "req.json")
        nodes_mod.export_package(
            nodes_mod.build_witness_request(store.load_ledger(), CTX["pend_idx"]),
            rq_path)
        rq2 = nodes_mod.import_package(rq_path)
        assert rq2["format"] == nodes_mod.REQUEST_FORMAT
        rc_path = os.path.join(tmp, "receipt.json")
        nodes_mod.export_package(CTX["r1"], rc_path)
        r2 = nodes_mod.import_package(rc_path)
        assert r2["signature_hex"] == CTX["r1"]["signature_hex"]
        try:
            nodes_mod.import_package(os.path.join(tmp, "nope.json"))
        except ValueError:
            return
        raise AssertionError("missing package must be refused")
    check("14. deterministic file export/import works offline (Model B)", t_export)

    # 15. clean-room from exported evidence only
    def t_cleanroom():
        pkg = evidence_mod.build_evidence_package(CTX["copy"]["event_id"],
                                                  CTX["copy"]["pdf_bytes"])
        assert len(pkg.get("node_receipts", [])) == 2
        anchor = evidence_mod.build_trust_anchor()
        assert "nodes" in anchor and len(anchor["nodes"]) == 3
        verdict = evidence_mod.verify_evidence_package(copy.deepcopy(pkg), anchor)
        assert verdict["valid"] is True and verdict["trust"] == "anchored", verdict
        # tamper the packaged event -> detected without any server state
        bad = copy.deepcopy(pkg)
        bad["event"]["timestamp"] = "2001-02-03T00:00:00+00:00"
        v2 = evidence_mod.verify_evidence_package(bad, anchor)
        assert v2["valid"] is False, v2
    check("15. clean-room verify from exports only; tampered event detected",
          t_cleanroom)

    # 16. single-node compromise cannot forge FINAL
    def t_compromise():
        forged = copy.deepcopy(CTX["r2"])
        forged["node"]["dsa_pk_hex"] = CTX["r1"]["node"]["dsa_pk_hex"]
        forged["receipt"]["custodian_id"] = "CUSTODIAN-1"
        try:
            nodes_mod.aggregate_receipts(store.load_ledger(), 0,
                                         [CTX["r1"], forged])
        except ValueError:
            assert store.load_ledger()[0]["status"] == "FINAL"  # unchanged history
            # now the real negative: one honest + one forged on a NEW event
            ch = core.create_decrypt_challenge(CTX["doc_id"], "RECIPIENT-C")
            sig = recipient_client_mod.authorize_challenge(
                ch, "RECIPIENT-C", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-C"])
            res = core.complete_attested_decryption(ch, sig.hex())
            idx = res["block_index"]
            rq = req_for(idx, A)
            honest = nodes_mod.witness_request(
                rq, A, nodes_mod.NODE_PASSPHRASES[A])
            fake = copy.deepcopy(honest)
            fake["receipt"]["custodian_id"] = "CUSTODIAN-3"
            try:
                nodes_mod.aggregate_receipts(store.load_ledger(), idx,
                                             [honest, fake])
            except ValueError:
                assert store.load_ledger()[idx]["status"] == "PENDING"
                return
            raise AssertionError("forged second witness must not finalize")
        raise AssertionError("substituted node key must be rejected")
    check("16. one compromised node cannot manufacture 2-of-3 FINAL", t_compromise)

    # 17. recipient authorization still works
    def t_auth():
        ch = core.create_decrypt_challenge(CTX["doc_id"], "RECIPIENT-B")
        sig = recipient_client_mod.authorize_challenge(
            ch, "RECIPIENT-B", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-B"])
        res = core.complete_attested_decryption(ch, sig.hex())
        assert res["status"] == "PENDING" and res["recipient_id"] == "RECIPIENT-B"
        CTX["b_copy"] = res
    check("17. recipient authorization ceremony still works", t_auth)

    # 18. watermark investigation still works
    def t_wm():
        res = core.investigate_leak_v2(CTX["b_copy"]["pdf_bytes"])
        assert res["match"] is False  # PENDING block: refused, honestly
        inv = core.investigate_leak_v2(CTX["copy"]["pdf_bytes"])
        assert inv["match"] is True and inv["status"] == "VERIFIED", inv
    check("18. watermark investigation intact (FINAL verifies, PENDING refused)",
          t_wm)

    # 19. screenshot investigation still works
    def t_shot():
        import latticemark as lattice_mod
        img = lattice_mod.rasterize_pdf_page(CTX["copy"]["pdf_bytes"], 0, zoom=1.5)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=75)
        res = core.investigate_screenshot(buf.getvalue())
        assert res["match"] is True and res.get("binding") == "ANALOG-HOLE", res
    check("19. screenshot investigation intact (ANALOG-HOLE VERIFIED)", t_shot)

    # 20. revocation blocks future, preserves past
    def t_revoke():
        import custodians as custodians_mod
        core.revoke_recipient("RECIPIENT-C", "CUSTODIAN-1",
                              custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-1"])
        try:
            core.create_decrypt_challenge(CTX["doc_id"], "RECIPIENT-C")
        except ValueError as e:
            assert "revoked" in str(e).lower(), e
            inv = core.investigate_leak_v2(CTX["copy"]["pdf_bytes"])
            assert inv["match"] is True, inv
            return
        raise AssertionError("revoked recipient must be blocked")
    check("20. revocation blocks future release, preserves old verification",
          t_revoke)

    print(f"ALL {len(PASS)} DISTRIBUTED CHECKS PASSED")


if __name__ == "__main__":
    main()
