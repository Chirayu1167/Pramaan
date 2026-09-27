"""Hostile SIH demo for PRAMAAN v2 over independent custodian nodes.

NOT "look, we encrypted a PDF". Every step is an attack that fails plus the
one honest path that verifies — with witnessing done by INDEPENDENT nodes
(separate dirs/keys/state, own enrollment snapshots), not one process
pretending to be three custodians:

  1. Admin fabricates Alice's authorization            -> BLOCKED
  2. Alice authorizes a fresh challenge (own device)   -> VERIFIED, released
  3. Fingerprint transplanted to another document      -> REJECTED (binding)
  4. Node A validates + signs (own state, own key)     -> NOT FINAL
  5. Node B validates + signs; receipts aggregate      -> FINAL
  5b. Screenshot of the copy                           -> VERIFIED / ANALOG-HOLE
  6. One ledger replica modified                        -> INTEGRITY FAILURE
  7. Evidence package moved to clean verifier           -> VERIFIED (anchored)
  8. Revoked recipient tries again                       -> BLOCKED

Run:  python3 demo_attested.py
"""
import copy
import io
import json
import os
import shutil

import core
import custodians as custodians_mod
import evidence as evidence_mod
import ledger as ledger_mod
import nodes as nodes_mod
import pqc
import recipient_client as recipient_client_mod
import store
import watermark
from demo import make_sample_pdf

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "demo_output_attested")


def hostile_demo() -> dict:
    steps: list[dict] = []
    ctx: dict = {}

    def step(name, fn):
        if ctx.get("_failed"):
            steps.append({"name": name, "ok": False,
                          "detail": "skipped (earlier step failed)"})
            return None
        try:
            detail = fn()
            steps.append({"name": name, "ok": True, "detail": detail})
            return detail
        except Exception as e:  # noqa: BLE001 — demo surfaces, never hides
            steps.append({"name": name, "ok": False,
                          "detail": f"{type(e).__name__}: {e}"})
            ctx["_failed"] = f"{type(e).__name__}: {e}"
            return None

    shutil.rmtree(store.DATA_DIR, ignore_errors=True)
    store.ensure_dirs()

    def s0():
        core.init_attested_identities()
        nodes_mod.init_nodes()
        nodes_mod.sync_enrollment()
        enc = core.encrypt_document(make_sample_pdf(), "nightingale_memo.pdf")
        ctx["doc_id"] = enc["doc_id"]
        return (f"3 recipients (separated signing vault) + 3 INDEPENDENT nodes "
                f"(own dirs/keys/state) + doc {enc['doc_id'][:8]} sealed once; "
                f"origin {enc['pc_id']} @ {enc['encrypted_at'][:19]}")
    step("0. Setup: attested identities, custodians, sealed document", s0)

    def s1():
        ch = core.create_decrypt_challenge(ctx["doc_id"], "RECIPIENT-A")
        _, rogue = pqc.dsa_generate_keypair()
        rogue_sig = pqc.dsa_sign(rogue, ledger_mod.canonical(ch))
        try:
            core.complete_attested_decryption(ch, rogue_sig.hex())
        except ValueError as e:
            ctx["challenge"] = ch  # reuse the fresh challenge honestly next
            return f"rejected: {e}"
        raise AssertionError("fabricated authorization was accepted!")
    step("1. ATTACK: admin fabricates Alice's authorization -> BLOCKED", s1)

    def s2():
        ch = ctx["challenge"]
        sig = recipient_client_mod.authorize_challenge(
            ch, "RECIPIENT-A", core.RECIPIENT_SIGN_PASSPHRASES["RECIPIENT-A"])
        res = core.complete_attested_decryption(ch, sig.hex())
        ctx["copy"] = res
        return (f"Alice's device signed session {res['event_id'][:8]}; "
                f"HKDF fingerprint embedded; block {res['block_index']} PENDING")
    step("2. HONEST: Alice authorizes fresh challenge -> released + fingerprinted", s2)

    def s3():
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        import io as _io
        buf = _io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, 720, "CONFIDENTIAL — Unrelated Memo")
        c.setFont("Helvetica", 11)
        c.drawString(72, 690, "Different content for the transplant attack.")
        c.showPage()
        c.save()
        other_doc = buf.getvalue()
        fp = watermark.extract_token(ctx["copy"]["pdf_bytes"])
        transplanted = watermark.embed_token(other_doc, fp)
        res = core.investigate_leak_v2(transplanted)
        # Block still PENDING here, so rejection reason is quorum-pending;
        # after FINAL (step 5b) the same bytes fail on binding. Either way:
        # no attribution without a FINAL + bound match.
        assert res["match"] is False, res
        ctx["transplanted"] = transplanted
        return f"REJECTED: {res.get('reason')}"
    step("3. ATTACK: transplant/modify fingerprinted bytes -> REJECTED", s3)

    def node_witness(cid):
        req = nodes_mod.build_witness_request(store.load_ledger(), 0)
        req["custodian_id"] = cid
        return nodes_mod.witness_request(
            req, cid, nodes_mod.NODE_PASSPHRASES[cid])

    def s4():
        ctx["r1"] = node_witness("CUSTODIAN-1")
        st = store.load_ledger()[0]["status"]
        assert st == "PENDING", st
        res = core.investigate_leak_v2(ctx["copy"]["pdf_bytes"])
        assert res["match"] is False and "PENDING" in res.get("reason", ""), res
        return ("node A validated vs its own enrollment + signed "
                f"(root {ctx['r1']['receipt']['state_root'][:12]}…): "
                "PENDING — investigation refuses (quorum not reached)")
    step("4. Independent node A witnesses -> NOT FINAL", s4)

    def s5():
        ctx["r2"] = node_witness("CUSTODIAN-2")
        blk = nodes_mod.aggregate_receipts(
            store.load_ledger(), 0, [ctx["r1"], ctx["r2"]])
        assert blk["status"] == "FINAL", blk
        # Same transplanted bytes, now against a FINAL ledger: binding decides.
        res = core.investigate_leak_v2(ctx["transplanted"])
        assert res["match"] is False and res.get("binding") == "MISMATCH", res
        ok = core.investigate_leak_v2(ctx["copy"]["pdf_bytes"])
        assert ok["match"] is True and ok["status"] == "VERIFIED", ok
        return ("node B validated + signed; 2 independent receipts -> FINAL; "
                "transplant fails on binding MISMATCH, honest copy VERIFIED")
    step("5. Independent node B witnesses -> FINAL", s5)

    def s5b():
        import latticemark as lattice_mod
        img = lattice_mod.rasterize_pdf_page(ctx["copy"]["pdf_bytes"], 0, zoom=1.5)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=75)
        res = core.investigate_screenshot(buf.getvalue())
        assert res["match"] is True and res.get("binding") == "ANALOG-HOLE", res
        return (f"screenshot blind-decoded ({res['lattice']['tiles_voted']} tiles) "
                f"-> {res['recipient']} VERIFIED / ANALOG-HOLE")
    step("5b. Screenshot of the copy -> VERIFIED / ANALOG-HOLE", s5b)

    def s6():
        bad = copy.deepcopy(store.load_ledger())
        bad[0]["event"]["timestamp"] = "2000-01-01T00:00:00+00:00"
        ok, msg = ledger_mod.verify_ledger(bad, store.load_recipients(),
                                           store.load_custodians())
        assert ok is False, "tamper must be detected"
        return f"INTEGRITY FAILURE: {msg}"
    step("6. ATTACK: modify one ledger replica -> detected", s6)

    def s7():
        pkg = evidence_mod.build_evidence_package(ctx["copy"]["event_id"],
                                                  ctx["copy"]["pdf_bytes"])
        verdict = evidence_mod.verify_evidence_package(copy.deepcopy(pkg))
        assert verdict["valid"] is True, verdict
        assert verdict["trust"] == "self-asserted-keys", verdict
        # Pin to the enrollment trust anchor: self-forged "MALLORY" packages
        # die here even though they are internally self-consistent.
        anchor = evidence_mod.build_trust_anchor()
        anchored = evidence_mod.verify_evidence_package(copy.deepcopy(pkg),
                                                        anchor)
        assert anchored["valid"] is True and anchored["trust"] == "anchored", \
            anchored
        os.makedirs(os.path.join(ARTIFACTS_DIR, "evidence"), exist_ok=True)
        with open(os.path.join(ARTIFACTS_DIR, "evidence",
                               "evidence_package.json"), "w",
                  encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
        with open(os.path.join(ARTIFACTS_DIR, "evidence",
                               "trust_anchor.json"), "w",
                  encoding="utf-8") as f:
            json.dump(anchor, f, indent=2)
        with open(os.path.join(ARTIFACTS_DIR, "evidence",
                               "forensic_report.txt"), "w",
                  encoding="utf-8") as f:
            f.write(evidence_mod.forensic_report_text(
                {"match": True, "valid": True,
                 "recipient": pkg["event"]["recipient_id"],
                 "event_id": pkg["event"]["event_id"],
                 "proven": pkg["proven"], "not_proven": pkg["not_proven"],
                 "conclusion": pkg["conclusion"]}))
        ctx["pkg"] = pkg
        return ("clean-room re-verify from package contents alone: "
                "authorization VALID + derivation VALID + quorum FINAL-2OF3; "
                "anchored to enrollment registry (forgeries stay self-asserted)")
    step("7. Evidence package -> clean verifier VERIFIED", s7)

    def s8():
        core.revoke_recipient(
            "RECIPIENT-A", "CUSTODIAN-1",
            custodians_mod.CUSTODIAN_PASSPHRASES["CUSTODIAN-1"])
        try:
            core.create_decrypt_challenge(ctx["doc_id"], "RECIPIENT-A")
        except ValueError as e:
            res = core.investigate_leak_v2(ctx["copy"]["pdf_bytes"])
            assert res["match"] is True, res  # history still verifies
            return f"BLOCKED: {e}; prior FINAL event still VERIFIED"
        raise AssertionError("revoked recipient obtained a challenge!")
    step("8. Revoked Alice tries again -> BLOCKED (history intact)", s8)

    if ctx.get("_failed"):
        return {"ok": False, "steps": steps, "error": ctx["_failed"]}
    closing = ("Authorized decryption event cryptographically verified. "
               "Physical leak attribution is not established.")
    return {"ok": True, "steps": steps, "closing": closing,
            "artifacts": ["evidence/evidence_package.json",
                          "evidence/trust_anchor.json",
                          "evidence/forensic_report.txt"]}


def main() -> None:
    out = hostile_demo()
    for s in out["steps"]:
        print(f"[{'ok' if s['ok'] else 'FAIL'}] {s['name']}: {s['detail']}")
    if not out.get("ok"):
        raise SystemExit(f"HOSTILE DEMO FAILED: {out.get('error')}")
    print()
    print(out["closing"])
    print("Artifacts:", out["artifacts"])
    print("HOSTILE DEMO COMPLETE — every attack blocked, honest path verified.")


if __name__ == "__main__":
    main()
