"""End-to-end BASE MVP demo (spec steps 1-14) + tamper-detection proof.

Run:  python demo.py
Then optionally:  python app.py  (local UI on http://127.0.0.1:5000)

`run_demo()` is also called by the web UI's "RUN FULL DEMO" button, so the
CLI and the UI execute exactly the same logic. It never hides errors: every
step records ok/detail, and any exception is captured on that step.
"""
import io
import json
import os
import shutil

import core
import ledger as ledger_mod
import store
import symcrypto
import watermark
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_output")


def make_sample_pdf() -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 720, "CONFIDENTIAL — Project Nightingale Memo")
    c.setFont("Helvetica", 11)
    lines = [
        "This is a sample sensitive document for the PS26237 MVP demo.",
        "It is encrypted once and shared with three demo recipients.",
        "Each decryption produces a uniquely watermarked, signed copy.",
        "If a copy leaks, the watermark identifies the decryption event.",
    ]
    y = 690
    for ln in lines:
        c.drawString(72, y, ln)
        y -= 18
    c.showPage()
    c.save()
    return buf.getvalue()


def forensic_text(res: dict) -> str:
    """Judge-ready forensic report text (Task 3 format)."""
    if not res.get("match"):
        return ("FORENSIC RESULT\n\nStatus: NOT VERIFIED\n"
                f"Reason: {res.get('reason', 'no verified match')}\n\n"
                "Conclusion: No verified decryption event matches this file.\n")
    lines = [
        "FORENSIC MATCH",
        "",
        f"Status: {res['status']}",
        f"Recipient: {res['recipient']}",
        f"Event ID: {res['event_id']}",
        f"Document Hash: {res['document_hash']}",
        f"Timestamp: {res['timestamp']}",
        "",
        f"Watermark: {res['watermark']}",
        f"ML-DSA Signature: {res['mldsa_signature']}",
        f"Ledger Integrity: {res['ledger_integrity']}",
        "",
        "Conclusion:",
        res["conclusion"],
        "",
        "Scope — cryptographic vs physical attribution:",
        "- " + res["scope"]["cryptographic_attribution"],
        "- " + res["scope"]["physical_attribution"],
        "",
    ]
    return "\n".join(lines)


def write_demo_artifacts(doc: dict, a: dict, b: dict, forensic: dict) -> dict:
    """Write judge-friendly artifacts. Never includes private keys."""
    enc_dir = os.path.join(ARTIFACTS_DIR, "encrypted")
    dec_dir = os.path.join(ARTIFACTS_DIR, "decrypted")
    inv_dir = os.path.join(ARTIFACTS_DIR, "investigation")
    led_dir = os.path.join(ARTIFACTS_DIR, "ledger")
    for d in (enc_dir, dec_dir, inv_dir, led_dir):
        os.makedirs(d, exist_ok=True)
    docs = store.load_documents()
    stored = docs[doc["doc_id"]]
    ct = store.load_blob(stored["ciphertext_file"])
    with open(os.path.join(enc_dir, "document_ciphertext.bin"), "wb") as f:
        f.write(ct)
    with open(os.path.join(enc_dir, "document.json"), "w", encoding="utf-8") as f:
        json.dump({"doc_id": doc["doc_id"], "filename": stored["filename"],
                   "document_hash": stored["document_hash"],
                   "cipher": "AES-256-GCM (single ciphertext for all recipients)",
                   "key_access": "one ML-KEM-768 envelope per recipient",
                   "envelopes": sorted(stored["envelopes"])}, f, indent=2)
    fa = os.path.join(dec_dir, f"RECIPIENT-A_{a['event_id'][:8]}.pdf")
    fb = os.path.join(dec_dir, f"RECIPIENT-B_{b['event_id'][:8]}.pdf")
    with open(fa, "wb") as f:
        f.write(a["pdf_bytes"])
    with open(fb, "wb") as f:
        f.write(b["pdf_bytes"])
    with open(os.path.join(inv_dir, "forensic_report.json"), "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in forensic.items()}, f, indent=2)
    with open(os.path.join(inv_dir, "forensic_report.txt"), "w", encoding="utf-8") as f:
        f.write(forensic_text(forensic))
    with open(os.path.join(led_dir, "ledger.json"), "w", encoding="utf-8") as f:
        json.dump(store.load_ledger(), f, indent=2)
    return {"encrypted": enc_dir, "decrypted": dec_dir,
            "investigation": inv_dir, "ledger": led_dir}


def run_demo() -> dict:
    """Execute the full demo flow. Returns steps + results (errors captured per step)."""
    steps: list[dict] = []

    def step(name, fn):
        if ctx.get("_failed"):
            steps.append({"name": name, "ok": False, "detail": "skipped (earlier step failed)"})
            return None
        try:
            detail = fn()
            steps.append({"name": name, "ok": True, "detail": detail})
            return detail
        except Exception as e:  # noqa: BLE001 — demo must surface, not hide, errors
            steps.append({"name": name, "ok": False, "detail": f"{type(e).__name__}: {e}"})
            ctx["_failed"] = f"{type(e).__name__}: {e}"
            return None

    # fresh state for a reproducible demo
    shutil.rmtree(store.DATA_DIR, ignore_errors=True)
    store.ensure_dirs()
    ctx: dict = {}

    def s1():
        recips = core.init_demo_recipients()
        assert sorted(recips) == ["RECIPIENT-A", "RECIPIENT-B", "RECIPIENT-C"]
        return "recipients: RECIPIENT-A, RECIPIENT-B, RECIPIENT-C (ML-KEM-768 + ML-DSA-65)"
    step("1. Initialize RECIPIENT-A/B/C", s1)

    def s2():
        ctx["sample"] = make_sample_pdf()
        enc = core.encrypt_document(ctx["sample"], "nightingale_memo.pdf")
        ctx["doc_id"] = enc["doc_id"]
        ctx["enc"] = enc
        assert len(enc["recipients"]) == 3
        return f"encrypted once: doc {enc['doc_id'][:8]}… hash {enc['document_hash'][:16]}…"
    step("2-3. Create sample PDF + encrypt once", s2)

    def s3():
        a = core.decrypt_for_recipient(ctx["doc_id"], "RECIPIENT-A")
        ctx["a"] = a
        return f"A: event {a['event_id'][:8]}… block {a['block_index']}"
    step("4-5. Decrypt as RECIPIENT-A (watermark A + ML-DSA + ledger)", s3)

    def s4():
        b = core.decrypt_for_recipient(ctx["doc_id"], "RECIPIENT-B")
        ctx["b"] = b
        return f"B: event {b['event_id'][:8]}… block {b['block_index']}"
    step("6-7. Decrypt as RECIPIENT-B (watermark B + ML-DSA + ledger)", s4)

    def s5():
        a, b = ctx["a"], ctx["b"]
        ta = watermark.extract_token(a["pdf_bytes"])
        tb = watermark.extract_token(b["pdf_bytes"])
        assert ta and tb, "watermark extraction failed on generated PDFs"
        ctx["ta"], ctx["tb"] = ta, tb
        assert ta != tb, "watermarks must differ"
        return f"watermark_A={ta[:12]}… watermark_B={tb[:12]}… (differ)"
    step("8. Extract watermarks, verify A != B", s5)

    def s6():
        a, b = ctx["a"], ctx["b"]
        assert a["event_id"] != b["event_id"], "event IDs must differ"
        assert a["signature_hex"] != b["signature_hex"], "signatures must differ"
        ctx["uniq"] = {"watermarks_differ": ctx["ta"] != ctx["tb"],
                       "events_differ": True, "signatures_differ": True}
        return "event_A != event_B, signature_A != signature_B"
    step("9. Verify events/signatures differ", s6)

    def s7():
        res = core.investigate_leak(ctx["a"]["pdf_bytes"])
        assert res["match"] is True, res
        assert res["recipient"] == "RECIPIENT-A", res
        assert res["event_id"] == ctx["a"]["event_id"], res
        ctx["forensic"] = res
        return f"FORENSIC MATCH -> {res['recipient']} (event {res['event_id'][:8]}…)"
    step("10. Investigate A's leaked copy -> RECIPIENT-A", s7)

    def s8():
        ok, msg = ledger_mod.verify_ledger(store.load_ledger(), store.load_recipients())
        assert ok, msg
        return msg
    step("11. Verify ledger integrity", s8)

    def s9():
        tampered = [dict(b, event=dict(b["event"])) for b in store.load_ledger()]
        tampered[0]["event"]["recipient_id"] = "RECIPIENT-C"  # attacker edit, no re-sign
        ok, msg = ledger_mod.verify_ledger(tampered, store.load_recipients())
        assert ok is False, "tamper must be detected"
        ctx["tamper"] = {"verified_after_tamper": ok, "detail": msg}
        return f"tamper detected: {msg}"
    step("12. Tamper-detection proof (in-memory copy; disk ledger untouched)", s9)

    def s10():
        arts = write_demo_artifacts(ctx["enc"], ctx["a"], ctx["b"], ctx["forensic"])
        return f"demo_output/ ({', '.join(sorted(arts))})"
    step("13. Write demo_output artifacts", s10)

    if ctx.get("_failed"):
        return {"ok": False, "steps": steps, "error": ctx["_failed"]}
    return {"ok": True, "steps": steps,
            "doc_id": ctx["doc_id"], "event_a": ctx["a"]["event_id"],
            "event_b": ctx["b"]["event_id"],
            "uniqueness": ctx["uniq"],
            "forensic": ctx["forensic"],
            "forensic_text": forensic_text(ctx["forensic"]),
            "tamper": ctx["tamper"],
            "artifacts": {"dirs": ["encrypted", "decrypted", "investigation", "ledger"]}}


def main() -> None:
    out = run_demo()
    for s in out["steps"]:
        mark = "ok" if s["ok"] else "FAIL"
        print(f"[{mark}] {s['name']}: {s['detail']}")
    if not out.get("ok"):
        raise SystemExit(f"DEMO FAILED at step: "
                         f"{[s for s in out['steps'] if not s['ok']][-1]}")
    print()
    print(forensic_text(out["forensic"]))
    print("Uniqueness: watermark_A != watermark_B:",
          out["uniqueness"]["watermarks_differ"],
          "| event_A != event_B:", out["uniqueness"]["events_differ"],
          "| sig_A != sig_B:", out["uniqueness"]["signatures_differ"])
    print("Tamper proof:", out["tamper"]["verified_after_tamper"],
          "|", out["tamper"]["detail"])
    print("Artifacts:", out["artifacts"])
    print("DEMO COMPLETE — all checks passed.")


if __name__ == "__main__":
    main()
