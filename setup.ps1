# PS26237 UI redesign — PowerShell version.
# Run this from inside your PS26237-MVP project root (the folder containing core.py, ledger.py, store.py, etc.)
# It creates/overwrites: app.py, templates\index.html, static\css\app.css, static\js\app.js
# Backend modules (core.py, ledger.py, store.py, pqc.py, symcrypto.py, watermark.py, demo.py) are untouched.

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path "templates" | Out-Null
New-Item -ItemType Directory -Force -Path "static\css" | Out-Null
New-Item -ItemType Directory -Force -Path "static\js" | Out-Null

$appPy = @'
"""Local web UI for the PS26237 BASE MVP. Runs fully offline (Flask, no CDN)."""
import io
import re

from flask import Flask, jsonify, request, send_file, render_template

import core
import demo as demo_mod
import ledger as ledger_mod
import store

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

LAST_INVESTIGATION: dict | None = None  # in-memory only, reset on restart
_HEX32 = re.compile(r"^[0-9a-f]{32}$")

@app.get("/")
def index():
    return render_template("index.html")


def last_inv_summary():
    if LAST_INVESTIGATION is None:
        return None
    return {"match": LAST_INVESTIGATION.get("match"),
            "recipient": LAST_INVESTIGATION.get("recipient"),
            "status": LAST_INVESTIGATION.get("status")}


@app.get("/api/status")
def status():
    try:
        recips = core.public_recipients()
        docs = store.load_documents()
        chain = store.load_ledger()
        ok, msg = ledger_mod.verify_ledger(chain, recips) if chain else (True, "ledger empty")
        return jsonify({
            "recipients": sorted(recips),
            "documents": [{"doc_id": d["doc_id"], "filename": d["filename"],
                           "document_hash": d["document_hash"]} for d in docs.values()],
            "decryption_events": len(chain),
            "ledger_valid": ok, "ledger_detail": msg,
            "last_investigation": last_inv_summary(),
        })
    except Exception as e:
        # e.g. corrupted JSON on disk: report as JSON, never an HTML 500 page
        return jsonify({"error": f"status unavailable: {type(e).__name__}: {e}"}), 500


@app.post("/api/init")
def init():
    try:
        return jsonify({"recipients": sorted(core.init_demo_recipients())})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/encrypt")
def encrypt():
    try:
        f = request.files.get("file")
        if f is None:
            return jsonify({"error": "no file uploaded"}), 400
        data = f.read()
        return jsonify(core.encrypt_document(data, f.filename or "document.pdf"))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/decrypt")
def decrypt():
    try:
        body = request.get_json(force=True)
        doc_id, recipient_id = body.get("doc_id"), body.get("recipient_id")
        if not isinstance(doc_id, str) or not isinstance(recipient_id, str):
            return jsonify({"error": "doc_id and recipient_id must be strings"}), 400
        res = core.decrypt_for_recipient(doc_id, recipient_id)
        return jsonify({
            "event_id": res["event_id"], "recipient_id": res["recipient_id"],
            "doc_id": res["doc_id"], "document_hash": res["document_hash"],
            "watermark_token_hash": res["watermark_token_hash"],
            "timestamp": res["timestamp"], "block_index": res["block_index"],
            "signature": res["signature_hex"][:64] + "…",
            "download": f"/api/copy/{res['event_id']}",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/copy/<event_id>")
def copy(event_id):
    if not _HEX32.match(event_id or ""):
        return jsonify({"error": "invalid event id"}), 404
    try:
        data = store.load_copy(event_id)
        return send_file(io.BytesIO(data), mimetype="application/pdf",
                         as_attachment=True, download_name=f"decrypted_{event_id[:8]}.pdf")
    except Exception:
        return jsonify({"error": "copy not found"}), 404


@app.get("/api/ledger")
def ledger_list():
    try:
        return jsonify(store.load_ledger())
    except Exception as e:
        return jsonify({"error": f"ledger unreadable: {type(e).__name__}: {e}"}), 500


@app.post("/api/verify")
def ledger_verify():
    try:
        chain = store.load_ledger()
        ok, msg = ledger_mod.verify_ledger(chain, store.load_recipients())
        return jsonify({"valid": ok, "detail": msg})
    except Exception as e:
        return jsonify({"valid": False, "detail": f"verify failed: {type(e).__name__}: {e}"})


@app.post("/api/investigate")
def investigate():
    global LAST_INVESTIGATION
    try:
        f = request.files.get("file")
        if f is None:
            return jsonify({"error": "no file uploaded"}), 400
        res = core.investigate_leak(f.read())
        LAST_INVESTIGATION = res
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/demo")
def run_full_demo():
    """One-click demo: same run_demo() as the CLI; resets local state. Errors surface."""
    global LAST_INVESTIGATION
    try:
        out = demo_mod.run_demo()
        if out.get("ok"):
            LAST_INVESTIGATION = out["forensic"]
        return jsonify(out)
    except Exception as e:  # never hide a crash
        return jsonify({"ok": False, "steps": [], "error": f"{type(e).__name__}: {e}"}), 500


if __name__ == "__main__":
    store.ensure_dirs()
    app.run(host="127.0.0.1", port=5000, debug=False)

'@
Set-Content -Path "app.py" -Value $appPy -Encoding UTF8 -NoNewline

$indexHtml = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PS26237 — Cryptographic Attribution &amp; Decryption Provenance</title>
<link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">
</head>
<body>
<div class="app-shell">

  <!-- ========== SIDEBAR ========== -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-top">
      <div class="brand">
        <div class="brand-mark">
          <svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>
        </div>
        <div class="brand-text">
          <span class="brand-title">PS26237</span>
          <span class="brand-sub">DECRYPTION PROVENANCE</span>
        </div>
      </div>
      <nav class="nav" id="nav">
        <button class="nav-item" data-view="overview">
          <svg class="svg-icon" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
          <span>Overview</span>
        </button>
        <button class="nav-item" data-view="encrypt">
          <svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
          <span>Encrypt</span>
        </button>
        <button class="nav-item" data-view="decrypt">
          <svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.8"/></svg>
          <span>Decrypt</span>
        </button>
        <button class="nav-item" data-view="investigate">
          <svg class="svg-icon" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg>
          <span>Investigate</span>
        </button>
        <button class="nav-item" data-view="ledger">
          <svg class="svg-icon" viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 12h7M9 16h7M9 8h3"/></svg>
          <span>Integrity Ledger</span>
        </button>
        <button class="nav-item" data-view="how-it-works">
          <svg class="svg-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/></svg>
          <span>How It Works</span>
        </button>
      </nav>
    </div>
    <div class="sidebar-bottom">
      <div class="status-row">
        <span class="status-label">Ledger integrity</span>
        <span class="chip chip-neutral" id="sb-ledger-chip">—</span>
      </div>
      <div class="status-row" style="margin-bottom:0">
        <span class="status-label">Mode</span>
        <span class="build-tag">Local &bull; No network egress</span>
      </div>
    </div>
  </aside>

  <!-- ========== MAIN ========== -->
  <div class="main-col">
    <header class="topbar">
      <div class="topbar-left">
        <button class="btn btn-ghost btn-sm menu-btn" id="menu-toggle" aria-label="Toggle navigation">
          <svg class="svg-icon" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
        </button>
        <span class="topbar-crumb" id="crumb">PS26237 / Overview</span>
      </div>
      <div class="topbar-right">
        <span class="offline-pill"><span class="dot" style="width:6px;height:6px"></span>OFFLINE</span>
      </div>
    </header>

    <!-- ===== OVERVIEW ===== -->
    <section class="view is-active" data-view="overview" id="view-overview">
      <div class="view-head">
        <div>
          <div class="view-eyebrow">SYSTEM STATUS</div>
          <h1 class="view-title">Overview</h1>
          <p class="view-desc">Live state of recipients, encrypted documents, decryption events and ledger integrity — read directly from local storage.</p>
        </div>
        <div class="view-actions">
          <button class="btn" id="btn-init">
            <svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>
            Initialize demo recipients
          </button>
          <button class="btn btn-primary" id="btn-demo">
            <svg class="svg-icon" viewBox="0 0 24 24"><path d="M6 4l14 8-14 8V4z"/></svg>
            Run full demo
          </button>
        </div>
      </div>

      <div class="metric-grid">
        <div class="metric">
          <div class="metric-top"><span class="metric-label">RECIPIENTS</span>
            <div class="metric-icon"><svg class="svg-icon" viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.2"/><path d="M5 20c0-3.5 3-6 7-6s7 2.5 7 6"/></svg></div></div>
          <div class="metric-value" id="m-recipients">—</div>
          <div class="metric-note">Enrolled with ML-KEM + ML-DSA keypairs</div>
        </div>
        <div class="metric">
          <div class="metric-top"><span class="metric-label">ENCRYPTED DOCUMENTS</span>
            <div class="metric-icon"><svg class="svg-icon" viewBox="0 0 24 24"><path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4"/></svg></div></div>
          <div class="metric-value" id="m-documents">—</div>
          <div class="metric-note">Sealed once with AES-256-GCM</div>
        </div>
        <div class="metric">
          <div class="metric-top"><span class="metric-label">DECRYPTION EVENTS</span>
            <div class="metric-icon"><svg class="svg-icon" viewBox="0 0 24 24"><path d="M5 11h14M5 11a7 7 0 1 1 7 7"/><path d="M9 15l-4-4 4-4"/></svg></div></div>
          <div class="metric-value" id="m-events">—</div>
          <div class="metric-note">Watermarked, signed and ledgered</div>
        </div>
        <div class="metric">
          <div class="metric-top"><span class="metric-label">LEDGER STATUS</span>
            <div class="metric-icon" id="m-ledger-icon"><svg class="svg-icon" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg></div></div>
          <div class="metric-value" id="m-ledger">—</div>
          <div class="metric-note" id="m-ledger-note">Checking hash chain…</div>
        </div>
      </div>

      <div class="card mt-20">
        <div class="card-head">
          <div>
            <h2>Cryptographic lifecycle</h2>
            <p class="card-sub">The fixed pipeline every document and decryption event passes through.</p>
          </div>
        </div>
        <div class="card-pad">
          <div class="pipeline">
            <div class="pipe-step"><div class="pipe-step-top"><span class="pipe-num">01</span><svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg></div><span class="pipe-name">Encrypt</span><span class="pipe-desc">AES-256-GCM seals the document once; ML-KEM-768 wraps the key per recipient.</span></div>
            <div class="pipe-step"><div class="pipe-step-top"><span class="pipe-num">02</span><svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.8"/></svg></div><span class="pipe-name">Decrypt</span><span class="pipe-desc">An authorized recipient opens their copy; a fresh event ID is minted.</span></div>
            <div class="pipe-step"><div class="pipe-step-top"><span class="pipe-num">03</span><svg class="svg-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="2.5"/></svg></div><span class="pipe-name">Watermark</span><span class="pipe-desc">A unique, invisible token is embedded in that recipient's copy only.</span></div>
            <div class="pipe-step"><div class="pipe-step-top"><span class="pipe-num">04</span><svg class="svg-icon" viewBox="0 0 24 24"><path d="M4 20l4-1 10-10-3-3L5 16l-1 4z"/></svg></div><span class="pipe-name">Sign</span><span class="pipe-desc">The event is signed with the recipient's ML-DSA-65 private key.</span></div>
            <div class="pipe-step"><div class="pipe-step-top"><span class="pipe-num">05</span><svg class="svg-icon" viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 12h7M9 16h7"/></svg></div><span class="pipe-name">Ledger</span><span class="pipe-desc">The signed event is appended to a local SHA-256 hash chain.</span></div>
            <div class="pipe-step"><div class="pipe-step-top"><span class="pipe-num">06</span><svg class="svg-icon" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg></div><span class="pipe-name">Investigate</span><span class="pipe-desc">A leaked copy's watermark is matched back to its signed event.</span></div>
          </div>
        </div>
      </div>

      <div class="card mt-20">
        <div class="card-head">
          <div>
            <h2>Recent decryption events</h2>
            <p class="card-sub">Latest entries from the local ledger, most recent first.</p>
          </div>
          <button class="btn btn-ghost btn-sm" data-goto="ledger">
            View full ledger
            <svg class="svg-icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
          </button>
        </div>
        <div class="table-wrap" id="overview-ledger-wrap">
          <div class="empty-state"><div class="spinner dark"></div></div>
        </div>
      </div>

      <details class="tech mt-20" id="overview-log">
        <summary>System log
          <svg class="svg-icon chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
        </summary>
        <div class="tech-body">
          <pre class="text-muted" id="overview-log-body" style="white-space:pre-wrap;font-family:var(--mono);font-size:12px;margin:0">No actions run yet this session.</pre>
        </div>
      </details>
    </section>

    <!-- ===== ENCRYPT ===== -->
    <section class="view" data-view="encrypt" id="view-encrypt">
      <div class="view-head">
        <div>
          <div class="view-eyebrow">STEP 01 — SEAL A DOCUMENT</div>
          <h1 class="view-title">Encrypt</h1>
          <p class="view-desc">Upload a PDF once. It is sealed with AES-256-GCM and the document key is wrapped separately for every enrolled recipient with ML-KEM-768.</p>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <div class="card-head"><div><h2>Upload document</h2><p class="card-sub">Original file never leaves this device.</p></div></div>
          <div class="card-pad gap-col">
            <div id="banner-encrypt"></div>
            <label class="dropzone" id="dropzone-encrypt" for="file-encrypt">
              <svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>
              <span class="dropzone-title">Drop a PDF or click to browse</span>
              <span class="dropzone-sub">Single file &bull; up to 15 MB</span>
              <span class="dropzone-file" id="dropzone-encrypt-file"></span>
            </label>
            <input type="file" id="file-encrypt" accept="application/pdf">
            <button class="btn btn-primary btn-block" id="btn-encrypt" disabled>
              <svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
              Encrypt document
            </button>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><div><h2>Result</h2><p class="card-sub">Sealed document record.</p></div></div>
          <div class="card-pad" id="encrypt-result">
            <div class="empty-state">
              <svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
              <strong>No document encrypted yet</strong>
              <span>Upload a PDF to see its sealed record here.</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ===== DECRYPT ===== -->
    <section class="view" data-view="decrypt" id="view-decrypt">
      <div class="view-head">
        <div>
          <div class="view-eyebrow">STEP 02 — AUTHORIZED ACCESS</div>
          <h1 class="view-title">Decrypt</h1>
          <p class="view-desc">Opening a document as a specific recipient mints a uniquely watermarked copy, signs the event with that recipient's key, and appends it to the ledger.</p>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <div class="card-head"><div><h2>Open a document</h2><p class="card-sub">Choose the document and the recipient decrypting it.</p></div></div>
          <div class="card-pad gap-col">
            <div id="banner-decrypt"></div>
            <div class="field">
              <label for="select-doc">Document</label>
              <select id="select-doc"><option>Loading…</option></select>
            </div>
            <div class="field" style="margin-bottom:0">
              <label for="select-recipient">Recipient</label>
              <select id="select-recipient"><option>Loading…</option></select>
            </div>
            <button class="btn btn-primary btn-block mt-8" id="btn-decrypt">
              <svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.8"/></svg>
              Decrypt, watermark &amp; sign
            </button>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><div><h2>Decryption certificate</h2><p class="card-sub">Proof of this specific decryption event.</p></div></div>
          <div class="card-pad" id="decrypt-result">
            <div class="empty-state">
              <svg class="svg-icon" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.6-1.8"/></svg>
              <strong>No decryption yet</strong>
              <span>Run a decryption to see its signed event here.</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ===== INVESTIGATE ===== -->
    <section class="view" data-view="investigate" id="view-investigate">
      <div class="view-head">
        <div>
          <div class="view-eyebrow">STEP 03 — LEAK FORENSICS</div>
          <h1 class="view-title">Investigate a leak</h1>
          <p class="view-desc">Upload a leaked PDF. Its embedded watermark is extracted and matched against the signed ledger to attribute the decryption event it came from.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-pad gap-col">
          <div id="banner-investigate"></div>
          <label class="dropzone" id="dropzone-investigate" for="file-investigate">
            <svg class="svg-icon" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg>
            <span class="dropzone-title">Drop the leaked PDF or click to browse</span>
            <span class="dropzone-sub">Analysis runs entirely offline, locally</span>
            <span class="dropzone-file" id="dropzone-investigate-file"></span>
          </label>
          <input type="file" id="file-investigate" accept="application/pdf">
          <button class="btn btn-primary" id="btn-investigate" disabled style="align-self:flex-start">
            <svg class="svg-icon" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg>
            Run forensic analysis
          </button>
        </div>
      </div>

      <div class="mt-20" id="investigate-result"></div>
    </section>

    <!-- ===== LEDGER ===== -->
    <section class="view" data-view="ledger" id="view-ledger">
      <div class="view-head">
        <div>
          <div class="view-eyebrow">TAMPER-EVIDENT AUDIT LOG</div>
          <h1 class="view-title">Integrity ledger</h1>
          <p class="view-desc">Every decryption event, linked by a local SHA-256 hash chain and signed with the recipient's ML-DSA-65 key. Any edit, reorder or forgery breaks verification.</p>
        </div>
        <div class="view-actions">
          <button class="btn" id="btn-refresh-ledger">
            <svg class="svg-icon" viewBox="0 0 24 24"><path d="M4 4v6h6M20 20v-6h-6"/><path d="M5.5 15a7 7 0 0 0 12.3 2.6M18.5 9A7 7 0 0 0 6.2 6.4"/></svg>
            Refresh
          </button>
          <button class="btn btn-primary" id="btn-verify-ledger">
            <svg class="svg-icon" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>
            Verify ledger integrity
          </button>
        </div>
      </div>

      <div id="ledger-verify-banner"></div>

      <div class="card mt-16">
        <div class="card-head">
          <div><h2>Blocks</h2><p class="card-sub">Chronological, append-only. Select a row for its cryptographic proof.</p></div>
        </div>
        <div class="table-wrap" id="ledger-table-wrap">
          <div class="empty-state"><div class="spinner dark"></div></div>
        </div>
      </div>

      <details class="tech mt-16" id="ledger-detail" style="display:none">
        <summary>Cryptographic proof — selected block
          <svg class="svg-icon chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
        </summary>
        <div class="tech-body">
          <div class="kv-list" id="ledger-detail-body"></div>
        </div>
      </details>
    </section>

    <!-- ===== HOW IT WORKS ===== -->
    <section class="view" data-view="how-it-works" id="view-how-it-works">
      <div class="view-head">
        <div>
          <div class="view-eyebrow">REFERENCE</div>
          <h1 class="view-title">How it works</h1>
          <p class="view-desc">The cryptographic reasoning behind attribution, in the order it happens.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-pad">
          <div class="step-flow">
            <div class="step-item">
              <div class="step-index">1</div>
              <div class="step-content">
                <h3>Hybrid encryption</h3>
                <p>AES-256-GCM encrypts the document once. ML-KEM-768 protects recipient-specific access to that document key — one envelope per recipient, one shared ciphertext.</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-index">2</div>
              <div class="step-content">
                <h3>Decryption provenance</h3>
                <p>Each decryption creates a unique random event ID and an opaque random watermark token, embedded invisibly in that recipient's copy at decryption time.</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-index">3</div>
              <div class="step-content">
                <h3>Cryptographic evidence</h3>
                <p>The event record — who decrypted, which document, which watermark — is signed with the recipient's ML-DSA-65 private key.</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-index">4</div>
              <div class="step-content">
                <h3>Immutable record</h3>
                <p>Signed events are linked through a SHA-256 hash chain. Editing, reordering or deleting any past record breaks verification for everything after it.</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-index">5</div>
              <div class="step-content">
                <h3>Leak investigation</h3>
                <p>The watermark is extracted from a leaked PDF and matched against the signed ledger record — attributing the <em>decryption event</em>, never claiming who physically leaked the file.</p>
              </div>
            </div>
          </div>

          <div class="standards-row">
            <div class="standard-tag"><span class="name">AES-256-GCM</span><span class="role">Authenticated document encryption</span></div>
            <div class="standard-tag"><span class="name">ML-KEM-768</span><span class="role">Post-quantum key encapsulation</span></div>
            <div class="standard-tag"><span class="name">ML-DSA-65</span><span class="role">Post-quantum digital signatures</span></div>
            <div class="standard-tag"><span class="name">SHA-256</span><span class="role">Hash-chain &amp; document digests</span></div>
          </div>

          <div class="banner banner-info mt-20">
            <svg class="svg-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/></svg>
            <span>This is a single-machine append-only audit log, not a distributed blockchain — there is no consensus network, no peers, no cloud. Tamper <em>evidence</em> comes from the hash chain and signatures; tamper <em>prevention</em> at the OS/file level is out of scope.</span>
          </div>
        </div>
      </div>
    </section>

  </div>
</div>

<div class="toast-stack" id="toast-stack"></div>

<script src="{{ url_for('static', filename='js/app.js') }}"></script>
</body>
</html>

'@
Set-Content -Path "templates\index.html" -Value $indexHtml -Encoding UTF8 -NoNewline

$appCss = @'
/* PS26237 — Cryptographic Attribution & Decryption Provenance
   Design system: charcoal structure, warm off-white workspace, white surfaces,
   muted blue for primary action, restrained green/red for verdicts. */

:root{
  --charcoal-950:#15161a;
  --charcoal-900:#1b1c21;
  --charcoal-850:#212228;
  --charcoal-800:#26272e;
  --charcoal-700:#34363f;
  --charcoal-line:#333540;

  --ink:#1b1c21;
  --ink-muted:#5b5e68;
  --ink-faint:#8b8e97;
  --on-charcoal:#e8e7e3;
  --on-charcoal-muted:#9a9ca6;

  --paper:#f4f1ea;
  --paper-raised:#ece7db;
  --white:#ffffff;

  --hairline:#e2ddd1;
  --hairline-strong:#d3cdbd;

  --blue:#3e5c82;
  --blue-strong:#33496a;
  --blue-tint:#e9eef4;
  --blue-tint-strong:#dbe4ee;

  --green:#3f7a57;
  --green-tint:#e7f1ea;
  --green-line:#c4dccb;

  --red:#b14b3e;
  --red-tint:#f7e9e6;
  --red-line:#e6c7c0;

  --amber:#96762f;
  --amber-tint:#f3ecdb;

  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SFMono-Regular","Cascadia Mono","Roboto Mono",Menlo,Consolas,monospace;

  --radius-sm:6px;
  --radius:10px;
  --radius-lg:14px;
  --shadow-1:0 1px 2px rgba(27,28,33,.06);
  --shadow-2:0 4px 16px rgba(27,28,33,.08);

  --sidebar-w:240px;
  --topbar-h:56px;
}

*,*::before,*::after{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  font-family:var(--sans);
  background:var(--paper);
  color:var(--ink);
  font-size:14px;
  line-height:1.5;
  -webkit-font-smoothing:antialiased;
}
h1,h2,h3,h4,p,ul,ol,figure{margin:0}
button{font:inherit;color:inherit}
a{color:inherit}
::selection{background:var(--blue-tint-strong)}
:focus-visible{outline:2px solid var(--blue);outline-offset:2px;border-radius:4px}

.svg-icon{width:1em;height:1em;display:inline-block;vertical-align:-0.15em;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}

/* ---------- App shell ---------- */
.app-shell{display:flex;min-height:100vh}

.sidebar{
  position:fixed;top:0;left:0;bottom:0;width:var(--sidebar-w);
  background:var(--charcoal-900);
  display:flex;flex-direction:column;justify-content:space-between;
  z-index:40;
}
.sidebar-top{padding:20px 16px 8px}
.brand{display:flex;align-items:center;gap:10px;padding:4px 4px 20px}
.brand-mark{
  width:34px;height:34px;border-radius:8px;flex:none;
  background:linear-gradient(160deg,var(--blue) 0%,var(--blue-strong) 100%);
  display:flex;align-items:center;justify-content:center;color:#fff;
}
.brand-mark svg{width:18px;height:18px}
.brand-text{display:flex;flex-direction:column;min-width:0}
.brand-title{font-weight:700;font-size:14.5px;letter-spacing:.02em;color:#fff;white-space:nowrap}
.brand-sub{font-size:10.5px;color:var(--on-charcoal-muted);letter-spacing:.06em;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

.nav{display:flex;flex-direction:column;gap:2px;padding:4px 8px}
.nav-item{
  display:flex;align-items:center;gap:11px;
  padding:9px 12px;border-radius:8px;
  color:var(--on-charcoal-muted);
  text-decoration:none;font-size:13.5px;font-weight:500;
  border:1px solid transparent;
  background:transparent;
  cursor:pointer;width:100%;text-align:left;
  transition:background .12s ease,color .12s ease;
}
.nav-item svg{width:17px;height:17px;flex:none;opacity:.85}
.nav-item:hover{background:var(--charcoal-800);color:var(--on-charcoal)}
.nav-item.is-active{background:var(--charcoal-800);color:#fff;border-color:var(--charcoal-line);box-shadow:inset 2.5px 0 0 var(--blue-tint-strong)}
.nav-section-label{
  padding:16px 12px 6px;font-size:10px;letter-spacing:.09em;text-transform:uppercase;
  color:#63656f;font-weight:600;
}

.sidebar-bottom{padding:14px 16px;border-top:1px solid var(--charcoal-line)}
.status-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.status-label{font-size:11.5px;color:var(--on-charcoal-muted);font-weight:500}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex:none}
.dot.dot-idle{background:#5b5e68}
.build-tag{font-family:var(--mono);font-size:10.5px;color:#63656f}

/* ---------- Topbar + main ---------- */
.main-col{margin-left:var(--sidebar-w);flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{
  position:sticky;top:0;z-index:30;height:var(--topbar-h);
  background:rgba(244,241,234,.92);backdrop-filter:blur(6px);
  border-bottom:1px solid var(--hairline);
  display:flex;align-items:center;justify-content:space-between;
  padding:0 24px;
}
.topbar-left{display:flex;align-items:center;gap:10px;min-width:0}
.topbar-crumb{font-family:var(--mono);font-size:11.5px;color:var(--ink-faint);letter-spacing:.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-right{display:flex;align-items:center;gap:12px}
.offline-pill{
  display:inline-flex;align-items:center;gap:6px;
  padding:4px 10px;border-radius:999px;border:1px solid var(--hairline-strong);
  background:var(--white);font-family:var(--mono);font-size:11px;color:var(--ink-muted);
}

.view{display:none;padding:28px 32px 64px;max-width:1180px;margin:0 auto;width:100%}
.view.is-active{display:block}

.view-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.view-eyebrow{font-family:var(--mono);font-size:11.5px;color:var(--blue);font-weight:600;margin-bottom:6px}
.view-title{font-size:23px;font-weight:700;letter-spacing:-.01em;color:var(--ink)}
.view-desc{font-size:13.5px;color:var(--ink-muted);margin-top:5px;max-width:56ch}
.view-actions{display:flex;gap:8px;flex-wrap:wrap}

/* ---------- Buttons ---------- */
.btn{
  display:inline-flex;align-items:center;gap:7px;
  padding:9px 15px;border-radius:8px;border:1px solid var(--hairline-strong);
  background:var(--white);color:var(--ink);font-size:13px;font-weight:600;
  cursor:pointer;transition:background .12s ease,border-color .12s ease,transform .05s ease;
  line-height:1;
}
.btn svg{width:15px;height:15px}
.btn:hover{background:var(--paper-raised)}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-primary{background:var(--blue);border-color:var(--blue);color:#fff}
.btn-primary:hover{background:var(--blue-strong);border-color:var(--blue-strong)}
.btn-ghost{background:transparent;border-color:transparent;color:var(--ink-muted)}
.btn-ghost:hover{background:var(--paper-raised);color:var(--ink)}
.btn-sm{padding:6px 11px;font-size:12px;border-radius:7px}
.btn-block{width:100%;justify-content:center}
.btn-danger-line{border-color:var(--red-line);color:var(--red)}
.btn-danger-line:hover{background:var(--red-tint)}

/* ---------- Cards / surfaces ---------- */
.card{background:var(--white);border:1px solid var(--hairline);border-radius:var(--radius-lg);box-shadow:var(--shadow-1)}
.card-pad{padding:20px 22px}
.card-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--hairline);gap:12px}
.card-head h2{font-size:15px;font-weight:650}
.card-sub{font-size:12.5px;color:var(--ink-muted);margin-top:2px}

/* ---------- Metric grid ---------- */
.metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
@media (max-width:980px){.metric-grid{grid-template-columns:repeat(2,1fr)}}
.metric{
  background:var(--white);border:1px solid var(--hairline);border-radius:var(--radius-lg);
  padding:16px 18px;display:flex;flex-direction:column;gap:10px;box-shadow:var(--shadow-1);
}
.metric-top{display:flex;align-items:center;justify-content:space-between}
.metric-label{font-size:11.5px;font-weight:650;color:var(--ink-muted);letter-spacing:.02em}
.metric-icon{width:28px;height:28px;border-radius:7px;background:var(--paper-raised);color:var(--blue);display:flex;align-items:center;justify-content:center}
.metric-icon svg{width:15px;height:15px}
.metric-value{font-size:26px;font-weight:700;letter-spacing:-.01em;line-height:1}
.metric-note{font-size:12px;color:var(--ink-muted)}
.metric-value.ok{color:var(--green)}
.metric-value.bad{color:var(--red)}

/* ---------- Pipeline ---------- */
.pipeline{display:grid;grid-template-columns:repeat(6,1fr);gap:10px}
@media (max-width:900px){.pipeline{grid-template-columns:repeat(3,1fr)}}
@media (max-width:560px){.pipeline{grid-template-columns:repeat(2,1fr)}}
.pipe-step{background:var(--paper);border:1px solid var(--hairline);border-radius:var(--radius);padding:13px 14px;display:flex;flex-direction:column;gap:8px}
.pipe-step-top{display:flex;align-items:center;justify-content:space-between}
.pipe-num{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--blue)}
.pipe-step svg{width:17px;height:17px;color:var(--ink-faint)}
.pipe-name{font-size:13px;font-weight:650}
.pipe-desc{font-size:12px;color:var(--ink-muted);line-height:1.45}

/* ---------- Status chips / badges ---------- */
.chip{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;font-size:11.5px;font-weight:650;line-height:1.6;white-space:nowrap}
.chip svg{width:12px;height:12px}
.chip-green{background:var(--green-tint);color:var(--green);border:1px solid var(--green-line)}
.chip-red{background:var(--red-tint);color:var(--red);border:1px solid var(--red-line)}
.chip-blue{background:var(--blue-tint);color:var(--blue-strong);border:1px solid var(--blue-tint-strong)}
.chip-neutral{background:var(--paper-raised);color:var(--ink-muted);border:1px solid var(--hairline-strong)}
.chip-amber{background:var(--amber-tint);color:var(--amber);border:1px solid var(--hairline-strong)}

/* ---------- Tables ---------- */
.table-wrap{overflow-x:auto}
table.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table thead th{
  text-align:left;font-size:11px;font-weight:650;text-transform:uppercase;letter-spacing:.05em;
  color:var(--ink-muted);padding:10px 16px;border-bottom:1px solid var(--hairline);white-space:nowrap;
}
.data-table tbody td{padding:12px 16px;border-bottom:1px solid var(--hairline);vertical-align:middle}
.data-table tbody tr:last-child td{border-bottom:none}
.data-table tbody tr{cursor:default}
.data-table tbody tr.is-clickable{cursor:pointer}
.data-table tbody tr.is-clickable:hover{background:var(--paper)}
.cell-mono{font-family:var(--mono);font-size:12px;color:var(--ink-muted)}
.cell-title{font-weight:600;color:var(--ink)}
.cell-sub{font-family:var(--mono);font-size:11.5px;color:var(--ink-faint);margin-top:1px}

/* ---------- Forms ---------- */
.field{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.field label{font-size:12.5px;font-weight:650;color:var(--ink-muted)}
select,input[type=text]{
  padding:9px 11px;border-radius:8px;border:1px solid var(--hairline-strong);
  background:var(--white);font-size:13.5px;color:var(--ink);width:100%;
}
select:focus,input:focus{border-color:var(--blue)}

.dropzone{
  border:1.5px dashed var(--hairline-strong);border-radius:var(--radius-lg);
  background:var(--paper);padding:34px 20px;text-align:center;
  display:flex;flex-direction:column;align-items:center;gap:10px;
  cursor:pointer;transition:border-color .12s ease,background .12s ease;
}
.dropzone:hover,.dropzone.is-drag{border-color:var(--blue);background:var(--blue-tint)}
.dropzone svg{width:26px;height:26px;color:var(--ink-faint)}
.dropzone-title{font-size:13.5px;font-weight:650}
.dropzone-sub{font-size:12px;color:var(--ink-muted)}
.dropzone-file{font-family:var(--mono);font-size:12.5px;color:var(--blue-strong);margin-top:2px;word-break:break-all}
input[type=file]{display:none}

/* ---------- Two column layout ---------- */
.split{display:grid;grid-template-columns:1.1fr .9fr;gap:20px}
@media (max-width:920px){.split{grid-template-columns:1fr}}

/* ---------- Banners / alerts ---------- */
.banner{display:flex;align-items:flex-start;gap:10px;padding:12px 14px;border-radius:var(--radius);font-size:13px;border:1px solid transparent}
.banner svg{width:16px;height:16px;flex:none;margin-top:1px}
.banner-error{background:var(--red-tint);border-color:var(--red-line);color:#7a2f26}
.banner-info{background:var(--blue-tint);border-color:var(--blue-tint-strong);color:var(--blue-strong)}
.banner-success{background:var(--green-tint);border-color:var(--green-line);color:#245538}

/* ---------- Key/value proof list ---------- */
.kv-list{display:flex;flex-direction:column}
.kv-row{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:9px 0;border-bottom:1px solid var(--hairline)}
.kv-row:last-child{border-bottom:none}
.kv-key{font-size:12.5px;color:var(--ink-muted);font-weight:600;flex:none;width:38%}
.kv-val{font-family:var(--mono);font-size:12.5px;color:var(--ink);text-align:right;word-break:break-all;flex:1}
.kv-val.plain{font-family:var(--sans);text-align:right}

.copy-inline{display:inline-flex;align-items:center;gap:6px}
.copy-btn{background:none;border:none;color:var(--ink-faint);cursor:pointer;padding:2px;display:inline-flex}
.copy-btn:hover{color:var(--blue)}
.copy-btn svg{width:13px;height:13px}

/* ---------- Evidence checklist (Investigate) ---------- */
.evidence-list{display:flex;flex-direction:column;gap:10px}
.evidence-row{display:flex;align-items:center;gap:12px;padding:11px 14px;border:1px solid var(--hairline);border-radius:var(--radius);background:var(--white)}
.evidence-icon{width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex:none}
.evidence-icon.pass{background:var(--green-tint);color:var(--green)}
.evidence-icon.fail{background:var(--red-tint);color:var(--red)}
.evidence-icon svg{width:14px;height:14px}
.evidence-text{display:flex;flex-direction:column;gap:1px;min-width:0}
.evidence-title{font-size:13px;font-weight:650}
.evidence-detail{font-size:12px;color:var(--ink-muted)}

/* ---------- Verdict panel ---------- */
.verdict{
  border-radius:var(--radius-lg);padding:26px 28px;display:flex;flex-direction:column;gap:14px;
  border:1px solid var(--hairline);
}
.verdict.verdict-match{background:linear-gradient(180deg,var(--green-tint) 0%,var(--white) 55%);border-color:var(--green-line)}
.verdict.verdict-nomatch{background:linear-gradient(180deg,var(--red-tint) 0%,var(--white) 55%);border-color:var(--red-line)}
.verdict-top{display:flex;align-items:center;gap:12px}
.verdict-icon{width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex:none}
.verdict-match .verdict-icon{background:var(--green);color:#fff}
.verdict-nomatch .verdict-icon{background:var(--red);color:#fff}
.verdict-icon svg{width:22px;height:22px}
.verdict-heading{font-size:19px;font-weight:700;letter-spacing:-.005em}
.verdict-sub{font-size:12.5px;color:var(--ink-muted);font-family:var(--mono)}
.verdict-body{font-size:14px;color:var(--ink);line-height:1.6;max-width:70ch}
.verdict-scope{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:4px}
@media (max-width:760px){.verdict-scope{grid-template-columns:1fr}}
.scope-box{background:var(--white);border:1px solid var(--hairline);border-radius:var(--radius);padding:12px 14px}
.scope-box h4{font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-muted);margin-bottom:6px}
.scope-box p{font-size:12.5px;color:var(--ink);line-height:1.55}

/* ---------- Details / collapsible technical panel ---------- */
details.tech{border:1px solid var(--hairline);border-radius:var(--radius-lg);overflow:hidden;background:var(--white)}
details.tech > summary{
  list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;
  padding:13px 18px;font-size:13px;font-weight:650;color:var(--ink);
}
details.tech > summary::-webkit-details-marker{display:none}
details.tech > summary .chev{width:15px;height:15px;color:var(--ink-faint);transition:transform .15s ease}
details.tech[open] > summary .chev{transform:rotate(180deg)}
details.tech > summary::before{content:"";}
.tech-body{padding:4px 18px 18px;border-top:1px solid var(--hairline)}

/* ---------- Empty / loading states ---------- */
.empty-state{display:flex;flex-direction:column;align-items:center;gap:8px;padding:40px 20px;text-align:center;color:var(--ink-muted)}
.empty-state svg{width:26px;height:26px;color:var(--ink-faint)}
.empty-state strong{color:var(--ink);font-size:13.5px}
.empty-state span{font-size:12.5px}

.spinner{width:15px;height:15px;border-radius:50%;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;animation:spin .7s linear infinite}
.spinner.dark{border:2px solid var(--hairline-strong);border-top-color:var(--blue)}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---------- How it works ---------- */
.step-flow{display:flex;flex-direction:column}
.step-item{display:flex;gap:16px;padding:18px 0;border-bottom:1px solid var(--hairline)}
.step-item:last-child{border-bottom:none}
.step-index{width:30px;height:30px;border-radius:50%;background:var(--charcoal-900);color:#fff;font-family:var(--mono);font-size:12.5px;font-weight:600;display:flex;align-items:center;justify-content:center;flex:none}
.step-content h3{font-size:14.5px;font-weight:650;margin-bottom:5px}
.step-content p{font-size:13.5px;color:var(--ink-muted);line-height:1.6;max-width:64ch}
.standards-row{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.standard-tag{display:flex;flex-direction:column;gap:2px;background:var(--paper);border:1px solid var(--hairline);border-radius:var(--radius);padding:9px 13px}
.standard-tag .name{font-family:var(--mono);font-size:12.5px;font-weight:650;color:var(--blue-strong)}
.standard-tag .role{font-size:11px;color:var(--ink-muted)}

/* ---------- Toast ---------- */
.toast-stack{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:8px;z-index:100}
.toast{background:var(--charcoal-900);color:#fff;padding:10px 14px;border-radius:8px;font-size:12.5px;box-shadow:var(--shadow-2);display:flex;align-items:center;gap:8px;animation:toast-in .18s ease}
.toast svg{width:14px;height:14px;flex:none}
@keyframes toast-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

/* ---------- Utility ---------- */
.mt-8{margin-top:8px}.mt-12{margin-top:12px}.mt-16{margin-top:16px}.mt-20{margin-top:20px}
.gap-col{display:flex;flex-direction:column;gap:14px}
.text-muted{color:var(--ink-muted)}
.hidden{display:none !important}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

@media (max-width:860px){
  .sidebar{transform:translateX(-100%);transition:transform .18s ease}
  .sidebar.is-open{transform:translateX(0)}
  .main-col{margin-left:0}
  .split{grid-template-columns:1fr}
  .view{padding:20px 16px 48px}
}
.menu-btn{display:none}
@media (max-width:860px){.menu-btn{display:inline-flex}}

'@
Set-Content -Path "static\css\app.css" -Value $appCss -Encoding UTF8 -NoNewline

$appJs = @'
/* PS26237 — front end. Talks only to the existing /api/* endpoints; no data is invented. */
(() => {
  "use strict";

  const STATE = { status: null, ledger: [], docIndex: {}, selectedBlock: null };

  const ICON = {
    check: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>',
    x: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>',
    copy: '<svg class="svg-icon" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
    download: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 4v12M7 11l5 5 5-5"/><path d="M5 20h14"/></svg>',
    alert: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 9v4.5M12 17v.01"/><path d="M10.3 3.9L2.6 18a1.6 1.6 0 0 0 1.4 2.4h16a1.6 1.6 0 0 0 1.4-2.4L13.7 3.9a1.6 1.6 0 0 0-2.8 0z"/></svg>',
    info: '<svg class="svg-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/></svg>',
    doc: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4"/></svg>',
    shield: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z"/></svg>',
  };

  // ---------- tiny utilities ----------
  function el(html) {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstElementChild;
  }
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }
  function short(hex, head = 8, tail = 6) {
    if (!hex || typeof hex !== "string") return "—";
    if (hex.length <= head + tail + 1) return hex;
    return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
  }
  function timeAgo(iso) {
    if (!iso) return "—";
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return iso;
    const s = Math.max(0, Math.round((Date.now() - then) / 1000));
    if (s < 5) return "just now";
    if (s < 60) return `${s}s ago`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.round(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.round(h / 24);
    return `${d}d ago`;
  }
  function copyRow(label, value, mono = true) {
    const v = value == null ? "—" : String(value);
    return `<div class="kv-row">
      <span class="kv-key">${esc(label)}</span>
      <span class="kv-val ${mono ? "" : "plain"}">
        <span class="copy-inline">${esc(v)}${v !== "—" ? `<button class="copy-btn" data-copy="${esc(v)}" title="Copy"> ${ICON.copy}</button>` : ""}</span>
      </span>
    </div>`;
  }
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied to clipboard", "check");
    } catch {
      toast("Could not copy — select manually", "alert");
    }
  }
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy-btn");
    if (btn) copyToClipboard(btn.getAttribute("data-copy") || "");
  });

  function toast(message, icon = "check") {
    const stack = document.getElementById("toast-stack");
    const node = el(`<div class="toast">${ICON[icon] || ICON.check}<span></span></div>`);
    node.querySelector("span").textContent = message;
    stack.appendChild(node);
    setTimeout(() => node.remove(), 3600);
  }

  function banner(kind, message) {
    const cls = kind === "error" ? "banner-error" : kind === "success" ? "banner-success" : "banner-info";
    const icon = kind === "error" ? ICON.alert : kind === "success" ? ICON.check : ICON.info;
    return `<div class="banner ${cls}">${icon}<span>${esc(message)}</span></div>`;
  }

  // ---------- API ----------
  async function api(method, url, body) {
    const opts = { method };
    if (body !== undefined) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    let data;
    try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
    if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
    return data;
  }
  async function apiForm(url, file) {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(url, { method: "POST", body: fd });
    let data;
    try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
    if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
    return data;
  }

  // ---------- navigation ----------
  const CRUMB = {
    overview: "PS26237 / Overview", encrypt: "PS26237 / Encrypt", decrypt: "PS26237 / Decrypt",
    investigate: "PS26237 / Investigate", ledger: "PS26237 / Integrity Ledger",
    "how-it-works": "PS26237 / How It Works",
  };
  function showView(name) {
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("is-active", v.dataset.view === name));
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("is-active", n.dataset.view === name));
    document.getElementById("crumb").textContent = CRUMB[name] || "PS26237";
    document.getElementById("sidebar").classList.remove("is-open");
    if (name === "ledger") renderLedgerTable();
    window.scrollTo(0, 0);
  }
  document.getElementById("nav").addEventListener("click", (e) => {
    const btn = e.target.closest(".nav-item");
    if (btn) showView(btn.dataset.view);
  });
  document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => showView(b.dataset.goto)));
  document.getElementById("menu-toggle").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("is-open");
  });

  // ---------- status / overview ----------
  function ledgerChip(ok) {
    if (ok === null || ok === undefined) return `<span class="chip chip-neutral">CHECKING</span>`;
    return ok
      ? `<span class="chip chip-green">${ICON.check}VALID</span>`
      : `<span class="chip chip-red">${ICON.x}INVALID</span>`;
  }

  async function loadStatus() {
    const d = await api("GET", "/api/status");
    if (d.error) { toast(d.error, "alert"); return; }
    STATE.status = d;
    STATE.docIndex = {};
    (d.documents || []).forEach((doc) => (STATE.docIndex[doc.doc_id] = doc));

    document.getElementById("m-recipients").textContent = (d.recipients || []).length;
    document.getElementById("m-documents").textContent = (d.documents || []).length;
    document.getElementById("m-events").textContent = d.decryption_events ?? 0;

    const ledgerVal = document.getElementById("m-ledger");
    ledgerVal.textContent = d.ledger_valid ? "Valid" : "Invalid";
    ledgerVal.className = "metric-value " + (d.ledger_valid ? "ok" : "bad");
    document.getElementById("m-ledger-note").textContent = d.ledger_detail || "";
    document.getElementById("sb-ledger-chip").outerHTML =
      `<span class="chip ${d.ledger_valid ? "chip-green" : "chip-red"}" id="sb-ledger-chip">${d.ledger_valid ? ICON.check + "VALID" : ICON.x + "INVALID"}</span>`;

    // populate decrypt selects
    const docSel = document.getElementById("select-doc");
    const recSel = document.getElementById("select-recipient");
    const prevDoc = docSel.value, prevRec = recSel.value;
    docSel.innerHTML = (d.documents || []).length
      ? (d.documents || []).map((x) => `<option value="${esc(x.doc_id)}">${esc(x.filename)} (${esc(short(x.doc_id, 8, 0))})</option>`).join("")
      : `<option value="">No documents encrypted yet</option>`;
    recSel.innerHTML = (d.recipients || []).length
      ? (d.recipients || []).map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join("")
      : `<option value="">No recipients enrolled</option>`;
    if ((d.documents || []).some((x) => x.doc_id === prevDoc)) docSel.value = prevDoc;
    if ((d.recipients || []).includes(prevRec)) recSel.value = prevRec;
  }

  async function loadLedger() {
    const d = await api("GET", "/api/ledger");
    if (d.error) { toast(d.error, "alert"); return; }
    STATE.ledger = Array.isArray(d) ? d : [];
    renderOverviewLedger();
    if (document.querySelector('.view[data-view="ledger"]').classList.contains("is-active")) renderLedgerTable();
  }

  function docLabel(docId) {
    const doc = STATE.docIndex[docId];
    return doc ? doc.filename : short(docId, 8, 0);
  }

  function renderOverviewLedger() {
    const wrap = document.getElementById("overview-ledger-wrap");
    const rows = [...STATE.ledger].reverse().slice(0, 6);
    if (!rows.length) {
      wrap.innerHTML = `<div class="empty-state">${ICON.doc}<strong>No decryption events yet</strong><span>Encrypt a document, then decrypt it as a recipient.</span></div>`;
      return;
    }
    wrap.innerHTML = `<table class="data-table"><thead><tr>
      <th>Document</th><th>Recipient</th><th>Event</th><th>Watermark</th><th>Time</th>
    </tr></thead><tbody>${rows.map((b) => `
      <tr>
        <td><div class="cell-title">${esc(docLabel(b.event.document_id))}</div><div class="cell-sub">${esc(short(b.event.document_hash))}</div></td>
        <td>${esc(b.signer)}</td>
        <td class="cell-mono">${esc(short(b.event.event_id, 8, 4))}</td>
        <td class="cell-mono">${esc(short(b.event.watermark_token_hash, 8, 4))}</td>
        <td class="cell-mono">${esc(timeAgo(b.timestamp))}</td>
      </tr>`).join("")}</tbody></table>`;
  }

  function renderLedgerTable() {
    const wrap = document.getElementById("ledger-table-wrap");
    if (!STATE.ledger.length) {
      wrap.innerHTML = `<div class="empty-state">${ICON.doc}<strong>Ledger is empty</strong><span>No decryption events have been recorded yet.</span></div>`;
      return;
    }
    const rows = [...STATE.ledger].reverse();
    wrap.innerHTML = `<table class="data-table"><thead><tr>
      <th>Block</th><th>Document</th><th>Recipient</th><th>Event ID</th><th>Watermark hash</th><th>Timestamp</th><th>Status</th>
    </tr></thead><tbody>${rows.map((b) => `
      <tr class="is-clickable" data-index="${b.index}">
        <td class="cell-mono">#${b.index}</td>
        <td><div class="cell-title">${esc(docLabel(b.event.document_id))}</div><div class="cell-sub">${esc(short(b.event.document_hash))}</div></td>
        <td>${esc(b.signer)}</td>
        <td class="cell-mono">${esc(short(b.event.event_id, 8, 6))}</td>
        <td class="cell-mono">${esc(short(b.event.watermark_token_hash, 8, 6))}</td>
        <td class="cell-mono">${esc(new Date(b.timestamp).toLocaleString())}</td>
        <td><span class="chip chip-blue">${ICON.shield}SEALED</span></td>
      </tr>`).join("")}</tbody></table>`;
    wrap.querySelectorAll("tr.is-clickable").forEach((tr) => {
      tr.addEventListener("click", () => selectBlock(Number(tr.dataset.index)));
    });
  }

  function selectBlock(index) {
    const block = STATE.ledger.find((b) => b.index === index);
    if (!block) return;
    STATE.selectedBlock = block;
    const panel = document.getElementById("ledger-detail");
    panel.style.display = "";
    panel.open = true;
    document.getElementById("ledger-detail-body").innerHTML = [
      copyRow("Block index", block.index, false),
      copyRow("Block hash", block.block_hash),
      copyRow("Previous hash", block.prev_hash),
      copyRow("Timestamp", block.timestamp, false),
      copyRow("Signer (recipient)", block.signer, false),
      copyRow("Signature (ML-DSA-65)", short(block.signature, 14, 10)),
      copyRow("Event ID", block.event.event_id),
      copyRow("Document", docLabel(block.event.document_id), false),
      copyRow("Document ID", block.event.document_id),
      copyRow("Document hash (SHA-256)", block.event.document_hash),
      copyRow("Watermark token hash", block.event.watermark_token_hash),
    ].join("");
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  document.getElementById("btn-refresh-ledger").addEventListener("click", async () => {
    await Promise.all([loadStatus(), loadLedger()]);
    toast("Ledger refreshed");
  });

  document.getElementById("btn-verify-ledger").addEventListener("click", async () => {
    const out = document.getElementById("ledger-verify-banner");
    out.innerHTML = banner("info", "Verifying hash chain and ML-DSA signatures…");
    const d = await api("POST", "/api/verify");
    out.innerHTML = banner(d.valid ? "success" : "error", d.detail || (d.valid ? "Ledger valid." : "Ledger invalid."));
    await loadStatus();
  });

  document.getElementById("btn-init").addEventListener("click", async () => {
    const d = await api("POST", "/api/init");
    if (d.error) { toast(d.error, "alert"); appendLog(`[FAIL] init: ${d.error}`); return; }
    toast(`Initialized ${d.recipients.length} recipients`);
    appendLog(`[ok] init: recipients = ${d.recipients.join(", ")}`);
    await loadStatus();
  });

  function appendLog(line) {
    const body = document.getElementById("overview-log-body");
    if (body.textContent.trim() === "No actions run yet this session.") body.textContent = "";
    body.textContent += (body.textContent ? "\n" : "") + line;
    document.getElementById("overview-log").open = true;
  }

  document.getElementById("btn-demo").addEventListener("click", async () => {
    const btn = document.getElementById("btn-demo");
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Running demo…`;
    appendLog("[ok] demo: starting full pipeline run (resets local state)…");
    const d = await api("POST", "/api/demo");
    btn.disabled = false;
    btn.innerHTML = original;
    if (!d.ok) {
      toast(d.error || "Demo failed", "alert");
      appendLog(`[FAIL] demo: ${d.error || "unknown error"}`);
      (d.steps || []).forEach((s) => appendLog(`[${s.ok ? "ok" : "FAIL"}] ${s.name}: ${s.detail}`));
      await loadStatus();
      await loadLedger();
      return;
    }
    (d.steps || []).forEach((s) => appendLog(`[${s.ok ? "ok" : "FAIL"}] ${s.name}: ${s.detail}`));
    toast("Full demo completed");
    await loadStatus();
    await loadLedger();
  });

  // ---------- dropzone helper ----------
  function wireDropzone(zoneId, inputId, fileLabelId, onFile) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const label = document.getElementById(fileLabelId);
    input.addEventListener("change", () => {
      if (input.files[0]) { label.textContent = input.files[0].name; onFile(input.files[0]); }
    });
    ["dragover", "dragenter"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("is-drag"); }));
    ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("is-drag"); }));
    zone.addEventListener("drop", (e) => {
      const f = e.dataTransfer.files[0];
      if (!f) return;
      if (f.type !== "application/pdf") { toast("Please choose a PDF file", "alert"); return; }
      input.files = e.dataTransfer.files;
      label.textContent = f.name;
      onFile(f);
    });
  }

  // ---------- Encrypt ----------
  let encryptFile = null;
  wireDropzone("dropzone-encrypt", "file-encrypt", "dropzone-encrypt-file", (f) => {
    encryptFile = f;
    document.getElementById("btn-encrypt").disabled = false;
  });
  document.getElementById("btn-encrypt").addEventListener("click", async () => {
    if (!encryptFile) return;
    const bannerEl = document.getElementById("banner-encrypt");
    const btn = document.getElementById("btn-encrypt");
    bannerEl.innerHTML = "";
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Encrypting…`;
    const d = await apiForm("/api/encrypt", encryptFile);
    btn.disabled = false;
    btn.innerHTML = original;
    if (d.error) {
      bannerEl.innerHTML = banner("error", d.error);
      return;
    }
    bannerEl.innerHTML = banner("success", "Document sealed. The original key never leaves this device.");
    document.getElementById("encrypt-result").innerHTML = `
      <div class="gap-col">
        <div class="banner banner-info" style="background:var(--paper);border-color:var(--hairline)">
          ${ICON.doc}<span><strong>${esc(d.filename)}</strong> — sealed for ${d.recipients.length} recipient${d.recipients.length === 1 ? "" : "s"}</span>
        </div>
        <div class="kv-list">
          ${copyRow("Document ID", d.doc_id)}
          ${copyRow("Document hash (SHA-256)", d.document_hash)}
          ${copyRow("Recipients enveloped", d.recipients.join(", "), false)}
        </div>
      </div>`;
    toast("Document encrypted");
    await loadStatus();
  });

  // ---------- Decrypt ----------
  document.getElementById("btn-decrypt").addEventListener("click", async () => {
    const docId = document.getElementById("select-doc").value;
    const recipientId = document.getElementById("select-recipient").value;
    const bannerEl = document.getElementById("banner-decrypt");
    bannerEl.innerHTML = "";
    if (!docId || !recipientId) { bannerEl.innerHTML = banner("error", "Choose a document and a recipient."); return; }
    const btn = document.getElementById("btn-decrypt");
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Decrypting…`;
    const d = await api("POST", "/api/decrypt", { doc_id: docId, recipient_id: recipientId });
    btn.disabled = false;
    btn.innerHTML = original;
    if (d.error) { bannerEl.innerHTML = banner("error", d.error); return; }
    bannerEl.innerHTML = banner("success", "Decrypted, watermarked and signed. Recorded on the ledger.");
    document.getElementById("decrypt-result").innerHTML = `
      <div class="gap-col">
        <div class="banner banner-info" style="background:var(--paper);border-color:var(--hairline)">
          ${ICON.shield}<span>Signed event for <strong>${esc(d.recipient_id)}</strong> on ${esc(docLabel(d.doc_id))}</span>
        </div>
        <a class="btn btn-primary btn-block" href="${d.download}">${ICON.download} Download watermarked copy</a>
        <div class="kv-list">
          ${copyRow("Event ID", d.event_id)}
          ${copyRow("Ledger block", "#" + d.block_index, false)}
          ${copyRow("Document hash (SHA-256)", d.document_hash)}
          ${copyRow("Watermark token hash", d.watermark_token_hash)}
          ${copyRow("ML-DSA-65 signature", d.signature)}
          ${copyRow("Timestamp", d.timestamp, false)}
        </div>
      </div>`;
    toast("Decryption recorded");
    await loadStatus();
    await loadLedger();
  });

  // ---------- Investigate ----------
  let investigateFileRef = null;
  wireDropzone("dropzone-investigate", "file-investigate", "dropzone-investigate-file", (f) => {
    investigateFileRef = f;
    document.getElementById("btn-investigate").disabled = false;
  });
  document.getElementById("btn-investigate").addEventListener("click", async () => {
    if (!investigateFileRef) return;
    const bannerEl = document.getElementById("banner-investigate");
    const resultEl = document.getElementById("investigate-result");
    bannerEl.innerHTML = "";
    const btn = document.getElementById("btn-investigate");
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Analyzing…`;
    resultEl.innerHTML = `<div class="empty-state"><div class="spinner dark"></div><span>Extracting watermark and checking the ledger…</span></div>`;
    const d = await apiForm("/api/investigate", investigateFileRef);
    btn.disabled = false;
    btn.innerHTML = original;
    if (d.error) { bannerEl.innerHTML = banner("error", d.error); resultEl.innerHTML = ""; return; }
    resultEl.innerHTML = renderVerdict(d);
    toast(d.match ? "Forensic match found" : "No verified match");
    await loadStatus();
  });

  function evidenceRow(pass, title, detail) {
    return `<div class="evidence-row">
      <div class="evidence-icon ${pass ? "pass" : "fail"}">${pass ? ICON.check : ICON.x}</div>
      <div class="evidence-text"><span class="evidence-title">${esc(title)}</span><span class="evidence-detail">${esc(detail)}</span></div>
    </div>`;
  }

  function renderVerdict(d) {
    if (!d.match) {
      return `
        <div class="verdict verdict-nomatch">
          <div class="verdict-top">
            <div class="verdict-icon">${ICON.x}</div>
            <div><div class="verdict-heading">Not verified</div><div class="verdict-sub">${esc(d.status || "NOT VERIFIED")}</div></div>
          </div>
          <p class="verdict-body">${esc(d.conclusion || "No verified decryption event matches this file.")}</p>
          ${d.reason ? `<p class="verdict-body text-muted">Reason: ${esc(d.reason)}</p>` : ""}
        </div>
        <details class="tech mt-16">
          <summary>Technical details / cryptographic proof <svg class="svg-icon chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></summary>
          <div class="tech-body kv-list">
            ${copyRow("Watermark", d.watermark || "NOT FOUND", false)}
            ${d.watermark_token_hash ? copyRow("Watermark token hash", d.watermark_token_hash) : ""}
          </div>
        </details>`;
    }
    return `
      <div class="verdict verdict-match">
        <div class="verdict-top">
          <div class="verdict-icon">${ICON.check}</div>
          <div><div class="verdict-heading">Verified match — attributed to ${esc(d.recipient)}</div><div class="verdict-sub">${esc(d.status)} &bull; ${esc(new Date(d.timestamp).toLocaleString())}</div></div>
        </div>
        <p class="verdict-body">${esc(d.conclusion)}</p>
        <div class="evidence-list">
          ${evidenceRow(true, "Watermark matched", "Token extracted from the leaked file matches a ledger record")}
          ${evidenceRow(d.mldsa_signature === "VALID", "ML-DSA-65 signature", d.mldsa_signature === "VALID" ? "Signature over the event is cryptographically valid" : "Signature check failed")}
          ${evidenceRow(d.ledger_integrity === "VALID", "Ledger integrity", d.ledger_integrity === "VALID" ? "Hash chain intact end to end" : String(d.ledger_integrity))}
        </div>
        ${d.scope ? `
        <div class="verdict-scope">
          <div class="scope-box"><h4>Cryptographic attribution</h4><p>${esc(d.scope.cryptographic_attribution)}</p></div>
          <div class="scope-box"><h4>Physical attribution</h4><p>${esc(d.scope.physical_attribution)}</p></div>
        </div>` : ""}
      </div>
      <details class="tech mt-16">
        <summary>Technical details / cryptographic proof <svg class="svg-icon chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></summary>
        <div class="tech-body kv-list">
          ${copyRow("Event ID", d.event_id)}
          ${copyRow("Ledger block", "#" + d.block_index, false)}
          ${copyRow("Document hash (SHA-256)", d.document_hash)}
          ${copyRow("Watermark token hash", d.watermark_token_hash)}
        </div>
      </details>`;
  }

  // ---------- init ----------
  (async function init() {
    await loadStatus();
    await loadLedger();
  })();
})();

'@
Set-Content -Path "static\js\app.js" -Value $appJs -Encoding UTF8 -NoNewline

Write-Host "PS26237 redesign applied. Start the app with: python app.py"
