"""Local web UI for the PS26237 BASE MVP. Runs fully offline (Flask, no CDN)."""
import io
import re

from flask import Flask, jsonify, request, send_file, render_template

import core
import custodians as custodians_mod
import demo as demo_mod
import evidence as evidence_mod
import ledger as ledger_mod
import provenance as prov_mod
import store

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

@app.before_request
def handle_options_preflight():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-Session-ID"
        return response

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-Session-ID"
    return response

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
        custodians = store.load_custodians()
        if chain:
            if any("witnesses" in b for b in chain if isinstance(b, dict)):
                ok, msg = ledger_mod.verify_ledger(chain, recips, custodians)
            else:
                ok, msg = ledger_mod.verify_ledger(chain, recips)
        else:
            ok, msg = True, "ledger empty"
        quorum = custodians_mod.quorum_counts(chain)
        return jsonify({
            "recipients": sorted(recips),
            "documents": [{"doc_id": d["doc_id"], "filename": d["filename"],
                           "document_hash": d["document_hash"]} for d in docs.values()],
            "encryption_records": len(store.load_encryption_registry()),
            "screenshot_layer": True,
            "decryption_events": len(chain),
            "ledger_valid": ok, "ledger_detail": msg,
            "protocol": prov_mod.PROTOCOL_VERSION,
            "quorum": quorum,
            "custodians": sorted(custodians),
            "checkpoint": store.load_checkpoint(),
            "last_investigation": last_inv_summary(),
            "device": __import__("device").get_device(),
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
        # Optional encrypting-PC identity supplied by the uploading machine.
        # Defaults to this server's stable device id (see device.py).
        pc_id = request.form.get("pc_id") or None
        pc_label = request.form.get("pc_label") or None
        return jsonify(core.encrypt_document(
            data, f.filename or "document.pdf",
            pc_id=pc_id, pc_label=pc_label))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/device")
def device_info():
    """This machine's stable PC identity used for encryption provenance."""
    try:
        import device as device_mod
        return jsonify(device_mod.get_device())
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/encryption-registry")
def encryption_registry():
    """The shared 'common DB': fingerprint + PC id recorded at encrypt time."""
    try:
        reg = store.load_encryption_registry()
        return jsonify(sorted(reg.values(),
                              key=lambda r: r.get("encrypted_at", "")))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/decrypt")
def decrypt():
    """RETIRED (410): server-custodial decryption contradicts the SIH
    requirement that records be signed with the recipient's OWN private key.
    Use /api/attested-decrypt (challenge -> recipient-device authorization ->
    verified release -> quorum). core.decrypt_for_recipient stays for
    backward-compatible tests/demos only."""
    try:
        body = request.get_json(force=True)
        doc_id, recipient_id = body.get("doc_id"), body.get("recipient_id")
        if not isinstance(doc_id, str) or not isinstance(recipient_id, str):
            return jsonify({"error": "doc_id and recipient_id must be strings"}), 400
        docs = store.load_documents()
        doc = docs.get(doc_id)
        if doc is None or recipient_id not in doc.get("envelopes", {}):
            # Preserve the legacy error shape for unknown doc/recipient.
            try:
                core.decrypt_for_recipient(doc_id, recipient_id)
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        return jsonify({"error": ("legacy custodial decrypt retired (410 Gone): "
                                  "use /api/attested-decrypt for recipient-signed release"),
                        "use": "/api/attested-decrypt"}), 410
    except Exception as e:
        return jsonify({"error": str(e)}), 400




@app.post("/api/attested-decrypt")
def attested_decrypt():
    """Demo simulation of the full v2 ceremony on this host, honestly labeled.

    Server mints challenge -> SIMULATED recipient device authorizes (module
    boundary preserved: this route, not core.py, touches recipient_client)
    -> server verifies + releases -> PENDING block (needs 2 witness calls).
    Production: the authorize step happens on the recipient's own hardware.
    """
    try:
        body = request.get_json(force=True)
        doc_id, recipient_id = body.get("doc_id"), body.get("recipient_id")
        if not isinstance(doc_id, str) or not isinstance(recipient_id, str):
            return jsonify({"error": "doc_id and recipient_id must be strings"}), 400
        import recipient_client as recipient_client_mod
        chal = core.create_decrypt_challenge(doc_id, recipient_id)
        try:
            passphrase = core.RECIPIENT_SIGN_PASSPHRASES[recipient_id]
        except KeyError:
            return jsonify({"error": f"unknown recipient {recipient_id!r}"}), 400
        sig = recipient_client_mod.authorize_challenge(chal, recipient_id, passphrase)
        res = core.complete_attested_decryption(chal, sig.hex())
        return jsonify({
            "event_id": res["event_id"], "recipient_id": res["recipient_id"],
            "doc_id": res["doc_id"], "document_hash": res["document_hash"],
            "watermark_token_hash": res["watermark_token_hash"],
            "copy_hash": res["copy_hash"],
            "timestamp": res["timestamp"], "block_index": res["block_index"],
            "status": res["status"],
            "simulated_device": True,
            "download": f"/api/copy/{res['event_id']}",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/investigate/image")
def investigate_image():
    """Attribute a screenshot/photo (analog hole) via the LatticeMark layer."""
    try:
        f = request.files.get("file")
        if f is None:
            return jsonify({"error": "no file uploaded"}), 400
        global LAST_INVESTIGATION
        res = core.investigate_screenshot(f.read())
        LAST_INVESTIGATION = res
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/robustness")
def robustness():
    """Measured LatticeMark survival matrix (scripts/measure_robustness.py)."""
    try:
        import json as _json
        import os as _os
        path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                             "docs_robustness.json")
        with open(path, encoding="utf-8") as fh:
            return jsonify(_json.load(fh))
    except Exception as e:
        return jsonify({"error": f"robustness data unavailable: {e}"}), 404


@app.post("/api/revoke")
def revoke():
    """Revoke a recipient's future authorization (custodian authority).

    Body: {recipient_id, custodian_id, passphrase}. Historical events stay
    verifiable; pending challenges for the recipient are dropped.
    """
    try:
        body = request.get_json(force=True)
        recipient_id = body.get("recipient_id")
        custodian_id = body.get("custodian_id")
        passphrase = body.get("passphrase")
        if not isinstance(recipient_id, str) or not isinstance(custodian_id, str):
            return jsonify({"error": "recipient_id and custodian_id must be strings"}), 400
        if not isinstance(passphrase, str) or not passphrase:
            return jsonify({"error": "custodian passphrase is required"}), 400
        res = core.revoke_recipient(recipient_id, custodian_id, passphrase)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---- PS26237-v2 attested endpoints (offline; recipient signs off-device) ----
@app.post("/api/challenge")
def challenge():
    """Server step 1: mint a single-use decrypt challenge for a recipient."""
    try:
        body = request.get_json(force=True)
        doc_id, recipient_id = body.get("doc_id"), body.get("recipient_id")
        if not isinstance(doc_id, str) or not isinstance(recipient_id, str):
            return jsonify({"error": "doc_id and recipient_id must be strings"}), 400
        return jsonify(core.create_decrypt_challenge(doc_id, recipient_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/complete")
def complete():
    """Server step 2: verify authorization signature, release fingerprinted copy."""
    try:
        body = request.get_json(force=True)
        chal, sig = body.get("challenge"), body.get("auth_signature_hex")
        if not isinstance(chal, dict) or not isinstance(sig, str):
            return jsonify({"error": "challenge dict and auth_signature_hex required"}), 400
        res = core.complete_attested_decryption(chal, sig)
        return jsonify({
            "event_id": res["event_id"], "recipient_id": res["recipient_id"],
            "doc_id": res["doc_id"], "document_hash": res["document_hash"],
            "watermark_token_hash": res["watermark_token_hash"],
            "copy_hash": res["copy_hash"],
            "timestamp": res["timestamp"], "block_index": res["block_index"],
            "status": res["status"],
            "download": f"/api/copy/{res['event_id']}",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/witness")
def witness():
    """Custodian step: add one witness signature to a PENDING block."""
    try:
        body = request.get_json(force=True)
        index, custodian_id = body.get("index"), body.get("custodian_id")
        passphrase = body.get("passphrase")
        if not isinstance(index, int) or not isinstance(custodian_id, str):
            return jsonify({"error": "index (int) and custodian_id required"}), 400
        if not isinstance(passphrase, str) or not passphrase:
            return jsonify({"error": "custodian passphrase is required"}), 400
        chain = store.load_ledger()
        block = custodians_mod.witness_block(chain, index, custodian_id, passphrase)
        return jsonify({"index": index, "status": block["status"],
                        "witnesses": [w["custodian_id"] for w in block["witnesses"]]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/demo-revoke")
def demo_revoke():
    """One-click custodian-authorized revocation for the live demo (labeled
    simulation; same trust note as /api/demo-witness)."""
    try:
        body = request.get_json(force=True)
        recipient_id, custodian_id = body.get("recipient_id"), body.get("custodian_id")
        if not isinstance(recipient_id, str) or not isinstance(custodian_id, str):
            return jsonify({"error": "recipient_id and custodian_id must be strings"}), 400
        import custodians as custodians_mod
        try:
            passphrase = custodians_mod.CUSTODIAN_PASSPHRASES[custodian_id]
        except KeyError:
            return jsonify({"error": f"unknown custodian {custodian_id!r}"}), 400
        return jsonify(core.revoke_recipient(recipient_id, custodian_id, passphrase))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/demo-witness")
def demo_witness():
    """One-click custodian witness for the live demo (labeled simulation).

    Fills the demo custodian passphrase server-side so the UI never handles
    witness secrets. Production: custodians sign on their own air-gapped
    hosts and submit {index, custodian_id, signature} instead.
    """
    try:
        body = request.get_json(force=True)
        index, custodian_id = body.get("index"), body.get("custodian_id")
        if not isinstance(index, int) or not isinstance(custodian_id, str):
            return jsonify({"error": "index (int) and custodian_id required"}), 400
        import custodians as custodians_mod
        try:
            passphrase = custodians_mod.CUSTODIAN_PASSPHRASES[custodian_id]
        except KeyError:
            return jsonify({"error": f"unknown custodian {custodian_id!r}"}), 400
        chain = store.load_ledger()
        block = custodians_mod.witness_block(chain, index, custodian_id, passphrase)
        return jsonify({"index": index, "status": block["status"],
                        "witnesses": [w["custodian_id"] for w in block["witnesses"]]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/evidence")
def evidence():
    """Build a portable evidence package for a FINAL event (needs leaked file)."""
    try:
        event_id = (request.get_json(force=True) or {}).get("event_id")
        f = request.files.get("file")
        if not isinstance(event_id, str) or f is None:
            return jsonify({"error": "event_id (json) and file (upload) required"}), 400
        pkg = evidence_mod.build_evidence_package(event_id, f.read())
        return jsonify(pkg)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/evidence/verify")
def evidence_verify():
    """Clean-room verification of a portable evidence package (stateless).

    Accepts either the package directly, or
    {"package": ..., "trust_anchor": ...} for anchored verification.
    """
    try:
        body = request.get_json(force=True)
        if not isinstance(body, dict):
            return jsonify({"error": "evidence package json required"}), 400
        if isinstance(body.get("package"), dict):
            pkg, anchor = body["package"], body.get("trust_anchor")
        else:
            pkg, anchor = body, None
        return jsonify(evidence_mod.verify_evidence_package(pkg, anchor))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/investigate/v2")
def investigate_v2():
    """Binding-aware v2 investigation (FINAL blocks only)."""
    global LAST_INVESTIGATION
    try:
        f = request.files.get("file")
        if f is None:
            return jsonify({"error": "no file uploaded"}), 400
        res = core.investigate_leak_v2(f.read())
        LAST_INVESTIGATION = res
        return jsonify(res)
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
        recips = store.load_recipients()
        if any("witnesses" in b for b in chain if isinstance(b, dict)):
            ok, msg = ledger_mod.verify_ledger(chain, recips, store.load_custodians())
        else:
            ok, msg = ledger_mod.verify_ledger(chain, recips)
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
    """One-click flagship demo: attested v2 ceremony over independent
    custodian nodes (resets local state, like the CLI). Errors surface."""
    global LAST_INVESTIGATION
    try:
        import demo_attested as attested_mod
        out = attested_mod.hostile_demo()
        if out.get("ok"):
            LAST_INVESTIGATION = {"match": True, "status": "VERIFIED",
                                  "recipient": "RECIPIENT-A"}
        return jsonify(out)
    except Exception as e:  # never hide a crash
        return jsonify({"ok": False, "steps": [], "error": f"{type(e).__name__}: {e}"}), 500


# ---- Independent custodian nodes (Model A loopback relay + Model B files) ----
@app.get("/api/nodes")
def nodes_status():
    """Public per-node state (no secrets): seq, tip, checkpoint linkage."""
    try:
        import nodes as nodes_mod
        reg = store.load_nodes_registry()
        return jsonify({cid: nodes_mod.node_status(cid) for cid in sorted(reg)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/nodes/witness")
def nodes_witness():
    """Demo relay: build the witness request for a block and have one
    independent node validate + sign it (node passphrase filled server-side;
    labeled simulation — production nodes sign on their own hosts).
    Body: {index, custodian_id}."""
    try:
        body = request.get_json(force=True)
        index, custodian_id = body.get("index"), body.get("custodian_id")
        if not isinstance(index, int) or not isinstance(custodian_id, str):
            return jsonify({"error": "index (int) and custodian_id required"}), 400
        import nodes as nodes_mod
        try:
            passphrase = nodes_mod.NODE_PASSPHRASES[custodian_id]
        except KeyError:
            return jsonify({"error": f"unknown custodian node {custodian_id!r}"}), 400
        chain = store.load_ledger()
        req = nodes_mod.build_witness_request(chain, index)
        req["custodian_id"] = custodian_id
        rpkg = nodes_mod.witness_request(req, custodian_id, passphrase)
        # Full signed package is returned so the caller (UI, Model B file
        # exchange, or tests) holds the receipt and aggregates explicitly.
        return jsonify({"custodian_id": custodian_id,
                        "event_id": rpkg["receipt"]["event_id"],
                        "seq": rpkg["receipt"]["seq"],
                        "state_root": rpkg["receipt"]["state_root"],
                        "checkpoint_seq": rpkg["checkpoint"]["seq"],
                        "receipt_package": rpkg})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/nodes/aggregate")
def nodes_aggregate():
    """Collect supplied receipt packages and finalize the block at 2-of-3.
    Body: {index, receipts: [receipt_package, ...]} (Model B import path)."""
    try:
        body = request.get_json(force=True)
        index, rpkgs = body.get("index"), body.get("receipts")
        if not isinstance(index, int) or not isinstance(rpkgs, list):
            return jsonify({"error": "index (int) and receipts (list) required"}), 400
        import nodes as nodes_mod
        block = nodes_mod.aggregate_receipts(store.load_ledger(), index, rpkgs)
        return jsonify({"index": index, "status": block["status"],
                        "witnesses": [w["custodian_id"] for w in block["witnesses"]]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/nodes/export-request")
def nodes_export_request():
    """Model B: export the deterministic witness-request package for a block."""
    try:
        body = request.get_json(force=True)
        index = body.get("index")
        if not isinstance(index, int):
            return jsonify({"error": "index (int) required"}), 400
        import nodes as nodes_mod
        req = nodes_mod.build_witness_request(store.load_ledger(), index)
        return jsonify({"package": req})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.get("/api/nodes/checkpoints/<custodian_id>")
def nodes_checkpoint(custodian_id):
    """Export a node's latest signed checkpoint (+history) for clean-room use."""
    try:
        import nodes as nodes_mod
        cp = store.load_node_checkpoint(custodian_id)
        if cp is None:
            return jsonify({"error": f"no checkpoint for {custodian_id!r}"}), 404
        ok, msg = nodes_mod.verify_checkpoint_history(custodian_id)
        return jsonify({"checkpoint": cp, "history_valid": ok, "history_detail": msg})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===============================================================
# FIREBASE AUTH & SESSION SECURITY APIS
# ===============================================================
@app.post("/api/auth/session")
def auth_create_session():
    """Validates Firebase ID token (Google Auth or Email/Password) and records active session in Firestore."""
    try:
        body = request.get_json(force=True)
        id_token = body.get("idToken")
        if not id_token:
            return jsonify({"error": "idToken is required"}), 400
        
        import auth_service
        ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        user_agent = request.headers.get("User-Agent", "Unknown")
        
        result = auth_service.register_user_session(
            id_token=id_token,
            ip_address=ip_addr,
            user_agent=user_agent
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 401


@app.get("/api/auth/session/<session_id>")
def auth_check_session(session_id):
    """Validates session state directly against Firestore."""
    try:
        import auth_service
        valid, session_data = auth_service.validate_session(session_id)
        if not valid:
            return jsonify({"valid": False, "error": "Session invalid or expired"}), 401
        return jsonify({"valid": True, "session": session_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/auth/logout")
def auth_logout():
    """Revokes active session in Firestore."""
    try:
        body = request.get_json(force=True)
        session_id = body.get("sessionId")
        if not session_id:
            return jsonify({"error": "sessionId required"}), 400
        import auth_service
        revoked = auth_service.revoke_user_session(session_id)
        return jsonify({"success": revoked})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    store.ensure_dirs()
    app.run(host="0.0.0.0", port=5000, debug=False)

