// /* PS26237 — front end. Talks only to the existing /api/* endpoints; no data is invented. */
// (() => {
//   "use strict";

//   const STATE = { status: null, ledger: [], docIndex: {}, selectedBlock: null };

//   const ICON = {
//     check: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>',
//     x: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>',
//     copy: '<svg class="svg-icon" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
//     download: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 4v12M7 11l5 5 5-5"/><path d="M5 20h14"/></svg>',
//     alert: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 9v4.5M12 17v.01"/><path d="M10.3 3.9L2.6 18a1.6 1.6 0 0 0 1.4 2.4h16a1.6 1.6 0 0 0 1.4-2.4L13.7 3.9a1.6 1.6 0 0 0-2.8 0z"/></svg>',
//     info: '<svg class="svg-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/></svg>',
//     doc: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4"/></svg>',
//     shield: '<svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6l7-3z"/></svg>',
//   };

//   // ---------- tiny utilities ----------
//   function el(html) {
//     const t = document.createElement("template");
//     t.innerHTML = html.trim();
//     return t.content.firstElementChild;
//   }
//   function esc(s) {
//     return String(s ?? "").replace(/[&<>"']/g, (c) => ({
//       "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
//     }[c]));
//   }
//   function short(hex, head = 8, tail = 6) {
//     if (!hex || typeof hex !== "string") return "—";
//     if (hex.length <= head + tail + 1) return hex;
//     return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
//   }
//   function timeAgo(iso) {
//     if (!iso) return "—";
//     const then = new Date(iso).getTime();
//     if (Number.isNaN(then)) return iso;
//     const s = Math.max(0, Math.round((Date.now() - then) / 1000));
//     if (s < 5) return "just now";
//     if (s < 60) return `${s}s ago`;
//     const m = Math.round(s / 60);
//     if (m < 60) return `${m}m ago`;
//     const h = Math.round(m / 60);
//     if (h < 24) return `${h}h ago`;
//     const d = Math.round(h / 24);
//     return `${d}d ago`;
//   }
//   function copyRow(label, value, mono = true) {
//     const v = value == null ? "—" : String(value);
//     return `<div class="kv-row">
//       <span class="kv-key">${esc(label)}</span>
//       <span class="kv-val ${mono ? "" : "plain"}">
//         <span class="copy-inline">${esc(v)}${v !== "—" ? `<button class="copy-btn" data-copy="${esc(v)}" title="Copy"> ${ICON.copy}</button>` : ""}</span>
//       </span>
//     </div>`;
//   }
//   async function copyToClipboard(text) {
//     try {
//       await navigator.clipboard.writeText(text);
//       toast("Copied to clipboard", "check");
//     } catch {
//       toast("Could not copy — select manually", "alert");
//     }
//   }
//   document.addEventListener("click", (e) => {
//     const btn = e.target.closest(".copy-btn");
//     if (btn) copyToClipboard(btn.getAttribute("data-copy") || "");
//   });

//   function toast(message, icon = "check") {
//     const stack = document.getElementById("toast-stack");
//     const node = el(`<div class="toast">${ICON[icon] || ICON.check}<span></span></div>`);
//     node.querySelector("span").textContent = message;
//     stack.appendChild(node);
//     setTimeout(() => node.remove(), 3600);
//   }

//   function banner(kind, message) {
//     const cls = kind === "error" ? "banner-error" : kind === "success" ? "banner-success" : "banner-info";
//     const icon = kind === "error" ? ICON.alert : kind === "success" ? ICON.check : ICON.info;
//     return `<div class="banner ${cls}">${icon}<span>${esc(message)}</span></div>`;
//   }

//   // ---------- API ----------
//   async function api(method, url, body) {
//     const opts = { method };
//     if (body !== undefined) {
//       opts.headers = { "Content-Type": "application/json" };
//       opts.body = JSON.stringify(body);
//     }
//     const res = await fetch(url, opts);
//     let data;
//     try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
//     if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
//     return data;
//   }
//   async function apiForm(url, file) {
//     const fd = new FormData();
//     fd.append("file", file);
//     const res = await fetch(url, { method: "POST", body: fd });
//     let data;
//     try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
//     if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
//     return data;
//   }

//   // ---------- navigation ----------
//   const CRUMB = {
//     overview: "PS26237 / Overview", encrypt: "PS26237 / Encrypt", decrypt: "PS26237 / Decrypt",
//     investigate: "PS26237 / Investigate", ledger: "PS26237 / Integrity Ledger",
//     "how-it-works": "PS26237 / How It Works",
//   };
//   function showView(name) {
//     document.querySelectorAll(".view").forEach((v) => v.classList.toggle("is-active", v.dataset.view === name));
//     document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("is-active", n.dataset.view === name));
//     document.getElementById("crumb").textContent = CRUMB[name] || "PS26237";
//     document.getElementById("sidebar").classList.remove("is-open");
//     if (name === "ledger") renderLedgerTable();
//     window.scrollTo(0, 0);
//   }
//   document.getElementById("nav").addEventListener("click", (e) => {
//     const btn = e.target.closest(".nav-item");
//     if (btn) showView(btn.dataset.view);
//   });
//   document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => showView(b.dataset.goto)));
//   document.getElementById("menu-toggle").addEventListener("click", () => {
//     document.getElementById("sidebar").classList.toggle("is-open");
//   });

//   // ---------- status / overview ----------
//   function ledgerChip(ok) {
//     if (ok === null || ok === undefined) return `<span class="chip chip-neutral">CHECKING</span>`;
//     return ok
//       ? `<span class="chip chip-green">${ICON.check}VALID</span>`
//       : `<span class="chip chip-red">${ICON.x}INVALID</span>`;
//   }

//   async function loadStatus() {
//     const d = await api("GET", "/api/status");
//     if (d.error) { toast(d.error, "alert"); return; }
//     STATE.status = d;
//     STATE.docIndex = {};
//     (d.documents || []).forEach((doc) => (STATE.docIndex[doc.doc_id] = doc));

//     document.getElementById("m-recipients").textContent = (d.recipients || []).length;
//     document.getElementById("m-documents").textContent = (d.documents || []).length;
//     document.getElementById("m-events").textContent = d.decryption_events ?? 0;

//     const ledgerVal = document.getElementById("m-ledger");
//     ledgerVal.textContent = d.ledger_valid ? "Valid" : "Invalid";
//     ledgerVal.className = "metric-value " + (d.ledger_valid ? "ok" : "bad");
//     document.getElementById("m-ledger-note").textContent = d.ledger_detail || "";
//     document.getElementById("sb-ledger-chip").outerHTML =
//       `<span class="chip ${d.ledger_valid ? "chip-green" : "chip-red"}" id="sb-ledger-chip">${d.ledger_valid ? ICON.check + "VALID" : ICON.x + "INVALID"}</span>`;

//     // populate decrypt selects
//     const docSel = document.getElementById("select-doc");
//     const recSel = document.getElementById("select-recipient");
//     const prevDoc = docSel.value, prevRec = recSel.value;
//     docSel.innerHTML = (d.documents || []).length
//       ? (d.documents || []).map((x) => `<option value="${esc(x.doc_id)}">${esc(x.filename)} (${esc(short(x.doc_id, 8, 0))})</option>`).join("")
//       : `<option value="">No documents encrypted yet</option>`;
//     recSel.innerHTML = (d.recipients || []).length
//       ? (d.recipients || []).map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join("")
//       : `<option value="">No recipients enrolled</option>`;
//     if ((d.documents || []).some((x) => x.doc_id === prevDoc)) docSel.value = prevDoc;
//     if ((d.recipients || []).includes(prevRec)) recSel.value = prevRec;
//   }

//   async function loadLedger() {
//     const d = await api("GET", "/api/ledger");
//     if (d.error) { toast(d.error, "alert"); return; }
//     STATE.ledger = Array.isArray(d) ? d : [];
//     renderOverviewLedger();
//     if (document.querySelector('.view[data-view="ledger"]').classList.contains("is-active")) renderLedgerTable();
//   }

//   function docLabel(docId) {
//     const doc = STATE.docIndex[docId];
//     return doc ? doc.filename : short(docId, 8, 0);
//   }

//   function renderOverviewLedger() {
//     const wrap = document.getElementById("overview-ledger-wrap");
//     const rows = [...STATE.ledger].reverse().slice(0, 6);
//     if (!rows.length) {
//       wrap.innerHTML = `<div class="empty-state">${ICON.doc}<strong>No decryption events yet</strong><span>Encrypt a document, then decrypt it as a recipient.</span></div>`;
//       return;
//     }
//     wrap.innerHTML = `<table class="data-table"><thead><tr>
//       <th>Document</th><th>Recipient</th><th>Event</th><th>Watermark</th><th>Time</th>
//     </tr></thead><tbody>${rows.map((b) => `
//       <tr>
//         <td><div class="cell-title">${esc(docLabel(b.event.document_id))}</div><div class="cell-sub">${esc(short(b.event.document_hash))}</div></td>
//         <td>${esc(b.signer)}</td>
//         <td class="cell-mono">${esc(short(b.event.event_id, 8, 4))}</td>
//         <td class="cell-mono">${esc(short(b.event.watermark_token_hash, 8, 4))}</td>
//         <td class="cell-mono">${esc(timeAgo(b.timestamp))}</td>
//       </tr>`).join("")}</tbody></table>`;
//   }

//   function renderLedgerTable() {
//     const wrap = document.getElementById("ledger-table-wrap");
//     if (!STATE.ledger.length) {
//       wrap.innerHTML = `<div class="empty-state">${ICON.doc}<strong>Ledger is empty</strong><span>No decryption events have been recorded yet.</span></div>`;
//       return;
//     }
//     const rows = [...STATE.ledger].reverse();
//     wrap.innerHTML = `<table class="data-table"><thead><tr>
//       <th>Block</th><th>Document</th><th>Recipient</th><th>Event ID</th><th>Watermark hash</th><th>Timestamp</th><th>Status</th>
//     </tr></thead><tbody>${rows.map((b) => `
//       <tr class="is-clickable" data-index="${b.index}">
//         <td class="cell-mono">#${b.index}</td>
//         <td><div class="cell-title">${esc(docLabel(b.event.document_id))}</div><div class="cell-sub">${esc(short(b.event.document_hash))}</div></td>
//         <td>${esc(b.signer)}</td>
//         <td class="cell-mono">${esc(short(b.event.event_id, 8, 6))}</td>
//         <td class="cell-mono">${esc(short(b.event.watermark_token_hash, 8, 6))}</td>
//         <td class="cell-mono">${esc(new Date(b.timestamp).toLocaleString())}</td>
//         <td><span class="chip chip-blue">${ICON.shield}SEALED</span></td>
//       </tr>`).join("")}</tbody></table>`;
//     wrap.querySelectorAll("tr.is-clickable").forEach((tr) => {
//       tr.addEventListener("click", () => selectBlock(Number(tr.dataset.index)));
//     });
//   }

//   function selectBlock(index) {
//     const block = STATE.ledger.find((b) => b.index === index);
//     if (!block) return;
//     STATE.selectedBlock = block;
//     const panel = document.getElementById("ledger-detail");
//     panel.style.display = "";
//     panel.open = true;
//     document.getElementById("ledger-detail-body").innerHTML = [
//       copyRow("Block index", block.index, false),
//       copyRow("Block hash", block.block_hash),
//       copyRow("Previous hash", block.prev_hash),
//       copyRow("Timestamp", block.timestamp, false),
//       copyRow("Signer (recipient)", block.signer, false),
//       copyRow("Signature (ML-DSA-65)", short(block.signature, 14, 10)),
//       copyRow("Event ID", block.event.event_id),
//       copyRow("Document", docLabel(block.event.document_id), false),
//       copyRow("Document ID", block.event.document_id),
//       copyRow("Document hash (SHA-256)", block.event.document_hash),
//       copyRow("Watermark token hash", block.event.watermark_token_hash),
//     ].join("");
//     panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
//   }

//   document.getElementById("btn-refresh-ledger").addEventListener("click", async () => {
//     await Promise.all([loadStatus(), loadLedger()]);
//     toast("Ledger refreshed");
//   });

//   document.getElementById("btn-verify-ledger").addEventListener("click", async () => {
//     const out = document.getElementById("ledger-verify-banner");
//     out.innerHTML = banner("info", "Verifying hash chain and ML-DSA signatures…");
//     const d = await api("POST", "/api/verify");
//     out.innerHTML = banner(d.valid ? "success" : "error", d.detail || (d.valid ? "Ledger valid." : "Ledger invalid."));
//     await loadStatus();
//   });

//   document.getElementById("btn-init").addEventListener("click", async () => {
//     const d = await api("POST", "/api/init");
//     if (d.error) { toast(d.error, "alert"); appendLog(`[FAIL] init: ${d.error}`); return; }
//     toast(`Initialized ${d.recipients.length} recipients`);
//     appendLog(`[ok] init: recipients = ${d.recipients.join(", ")}`);
//     await loadStatus();
//   });

//   function appendLog(line) {
//     const body = document.getElementById("overview-log-body");
//     if (body.textContent.trim() === "No actions run yet this session.") body.textContent = "";
//     body.textContent += (body.textContent ? "\n" : "") + line;
//     document.getElementById("overview-log").open = true;
//   }

//   document.getElementById("btn-demo").addEventListener("click", async () => {
//     const btn = document.getElementById("btn-demo");
//     btn.disabled = true;
//     const original = btn.innerHTML;
//     btn.innerHTML = `<span class="spinner"></span> Running demo…`;
//     appendLog("[ok] demo: starting full pipeline run (resets local state)…");
//     const d = await api("POST", "/api/demo");
//     btn.disabled = false;
//     btn.innerHTML = original;
//     if (!d.ok) {
//       toast(d.error || "Demo failed", "alert");
//       appendLog(`[FAIL] demo: ${d.error || "unknown error"}`);
//       (d.steps || []).forEach((s) => appendLog(`[${s.ok ? "ok" : "FAIL"}] ${s.name}: ${s.detail}`));
//       await loadStatus();
//       await loadLedger();
//       return;
//     }
//     (d.steps || []).forEach((s) => appendLog(`[${s.ok ? "ok" : "FAIL"}] ${s.name}: ${s.detail}`));
//     toast("Full demo completed");
//     await loadStatus();
//     await loadLedger();
//   });

//   // ---------- dropzone helper ----------
//   function wireDropzone(zoneId, inputId, fileLabelId, onFile) {
//     const zone = document.getElementById(zoneId);
//     const input = document.getElementById(inputId);
//     const label = document.getElementById(fileLabelId);
//     input.addEventListener("change", () => {
//       if (input.files[0]) { label.textContent = input.files[0].name; onFile(input.files[0]); }
//     });
//     ["dragover", "dragenter"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("is-drag"); }));
//     ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("is-drag"); }));
//     zone.addEventListener("drop", (e) => {
//       const f = e.dataTransfer.files[0];
//       if (!f) return;
//       if (f.type !== "application/pdf") { toast("Please choose a PDF file", "alert"); return; }
//       input.files = e.dataTransfer.files;
//       label.textContent = f.name;
//       onFile(f);
//     });
//   }

//   // ---------- Encrypt ----------
//   let encryptFile = null;
//   wireDropzone("dropzone-encrypt", "file-encrypt", "dropzone-encrypt-file", (f) => {
//     encryptFile = f;
//     document.getElementById("btn-encrypt").disabled = false;
//   });
//   document.getElementById("btn-encrypt").addEventListener("click", async () => {
//     if (!encryptFile) return;
//     const bannerEl = document.getElementById("banner-encrypt");
//     const btn = document.getElementById("btn-encrypt");
//     bannerEl.innerHTML = "";
//     btn.disabled = true;
//     const original = btn.innerHTML;
//     btn.innerHTML = `<span class="spinner"></span> Encrypting…`;
//     const pcLabel = (document.getElementById("input-pc-label") || {}).value || "";
    const d = await apiForm("/api/encrypt", encryptFile, { pc_label: pcLabel.trim() });
//     btn.disabled = false;
//     btn.innerHTML = original;
//     if (d.error) {
//       bannerEl.innerHTML = banner("error", d.error);
//       return;
//     }
//     bannerEl.innerHTML = banner("success", "Document sealed. The original key never leaves this device.");
//     document.getElementById("encrypt-result").innerHTML = `
//       <div class="gap-col">
//         <div class="banner banner-info" style="background:var(--paper);border-color:var(--hairline)">
//           ${ICON.doc}<span><strong>${esc(d.filename)}</strong> — sealed for ${d.recipients.length} recipient${d.recipients.length === 1 ? "" : "s"}</span>
//         </div>
//         <div class="kv-list">
//           ${copyRow("Document ID", d.doc_id)}
//           ${copyRow("Document hash (SHA-256)", d.document_hash)}
//           ${copyRow("Recipients enveloped", d.recipients.join(", "), false)}
//         </div>
//       </div>`;
//     toast("Document encrypted");
//     await loadStatus();
//   });

//   // ---------- Decrypt ----------
//   document.getElementById("btn-decrypt").addEventListener("click", async () => {
//     const docId = document.getElementById("select-doc").value;
//     const recipientId = document.getElementById("select-recipient").value;
//     const bannerEl = document.getElementById("banner-decrypt");
//     bannerEl.innerHTML = "";
//     if (!docId || !recipientId) { bannerEl.innerHTML = banner("error", "Choose a document and a recipient."); return; }
//     const btn = document.getElementById("btn-decrypt");
//     btn.disabled = true;
//     const original = btn.innerHTML;
//     btn.innerHTML = `<span class="spinner"></span> Decrypting…`;
//     const d = await api("POST", "/api/decrypt", { doc_id: docId, recipient_id: recipientId });
//     btn.disabled = false;
//     btn.innerHTML = original;
//     if (d.error) { bannerEl.innerHTML = banner("error", d.error); return; }
//     bannerEl.innerHTML = banner("success", "Decrypted, watermarked and signed. Recorded on the ledger.");
//     document.getElementById("decrypt-result").innerHTML = `
//       <div class="gap-col">
//         <div class="banner banner-info" style="background:var(--paper);border-color:var(--hairline)">
//           ${ICON.shield}<span>Signed event for <strong>${esc(d.recipient_id)}</strong> on ${esc(docLabel(d.doc_id))}</span>
//         </div>
//         <a class="btn btn-primary btn-block" href="${d.download}">${ICON.download} Download watermarked copy</a>
//         <div class="kv-list">
//           ${copyRow("Event ID", d.event_id)}
//           ${copyRow("Ledger block", "#" + d.block_index, false)}
//           ${copyRow("Document hash (SHA-256)", d.document_hash)}
//           ${copyRow("Watermark token hash", d.watermark_token_hash)}
//           ${copyRow("ML-DSA-65 signature", d.signature)}
//           ${copyRow("Timestamp", d.timestamp, false)}
//         </div>
//       </div>`;
//     toast("Decryption recorded");
//     await loadStatus();
//     await loadLedger();
//   });

//   // ---------- Investigate ----------
//   let investigateFileRef = null;
//   wireDropzone("dropzone-investigate", "file-investigate", "dropzone-investigate-file", (f) => {
//     investigateFileRef = f;
//     document.getElementById("btn-investigate").disabled = false;
//   });
//   document.getElementById("btn-investigate").addEventListener("click", async () => {
//     if (!investigateFileRef) return;
//     const bannerEl = document.getElementById("banner-investigate");
//     const resultEl = document.getElementById("investigate-result");
//     bannerEl.innerHTML = "";
//     const btn = document.getElementById("btn-investigate");
//     btn.disabled = true;
//     const original = btn.innerHTML;
//     btn.innerHTML = `<span class="spinner"></span> Analyzing…`;
//     resultEl.innerHTML = `<div class="empty-state"><div class="spinner dark"></div><span>Extracting watermark and checking the ledger…</span></div>`;
//     const d = await apiForm("/api/investigate", investigateFileRef);
//     btn.disabled = false;
//     btn.innerHTML = original;
//     if (d.error) { bannerEl.innerHTML = banner("error", d.error); resultEl.innerHTML = ""; return; }
//     resultEl.innerHTML = renderVerdict(d);
//     toast(d.match ? "Forensic match found" : "No verified match");
//     await loadStatus();
//   });

//   function evidenceRow(pass, title, detail) {
//     return `<div class="evidence-row">
//       <div class="evidence-icon ${pass ? "pass" : "fail"}">${pass ? ICON.check : ICON.x}</div>
//       <div class="evidence-text"><span class="evidence-title">${esc(title)}</span><span class="evidence-detail">${esc(detail)}</span></div>
//     </div>`;
//   }

//   function renderVerdict(d) {
//     if (!d.match) {
//       return `
//         <div class="verdict verdict-nomatch">
//           <div class="verdict-top">
//             <div class="verdict-icon">${ICON.x}</div>
//             <div><div class="verdict-heading">Not verified</div><div class="verdict-sub">${esc(d.status || "NOT VERIFIED")}</div></div>
//           </div>
//           <p class="verdict-body">${esc(d.conclusion || "No verified decryption event matches this file.")}</p>
//           ${d.reason ? `<p class="verdict-body text-muted">Reason: ${esc(d.reason)}</p>` : ""}
//         </div>
//         <details class="tech mt-16">
//           <summary>Technical details / cryptographic proof <svg class="svg-icon chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></summary>
//           <div class="tech-body kv-list">
//             ${copyRow("Watermark", d.watermark || "NOT FOUND", false)}
//             ${d.watermark_token_hash ? copyRow("Watermark token hash", d.watermark_token_hash) : ""}
//           </div>
//         </details>`;
//     }
//     return `
//       <div class="verdict verdict-match">
//         <div class="verdict-top">
//           <div class="verdict-icon">${ICON.check}</div>
//           <div><div class="verdict-heading">Verified match — attributed to ${esc(d.recipient)}</div><div class="verdict-sub">${esc(d.status)} &bull; ${esc(new Date(d.timestamp).toLocaleString())}</div></div>
//         </div>
//         <p class="verdict-body">${esc(d.conclusion)}</p>
//         <div class="evidence-list">
//           ${evidenceRow(true, "Watermark matched", "Token extracted from the leaked file matches a ledger record")}
//           ${evidenceRow(d.mldsa_signature === "VALID", "ML-DSA-65 signature", d.mldsa_signature === "VALID" ? "Signature over the event is cryptographically valid" : "Signature check failed")}
//           ${evidenceRow(d.ledger_integrity === "VALID", "Ledger integrity", d.ledger_integrity === "VALID" ? "Hash chain intact end to end" : String(d.ledger_integrity))}
//         </div>
//         ${d.scope ? `
//         <div class="verdict-scope">
//           <div class="scope-box"><h4>Cryptographic attribution</h4><p>${esc(d.scope.cryptographic_attribution)}</p></div>
//           <div class="scope-box"><h4>Physical attribution</h4><p>${esc(d.scope.physical_attribution)}</p></div>
//         </div>` : ""}
//       </div>
//       <details class="tech mt-16">
//         <summary>Technical details / cryptographic proof <svg class="svg-icon chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></summary>
//         <div class="tech-body kv-list">
//           ${copyRow("Event ID", d.event_id)}
//           ${copyRow("Ledger block", "#" + d.block_index, false)}
//           ${copyRow("Document hash (SHA-256)", d.document_hash)}
//           ${copyRow("Watermark token hash", d.watermark_token_hash)}
//         </div>
//       </details>`;
//   }

//   // ---------- init ----------
//   (async function init() {
//     await loadStatus();
//     await loadLedger();
//   })();
// })();


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
  const BACKEND_BASE = (window.location.hostname.includes("firebaseapp.com") || window.location.hostname.includes("web.app"))
    ? "https://parmaan-5768.onrender.com"
    : "";

  async function api(method, url, body) {
    const fullUrl = url.startsWith("/") ? BACKEND_BASE + url : url;
    const opts = { method };
    if (body !== undefined) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(fullUrl, opts);
    let data;
    try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
    if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
    return data;
  }
  async function apiForm(url, file, extra) {
    const fullUrl = url.startsWith("/") ? BACKEND_BASE + url : url;
    const fd = new FormData();
    fd.append("file", file);
    if (extra) Object.entries(extra).forEach(([k, v]) => { if (v) fd.append(k, v); });
    const res = await fetch(fullUrl, { method: "POST", body: fd });
    let data;
    try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
    if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
    return data;
  }

  // ---------- navigation ----------
  const CRUMB = {
    overview: "PRAMAAN / Overview", encrypt: "PRAMAAN / Encrypt", decrypt: "PRAMAAN / Decrypt",
    investigate: "PRAMAAN / Investigate", ledger: "PRAMAAN / Integrity Ledger",
    robustness: "PRAMAAN / Screenshot Robustness",
    "how-it-works": "PRAMAAN / How It Works",
  };
  function showView(name) {
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("is-active", v.dataset.view === name));
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("is-active", n.dataset.view === name));
    document.getElementById("crumb").textContent = CRUMB[name] || "PRAMAAN";
    document.getElementById("sidebar").classList.remove("is-open");
    if (name === "ledger") renderLedgerTable();
    if (name === "robustness") renderRobustness();
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
    let ledgerNote = d.ledger_detail || "";
    if (d.quorum && typeof d.quorum.final === "number") {
      ledgerNote += ` · quorum ${d.quorum.final} FINAL / ${d.quorum.pending} PENDING`;
    }
    if (d.protocol) ledgerNote += ` · ${d.protocol}`;
    document.getElementById("m-ledger-note").textContent = ledgerNote;
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
    const revRec = document.getElementById("select-revoke-recipient");
    const revCus = document.getElementById("select-revoke-custodian");
    if (revRec && revCus) {
      revRec.innerHTML = (d.recipients || []).length
        ? (d.recipients || []).map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join("")
        : `<option value="">No recipients enrolled</option>`;
      revCus.innerHTML = (d.custodians || []).length
        ? (d.custodians || []).map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join("")
        : `<option value="">No custodians</option>`;
    }
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
        <td>${quorumChip(b)}</td>
      </tr>`).join("")}</tbody></table>`;
    wrap.querySelectorAll("tr.is-clickable").forEach((tr) => {
      tr.addEventListener("click", () => selectBlock(Number(tr.dataset.index)));
    });
  }

  // PS26237-v2: v2 blocks show quorum state; v1 blocks keep the legacy SEALED chip.
  function quorumChip(b) {
    if (!("witnesses" in (b || {}))) return `<span class="chip chip-blue">${ICON.shield}SEALED</span>`;
    const n = (b.witnesses || []).length;
    if (b.status === "FINAL") return `<span class="chip chip-green">${ICON.check}FINAL ${n}/3</span>`;
    return `<span class="chip chip-neutral">PENDING ${n}/3</span>`;
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
      block.signature ? copyRow("Signature (ML-DSA-65)", short(block.signature, 14, 10)) : "",
      ("witnesses" in block) ? copyRow("Quorum status",
        `${block.status} (${(block.witnesses || []).length}-of-3 witnesses)`, false) : "",
      ((block.witnesses || []).map((w) => copyRow(`Witness ${w.custodian_id}`, short(w.signature_hex, 14, 10)))).join(""),
      copyRow("Event ID", block.event.event_id),
      copyRow("Document", docLabel(block.event.document_id), false),
      copyRow("Document ID", block.event.document_id),
      copyRow("Document hash (SHA-256)", block.event.document_hash),
      copyRow("Watermark token hash", block.event.watermark_token_hash),
      block.event.protocol_version ? copyRow("Protocol", block.event.protocol_version, false) : "",
      block.event.authorization_signature_hex ? copyRow("Authorization (ML-DSA-65)",
        short(block.event.authorization_signature_hex, 14, 10)) : "",
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
  const ACCEPTED_EXTENSIONS = [".pdf", ".txt", ".md"];
  function isAcceptedFile(f) {
    const name = (f.name || "").toLowerCase();
    return ACCEPTED_EXTENSIONS.some((ext) => name.endsWith(ext));
  }
  function wireDropzone(zoneId, inputId, fileLabelId, onFile) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const label = document.getElementById(fileLabelId);
    input.addEventListener("change", () => {
      const f = input.files[0];
      if (!f) return;
      if (!isAcceptedFile(f)) { toast("Please choose a PDF, TXT, or MD file", "alert"); input.value = ""; return; }
      label.textContent = f.name;
      onFile(f);
    });
    ["dragover", "dragenter"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("is-drag"); }));
    ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("is-drag"); }));
    zone.addEventListener("drop", (e) => {
      const f = e.dataTransfer.files[0];
      if (!f) return;
      if (!isAcceptedFile(f)) { toast("Please choose a PDF, TXT, or MD file", "alert"); return; }
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
          ${copyRow("Fingerprint (SHA-256)", d.fingerprint || d.document_hash)}
          ${d.pc_id ? copyRow("Encrypted on PC", d.pc_label ? `${d.pc_id} (${d.pc_label})` : d.pc_id, false) : ""}
          ${d.encrypted_at ? copyRow("Encrypted at", new Date(d.encrypted_at).toLocaleString(), false) : ""}
          ${copyRow("Recipients enveloped", d.recipients.join(", "), false)}
        </div>
      </div>`;
    toast("Document encrypted");
    await loadStatus();
  });

  // ---------- Decrypt (attested v2 ceremony over independent nodes) ----------
  document.getElementById("btn-decrypt").addEventListener("click", async () => {
    const docId = document.getElementById("select-doc").value;
    const recipientId = document.getElementById("select-recipient").value;
    const bannerEl = document.getElementById("banner-decrypt");
    bannerEl.innerHTML = "";
    if (!docId || !recipientId) { bannerEl.innerHTML = banner("error", "Choose a document and a recipient."); return; }
    const btn = document.getElementById("btn-decrypt");
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Challenge, authorize, release…`;
    const d = await api("POST", "/api/attested-decrypt", { doc_id: docId, recipient_id: recipientId });
    btn.disabled = false;
    btn.innerHTML = original;
    if (d.error) { bannerEl.innerHTML = banner("error", d.error); return; }
    bannerEl.innerHTML = banner("success", "Authorized release recorded as PENDING — needs 2 independent custodian witnesses.");
    renderAttestedRelease(d);
    toast("Attested release recorded (PENDING)");
    await loadStatus();
    await loadLedger();
  });

  const WITNESS_IDS = ["CUSTODIAN-1", "CUSTODIAN-2", "CUSTODIAN-3"];

  function witnessButtons(blockIndex, done) {
    done = done || [];
    return `<div class="gap-col" style="margin-top:8px">
      <span class="text-muted" style="font-size:12px">Independent node witnesses (${done.length}/3 recorded, 2 needed for FINAL):</span>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${WITNESS_IDS.map((cid) => `<button class="btn btn-sm witness-btn" data-index="${blockIndex}" data-cid="${cid}" data-event="${window.__lastEventId || ""}" ${done.includes(cid) ? "disabled" : ""}>${esc(cid)}${done.includes(cid) ? " ✓" : ""}</button>`).join("")}
      </div>
      <span class="text-muted" style="font-size:12px">Each node validates the event against its own enrollment snapshot before signing. Demo relay fills node secrets server-side (simulation).</span>
    </div>`;
  }

  function renderAttestedRelease(d, done) {
    window.__lastEventId = d.event_id;
    window.__receipts = [];
    document.getElementById("decrypt-result").innerHTML = `
      <div class="gap-col">
        <div class="banner banner-info" style="background:var(--paper);border-color:var(--hairline)">
          ${ICON.shield}<span>Attested release for <strong>${esc(d.recipient_id)}</strong> — block <strong>#${d.block_index}</strong> <strong id="release-status">${esc(d.status || "PENDING")}</strong></span>
        </div>
        <div id="witness-zone">${witnessButtons(d.block_index, done)}</div>
        <div class="kv-list">
          ${copyRow("Event ID", d.event_id)}
          ${copyRow("Ledger block", "#" + d.block_index, false)}
          ${copyRow("Document hash (SHA-256)", d.document_hash)}
          ${copyRow("Watermark token hash", d.watermark_token_hash)}
          ${copyRow("Copy hash (SHA-256)", d.copy_hash || "—")}
          ${copyRow("Timestamp", d.timestamp, false)}
          ${d.simulated_device ? copyRow("Device step", "simulated recipient device (demo)", false) : ""}
        </div>
        <div id="download-zone"></div>
      </div>`;
  }

  // Single delegated handler: survives re-renders of the witness zone.
  // Each node returns its signed receipt package; the UI aggregates them
  // explicitly (Model B semantics) — FINAL only at 2 distinct valid receipts.
  document.getElementById("decrypt-result").addEventListener("click", async (e) => {
    const b = e.target.closest(".witness-btn");
    if (!b || b.disabled) return;
    b.disabled = true;
    const idx = Number(b.dataset.index);
    const r = await api("POST", "/api/nodes/witness", { index: idx, custodian_id: b.dataset.cid });
    if (r.error) { toast(r.error, "alert"); b.disabled = false; return; }
    if (r.receipt_package) window.__receipts.push(r.receipt_package);
    const agg = await api("POST", "/api/nodes/aggregate", { index: idx, receipts: window.__receipts });
    const zone = document.getElementById("witness-zone");
    const doneNow = [...zone.querySelectorAll(".witness-btn")].filter((x) => x.disabled).map((x) => x.dataset.cid);
    if (!doneNow.includes(b.dataset.cid)) doneNow.push(b.dataset.cid);
    zone.innerHTML = witnessButtons(idx, doneNow);
    if (!agg.error && agg.status === "FINAL") {
      const st = document.getElementById("release-status");
      if (st) st.textContent = "FINAL";
      zone.querySelectorAll(".witness-btn").forEach((x) => { x.disabled = true; });
      const ev = window.__lastEventId || "";
      if (ev) document.getElementById("download-zone").innerHTML =
        `<a class="btn btn-primary btn-block" href="/api/copy/${ev}">${ICON.download} Download fingerprinted copy (FINAL)</a>`;
      toast("Block FINAL — 2 independent witnesses", "check");
    } else if (agg.error && /quorum|PENDING/i.test(agg.error)) {
      toast(`Receipt ${doneNow.length}/3 collected — block PENDING (need 2)`);
    } else if (agg.error) {
      toast(agg.error, "alert");
    }
    await loadStatus();
    await loadLedger();
  });

  // ---------- Revoke (custodian-authorized, demo-signed) ----------
  document.getElementById("btn-revoke").addEventListener("click", async () => {
    const recipientId = document.getElementById("select-revoke-recipient").value;
    const custodianId = document.getElementById("select-revoke-custodian").value;
    const bannerEl = document.getElementById("banner-revoke");
    bannerEl.innerHTML = "";
    if (!recipientId || !custodianId) { bannerEl.innerHTML = banner("error", "Choose a recipient and an authorizing custodian."); return; }
    const d = await api("POST", "/api/demo-revoke", { recipient_id: recipientId, custodian_id: custodianId });
    if (d.error) { bannerEl.innerHTML = banner("error", d.error); return; }
    bannerEl.innerHTML = banner("success", `${recipientId} revoked by ${custodianId}. History stays verifiable.`);
    toast("Recipient revoked");
    await loadStatus();
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

  // ---------- Screenshot / photo leak (LatticeMark pixels) ----------
  let shotFileRef = null;
  wireDropzone("dropzone-shot", "file-shot", "dropzone-shot-file", (f) => {
    shotFileRef = f;
    document.getElementById("btn-shot").disabled = false;
  });
  document.getElementById("btn-shot").addEventListener("click", async () => {
    if (!shotFileRef) return;
    const bannerEl = document.getElementById("banner-shot");
    const resultEl = document.getElementById("investigate-result");
    bannerEl.innerHTML = "";
    const btn = document.getElementById("btn-shot");
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Decoding pixels…`;
    resultEl.innerHTML = `<div class="empty-state"><div class="spinner dark"></div><span>Blind-decoding the pixel lattice, no original needed…</span></div>`;
    const fd = new FormData();
    fd.append("file", shotFileRef);
    const res = await fetch(BACKEND_BASE + "/api/investigate/image", { method: "POST", body: fd });
    let d;
    try { d = await res.json(); } catch { d = { error: `HTTP ${res.status}` }; }
    btn.disabled = false;
    btn.innerHTML = original;
    if (!res.ok && !d.error) d.error = `HTTP ${res.status}`;
    if (d.error) { bannerEl.innerHTML = banner("error", d.error); resultEl.innerHTML = ""; return; }
    resultEl.innerHTML = renderVerdict(d);
    toast(d.match ? "Screenshot attributed" : "No verified match");
    await loadStatus();
  });

  // ---------- Robustness matrix ----------
  async function renderRobustness() {
    const wrap = document.getElementById("robustness-table-wrap");
    if (!wrap) return;
    wrap.innerHTML = `<div class="empty-state"><div class="spinner dark"></div></div>`;
    const d = await api("GET", "/api/robustness");
    if (d.error) { wrap.innerHTML = `<div class="empty-state"><strong>Measurements unavailable</strong><span>${esc(d.error)}</span></div>`; return; }
    const matrix = d.matrix || {};
    const qs = [95, 75, 60, 40], scales = ["1.0", "0.75", "0.5"], crops = ["full", "half", "quarter"];
    let html = `<table class="data-table"><thead><tr><th>JPEG ↓ / scale × crop →</th>${scales.map((s) => crops.map((c) => `<th>x${s} ${c}</th>`).join("")).join("")}</tr></thead><tbody>`;
    for (const q of qs) {
      html += `<tr><td class="cell-mono">q${q}</td>`;
      for (const s of scales) {
        for (const c of crops) {
          const m = matrix[`q${q}/x${s}/${c}`];
          if (!m) { html += `<td>—</td>`; continue; }
          const ok = m.ok === m.n;
          const cls = ok ? "chip-green" : (m.ok === 0 ? "chip-red" : "chip-neutral");
          html += `<td><span class="chip ${cls}">${m.ok}/${m.n}</span></td>`;
        }
      }
      html += `</tr>`;
    }
    html += `</tbody></table><p class="card-sub" style="margin:8px 0 0">Blind decodes per 6 random fingerprints (108dpi sim: crop → downscale → JPEG). Quarter-crop keeps &lt;2 full tiles — the documented decode floor.</p>`;
    wrap.innerHTML = html;
  }
  document.getElementById("btn-robustness").addEventListener("click", renderRobustness);

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
        ${d.binding_note ? `<p class="verdict-body text-muted">${esc(d.binding_note)}</p>` : ""}
        ${d.encryption && d.encryption.found ? `<div class="banner banner-info" style="background:var(--paper);border-color:var(--hairline)">${ICON.shield}<span>Encrypted <strong>${esc(new Date(d.encryption.encrypted_at).toLocaleString())}</strong> on PC <strong>${esc(d.encryption.pc_label ? `${d.encryption.pc_id} (${d.encryption.pc_label})` : d.encryption.pc_id)}</strong> &mdash; file <strong>${esc(d.encryption.filename)}</strong></span></div>` : ""}
        ${d.encryption && !d.encryption.found ? `<p class="verdict-body text-muted">Encryption origin: no record in the common DB for this file.</p>` : ""}
        <div class="evidence-list">
          ${evidenceRow(true, "Watermark matched", "Token extracted from the leaked file matches a ledger record")}
          ${d.authorization ? evidenceRow(d.authorization === "VALID", "Recipient authorization",
            d.authorization === "VALID" ? "Recipient device signed this document session (ML-DSA-65)" : `Authorization check: ${d.authorization}`) : ""}
          ${d.derivation ? evidenceRow(d.derivation === "VALID", "Provenance binding",
            d.derivation === "VALID" ? "Fingerprint re-derives from the authorization (HKDF-SHA256)" : `Derivation check: ${d.derivation}`) : ""}
          ${d.binding ? (d.binding === "ANALOG-HOLE"
            ? evidenceRow(true, "Analog-hole binding", "Screenshot never byte-matches by design — attribution rests on fingerprint + authorization + quorum")
            : evidenceRow(d.binding === "VALID", "Copy binding",
              d.binding === "VALID" ? "Leaked bytes equal the recorded copy (SHA-256)" : `Binding check: ${d.binding}`)) : ""}
          ${d.lattice ? evidenceRow(true, "Pixel lattice",
            `Decoded with ${d.lattice.tiles_voted ?? "?"} tile votes, header agreement ${d.lattice.mean_header_agree ?? "? "}/16`) : ""}
          ${d.channel ? evidenceRow(true, "Channel", d.channel === "pixels-latticemark" ? "LatticeMark pixel lattice (screenshot/photo)" : String(d.channel)) : ""}
          ${d.quorum ? evidenceRow(String(d.quorum).startsWith("FINAL"), "Custodian quorum",
            String(d.quorum).startsWith("FINAL") ? "2-of-3 custodian witnesses reached" : `Quorum: ${d.quorum}`) : ""}
          ${evidenceRow(d.mldsa_signature === "VALID" || d.authorization === "VALID", "ML-DSA-65 signature", (d.mldsa_signature === "VALID" || d.authorization === "VALID") ? "Signature over the event is cryptographically valid" : "Signature check failed")}
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