"""LatticeMark: analog-hole forensic watermark (PS26237-v2 screenshot layer).

Why this exists: the text-layer carriers (`watermark.py`, `watermark_text.py`)
die the moment a page is rasterized — screenshot, JPEG recompression, resize,
crop, phone-photo-of-screen. That is precisely how real leaks happen, and it
is the gap the brief's "live screenshot demo" row demands we close.

Method (novel combination, all local/offline):
  - At decryption time, every PDF page gets a tiled lattice of micro-dots
    (vector circles, ~1pt radius, ~93% gray on white: invisible at normal
    viewing distance, no text-layer change, text selection untouched).
  - Each tile encodes a 16-bit sync header + the same 128-bit event
    fingerprint the text layer carries (whitened with a public fixed mask so
    dot density stays ~50% for any token). Encoding is presence/absence
    (on-off keying) per lattice cell: JPEG, scaling and cropping all
    preserve "a dark speck is/isn't near this lattice point".
  - Decoding is fully blind (no original needed): background subtraction ->
    uniform-dot filtering -> FFT lattice-period estimation -> phase search ->
    sync-header lock -> per-window payload tally with a 2-tile consensus
    rule -> token hex. The ledger lookup (SHA-256 of the token) is the final
    error check: a mis-decode matches no signed event, so false attribution
    is cryptographically impossible.
  - Robust by construction to: screenshot rasterization, JPEG recompression,
    uniform rescaling (periods are re-estimated from the image itself),
    cropping (tiles repeat across the page; any 2 surviving tiles decode),
    mild brightness/contrast shifts (adaptive threshold).

Honest limits: rotation/skew beyond ~2 degrees is not corrected (screenshots
are axis-aligned); fewer than 2 surviving tiles cannot decode; .txt/.md
documents have no pixel domain so they keep the dual text channels only.

No networking. Dependencies: reportlab + pypdf (embed), PIL + numpy +
opencv (decode), pymupdf only inside the rasterize helper (demo/harness).
"""
import hashlib
import io
import re

import numpy as np
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

TOKEN_HEX_LEN = 32  # same 128-bit token format as watermark.py
PAYLOAD_BITS = TOKEN_HEX_LEN * 4  # 128

# ---- tile geometry (PDF points; 72pt = 1in) ----
COLS, ROWS = 18, 8
HEADER_LEN = 16
TILE_BITS = COLS * ROWS  # 144 = 16 header + 128 payload
CELL_PT = 18.0
DOT_R_PT = 1.4
DOT_GRAY = 0.93  # near-white: invisible at a glance, detectable in pixels
MARGIN_PT = 36.0

# Decode policy
HEADER_AGREE_MIN = 14  # of 16 sync bits must match for a tile to vote
CONSENSUS_TILES_MIN = 2  # identical-token windows required (kills false locks)

# Fixed public sync header (alternating + end marker) and whitening mask.
SYNC_HEADER = tuple([1, 0] * 7 + [1, 1])
_MASK_BYTES = hashlib.sha256(b"PS26237-LatticeMark/mask/v1").digest()
WHITEMASK = tuple((b >> i) & 1 for b in _MASK_BYTES[:18] for i in range(8))[:TILE_BITS]

_HEX_RE = re.compile(r"[0-9a-f]{%d}" % TOKEN_HEX_LEN)


def _validate_token(token_hex: str) -> None:
    if len(token_hex) != TOKEN_HEX_LEN or not _HEX_RE.fullmatch(token_hex):
        raise ValueError("token_hex must be 32 lowercase hex chars")


def _token_to_bits(token_hex: str) -> list:
    _validate_token(token_hex)
    bits = []
    for ch in token_hex:
        bits.extend(int(b) for b in f"{int(ch, 16):04b}")
    return bits


def _bits_to_token(bits) -> str | None:
    if len(bits) != PAYLOAD_BITS:
        return None
    try:
        token = "".join(
            f"{int(''.join(str(x) for x in bits[i:i + 4]), 2):x}"
            for i in range(0, len(bits), 4))
    except Exception:
        return None
    return token if _HEX_RE.fullmatch(token) else None


def _tile_bits(token_hex: str) -> list:
    payload = _token_to_bits(token_hex)
    raw = list(SYNC_HEADER) + payload
    return [(b ^ m) for b, m in zip(raw, WHITEMASK)]


# ---------------------------------------------------------------- embed ----
def _overlay_for_size(width: float, height: float, token_hex: str) -> bytes:
    bits = _tile_bits(token_hex)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(width, height))
    c.setFillColorRGB(DOT_GRAY, DOT_GRAY, DOT_GRAY, alpha=1)
    tile_w, tile_h = COLS * CELL_PT, ROWS * CELL_PT
    y = MARGIN_PT
    while y + tile_h <= height - MARGIN_PT + 1e-6:
        x = MARGIN_PT
        while x + tile_w <= width - MARGIN_PT + 1e-6:
            for r in range(ROWS):
                for col in range(COLS):
                    if bits[r * COLS + col]:
                        cx = x + (col + 0.5) * CELL_PT
                        cy = y + (r + 0.5) * CELL_PT
                        c.circle(cx, cy, DOT_R_PT, fill=1, stroke=0)
            x += tile_w
        y += tile_h
    c.showPage()
    c.save()
    return buf.getvalue()


def count_tiles(width: float, height: float) -> int:
    """How many full tiles fit on a page of this size (diagnostics)."""
    tile_w, tile_h = COLS * CELL_PT, ROWS * CELL_PT
    nx = int((width - 2 * MARGIN_PT) // tile_w)
    ny = int((height - 2 * MARGIN_PT) // tile_h)
    return max(0, nx) * max(0, ny)


def embed_lattice(pdf_bytes: bytes, token_hex: str) -> bytes:
    """Return a copy of the PDF with the LatticeMark dot tiles on every page.

    Additive to the text-layer watermark: it changes no text, breaks no
    text extraction, and is visually negligible (near-white micro-dots).
    """
    _validate_token(token_hex)
    reader = PdfReader(io.BytesIO(pdf_bytes))
    if len(reader.pages) == 0:
        raise ValueError("PDF has no pages")
    writer = PdfWriter()
    cache: dict = {}
    for page in reader.pages:
        box = page.mediabox
        size = (float(box.width), float(box.height))
        ov = cache.get(size)
        if ov is None:
            ov = PdfReader(
                io.BytesIO(_overlay_for_size(size[0], size[1], token_hex))).pages[0]
            cache[size] = ov
        page.merge_page(ov)
        writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# --------------------------------------------------------------- raster ----
def rasterize_pdf_page(pdf_bytes: bytes, page: int = 0, zoom: float = 2.0):
    """Render one PDF page to a grayscale PIL image (demo/harness helper)."""
    import pymupdf  # local import: rasterizer needed only for screenshot sim
    doc = pymupdf.open(stream=bytes(pdf_bytes), filetype="pdf")
    pix = doc[page].get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
    doc.close()
    from PIL import Image
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    return img.convert("L")


# --------------------------------------------------------------- decode ----
def _candidate_periods(proj: np.ndarray, lo: int, hi: int, top: int = 3):
    """Top-N period candidates (robust against text-line-pitch hijack: the
    true lattice period only needs to be *among* the candidates, the sync
    header decides)."""
    n = len(proj)
    out = []
    if n < hi * 2 + 8:
        return out
    v = proj.astype(np.float64)
    v -= v.mean()
    spec = np.abs(np.fft.rfft(v)) ** 2
    freqs = np.fft.rfftfreq(n, d=1.0)
    total = spec[1:].sum() + 1e-9
    scored = []
    for k in range(1, len(spec)):
        f = freqs[k]
        if f <= 0:
            continue
        p = 1.0 / f
        if lo <= p <= hi and p < n / 2:
            a, b = max(1, k - 3), min(len(spec), k + 4)
            local = np.median(np.delete(spec[a:b], k - a))
            scored.append((p, (spec[k] / (local + 1e-9)) * (spec[k] / total)))
    scored.sort(key=lambda t: -t[1])
    for p, s in scored:
        if all(abs(p - q) > 1.5 for q, _ in out):
            out.append((p, s))
        if len(out) >= top:
            break
    return out


def _uniform_dot_filter(stats, cents) -> np.ndarray:
    """Keep the most size-uniform population of blobs (the lattice dots).

    Text punctuation ('.', ':', 'i'-dots, fragments) varies widely in size;
    lattice dots are near-identical. Clustering on sqrt(area) isolates them.
    """
    if len(stats) == 0:
        return np.array([])
    sizes = np.sqrt(stats[:, cv2_CC_STAT_AREA].astype(np.float64))
    # histogram peak = densest size cluster
    lo, hi = max(1.0, sizes.min()), sizes.max() + 1e-6
    hist, edges = np.histogram(sizes, bins=min(40, max(8, len(sizes) // 10)),
                               range=(lo, hi))
    peak = int(np.argmax(hist))
    c0, c1 = edges[peak], edges[peak + 1]
    center = (c0 + c1) / 2
    span = max(1.2, 0.45 * center)
    keep = (sizes >= center - span) & (sizes <= center + span)
    # compactness: reject long streaks (dashes, fragments)
    wh = stats[:, 2:4].astype(np.float64)
    compact = np.maximum(wh[:, 0], wh[:, 1]) <= 4 * np.minimum(wh[:, 0], wh[:, 1]) + 2
    return np.array([cents[i] for i in range(len(cents)) if keep[i] and compact[i]])


try:
    import cv2 as _cv2
    cv2_CC_STAT_AREA = _cv2.CC_STAT_AREA
except Exception:  # pragma: no cover
    _cv2 = None
    cv2_CC_STAT_AREA = 4


def extract_lattice_token(image_bytes: bytes):
    """Decode the LatticeMark token from screenshot/photo bytes (PNG/JPEG).

    Returns (token_hex_or_None, diagnostics_dict). Blind: no original needed.
    """
    import cv2
    from PIL import Image
    diag: dict = {"stage": "start"}
    try:
        img = Image.open(io.BytesIO(bytes(image_bytes))).convert("L")
    except Exception:
        diag["stage"] = "unreadable-image"
        return None, diag
    gray = np.asarray(img, dtype=np.float32)
    h, w = gray.shape
    diag["size"] = [w, h]
    max_dim = 1600  # normalize huge captures; periods re-estimate anyway
    if max(w, h) > max_dim:
        scale = max_dim / max(w, h)
        img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        gray = np.asarray(img, dtype=np.float32)
        h, w = gray.shape
    # background subtraction: dots are darker than local background
    k = max(21, (min(h, w) // 25) | 1)  # odd kernel
    bg = cv2.GaussianBlur(gray, (k, k), 0)
    diff = bg - gray
    # text masking: black text dominates contrast statistics and litters
    # dot-sized punctuation; mask it (dilated) so the threshold adapts to
    # the faint lattice dots instead of the body text.
    strong = (diff > 50).astype(np.uint8)
    text_mask = cv2.dilate(strong, np.ones((3, 3), np.uint8), iterations=2)
    valid = text_mask == 0
    diag["text_fraction"] = round(1 - float(valid.mean()), 3)
    if valid.mean() < 0.3:
        diag["stage"] = "page-mostly-text"
        return None, diag
    # noise-floor threshold: background diff is ~zero plus sensor/JPEG
    # noise; lattice dots stick out far above it. MAD-based (dots are a
    # tiny fraction of pixels, so they never move the noise estimate).
    absd = np.abs(diff[valid])
    med = float(np.median(absd))
    mad = float(np.median(np.abs(absd - med))) + 1e-6
    sigma = 1.4826 * mad
    thr = min(12.0, max(3.0, med + 10 * sigma))
    diag["threshold"] = round(thr, 2)
    diag["dot_contrast"] = round(float(np.percentile(diff[valid], 99.9)), 1)
    if diag["dot_contrast"] < 2.0:
        diag["stage"] = "no-contrast"
        return None, diag
    binary = ((diff > thr) & valid).astype(np.uint8)
    n, _, stats, cents = cv2.connectedComponentsWithStats(binary, 8)
    if n <= 1:
        diag["stage"] = "too-few-dots"
        return None, diag
    # compactness-only pre-filter (roundish blobs: lattice dots plus text
    # punctuation). Size clustering is deliberately NOT applied: dot size is
    # scale-dependent and text specks are not lattice-periodic, so the sync
    # header — not a size guess — is the arbiter.
    pts = []
    for i in range(1, n):
        area = stats[i, cv2.CC_STAT_AREA]
        if not (3 <= area <= 900):
            continue
        ww, hh = stats[i, cv2.CC_STAT_WIDTH], stats[i, cv2.CC_STAT_HEIGHT]
        if max(ww, hh) <= 4 * min(ww, hh) + 2:
            pts.append(cents[i])
    pts = np.array(pts)
    diag["dots"] = int(len(pts))
    if len(pts) < 100:
        diag["stage"] = "too-few-dots"
        return None, diag
    bx = np.clip((pts[:, 0] / 2).astype(int), 0, w // 2)
    by = np.clip((pts[:, 1] / 2).astype(int), 0, h // 2)
    hx = np.bincount(bx, minlength=w // 2 + 1).astype(np.float64)
    hy = np.bincount(by, minlength=h // 2 + 1).astype(np.float64)
    px_cands = [(p * 2, s) for p, s in _candidate_periods(hx, 6, 60, top=5)]
    py_cands = [(p * 2, s) for p, s in _candidate_periods(hy, 6, 60, top=5)]
    if not px_cands or not py_cands:
        diag["stage"] = "no-period"
        return None, diag
    diag["px_cands"] = [round(p, 1) for p, _ in px_cands]
    diag["py_cands"] = [round(p, 1) for p, _ in py_cands]
    # token -> [votes, agree_sum, residual_best, px, py]: rank by header
    # quality first, then by lattice snap residual (true phase centers dots
    # in cells, residual ~1px; half-period folds park dots on cell corners,
    # residual ~period/4 — this kills alias/fold impostors that vote en
    # masse), then square-cell aspect, then vote count.
    token_stats: dict = {}
    for px, _ in px_cands:
        for py, _ in py_cands:
            for ox in (0.0, px / 4, px / 2, 3 * px / 4):
                for oy in (0.0, py / 4, py / 2, 3 * py / 4):
                    gx = np.round((pts[:, 0] - ox) / px).astype(int)
                    gy = np.round((pts[:, 1] - oy) / py).astype(int)
                    resid = float(np.mean(np.abs(pts[:, 0] - (ox + gx * px)) / px +
                                          np.abs(pts[:, 1] - (oy + gy * py)) / py) / 2)
                    occ = set(zip(gx.tolist(), gy.tolist()))
                    xs = [p[0] for p in occ]
                    ys = [p[1] for p in occ]
                    gx0, gx1, gy0, gy1 = min(xs), max(xs), min(ys), max(ys)
                    for wx in range(gx0, gx1 - COLS + 2):
                        for wy in range(gy0, gy1 - ROWS + 2):
                            # image rows run top-down, PDF/tile rows bottom-up:
                            # flip vertically to recover tile order.
                            win = [1 if (wx + c, wy + (ROWS - 1 - r)) in occ else 0
                                   for r in range(ROWS) for c in range(COLS)]
                            masked = [(v ^ m) for v, m in zip(win, WHITEMASK)]
                            agree = sum(1 for i in range(HEADER_LEN)
                                        if masked[i] == SYNC_HEADER[i])
                            if agree < HEADER_AGREE_MIN:
                                continue
                            token = _bits_to_token(masked[HEADER_LEN:])
                            if token is None:
                                continue
                            st = token_stats.setdefault(
                                token, [0, 0, 1.0, px, py])
                            st[0] += 1
                            st[1] += agree
                            if resid < st[2]:
                                st[2] = resid
                                st[3], st[4] = px, py
    if not token_stats:
        diag["stage"] = "no-sync-lock"
        return None, diag

    def _rank(item):
        tok, (votes, asum, resid, px, py) = item
        mean_agree = asum / max(1, votes)
        aspect = 1 - min(1.0, abs(px - py) / max(px, py))
        return (mean_agree, -resid, aspect, votes)

    ranked = sorted(token_stats.items(), key=_rank, reverse=True)
    winner, (votes, asum, resid, px, py) = ranked[0]
    mean_agree = asum / max(1, votes)
    aspect = 1 - min(1.0, abs(px - py) / max(px, py))
    diag.update({"stage": "decoded", "winner_votes": votes,
                 "contenders": len(token_stats),
                 "period": [round(px, 1), round(py, 1)],
                 "mean_header_agree": round(mean_agree, 2),
                 "residual": round(resid, 3),
                 "aspect": round(aspect, 3)})
    if votes < CONSENSUS_TILES_MIN or mean_agree < 14.5:
        diag["stage"] = "no-consensus"
        return None, diag
    return winner, diag
