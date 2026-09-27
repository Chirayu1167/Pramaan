"""LatticeMark robustness harness: analog-hole survival matrix (offline).

Simulates the real leak path: render decrypted PDF page -> screenshot-like
transforms (JPEG recompression, downscale, crop) -> blind decode. Prints the
success matrix and writes scripts/../docs_robustness.json (consumed by the UI
robustness table and README numbers).

Usage: python scripts/measure_robustness.py [--tokens N] [--quick]
"""
import io
import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import latticemark as lm
from demo import make_sample_pdf
from PIL import Image

JPEG_QS = [95, 75, 60, 40]
SCALES = [1.0, 0.75, 0.5]
CROPS = ["full", "half", "quarter"]


def screenshot_sim(img: Image.Image, jpeg_q, scale, crop) -> bytes:
    w, h = img.size
    if crop == "half":
        img = img.crop((0, h // 4, w, 3 * h // 4))
    elif crop == "quarter":
        img = img.crop((0, 3 * h // 8, w, 5 * h // 8))
    if scale != 1.0:
        img = img.resize((max(1, int(img.size[0] * scale)),
                          max(1, int(img.size[1] * scale))), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=jpeg_q)
    return buf.getvalue()


def run(n_tokens: int = 6, quick: bool = False):
    if quick:
        global JPEG_QS, SCALES, CROPS
        JPEG_QS, SCALES, CROPS = [75, 60], [1.0, 0.75], ["full", "half"]
    pdf = make_sample_pdf()
    tokens = [secrets.token_hex(16) for _ in range(n_tokens)]
    results = []
    t0 = time.time()
    total = len(tokens) * len(JPEG_QS) * len(SCALES) * len(CROPS)
    done = 0
    for tok in tokens:
        marked = lm.embed_lattice(pdf, tok)
        base = lm.rasterize_pdf_page(marked, 0, zoom=1.5)  # ~108dpi screenshot
        for q in JPEG_QS:
            for s in SCALES:
                for c in CROPS:
                    shot = screenshot_sim(base, q, s, c)
                    t1 = time.time()
                    out, diag = lm.extract_lattice_token(shot)
                    dt = time.time() - t1
                    ok = out == tok
                    results.append({"q": q, "scale": s, "crop": c, "ok": ok,
                                    "votes": diag.get("winner_votes", 0),
                                    "secs": round(dt, 1)})
                    done += 1
                    print(f"[{done}/{total}] q={q} scale={s} crop={c:7s} "
                          f"-> {'OK ' if ok else 'FAIL'} "
                          f"(votes={diag.get('winner_votes', 0)}, {dt:.1f}s)",
                          flush=True)
    # aggregate matrix
    matrix = {}
    for r in results:
        key = f"q{r['q']}/x{r['scale']}/{r['crop']}"
        m = matrix.setdefault(key, {"ok": 0, "n": 0})
        m["n"] += 1
        m["ok"] += 1 if r["ok"] else 0
    print("\n==== LatticeMark survival matrix "
          f"({n_tokens} tokens, {time.time() - t0:.0f}s total) ====")
    for key in sorted(matrix):
        m = matrix[key]
        print(f"  {key:18s} {m['ok']}/{m['n']}")
    out_path = os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))), "docs_robustness.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"matrix": matrix, "detail": results,
                   "tokens": n_tokens,
                   "note": "screenshot sim: 108dpi render -> crop -> "
                           "downscale -> JPEG; blind decode, 2-tile consensus"},
                  f, indent=2)
    print("wrote", out_path)
    return matrix


if __name__ == "__main__":
    n = int(sys.argv[sys.argv.index("--tokens") + 1]) if "--tokens" in sys.argv else 6
    run(n_tokens=n, quick="--quick" in sys.argv)
