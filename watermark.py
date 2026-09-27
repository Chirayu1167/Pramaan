# """Invisible per-decryption-event watermark for PDF/text documents.

# Method (MVP): invisible text-layer payload.
#   - Payload is an opaque random 128-bit token rendered as
#     ``WM:TOK:<32 hex chars>`` in 1pt type, painted with PDF text rendering
#     mode 3 ("invisible" — glyphs are added to the content stream but not
#     painted) at the corner of page 1.
#   - Visually imperceptible: nothing is painted; the page looks identical.
#   - Opaque: the token is pure randomness; it contains no recipient name/ID.
#   - Embedded at decryption time into that event's copy only.
#   - Recoverable: extracted with ordinary PDF text extraction (pypdf) +
#     regex, then matched (by SHA-256 hash) against the signed ledger.

# This follows the Research.pdf concept of "embed a short secret event token
# into the rendered visual document" (text-document branch, cf. FontCode
# glyph/text ideas). MVP LIMITATION (honest): an invisible text layer does
# NOT survive rasterization (screenshot/print-scan/JPEG) or OCR — that needs
# the DCT/luminance image-domain methods from Research.pdf and is future
# scope. Reliability target for the MVP is the distributed PDF itself.
# """
# import io
# import re

# from pypdf import PdfReader, PdfWriter
# from reportlab.lib.colors import white
# from reportlab.pdfgen import canvas

# PAYLOAD_PREFIX = "WM:TOK:"
# TOKEN_HEX_LEN = 32  # 128-bit token
# _TOKEN_RE = re.compile(r"WM:TOK:([0-9a-f]{32})")


# def make_overlay_page(width: float, height: float, token_hex: str) -> bytes:
#     """Build a 1-page transparent overlay PDF carrying the invisible payload."""
#     buf = io.BytesIO()
#     c = canvas.Canvas(buf, pagesize=(width, height))
#     c.saveState()
#     c.setFillColor(white)
#     c.setFont("Helvetica", 1)
#     # PDF text rendering mode 3 = invisible (neither fill nor stroke).
#     # reportlab has no public API for Tr, so emit the operator directly.
#     try:
#         c._code.append("3 Tr")
#     except Exception:
#         pass
#     c.drawString(8, 8, f"{PAYLOAD_PREFIX}{token_hex}")
#     try:
#         c._code.append("0 Tr")
#     except Exception:
#         pass
#     c.restoreState()
#     c.showPage()
#     c.save()
#     return buf.getvalue()


# def embed_token(pdf_bytes: bytes, token_hex: str) -> bytes:
#     """Return a copy of the PDF with the invisible token embedded on page 1."""
#     if len(token_hex) != TOKEN_HEX_LEN or not re.fullmatch(r"[0-9a-f]+", token_hex):
#         raise ValueError("token_hex must be 32 lowercase hex chars")
#     reader = PdfReader(io.BytesIO(pdf_bytes))
#     if len(reader.pages) == 0:
#         raise ValueError("PDF has no pages")
#     box = reader.pages[0].mediabox
#     width, height = float(box.width), float(box.height)
#     overlay = PdfReader(io.BytesIO(make_overlay_page(width, height, token_hex)))
#     writer = PdfWriter()
#     for i, page in enumerate(reader.pages):
#         if i == 0:
#             page.merge_page(overlay.pages[0])
#         writer.add_page(page)
#     out = io.BytesIO()
#     writer.write(out)
#     return out.getvalue()


# def extract_token(pdf_bytes: bytes) -> str | None:
#     """Extract the watermark token hex string, or None if absent."""
#     reader = PdfReader(io.BytesIO(pdf_bytes))
#     chunks = []
#     for page in reader.pages:
#         try:
#             chunks.append(page.extract_text() or "")
#         except Exception:
#             chunks.append("")
#     m = _TOKEN_RE.search("\n".join(chunks))
#     return m.group(1) if m else None

"""Invisible per-decryption-event watermark for PDF/text documents.

Method (MVP): invisible text-layer payload.
  - Payload is an opaque random 128-bit token rendered as
    ``WM:TOK:<32 hex chars>`` in 1pt type, painted with PDF text rendering
    mode 3 ("invisible" — glyphs are added to the content stream but not
    painted) at the corner of every page, so a single leaked page still
    carries and extracts the token.
  - Visually imperceptible: nothing is painted; the page looks identical.
  - Opaque: the token is pure randomness; it contains no recipient name/ID.
  - Embedded at decryption time into that event's copy only.
  - Recoverable: extracted with ordinary PDF text extraction (pypdf) +
    regex, then matched (by SHA-256 hash) against the signed ledger.

This follows the Research.pdf concept of "embed a short secret event token
into the rendered visual document" (text-document branch, cf. FontCode
glyph/text ideas). MVP LIMITATION (honest): an invisible text layer does
NOT survive rasterization (screenshot/print-scan/JPEG) or OCR — that needs
the DCT/luminance image-domain methods from Research.pdf and is future
scope. Reliability target for the MVP is the distributed PDF itself.
"""
import io
import re

from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import white
from reportlab.pdfgen import canvas

PAYLOAD_PREFIX = "WM:TOK:"
TOKEN_HEX_LEN = 32  # 128-bit token
_TOKEN_RE = re.compile(r"WM:TOK:([0-9a-f]{32})")


def make_overlay_page(width: float, height: float, token_hex: str) -> bytes:
    """Build a 1-page transparent overlay PDF carrying the invisible payload."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(width, height))
    c.saveState()
    c.setFillColor(white)
    c.setFont("Helvetica", 1)
    # PDF text rendering mode 3 = invisible (neither fill nor stroke).
    # reportlab has no public API for Tr, so emit the operator directly.
    try:
        c._code.append("3 Tr")
    except Exception:
        pass
    c.drawString(8, 8, f"{PAYLOAD_PREFIX}{token_hex}")
    try:
        c._code.append("0 Tr")
    except Exception:
        pass
    c.restoreState()
    c.showPage()
    c.save()
    return buf.getvalue()


def embed_token(pdf_bytes: bytes, token_hex: str) -> bytes:
    """Return a copy of the PDF with the invisible token embedded on every
    page, so a leaked single page (not just page 1) still extracts correctly.
    """
    if len(token_hex) != TOKEN_HEX_LEN or not re.fullmatch(r"[0-9a-f]+", token_hex):
        raise ValueError("token_hex must be 32 lowercase hex chars")
    reader = PdfReader(io.BytesIO(pdf_bytes))
    if len(reader.pages) == 0:
        raise ValueError("PDF has no pages")
    writer = PdfWriter()
    overlay_cache: dict[tuple[float, float], object] = {}
    for page in reader.pages:
        box = page.mediabox
        size = (float(box.width), float(box.height))
        overlay_page = overlay_cache.get(size)
        if overlay_page is None:
            overlay_reader = PdfReader(io.BytesIO(make_overlay_page(*size, token_hex)))
            overlay_page = overlay_reader.pages[0]
            overlay_cache[size] = overlay_page
        page.merge_page(overlay_page)
        writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def extract_token(pdf_bytes: bytes) -> str | None:
    """Extract the watermark token hex string, or None if absent."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    chunks = []
    for page in reader.pages:
        try:
            chunks.append(page.extract_text() or "")
        except Exception:
            chunks.append("")
    m = _TOKEN_RE.search("\n".join(chunks))
    return m.group(1) if m else None
