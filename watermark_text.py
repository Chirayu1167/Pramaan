"""Dual-channel invisible/visible watermark for plain-text (.txt) and
Markdown (.md) leaked-document investigation.

Mirrors watermark.py's model exactly — an opaque, random 128-bit token,
minted once per decryption event, embedded into that event's copy only,
matched back to the signed ledger by SHA-256 of the hex — but targets
plain text instead of a PDF content stream, using two independent
channels so the two failure modes cover for each other:

  1. INVISIBLE CHANNEL (zero-width Unicode steganography)
     The 128-bit hex token is encoded bit-by-bit as zero-width Unicode
     characters (U+200B = 0, U+200C = 1) and a full copy of the encoded
     token is re-inserted after every ~40 words. That way, a partial
     copy-paste of any single chunk of a longer leaked document still
     carries at least one complete, intact copy of the token — the same
     "survive a partial leak" property the PDF path gets from stamping
     every page. Invisible in any normal viewer/editor (nothing is
     rendered differently); the honest MVP limitation is that it is
     trivially destroyed by anything that strips zero-width characters,
     or by retyping the text by hand — which is exactly why channel 2
     exists.

  2. VISIBLE CANARY CHANNEL
     A short, deliberately unremarkable footer line —
     ``Ref: 8f3a21c9`` — carrying only the first 8 hex chars (32 bits)
     of the same token. It is styled like ordinary document-reference
     boilerplate rather than anything that reads as "watermark" or
     "security", so it doesn't invite removal, but it degrades
     gracefully to a *partial* forensic signal (looked up by an exact
     canary-prefix match recorded in that event's signed ledger entry,
     see core.py) if the invisible channel above is stripped or the
     document is retyped from scratch (short of the canary line itself
     being edited out, which core.py's investigate_leak reports openly
     as "canary-only", not a full/normal match).

Honest MVP limitation (mirrors watermark.py's own limitation note): this
is a text-domain watermark. It does not survive re-typing a document from
a *screenshot* or photo of the text (no channel here does — that would
need image-domain methods), and the canary line by itself is trivially
removable by anyone editing the visible document; investigate_leak in
core.py is explicit about the resulting confidence level in each case
rather than overclaiming.
"""
import re

from watermark import TOKEN_HEX_LEN  # reuse the PDF path's token format; no crypto change

# --- zero-width invisible channel -----------------------------------------
ZW_ZERO = "\u200b"  # ZERO WIDTH SPACE      -> bit 0
ZW_ONE = "\u200c"   # ZERO WIDTH NON-JOINER -> bit 1

_TOKEN_BIT_LEN = TOKEN_HEX_LEN * 4  # 32 hex chars * 4 bits/char = 128 bits
_HEX_TOKEN_RE = re.compile(r"[0-9a-f]{%d}" % TOKEN_HEX_LEN)  # same format as watermark.py
_ZW_RUN_RE = re.compile(f"[{ZW_ZERO}{ZW_ONE}]+")
_SPLIT_RE = re.compile(r"(\s+)")  # keep whitespace tokens so the text reconstructs exactly

WORDS_PER_COPY = 40  # re-insert one full token copy after every ~40 words


def _validate_token_hex(token_hex: str) -> None:
    if len(token_hex) != TOKEN_HEX_LEN or not re.fullmatch(r"[0-9a-f]+", token_hex):
        raise ValueError(f"token_hex must be {TOKEN_HEX_LEN} lowercase hex chars")


def _token_to_bits(token_hex: str) -> str:
    _validate_token_hex(token_hex)
    return "".join(f"{int(c, 16):04b}" for c in token_hex)


def _bits_to_token(bits: str) -> str | None:
    """Decode a 128-bit string back to hex, validating it against the same
    TOKEN_HEX_LEN/hex-charset format watermark.py uses for the PDF channel."""
    if len(bits) != _TOKEN_BIT_LEN:
        return None
    nibbles = (bits[i:i + 4] for i in range(0, len(bits), 4))
    token = "".join(f"{int(n, 2):x}" for n in nibbles)
    return token if _HEX_TOKEN_RE.fullmatch(token) else None


def _encode_zw(token_hex: str) -> str:
    """Render token_hex as a run of zero-width characters."""
    return "".join(ZW_ONE if b == "1" else ZW_ZERO for b in _token_to_bits(token_hex))


def embed_token_invisible(text: str, token_hex: str) -> str:
    """Return text with a zero-width-encoded copy of token_hex inserted after
    every ~WORDS_PER_COPY words (and always at least once), so a partial
    copy-paste of any chunk of the document still carries an intact copy.
    """
    payload = _encode_zw(token_hex)
    if text == "":
        return payload
    # Split on whitespace, KEEPING the whitespace tokens (odd indices), so
    # "".join(tokens) reconstructs the original text exactly; only the
    # non-whitespace ("word") tokens are counted and get the payload
    # appended directly after them, before any following whitespace.
    tokens = _SPLIT_RE.split(text)
    word_count = 0
    for i, tok in enumerate(tokens):
        if tok == "" or tok.isspace():
            continue
        word_count += 1
        if word_count % WORDS_PER_COPY == 0:
            tokens[i] = tok + payload
    result = "".join(tokens)
    if payload not in result:
        # Fewer than WORDS_PER_COPY words in the whole document: still
        # guarantee at least one intact copy is present.
        result += payload
    return result


def extract_token_invisible(text: str) -> str | None:
    """Scan for zero-width runs, decode each, and validate against the
    existing TOKEN_HEX_LEN/hex format from watermark.py. Returns the first
    valid hit, or None. Checks every aligned 128-bit window within a run (not
    just the whole run) so a valid copy is still found even if the leaked
    excerpt begins mid-run or two runs ended up adjacent."""
    for m in _ZW_RUN_RE.finditer(text):
        run = m.group(0)
        if len(run) < _TOKEN_BIT_LEN:
            continue
        for start in range(0, len(run) - _TOKEN_BIT_LEN + 1):
            window = run[start:start + _TOKEN_BIT_LEN]
            bits = "".join("1" if ch == ZW_ONE else "0" for ch in window)
            token = _bits_to_token(bits)
            if token is not None:
                return token
    return None


# --- visible canary channel -------------------------------------------------
CANARY_PREFIX_LEN = 8  # first 8 hex chars (32 bits) of the token
_CANARY_RE = re.compile(r"Ref: ([0-9a-f]{%d})\b" % CANARY_PREFIX_LEN)


def embed_canary(text: str, token_hex: str) -> str:
    """Append a short, unobtrusive footer line carrying the first
    CANARY_PREFIX_LEN hex chars of token_hex, styled like ordinary document
    boilerplate rather than anything that reads as a security marker."""
    _validate_token_hex(token_hex)
    prefix = token_hex[:CANARY_PREFIX_LEN]
    footer = f"\n\n---\nRef: {prefix}\n"
    return text + footer


def extract_canary(text: str) -> str | None:
    """Return the 8-hex-char canary prefix if present, else None."""
    m = _CANARY_RE.search(text)
    return m.group(1) if m else None


# --- combined helpers --------------------------------------------------------
def embed_text_watermark(text: str, token_hex: str) -> str:
    """Apply both channels: invisible zero-width copies through the body,
    then the visible canary footer at the end."""
    return embed_canary(embed_token_invisible(text, token_hex), token_hex)


def extract_text_watermark(text: str) -> dict:
    """Independently check both channels (never short-circuits: absence of
    one channel never prevents checking the other).

    Returns {"invisible": token_hex_or_None, "canary": prefix_or_None}.
    """
    return {
        "invisible": extract_token_invisible(text),
        "canary": extract_canary(text),
    }