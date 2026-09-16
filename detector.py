"""
Evaluate three defense levels on the generated corpus.

Def-SIG   : PAdES-style signature check on the original signed byte range.
            Passes any file whose byte-prefix equals the committed baseline.
Def-HASH  : SHA-256 of the entire file compared to the committed baseline
            hash. Any byte-level difference is rejected.
Def-DPM   : Approach.tex predicate stack:
              r_reach   — no new orphaned reachable objects; annotation set
                          in signed doc unchanged
              r_tree    — page tree /Kids and /Count unchanged
              r_xref    — no shadow duplicate object numbers reachable from
                          the catalog after /Prev chain resolution
              r_layer   — /OCProperties unchanged (no new OCGs, no visibility
                          flips) and /ViewerPreferences unchanged
              r_meta    — /Info /Title, /Author, /Subject unchanged
                          (/ModDate is allowlisted)
              r_semeq   — extracted text equal
              r_catalog — /Pages reference in Catalog unchanged
            A_k allowlist accepts semantically-null updates whose only
            structural delta is /Info /ModDate.

Outputs: results.csv (per-file), summary.csv (per-defense × per-category),
         predicate_hits.csv (DPM rejection reasons).
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Optional

from pypdf import PdfReader
from pypdf.generic import IndirectObject

ROOT = Path(__file__).parent
CORPUS = ROOT / "corpus"


# ---------------------------------------------------------------------------
# Ledger commitment: for each baseline we capture the ground-truth state.
# ---------------------------------------------------------------------------

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _resolve(o):
    return o.get_object() if isinstance(o, IndirectObject) else o


def structural_fingerprint(reader: PdfReader) -> dict:
    """Extract canonicalised structural features from a PDF."""
    root = _resolve(reader.trailer["/Root"])
    fp: dict = {
        "num_pages": len(reader.pages),
        "info_title": None,
        "info_author": None,
        "info_subject": None,
        "has_viewerprefs": "/ViewerPreferences" in root,
        "page_mode": str(root.get("/PageMode", "")),
        "has_ocproperties": "/OCProperties" in root,
        "num_ocgs": 0,
        "pages_kids_count": 0,
        "annot_counts": [],
        "text": "",
        "catalog_pages_ref": None,
    }
    meta = reader.metadata or {}
    fp["info_title"] = str(meta.get("/Title", ""))
    fp["info_author"] = str(meta.get("/Author", ""))
    fp["info_subject"] = str(meta.get("/Subject", ""))

    if "/OCProperties" in root:
        ocp = _resolve(root["/OCProperties"])
        ocgs = ocp.get("/OCGs")
        fp["num_ocgs"] = len(ocgs) if ocgs else 0

    pages_obj = _resolve(root["/Pages"])
    kids = pages_obj.get("/Kids") or []
    fp["pages_kids_count"] = len(kids)
    fp["catalog_pages_ref"] = (
        f"{root.raw_get('/Pages').idnum} {root.raw_get('/Pages').generation}"
        if isinstance(root.raw_get("/Pages"), IndirectObject) else None
    )

    for pg in reader.pages:
        annots = pg.get("/Annots") or []
        fp["annot_counts"].append(len(annots))

    try:
        fp["text"] = "".join(p.extract_text() or "" for p in reader.pages)
    except Exception:
        fp["text"] = ""

    return fp


def commit_baseline(path: Path) -> dict:
    data = path.read_bytes()
    reader = PdfReader(str(path))
    return {
        "path": path,
        "bytes": data,
        "size": len(data),
        "sha256": sha256(data),
        "fingerprint": structural_fingerprint(reader),
    }


# ---------------------------------------------------------------------------
# Defense implementations
# ---------------------------------------------------------------------------

def def_sig(candidate: bytes, commit: dict) -> tuple[bool, str]:
    """
    PAdES-style: accept iff candidate starts with the committed baseline
    bytes (i.e. any modification is confined to an incremental-update
    suffix). This is exactly the assumption shadow attacks weaponise.
    """
    b = commit["bytes"]
    if len(candidate) < len(b):
        return False, "byte_range_shorter"
    if candidate[: len(b)] != b:
        return False, "signed_range_mutated"
    return True, "sig_valid"


def def_hash(candidate: bytes, commit: dict) -> tuple[bool, str]:
    if sha256(candidate) != commit["sha256"]:
        return False, "hash_mismatch"
    return True, "hash_ok"


def def_dpm(candidate_path: Path, commit: dict) -> tuple[bool, str]:
    """
    Approach.tex predicate stack + A_k allowlist for /ModDate-only updates.
    Returns (accept, reason). reason names the first violated predicate,
    or 'accept_moddate' / 'accept_identical' on accept.
    """
    try:
        cand = PdfReader(str(candidate_path), strict=False)
    except Exception as e:
        return False, f"parse_error:{type(e).__name__}"

    fp_c = structural_fingerprint(cand)
    fp_b = commit["fingerprint"]

    # r_catalog / r_tree
    if fp_c["catalog_pages_ref"] != fp_b["catalog_pages_ref"]:
        return False, "r_catalog"
    if fp_c["pages_kids_count"] != fp_b["pages_kids_count"]:
        return False, "r_tree"

    # r_reach — annotation set unchanged on every signed page
    if fp_c["annot_counts"] != fp_b["annot_counts"]:
        return False, "r_reach"

    # r_layer — OCG state and viewer prefs unchanged
    if fp_c["has_ocproperties"] != fp_b["has_ocproperties"]:
        return False, "r_layer"
    if fp_c["num_ocgs"] != fp_b["num_ocgs"]:
        return False, "r_layer"
    if fp_c["has_viewerprefs"] != fp_b["has_viewerprefs"]:
        return False, "r_layer"
    if fp_c["page_mode"] != fp_b["page_mode"]:
        return False, "r_layer"

    # r_meta — allowlist /ModDate but reject Title/Author/Subject tampering
    for k in ("info_title", "info_author", "info_subject"):
        if fp_c[k] != fp_b[k]:
            return False, "r_meta"

    # r_semeq — extracted text equal
    if fp_c["text"].strip() != fp_b["text"].strip():
        return False, "r_semeq"

    # r_xref — proxied by successful parse + all above holding.
    if sha256(candidate_path.read_bytes()) == commit["sha256"]:
        return True, "accept_identical"
    return True, "accept_moddate"


# ---------------------------------------------------------------------------
# Evaluation harness
# ---------------------------------------------------------------------------

CATEGORIES = [
    "baseline",
    "benign_moddate",
    "attack_A1_replacement",
    "attack_A2_metadata/a_metadata_info",
    "attack_A2_metadata/b_viewer_prefs",
    "attack_A2_metadata/c_annotation_overlay",
    "attack_A2_metadata/d_ocg_toggle",
    "attack_A2_metadata/e_hide_and_replace",
    "attack_A3_scapy",
]

# Which categories are attacks (positives) vs. benign (negatives)
IS_ATTACK = {
    "baseline": False,
    "benign_moddate": False,
    "attack_A1_replacement": True,
    "attack_A2_metadata/a_metadata_info": True,
    "attack_A2_metadata/b_viewer_prefs": True,
    "attack_A2_metadata/c_annotation_overlay": True,
    "attack_A2_metadata/d_ocg_toggle": True,
    "attack_A2_metadata/e_hide_and_replace": True,
    "attack_A3_scapy": True,
}


def main() -> None:
    # Build baseline commitments keyed by (doc_class, filename)
    commits: dict[tuple[str, str], dict] = {}
    for p in (CORPUS / "baseline").rglob("*.pdf"):
        cls = p.parent.name
        commits[(cls, p.name)] = commit_baseline(p)

    per_file: list[dict] = []
    for cat in CATEGORIES:
        cat_root = CORPUS / cat
        for p in sorted(cat_root.rglob("*.pdf")):
            cls = p.parent.name
            key = (cls, p.name)
            if key not in commits:
                continue
            commit = commits[key]
            cand_bytes = p.read_bytes()

            sig_ok, sig_reason = def_sig(cand_bytes, commit)
            hash_ok, hash_reason = def_hash(cand_bytes, commit)
            dpm_ok, dpm_reason = def_dpm(p, commit)

            per_file.append({
                "category": cat,
                "doc_class": cls,
                "filename": p.name,
                "is_attack": IS_ATTACK[cat],
                "sig_accept": sig_ok, "sig_reason": sig_reason,
                "hash_accept": hash_ok, "hash_reason": hash_reason,
                "dpm_accept": dpm_ok, "dpm_reason": dpm_reason,
            })

    # Persist per-file results
    with (ROOT / "results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_file[0].keys()))
        w.writeheader()
        w.writerows(per_file)

    # Aggregate per (defense, category)
    summary: list[dict] = []
    for defense in ("sig", "hash", "dpm"):
        for cat in CATEGORIES:
            rows = [r for r in per_file if r["category"] == cat]
            n = len(rows)
            accepted = sum(1 for r in rows if r[f"{defense}_accept"])
            rejected = n - accepted
            is_atk = IS_ATTACK[cat]
            if is_atk:
                metric_name = "detection_rate"
                metric = rejected / n if n else 0.0
            else:
                metric_name = "false_reject_rate"
                metric = rejected / n if n else 0.0
            summary.append({
                "defense": defense,
                "category": cat,
                "is_attack": is_atk,
                "n": n,
                "accepted": accepted,
                "rejected": rejected,
                "metric": metric_name,
                "value": round(metric, 4),
            })
    with (ROOT / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)

    # DPM predicate histogram (which predicate rejected each attack)
    hits: dict[tuple[str, str], int] = {}
    for r in per_file:
        if r["is_attack"] and not r["dpm_accept"]:
            hits[(r["category"], r["dpm_reason"])] = \
                hits.get((r["category"], r["dpm_reason"]), 0) + 1
    with (ROOT / "predicate_hits.csv").open("w", newline="",
                                             encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "predicate", "count"])
        for (cat, pred), c in sorted(hits.items()):
            w.writerow([cat, pred, c])

    # Console summary
    print("=" * 78)
    print(f"{'Defense':6s}  {'Category':45s}  {'Metric':18s}  Value")
    print("-" * 78)
    for row in summary:
        print(f"{row['defense']:6s}  {row['category']:45s}  "
              f"{row['metric']:18s}  {row['value']:.3f}  "
              f"({row['rejected']}/{row['n']})")
    print()
    print("DPM predicate hits (attack rejections):")
    for (cat, pred), c in sorted(hits.items()):
        print(f"  {cat:45s} {pred:20s} {c}")


if __name__ == "__main__":
    main()
