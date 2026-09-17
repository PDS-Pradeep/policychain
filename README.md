# PolicyChain PDF Attack Corpus

Reproducible test corpus for evaluating PDF integrity / policy-governance
frameworks against three attack categories.

## Regenerate the corpus

```powershell
python -m pip install reportlab pypdf
python generate_corpus.py
```

Deterministic (seed = `20260901`). Output goes to `./corpus`.

## Full evaluation pipeline

The corpus generator, detector, real Merkle-linked provenance ledger, and
the RQ1/RQ3/RQ4 drivers are documented in
[`ARCHITECTURE.md`](ARCHITECTURE.md). To run everything (the ledger uses
Ed25519 signatures via `cryptography`):

```powershell
python -m pip install reportlab pypdf cryptography
python generate_corpus.py     # corpus + manifest
python detector.py            # results.csv, summary.csv, predicate_hits.csv
python build_ledger.py        # real Merkle ledger: ledger.jsonl, ledger_root.txt
python governance_sim.py      # governance.csv  (G2/G3 executed on the ledger)
python benchmark.py           # bench.csv, bench_summary.csv
python resilience_sim.py      # resilience.csv
```

## Layout

```
corpus/
├── baseline/                             # 18 clean PDFs (6 per class)
│   ├── certificate/
│   ├── invoice/
│   └── admin_record/
│
├── attack_A1_replacement/                # 18  — whole-file substitution
│   └── <class>/<same-filename>.pdf
│
├── attack_A2_metadata/                   # 90  — 5 shadow-attack variants × 18
│   ├── a_metadata_info/                  #      /Info dict tampering
│   ├── b_viewer_prefs/                   #      Catalog + /ViewerPreferences via incremental update
│   ├── c_annotation_overlay/             #      FreeText annotation masking content
│   ├── d_ocg_toggle/                     #      New OCG layer, default-visible
│   └── e_hide_and_replace/               #      Full shadow page-tree, catalog swap
│
├── attack_A3_scapy/                      # 18  — byte-level content-stream tampering
│   └── <class>/<same-filename>.pdf
│
├── benign_moddate/                       # 18  — legitimate /ModDate-only update
│   └── <class>/<same-filename>.pdf       #      (negative case for false-rejection)
│
└── manifest.csv                          # sha256 + size + label for every file
```

Total: **162 PDFs** — 18 baseline, 126 attack (A1 + A2 + A3), and 18 benign.

## Attack semantics (verified)

| ID   | Variant             | What changes                                          | Byte-range prefix intact? |
|------|---------------------|-------------------------------------------------------|---------------------------|
| A1   | Direct replacement  | Entire file replaced                                  | No                        |
| A2.a | Info-dict tamper    | `/Title`, `/Author` rewritten via incremental update  | Yes                       |
| A2.b | Viewer preferences  | New `/ViewerPreferences`, `/PageMode /FullScreen`     | Yes                       |
| A2.c | Annotation overlay  | FreeText annotation added on page 1                   | Yes (structural add only) |
| A2.d | OCG toggle          | New optional-content group forced ON at default       | Yes (structural add only) |
| A2.e | Hide-and-Replace    | Shadow page tree + catalog `/Pages` swap              | Yes                       |
| A3   | Scapy byte-flip     | 16-byte XOR-0xA5 window inside first content stream   | No                        |
| benign | ModDate update    | `/ModDate`-only incremental update (allowlisted)      | Yes (must be accepted)    |

## Expected detection outcomes

Under the RQ1 model of Section 6.4:

- **A1** → detected by any hash check on the full file (H(D) mismatch).
- **A3** → detected by any hash check; byte-range covers modified bytes.
- **A2.a, A2.e** → detected by structural fingerprint Φ(D) that canonicalises
  the resolved object graph after `/Prev` chaining.
- **A2.b, A2.c, A2.d** → these are the residual-vulnerability cases in your
  paper (display-preference / annotation-layer / non-rendered metadata). They
  will pass a naive H(D)-over-final-bytes-only check because they look like
  legitimate incremental updates. Detecting them requires Φ(D) to include
  `/ViewerPreferences`, `/OCProperties`, and annotation `/AP` appearance
  streams, or a rendering-based secondary check.

## Manifest columns

`category, doc_class, relative_path, sha256, size_bytes`

Baseline files and their paired attack files share filenames, so a join on
`filename` gives you 1-to-1 comparison rows for each attack variant.

## Notes

- All A2 variants use real PDF **incremental updates** (`/Prev` chain, sparse
  xref subsections), matching how shadow attacks work against signed PDFs.
- No external cross-references, no network, no macros — safe to keep in a
  test repo.
