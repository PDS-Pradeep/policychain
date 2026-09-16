# PolicyChain — Code Architecture

This repository contains the **evaluation pipeline** for the PolicyChain
paper: a corpus generator, a PDF validation detector, and three evaluation
drivers. It is a reproducible experimental harness, **not** a running
blockchain deployment. The "blockchain / BFT" results are analytical models
and Monte-Carlo simulations; actual attack detection is performed by
deterministic structural-fingerprint predicates in `detector.py`.

All scripts are seeded with `SEED = 20260901` for bit-identical
reproducibility.

## Dependency graph

```
generate_corpus.py ──► corpus/ (PDFs + manifest.csv)
                          │
        ┌─────────────────┼──────────────────────────────┐
        ▼                 ▼                                ▼
   detector.py        benchmark.py                  resilience_sim.py
 (results.csv,       (bench.csv,                     (resilience.csv)
  summary.csv,        bench_summary.csv)                   │
  predicate_hits.csv)      │                               │
        └──── both import from detector.py ────────────────┘

   governance_sim.py ──► governance.csv   (standalone BFT-vote model)
```

`benchmark.py` and `resilience_sim.py` import `commit_baseline`, `def_dpm`,
and `structural_fingerprint` directly from `detector.py`, so the detector is
the single source of truth. `governance_sim.py` shares only the consensus
constants (`N = 10`, `f = 3`, `T = 2f + 1 = 7`).

## Run order

```powershell
python -m pip install reportlab pypdf
python generate_corpus.py     # -> corpus/, manifest.csv
python detector.py            # -> results.csv, summary.csv, predicate_hits.csv
python governance_sim.py      # -> governance.csv          (RQ1)
python benchmark.py           # -> bench.csv, bench_summary.csv (RQ3)
python resilience_sim.py      # -> resilience.csv          (RQ4)
```

---

## 1. `generate_corpus.py` — corpus builder

Builds the test set from scratch using `reportlab` (draws baseline PDFs) and
`pypdf` (manipulates them).

- **Baselines**: 18 PDFs — 3 classes (certificate, invoice, admin_record) ×
  6 each, each with real `/Title`, `/Author`, `/Subject` metadata.
- **A1 — direct replacement**: writes a wholly different attacker PDF, same
  filename.
- **A2 — five shadow-attack variants** built as real PDF **incremental
  updates** via `_append_incremental_update()` (sparse xref subsections +
  `/Prev` chain), so the signed byte prefix stays intact:
  - `a_metadata_info` — `/Info` override (Title/Author tamper)
  - `b_viewer_prefs` — catalog rewrite adding `/ViewerPreferences` +
    `/PageMode /FullScreen`
  - `c_annotation_overlay` — FreeText annotation masking content
  - `d_ocg_toggle` — injected optional-content group, default-visible
  - `e_hide_and_replace` — shadow page-tree + catalog `/Pages` swap
- **A3 — Scapy-style byte flip**: XORs a deterministic 16-byte window
  (`^ 0xA5`) inside the first content stream.
- **benign_moddate**: a legitimate incremental update adding only `/ModDate`
  (negative case for false-rejection testing).
- **Output**: `manifest.csv` (category, class, path, SHA-256, size).

## 2. `detector.py` — core: three defenses

Commits each baseline (bytes, SHA-256, and a `structural_fingerprint`), then
evaluates three defenses per candidate:

- **Def-SIG** — PAdES-style byte-prefix check. Accepts if the candidate
  starts with the committed baseline bytes; deliberately models the weakness
  shadow attacks exploit (incremental-update suffixes pass).
- **Def-HASH** — full-file SHA-256 equality; rejects any byte difference
  (also rejects benign `/ModDate` → high false-rejection).
- **Def-DPM** — the paper's predicate stack over the fingerprint:
  `r_catalog` (catalog `/Pages` ref), `r_tree` (page-tree kids/count),
  `r_reach` (annotation set), `r_layer` (`/OCProperties`, OCG count,
  `/ViewerPreferences`, `/PageMode`), `r_meta` (Title/Author/Subject, with
  `/ModDate` allowlisted), `r_semeq` (extracted-text equality). Returns the
  first violated predicate as the reason.

**Semantic equivalence** is defined operationally as a fingerprint match —
not a full PDF semantics.

**Outputs**: `results.csv` (per-file verdicts), `summary.csv` (detection /
false-reject rates per defense × category), `predicate_hits.csv`
(per-predicate attribution).

## 3. `governance_sim.py` — RQ1 (simulation)

No PDFs. Monte-Carlo BFT model (10,000 trials each) on `N=10, f=3, T=7`:

- **G1** Byzantine push — unsafe policy commits only if `|B| ≥ T`.
- **G2** silent downgrade — detected by ledger-vs-local hash mismatch.
- **G3** ledger rewrite — flips a bit in a 256-byte block, confirms the
  SHA-256 changes.
- **G4** concurrent fork — randomized voting; checks BFT total order never
  commits both proposals.

A model of consensus rules, not a live ledger. **Output**: `governance.csv`.

## 4. `benchmark.py` — RQ3 (measured + modeled)

Times each pipeline stage over 5 iterations (median per file):

- **Measured**: parse, fingerprint, predicate, end-to-end DPM, hash, and
  signature latencies; fingerprint byte-size; throughput (files/s).
- **Modeled**: ledger record size (`fingerprint + 32 + 8 + 8 + 10×64 B`
  Ed25519 signatures); BFT latency estimated as `median_dpm + 5 ms`
  (parallel) and `10 × median_dpm + 5 ms` (sequential).

Measured timings and the `+5 ms` network assumption are kept separate.
**Outputs**: `bench.csv`, `bench_summary.csv`.

## 5. `resilience_sim.py` — RQ4 (hybrid)

Combines real corpus detection with network simulation:

- **R1** validator outage — quorum arithmetic (`N-k ≥ T`).
- **R2** partition — 10,000 random splits; liveness if either side ≥ T.
- **R3 / R4 / R5** — actually run `def_dpm` over the real A3 and A2.b corpus
  subdirectories to confirm detection holds under simulated crash + MitM
  conditions.

R1/R2 are pure simulation; R3–R5 are real detector runs wrapped in a
simulated network scenario. **Output**: `resilience.csv`.

---

## What is real vs. modeled

| Component | Status |
|---|---|
| PDF attack corpus + incremental-update construction | Real artifacts |
| Def-SIG / Def-HASH / Def-DPM detection | Real, measured on the corpus |
| Per-file validation latency / throughput | Real, measured |
| Ledger record size, BFT vote latency | Analytical estimates |
| Governance tamper resistance (G1–G4) | Monte-Carlo simulation |
| Validator outage / partition (R1–R2) | Simulation |
| MitM / crash detection (R3–R5) | Real detector + simulated network |

There is no live blockchain, consortium network, or on-chain smart contract
in this repository; those belong to the target architecture described in the
paper and are future work.
