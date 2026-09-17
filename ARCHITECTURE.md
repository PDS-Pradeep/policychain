# PolicyChain — Code Architecture

This repository contains the **evaluation pipeline** for the PolicyChain
paper: a corpus generator, a PDF validation detector, a real Merkle-linked
provenance ledger, and three evaluation drivers. Attack detection is
performed by deterministic structural-fingerprint predicates in
`detector.py`; the provenance/immutability layer is a real, executed,
Ed25519-signed Merkle ledger in `ledger.py`. What remains modelled is
Byzantine-fault-tolerant **consensus** and live multi-node replication —
there is no distributed consensus protocol or on-chain smart contract here.

All scripts are seeded with `SEED = 20260901` for bit-identical
reproducibility.

## Dependency graph

```
generate_corpus.py ──► corpus/ (PDFs + manifest.csv)
                          │
   detector.py  ◄─────────┘   (defenses + fingerprints; single source of truth)
        │
        ├─► results.csv, summary.csv, predicate_hits.csv
        │
   ledger.py ──► build_ledger.py ──► ledger.jsonl, ledger_root.txt,
        │                            ledger_metrics.csv
        ▼
   governance_sim.py ──► governance.csv    (G2/G3 executed on ledger; G1/G4 model)
   benchmark.py      ──► bench.csv, bench_summary.csv   (RQ3)
   resilience_sim.py ──► resilience.csv                 (RQ4)
```

`benchmark.py`, `resilience_sim.py`, `build_ledger.py`, and
`governance_sim.py` import from `detector.py` (fingerprints/defenses) and
`ledger.py` (the Merkle ledger), so those two modules are the single sources
of truth. Consensus constants are shared: `N = 10`, `f = 3`, `T = 2f+1 = 7`.

## Run order

```powershell
python -m pip install reportlab pypdf cryptography
python generate_corpus.py     # -> corpus/, manifest.csv
python detector.py            # -> results.csv, summary.csv, predicate_hits.csv
python build_ledger.py        # -> ledger.jsonl, ledger_root.txt, ledger_metrics.csv
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

## 3. `ledger.py` + `build_ledger.py` — real Merkle provenance ledger

`ledger.py` is an executed (not simulated) append-only, hash-chained,
Merkle-committed ledger. Each block carries `prev_hash`, the committed DPM
fingerprint hash, a Merkle root over all commitments, and a quorum of real
**Ed25519 validator signatures** (7-of-10). `verify()` performs genuine
integrity checking: chain-link, block-hash, Merkle-root, and
signature-quorum recomputation, and reports the first broken block.

`build_ledger.py` commits every baseline fingerprint into this ledger and
persists it:

- `ledger.jsonl` — the serialized signed chain (one block per line)
- `ledger_root.txt` — final Merkle root + block count
- `ledger_metrics.csv` — measured commit latency + record size

This makes **immutability, provenance, and multi-party attestation real and
measured**. It does **not** provide Byzantine consensus (single-process log).

## 4. `governance_sim.py` — RQ1 (executed ledger + consensus model)

`N=10, f=3, T=7`. Two attacks are now **executed against the real ledger**;
two remain consensus **models** (labelled in the `method` column of
`governance.csv`):

- **G1** Byzantine push — `[model]` unsafe policy commits only if `|B| ≥ T`.
- **G2** silent downgrade — `[executed]` forges a committed block's
  fingerprint without valid re-signing; `ledger.verify()` catches every
  per-block attempt.
- **G3** ledger rewrite — `[executed]` mutates each block's payload and,
  separately, a validator signature; `ledger.verify()` catches every attempt
  via Merkle-root / hash-chain / signature-quorum failure.
- **G4** concurrent fork — `[model]` randomized voting; BFT total order never
  commits both proposals.

**Output**: `governance.csv` (with a `method` column: `executed_ledger` vs
`model`).

## 5. `benchmark.py` — RQ3 (measured + estimate)

Times each pipeline stage over 5 iterations (median per file):

- **Measured**: parse, fingerprint, predicate, end-to-end DPM, hash, and
  signature latencies; fingerprint byte-size; throughput (files/s). Also
  **measured**: real ledger commit latency (`ledger.py`) and true serialized
  ledger record size.
- **Estimate**: consensus-round latency, computed from the measured
  per-commit cost (`median_dpm + ledger_commit` parallel; `+ N×commit`
  sequential). Inter-node network RTT is intentionally excluded and flagged
  as deployment-specific future work — no fabricated network constant.

Measured values and the analytical consensus estimate are labelled
separately in the CSV (`ms(measured)` vs `ms(estimate)`).
**Outputs**: `bench.csv`, `bench_summary.csv`.

## 6. `resilience_sim.py` — RQ4 (hybrid)

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
| PDF attack corpus + incremental-update construction | **Real artifacts** |
| Def-SIG / Def-HASH / Def-DPM detection | **Real, measured** on the corpus |
| Per-file validation latency / throughput | **Real, measured** |
| Merkle provenance ledger (chain, root, Ed25519 signatures) | **Real, executed** (`ledger.py`) |
| Ledger commit latency + record size | **Real, measured** |
| Immutability / tamper-evidence: G2 downgrade, G3 rewrite | **Real, executed** against the ledger |
| MitM / crash detection (R3–R5) | Real detector + simulated network |
| Consensus-round latency | Analytical **estimate** on measured commit cost |
| Byzantine consensus: G1 push, G4 fork | **Model** (BFT voting arithmetic) |
| Validator outage / partition (R1–R2) | **Simulation** |

The provenance/immutability layer is now a real, executed, tamper-evident
Merkle ledger. What remains modelled is **Byzantine-fault-tolerant
consensus** and **live multi-node network replication** — there is no
distributed consensus protocol or on-chain smart contract in this
repository; those belong to the target architecture described in the paper
and are future work.
