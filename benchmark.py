"""
Performance benchmark for the DPM validation pipeline (RQ4).

Measures:
    L_parse    — PDF parse time
    L_finger   — structural fingerprint computation time
    L_pred     — predicate-stack evaluation time (excluding parse)
    L_dpm      — end-to-end DPM validation time (parse + finger + pred)
    L_hash     — SHA-256 whole-file digest time
    L_sig      — byte-prefix comparison time
    Throughput — files / second per defence
    C_finger   — canonical fingerprint size in bytes (ledger overhead proxy)
    C_ledger   — simulated per-policy ledger commitment record size
    L_bft      — simulated 10-validator quorum vote-collection latency

Outputs bench.csv (per-file timings) and bench_summary.csv (aggregates).
"""
from __future__ import annotations

import csv
import hashlib
import json
import statistics
import time
from pathlib import Path
from typing import Callable

from pypdf import PdfReader

from detector import (
    structural_fingerprint,
    commit_baseline,
    def_sig, def_hash, def_dpm,
)

ROOT = Path(__file__).parent
CORPUS = ROOT / "corpus"
ITERATIONS = 5  # per file, we average to reduce noise


def _time(fn: Callable[[], object]) -> float:
    t0 = time.perf_counter_ns()
    fn()
    return (time.perf_counter_ns() - t0) / 1e6  # ms


def _bench_stage_dpm(candidate_path: Path, commit: dict) -> dict:
    """Break DPM validation into parse / fingerprint / predicates."""
    # Parse
    t0 = time.perf_counter_ns()
    reader = PdfReader(str(candidate_path), strict=False)
    t1 = time.perf_counter_ns()
    # Fingerprint
    fp = structural_fingerprint(reader)
    t2 = time.perf_counter_ns()
    # Predicate stack (fingerprint compare only — parse+fp already timed)
    _ = def_dpm(candidate_path, commit)
    t3 = time.perf_counter_ns()
    return {
        "parse_ms":  (t1 - t0) / 1e6,
        "finger_ms": (t2 - t1) / 1e6,
        "pred_ms":   (t3 - t2) / 1e6,
        "dpm_total_ms": (t3 - t0) / 1e6,
        "finger_bytes": len(json.dumps(fp, default=str).encode()),
    }


def main() -> None:
    # Commitments
    commits: dict[tuple[str, str], dict] = {}
    for p in (CORPUS / "baseline").rglob("*.pdf"):
        commits[(p.parent.name, p.name)] = commit_baseline(p)

    pdfs = list(CORPUS.rglob("*.pdf"))
    per_file: list[dict] = []

    for p in pdfs:
        cls = p.parent.name
        key = (cls, p.name)
        if key not in commits:
            continue
        commit = commits[key]
        b = p.read_bytes()

        samples = []
        for _ in range(ITERATIONS):
            row = _bench_stage_dpm(p, commit)
            row["sig_ms"]  = _time(lambda: def_sig(b, commit))
            row["hash_ms"] = _time(lambda: def_hash(b, commit))
            samples.append(row)
        # median per file to be robust
        agg = {k: statistics.median(s[k] for s in samples)
               for k in samples[0]}
        agg.update({"path": p.relative_to(ROOT).as_posix(),
                    "category": p.relative_to(CORPUS).parts[0],
                    "size_bytes": len(b)})
        per_file.append(agg)

    with (ROOT / "bench.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_file[0].keys()))
        w.writeheader()
        w.writerows(per_file)

    # Aggregate summary
    def stats(key: str) -> dict:
        vals = [r[key] for r in per_file]
        vals_sorted = sorted(vals)
        n = len(vals)
        p95 = vals_sorted[int(0.95 * (n - 1))]
        p99 = vals_sorted[int(0.99 * (n - 1))]
        return {
            "metric": key,
            "n": n,
            "mean": round(statistics.mean(vals), 3),
            "median": round(statistics.median(vals), 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "min": round(min(vals), 3),
            "max": round(max(vals), 3),
        }

    summary_rows = [stats(k) for k in
                    ("parse_ms", "finger_ms", "pred_ms",
                     "dpm_total_ms", "sig_ms", "hash_ms",
                     "finger_bytes")]

    # Throughput: 1000 / median_ms
    median_dpm  = statistics.median(r["dpm_total_ms"] for r in per_file)
    median_hash = statistics.median(r["hash_ms"] for r in per_file)
    median_sig  = statistics.median(r["sig_ms"] for r in per_file)

    # -----------------------------------------------------------------
    # REAL ledger commitment measurement (executed, not modelled).
    # We build the actual Merkle-linked ledger (ledger.py) over the
    # baseline fingerprints and measure per-block commit latency and the
    # true serialized record size. This replaces the previously modelled
    # ledger record size and BFT latency estimates.
    # -----------------------------------------------------------------
    from dataclasses import asdict as _asdict
    from ledger import MerkleLedger, ValidatorSet

    N_VAL, QUORUM = 10, 7
    validators = ValidatorSet(N_VAL)
    ledger = MerkleLedger(validators, quorum=QUORUM)

    commit_ms: list[float] = []
    record_bytes: list[int] = []
    for (cls, name), commit in commits.items():
        t0 = time.perf_counter_ns()
        blk = ledger.commit(commit["fingerprint_hash"], f"{cls}/{name}")
        commit_ms.append((time.perf_counter_ns() - t0) / 1e6)
        record_bytes.append(
            len(json.dumps(_asdict(blk), separators=(",", ":")).encode())
        )

    # Measured single-node commit cost (parse+fingerprint already timed
    # separately above; this is the ledger seal + k-signature step).
    ledger_commit_median_ms = statistics.median(commit_ms)
    ledger_record_bytes = int(statistics.median(record_bytes))

    # Verify the built ledger really validates (executed integrity check).
    chain_ok, _reason = ledger.verify()

    # Consensus-round latency remains an ANALYTICAL estimate built on the
    # measured per-commit cost: a genuine distributed BFT run would add
    # inter-node network RTT that a single-machine build cannot measure.
    # Parallel: one validation + one signed commit. Sequential upper bound:
    # k serial commits. Network RTT is intentionally NOT added here — it is
    # deployment-specific and reported as future work.
    l_consensus_parallel = median_dpm + ledger_commit_median_ms
    l_consensus_sequential = median_dpm + N_VAL * ledger_commit_median_ms

    with (ROOT / "bench_summary.csv").open("w", newline="",
                                            encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value", "unit"])
        for row in summary_rows:
            w.writerow([f"{row['metric']}_mean", row["mean"],
                        "bytes" if row["metric"] == "finger_bytes" else "ms"])
            w.writerow([f"{row['metric']}_median", row["median"],
                        "bytes" if row["metric"] == "finger_bytes" else "ms"])
            w.writerow([f"{row['metric']}_p95", row["p95"],
                        "bytes" if row["metric"] == "finger_bytes" else "ms"])
            w.writerow([f"{row['metric']}_p99", row["p99"],
                        "bytes" if row["metric"] == "finger_bytes" else "ms"])
        w.writerow(["throughput_dpm_fps", round(1000 / median_dpm, 1),
                    "files/s"])
        w.writerow(["throughput_hash_fps", round(1000 / median_hash, 1),
                    "files/s"])
        w.writerow(["throughput_sig_fps", round(1000 / median_sig, 1),
                    "files/s"])
        # Measured ledger metrics
        w.writerow(["ledger_commit_median_ms",
                    round(ledger_commit_median_ms, 4), "ms(measured)"])
        w.writerow(["ledger_record_bytes", ledger_record_bytes,
                    "bytes(measured)"])
        w.writerow(["ledger_chain_verified", chain_ok, "bool(measured)"])
        # Analytical consensus estimates built on the measured commit cost
        w.writerow(["consensus_latency_parallel_ms",
                    round(l_consensus_parallel, 2), "ms(estimate)"])
        w.writerow(["consensus_latency_sequential_ms",
                    round(l_consensus_sequential, 2), "ms(estimate)"])

    # Console
    print(f"{'metric':22s} {'mean':>8s} {'median':>8s} {'p95':>8s} "
          f"{'p99':>8s} {'unit':6s}")
    print("-" * 66)
    for row in summary_rows:
        unit = "B" if row["metric"] == "finger_bytes" else "ms"
        print(f"{row['metric']:22s} {row['mean']:>8.3f} {row['median']:>8.3f} "
              f"{row['p95']:>8.3f} {row['p99']:>8.3f} {unit:>4s}")
    print()
    print(f"throughput DPM   : {1000/median_dpm:8.1f} files/s")
    print(f"throughput Hash  : {1000/median_hash:8.1f} files/s")
    print(f"throughput Sig   : {1000/median_sig:8.1f} files/s")
    print(f"ledger commit    : {ledger_commit_median_ms:8.4f} ms/block "
          f"(measured, chain_verified={chain_ok})")
    print(f"ledger record    : {ledger_record_bytes} bytes/block (measured)")
    print(f"consensus par.   : {l_consensus_parallel:8.2f} ms  (estimate, "
          f"10 validators, parallel, no network RTT)")
    print(f"consensus seq.   : {l_consensus_sequential:8.2f} ms  (estimate, "
          f"10 validators, sequential)")


if __name__ == "__main__":
    main()
