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

    # Ledger commitment record: fingerprint json + sha256 + seq + timestamp
    # + 10 validator signatures (Ed25519 = 64B each)
    median_fp_bytes = statistics.median(r["finger_bytes"] for r in per_file)
    ledger_record_bytes = int(median_fp_bytes + 32 + 8 + 8 + 10 * 64)

    # Simulated BFT vote collection: each validator runs def_dpm once and
    # emits a 64B Ed25519 signature. Wall-clock lower bound is the max of
    # ten independent validations plus a small network fanout term.
    # We assume perfectly parallel validators, so latency ≈ single
    # validation + a 5ms round-trip.
    l_bft_lb = median_dpm + 5.0

    # Sequential (worst case): 10 * median_dpm + fanout
    l_bft_ub = 10 * median_dpm + 5.0

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
        w.writerow(["ledger_record_bytes", ledger_record_bytes, "bytes"])
        w.writerow(["bft_latency_parallel_ms", round(l_bft_lb, 2), "ms"])
        w.writerow(["bft_latency_sequential_ms", round(l_bft_ub, 2), "ms"])

    # Console
    print(f"{'metric':22s} {'mean':>8s} {'median':>8s} {'p95':>8s} "
          f"{'p99':>8s} {'unit':6s}")
    print("-" * 66)
    for row in summary_rows:
        unit = "B" if row["metric"] == "finger_bytes" else "ms"
        print(f"{row['metric']:22s} {row['mean']:>8.3f} {row['median']:>8.3f} "
              f"{row['p95']:>8.3f} {row['p99']:>8.3f} {unit:>4s}")
    print()
    print(f"throughput DPM  : {1000/median_dpm:8.1f} files/s")
    print(f"throughput Hash : {1000/median_hash:8.1f} files/s")
    print(f"throughput Sig  : {1000/median_sig:8.1f} files/s")
    print(f"ledger record   : {ledger_record_bytes} bytes / policy")
    print(f"BFT parallel LB : {l_bft_lb:8.2f} ms  (10 validators, parallel)")
    print(f"BFT sequential  : {l_bft_ub:8.2f} ms  (10 validators, sequential)")


if __name__ == "__main__":
    main()
