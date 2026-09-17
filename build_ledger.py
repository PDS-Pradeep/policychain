"""
Build the real Merkle-linked provenance ledger from the corpus baselines.

Commits each baseline document's DPM structural-fingerprint hash as a signed,
Merkle-committed block (see ledger.py). Persists the ledger and reports
*measured* commit metrics used by the paper's RQ3:

    ledger.jsonl         — the full serialized ledger (one block per line)
    ledger_root.txt      — the final Merkle root + block count
    ledger_metrics.csv   — measured per-block commit latency + record size

This replaces the previously *modelled* ledger record size and BFT latency
figures with real measurements from an executed ledger. Consensus (Byzantine
voting) remains modelled in governance_sim.py; this step makes the
immutability / provenance / attestation layer real.
"""
from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path

from detector import commit_baseline
from ledger import MerkleLedger, ValidatorSet

ROOT = Path(__file__).parent
CORPUS = ROOT / "corpus"

N_VALIDATORS = 10
QUORUM = 7  # T = 2f + 1 with f = 3


def build() -> MerkleLedger:
    validators = ValidatorSet(N_VALIDATORS)
    ledger = MerkleLedger(validators, quorum=QUORUM)

    baselines = sorted((CORPUS / "baseline").rglob("*.pdf"))
    commit_latencies_ms: list[float] = []
    record_sizes: list[int] = []

    for p in baselines:
        commit = commit_baseline(p)
        payload_id = f"{p.parent.name}/{p.name}"
        t0 = time.perf_counter_ns()
        blk = ledger.commit(commit["fingerprint_hash"], payload_id)
        t1 = time.perf_counter_ns()
        commit_latencies_ms.append((t1 - t0) / 1e6)
        # Real serialized record size (bytes on the wire / on disk).
        import json
        from dataclasses import asdict
        record_sizes.append(
            len(json.dumps(asdict(blk), separators=(",", ":")).encode())
        )

    # Persist ledger + root
    ledger.save(ROOT / "ledger.jsonl")
    (ROOT / "ledger_root.txt").write_text(
        f"merkle_root={ledger.root()}\nblocks={len(ledger.blocks)}\n",
        encoding="utf-8",
    )

    # Verify the freshly built ledger (sanity + demonstrates real check).
    ok, reason = ledger.verify()

    # Measured metrics
    with (ROOT / "ledger_metrics.csv").open("w", newline="",
                                             encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value", "unit"])
        w.writerow(["blocks", len(ledger.blocks), "count"])
        w.writerow(["validators", N_VALIDATORS, "count"])
        w.writerow(["quorum", QUORUM, "count"])
        w.writerow(["commit_latency_median_ms",
                    round(statistics.median(commit_latencies_ms), 4), "ms"])
        w.writerow(["commit_latency_mean_ms",
                    round(statistics.mean(commit_latencies_ms), 4), "ms"])
        w.writerow(["commit_latency_max_ms",
                    round(max(commit_latencies_ms), 4), "ms"])
        w.writerow(["ledger_record_median_bytes",
                    int(statistics.median(record_sizes)), "bytes"])
        w.writerow(["chain_verified", ok, "bool"])
        if reason:
            w.writerow(["verify_reason", reason, "text"])

    print("=" * 60)
    print(f"Ledger built: {len(ledger.blocks)} signed blocks")
    print(f"Validators: {N_VALIDATORS}  Quorum: {QUORUM}")
    print(f"Merkle root: {ledger.root()}")
    print(f"Chain verified: {ok}" + (f" ({reason})" if reason else ""))
    print(f"Commit latency: median "
          f"{statistics.median(commit_latencies_ms):.4f} ms, "
          f"max {max(commit_latencies_ms):.4f} ms")
    print(f"Ledger record: median "
          f"{int(statistics.median(record_sizes))} bytes/block")
    print("Artifacts: ledger.jsonl, ledger_root.txt, ledger_metrics.csv")
    return ledger


if __name__ == "__main__":
    build()
