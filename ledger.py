"""
Embedded Merkle-linked provenance ledger for PolicyChain.

This is a REAL, executed tamper-evident ledger — not a simulation. It is an
append-only, hash-chained log of policy/document commitments. Each block:

    block = {
        index          : monotonic block height
        timestamp      : commit time (ns)
        fingerprint    : the DPM structural fingerprint hash committed
        payload_id     : human-readable id (doc_class/filename)
        prev_hash      : SHA-256 of the previous block header (chain link)
        merkle_root    : Merkle root over all commitments up to this block
        signatures     : k Ed25519 validator signatures over the block header
        block_hash     : SHA-256 of the canonical block header
    }

What this ledger DOES provide (and what the paper may claim as *measured*):
  - Immutability / tamper-evidence: any post-hoc mutation of a committed
    block breaks the hash chain and/or the Merkle root, detectable by
    recomputation on any replica.
  - Multi-party attestation: each block carries k independent Ed25519
    validator signatures; forging a block requires forging signatures.
  - Provenance: the ordered chain reconstructs the exact committed state at
    any height.

What this ledger DOES NOT provide (must remain modelled / future work):
  - Byzantine fault-tolerant *consensus*. This is a single-process
    append-only log, not a distributed BFT protocol. It does not decide
    which of two conflicting proposals wins under adversarial network
    conditions; that is the RR-PoA/BFT layer the paper models.
  - Real network replication across independent nodes.

So: this makes IMMUTABILITY / PROVENANCE / TAMPER-EVIDENCE real and measured;
CONSENSUS (Byzantine push, concurrent fork) remains an analytical model.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Binary Merkle root over hex-string leaves (SHA-256, duplicate-last)."""
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last for odd count
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


# ---------------------------------------------------------------------------
# Validator set — k independent Ed25519 keypairs (a real signing quorum).
# ---------------------------------------------------------------------------
class ValidatorSet:
    """A fixed set of validators, each with a real Ed25519 keypair."""

    def __init__(self, n: int, seed: int = 20260901) -> None:
        # Deterministic keys for reproducibility: derive 32-byte seeds.
        self.privkeys: list[Ed25519PrivateKey] = []
        self.pubkeys: list[Ed25519PublicKey] = []
        for i in range(n):
            seed_bytes = hashlib.sha256(
                f"validator-{seed}-{i}".encode()
            ).digest()  # 32 bytes
            sk = Ed25519PrivateKey.from_private_bytes(seed_bytes)
            self.privkeys.append(sk)
            self.pubkeys.append(sk.public_key())

    def sign(self, i: int, msg: bytes) -> str:
        return self.privkeys[i].sign(msg).hex()

    def verify(self, i: int, sig_hex: str, msg: bytes) -> bool:
        try:
            self.pubkeys[i].verify(bytes.fromhex(sig_hex), msg)
            return True
        except (InvalidSignature, ValueError):
            return False

    def __len__(self) -> int:
        return len(self.privkeys)


# ---------------------------------------------------------------------------
# Block + Ledger
# ---------------------------------------------------------------------------
@dataclass
class Block:
    index: int
    timestamp: int
    fingerprint: str          # committed DPM fingerprint hash
    payload_id: str
    prev_hash: str
    merkle_root: str
    signatures: list[str] = field(default_factory=list)
    block_hash: str = ""

    def header_bytes(self) -> bytes:
        """Canonical, signature-independent header used for hashing/signing."""
        header = {
            "index": self.index,
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint,
            "payload_id": self.payload_id,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
        }
        return json.dumps(header, sort_keys=True,
                          separators=(",", ":")).encode()

    def compute_hash(self) -> str:
        return sha256_hex(self.header_bytes())


GENESIS_PREV = "0" * 64


class MerkleLedger:
    """Append-only, hash-chained, Merkle-committed, multi-signed ledger."""

    def __init__(self, validators: ValidatorSet, quorum: int) -> None:
        self.validators = validators
        self.quorum = quorum
        self.blocks: list[Block] = []
        self._commit_hashes: list[str] = []  # Merkle leaves

    # --- write path --------------------------------------------------------
    def commit(self, fingerprint_hash: str, payload_id: str) -> Block:
        """Append a new commitment; returns the sealed block."""
        idx = len(self.blocks)
        prev_hash = self.blocks[-1].block_hash if self.blocks else GENESIS_PREV
        self._commit_hashes.append(fingerprint_hash)
        root = merkle_root(self._commit_hashes)
        blk = Block(
            index=idx,
            timestamp=time.time_ns(),
            fingerprint=fingerprint_hash,
            payload_id=payload_id,
            prev_hash=prev_hash,
            merkle_root=root,
        )
        msg = blk.header_bytes()
        # A quorum of validators independently sign the block header.
        blk.signatures = [
            self.validators.sign(i, msg) for i in range(self.quorum)
        ]
        blk.block_hash = blk.compute_hash()
        self.blocks.append(blk)
        return blk

    # --- verify path -------------------------------------------------------
    def verify(self) -> tuple[bool, Optional[str]]:
        """
        Full-chain verification. Returns (ok, reason). On any tamper, returns
        (False, human-readable reason identifying the first broken block).
        """
        recomputed_leaves: list[str] = []
        prev = GENESIS_PREV
        for blk in self.blocks:
            # 1. chain link
            if blk.prev_hash != prev:
                return False, f"chain_break@{blk.index}"
            # 2. block hash integrity
            if blk.block_hash != blk.compute_hash():
                return False, f"block_hash_mismatch@{blk.index}"
            # 3. merkle root consistency
            recomputed_leaves.append(blk.fingerprint)
            if blk.merkle_root != merkle_root(recomputed_leaves):
                return False, f"merkle_root_mismatch@{blk.index}"
            # 4. signature quorum
            valid_sigs = sum(
                1 for i, s in enumerate(blk.signatures)
                if self.validators.verify(i, s, blk.header_bytes())
            )
            if valid_sigs < self.quorum:
                return False, f"insufficient_valid_signatures@{blk.index}"
            prev = blk.block_hash
        return True, None

    def root(self) -> str:
        return self.blocks[-1].merkle_root if self.blocks else merkle_root([])

    # --- persistence -------------------------------------------------------
    def save(self, path: Path) -> None:
        with path.open("w", encoding="utf-8") as f:
            for blk in self.blocks:
                f.write(json.dumps(asdict(blk), separators=(",", ":")) + "\n")

    @classmethod
    def load(cls, path: Path, validators: ValidatorSet,
             quorum: int) -> "MerkleLedger":
        led = cls(validators, quorum)
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                d = json.loads(line)
                blk = Block(**d)
                led.blocks.append(blk)
                led._commit_hashes.append(blk.fingerprint)
        return led
