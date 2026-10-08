"""Append-only JSONL audit log. Argument values are hashed, not stored, to avoid leaking secrets.

Opt-in tamper evidence: ``AuditLog(path, chain=True)`` adds ``seq``, ``prev`` and ``hash`` to
each record, where ``hash = sha256(prev + canonical_json(record_without_hash))`` and the first
record's ``prev`` is 64 zeros. :func:`verify` recomputes the chain and reports the first bad line.

What the chain does and does not prove:
* It detects edits, insertions, deletions and re-ordering of records *within* the file.
* It cannot, on its own, detect the newest records being cut off the end, or a full rewrite by
  someone able to recompute every hash. Copy ``verify(path).head`` (the latest hash) somewhere
  the writer of the log cannot modify if you need to detect those.
* ``args_sha256`` is an un-keyed SHA-256 of the argument values. Low-entropy values (e.g.
  "yes"/"no", small numbers) can be guessed by hashing candidates. Pass ``hash_key=b"..."`` to
  use HMAC-SHA256 instead.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _link(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + _canonical(body)).encode("ascii")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, *, chain: bool = False, hash_key: bytes | None = None,
                 fsync: bool = False):
        self.path = Path(path)
        self.chain = chain
        self._key = hash_key
        self._fsync = fsync
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        if chain and self.path.exists() and self.path.stat().st_size > 0:
            res = verify(self.path)
            if not res.ok:  # refuse to extend a broken chain
                raise ValueError(f"existing audit log {str(self.path)!r} failed verification: {res.error}")
            self._seq, self._prev = res.records, res.head

    def _digest(self, blob: bytes) -> str:
        if self._key is not None:
            return hmac.new(self._key, blob, hashlib.sha256).hexdigest()
        return hashlib.sha256(blob).hexdigest()

    def write(self, tool: str, arguments: Any, allowed: bool, reason: str, latency_ms: float) -> None:
        try:
            blob = json.dumps(arguments, sort_keys=True, default=str).encode()
        except Exception:
            blob = b"<unserializable>"
        record = {
            "ts": time.time(),
            "tool": str(tool),
            "arg_keys": sorted(map(str, arguments)) if isinstance(arguments, dict) else [],
            "args_sha256": self._digest(blob),
            "allowed": allowed,
            "reason": reason,
            "latency_ms": round(latency_ms, 4),
        }
        if self._key is not None:
            record["args_digest_alg"] = "hmac-sha256"
        with self._lock:
            if self.chain:
                record["seq"] = self._seq
                record["prev"] = self._prev
                h = _link(self._prev, record)
                line = _canonical({**record, "hash": h})
            else:
                line = json.dumps(record)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                if self._fsync:
                    os.fsync(f.fileno())
            if self.chain:
                self._seq, self._prev = self._seq + 1, h


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    head: str                        # hash of the last valid record (GENESIS if none)
    error: str | None = None
    bad_line: int | None = None      # 1-based line number of the first bad record

    def __bool__(self) -> bool:
        return self.ok


def verify(path: str | Path) -> VerifyResult:
    """Recompute the hash chain of a log written with ``AuditLog(..., chain=True)``."""
    prev, n = GENESIS, 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.endswith("\n"):
                    return VerifyResult(False, n, prev, "incomplete final line", lineno)
                try:
                    rec = json.loads(line)
                except ValueError:
                    return VerifyResult(False, n, prev, "not valid JSON", lineno)
                if not isinstance(rec, dict) or not {"seq", "prev", "hash"} <= set(rec):
                    return VerifyResult(False, n, prev, "record is not chained", lineno)
                if rec["seq"] != n:
                    return VerifyResult(False, n, prev, "sequence gap or reorder", lineno)
                if rec["prev"] != prev:
                    return VerifyResult(False, n, prev, "prev-hash link broken", lineno)
                body = {k: v for k, v in rec.items() if k != "hash"}
                if _link(prev, body) != rec["hash"]:
                    return VerifyResult(False, n, prev, "hash mismatch (record altered)", lineno)
                prev, n = rec["hash"], n + 1
    except (OSError, UnicodeDecodeError) as exc:
        return VerifyResult(False, n, prev, f"cannot read log: {type(exc).__name__}")
    return VerifyResult(True, n, prev)
