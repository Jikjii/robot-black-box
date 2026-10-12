"""Append-only, hash-chained, Ed25519-signed event log.

Format (version 1)
------------------
One record per line, newline-terminated, in canonical JSON: keys sorted, no whitespace, UTF-8.

    {"data": ..., "hash": "<hex>", "prev": "<hex>", "seq": 0, "sig": "<hex>", "ts": "...", "type": "...", "v": 1}

- ``seq``  : 0, 1, 2, ... with no gaps.
- ``prev`` : the ``hash`` of the previous record (64 zeros for record 0).
- ``hash`` : SHA-256 of the canonical JSON of the record body (every field except ``hash`` and ``sig``).
- ``sig``  : Ed25519 signature over the 32-byte ``hash``.

Record 0 is always a ``genesis`` record whose data carries the log's public key. Verification
re-serializes every line and requires it to match byte for byte, so any change to a stored
byte (content, field, escape or newline) is detected and attributed to the record it sits in.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blackbox import keys

FORMAT = "blackbox-log/1"
VERSION = 1
GENESIS_PREV = "0" * 64
RECORD_FIELDS = frozenset({"v", "seq", "ts", "type", "data", "prev", "hash", "sig"})


def canonical(obj: Any) -> bytes:
    """Canonical JSON encoding used for hashing and for the stored lines."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _body(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record[k] for k in ("v", "seq", "ts", "type", "data", "prev")}


def _digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(c in "0123456789abcdef" for c in value)


class LogError(Exception):
    """Raised when a log can't be opened for appending."""


class EventLog:
    """Writer for a black-box log. Creates the genesis record on first use, resumes otherwise."""

    def __init__(
        self,
        path: str | Path,
        signing_key: Ed25519PrivateKey,
        device: str | None = None,
        fsync: bool = True,
    ) -> None:
        self.path = Path(path)
        self._key = signing_key
        self._pub = keys.public_hex(signing_key)
        self._fsync = fsync
        if self.path.exists() and self.path.stat().st_size > 0:
            self._resume()
        else:
            self._seq = 0
            self._prev = GENESIS_PREV
            self._write(
                "genesis",
                {"format": FORMAT, "public_key": self._pub, "device": device},
                utc_now(),
            )

    def _resume(self) -> None:
        raw = self.path.read_bytes()
        if not raw.endswith(b"\n"):
            raise LogError(f"{self.path}: last record is incomplete; run `blackbox verify` first")
        lines = raw[:-1].split(b"\n")
        try:
            first = json.loads(lines[0])
            last = json.loads(lines[-1])
            genesis_key = first["data"]["public_key"] if first["type"] == "genesis" else None
            next_seq = last["seq"] + 1
            prev = last["hash"]
        except (ValueError, KeyError, TypeError) as exc:
            raise LogError(f"{self.path}: unreadable record; run `blackbox verify` first") from exc
        if genesis_key != self._pub:
            raise LogError(f"{self.path}: this log was started with a different signing key")
        self._seq = next_seq
        self._prev = prev

    def append(self, type: str, data: Any = None, ts: str | None = None) -> dict[str, Any]:
        """Append one signed event and return the stored record."""
        if type == "genesis":
            raise ValueError("'genesis' is reserved for the first record")
        return self._write(type, data, ts or utc_now())

    def _write(self, type: str, data: Any, ts: str) -> dict[str, Any]:
        body = {"v": VERSION, "seq": self._seq, "ts": ts, "type": type, "data": data, "prev": self._prev}
        digest = _digest(body)
        record = {**body, "hash": digest, "sig": self._key.sign(bytes.fromhex(digest)).hex()}
        with open(self.path, "ab") as handle:
            handle.write(canonical(record) + b"\n")
            handle.flush()
            if self._fsync:
                os.fsync(handle.fileno())
        self._seq += 1
        self._prev = digest
        return record


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    first_bad: int | None = None
    reason: str | None = None
    head: str | None = None
    public_key: str | None = None
    key_pinned: bool = False


def verify_bytes(raw: bytes, pinned_public_key: str | None = None) -> VerifyResult:
    """Check every record; stop at the first bad one and say which and why."""
    pinned = pinned_public_key.strip().lower() if pinned_public_key else None

    def bad(index: int, reason: str, good: int, pub: str | None = None) -> VerifyResult:
        return VerifyResult(False, good, index, reason, None, pub, pinned is not None)

    if not raw:
        return bad(0, "log is empty", 0)
    lines = raw.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    else:
        # No trailing newline: the last record was cut short or its newline was altered.
        pass

    verifier = None
    public_key = None
    prev = GENESIS_PREV
    for index, line in enumerate(lines):
        is_last = index == len(lines) - 1
        if is_last and not raw.endswith(b"\n"):
            return bad(index, "record is incomplete (missing its newline)", index, public_key)
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return bad(index, "record is not valid JSON", index, public_key)
        if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
            return bad(index, "record has missing or unexpected fields", index, public_key)
        try:
            reencoded = canonical(record)
        except ValueError:
            return bad(index, "record is not valid JSON", index, public_key)
        if reencoded != line:
            return bad(index, "record bytes are not in canonical form", index, public_key)
        if record["v"] != VERSION or type(record["v"]) is not int:
            return bad(index, "unsupported record version", index, public_key)
        if type(record["seq"]) is not int or record["seq"] != index:
            return bad(index, f"sequence number should be {index}", index, public_key)
        if not isinstance(record["ts"], str) or not isinstance(record["type"], str):
            return bad(index, "timestamp and type must be strings", index, public_key)
        if not (_is_hex(record["prev"], 64) and _is_hex(record["hash"], 64) and _is_hex(record["sig"], 128)):
            return bad(index, "hash, prev or signature is malformed", index, public_key)
        if record["prev"] != prev:
            return bad(index, "chain broken: prev does not match the previous record's hash", index, public_key)
        if _digest(_body(record)) != record["hash"]:
            return bad(index, "hash mismatch: record contents were changed", index, public_key)

        if index == 0:
            data = record["data"]
            if record["type"] != "genesis" or not isinstance(data, dict):
                return bad(0, "first record is not a genesis record", 0)
            public_key = data.get("public_key")
            try:
                verifier = keys.public_from_hex(public_key)
            except (TypeError, ValueError, AttributeError):
                return bad(0, "genesis record has no valid public key", 0)
            if public_key != public_key.lower():
                return bad(0, "genesis public key must be lowercase hex", 0)
            if pinned is not None and public_key != pinned:
                return bad(0, "log was signed by a different key than the pinned public key", 0, public_key)
        elif record["type"] == "genesis":
            return bad(index, "genesis record appears after the start of the log", index, public_key)

        try:
            verifier.verify(bytes.fromhex(record["sig"]), bytes.fromhex(record["hash"]))
        except InvalidSignature:
            return bad(index, "signature does not verify", index, public_key)
        prev = record["hash"]

    return VerifyResult(True, len(lines), None, None, prev, public_key, pinned is not None)


def verify_file(path: str | Path, pinned_public_key: str | None = None) -> VerifyResult:
    return verify_bytes(Path(path).read_bytes(), pinned_public_key)


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield records without verifying them. Use verify_file first for evidence."""
    with open(path, "rb") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)
