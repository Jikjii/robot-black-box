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
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterator

try:  # POSIX file locking; robots run Linux. Without it, use one writer per log.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

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


@contextmanager
def _locked(path: Path) -> Iterator[BinaryIO]:
    """Open the log for appending under an exclusive inter-process lock (POSIX)."""
    with open(path, "a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield handle
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _first_and_last(handle: BinaryIO, path: Path) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Read the genesis and the current head record straight from disk, or None for an empty log."""
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size == 0:
        return None
    position, tail = size, b""
    while position > 0 and tail.count(b"\n") < 2:
        step = min(65536, position)
        position -= step
        handle.seek(position)
        tail = handle.read(step) + tail
    if not tail.endswith(b"\n"):
        raise LogError(f"{path}: last record is incomplete; run `blackbox verify` first")
    handle.seek(0)
    try:
        first = json.loads(handle.readline())
        last = json.loads(tail[:-1].rsplit(b"\n", 1)[-1])
        if first["type"] != "genesis" or not isinstance(last["seq"], int) or not _is_hex(last["hash"], 64):
            raise ValueError("bad genesis or head record")
    except (ValueError, KeyError, TypeError) as exc:
        raise LogError(f"{path}: unreadable record; run `blackbox verify` first") from exc
    return first, last


class EventLog:
    """Writer for a black-box log. Creates the genesis record on first use, resumes otherwise.

    Every append re-reads the head record from disk under an exclusive lock, so several writers
    (threads, processes, `blackbox append` calls) can share one log without forking the chain.
    """

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
        with _locked(self.path) as handle:
            ends = _first_and_last(handle, self.path)
            if ends is None:
                genesis = {"format": FORMAT, "public_key": self._pub, "device": device}
                self._write(handle, 0, GENESIS_PREV, "genesis", genesis, utc_now())
            else:
                self._check_owner(ends[0])

    def _check_owner(self, genesis: dict[str, Any]) -> None:
        data = genesis.get("data")
        if not isinstance(data, dict) or data.get("public_key") != self._pub:
            raise LogError(f"{self.path}: this log was started with a different signing key")

    def append(self, type: str, data: Any = None, ts: str | None = None) -> dict[str, Any]:
        """Append one signed event and return the stored record."""
        if type == "genesis":
            raise ValueError("'genesis' is reserved for the first record")
        with _locked(self.path) as handle:
            ends = _first_and_last(handle, self.path)
            if ends is None:
                raise LogError(f"{self.path}: log is empty; it has lost its genesis record")
            first, last = ends
            self._check_owner(first)
            return self._write(handle, last["seq"] + 1, last["hash"], type, data, ts or utc_now())

    def _write(self, handle: BinaryIO, seq: int, prev: str, type: str, data: Any, ts: str) -> dict[str, Any]:
        body = {"v": VERSION, "seq": seq, "ts": ts, "type": type, "data": data, "prev": prev}
        digest = _digest(body)
        record = {**body, "hash": digest, "sig": self._key.sign(bytes.fromhex(digest)).hex()}
        handle.seek(0, os.SEEK_END)
        handle.write(canonical(record) + b"\n")
        handle.flush()
        if self._fsync:
            os.fsync(handle.fileno())
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
    anchored: bool = False


def normalize_anchor(anchor: str) -> str:
    """An anchor is a record hash (or a prefix of at least 12 hex characters) saved outside the log."""
    value = anchor.strip().lower()
    if not (12 <= len(value) <= 64 and _is_hex(value, len(value))):
        raise ValueError("an anchor is 12 to 64 hex characters of a record hash (see `blackbox head`)")
    return value


def verify_bytes(
    raw: bytes, pinned_public_key: str | None = None, anchor: str | None = None
) -> VerifyResult:
    """Check every record; stop at the first bad one and say which and why.

    A hash chain alone can't prove nothing was cut off the end. Pass `anchor`, a head hash recorded
    somewhere outside the log (`blackbox head`), to also prove the log still reaches that record.
    """
    pinned = pinned_public_key.strip().lower() if pinned_public_key else None
    # An explicitly passed anchor must be valid, even if empty (e.g. an unset shell variable).
    expected_anchor = normalize_anchor(anchor) if anchor is not None else None

    def bad(index: int, reason: str, good: int, pub: str | None = None) -> VerifyResult:
        return VerifyResult(False, good, index, reason, None, pub, pinned is not None, expected_anchor is not None)

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
    anchor_found = False
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
        if expected_anchor and prev.startswith(expected_anchor):
            anchor_found = True

    if expected_anchor and not anchor_found:
        return bad(
            len(lines),
            "anchored record is missing: records were cut from the end, or this is a different log",
            len(lines),
            public_key,
        )
    return VerifyResult(True, len(lines), None, None, prev, public_key, pinned is not None, expected_anchor is not None)


def verify_file(path: str | Path, pinned_public_key: str | None = None, anchor: str | None = None) -> VerifyResult:
    return verify_bytes(Path(path).read_bytes(), pinned_public_key, anchor)


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield records without verifying them. Use verify_file first for evidence."""
    with open(path, "rb") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)
