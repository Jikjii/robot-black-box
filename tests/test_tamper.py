"""Exhaustive tamper tests: any single-byte change must fail verify and name the record it hit."""

import pytest

from blackbox.log import verify_bytes


def _record_index(raw: bytes, position: int) -> int:
    """Index of the record (line) that contains the byte at `position`, newline included."""
    return raw[:position].count(b"\n")


@pytest.mark.parametrize("mask", [0x01, 0x20, 0x80])
def test_every_single_byte_flip_is_caught(sample_log, mask):
    raw = sample_log.read_bytes()
    assert verify_bytes(raw).ok

    for position in range(len(raw)):
        tampered = bytearray(raw)
        tampered[position] ^= mask
        result = verify_bytes(bytes(tampered))
        expected = _record_index(raw, position)
        assert not result.ok, f"flip {mask:#04x} at byte {position} went undetected"
        assert result.first_bad == expected, (
            f"flip {mask:#04x} at byte {position} blamed record {result.first_bad}, expected {expected}"
        )


def test_every_single_byte_deletion_is_caught(sample_log):
    raw = sample_log.read_bytes()
    for position in range(len(raw)):
        tampered = raw[:position] + raw[position + 1 :]
        result = verify_bytes(tampered)
        assert not result.ok, f"deleting byte {position} went undetected"
        assert result.first_bad == _record_index(raw, position)
