import json

import pytest

from blackbox import keys
from blackbox.log import GENESIS_PREV, EventLog, LogError, read_records, verify_bytes, verify_file


def test_new_log_starts_with_genesis(sample_log, key):
    records = list(read_records(sample_log))
    assert records[0]["type"] == "genesis"
    assert records[0]["prev"] == GENESIS_PREV
    assert records[0]["data"]["public_key"] == keys.public_hex(key)
    assert records[0]["data"]["device"] == "arm-01"
    assert [r["seq"] for r in records] == [0, 1, 2, 3]


def test_records_are_chained(sample_log):
    records = list(read_records(sample_log))
    for earlier, later in zip(records, records[1:]):
        assert later["prev"] == earlier["hash"]


def test_untouched_log_verifies(sample_log):
    result = verify_file(sample_log)
    assert result.ok
    assert result.records == 4
    assert result.first_bad is None
    assert not result.key_pinned


def test_verify_with_pinned_key(sample_log, key):
    result = verify_file(sample_log, keys.public_hex(key))
    assert result.ok and result.key_pinned


def test_pinned_key_mismatch_fails(sample_log):
    other = keys.public_hex(keys.generate())
    result = verify_file(sample_log, other)
    assert not result.ok
    assert result.first_bad == 0
    assert "different key" in result.reason


def test_resume_continues_the_chain(sample_log, key):
    EventLog(sample_log, key, fsync=False).append("note", {"msg": "resumed"})
    records = list(read_records(sample_log))
    assert records[-1]["seq"] == 4
    assert records[-1]["prev"] == records[-2]["hash"]
    assert verify_file(sample_log).ok


def test_resume_with_another_key_is_refused(sample_log):
    with pytest.raises(LogError):
        EventLog(sample_log, keys.generate(), fsync=False)


def test_genesis_type_is_reserved(sample_log, key):
    with pytest.raises(ValueError):
        EventLog(sample_log, key, fsync=False).append("genesis", {})


def test_deleted_record_breaks_the_chain(sample_log):
    lines = sample_log.read_bytes().split(b"\n")
    del lines[2]
    result = verify_bytes(b"\n".join(lines))
    assert not result.ok
    assert result.first_bad == 2


def test_swapped_records_fail(sample_log):
    lines = sample_log.read_bytes().split(b"\n")
    lines[1], lines[2] = lines[2], lines[1]
    result = verify_bytes(b"\n".join(lines))
    assert not result.ok
    assert result.first_bad == 1


def test_edited_value_is_caught_as_hash_mismatch(sample_log):
    lines = sample_log.read_bytes().split(b"\n")
    record = json.loads(lines[2])
    record["data"]["reason"] = "no one in cell"
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    result = verify_bytes(b"\n".join(lines))
    assert not result.ok
    assert result.first_bad == 2
    assert "hash mismatch" in result.reason


def test_rehashed_forgery_without_the_key_fails_signature(sample_log):
    """An attacker who edits a record and recomputes the whole chain still can't sign it."""
    from blackbox.log import _body, _digest, canonical

    lines = [json.loads(line) for line in sample_log.read_bytes().splitlines()]
    lines[2]["data"]["reason"] = "no one in cell"
    prev = lines[1]["hash"]
    for record in lines[2:]:
        record["prev"] = prev
        record["hash"] = _digest(_body(record))
        prev = record["hash"]
    forged = b"".join(canonical(r) + b"\n" for r in lines)
    result = verify_bytes(forged)
    assert not result.ok
    assert result.first_bad == 2
    assert "signature" in result.reason


def test_truncated_last_record_fails(sample_log):
    raw = sample_log.read_bytes()
    result = verify_bytes(raw[:-10])
    assert not result.ok
    assert result.first_bad == 3


def test_empty_log_fails():
    result = verify_bytes(b"")
    assert not result.ok
    assert result.first_bad == 0


def test_two_writers_on_one_log_keep_a_single_chain(sample_log, key):
    first = EventLog(sample_log, key, fsync=False)
    second = EventLog(sample_log, key, fsync=False)  # opened before either writes
    first.append("note", {"by": "first"})
    second.append("note", {"by": "second"})
    first.append("note", {"by": "first again"})
    result = verify_file(sample_log)
    assert result.ok, result.reason
    assert result.records == 7


def test_concurrent_threads_never_fork_the_chain(sample_log, key):
    import threading

    def writer(name):
        log = EventLog(sample_log, key, fsync=False)
        for i in range(25):
            log.append("joint_state", {"writer": name, "i": i})

    threads = [threading.Thread(target=writer, args=(f"w{n}",)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result = verify_file(sample_log)
    assert result.ok, result.reason
    assert result.records == 4 + 100


def test_cut_tail_is_caught_with_an_anchor(sample_log):
    anchor = verify_file(sample_log).head
    raw = sample_log.read_bytes()
    cut = raw[: raw.rstrip(b"\n").rfind(b"\n") + 1]  # drop the last complete record
    assert verify_bytes(cut).ok  # a hash chain alone can't see this
    result = verify_bytes(cut, anchor=anchor)
    assert not result.ok
    assert result.first_bad == 3
    assert "anchored record is missing" in result.reason


def test_anchor_still_passes_after_legitimate_appends(sample_log, key):
    anchor = verify_file(sample_log).head[:16]  # a prefix is enough
    EventLog(sample_log, key, fsync=False).append("note", {"msg": "later event"})
    result = verify_file(sample_log, anchor=anchor)
    assert result.ok and result.anchored


@pytest.mark.parametrize("pinned", ["", "   ", "abc"])
def test_empty_or_malformed_pinned_key_is_rejected(sample_log, pinned):
    with pytest.raises(ValueError):
        verify_file(sample_log, pinned)


@pytest.mark.parametrize("anchor", ["xyz", "", "   "])
def test_malformed_or_empty_anchor_is_rejected(sample_log, anchor):
    with pytest.raises(ValueError):
        verify_file(sample_log, anchor=anchor)


def test_non_ascii_payload_round_trips(tmp_path, key):
    path = tmp_path / "unicode.log"
    EventLog(path, key, fsync=False).append("note", {"msg": "operador detuvo el brazo", "temp_c": 41.5})
    assert verify_file(path).ok
