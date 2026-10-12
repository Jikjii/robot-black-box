from blackbox.cli import main


def _keygen(tmp_path):
    keyfile = tmp_path / "robot.key"
    assert main(["keygen", str(keyfile)]) == 0
    return keyfile


def test_keygen_writes_both_files_and_refuses_overwrite(tmp_path, capsys):
    keyfile = _keygen(tmp_path)
    assert keyfile.exists()
    assert (tmp_path / "robot.key.pub").exists()
    assert oct(keyfile.stat().st_mode & 0o777) == "0o600"
    assert main(["keygen", str(keyfile)]) == 2


def test_append_then_verify(tmp_path, capsys):
    keyfile = _keygen(tmp_path)
    log = tmp_path / "incident.log"
    assert main(["append", str(log), "--key", str(keyfile), "--type", "estop", "--data", '{"source": "operator"}']) == 0
    assert main(["append", str(log), "--key", str(keyfile), "--type", "fault", "--data", '{"code": "E-217"}']) == 0
    capsys.readouterr()

    assert main(["verify", str(log), "--pubkey", f"{keyfile}.pub"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK: 3 records verified")
    assert "pinned public key" in out


def test_verify_reports_the_first_bad_record(tmp_path, capsys):
    keyfile = _keygen(tmp_path)
    log = tmp_path / "incident.log"
    for event in ("joint_state", "estop", "fault"):
        assert main(["append", str(log), "--key", str(keyfile), "--type", event]) == 0
    raw = bytearray(log.read_bytes())
    second_line_start = raw.index(b"\n") + 1
    third_line_start = raw.index(b"\n", second_line_start) + 1
    raw[third_line_start + 20] ^= 0x01
    log.write_bytes(bytes(raw))
    capsys.readouterr()

    assert main(["verify", str(log)]) == 1
    assert capsys.readouterr().out.startswith("FAIL: record 2:")


def test_keygen_force_resets_loose_permissions(tmp_path):
    keyfile = _keygen(tmp_path)
    keyfile.chmod(0o644)
    assert main(["keygen", str(keyfile), "--force"]) == 0
    assert oct(keyfile.stat().st_mode & 0o777) == "0o600"
    assert not list(tmp_path.glob(".*.tmp"))


def test_head_then_verify_with_anchor(tmp_path, capsys):
    keyfile = _keygen(tmp_path)
    log = tmp_path / "incident.log"
    for event in ("joint_state", "estop"):
        assert main(["append", str(log), "--key", str(keyfile), "--type", event]) == 0
    capsys.readouterr()

    assert main(["head", str(log)]) == 0
    head = capsys.readouterr().out.split("head ")[1].split()[0]
    assert len(head) == 64

    assert main(["verify", str(log), "--anchor", head]) == 0
    assert "anchor found" in capsys.readouterr().out

    raw = log.read_bytes()
    log.write_bytes(raw[: raw.rstrip(b"\n").rfind(b"\n") + 1])
    assert main(["verify", str(log), "--anchor", head]) == 1
    assert "anchored record is missing" in capsys.readouterr().out


def test_bad_json_data_is_rejected(tmp_path):
    keyfile = _keygen(tmp_path)
    assert main(["append", str(tmp_path / "x.log"), "--key", str(keyfile), "--type", "note", "--data", "{oops"]) == 2
