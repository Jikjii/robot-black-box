"""Command-line interface for the black box."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from blackbox import __version__, keys
from blackbox.log import EventLog, LogError, verify_file


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.keyfile)
    public_path = Path(f"{args.keyfile}.pub")
    if not args.force and (private_path.exists() or public_path.exists()):
        print(f"refusing to overwrite {private_path} or {public_path} (use --force)", file=sys.stderr)
        return 2
    key = keys.generate()
    keys.save_private(key, private_path)
    keys.save_public(key, public_path)
    print(f"private key: {private_path} (keep it secret)")
    print(f"public key:  {public_path}  {keys.public_hex(key)}")
    return 0


def _cmd_append(args: argparse.Namespace) -> int:
    try:
        data = json.loads(args.data) if args.data is not None else None
    except ValueError:
        print("--data must be valid JSON", file=sys.stderr)
        return 2
    try:
        log = EventLog(args.log, keys.load_private(args.key), device=args.device)
        record = log.append(args.type, data, ts=args.ts)
    except (LogError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"appended record {record['seq']} ({record['type']}) {record['hash'][:12]}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        pinned = keys.load_public_hex(args.pubkey) if args.pubkey else None
        result = verify_file(args.log, pinned, args.anchor)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if result.ok:
        source = "pinned public key" if result.key_pinned else "key from the log itself (pass --pubkey to pin it)"
        print(f"OK: {result.records} records verified, head {result.head[:12]}, checked against {source}")
        if result.anchored:
            print("anchor found: no records were cut from the end up to the anchored record")
        else:
            print("note: pass --anchor <hash from `blackbox head`> to also prove nothing was cut from the end")
        return 0
    print(f"FAIL: record {result.first_bad}: {result.reason}")
    print(f"{result.records} record(s) before it verified")
    return 1


def _cmd_head(args: argparse.Namespace) -> int:
    try:
        pinned = keys.load_public_hex(args.pubkey) if args.pubkey else None
        result = verify_file(args.log, pinned)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not result.ok:
        print(f"FAIL: record {result.first_bad}: {result.reason}")
        return 1
    print(f"record {result.records - 1} head {result.head}")
    print("save this hash somewhere outside the log; `verify --anchor` proves the log still reaches it")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackbox",
        description="Tamper-evident, signed incident recorder for robots.",
    )
    parser.add_argument("--version", action="version", version=f"blackbox {__version__}")
    sub = parser.add_subparsers(dest="command")

    keygen = sub.add_parser("keygen", help="create an Ed25519 signing key pair")
    keygen.add_argument("keyfile", help="path for the private key; the public key goes to KEYFILE.pub")
    keygen.add_argument("--force", action="store_true", help="overwrite existing key files")
    keygen.set_defaults(func=_cmd_keygen)

    append = sub.add_parser("append", help="append one signed event to a log")
    append.add_argument("log", help="log file (created with a genesis record if new)")
    append.add_argument("--key", required=True, help="private key file from `blackbox keygen`")
    append.add_argument("--type", required=True, help="event type, e.g. estop, fault, joint_state")
    append.add_argument("--data", help="event payload as JSON")
    append.add_argument("--ts", help="event timestamp (defaults to now, UTC)")
    append.add_argument("--device", help="device id recorded in the genesis record of a new log")
    append.set_defaults(func=_cmd_append)

    verify = sub.add_parser("verify", help="check every record's chain link and signature")
    verify.add_argument("log", help="log file to verify")
    verify.add_argument("--pubkey", help="public key file to pin against (recommended for evidence)")
    verify.add_argument("--anchor", help="head hash saved earlier with `blackbox head`; proves nothing was cut from the end")
    verify.set_defaults(func=_cmd_verify)

    head = sub.add_parser("head", help="verify a log and print its head hash to save as an anchor")
    head.add_argument("log", help="log file")
    head.add_argument("--pubkey", help="public key file to pin against")
    head.set_defaults(func=_cmd_head)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
