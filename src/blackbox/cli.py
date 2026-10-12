"""Command-line interface for the black box."""

from __future__ import annotations

import argparse

from blackbox import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackbox",
        description="Tamper-evident, signed incident recorder for robots.",
    )
    parser.add_argument("--version", action="version", version=f"blackbox {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
