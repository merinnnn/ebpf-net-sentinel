#!/usr/bin/env python3
"""Project-wide logging helpers.

Style:
  [*] info
  [+] success
  [!] warning
  [x] error

All logs are UTC timestamped to keep runs comparable across machines.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt(prefix: str, msg: str) -> str:
    return f"{_ts()} {prefix} {msg}"


def info(msg: str) -> None:
    print(_fmt("[*]", msg), flush=True)


def ok(msg: str) -> None:
    print(_fmt("[+]", msg), flush=True)


def warn(msg: str) -> None:
    print(_fmt("[!]", msg), flush=True)


def err(msg: str) -> None:
    print(_fmt("[x]", msg), flush=True)


def die(msg: str, code: int = 1) -> None:
    print(f"[x] {msg}", flush=True)
    raise SystemExit(code)
