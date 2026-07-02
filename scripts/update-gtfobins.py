#!/usr/bin/env python3
"""Download the latest GTFOBins API snapshot into the package data directory."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

API_URL = "https://gtfobins.org/api.json"
TARGET = Path(__file__).resolve().parents[1] / "binsuid" / "data" / "gtfobins-api.json"


def main() -> int:
    print(f"Downloading {API_URL} ...")
    with urllib.request.urlopen(API_URL, timeout=60) as response:
        payload = json.load(response)

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with TARGET.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    count = len(payload.get("executables", {}))
    print(f"Wrote {TARGET} ({count} executables)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
