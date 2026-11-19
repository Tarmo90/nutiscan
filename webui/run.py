#!/usr/bin/env python3
"""Launch Nutiscan Web UI: python webui/run.py [--port 8822] [--no-browser]"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webui.server import serve  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(prog="nutiscan-web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8822)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    serve(args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
