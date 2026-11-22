#!/usr/bin/env python3
"""Build a clean distributable ZIP of Nutiscan.

Usage:
    python make_release.py [output.zip]

Never includes: the vendor private key, git metadata, bytecode, scan reports,
history, webhook state or previous release archives.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

INCLUDE_FILES = (
    "README.md", "LICENSE", "LICENSE_KEYS.md", "CHANGELOG.md",
    "scan.py", "license_tool.py", "license_webhook.py", "make_release.py",
    "gui.py", "Nutiscan-Web.bat", "Nutiscan.spec", "NutiscanGUI.spec",
    "demo_target.py", "demo_fixed.py", "make_icon.py",
)
INCLUDE_DIRS = ("nutiscan", "webui", "tests")
EXCLUDE_DIRS = {"__pycache__", ".git", "reports", "webui-history", "webhook-state", ".pytest_cache"}
EXCLUDE_FILES = {"license_private.key"}
EXCLUDE_SUFFIXES = (".pyc", ".zip", ".log", ".tmp")


def allowed(relative: Path) -> bool:
    parts = relative.parts
    if any(part in EXCLUDE_DIRS for part in parts):
        return False
    if parts[-1] in EXCLUDE_FILES:
        return False
    return not parts[-1].endswith(EXCLUDE_SUFFIXES)


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "nutiscan-free.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []

    for name in INCLUDE_FILES:
        path = ROOT / name
        if path.is_file():
            paths.append(path)
    for name in INCLUDE_DIRS:
        directory = ROOT / name
        if directory.is_dir():
            paths.extend(
                path for path in sorted(directory.rglob("*"))
                if path.is_file() and allowed(path.relative_to(ROOT))
            )

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in paths:
            archive.write(path, path.relative_to(ROOT).as_posix())

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        if "license_private.key" in names or any("__pycache__" in name for name in names):
            raise SystemExit("Build contains forbidden files — aborting")
        if "nutiscan/public_key.py" not in names or "scan.py" not in names:
            raise SystemExit("Build is missing essential files — aborting")
        print(f"{output} — {len(names)} files, {output.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
