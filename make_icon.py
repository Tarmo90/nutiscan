#!/usr/bin/env python3
"""Generate Nutiscan.ico with the standard library only (no pip packages)."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent / "Nutiscan.ico"


class Canvas:
    def __init__(self, size: int) -> None:
        self.size = size
        self.px = [[(0, 0, 0, 0) for _ in range(size)] for _ in range(size)]

    def set(self, x: int, y: int, color) -> None:
        if 0 <= x < self.size and 0 <= y < self.size:
            self.px[y][x] = color

    def rounded(self, x0: int, y0: int, x1: int, y1: int, r: int, color) -> None:
        for y in range(y0, y1 + 1):
            for x in range(x0, x1 + 1):
                dx = max(x0 + r - x, 0, x - (x1 - r))
                dy = max(y0 + r - y, 0, y - (y1 - r))
                if dx * dx + dy * dy <= r * r:
                    self.set(x, y, color)

    def ring(self, cx: float, cy: float, radius: float, width: float, color) -> None:
        inner = (radius - width) ** 2
        outer = radius ** 2
        for y in range(int(cy - radius - 1), int(cy + radius + 2)):
            for x in range(int(cx - radius - 1), int(cx + radius + 2)):
                d = (x - cx) ** 2 + (y - cy) ** 2
                if inner <= d <= outer:
                    self.set(x, y, color)

    def disc(self, cx: float, cy: float, radius: float, color) -> None:
        for y in range(int(cy - radius - 1), int(cy + radius + 2)):
            for x in range(int(cx - radius - 1), int(cx + radius + 2)):
                if (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2:
                    self.set(x, y, color)

    def line(self, x0: float, y0: float, x1: float, y1: float, width: float, color) -> None:
        steps = int(max(abs(x1 - x0), abs(y1 - y0)) * 3) + 1
        for i in range(steps + 1):
            t = i / steps
            x = x0 + (x1 - x0) * t
            y = y0 + (y1 - y0) * t
            self.disc(x, y, width / 2, color)

    def png(self) -> bytes:
        raw = b"".join(b"\x00" + bytes(v for pixel in row for v in pixel) for row in self.px)

        def chunk(kind: bytes, data: bytes) -> bytes:
            return (struct.pack(">I", len(data)) + kind + data
                    + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

        header = struct.pack(">IIBBBBB", self.size, self.size, 8, 6, 0, 0, 0)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def draw(size: int) -> bytes:
    c = Canvas(size)
    s = size / 64
    green = (61, 220, 151, 255)
    dark = (9, 15, 24, 255)
    panel = (16, 34, 44, 255)
    white = (222, 240, 247, 255)

    c.rounded(int(2 * s), int(2 * s), int(62 * s), int(62 * s), int(12 * s), green)
    c.rounded(int(4 * s), int(4 * s), int(60 * s), int(60 * s), int(11 * s), dark)
    c.rounded(int(8 * s), int(8 * s), int(56 * s), int(56 * s), int(9 * s), panel)

    # Magnifier glass: scan / find.
    c.ring(29 * s, 28 * s, 14 * s, 4 * s, green)
    c.line(39 * s, 38 * s, 51 * s, 51 * s, 7 * s, green)
    c.line(39 * s, 38 * s, 51 * s, 51 * s, 4 * s, dark)

    # Shield check: security / fix.
    cx, cy = 29 * s, 28 * s
    c.ring(cx, cy, 9 * s, 2.5 * s, white)
    c.line(24 * s, 28 * s, 28 * s, 32 * s, 2.8 * s, white)
    c.line(28 * s, 32 * s, 35 * s, 23 * s, 2.8 * s, white)
    return c.png()


def main() -> None:
    sizes = (16, 24, 32, 48, 64, 128, 256)
    images = [(n, draw(n)) for n in sizes]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    data = b""
    for size, png in images:
        dim = size if size < 256 else 0
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        data += png
        offset += len(png)
    OUT.write_bytes(header + entries + data)
    print(f"{OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
