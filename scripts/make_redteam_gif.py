#!/usr/bin/env python3
"""Render docs/media/redteam.gif from the adversarial benchmark (`zcg-redteam`).

Runs the real benchmark (no color), captures its text, animates it. The
percentages shown come straight from the engine.

Usage: python3 scripts/make_redteam_gif.py [output.gif]
Requires: Pillow. Build first: cargo build --workspace --release
"""
import os
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BG = (13, 17, 23)
BAR = (22, 27, 34)
WHITE = (230, 237, 243)
DIM = (139, 148, 158)
CYAN = (57, 197, 207)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
YELLOW = (210, 153, 34)
GREENBG = (35, 134, 54)

FS = 17
LH = 25
PAD = 22
WIDTH = 1240


def font(names, size):
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            continue
    return ImageFont.load_default()


MONO = font(["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"], FS)
MONO_B = font(["/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"], FS)


def binary():
    rel = os.path.join(ROOT, "target", "release", "zcg-redteam")
    dbg = os.path.join(ROOT, "target", "debug", "zcg-redteam")
    return rel if os.path.exists(rel) else dbg


def capture():
    env = dict(os.environ, NO_COLOR="1")
    out = subprocess.run([binary()], capture_output=True, text=True, env=env).stdout
    return [ln.rstrip("\n") for ln in out.splitlines()]


def style(line):
    s = line.strip()
    if "DEFENSE HOLDS" in line:
        return (WHITE, True, GREENBG)
    if "DEFENSE REGRESSED" in line:
        return (WHITE, True, RED)
    if any(s.startswith(t) for t in ("CORE ATTACKS", "EVASION SUITE", "FALSE POSITIVES")) or "SCORECARD" in line:
        return (CYAN, True, None)
    if "✓ caught" in line or line.strip().startswith("✓"):
        return (GREEN, False, None)
    if "~ partial" in line:
        return (YELLOW, False, None)
    if "✗ missed" in line or line.strip().startswith("✗"):
        return (RED, False, None)
    if "Evasion suite:" in line or "Honest:" in line or "real sockets" in line:
        return (DIM, False, None)
    if line.rstrip().endswith("%"):
        # scorecard metric line
        return (WHITE, True, None)
    if any(ch in line for ch in "┌└│"):
        return (RED, True, None)
    return (WHITE, False, None)


def render(lines, out_path):
    height = 44 + PAD * 2 + len(lines) * LH
    frames, durations = [], []

    def make(count):
        img = Image.new("RGB", (WIDTH, height), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, WIDTH, 44], fill=BAR)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([20 + i * 26, 15, 34 + i * 26, 29], fill=c)
        d.text((WIDTH / 2, 22), "zeroclick-guard — red team benchmark", font=MONO, fill=DIM, anchor="mm")
        y = 44 + PAD
        for line in lines[:count]:
            color, bold, bg = style(line)
            f = MONO_B if bold else MONO
            if bg is not None and line.strip():
                w = d.textlength(line, font=f)
                d.rectangle([PAD - 4, y - 2, PAD + w + 6, y + FS + 6], fill=bg)
            d.text((PAD, y), line, font=f, fill=color)
            y += LH
        return img

    for count in range(1, len(lines) + 1):
        frames.append(make(count))
        last = lines[count - 1]
        durations.append(1000 if "DEFENSE" in last else 150)
    frames.append(make(len(lines)))
    durations.append(2800)

    frames = [f.quantize(colors=64, method=Image.MEDIANCUT, dither=Image.NONE) for f in frames]
    frames[0].save(out_path, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True, disposal=2)
    return out_path, len(frames), height


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs", "media", "redteam.gif")
    if not os.path.exists(binary()):
        sys.exit("build first: cargo build --workspace --release")
    lines = capture()
    if not lines:
        sys.exit("no output")
    path, n, h = render(lines, out)
    print(f"wrote {path}  ({n} frames, {WIDTH}x{h}, {os.path.getsize(path)//1024} KB)")


if __name__ == "__main__":
    main()
