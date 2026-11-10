#!/usr/bin/env python3
"""Render docs/media/live-proof.gif from the REAL-traffic proof (`zcg-proof`).

Runs the proof (real TCP sockets), captures its plain-text output, and animates
it as a terminal recording. The text shown is exactly what the tool printed —
the detections come from real socket measurements.

Usage: python3 scripts/make_proof_gif.py [output.gif]
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
REDBG = (218, 54, 51)

FS = 17
LH = 25
PAD = 22
WIDTH = 1340


def load_font(names, size):
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            continue
    return ImageFont.load_default()


MONO = load_font(["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"], FS)
MONO_B = load_font(["/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"], FS)


def binary():
    rel = os.path.join(ROOT, "target", "release", "zcg-proof")
    dbg = os.path.join(ROOT, "target", "debug", "zcg-proof")
    return rel if os.path.exists(rel) else dbg


def capture():
    env = dict(os.environ, NO_COLOR="1")
    # Short interval still > engine's 2s min so the beacon fires; quick to run.
    out = subprocess.run(
        [binary(), "com.demo.spyware", "6", "2000"],
        capture_output=True,
        text=True,
        env=env,
    ).stdout
    # The mono font lacks these emoji glyphs; swap for ones it has.
    for a, b in (("⛔", "■"), ("⚠", "▲"), ("⚡", "»"), ("✔", "✓")):
        out = out.replace(a, b)
    return [ln.rstrip("\n") for ln in out.splitlines()]


import re


def style(line):
    """Return (color, bold, bg) for a whole line based on its content."""
    s = line.strip()
    if "NEUTRALIZED" in line:
        return (WHITE, True, REDBG)
    if s.startswith("[") and s.endswith("]"):
        return (CYAN, True, None)  # section header like [VERIFICATION]
    if "LIKELY SPYWARE" in line or s.startswith("▲"):
        return (RED, True, None)
    if "Bypass" in line:  # "... detected: NO" is the GOOD outcome here
        return ((GREEN, True, None) if line.rstrip().endswith("NO") else (RED, True, None))
    # Verdict value lines: "LABEL:   YES" / "... : NO"
    m = re.search(r":\s+(YES|NO)\s*$", line)
    if m:
        return ((GREEN, True, None) if m.group(1) == "YES" else (RED, True, None))
    if "✗" in line:
        return (RED, True, None)
    if "✓" in line:
        return (GREEN, False, None)
    if s.startswith("├"):
        return (WHITE, True, None)
    if s.startswith("│") or s.startswith("·") or "evidence written" in line:
        return (DIM, False, None)
    if any(ch in line for ch in "┌└") or "zeroclick-guard" in line:
        return (CYAN, True, None)
    return (WHITE, False, None)


def render(lines, out_path):
    nlines = len(lines)
    height = 44 + PAD * 2 + nlines * LH
    frames, durations = [], []

    # Reveal one line per frame; hold key lines longer.
    def make(count):
        img = Image.new("RGB", (WIDTH, height), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, WIDTH, 44], fill=BAR)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([20 + i * 26, 15, 34 + i * 26, 29], fill=c)
        d.text((WIDTH / 2, 22), "zeroclick-guard — live proof (real traffic)", font=MONO, fill=DIM, anchor="mm")
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

    for count in range(1, nlines + 1):
        img = make(count)
        last = lines[count - 1]
        hold = 1
        if "QUARANTINED" in last or "NEUTRALIZED" in last:
            hold = 4
        elif last.strip() == "":
            hold = 1
        frames.append(img)
        durations.append(260 if hold == 1 else 260 * hold)
    # Long final hold before looping.
    frames.append(make(nlines))
    durations.append(2600)

    frames = [f.quantize(colors=64, method=Image.MEDIANCUT, dither=Image.NONE) for f in frames]
    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    return out_path, len(frames), height


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs", "media", "live-proof.gif")
    if not os.path.exists(binary()):
        sys.exit("build first: cargo build --workspace --release")
    lines = capture()
    if not lines:
        sys.exit("no output captured from zcg-proof")
    path, n, h = render(lines, out)
    print(f"wrote {path}  ({n} frames, {WIDTH}x{h}, {os.path.getsize(path)//1024} KB)")


if __name__ == "__main__":
    main()
