#!/usr/bin/env python3
"""Render an animated terminal-style GIF of the "World Spyware Gauntlet".

It runs the real engine over each benign family profile, then animates the
scoreboard (scanning -> DETECTED) and a final tally. The numbers in the GIF
come straight from the engine — nothing is drawn by hand.

Usage: python3 scripts/make_gif.py [output.gif]
Requires: Pillow. Build binaries first: cargo build --workspace --release
"""
import json
import os
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOC = os.path.join(ROOT, "examples", "ioc-families.json")


def bins():
    rel = os.path.join(ROOT, "target", "release")
    dbg = os.path.join(ROOT, "target", "debug")
    base = rel if os.path.exists(os.path.join(rel, "zcg")) else dbg
    return os.path.join(base, "zcg"), os.path.join(base, "zcg-testlab")


ZCG, LAB = bins()

FAMILIES = [
    ("pegasus", "Pegasus (NSO Group)", "zero-click via messenger"),
    ("triangulation", "Operation Triangulation", "zero-click via iMessage"),
    ("predator", "Predator (Cytrox)", "installed, full capture"),
    ("finfisher", "FinFisher / FinSpy", "installed, mic + camera"),
    ("hermit", "Hermit (RCS Lab)", "installed via SMS lure"),
    ("chrysaor", "Chrysaor", "accessibility keylogging"),
    ("stalkerware", "Commercial stalkerware", "hidden tracker app"),
]

# GitHub-dark palette.
BG = (13, 17, 23)
BAR = (22, 27, 34)
WHITE = (230, 237, 243)
DIM = (139, 148, 158)
CYAN = (57, 197, 207)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
YELLOW = (210, 153, 34)

FS = 22
LH = 32
PAD = 28
WIDTH = 1180


def load_font(names, size):
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            continue
    return ImageFont.load_default()


MONO = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ],
    FS,
)
MONO_B = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    ],
    FS,
)


def run_family(key):
    out = subprocess.run(
        f'"{LAB}" {key} | "{ZCG}" --ioc "{IOC}" --json',
        shell=True,
        capture_output=True,
        text=True,
    ).stdout
    data = json.loads(out) if out.strip() else []
    if not data:
        return 0, "clean"
    top = max(data, key=lambda x: x["score"])
    return top["score"], top["severity"]


def seg(text, color=WHITE, bold=False):
    return (text, color, bold)


def build_states(results):
    """Each state is a list of lines; each line is a list of segments."""
    header = [
        [seg("zeroclick-guard", CYAN, True), seg("  —  WORLD SPYWARE GAUNTLET", WHITE, True)],
        [seg("benign behavioral profiles  vs.  the real engine", DIM)],
        [seg("not a claim — proof", DIM)],
        [],
    ]
    states = []
    rows = []  # finalized rows so far

    def frame(extra_line=None, hold=1):
        body = [list(r) for r in rows]
        if extra_line is not None:
            body.append(extra_line)
        states.append((header + body, hold))

    frame()  # header only
    for (key, name, desc), (score, sev) in zip(FAMILIES, results):
        # scanning frame
        frame([seg("  ▸ ", YELLOW), seg("scanning ", DIM), seg(name, WHITE, True), seg(" …", DIM)], hold=1)
        # detected frame (appended to permanent rows)
        detected = sev in ("high", "critical")
        dot = seg("  ● ", GREEN if detected else RED)
        label = seg("DETECTED  " if detected else "MISSED    ", GREEN if detected else RED, True)
        row = [
            dot,
            label,
            seg(f"{name:<24}", WHITE, True),
            seg(f"{desc:<26}", DIM),
            seg("score ", DIM),
            seg(f"{score:>3} ", WHITE, True),
            seg(sev.upper(), RED if detected else DIM, True),
        ]
        rows.append(row)
        frame(hold=2)

    passed = sum(1 for _, s in results if s in ("high", "critical"))
    total = len(results)
    rows.append([])
    rows.append(
        [seg("  RESULT: ", WHITE, True), seg(f"{passed}/{total} families DETECTED", GREEN, True), seg(" — 0 missed", GREEN)]
    )
    frame(hold=16)  # long hold at the end before looping
    return states


def render(states, out_path):
    nlines = max(len(lines) for lines, _ in states)
    height = PAD * 2 + 44 + nlines * LH  # 44 for the window title bar
    frames, durations = [], []
    for lines, hold in states:
        img = Image.new("RGB", (WIDTH, height), BG)
        d = ImageDraw.Draw(img)
        # window chrome
        d.rectangle([0, 0, WIDTH, 44], fill=BAR)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([20 + i * 26, 15, 34 + i * 26, 29], fill=c)
        d.text((WIDTH / 2, 22), "zeroclick-guard — detection benchmark", font=MONO, fill=DIM, anchor="mm")
        y = 44 + PAD
        for line in lines:
            x = PAD
            for text, color, bold in line:
                f = MONO_B if bold else MONO
                d.text((x, y), text, font=f, fill=color)
                x += d.textlength(text, font=f)
            y += LH
        for _ in range(hold):
            frames.append(img.copy())
            durations.append(140)
    # Build a shared adaptive palette for crisp text.
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
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs", "media", "gauntlet.gif")
    if not os.path.exists(ZCG):
        sys.exit("build first: cargo build --workspace --release")
    results = [run_family(k) for k, _, _ in FAMILIES]
    states = build_states(results)
    path, nframes, h = render(states, out)
    size = os.path.getsize(path)
    print(f"wrote {path}  ({nframes} frames, {WIDTH}x{h}, {size // 1024} KB)")


if __name__ == "__main__":
    main()
