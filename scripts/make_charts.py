#!/usr/bin/env python3
"""Generate the README result charts as static SVG (light 'card' surface, works in
GitHub light/dark). Grouped bars per the data-viz spec: thin bars, 4px top-rounded
data-ends, 2px surface gap, direct value labels, recessive grid, ink text.

    python scripts/make_charts.py   ->  docs/assets/{provenance,detection}.svg
"""

from __future__ import annotations

from pathlib import Path

# Validated categorical palette (light surface), CVD-safe. aqua gets direct labels.
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASE = "#c3c2b7"
BLUE = "#2a78d6"
AQUA = "#1baf7a"

W, H = 720, 410
L, R, T, B = 62, 24, 96, 56  # margins (top leaves room for title + subtitle + legend row)
X0, X1 = L, W - R
Y0, Y1 = T, H - B
PLOTH = Y1 - Y0


def _bar_path(x, y, w, h, r=4):
    r = min(r, w / 2, h)
    return (f"M{x:.1f},{y + h:.1f} L{x:.1f},{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
            f"L{x + w - r:.1f},{y:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} "
            f"L{x + w:.1f},{y + h:.1f} Z")


def grouped_bar(title, subtitle, categories, series, fmt=lambda v: f"{v * 100:.0f}%"):
    """series: list of (name, color, [values 0..1 per category])."""
    p = []
    p.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
             f'font-family="system-ui,-apple-system,Segoe UI,sans-serif">')
    p.append(f'<rect x="0" y="0" width="{W}" height="{H}" rx="12" fill="{SURFACE}"/>')
    p.append(f'<text x="{L}" y="32" font-size="19" font-weight="700" fill="{INK}">{title}</text>')
    if subtitle:
        p.append(f'<text x="{L}" y="54" font-size="13" fill="{INK2}">{subtitle}</text>')

    # legend on its own row (right-aligned, below the subtitle)
    ly = 78
    lx = X1
    for name, color, _ in reversed(series):
        tw = 8 + len(name) * 7.4
        lx -= tw + 20
        p.append(f'<rect x="{lx:.0f}" y="{ly - 10}" width="11" height="11" rx="3" fill="{color}"/>')
        p.append(f'<text x="{lx + 16:.0f}" y="{ly}" font-size="13" fill="{INK2}">{name}</text>')

    # y gridlines 0..100%
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        y = Y1 - t * PLOTH
        p.append(f'<line x1="{X0}" y1="{y:.1f}" x2="{X1}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
        p.append(f'<text x="{X0 - 8}" y="{y + 4:.1f}" font-size="11" fill="{MUTED}" '
                 f'text-anchor="end" font-variant-numeric="tabular-nums">{t * 100:.0f}</text>')
    p.append(f'<line x1="{X0}" y1="{Y1}" x2="{X1}" y2="{Y1}" stroke="{BASE}" stroke-width="1.5"/>')

    n = len(categories)
    s = len(series)
    gw = (X1 - X0) / n
    bw = min(46, gw * 0.62 / s)
    gap = 2
    cluster = bw * s + gap * (s - 1)
    for ci, cat in enumerate(categories):
        cx = X0 + gw * (ci + 0.5)
        start = cx - cluster / 2
        for si, (name, color, vals) in enumerate(series):
            v = vals[ci]
            bx = start + si * (bw + gap)
            bh = v * PLOTH
            by = Y1 - bh
            p.append(f'<path d="{_bar_path(bx, by, bw, bh)}" fill="{color}"/>')
            p.append(f'<text x="{bx + bw / 2:.1f}" y="{by - 6:.1f}" font-size="12" font-weight="600" '
                     f'fill="{INK2}" text-anchor="middle" font-variant-numeric="tabular-nums">{fmt(v)}</text>')
        p.append(f'<text x="{cx:.1f}" y="{Y1 + 20:.1f}" font-size="13" fill="{INK}" '
                 f'text-anchor="middle">{cat}</text>')
    p.append("</svg>")
    return "\n".join(p)


def main() -> None:
    out = Path("docs/assets")
    out.mkdir(parents=True, exist_ok=True)

    # 1) The confound and its removal — cross-generator provenance recall
    prov = grouped_bar(
        "Remove the confound, and AI-fraud detection collapses",
        "Cross-generator recall: train on one generator, test on a held-out one",
        ["Naive corpus", "Distribution-matched"],
        [
            ("DeepSeek", BLUE, [0.98, 0.32]),
            ("Mistral", AQUA, [1.00, 0.56]),
        ],
    )
    (out / "provenance.svg").write_text(prov, encoding="utf-8")

    # 2) Detection by typology — keyword heuristic vs trained baseline
    det = grouped_bar(
        "Detection rate by fraud typology",
        "A keyword heuristic fails on AI lures; a trained baseline sets the real bar",
        ["Phishing", "BEC", "Romance", "Pig-butchering"],
        [
            ("heuristic-v0", BLUE, [0.199, 0.826, 0.148, 0.091]),
            ("tfidf-logreg", AQUA, [0.963, 0.957, 1.000, 0.955]),
        ],
    )
    (out / "detection.svg").write_text(det, encoding="utf-8")
    print("wrote docs/assets/provenance.svg and docs/assets/detection.svg")


if __name__ == "__main__":
    main()
