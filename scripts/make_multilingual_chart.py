#!/usr/bin/env python3
"""Generate the multilingual script-line-split chart as static SVG.

The story: an English-trained TF-IDF fraud detector posts ~1.00 raw recall in every
language, but once the defang placeholder is stripped, recall splits cleanly along
script lines — Latin-script survives, every non-Latin script collapses. The chart shows
raw recall (neutral) next to artifact-controlled recall (green if it survives, red if it
collapses), with a divider marking the Latin / non-Latin boundary.

    python scripts/make_multilingual_chart.py  ->  docs/assets/multilingual.svg
"""

from __future__ import annotations

from pathlib import Path

# Reuse the validated palette from the main chart script.
from make_charts import BASE, GRID, INK, INK2, MUTED, SURFACE, _bar_path

GREEN = "#1baf7a"
RED = "#e34948"

W, H = 900, 470
L, R, T, B = 62, 24, 132, 64
X0, X1 = L, W - R
Y0, Y1 = T, H - B
PLOTH = Y1 - Y0

# (label, script_group, raw, controlled). Latin group first, then non-Latin.
DATA = [
    ("English", "latin", 0.97, 0.97),
    ("Spanish", "latin", 1.00, 1.00),
    ("French", "latin", 1.00, 0.96),
    ("German", "latin", 1.00, 1.00),
    ("Italian", "latin", 1.00, 0.91),
    ("Portuguese", "latin", 0.93, 0.79),
    ("Chinese", "nonlatin", 1.00, 0.09),
    ("Russian", "nonlatin", 0.94, 0.06),
    ("Arabic", "nonlatin", 0.98, 0.04),
]


def build() -> str:
    n = len(DATA)
    gw = (X1 - X0) / n
    bw = min(30, gw * 0.60 / 2)
    gap = 3
    cluster = bw * 2 + gap

    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
         f'font-family="system-ui,-apple-system,Segoe UI,sans-serif">',
         f'<rect x="0" y="0" width="{W}" height="{H}" rx="12" fill="{SURFACE}"/>',
         f'<text x="{L}" y="34" font-size="20" font-weight="700" fill="{INK}">'
         f'Strip the placeholder, and &#8220;multilingual&#8221; detection splits by script</text>',
         f'<text x="{L}" y="57" font-size="13.5" fill="{INK2}">'
         f'English-trained TF-IDF fraud detector: recall raw vs artifact-controlled '
         f'(defang placeholder removed)</text>']

    # legend (own row, above the group labels)
    ly = 82
    for i, (name, col, wdt) in enumerate([("raw recall", BASE, 150),
                                          ("artifact-controlled — survives", GREEN, 250),
                                          ("collapses", RED, 0)]):
        lx = L + (0 if i == 0 else (150 if i == 1 else 400))
        p.append(f'<rect x="{lx}" y="{ly - 10}" width="11" height="11" rx="3" fill="{col}"/>')
        p.append(f'<text x="{lx + 16}" y="{ly}" font-size="12.5" fill="{INK2}">{name}</text>')

    # y gridlines
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        y = Y1 - t * PLOTH
        p.append(f'<line x1="{X0}" y1="{y:.1f}" x2="{X1}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
        p.append(f'<text x="{X0 - 8}" y="{y + 4:.1f}" font-size="11" fill="{MUTED}" '
                 f'text-anchor="end" font-variant-numeric="tabular-nums">{t * 100:.0f}</text>')
    p.append(f'<line x1="{X0}" y1="{Y1}" x2="{X1}" y2="{Y1}" stroke="{BASE}" stroke-width="1.5"/>')

    # divider between Latin (6) and non-Latin (3)
    split_i = sum(1 for d in DATA if d[1] == "latin")
    div_x = X0 + gw * split_i
    p.append(f'<line x1="{div_x:.1f}" y1="{Y0 - 6}" x2="{div_x:.1f}" y2="{Y1}" '
             f'stroke="{MUTED}" stroke-width="1.2" stroke-dasharray="4 4"/>')
    lat_cx = X0 + gw * split_i / 2
    non_cx = X0 + gw * split_i + gw * (n - split_i) / 2
    gly = 108  # group-label row, between the legend and the plot
    p.append(f'<text x="{lat_cx:.0f}" y="{gly}" font-size="12.5" font-weight="700" '
             f'fill="{GREEN}" text-anchor="middle">LATIN SCRIPT — survives</text>')
    p.append(f'<text x="{non_cx:.0f}" y="{gly}" font-size="12.5" font-weight="700" '
             f'fill="{RED}" text-anchor="middle">NON-LATIN SCRIPT — collapses</text>')

    for ci, (name, group, raw, ctrl) in enumerate(DATA):
        cx = X0 + gw * (ci + 0.5)
        start = cx - cluster / 2
        ctrl_color = GREEN if ctrl >= 0.5 else RED
        for si, (val, color) in enumerate([(raw, BASE), (ctrl, ctrl_color)]):
            bx = start + si * (bw + gap)
            bh = val * PLOTH
            by = Y1 - bh
            p.append(f'<path d="{_bar_path(bx, by, bw, max(bh, 1))}" fill="{color}"/>')
            p.append(f'<text x="{bx + bw / 2:.1f}" y="{by - 5:.1f}" font-size="10.5" '
                     f'font-weight="600" fill="{INK2}" text-anchor="middle" '
                     f'font-variant-numeric="tabular-nums">{val:.2f}</text>')
        p.append(f'<text x="{cx:.1f}" y="{Y1 + 20:.1f}" font-size="11.5" fill="{INK}" '
                 f'text-anchor="middle">{name}</text>')

    p.append("</svg>")
    return "\n".join(p)


def main() -> None:
    out = Path("docs/assets")
    out.mkdir(parents=True, exist_ok=True)
    (out / "multilingual.svg").write_text(build(), encoding="utf-8")
    print("wrote docs/assets/multilingual.svg")


if __name__ == "__main__":
    main()
