#!/usr/bin/env python3
"""Dark chart: artifact-controlled recall, tfidf-logreg vs llm-judge, per language.

The honest picture: under artifact control (placeholder stripped), the token-based
detector craters on any non-Latin script while the LLM holds — because one reads tokens
and the other reads meaning. On Latin scripts they are comparable (the LLM is a touch
lower: it misses subtle lures instead of riding cognates). Shows all nine languages with
a divider at the Latin / non-Latin boundary.

    python scripts/make_llm_comparison_chart.py
      -> docs/assets/llm-multilingual.svg  and  ~/Documents/lurebench-social/llm-multilingual.png
"""

from __future__ import annotations

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

BG = "#0a1628"
INK = "#ffffff"
MUT = "#94a3b8"
DIM = "#64748b"
GRID = "#1e293b"
AXIS = "#334155"
AMBER = "#e0a83a"
CYAN = "#22d3ee"
plt.rcParams["font.family"] = "DejaVu Sans"

LABELS = ["EN", "ES", "FR", "DE", "IT", "PT", "ZH", "RU", "AR"]
TFIDF = [0.97, 1.00, 0.96, 1.00, 0.91, 0.79, 0.09, 0.06, 0.04]
LLM = [0.68, 0.80, 0.96, 0.96, 0.72, 0.70, 0.91, 0.97, 0.95]
SPLIT = 6  # first 6 are Latin


def main():
    n = len(LABELS)
    fig = plt.figure(figsize=(11, 6.2), dpi=110)
    fig.patch.set_facecolor(BG)
    ax = fig.add_axes([0.06, 0.12, 0.90, 0.60])
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, n - 0.4)
    ax.set_ylim(0, 1.22)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color=AXIS, lw=1.5)

    bw = 0.34
    for i in range(n):
        for j, (vals, col) in enumerate([(TFIDF, AMBER), (LLM, CYAN)]):
            x = i + (j - 0.5) * bw
            ax.bar(x, vals[i], width=bw, color=col, zorder=3)
            ax.text(x, vals[i] + 0.02, f"{vals[i]*100:.0f}", ha="center", va="bottom",
                    fontsize=9.5, color="#cbd5e1", fontweight="bold")
        ax.text(i, -0.06, LABELS[i], ha="center", va="top", fontsize=12, color=MUT)

    # divider + group labels
    dx = SPLIT - 0.5
    ax.axvline(dx, color=DIM, ls=(0, (3, 3)), lw=1.2, ymax=0.9)
    ax.text((SPLIT - 1) / 2, 1.16, "LATIN SCRIPT", ha="center", fontsize=12,
            color=MUT, fontweight="bold")
    ax.text(SPLIT + (n - SPLIT - 1) / 2, 1.16, "NON-LATIN — tfidf collapses",
            ha="center", fontsize=12, color="#f87171", fontweight="bold")

    # title + legend + accent
    fig.patches.append(plt.Rectangle((0.06, 0.925), 0.05, 0.012, transform=fig.transFigure,
                       color=CYAN))
    fig.text(0.06, 0.88, "Reading tokens vs reading meaning", fontsize=22, color=INK,
             fontweight="bold")
    fig.text(0.06, 0.835, "Artifact-controlled recall (defang placeholder stripped): only "
             "the LLM survives a change of script", fontsize=13, color=MUT)
    for k, (name, col) in enumerate([("tfidf-logreg", AMBER), ("llm-judge (LLM)", CYAN)]):
        lx = 0.62 + k * 0.19
        fig.patches.append(plt.Rectangle((lx, 0.925), 0.02, 0.014, transform=fig.transFigure,
                           color=col))
        fig.text(lx + 0.025, 0.923, name, fontsize=12.5, color=MUT)

    os.makedirs("docs/assets", exist_ok=True)
    fig.savefig("docs/assets/llm-multilingual.svg", facecolor=BG)
    social = os.path.expanduser("~/Documents/lurebench-social")
    os.makedirs(social, exist_ok=True)
    fig.savefig(os.path.join(social, "llm-multilingual.png"), facecolor=BG)
    print("wrote docs/assets/llm-multilingual.svg and ~/Documents/lurebench-social/llm-multilingual.png")


if __name__ == "__main__":
    main()
