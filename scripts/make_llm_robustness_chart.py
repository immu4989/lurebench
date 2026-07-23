#!/usr/bin/env python3
"""Dark chart: attack-success-rate by attack, heuristic vs tfidf vs llm-judge.

Higher bar = more brittle (more of the caught lures evade after the attack). The
character tricks that shatter the keyword detector (ASR ~1.00) barely touch the LLM; the
LLM's only real weakness is a semantic paraphrase.

    python scripts/make_llm_robustness_chart.py
      -> docs/assets/llm-robustness.svg  and  ~/Documents/lurebench-social/llm-robustness.png
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
RED = "#ef4444"
AMBER = "#e0a83a"
CYAN = "#22d3ee"
plt.rcParams["font.family"] = "DejaVu Sans"

ATTACKS = ["homoglyph", "leet", "zero-width", "whitespace", "paraphrase\n(LLM rewrite)"]
HEUR = [1.00, 1.00, 1.00, 0.78, None]
TFIDF = [0.47, 0.13, 0.00, 0.00, None]
LLM = [0.08, 0.04, 0.08, 0.04, 0.17]


def main():
    n = len(ATTACKS)
    fig = plt.figure(figsize=(11, 6.2), dpi=110)
    fig.patch.set_facecolor(BG)
    ax = fig.add_axes([0.06, 0.16, 0.90, 0.56])
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, n - 0.4)
    ax.set_ylim(0, 1.16)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color=AXIS, lw=1.5)

    series = [("heuristic-v0", HEUR, RED), ("tfidf-logreg", TFIDF, AMBER),
              ("llm-judge", LLM, CYAN)]
    bw = 0.26
    for i in range(n):
        for j, (_name, vals, col) in enumerate(series):
            if vals[i] is None:
                continue
            x = i + (j - 1) * bw
            ax.bar(x, vals[i], width=bw, color=col, zorder=3)
            ax.text(x, vals[i] + 0.02, f"{vals[i]*100:.0f}", ha="center", va="bottom",
                    fontsize=9.5, color="#cbd5e1", fontweight="bold")
        ax.text(i, -0.055, ATTACKS[i], ha="center", va="top", fontsize=11.5, color=MUT)

    fig.patches.append(plt.Rectangle((0.06, 0.935), 0.05, 0.012, transform=fig.transFigure,
                       color=CYAN))
    fig.text(0.06, 0.89, "Character tricks break keyword rules, not the LLM",
             fontsize=20, color=INK, fontweight="bold")
    fig.text(0.06, 0.845, "Attack success rate (higher = more brittle). The LLM's only real "
             "weakness is a semantic paraphrase.", fontsize=12.5, color=MUT)
    for k, (name, _v, col) in enumerate(series):
        lx = 0.06 + k * 0.16
        fig.patches.append(plt.Rectangle((lx, 0.792), 0.02, 0.014, transform=fig.transFigure,
                           color=col))
        fig.text(lx + 0.024, 0.79, name, fontsize=12, color=MUT)

    os.makedirs("docs/assets", exist_ok=True)
    fig.savefig("docs/assets/llm-robustness.svg", facecolor=BG)
    social = os.path.expanduser("~/Documents/lurebench-social")
    os.makedirs(social, exist_ok=True)
    fig.savefig(os.path.join(social, "llm-robustness.png"), facecolor=BG)
    print("wrote docs/assets/llm-robustness.svg and ~/Documents/lurebench-social/llm-robustness.png")


if __name__ == "__main__":
    main()
