#!/usr/bin/env python3
"""Short (~17s) dark video of the llm-judge finding, as MP4.

Beats: the token detector 'read' non-Latin fraud but was reading the URL placeholder ->
give it a detector that reads meaning -> the LLM holds where tfidf collapsed -> and it
shrugs off the attacks that broke the keyword detector -> one real weakness, paraphrase.

Uses matplotlib + pip-installed static ffmpeg (imageio-ffmpeg); no system ffmpeg.

    python scripts/make_llm_video.py  ->  ~/Documents/lurebench-social/llm-story.mp4
"""

from __future__ import annotations

import os

import imageio_ffmpeg
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.animation import FFMpegWriter, FuncAnimation  # noqa: E402

plt.rcParams["animation.ffmpeg_path"] = imageio_ffmpeg.get_ffmpeg_exe()
plt.rcParams["font.family"] = "DejaVu Sans"

BG = "#0a1628"
INK = "#ffffff"
MUT = "#94a3b8"
DIM = "#64748b"
GRID = "#1e293b"
AXIS = "#334155"
RED = "#ef4444"
AMBER = "#e0a83a"
CYAN = "#22d3ee"

FPS = 24
FADE = 0.3
SCENES = [("hook", 4.0), ("reveal", 7.0), ("rob", 3.8), ("close", 3.2)]
_starts, _acc = {}, 0.0
for _n, _d in SCENES:
    _starts[_n] = (_acc, _acc + _d)
    _acc += _d
DURATION = _acc
FRAMES = int(DURATION * FPS)


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def ease(x):
    x = clamp(x)
    return x * x * (3 - 2 * x)


def seg(t, a, b):
    return ease((t - a) / (b - a)) if b > a else 0.0


fig = plt.figure(figsize=(9, 9), dpi=120)
fig.patch.set_facecolor(BG)
ax = fig.add_axes([0.09, 0.13, 0.84, 0.56])

NL = ["Chinese", "Russian", "Arabic"]
TFIDF = [0.09, 0.06, 0.04]
LLM = [0.91, 0.97, 0.95]


def Tx(x, y, s, size, color, A, weight="normal", ha="center", style="normal"):
    if A > 0.01:
        fig.text(x, y, s, fontsize=size, color=color, alpha=clamp(A), ha=ha,
                 fontweight=weight, fontstyle=style)


def accent(A):
    if A > 0.01:
        fig.patches.append(plt.Rectangle((0.09, 0.935), 0.05, 0.011,
                           transform=fig.transFigure, color=CYAN, alpha=clamp(A)))


def axes_grid(xmax):
    ax.clear()
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, xmax)
    ax.set_ylim(0, 1.16)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color=AXIS, lw=1.5)


def scene_hook(t, A):
    ax.set_visible(True)
    axes_grid(2.6)
    entrance = ease(t / 0.8)
    for i in range(3):
        h = TFIDF[i] * entrance
        ax.bar(i, h, width=0.5, color=RED, alpha=A, zorder=3)
        ax.text(i, h + 0.02, f"{TFIDF[i]*100:.0f}%", ha="center", va="bottom",
                fontsize=12, color="#cbd5e1", fontweight="bold", alpha=A)
        ax.text(i, -0.06, NL[i], ha="center", va="top", fontsize=13, color=MUT, alpha=A)
    accent(A)
    Tx(0.09, 0.90, "My detector 'caught' fraud in every language.", 20, INK, A,
       weight="bold", ha="left")
    if t < 2.0:
        Tx(0.09, 0.855, "Chinese, Russian, Arabic. 90%+ recall.", 14, MUT, A, ha="left")
    else:
        Tx(0.09, 0.855, "Strip the redacted URL and it detects almost nothing.",
           14, "#f87171", A, ha="left")
    Tx(0.5, 0.045, "It was reading the placeholder, not the fraud.", 15, DIM, A,
       style="italic")


def scene_reveal(t, A):
    ax.set_visible(True)
    axes_grid(2.6)
    grow = seg(t, 1.2, 4.2)
    bw = 0.34
    for i in range(3):
        # tfidf stub (static red)
        ax.bar(i - bw / 2, TFIDF[i], width=bw, color=RED, alpha=A, zorder=3)
        # llm-judge grows and holds (cyan)
        h = LLM[i] * grow
        ax.bar(i + bw / 2, h, width=bw, color=CYAN, alpha=A, zorder=3)
        if grow > 0.5:
            ax.text(i + bw / 2, h + 0.02, f"{LLM[i]*100:.0f}%", ha="center", va="bottom",
                    fontsize=12, color="#a5f3fc", fontweight="bold", alpha=A)
        ax.text(i, -0.06, NL[i], ha="center", va="top", fontsize=13, color=MUT, alpha=A)
    accent(A)
    Tx(0.09, 0.90, "So I used a detector that reads meaning.", 20, INK, A,
       weight="bold", ha="left")
    Tx(0.09, 0.855, "An LLM reads the fraud in the language itself. It holds where the "
       "token model collapsed.", 13, MUT, A, ha="left")
    # legend
    lx = 0.5
    ax.text(1.0, 1.08, "tfidf (reads tokens)", color=RED, fontsize=11.5,
            fontweight="bold", ha="right", alpha=A, transform=ax.transData)
    ax.text(1.1, 1.08, "llm-judge (reads meaning)", color=CYAN, fontsize=11.5,
            fontweight="bold", ha="left", alpha=A, transform=ax.transData)
    _ = lx


def scene_rob(t, A):
    ax.set_visible(True)
    axes_grid(1.6)
    grow = ease(t / 1.2)
    vals = [("keyword\ndetector", 1.00, RED), ("llm-judge", 0.08, CYAN)]
    for i, (lab, v, col) in enumerate(vals):
        h = v * grow
        ax.bar(i, h, width=0.5, color=col, alpha=A, zorder=3)
        ax.text(i, h + 0.02, f"{v*100:.0f}%", ha="center", va="bottom", fontsize=13,
                color="#cbd5e1", fontweight="bold", alpha=A)
        ax.text(i, -0.07, lab, ha="center", va="top", fontsize=13, color=MUT, alpha=A)
    accent(A)
    Tx(0.09, 0.90, "The homoglyph attack that broke the keyword detector?", 18, INK, A,
       weight="bold", ha="left")
    Tx(0.09, 0.855, "Attack success rate. The LLM reads through 'vеrify' like you do.",
       14, MUT, A, ha="left")


def scene_close(t, A):
    ax.set_visible(False)
    accent(A)
    Tx(0.5, 0.66, "Reads meaning. Survives the tricks.", 26, INK, A, weight="bold")
    Tx(0.5, 0.57, "One real weakness: a semantic paraphrase.", 18, MUT,
       A * seg(t, 0.6, 1.4))
    Tx(0.5, 0.40, "github.com/immu4989/lurebench", 17, CYAN, A * seg(t, 1.2, 2.0),
       weight="bold")


DISPATCH = {"hook": scene_hook, "reveal": scene_reveal, "rob": scene_rob, "close": scene_close}


def draw(frame):
    t = frame / FPS
    fig.texts.clear()
    fig.patches.clear()
    for extra in list(fig.axes):
        if extra is not ax:
            extra.remove()
    ax.clear()
    ax.set_axis_off()
    name = SCENES[-1][0]
    for nm, _d in SCENES:
        s, e = _starts[nm]
        if s <= t < e:
            name = nm
            break
    s, e = _starts[name]
    A = min(ease((t - s) / FADE), ease((e - t) / FADE))
    DISPATCH[name](t - s, clamp(A))
    return []


def main():
    out_dir = os.path.expanduser("~/Documents/lurebench-social")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "llm-story.mp4")
    anim = FuncAnimation(fig, draw, frames=FRAMES, interval=1000 / FPS, blit=False)
    writer = FFMpegWriter(fps=FPS, bitrate=4500, extra_args=["-pix_fmt", "yuv420p"])
    anim.save(out, writer=writer, dpi=120, savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out)/1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")


if __name__ == "__main__":
    main()
