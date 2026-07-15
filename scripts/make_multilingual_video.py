#!/usr/bin/env python3
"""Animated 1080x1080 explainer of the multilingual finding, as MP4.

Story beats (a gradual reveal):
  1. Bars grow to raw recall — the detector looks perfect in every language.
  2. "Strip the URL placeholder" prompt.
  3. Bars morph to artifact-controlled recall: Latin-script survives (green),
     every non-Latin script collapses (red), with a dashed ghost marking where
     each bar used to be.
  4. Payoff line + end card.

Uses matplotlib + the pip-installed static ffmpeg (imageio-ffmpeg), so no system
ffmpeg is required.

    python scripts/make_multilingual_video.py  ->  ~/Documents/lurebench-social/multilingual.mp4
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

# Palette (LureBench light surface)
BG = "#fbfbf9"
INK = "#14171c"
INK2 = "#52514e"
MUTED = "#8a8a84"
GRID = "#e6e5df"
BLUE = "#2a78d6"
GREEN = "#1baf7a"
RED = "#e34948"

LABELS = ["English", "Spanish", "French", "German", "Italian", "Portuguese",
          "Chinese", "Russian", "Arabic"]
RAW = [0.97, 1.00, 1.00, 1.00, 1.00, 0.93, 1.00, 0.94, 0.98]
CTRL = [0.97, 1.00, 0.96, 1.00, 0.91, 0.79, 0.09, 0.06, 0.04]
IS_LATIN = [True] * 6 + [False] * 3
N = len(LABELS)

FPS = 24
# Timeline (seconds)
T_TITLE = 1.0
T_GROW = (1.0, 3.6)
T_HOLD1 = (3.6, 5.0)
T_STRIP = (5.0, 6.2)
T_COLLAPSE = (6.2, 8.8)
T_HOLD2 = (8.8, 11.2)
T_END = (11.2, 13.2)
DURATION = T_END[1]
FRAMES = int(DURATION * FPS)


def ease(x: float) -> float:
    x = max(0.0, min(1.0, x))
    return x * x * (3 - 2 * x)  # smoothstep


def seg(t, a, b):
    return ease((t - a) / (b - a)) if b > a else 0.0


def lerp(a, b, x):
    return a + (b - a) * x


def hex_lerp(c1, c2, x):
    c1 = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    c2 = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{int(lerp(a, b, x)):02x}" for a, b in zip(c1, c2))


fig = plt.figure(figsize=(9, 9), dpi=120)
fig.patch.set_facecolor(BG)
ax = fig.add_axes([0.06, 0.135, 0.88, 0.62])  # leave room for title above and URL below
ax.set_facecolor(BG)

x = list(range(N))
bw = 0.62


def draw(frame):
    t = frame / FPS
    ax.clear()
    ax.set_facecolor(BG)
    ax.set_xlim(-0.6, N - 0.4)
    ax.set_ylim(0, 1.12)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])

    # gridlines
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color="#cfcec6", lw=1.5, zorder=1)

    grow = seg(t, *T_GROW)
    collapse = seg(t, *T_COLLAPSE)

    # bar heights: grow to RAW, then morph RAW->CTRL during collapse
    heights = []
    for i in range(N):
        h_raw = RAW[i] * grow
        h = lerp(h_raw, CTRL[i], collapse) if t >= T_COLLAPSE[0] else h_raw
        heights.append(h)

    # colors: blue until collapse, then blue->(green/red)
    for i in range(N):
        final = GREEN if CTRL[i] >= 0.5 else RED
        color = hex_lerp(BLUE, final, collapse) if t >= T_COLLAPSE[0] else BLUE
        # ghost of raw height for bars that dropped
        if collapse > 0.05 and RAW[i] - CTRL[i] > 0.15:
            ax.add_patch(plt.Rectangle((i - bw / 2, 0), bw, RAW[i], fill=False,
                                       ec=MUTED, ls=(0, (3, 3)), lw=1.1,
                                       alpha=0.55 * collapse, zorder=2))
        ax.bar(i, heights[i], width=bw, color=color, zorder=3)
        if grow > 0.6:
            ax.text(i, heights[i] + 0.02, f"{heights[i]:.2f}", ha="center",
                    va="bottom", fontsize=11, color=INK2, fontweight="bold")
        # language label
        ax.text(i, -0.055, LABELS[i], ha="center", va="top", fontsize=10.5,
                color=INK, rotation=0)

    # divider + group labels (appear during/after collapse)
    ga = min(1.0, max(0.0, (t - T_COLLAPSE[0]) / 1.2))
    if ga > 0:
        ax.axvline(5.5, color=MUTED, ls=(0, (3, 3)), lw=1.2, alpha=0.8 * ga, ymax=0.9)
        ax.text(2.75, 1.06, "LATIN SCRIPT — survives", ha="center", fontsize=11.5,
                color=GREEN, fontweight="bold", alpha=ga)
        ax.text(7.0, 1.06, "NON-LATIN — collapses", ha="center", fontsize=11.5,
                color=RED, fontweight="bold", alpha=ga)

    # --- title + caption (figure coords) ---
    fig.texts.clear()
    ta = min(1.0, t / T_TITLE)
    fig.text(0.06, 0.93, "Does a fraud detector work in every language?",
             fontsize=20, fontweight="bold", color=INK, alpha=ta)

    if t < T_HOLD1[1]:
        cap = "An English-trained detector, tested in 8 languages. Recall looks perfect everywhere."
        cc = INK2
    elif t < T_COLLAPSE[0]:
        cap = "Now strip the defang placeholder  <<link>>  from every lure and re-score →"
        cc = INK
    elif t < T_HOLD2[1]:
        cap = "It was never reading the fraud. It was reading the URL that got replaced."
        cc = INK
    else:
        cap = "LureBench reports recall raw vs artifact-controlled by default."
        cc = INK2
    fig.text(0.06, 0.885, cap, fontsize=13.5, color=cc)

    # end card
    ea = seg(t, *T_END)
    if ea > 0:
        fig.text(0.5, 0.028, "github.com/immu4989/lurebench   ·   live demo on Hugging Face",
                 ha="center", fontsize=12.5, color=MUTED, alpha=ea, fontweight="bold")

    return []


def main() -> None:
    out_dir = os.path.expanduser("~/Documents/lurebench-social")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "multilingual.mp4")
    anim = FuncAnimation(fig, draw, frames=FRAMES, interval=1000 / FPS, blit=False)
    writer = FFMpegWriter(fps=FPS, bitrate=4000,
                          extra_args=["-pix_fmt", "yuv420p"])  # yuv420p = broad compatibility
    anim.save(out, writer=writer, dpi=120,
              savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out) / 1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")


if __name__ == "__main__":
    main()
