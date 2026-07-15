#!/usr/bin/env python3
"""Dark-palette story video (1080x1080 MP4) — cold-open on the anomaly.

Opens on a curious graph (three languages crashed — why?), promises a pattern, then
walks the three findings, each "looks perfect -> honest check -> collapse", closing on
the LureScope demo. Dark navy palette so the green/red data pops in a feed.

Uses matplotlib + pip-installed static ffmpeg (imageio-ffmpeg); no system ffmpeg.

    python scripts/make_story_video_dark.py  ->  ~/Documents/lurebench-social/lurebench-story.mp4
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

# Dark palette
BG = "#0a1628"
INK = "#ffffff"
MUT = "#94a3b8"
DIM = "#64748b"
GRID = "#1e293b"
AXIS = "#334155"
CYAN = "#06b6d4"
BLUE = "#3b82f6"
GREEN = "#22c55e"
RED = "#ef4444"
AMBER = "#e0a83a"

FPS = 24
FADE = 0.3
DEMO_IMG = os.path.expanduser("~/Documents/lurebench-social/3-lurescope-demo.png")

SCENES = [("hook", 5.0), ("prov", 8.0), ("rob", 8.0), ("lang", 9.0), ("close", 6.2)]
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


def lerp(a, b, x):
    return a + (b - a) * x


def hexlerp(c1, c2, x):
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{int(lerp(p, q, x)):02x}" for p, q in zip(a, b))


fig = plt.figure(figsize=(9, 9), dpi=120)
fig.patch.set_facecolor(BG)
ax = fig.add_axes([0.07, 0.13, 0.86, 0.60])

_demo = plt.imread(DEMO_IMG) if os.path.exists(DEMO_IMG) else None


def Tx(x, y, s, size, color, A, weight="normal", ha="center", style="normal"):
    if A > 0.01:
        fig.text(x, y, s, fontsize=size, color=color, alpha=clamp(A), ha=ha,
                 fontweight=weight, fontstyle=style)


def accent(A):
    if A > 0.01:
        fig.patches.append(plt.Rectangle((0.07, 0.935), 0.05, 0.011,
                           transform=fig.transFigure, color=CYAN, alpha=clamp(A)))


def head(title_parts, cap, A, capcolor=MUT):
    """title_parts: list of (text, color). Rendered left-aligned, concatenated."""
    accent(A)
    x = 0.07
    for txt, col in title_parts:
        Tx(x, 0.90, txt, 22, col, A, weight="bold", ha="left")
        x += 0.0135 * len(txt) + 0.012
    if cap:
        Tx(0.07, 0.855, cap, 14, capcolor, A, ha="left")


def setup_axes(xmax=8.6, ymax=1.16):
    ax.clear()
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, xmax)
    ax.set_ylim(0, ymax)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color=AXIS, lw=1.5)


def bars(labels, heights, colors, ghosts=None, fmt="{:.0%}", A=1.0, dy=-0.06, lab_size=11):
    for i in range(len(labels)):
        if ghosts and ghosts[i] is not None:
            ax.add_patch(plt.Rectangle((i - 0.31, 0), 0.62, ghosts[i], fill=False,
                                       ec=DIM, ls=(0, (3, 3)), lw=1.2, alpha=0.7 * A))
        ax.bar(i, heights[i], width=0.62, color=colors[i], alpha=A, zorder=3)
        if heights[i] > 0.035:
            ax.text(i, heights[i] + 0.02, fmt.format(heights[i]), ha="center", va="bottom",
                    fontsize=12, color="#cbd5e1", fontweight="bold", alpha=A)
        ax.text(i, dy, labels[i], ha="center", va="top", fontsize=lab_size, color=MUT, alpha=A)


LANGS = ["EN", "ES", "FR", "DE", "IT", "PT", "ZH", "RU", "AR"]
RAW = [0.97, 1.00, 1.00, 1.00, 1.00, 0.93, 1.00, 0.94, 0.98]
CTRL = [0.97, 1.00, 0.96, 1.00, 0.91, 0.79, 0.09, 0.06, 0.04]


# ---------------------------------------------------------------- scenes
def scene_hook(t, A):
    # Cold open on the anomaly, then a one-line promise.
    graphA = A * (1.0 if t < 3.1 else clamp((3.6 - t) / 0.5))
    if graphA > 0.01:
        ax.set_visible(True)
        setup_axes()
        entrance = ease(t / 0.8)
        colors = [GREEN if CTRL[i] >= 0.5 else RED for i in range(9)]
        ghosts = [RAW[i] if RAW[i] - CTRL[i] > 0.15 else None for i in range(9)]
        heights = [CTRL[i] * entrance for i in range(9)]
        bars(LANGS, heights, colors, ghosts, A=graphA)
        accent(graphA)
        Tx(0.07, 0.90, "Three languages just fell", 25, INK, graphA, weight="bold", ha="left")
        Tx(0.07, 0.855, "off a cliff.", 25, RED, graphA, weight="bold", ha="left")
        Tx(0.5, 0.045, "Same detector. Same test.  What happened?", 16, DIM, graphA,
           style="italic")
    else:
        ax.set_visible(False)
    if t >= 3.3:
        a = A * ease((t - 3.3) / 0.5)
        Tx(0.5, 0.56, "A perfect score has fooled me three times.", 24, INK, a, weight="bold")
        Tx(0.5, 0.47, "Here's the pattern.", 26, CYAN, a, weight="bold")


def scene_prov(t, A):
    ax.set_visible(True)
    setup_axes(xmax=2.6)
    labels = ["DeepSeek", "GLM", "Mistral"]
    naive, matched = [1.0, 1.0, 1.0], [0.58, 0.57, 0.84]
    drop = seg(t, 3.0, 5.8)
    heights = [lerp(naive[i] * seg(t, 0.4, 2.2), matched[i], drop) if t >= 3.0
               else naive[i] * seg(t, 0.4, 2.2) for i in range(3)]
    colors = [hexlerp(BLUE, RED if matched[i] < 0.65 else AMBER, drop) for i in range(3)]
    ghosts = [1.0 if drop > 0.05 else None for _ in range(3)]
    ca = seg(t, 3.0, 4.0)
    if ca > 0:
        ax.axhline(0.50, color=MUT, ls=(0, (5, 4)), lw=1.5, alpha=ca * A)
        ax.text(-0.55, 0.53, "chance 0.50", ha="left", fontsize=11.5, style="italic",
                color=MUT, alpha=ca * A)
    bars(labels, heights, colors, ghosts, fmt="{:.2f}", A=A)
    cap = ("Naive corpus: cross-generator AUC 1.00. Looks perfect." if t < 2.9
           else "Match the distributions, and it falls toward chance.")
    head([("Tell AI fraud from human fraud?", INK)], cap, A,
         capcolor=MUT if t < 2.9 else INK)


def scene_rob(t, A):
    ax.set_visible(True)
    setup_axes(xmax=1.6)
    labels = ["keyword\ndetector", "trained\nmodel"]
    kept = [0.01, 0.62]
    grow, drain = seg(t, 0.4, 2.2), seg(t, 3.0, 5.6)
    heights = [lerp(1.0 * grow, kept[i], drain) if t >= 3.0 else 1.0 * grow for i in range(2)]
    colors = [hexlerp(BLUE, RED if kept[i] < 0.3 else AMBER, drain) for i in range(2)]
    ghosts = [1.0 if drain > 0.05 else None for _ in range(2)]
    bars(labels, heights, colors, ghosts, fmt="{:.0%}", A=A, dy=-0.08)
    cap = ("Start from every lure they catch on clean text." if t < 2.9
           else "One homoglyph, and 99% of the keyword catches evade.")
    head([("Do these detectors survive an attacker?", INK)], cap, A,
         capcolor=MUT if t < 2.9 else INK)


def scene_lang(t, A):
    ax.set_visible(True)
    setup_axes()
    grow, collapse = seg(t, 0.4, 2.4), seg(t, 3.2, 6.2)
    heights, colors, ghosts = [], [], []
    for i in range(9):
        h = lerp(RAW[i] * grow, CTRL[i], collapse) if t >= 3.2 else RAW[i] * grow
        heights.append(h)
        colors.append(hexlerp(BLUE, GREEN if CTRL[i] >= 0.5 else RED, collapse)
                      if t >= 3.2 else BLUE)
        ghosts.append(RAW[i] if (collapse > 0.05 and RAW[i] - CTRL[i] > 0.15) else None)
    ga = seg(t, 3.2, 4.4)
    if ga > 0:
        ax.axvline(5.5, color=DIM, ls=(0, (3, 3)), lw=1.2, alpha=0.8 * ga * A, ymax=0.9)
        Tx(0.30, 0.735, "LATIN — survives", 12.5, GREEN, ga * A, weight="bold")
        Tx(0.74, 0.735, "NON-LATIN — collapses", 12.5, RED, ga * A, weight="bold")
    bars(LANGS, heights, colors, ghosts, fmt="{:.2f}", A=A)
    cap = ("Perfect recall across 8 languages." if t < 3.0
           else "Strip the URL placeholder: it was reading the URL, not the fraud.")
    head([("Does it work in every language?", INK)], cap, A,
         capcolor=MUT if t < 3.0 else INK)


def scene_close(t, A):
    ax.set_visible(False)
    accent(A)
    Tx(0.5, 0.90, "The number looked great every time.", 24, INK, A, weight="bold")
    Tx(0.5, 0.845, "It was measuring an artifact every time.", 20, RED,
       A * seg(t, 0.5, 1.3), weight="bold")
    if _demo is not None and A * seg(t, 1.0, 2.0) > 0.01:
        iax = fig.add_axes([0.20, 0.25, 0.60, 0.50])
        iax.imshow(_demo, alpha=A * seg(t, 1.0, 2.0))
        iax.axis("off")
    Tx(0.5, 0.175, "LureBench reports raw vs artifact-controlled by default.",
       15, MUT, A * seg(t, 1.6, 2.4))
    Tx(0.5, 0.09, "github.com/immu4989/lurebench", 16, INK, A * seg(t, 2.0, 2.8),
       weight="bold")
    Tx(0.5, 0.05, "live demo: huggingface.co/spaces/immu4989/lurescope", 13, CYAN,
       A * seg(t, 2.2, 3.0))


DISPATCH = {"hook": scene_hook, "prov": scene_prov, "rob": scene_rob,
            "lang": scene_lang, "close": scene_close}


def draw(frame):
    t = frame / FPS
    fig.texts.clear()
    fig.patches.clear()  # remove per-frame accent rects; fig.patch background is separate
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
    out = os.path.join(out_dir, "lurebench-story.mp4")
    anim = FuncAnimation(fig, draw, frames=FRAMES, interval=1000 / FPS, blit=False)
    writer = FFMpegWriter(fps=FPS, bitrate=4500, extra_args=["-pix_fmt", "yuv420p"])
    anim.save(out, writer=writer, dpi=120, savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out) / 1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")


if __name__ == "__main__":
    main()
