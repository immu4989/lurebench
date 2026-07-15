#!/usr/bin/env python3
"""One 1080x1080 story video tying the three LureBench findings together, as MP4.

Spine: every result looked perfect, then the honest check made it collapse.

  Cold open  — "Perfect score. Perfect score. Perfect score. All three were lies."
  Act 1 prov — AI-vs-human fraud: AUC 1.00 -> drops toward the 0.50 chance line.
  Act 2 rob  — keyword detector catches fraud -> one homoglyph, 99% of catches evade.
  Act 3 lang — perfect recall in 8 languages -> strip the placeholder, non-Latin collapses.
  Close      — LureScope live demo + links.

Uses matplotlib + pip-installed static ffmpeg (imageio-ffmpeg); no system ffmpeg.

    python scripts/make_story_video.py  ->  ~/Documents/lurebench-social/lurebench-story.mp4
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

BG = "#fbfbf9"
INK = "#14171c"
INK2 = "#52514e"
MUTED = "#8a8a84"
GRID = "#e6e5df"
BLUE = "#2a78d6"
GREEN = "#1baf7a"
RED = "#e34948"
AMBER = "#d9a441"

FPS = 24
FADE = 0.3

DEMO_IMG = os.path.expanduser("~/Documents/lurebench-social/3-lurescope-demo.png")

# scene name -> duration (s)
SCENES = [
    ("hook", 5.0),
    ("prov", 8.5),
    ("rob", 8.5),
    ("lang", 9.5),
    ("close", 6.5),
]
_starts = {}
_acc = 0.0
for _name, _d in SCENES:
    _starts[_name] = (_acc, _acc + _d)
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

_demo = None
if os.path.exists(DEMO_IMG):
    _demo = plt.imread(DEMO_IMG)


def T(x, y, s, size, color, A, weight="normal", ha="center", style="normal"):
    if A <= 0.01:
        return
    fig.text(x, y, s, fontsize=size, color=color, alpha=clamp(A), ha=ha,
             fontweight=weight, fontstyle=style)


def title_caption(title, cap, A, capcolor=INK2):
    T(0.07, 0.925, title, 21, INK, A, weight="bold", ha="left")
    if cap:
        T(0.07, 0.878, cap, 13.5, capcolor, A, ha="left")


def setup_axes(ymax=1.14):
    ax.clear()
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, 8.6)
    ax.set_ylim(0, ymax)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])


# ------------------------------------------------------------------ scenes
def scene_hook(t, A):
    ax.set_visible(False)
    # three quick "perfect score" beats, then the turn
    beats = [
        (0.2, "Perfect score.", INK),
        (1.1, "Perfect score.", INK),
        (2.0, "Perfect score.", INK),
    ]
    for i, (t0, txt, col) in enumerate(beats):
        a = A * ease((t - t0) / 0.35) * (1.0 if t < 3.1 else clamp((3.6 - t) / 0.4))
        T(0.5, 0.66 - i * 0.11, txt, 40 - i * 2, col, a, weight="bold")
    if t >= 3.2:
        a = A * ease((t - 3.2) / 0.4)
        T(0.5, 0.44, "All three were lies.", 44, RED, a, weight="bold")
    if t >= 4.1:
        a = A * ease((t - 4.1) / 0.4)
        T(0.5, 0.33, "A fraud detector that kept acing every test.", 18, INK2, a)
        T(0.5, 0.28, "Here's the pattern.", 18, INK2, a)


def _bars(labels, heights, colors, ghosts=None, val_fmt="{:.2f}", A=1.0, label_dy=-0.06):
    n = len(labels)
    for i in range(n):
        if ghosts and ghosts[i] is not None:
            ax.add_patch(plt.Rectangle((i - 0.31, 0), 0.62, ghosts[i], fill=False,
                                       ec=MUTED, ls=(0, (3, 3)), lw=1.1, alpha=0.5 * A))
        ax.bar(i, heights[i], width=0.62, color=colors[i], alpha=A, zorder=3)
        if heights[i] > 0.03:
            ax.text(i, heights[i] + 0.02, val_fmt.format(heights[i]), ha="center",
                    va="bottom", fontsize=12, color=INK2, fontweight="bold", alpha=A)
        ax.text(i, label_dy, labels[i], ha="center", va="top", fontsize=11,
                color=INK, alpha=A)


def scene_prov(t, A):
    ax.set_visible(True)
    setup_axes()
    ax.set_xlim(-0.6, 2.6)
    labels = ["DeepSeek", "GLM", "Mistral"]
    naive = [1.00, 1.00, 1.00]
    matched = [0.58, 0.57, 0.84]
    drop = seg(t, 3.2, 6.2)
    heights = [lerp(naive[i] * seg(t, 0.4, 2.2), matched[i], drop) if t >= 3.2
               else naive[i] * seg(t, 0.4, 2.2) for i in range(3)]
    colors = [hexlerp(BLUE, RED if matched[i] < 0.65 else AMBER, drop) for i in range(3)]
    ghosts = [1.0 if drop > 0.05 else None for _ in range(3)]
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color="#cfcec6", lw=1.5)
    # chance line
    ca = seg(t, 3.2, 4.2)
    if ca > 0:
        ax.axhline(0.50, color=MUTED, ls=(0, (5, 4)), lw=1.5, alpha=ca * A)
        ax.text(-0.55, 0.53, "chance 0.50", ha="left", fontsize=11.5, style="italic",
                color=MUTED, alpha=ca * A)
    _bars(labels, heights, colors, ghosts, A=A)
    if t < 3.0:
        title_caption("Tell AI fraud from human fraud?",
                      "Naive corpus: cross-generator AUC 1.00. Looks perfect.", A)
    else:
        title_caption("Tell AI fraud from human fraud?",
                      "Match the distributions, and it falls toward chance.", A, capcolor=INK)


def scene_rob(t, A):
    ax.set_visible(True)
    setup_axes()
    ax.set_xlim(-0.6, 1.6)
    labels = ["keyword\ndetector", "trained\nmodel"]
    kept_after = [0.01, 0.62]  # share of caught frauds still caught after one homoglyph
    grow = seg(t, 0.4, 2.2)
    drain = seg(t, 3.2, 6.0)
    heights = [lerp(1.0 * grow, kept_after[i], drain) if t >= 3.2 else 1.0 * grow
               for i in range(2)]
    colors = [hexlerp(BLUE, RED if kept_after[i] < 0.3 else AMBER, drain) for i in range(2)]
    ghosts = [1.0 if drain > 0.05 else None for _ in range(2)]
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color="#cfcec6", lw=1.5)
    _bars(labels, heights, colors, ghosts, val_fmt="{:.0%}", A=A, label_dy=-0.08)
    if t < 3.0:
        title_caption("Do these detectors survive an attacker?",
                      "Start from every lure they catch on clean text.", A)
    else:
        title_caption("Do these detectors survive an attacker?",
                      "One homoglyph, and 99% of the keyword catches evade.", A, capcolor=INK)


def scene_lang(t, A):
    ax.set_visible(True)
    setup_axes()
    labels = ["English", "Spanish", "French", "German", "Italian", "Portuguese",
              "Chinese", "Russian", "Arabic"]
    raw = [0.97, 1.00, 1.00, 1.00, 1.00, 0.93, 1.00, 0.94, 0.98]
    ctrl = [0.97, 1.00, 0.96, 1.00, 0.91, 0.79, 0.09, 0.06, 0.04]
    grow = seg(t, 0.4, 2.4)
    collapse = seg(t, 3.4, 6.4)
    heights, colors, ghosts = [], [], []
    for i in range(9):
        h = lerp(raw[i] * grow, ctrl[i], collapse) if t >= 3.4 else raw[i] * grow
        heights.append(h)
        final = GREEN if ctrl[i] >= 0.5 else RED
        colors.append(hexlerp(BLUE, final, collapse) if t >= 3.4 else BLUE)
        ghosts.append(raw[i] if (collapse > 0.05 and raw[i] - ctrl[i] > 0.15) else None)
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color="#cfcec6", lw=1.5)
    ga = seg(t, 3.4, 4.6)
    if ga > 0:
        ax.axvline(5.5, color=MUTED, ls=(0, (3, 3)), lw=1.2, alpha=0.8 * ga * A, ymax=0.9)
        T(0.30, 0.735, "LATIN — survives", 12.5, GREEN, ga * A, weight="bold")
        T(0.74, 0.735, "NON-LATIN — collapses", 12.5, RED, ga * A, weight="bold")
    _bars(labels, heights, colors, ghosts, A=A)
    if t < 3.2:
        title_caption("Does it work in every language?",
                      "Perfect recall across 8 languages.", A)
    else:
        title_caption("Does it work in every language?",
                      "Strip the URL placeholder: non-Latin scripts collapse.", A, capcolor=INK)


def scene_close(t, A):
    ax.set_visible(False)
    T(0.5, 0.90, "The number looked great every time.", 24, INK, A, weight="bold")
    T(0.5, 0.845, "It was measuring an artifact every time.", 20, RED, A * seg(t, 0.5, 1.3),
      weight="bold")
    if _demo is not None:
        da = A * seg(t, 1.0, 2.0)
        if da > 0.01:
            iax = fig.add_axes([0.22, 0.24, 0.56, 0.52])
            iax.imshow(_demo, alpha=da)
            iax.axis("off")
    T(0.5, 0.165, "LureBench reports raw vs artifact-controlled by default.",
      15, INK2, A * seg(t, 1.6, 2.4))
    T(0.5, 0.085, "github.com/immu4989/lurebench", 15, INK, A * seg(t, 2.0, 2.8), weight="bold")
    T(0.5, 0.05, "live demo: huggingface.co/spaces/immu4989/lurescope",
      13, MUTED, A * seg(t, 2.2, 3.0))


DISPATCH = {"hook": scene_hook, "prov": scene_prov, "rob": scene_rob,
            "lang": scene_lang, "close": scene_close}


def draw(frame):
    t = frame / FPS
    fig.texts.clear()
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
    local = t - s
    A = min(ease(local / FADE), ease((e - t) / FADE))
    DISPATCH[name](local, clamp(A))
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
