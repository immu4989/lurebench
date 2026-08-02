#!/usr/bin/env python3
"""Dark-palette story video (1080x1080 MP4) — the perfect score that was a lie.

Same visual grammar as make_story_video_dark.py ("looks perfect -> honest check ->
collapse", dashed ghost outlines marking where a bar fell from), applied to the
measurement-integrity findings: a detector that scored 1.000 while declining half
the corpus, and a sample of "120 lures" that was really 73 distinct records.

Cold-opens on the anomaly (three flawless bars) rather than on text, per what
worked last time.

    python scripts/make_denominator_video.py
      -> ~/Documents/lurebench-social/denominator.mp4
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

BG, INK, MUT, DIM = "#0a1628", "#ffffff", "#94a3b8", "#64748b"
GRID, AXIS = "#1e293b", "#334155"
CYAN, BLUE, GREEN, RED, AMBER = "#06b6d4", "#3b82f6", "#22c55e", "#ef4444", "#e0a83a"

FPS = 24
SCENES = [("hook", 6.0), ("check", 8.5), ("again", 8.0), ("why", 7.0), ("close", 5.5)]
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
ax = fig.add_axes([0.07, 0.16, 0.86, 0.55])


def Tx(x, y, s, size, color, A, weight="normal", ha="center", style="normal"):
    if A > 0.01:
        fig.text(x, y, s, fontsize=size, color=color, alpha=clamp(A), ha=ha,
                 fontweight=weight, fontstyle=style)


def accent(A):
    if A > 0.01:
        fig.patches.append(plt.Rectangle((0.07, 0.935), 0.05, 0.011,
                           transform=fig.transFigure, color=CYAN, alpha=clamp(A)))


def head(title, cap, A, tcolor=INK, capcolor=MUT, size=23):
    accent(A)
    Tx(0.07, 0.885, title, size, tcolor, A, weight="bold", ha="left")
    if cap:
        Tx(0.07, 0.838, cap, 13.5, capcolor, A, ha="left")


def setup_axes(xmax=2.7, ymax=1.20):
    ax.clear()
    ax.set_facecolor("none")
    ax.set_xlim(-0.75, xmax)
    ax.set_ylim(0, ymax)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color=AXIS, lw=1.5)


def bars(labels, heights, colors, ghosts=None, fmts=None, A=1.0, dy=-0.065, lab=12):
    for i in range(len(labels)):
        if ghosts and ghosts[i] is not None:
            ax.add_patch(plt.Rectangle((i - 0.28, 0), 0.56, ghosts[i], fill=False,
                                       ec=DIM, ls=(0, (3, 3)), lw=1.3, alpha=0.75 * A))
        ax.bar(i, heights[i], width=0.56, color=colors[i], alpha=A, zorder=3)
        if heights[i] > 0.03:
            txt = fmts[i] if fmts else f"{heights[i]:.3f}"
            ax.text(i, heights[i] + 0.025, txt, ha="center", va="bottom",
                    fontsize=15, color="#e2e8f0", fontweight="bold", alpha=A)
        ax.text(i, dy, labels[i], ha="center", va="top", fontsize=lab, color=MUT, alpha=A)


def panel(x, y, w, h, A, color=CYAN, alpha_fill=0.10):
    if A > 0.01:
        fig.patches.append(plt.Rectangle((x, y), w, h, transform=fig.transFigure,
                                         facecolor=color, alpha=alpha_fill * A,
                                         edgecolor=color, lw=1.4, zorder=1))


# ------------------------------------------------------------------ scenes
M_LABELS = ["MCC", "TPR", "AUC"]
REPORTED = [1.000, 1.000, 1.000]
ACTUAL = [0.614, 0.897, 0.865]


def scene_hook(t, A):
    """Cold open: three flawless bars. Nothing looks wrong."""
    setup_axes()
    ax.set_visible(True)
    grow = ease(t / 1.1)
    heights = [v * grow for v in REPORTED]
    bars(M_LABELS, heights, [GREEN] * 3, fmts=[f"{v:.3f}" for v in REPORTED], A=A)
    accent(A)
    Tx(0.07, 0.885, "A fraud detector scored", 26, INK, A, weight="bold", ha="left")
    Tx(0.07, 0.828, "a perfect 1.000", 26, GREEN, A, weight="bold", ha="left")
    r = seg(t, 2.6, 3.6) * A
    Tx(0.07, 0.075, "Every metric. Nothing looked wrong.", 15, MUT, r, ha="left")
    r2 = seg(t, 4.1, 5.0) * A
    Tx(0.07, 0.030, "So I checked how many records it answered.", 15, AMBER, r2, ha="left")


def scene_check(t, A):
    """The honest check: it declined half the corpus, and the score collapses."""
    setup_axes()
    ax.set_visible(True)
    head("The honest check", "Of 60 records, how many did it actually score?", A)

    # denominator reveal
    dn = seg(t, 0.5, 1.6) * A
    panel(0.60, 0.735, 0.33, 0.085, dn)
    Tx(0.765, 0.787, "scored", 13, MUT, dn)
    Tx(0.765, 0.748, "29 / 60", 24, RED, dn, weight="bold")

    # bars collapse from reported to actual
    k = seg(t, 2.3, 4.6)
    heights = [lerp(REPORTED[i], ACTUAL[i], k) for i in range(3)]
    colors = [hexlerp(GREEN, RED, k) for _ in range(3)]
    ghosts = [REPORTED[i] if k > 0.05 else None for i in range(3)]
    fmts = [f"{h:.3f}" for h in heights]
    bars(M_LABELS, heights, colors, ghosts, fmts=fmts, A=A)

    c1 = seg(t, 5.0, 5.9) * A
    Tx(0.07, 0.075, "It declined 31 records. The metrics were computed", 15, INK, c1, ha="left")
    Tx(0.07, 0.038, "only over the 29 it chose to answer.", 15, INK, c1, ha="left")


def scene_again(t, A):
    """The same shape of error, in a different place."""
    setup_axes(xmax=1.7, ymax=1.20)
    ax.set_visible(True)
    head("Then it happened again", "A different table. The same kind of mistake.", A)

    full, real = 1.00, 0.608   # 120 -> 73 records, drawn proportionally
    k = seg(t, 1.4, 3.6)
    h = [full, lerp(full, real, k)]
    cols = [DIM, hexlerp(GREEN, RED, k)]
    ghosts = [None, full if k > 0.05 else None]
    fmts = ["120 stated", f"{int(lerp(120, 73, k))} actual"]
    bars(["what it claimed", "what it measured"], h, cols, ghosts, fmts=fmts, A=A, lab=13)

    c = seg(t, 4.2, 5.2) * A
    Tx(0.07, 0.082, "Record ids collided, so records overwrote each other.", 15, INK, c,
       ha="left")
    c2 = seg(t, 5.6, 6.5) * A
    Tx(0.07, 0.042, "25 ids appeared two or three times. Nothing warned.", 15, MUT, c2,
       ha="left")


def scene_why(t, A):
    """Why this class of bug is dangerous: it is silent AND flattering."""
    ax.set_visible(False)
    # Two-line title, so the caption cannot sit at head()'s default y - it lands on
    # top of the second line. Title lines at .885/.828, caption dropped to .772.
    head("Both failures flattered", None, A, tcolor=INK)
    Tx(0.07, 0.828, "the model", 23, RED, A, weight="bold", ha="left")
    Tx(0.07, 0.772, "Silence is not the dangerous part.", 13.5, MUT, A, ha="left")

    rows = [
        (0.63, "A model that declines the hard records", "gets graded on the easy ones."),
        (0.45, "A sample that silently shrinks", "reports a number it never measured."),
        (0.27, "Neither one throws an error.", "Both make the score look better."),
    ]
    for i, (y, a, b) in enumerate(rows):
        r = seg(t, 0.8 + i * 1.5, 1.7 + i * 1.5) * A
        panel(0.07, y - 0.035, 0.86, 0.115, r, color=CYAN if i < 2 else AMBER)
        Tx(0.10, y + 0.038, a, 16.5, INK, r, ha="left", weight="bold")
        Tx(0.10, y - 0.004, b, 15, MUT, r, ha="left")

    c = seg(t, 5.4, 6.3) * A
    Tx(0.07, 0.13, "Once fixed, judge recall moved 4 to 10 points.", 15, GREEN, c, ha="left")


def scene_close(t, A):
    ax.set_visible(False)
    accent(A)
    Tx(0.07, 0.70, "Check the", 34, INK, A, weight="bold", ha="left")
    Tx(0.07, 0.615, "denominator.", 34, CYAN, A, weight="bold", ha="left")
    r = seg(t, 1.0, 2.0) * A
    Tx(0.07, 0.50, "Every metric is computed over the records", 16, MUT, r, ha="left")
    Tx(0.07, 0.458, "a model was willing to answer. Report that number.", 16, MUT, r,
       ha="left")
    r2 = seg(t, 2.4, 3.3) * A
    Tx(0.07, 0.32, "Open benchmark, corpus and code:", 15, DIM, r2, ha="left")
    Tx(0.07, 0.265, "github.com/immu4989/lurebench", 19, INK, r2, weight="bold", ha="left")


DRAW = {"hook": scene_hook, "check": scene_check, "again": scene_again,
        "why": scene_why, "close": scene_close}
FADE = 0.35


def draw(frame):
    t = frame / FPS
    fig.texts.clear()
    fig.patches.clear()          # never reassign: it silently kills all axes rendering
    ax.clear()
    ax.set_visible(False)
    ax.set_facecolor("none")
    for name, (s, e) in _starts.items():
        if s - 0.01 <= t < e:
            local = t - s
            A = min(seg(t, s, s + FADE), 1.0 - seg(t, e - FADE, e)) if e - s > 2 * FADE else 1.0
            DRAW[name](local, clamp(A))
            break
    return []


def main():
    out_dir = os.path.expanduser("~/Documents/lurebench-social")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "denominator.mp4")
    anim = FuncAnimation(fig, draw, frames=FRAMES, interval=1000 / FPS, blit=False)
    writer = FFMpegWriter(fps=FPS, bitrate=4500, extra_args=["-pix_fmt", "yuv420p"])
    anim.save(out, writer=writer, dpi=120, savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out) / 1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")


if __name__ == "__main__":
    main()
