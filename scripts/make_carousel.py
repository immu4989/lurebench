"""Build the LinkedIn carousel (1080x1080 slides + combined PDF) for the LureBench
LLM-panel results. Palette and mark rules follow the dataviz reference instance."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

OUT = "/Users/imranahamed/Documents/top_repos/lurebench/docs/assets/carousel"

# --- palette (dataviz reference instance, light mode) ---
SURFACE = "#fcfcfb"
INK     = "#0b0b0b"
MUTED   = "#52514e"
BLUE    = "#2a78d6"   # categorical slot 1
ORANGE  = "#eb6834"   # categorical slot 2
RED     = "#e34948"   # status: critical
GREEN   = "#008300"   # status: good
LINE    = "#dedddA"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "text.color": INK, "axes.labelcolor": MUTED,
    "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.edgecolor": LINE, "axes.linewidth": 1.0,
})

FIGSIZE = (7.2, 7.2)   # 1080x1080 at 150 dpi
DPI = 150


def frame(title, subtitle=None, top=0.90):
    """Title block. The subtitle is offset by the *rendered* title height rather
    than a constant, because a two-line title otherwise lands on top of it."""
    fig = plt.figure(figsize=FIGSIZE)
    fig.text(0.07, top + 0.045, title, fontsize=25, fontweight="bold",
             color=INK, va="top", linespacing=1.25)
    if subtitle:
        title_lines = title.count("\n") + 1
        y = top + 0.045 - (title_lines * 0.058) - 0.022
        fig.text(0.07, y, subtitle, fontsize=13.5, color=MUTED,
                 va="top", linespacing=1.55)
    return fig


def footer(fig, text="github.com/immu4989/lurebench"):
    fig.text(0.07, 0.045, text, fontsize=11.5, color=MUTED)


def bare(ax):
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(left=False)
    ax.grid(axis="x", color=LINE, linewidth=0.9)
    ax.set_axisbelow(True)


slides = []

# ---------- 1. title ----------
fig = plt.figure(figsize=FIGSIZE)
fig.text(0.07, 0.72, "A fraud detector\nscored a perfect\n1.000.", fontsize=42,
         fontweight="bold", color=INK, va="top", linespacing=1.15)
fig.text(0.07, 0.38, "The score was a lie.", fontsize=30, color=RED,
         fontweight="bold", va="top")
fig.text(0.07, 0.28, "What six LLMs actually do when you ask them\n"
                     "to catch fraud, and where the measurement breaks.",
         fontsize=14.5, color=MUTED, va="top", linespacing=1.6)
footer(fig)
slides.append(fig)

# ---------- 2. the abstention trap ----------
fig = frame("It was declining half the records",
            "It returned empty content on records it wouldn't answer. The harness\n"
            "excluded abstentions from the metrics, so it was graded only on the\n"
            "half it attempted. Reasoning models burn their budget on hidden\n"
            "reasoning, so the failure was silent and it flattered the score.")
ax = fig.add_axes([0.10, 0.16, 0.82, 0.44])
labels = ["Reported\n(abstentions hidden)", "Actual\n(all 60 scored)"]
vals = [1.000, 0.614]
bars = ax.bar(labels, vals, width=0.42, color=[RED, BLUE],
              zorder=3, edgecolor=SURFACE, linewidth=2)
for b, v, note in zip(bars, vals, ["scored 29/60", "scored 60/60"]):
    ax.text(b.get_x() + b.get_width()/2, v + 0.03, f"{v:.3f}", ha="center",
            fontsize=21, fontweight="bold", color=INK)
    ax.text(b.get_x() + b.get_width()/2, v - 0.09, note, ha="center",
            fontsize=12, color="white", fontweight="bold")
ax.set_ylim(0, 1.18); ax.set_ylabel("MCC", fontsize=12)
ax.set_yticks([0, 0.5, 1.0])
for s in ("top", "right"): ax.spines[s].set_visible(False)
ax.grid(axis="y", color=LINE, linewidth=0.9); ax.set_axisbelow(True)
ax.tick_params(axis="x", labelsize=12.5)
footer(fig)
slides.append(fig)

# ---------- 3. provenance null result ----------
fig = frame("Can an LLM tell AI-written fraud\nfrom human-written fraud?",
            "Six models, 1,072 distribution-matched records. 0.50 is chance.\n"
            "Four of six land at or below it. Three answered \"AI\" every time.",
            top=0.86)
ax = fig.add_axes([0.34, 0.14, 0.60, 0.50])
models = ["qwen-2.5-7b", "llama-3.1-8b", "gpt-5-nano", "mistral-nemo",
          "gemini-2.5-flash-lite", "deepseek-v4-flash"]
auc = [0.461, 0.461, 0.503, 0.533, 0.665, 0.737]
colors = [RED if a <= 0.55 else BLUE for a in auc]
ax.barh(models, auc, color=colors, height=0.56, zorder=3,
        edgecolor=SURFACE, linewidth=2)
for i, a in enumerate(auc):
    ax.text(a + 0.008, i, f"{a:.3f}", va="center", fontsize=13,
            fontweight="bold", color=INK)
ax.axvline(0.5, color=INK, linewidth=1.6, linestyle=(0, (4, 3)), zorder=4)
ax.text(0.5, len(models) - 0.25, " chance", fontsize=12, color=INK,
        fontweight="bold", va="center")
ax.set_xlim(0.40, 0.80); ax.set_xlabel("AUC (provenance task)", fontsize=12)
bare(ax); ax.tick_params(axis="y", labelsize=12.5)
footer(fig)
slides.append(fig)

# ---------- 4. multilingual ----------
fig = frame("Off Latin script, the trained model\nis not detecting anything",
            "Detection rate on fraud lures, artifact-controlled. The LLM judge runs\n"
            "at a 1% false-positive rate, the baseline at 5%.", top=0.86)
ax = fig.add_axes([0.10, 0.15, 0.84, 0.43])
langs = ["Arabic", "Russian", "Chinese", "Spanish", "French", "German"]
tfidf = [0.04, 0.06, 0.09, 1.00, 0.96, 1.00]
judge = [0.93, 0.78, 0.75, 0.91, 0.96, 0.96]
x = range(len(langs)); w = 0.38
b1 = ax.bar([i - w/2 for i in x], tfidf, w, label="tfidf-logreg (trained)",
            color=BLUE, zorder=3, edgecolor=SURFACE, linewidth=2)
b2 = ax.bar([i + w/2 for i in x], judge, w, label="LLM judge (deepseek)",
            color=ORANGE, zorder=3, edgecolor=SURFACE, linewidth=2)
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.03,
                f"{b.get_height():.2f}", ha="center", fontsize=10.5, color=INK)
ax.axvspan(-0.5, 2.5, color="#f0efec", zorder=0)
ax.text(1.0, 1.18, "non-Latin script", fontsize=12, color=MUTED,
        ha="center", fontweight="bold")
ax.set_xticks(list(x)); ax.set_xticklabels(langs, fontsize=12)
ax.set_ylim(0, 1.30); ax.set_ylabel("detection rate", fontsize=12)
ax.set_yticks([0, 0.5, 1.0])
for s in ("top", "right"): ax.spines[s].set_visible(False)
ax.grid(axis="y", color=LINE, linewidth=0.9); ax.set_axisbelow(True)
ax.legend(frameon=False, fontsize=12, ncol=2, loc="lower center",
          bbox_to_anchor=(0.5, 1.06))
footer(fig)
slides.append(fig)

# ---------- 5. the inversion ----------
fig = frame("Robustness flips with the attack",
            "Evasion rate: lower is better. Character tricks break token models.\n"
            "An attacker who rewrites the message repeatedly breaks the judges.",
            top=0.87)
names = ["tfidf-logreg", "gpt-5-nano", "deepseek-v4-flash"]
for k, (ttl, data, note) in enumerate([
        ("Homoglyph swap", [0.52, 0.00, 0.03], "one character changed"),
        ("Adaptive rewrite", [0.09, 0.35, 0.40], "up to 5 attempts")]):
    ax = fig.add_axes([0.10 + k*0.46, 0.21, 0.34, 0.40])
    cols = [BLUE, ORANGE, ORANGE]
    ax.bar(names, data, width=0.5, color=cols, zorder=3,
           edgecolor=SURFACE, linewidth=2)
    for i, v in enumerate(data):
        ax.text(i, v + 0.025, f"{v:.0%}", ha="center", fontsize=14,
                fontweight="bold", color=INK)
    ax.set_ylim(0, 0.68); ax.set_title(ttl, fontsize=16, fontweight="bold",
                                       color=INK, pad=14)
    ax.text(0.5, 1.02, note, transform=ax.transAxes, ha="center",
            fontsize=11, color=MUTED)
    ax.set_xticks(range(3))
    ax.set_xticklabels(names, fontsize=10.5, rotation=28, ha="right")
    ax.set_yticks([0, 0.25, 0.5])
    ax.set_yticklabels(["0%", "25%", "50%"])
    if k == 0: ax.set_ylabel("evaded", fontsize=12)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.grid(axis="y", color=LINE, linewidth=0.9); ax.set_axisbelow(True)
footer(fig)
slides.append(fig)

# ---------- 6. the correction ----------
fig = frame("A correction to what I posted before",
            "I said LLM judges trade recall for robustness. Wrong. They rank fraud\n"
            "above benign well. They are simply miscalibrated at the default 0.5\n"
            "cutoff, and lowering it recovers the recall at a 2.5% false-positive rate.",
            top=0.87)
ax = fig.add_axes([0.30, 0.16, 0.64, 0.44])
js = ["qwen-2.5-7b", "gemini-2.5-flash-lite", "deepseek-v4-flash"]
tpr50 = [0.576, 0.726, 0.750]
tprbest = [0.832, 0.870, 0.856]
y = range(len(js))
for i, (a, b) in enumerate(zip(tpr50, tprbest)):
    ax.plot([a, b], [i, i], color=LINE, linewidth=3, zorder=2,
            solid_capstyle="round")
ax.scatter(tpr50, list(y), s=150, color=RED, zorder=4, label="recall at 0.50 cutoff")
ax.scatter(tprbest, list(y), s=150, color=BLUE, zorder=4,
           label="recall at tuned cutoff")
for i, (a, b) in enumerate(zip(tpr50, tprbest)):
    ax.text(a - 0.018, i, f"{a:.2f}", ha="right", va="center", fontsize=12, color=INK)
    ax.text(b + 0.018, i, f"{b:.2f}", ha="left", va="center", fontsize=12, color=INK)
ax.set_yticks(list(y)); ax.set_yticklabels(js, fontsize=12.5)
ax.set_xlim(0.48, 0.96); ax.set_xlabel("recall on fraud lures", fontsize=12)
bare(ax)
ax.legend(frameon=False, fontsize=11.5, loc="upper center",
          bbox_to_anchor=(0.45, 1.22), ncol=2)
footer(fig)
slides.append(fig)

# ---------- 7. close ----------
fig = plt.figure(figsize=FIGSIZE)
fig.text(0.07, 0.86, "What I'd take from this", fontsize=30, fontweight="bold",
         color=INK, va="top")
pts = [
    ("Check the denominator.", "A model that declines the hard records gets\n"
                               "graded on the easy ones and looks perfect."),
    ("Run it more than once.", "One run of the attack experiment swung 17 points.\n"
                               "Temperature 0 does not make a hosted model deterministic."),
    ("Pick the detector for the attack.", "Token models die to typography.\n"
                                          "LLM judges die to rewriting. Run both."),
]
ypos = 0.745
for head, body in pts:
    fig.text(0.07, ypos, head, fontsize=19, fontweight="bold", color=BLUE, va="top")
    fig.text(0.07, ypos - 0.055, body, fontsize=14, color=MUTED, va="top",
             linespacing=1.6)
    ypos -= 0.19
fig.text(0.07, 0.13, "Code, data, and every table:", fontsize=13.5, color=MUTED)
fig.text(0.07, 0.085, "github.com/immu4989/lurebench", fontsize=17,
         fontweight="bold", color=INK)
slides.append(fig)

# ---------- write ----------
import os
os.makedirs(OUT, exist_ok=True)
for i, fig in enumerate(slides, 1):
    fig.savefig(f"{OUT}/slide{i}.png", dpi=DPI)
with PdfPages(f"{OUT}/lurebench-carousel.pdf") as pdf:
    for fig in slides:
        pdf.savefig(fig, dpi=DPI)
for fig in slides:
    plt.close(fig)
print(f"wrote {len(slides)} slides + PDF to {OUT}")
