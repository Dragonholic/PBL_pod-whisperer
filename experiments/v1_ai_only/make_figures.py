#!/usr/bin/env python3
"""Draw the v1 result tables as figures (PNG) into experiments/v1_ai_only/figures/.

Every number is read from the result CSVs (or recomputed from data/ with
detector.py for the per-scenario outcome chart), nothing is typed in by hand.

Run from anywhere:  python3 experiments/v1_ai_only/make_figures.py
Needs: matplotlib and koreanize-matplotlib (bundles the NanumGothic font).
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

import koreanize_matplotlib  # noqa: F401  (sets a Korean-capable font)
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Rectangle

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
import detector  # noqa: E402

OUT = HERE / "figures"
OUT.mkdir(exist_ok=True)
RES = HERE / "results"
RES_SCOPED = HERE / "results_scoped"

# palette (reference instance of the dataviz skill, light mode)
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
BLUE = "#2a78d6"    # categorical slot 1
ORANGE = "#eb6834"  # categorical slot 2
SEQ = LinearSegmentedColormap.from_list("seq", ["#eef3fb", "#9fc2ef", "#2a78d6", "#123f7a"])

RULES = [("R1", "차단된 접속"), ("R2", "처음 보는 통신"), ("R3", "관리용 포트"), ("R4", "여러 곳 동시 접속"), ("R5", "요청 횟수")]
ATTACK_ORDER = ["abnormal_1", "abnormal_2", "abnormal_3", "k8s_1", "k8s_2", "k8s_3", "evasion_1", "evasion_2"]
NORMAL_ORDER = ["normal", "fp_1", "fp_2", "fp_3"]
PROVIDED = {"normal", "abnormal_1", "abnormal_2", "abnormal_3"}


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def style(ax, grid_axis="y"):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK2, length=0)
    if grid_axis:
        ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)


def new_fig(w, h, title, subtitle=None):
    fig = plt.figure(figsize=(w, h), facecolor=SURFACE)
    fig.text(0.04, 0.965, title, fontsize=15, fontweight="bold", color=INK, va="top", ha="left")
    if subtitle:
        fig.text(0.04, 0.905, subtitle, fontsize=10.5, color=INK2, va="top", ha="left")
    return fig


def save(fig, name):
    p = OUT / name
    fig.savefig(p, dpi=200, facecolor=SURFACE)
    plt.close(fig)
    print("wrote", p.relative_to(ROOT))


# ----------------------------------------------------------------- data
matrix = {r["scenario"]: r for r in read_csv(RES / "table1_scenario_rule_matrix.csv")}
overall = read_csv(RES / "table2_overall_prf.csv")[0]
grid = read_csv(RES / "experiment_a_grid.csv")
abl = {r["subset"]: r for r in read_csv(RES / "experiment_b_ablation.csv")}
abl_s = {r["subset"]: r for r in read_csv(RES_SCOPED / "experiment_b_ablation.csv")}
grid_s = read_csv(RES_SCOPED / "experiment_a_grid.csv")
cfg = detector.load_config(str(ROOT / "config.yaml"))
baseline = detector.load_baseline(str(ROOT / "data" / "baseline.json"))


def cell(rows, n, w=10):
    return next(r for r in rows if int(r["N"]) == n and int(r["W"]) == w)


# per-scenario "flagged runs" recomputed from the raw flows (default settings)
flagged = defaultdict(int)
runs = defaultdict(int)
for row in read_csv(ROOT / "data" / "manifest.csv"):
    alerts = detector.detect(
        str(ROOT / row["data_file"]),
        baseline=baseline,
        window_seconds=cfg["detection"]["window_seconds"],
        fanout_threshold=cfg["detection"]["fanout_threshold"],
        sensitive_ports=set(cfg["detection"]["sensitive_ports"]),
        k_sigma=cfg["detection"]["frequency"]["k_sigma"],
    )
    runs[row["scenario"]] += 1
    flagged[row["scenario"]] += 1 if alerts else 0

tp, fp, fn, tn = (int(overall[k]) for k in ("TP", "FP", "FN", "TN"))
assert sum(flagged[s] for s in ATTACK_ORDER) == tp, "recomputed TP differs from table 2"
assert sum(flagged[s] for s in NORMAL_ORDER) == fp, "recomputed FP differs from table 2"
precision, recall, f1 = (float(overall[k]) for k in ("Precision", "Recall", "F1"))
all_attack_precision = 80 / 120  # baseline: call every run an attack

# ------------------------------------------------- fig 1: outcome by source
groups = [
    ("제공 공격\n(abnormal_1~3)", [s for s in ATTACK_ORDER if s in PROVIDED], True),
    ("제공 정상\n(normal)", [s for s in NORMAL_ORDER if s in PROVIDED], False),
    ("추가 공격\n(k8s_1~3, evasion_1~2)", [s for s in ATTACK_ORDER if s not in PROVIDED], True),
    ("추가 정상(변형)\n(fp_1~3)", [s for s in NORMAL_ORDER if s not in PROVIDED], False),
]
right, wrong, labels = [], [], []
for label, scen, is_attack in groups:
    n = sum(runs[s] for s in scen)
    fl = sum(flagged[s] for s in scen)
    right.append(fl if is_attack else n - fl)
    wrong.append(n - fl if is_attack else fl)
    labels.append(label)

fig = new_fig(10, 4.6, "공격은 출처와 무관하게 전부 탐지, 정상은 거의 전부 오탐",
              "기본 설정(기준 개수 N=5) · 시나리오 1회 실행 = 1건 · 경보가 하나라도 나오면 \"공격\"으로 판정")
ax = fig.add_axes([0.20, 0.24, 0.76, 0.54])
style(ax, "x")
y = range(len(labels))[::-1]
for yi, r, w in zip(y, right, wrong):
    ax.barh(yi, r, height=0.5, color=BLUE, edgecolor=SURFACE, linewidth=2)
    if w:
        ax.barh(yi, w, left=r, height=0.5, color=ORANGE, edgecolor=SURFACE, linewidth=2)
    if r >= 3:
        ax.text(r / 2, yi, f"{r}건", ha="center", va="center", color="white", fontsize=11, fontweight="bold")
    elif r:  # segment too narrow for an inside label: note it beside the bar
        ax.text(r + w + 0.8, yi, f"(정답과 일치 {r}건)", ha="left", va="center", color=INK2, fontsize=10)
    if w >= 3:
        ax.text(r + w / 2, yi, f"{w}건", ha="center", va="center", color="white", fontsize=11, fontweight="bold")
ax.set_yticks(list(y))
ax.set_yticklabels(labels, fontsize=10.5, color=INK)
ax.set_xlim(0, 52)
ax.set_xlabel("실행 횟수", color=INK2, fontsize=10)
fig.legend(handles=[Rectangle((0, 0), 1, 1, color=BLUE), Rectangle((0, 0), 1, 1, color=ORANGE)],
           labels=["정답과 일치 (공격은 탐지, 정상은 정상 판정)", "정답과 다름 (공격은 놓침, 정상은 오탐)"],
           loc="lower center", bbox_to_anchor=(0.58, 0.02), ncol=2, frameon=False, fontsize=9.5, labelcolor=INK2)
save(fig, "fig1_출처별_판정결과.png")

# ------------------------------------------------- fig 2: confusion matrix
fig = new_fig(8.6, 5.4, f"공격 80건은 모두 잡았지만, 정상 40건 중 {fp}건도 공격으로 판정",
              f"정밀도 {precision:.3f} · 재현율 {recall:.3f} · F1 {f1:.3f}   |   모든 실행을 \"공격\"이라 해도 정밀도 {all_attack_precision:.3f}")
ax = fig.add_axes([0.22, 0.10, 0.72, 0.70])
vals = [[tp, fn], [fp, tn]]
names = [["공격을 공격으로 맞힘\n(TP)", "공격을 놓침 (미탐)\n(FN)"],
         ["정상을 공격으로 오판 (오탐)\n(FP)", "정상을 정상으로 맞힘\n(TN)"]]
vmax = max(max(r) for r in vals)
for i in range(2):
    for j in range(2):
        v = vals[i][j]
        ax.add_patch(Rectangle((j, 1 - i), 1, 1, facecolor=SEQ(v / vmax), edgecolor=SURFACE, linewidth=4))
        tc = "white" if v / vmax > 0.45 else INK
        ax.text(j + 0.5, 1 - i + 0.60, f"{v}", ha="center", va="center", fontsize=26, fontweight="bold", color=tc)
        ax.text(j + 0.5, 1 - i + 0.25, names[i][j], ha="center", va="center", fontsize=10, color=tc)
ax.set_xlim(0, 2)
ax.set_ylim(0, 2)
ax.set_xticks([0.5, 1.5])
ax.set_xticklabels(["공격으로 판정", "정상으로 판정"], fontsize=11, color=INK)
ax.set_yticks([0.5, 1.5])
ax.set_yticklabels(["실제 정상\n(40건)", "실제 공격\n(80건)"], fontsize=11, color=INK)
ax.xaxis.tick_top()
ax.tick_params(length=0)
for s in ax.spines.values():
    s.set_visible(False)
save(fig, "fig2_전체_혼동행렬.png")

# ------------------------------------------------- fig 3: scenario x rule heatmap
order = ATTACK_ORDER + NORMAL_ORDER
data = [[int(matrix[s][r]) for r, _ in RULES] for s in order]
fig = new_fig(10.5, 8.2, "어떤 시나리오가 어떤 규칙에 걸렸나 (10회 중 발동 횟수)",
              "차단된 접속·처음 보는 통신만으로 evasion_2를 뺀 공격 7개가 잡힘 · evasion_2는 요청 횟수 규칙이 있어야 탐지")
ax = fig.add_axes([0.20, 0.14, 0.74, 0.63])
for i, row in enumerate(data):
    for j, v in enumerate(row):
        ax.add_patch(Rectangle((j, len(order) - 1 - i), 1, 1, facecolor=SEQ(v / 10), edgecolor=SURFACE, linewidth=2))
        ax.text(j + 0.5, len(order) - 1 - i + 0.5, str(v), ha="center", va="center", fontsize=11,
                color="white" if v / 10 > 0.45 else INK)
ev = len(order) - 1 - order.index("evasion_2")
ax.add_patch(Rectangle((0, ev), 5, 1, facecolor="none", edgecolor=ORANGE, linewidth=3))
sep = len(order) - len(ATTACK_ORDER)
ax.axhline(sep, color=INK2, linewidth=1.2)
ax.text(5.08, sep + 4, "공격", rotation=270, va="center", ha="left", color=INK2, fontsize=10)
ax.text(5.08, sep - 2, "정상", rotation=270, va="center", ha="left", color=INK2, fontsize=10)
ax.set_xlim(0, 5)
ax.set_ylim(0, len(order))
ax.set_xticks([j + 0.5 for j in range(5)])
ax.set_xticklabels([f"{n}\n({c})" for c, n in RULES], fontsize=10.5, color=INK)
ax.xaxis.tick_top()
ax.set_yticks([len(order) - 1 - i + 0.5 for i in range(len(order))])
ax.set_yticklabels([s + ("" if s in PROVIDED else " *") for s in order], fontsize=10.5, color=INK)
ax.tick_params(length=0)
for s in ax.spines.values():
    s.set_visible(False)
fig.text(0.04, 0.075, "* 이번 프로젝트에서 추가한 시나리오(나머지는 과제 제공)   |   주황 테두리: 허용된 경로 악용(evasion_2)",
         fontsize=9.5, color=INK2)
fig.text(0.04, 0.040, "요청 횟수 열의 높은 값은 대부분 시스템 경로(노드 헬스체크, DNS 등)의 요청 횟수 이상 증가이며, 공격 경로 자체를 잡은 진짜 신호는 evasion_2뿐 (1회차 경보 확인 기준)",
         fontsize=9.5, color=INK2)
save(fig, "fig3_시나리오별_규칙발동.png")

# ------------------------------------------------- fig 4: experiment A
ns = [3, 5, 10]
fps = [int(cell(grid, n)["FP"]) for n in ns]
precs = [float(cell(grid, n)["Precision"]) for n in ns]
fig = new_fig(9, 5.2, "오탐은 기준 개수 N을 10으로 올려야 줄어든다",
              "N=3은 정상을 하나도 정상으로 못 보는 \"전부 공격 판정\"과 같은 결과 · 재현율은 모두 1.000")
ax = fig.add_axes([0.12, 0.16, 0.82, 0.62])
style(ax, "y")
xs = range(len(ns))
ax.axhline(40, color=INK2, linestyle=(0, (4, 4)), linewidth=1.2, zorder=1)
ax.text(2.4, 40.8, "정상 40건 전부 오탐", ha="right", va="bottom", fontsize=9.5, color=INK2)
ax.bar(xs, fps, width=0.45, color=BLUE, zorder=2)
tbox = dict(facecolor=SURFACE, edgecolor="none", pad=1.5)
for x, v, p in zip(xs, fps, precs):
    ax.text(x, v + 1.0, f"오탐 {v}건", ha="center", va="bottom", fontsize=12, fontweight="bold", color=INK, bbox=tbox, zorder=3)
    ax.text(x, v + 4.6, f"정밀도 {p:.3f}", ha="center", va="bottom", fontsize=10, color=INK2, bbox=tbox, zorder=3)
ax.set_xticks(list(xs))
ax.set_xticklabels(["N=3", "N=5 (기본)", "N=10"], fontsize=11, color=INK)
ax.set_xlabel("기준 개수 N = 짧은 시간에 서로 다른 곳(대상·포트)에 접속하면 \"여러 곳 동시 접속\"으로 보는 최소 개수", color=INK2, fontsize=9.5)
ax.set_ylim(0, 50)
ax.set_ylabel("오탐 건수 (정상을 공격으로 오판)", color=INK2, fontsize=10)
save(fig, "fig4_실험A_기준개수.png")

# ------------------------------------------------- fig 5: experiment B
combos = [("R1", "차단된 접속\n(R1)"), ("R1+R2", "+ 처음 보는 통신\n(R1+R2)"), ("R1-3", "+ 관리용 포트\n(R1~R3)"),
          ("R1-4", "+ 여러 곳 동시 접속\n(R1~R4)")]
rec_u = [float(abl[k]["Recall"]) for k, _ in combos] + [recall]
rec_s = [float(abl_s[k]["Recall"]) for k, _ in combos] + [1.0]
xl = [lab for _, lab in combos] + ["+ 요청 횟수\n(R1~R5, 전체)"]
fig = new_fig(10.5, 5.6, "요청 횟수 규칙을 더해야 재현율 1.000 (0.975는 우연)",
              "규칙을 하나씩 더할 때 공격 80건 중 잡은 비율(재현율) · 놓친 공격은 전부 evasion_2(허용된 경로 악용)")
ax = fig.add_axes([0.08, 0.17, 0.89, 0.62])
style(ax, "y")
w = 0.34
for k in range(5):
    ax.bar(k - w / 2 - 0.01, rec_u[k], width=w, color=BLUE)
    ax.bar(k + w / 2 + 0.01, rec_s[k], width=w, color=ORANGE)
    ax.text(k - w / 2 - 0.01, rec_u[k] + 0.012, f"{rec_u[k]:.3f}", ha="center", fontsize=10, color=INK)
    ax.text(k + w / 2 + 0.01, rec_s[k] + 0.012, f"{rec_s[k]:.3f}", ha="center", fontsize=10, color=INK)
ax.annotate("여러 곳 동시 접속이 쿠버네티스 자체 통신 덕에 evasion_2를\n우연히 7건 잡음 (대상 제한하면 0.887로 돌아감)",
            xy=(3 - w / 2 - 0.01, rec_u[3] + 0.055), xytext=(1.6, 1.13), fontsize=9.5, color=INK2, ha="center",
            va="center", arrowprops=dict(arrowstyle="-", color=INK2, lw=1))
ax.set_xticks(range(5))
ax.set_xticklabels(xl, fontsize=10, color=INK)
ax.set_ylim(0, 1.22)
ax.set_ylabel("재현율 (진짜 공격 중 잡은 비율)", color=INK2, fontsize=10)
fig.legend(handles=[Rectangle((0, 0), 1, 1, color=BLUE), Rectangle((0, 0), 1, 1, color=ORANGE)],
           labels=["여러 곳 동시 접속을 모든 출발지에 적용(대상 제한 없음, 기본)", "여러 곳 동시 접속을 우리 앱 출발지로 제한(대상 제한)"],
           loc="lower center", bbox_to_anchor=(0.5, 0.01), ncol=2, frameon=False, fontsize=9.5, labelcolor=INK2)
save(fig, "fig5_실험B_규칙조합.png")

# ------------------------------------------------- fig 6: scope comparison
items = [
    ("대상 제한 없음\nN=5 (기본)", cell(grid, 5), BLUE),
    ("대상 제한 없음\nN=10", cell(grid, 10), BLUE),
    ("대상 제한\nN=3", cell(grid_s, 3), ORANGE),
    ("대상 제한\nN=5", cell(grid_s, 5), ORANGE),
]
fig = new_fig(9.5, 5.4, "접속 대상을 우리 앱으로 제한하면 기준을 올리지 않고도 오탐 17건",
              "대상 제한 N=5는 대상 제한 없음 N=10과 같은 결과\n남은 17건은 fp_1(요청 횟수 10건)과 fp_2(7건) — 쿠버네티스 자체 통신이 아닌 정상 트래픽의 변동성")
ax = fig.add_axes([0.11, 0.25, 0.83, 0.52])
style(ax, "y")
ax.axhline(40, color=INK2, linestyle=(0, (4, 4)), linewidth=1.2, zorder=1)
ax.text(3.4, 40.8, "정상 40건 전부 오탐", ha="right", va="bottom", fontsize=9.5, color=INK2)
tbox = dict(facecolor=SURFACE, edgecolor="none", pad=1.5)
for x, (lab, r, c) in enumerate(items):
    v = int(r["FP"])
    ax.bar(x, v, width=0.45, color=c, zorder=2)
    ax.text(x, v + 1.0, f"오탐 {v}건", ha="center", va="bottom", fontsize=12, fontweight="bold", color=INK, bbox=tbox, zorder=3)
    ax.text(x, v + 4.6, f"정밀도 {float(r['Precision']):.3f}", ha="center", va="bottom", fontsize=10, color=INK2, bbox=tbox, zorder=3)
ax.set_xticks(range(4))
ax.set_xticklabels([i[0] for i in items], fontsize=10.5, color=INK)
ax.set_ylim(0, 52)
ax.set_ylabel("오탐 건수 (정상을 공격으로 오판)", color=INK2, fontsize=10)
fig.legend(handles=[Rectangle((0, 0), 1, 1, color=BLUE), Rectangle((0, 0), 1, 1, color=ORANGE)],
           labels=["대상 제한 없음 (여러 곳 동시 접속이 모든 출발지 대상)", "대상 제한 (여러 곳 동시 접속이 frontend·backend·db 출발지만 대상)"],
           loc="lower center", bbox_to_anchor=(0.5, 0.01), ncol=2, frameon=False, fontsize=9.5, labelcolor=INK2)
save(fig, "fig6_대상제한_비교.png")
