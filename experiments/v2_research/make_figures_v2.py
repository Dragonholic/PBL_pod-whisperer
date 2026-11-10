#!/usr/bin/env python3
"""Draw the v2 result tables as figures (PNG) into experiments/v2_research/figures/.

Every number is read from experiments/v2_research/results/*.csv (written by
v2_experiments.py and v2_followup.py); nothing is typed in by hand.
Needs matplotlib and koreanize-matplotlib (bundles the NanumGothic font).
"""
import csv
import re
from pathlib import Path

import koreanize_matplotlib  # noqa: F401  (sets a Korean-capable font)
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Rectangle

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
OUT = HERE / "figures"
OUT.mkdir(exist_ok=True)

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE = "#2a78d6", "#eb6834"
SEQ = LinearSegmentedColormap.from_list("seq", ["#eef3fb", "#9fc2ef", "#2a78d6", "#123f7a"])
BLUES4 = ["#9fc2ef", "#5b9be0", "#2a78d6", "#123f7a"]  # light -> dark = k sigma 2..5


def rows(name):
    with open(RES / name, newline="") as f:
        return list(csv.DictReader(f))


def pm(s):
    """'0.526+-0.159' -> (0.526, 0.159); '0.975' -> (0.975, 0.0)."""
    m = re.match(r"\s*([\d.]+)\s*(?:\+-\s*([\d.]+))?", s)
    return float(m.group(1)), float(m.group(2) or 0)


def counts(s):
    return {k: int(v) for k, v in (p.split(":") for p in s.split(", ") if p)}


def style(ax, grid_axis="y"):
    ax.set_facecolor(SURFACE)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
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


def legend(fig, handles, labels, y=0.01, ncol=None):
    fig.legend(handles=handles, labels=labels, loc="lower center", bbox_to_anchor=(0.5, y),
               ncol=ncol or len(labels), frameon=False, fontsize=9.5, labelcolor=INK2)


def swatch(c):
    return Rectangle((0, 0), 1, 1, color=c)


def save(fig, name):
    p = OUT / name
    fig.savefig(p, dpi=200, facecolor=SURFACE)
    plt.close(fig)
    print("wrote", p.name)


def bar_labels(ax, xs, vals, fmt="{:.3f}", dy=0.012, fs=10.5, bold=False):
    for x, v in zip(xs, vals):
        ax.text(x, v + dy, fmt.format(v), ha="center", va="bottom", fontsize=fs,
                color=INK, fontweight="bold" if bold else "normal")


# ---------------------------------------------------------------- g0: E0-1
base = rows("e0_1_base_rate.csv")
fig = new_fig(9, 5.2, "공격이 드물수록 정밀도는 급격히 떨어진다 (방향성만)",
              "1차 결과(재현율 1.000, 오탐 실행 비율 0.975 / 0.425)로 공격 비율만 바꿔 다시 계산 · 단위는 실행 1회")
ax = fig.add_axes([0.10, 0.17, 0.80, 0.62])
style(ax, "y")
xs = [0.001, 0.01, 0.1, 2 / 3]
for name, color, label in (("default", BLUE, "기본 설정 (오탐 비율 0.975)"),
                           ("R4 scoped / N=10", ORANGE, "여러 곳 동시 접속 대상 제한 또는 N=10 (오탐 비율 0.425)")):
    ys = [float(r["precision"]) for r in base if r["setting"] == name]
    ys = ys[::-1]  # file order is 2/3, 10%, 1%, 0.1%
    ax.plot(xs, ys, marker="o", color=color, linewidth=2, markersize=7, label=label)
    for i, (x, y) in enumerate(zip(xs, ys)):
        if color == BLUE and i < 2:   # low points overlap: blue label goes to the right
            if i == 1:
                ax.text(x * 1.18, y - 0.002, f"{y:.3f}", ha="left", va="center", fontsize=9.5, color=INK)
            continue
        txt = f"{y:.3f}" + (" (기본 0.001)" if i == 0 else "")
        ax.text(x, y + 0.035, txt, ha="center", fontsize=9.5, color=INK)
ax.set_xscale("log")
ax.set_xticks(xs)
ax.set_xticklabels(["0.1%", "1%", "10%", "2/3\n(1차 구성)"], fontsize=10.5, color=INK)
ax.minorticks_off()
ax.set_ylim(0, 1.0)
ax.set_xlabel("전체 중 공격의 비율", color=INK2, fontsize=10)
ax.set_ylabel("정밀도", color=INK2, fontsize=10)
legend(fig, [plt.Line2D([0], [0], color=BLUE, lw=2, marker="o"), plt.Line2D([0], [0], color=ORANGE, lw=2, marker="o")],
       ["기본 설정 (오탐 비율 0.975)", "대상 제한 또는 N=10 (오탐 비율 0.425)"])
save(fig, "v2_g0_공격비율별_정밀도.png")

# ---------------------------------------------------------------- g1: E0-2 / E2-1
e02 = [r for r in rows("e0_2_unit_and_label.csv") if r["label policy"] == "B"]
prec = {r["rules"]: float(r["alert precision"]) for r in e02}
r6 = {r["rule"]: float(r["alert precision (B)"]) for r in rows("e2_1_r6.csv")}
items = [("관리용 포트 (R3)", prec["R3 alone"]), ("연속 접속 실패 (R6, 2차 신규)", r6["R6 alone"]),
         ("차단된 접속 (R1)", prec["R1 alone"]), ("처음 보는 통신 (R2)", prec["R2 alone"]),
         ("여러 곳 동시 접속 (R4)", prec["R4 alone"]), ("요청 횟수 (R5)", prec["R5 alone"])]
fig = new_fig(10, 5.4, "경보 단위로 보면 R4·R5가 오탐 경보 대부분을 만든다",
              "규칙 하나만 켰을 때 경보 중 실제 공격 접속에 해당하는 비율 (라벨 정책 B) · 점선 = 전체 R1~R5 합산")
ax = fig.add_axes([0.28, 0.14, 0.68, 0.62])
style(ax, "x")
ys = list(range(len(items)))[::-1]
for y, (lab, v) in zip(ys, items):
    ax.barh(y, v, height=0.55, color=BLUE)
    ax.text(v + 0.012, y, f"{v:.3f}", va="center", fontsize=11, color=INK, fontweight="bold")
ax.axvline(prec["R1-R5 (v1 default)"], color=INK2, linestyle=(0, (4, 4)), linewidth=1.2)
ax.text(prec["R1-R5 (v1 default)"] + 0.01, len(items) - 0.45, f"전체 합산 {prec['R1-R5 (v1 default)']:.3f}",
        fontsize=9.5, color=INK2, va="bottom")
ax.set_yticks(ys)
ax.set_yticklabels([i[0] for i in items], fontsize=10.5, color=INK)
ax.set_xlim(0, 1.12)
ax.set_xlabel("경보 정밀도", color=INK2, fontsize=10)
save(fig, "v2_g1_규칙별_경보정밀도.png")

# ---------------------------------------------------------------- g2: E0-3
agg = rows("e0_3_aggregation.csv")
sets = [("R1-R5 (v1 default)", "대상 제한 없음 (1차 기본)", BLUE), ("R1-R5, R4 scoped", "여러 곳 동시 접속 대상 제한", ORANGE)]
fig = new_fig(11, 5.2, "경보를 묶으면 개수는 34~60% 줄지만, 사건 정밀도는 오르지 않는다",
              "같은 (규칙, 출발지, 목적지, 포트) 경보를 시간 범위 안에서 1건으로 합침 · 정밀도는 라벨 정책 B")
wins = [0, 2, 120]
wl = ["합치지 않음", "2초", "120초"]
for k, (key, lab, c) in enumerate(sets):
    pass
axA = fig.add_axes([0.07, 0.17, 0.40, 0.60])
axB = fig.add_axes([0.58, 0.17, 0.40, 0.60])
for ax, col, ttl, fmtv, ylim in ((axA, "incidents", "사건 수 (건)", "{:,.0f}", None), (axB, "incident precision (policy B)", "사건 정밀도", "{:.3f}", (0, 1.0))):
    style(ax, "y")
    w = 0.36
    for k, (key, lab, c) in enumerate(sets):
        vals = [float(next(r for r in agg if r["rules"] == key and int(r["merge window (s)"]) == win)[col]) for win in wins]
        xs = [i + (k - 0.5) * (w + 0.02) for i in range(3)]
        ax.bar(xs, vals, width=w, color=c)
        top = max(vals) if ylim is None else 1.0
        for x, v in zip(xs, vals):
            ax.text(x, v + top * 0.012, fmtv.format(v), ha="center", va="bottom", fontsize=9)
    ax.set_xticks(range(3))
    ax.set_xticklabels(wl, fontsize=10.5, color=INK)
    ax.set_title(ttl, fontsize=11, color=INK, loc="left")
    if ylim:
        ax.set_ylim(*ylim)
    else:
        ax.set_ylim(0, 11000)
legend(fig, [swatch(c) for _, _, c in sets], [lab for _, lab, _ in sets])
save(fig, "v2_g2_경보집계.png")

# ---------------------------------------------------------------- g3: E0-4b
lk = next(r for r in rows("e0_4b_like_for_like.csv") if r["rule set"] == "any rule")
fp10 = int(lk["fp_1-3 flagged, learn 10"].split("/")[0]) / 30
fp5, fp5sd = pm(lk["fp_1-3 flagged, learn 5"])
nm5, nm5sd = pm(lk["normal flagged, learn 5"])
fig = new_fig(9.5, 5.4, "학습에서 뺀 정상은 44%가 오탐 — 1차에서는 가려져 있었다",
              "여러 곳 동시 접속을 우리 앱으로 제한한 설정, 모든 규칙 · 학습 5회는 무작위 30번 평균(막대 위 선 = 표준편차)")
ax = fig.add_axes([0.10, 0.17, 0.86, 0.60])
style(ax, "y")
cats = ["정상(normal)\n(학습 10회 때는 학습에 쓴 것, 5회 때는 뺀 것)", "fp_1~3 (정상 변형 30회)"]
v10 = [0.0, fp10]
v5 = [nm5 / 5, fp5 / 30]
sd5 = [nm5sd / 5, fp5sd / 30]
w = 0.34
x10 = [0 - w / 2 - 0.01, 1 - w / 2 - 0.01]
x5 = [0 + w / 2 + 0.01, 1 + w / 2 + 0.01]
ax.bar(x10, v10, width=w, color=BLUE)
ax.bar(x5, v5, width=w, color=ORANGE, yerr=sd5, error_kw=dict(ecolor=INK2, lw=1.2, capsize=4))
for x, v in zip(x10, v10):
    ax.text(x, v + 0.015, f"{v:.0%}", ha="center", fontsize=11, fontweight="bold", color=INK)
for x, v, s in zip(x5, v5, sd5):
    ax.text(x + 0.09, v + s + 0.015, f"{v:.0%}", ha="center", fontsize=11, fontweight="bold", color=INK)
ax.set_xticks([0, 1])
ax.set_xticklabels(cats, fontsize=10, color=INK)
ax.set_ylim(0, 1.0)
ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
ax.set_ylabel("경보가 하나라도 걸린 실행의 비율", color=INK2, fontsize=10)
legend(fig, [swatch(BLUE), swatch(ORANGE)], ["정상 10회로 학습 (1차 방식)", "정상 5회로 학습 (나머지로 평가)"])
save(fig, "v2_g3_학습평가분리.png")

# ---------------------------------------------------------------- g4: E0-5
r5 = rows("e0_5_r5_sensitivity.csv")
fig = new_fig(10, 5.4, "요청 횟수 규칙: 학습이 적을수록 오탐이 늘고, 기준을 높여도 조금만 준다",
              "요청 횟수 규칙(R5)만 켰을 때 정상 실행의 오탐 비율 · 막대 위 선 = 표준편차, evasion_2 탐지는 12개 설정 모두 100%")
ax = fig.add_axes([0.08, 0.17, 0.89, 0.60])
style(ax, "y")
w = 0.19
for j, k in enumerate((2, 3, 4, 5)):
    vals, sds = [], []
    for n in (3, 5, 10):
        r = next(x for x in r5 if int(x["learning runs"]) == n and int(x["k sigma"]) == k)
        v, s = pm(r["R5 false-alarm run rate"])
        vals.append(v)
        sds.append(s)
    xs = [i + (j - 1.5) * (w + 0.01) for i in range(3)]
    ax.bar(xs, vals, width=w, color=BLUES4[j], yerr=sds, error_kw=dict(ecolor=INK2, lw=1, capsize=3))
    for x, v, s in zip(xs, vals, sds):
        ax.text(x, v + s + 0.01, f"{v:.2f}", ha="center", fontsize=8.5, color=INK)
ax.set_xticks(range(3))
ax.set_xticklabels(["학습 3회", "학습 5회", "학습 10회\n(학습에서 뺀 정상이 없어 fp만 평가)"], fontsize=10, color=INK)
ax.set_ylim(0, 0.85)
ax.set_ylabel("오탐 비율", color=INK2, fontsize=10)
legend(fig, [swatch(c) for c in BLUES4], ["평균+2σ", "평균+3σ (1차)", "평균+4σ", "평균+5σ"])
save(fig, "v2_g4_요청횟수_민감도.png")

# ---------------------------------------------------------------- g5: E0-6
cov = rows("e0_6b_port_coverage.csv")
names = {"v1 list": "1차 목록", "official table + NodePort": "공식 표 + NodePort 범위",
         "official + 443": "공식 표 + NodePort + 443",
         "v1 minus non-Kubernetes (22, 3306, 6379)": "1차 목록에서 쿠버네티스 포트\n아닌 것(22, 3306, 6379) 뺌"}
fig = new_fig(10, 5.4, "관리용 포트 목록: 실행 단위로는 똑같지만 포트 단위로는 공식 표만 쓰면 32%만 잡는다",
              "관리용 포트 규칙(R3)만 켰을 때 공격 접속 경로 중 경보가 달린 비율 (라벨 정책 B) · 4개 목록 모두 실행 단위 결과는 동일(공격 40/80, 정상 0/40)")
ax = fig.add_axes([0.08, 0.20, 0.89, 0.55])
style(ax, "y")
vals = [float(r["path recall (B)"]) for r in cov]
xs = range(len(cov))
ax.bar(xs, vals, width=0.5, color=BLUE)
bar_labels(ax, xs, vals, fmt="{:.3f}", fs=11.5, bold=True)
ax.set_xticks(list(xs))
ax.set_xticklabels([names[r["R3 list"]] for r in cov], fontsize=10, color=INK)
ax.set_ylim(0, 1.05)
ax.set_ylabel("경로 재현율", color=INK2, fontsize=10)
fig.text(0.04, 0.045, "※ 22, 443, 3306, 6379는 과제가 제공한 abnormal_3이 스캔하는 포트라 1차 목록과 시나리오가 서로 맞춰져 있을 가능성이 있다 (공식 표가 틀렸다는 뜻이 아님)",
         fontsize=9.5, color=INK2)
save(fig, "v2_g5_관리용포트목록.png")

# ---------------------------------------------------------------- g6: E2-1 heatmap
r61 = {r["rule"]: counts(r["runs flagged by scenario"]) for r in rows("e2_1_r6.csv")}
cols = [("여러 곳 동시 접속\n(1차, 제한 없음)", r61["R4 alone (v1)"]), ("여러 곳 동시 접속\n(우리 앱만)", r61["R4 alone, scoped"]),
        ("연속 접속 실패\n(R6, 2차 신규)", r61["R6 alone"])]
order = ["abnormal_1", "abnormal_2", "abnormal_3", "k8s_1", "k8s_2", "k8s_3", "evasion_1", "evasion_2", "normal", "fp_1", "fp_2", "fp_3"]
nat = 8
fig = new_fig(9.5, 8.2, "R6는 정상에서 한 번도 울리지 않지만, 잡는 공격은 3개뿐이다",
              "규칙 하나만 켰을 때 10회 중 경보가 걸린 실행 수 · 위 8개 = 공격, 아래 4개 = 정상(걸리면 오탐)")
ax = fig.add_axes([0.22, 0.10, 0.68, 0.70])
for i, s in enumerate(order):
    for j, (_, d) in enumerate(cols):
        v = d.get(s, 0)
        ax.add_patch(Rectangle((j, len(order) - 1 - i), 1, 1, facecolor=SEQ(v / 10), edgecolor=SURFACE, linewidth=2))
        ax.text(j + 0.5, len(order) - 1 - i + 0.5, str(v), ha="center", va="center", fontsize=11,
                color="white" if v / 10 > 0.45 else INK)
ax.axhline(len(order) - nat, color=INK2, linewidth=1.2)
ax.set_xlim(0, 3)
ax.set_ylim(0, len(order))
ax.set_xticks([j + 0.5 for j in range(3)])
ax.set_xticklabels([c[0] for c in cols], fontsize=10, color=INK)
ax.xaxis.tick_top()
ax.set_yticks([len(order) - 1 - i + 0.5 for i in range(len(order))])
ax.set_yticklabels(order, fontsize=10.5, color=INK)
ax.tick_params(length=0)
for sp in ax.spines.values():
    sp.set_visible(False)
fig.text(0.04, 0.045, "R6가 놓친 공격: abnormal_1, abnormal_2, k8s_1, k8s_3, evasion_2 (원인은 아직 확인하지 않음)", fontsize=9.5, color=INK2)
save(fig, "v2_g6_R6_시나리오별.png")

# ---------------------------------------------------------------- g7: E2-2
grid = rows("e2_2_r4_grid.csv")
Ws = [10, 60, 300]


def g(scope, n, w):
    return next(r for r in grid if r["R4 scope"] == scope and int(r["N"]) == n and int(r["W (s)"]) == w)


det_scoped = [int(g("known apps", 5, w)["evasion_1"].split("/")[0]) * 10 for w in Ws]
fp_scoped = [int(g("known apps", 5, w)["normal runs flagged (of 40)"]) / 40 * 100 for w in Ws]
fp_none = [int(g("none", 5, w)["normal runs flagged (of 40)"]) / 40 * 100 for w in Ws]
fig = new_fig(10, 5.4, "저속 스캔(evasion_1)은 시간 범위를 60초로만 늘려도 잡히고, 정상 오탐은 늘지 않는다",
              "여러 곳 동시 접속 규칙(R4)만 켠 경우, 기준 개수 N=5 · 막대 위 숫자는 %")
ax = fig.add_axes([0.08, 0.17, 0.89, 0.60])
style(ax, "y")
w = 0.26
series = [(det_scoped, BLUE, "우리 앱만: evasion_1 탐지율"), (fp_scoped, ORANGE, "우리 앱만: 정상 오탐 비율"), (fp_none, INK2, "제한 없음: 정상 오탐 비율")]
for j, (vals, c, _) in enumerate(series):
    xs = [i + (j - 1) * (w + 0.02) for i in range(3)]
    ax.bar(xs, vals, width=w, color=c)
    for x, v in zip(xs, vals):
        ax.text(x, v + 1.5, f"{v:.0f}", ha="center", fontsize=10, color=INK)
ax.set_xticks(range(3))
ax.set_xticklabels([f"시간 범위 {x}초" for x in Ws], fontsize=11, color=INK)
ax.set_ylim(0, 110)
ax.set_ylabel("%", color=INK2, fontsize=10)
legend(fig, [swatch(c) for _, c, _ in series], [s[2] for s in series])
save(fig, "v2_g7_R4_시간범위.png")

# ---------------------------------------------------------------- g8: combo
cb = rows("combo.csv")
lab = ["K1\n1차 기본\n(R1~R5)", "K2\nR4 대상 제한\n(R1~R5)", "K3\nR4를 R6로 교체\n(R1,R2,R3,R5,R6)", "K4\nR1~R6\nR4·R6 대상 제한"]
fig = new_fig(11, 5.4, "대상 제한이 오탐 감소의 거의 전부이고, R6를 넣거나 R4를 R6로 바꿔도 같다",
              "학습 5회 / 나머지로 평가, 무작위 30번 평균 (막대 위 선 = 표준편차) · 재현율은 4개 조합 모두 1.000")
axA = fig.add_axes([0.07, 0.20, 0.40, 0.55])
axB = fig.add_axes([0.58, 0.20, 0.40, 0.55])
for ax, col, ttl in ((axA, "false-alarm run rate (held-out normal + fp)", "오탐 실행 비율 (낮을수록 좋음)"),
                     (axB, "alert precision (policy B)", "경보 정밀도 (높을수록 좋음)")):
    style(ax, "y")
    vals, sds = zip(*[pm(r[col]) for r in cb])
    xs = range(4)
    ax.bar(xs, vals, width=0.55, color=[ORANGE, BLUE, BLUE, BLUE], yerr=sds, error_kw=dict(ecolor=INK2, lw=1.2, capsize=4))
    for x, v, s in zip(xs, vals, sds):
        ax.text(x, v + s + 0.015, f"{v:.3f}", ha="center", fontsize=10, fontweight="bold", color=INK)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(lab, fontsize=8.6, color=INK)
    ax.set_ylim(0, 1.1)
    ax.set_title(ttl, fontsize=11, color=INK, loc="left")
legend(fig, [swatch(ORANGE), swatch(BLUE)], ["1차 기본 조합", "2차 조합"])
save(fig, "v2_g8_조합비교.png")
