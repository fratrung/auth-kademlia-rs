#!/usr/bin/env python3
"""
Degradation sweep — acceptance rate, p95 latency and throughput vs attacker concurrency.

For each concurrency level runs the resilience test RUNS times, computes
mean ± 95% t-CI, then plots and saves the degradation curves.

Usage (from auth-kademlia-rs/resilience/):
    python3 degradation_sweep.py                          # defaults
    python3 degradation_sweep.py --levels 5 10 25 50 100 --runs 5
    python3 degradation_sweep.py --no-build               # skip initial docker build

Output:
    resilience/degradation.json   raw data + stats
    resilience/degradation.png    plot (requires matplotlib)
"""

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

COMPOSE_DIR   = Path(__file__).parent
OVERRIDE_FILE = COMPOSE_DIR / "docker-compose.override.yml"

DEFAULT_LEVELS = [5, 10, 20, 30, 50, 75, 100]


# ── t-CI (self-contained, same logic as run_stats.py) ─────────────────────────

def _t_ppf(alpha_half: float, df: int) -> float:
    try:
        from scipy.stats import t as _t
        return float(_t.ppf(1.0 - alpha_half, df))
    except ImportError:
        pass
    TABLE = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447,  7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        12: 2.179, 15: 2.131, 20: 2.086, 30: 2.042, 60: 2.000,
    }
    keys = sorted(TABLE)
    for i, k in enumerate(keys):
        if df <= k:
            if i == 0:
                return TABLE[k]
            k0, k1 = keys[i - 1], k
            return TABLE[k0] + (TABLE[k1] - TABLE[k0]) * (df - k0) / (k1 - k0)
    return 1.960


def describe(samples: list, confidence: float = 0.95) -> dict:
    n = len(samples)
    mean = sum(samples) / n
    if n < 2:
        return {"mean": mean, "std": 0.0, "ci_half": 0.0}
    var  = sum((x - mean) ** 2 for x in samples) / (n - 1)
    std  = math.sqrt(var)
    sem  = std / math.sqrt(n)
    tc   = _t_ppf((1.0 - confidence) / 2.0, n - 1)
    return {"mean": mean, "std": std, "ci_half": tc * sem}


# ── Docker helpers ─────────────────────────────────────────────────────────────

def _write_override(concurrency: int):
    OVERRIDE_FILE.write_text(
        "services:\n"
        "  node_b:\n"
        "    environment:\n"
        f"      - CONCURRENCY={concurrency}\n"
    )


def _remove_override():
    OVERRIDE_FILE.unlink(missing_ok=True)


def docker_run(concurrency: int, build: bool) -> dict | None:
    _write_override(concurrency)
    try:
        subprocess.run(
            ["docker", "compose", "down", "--remove-orphans"],
            cwd=COMPOSE_DIR, capture_output=True,
        )
        cmd = ["docker", "compose", "up", "--abort-on-container-exit"]
        if build:
            cmd.append("--build")
        proc = subprocess.run(cmd, cwd=COMPOSE_DIR, capture_output=True, text=True)
        marker = "METRICS_JSON "
        for line in reversed((proc.stdout + proc.stderr).splitlines()):
            idx = line.find(marker)
            if idx != -1:
                try:
                    return json.loads(line[idx + len(marker):])
                except json.JSONDecodeError:
                    pass
    finally:
        _remove_override()
    return None


# ── Sweep ──────────────────────────────────────────────────────────────────────

def sweep(levels: list, runs: int, confidence: float, no_build: bool) -> list:
    """
    Returns a list of dicts, one per concurrency level:
        { concurrency, acceptance, store_p95, store_tps }
    each containing mean, std, ci_half.
    """
    results = []
    first_build_done = no_build

    for level in levels:
        print(f"\n  concurrency={level:>3}  ({runs} runs)")
        samples = {"acceptance": [], "store_p95": [], "store_tps": []}

        for r in range(runs):
            build = (not first_build_done) and (r == 0)
            if build:
                first_build_done = True
            tag = "(build)" if build else "      "
            print(f"    run {r + 1}/{runs} {tag} … ", end="", flush=True)

            m = docker_run(level, build)
            if m is None:
                print("FAILED")
                continue

            total = m["p1_accepted"] + m["p1_rejected"] + m["p1_timeout"]
            acc   = m["p1_accepted"] / total * 100 if total else 0.0
            samples["acceptance"].append(acc)
            samples["store_p95"].append(m["p1_p95_ms"])
            samples["store_tps"].append(m["p1_tps"])
            print(f"ok  acceptance={acc:.1f}%  p95={m['p1_p95_ms']:.1f}ms")

        if len(samples["acceptance"]) < 1:
            print(f"    all runs failed — skipping level {level}")
            continue

        entry = {"concurrency": level}
        for key, vals in samples.items():
            entry[key] = describe(vals, confidence)
        results.append(entry)

    return results


# ── Plot ───────────────────────────────────────────────────────────────────────

def plot(results: list, confidence: float, out_path: Path):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not found — install with: pip install matplotlib")
        print("Skipping plot; raw data saved to degradation.json")
        return

    x     = [r["concurrency"]              for r in results]
    acc   = [r["acceptance"]["mean"]        for r in results]
    acc_e = [r["acceptance"]["ci_half"]     for r in results]
    p95   = [r["store_p95"]["mean"]         for r in results]
    p95_e = [r["store_p95"]["ci_half"]      for r in results]
    tps   = [r["store_tps"]["mean"]         for r in results]
    tps_e = [r["store_tps"]["ci_half"]      for r in results]

    fig, axes = plt.subplots(3, 1, figsize=(8, 10), sharex=True)
    fig.suptitle(
        f"Resilience degradation vs attacker concurrency\n"
        f"(victim: 2 CPU, ML-DSA-65 — error bars: {int(confidence*100)}% t-CI)",
        fontsize=12,
    )

    kw = dict(fmt="-o", capsize=4, linewidth=1.5, markersize=5)

    axes[0].errorbar(x, acc, yerr=acc_e, color="steelblue", **kw)
    axes[0].set_ylabel("Acceptance rate (%)")
    axes[0].set_ylim(0, 105)
    axes[0].axhline(100, color="gray", linestyle="--", linewidth=0.8)
    axes[0].grid(True, alpha=0.3)

    axes[1].errorbar(x, p95, yerr=p95_e, color="darkorange", **kw)
    axes[1].set_ylabel("Store p95 latency (ms)")
    axes[1].grid(True, alpha=0.3)

    axes[2].errorbar(x, tps, yerr=tps_e, color="seagreen", **kw)
    axes[2].set_ylabel("Store throughput (ops/s)")
    axes[2].set_xlabel("Attacker concurrency")
    axes[2].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    print(f"\nPlot saved → {out_path}")
    plt.show()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--levels",     nargs="+", type=int, default=DEFAULT_LEVELS,
                    metavar="N",    help="concurrency values to sweep")
    ap.add_argument("--runs",       type=int,  default=3,
                    help="runs per concurrency level (default: 3)")
    ap.add_argument("--confidence", type=float, default=0.95)
    ap.add_argument("--no-build",   action="store_true")
    args = ap.parse_args()

    print(f"Degradation sweep — levels={args.levels}  "
          f"runs/level={args.runs}  CI={args.confidence*100:.0f}%")

    results = []
    try:
        results = sweep(args.levels, args.runs, args.confidence, args.no_build)
    except KeyboardInterrupt:
        print("\n\nInterrupted — saving collected data…")

    if not results:
        print("No data collected.")
        sys.exit(1)

    out_json = COMPOSE_DIR / "degradation.json"
    out_json.write_text(json.dumps(
        {"confidence": args.confidence, "runs_per_level": args.runs, "results": results},
        indent=2,
    ))
    print(f"\nData saved → {out_json}")

    plot(results, args.confidence, COMPOSE_DIR / "degradation.png")


if __name__ == "__main__":
    main()
