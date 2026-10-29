#!/usr/bin/env python3
"""CLI: python cli.py report data/auth_log.csv --top 20"""
import argparse
import sys

from sentinellog.pipeline import load_events, run_pipeline


def main():
    ap = argparse.ArgumentParser(description="SentinelLog -- auth log anomaly triage")
    ap.add_argument("command", choices=["report"])
    ap.add_argument("log_path")
    ap.add_argument("--top", type=int, default=20, help="show top-N ranked alerts")
    ap.add_argument("--min-score", type=float, default=0.0)
    args = ap.parse_args()

    df = load_events(args.log_path)
    alerts = run_pipeline(df)
    alerts = [a for a in alerts if a.score >= args.min_score][: args.top]

    print(f"\n{len(alerts)} alerts shown (of pipeline total, min_score={args.min_score})\n")
    print(f"{'score':>6}  {'ts':<26} {'user':<10} {'detector':<28} reason")
    print("-" * 110)
    for a in alerts:
        print(f"{a.score:6.2f}  {a.ts:<26} {a.user:<10} {a.detector:<28} {a.reason}")


if __name__ == "__main__":
    sys.exit(main())
