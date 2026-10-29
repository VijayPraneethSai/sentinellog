"""
Independent validation of the brute-force/credential-stuffing detector
against real multi-day honeypot traffic.

Why this script exists: an earlier validation pass defined "this IP is
attacking" as "this IP ever hit >=4 failures in a 120s window" -- which is
*exactly* the detector's own firing condition. Measuring the detector's
recall against that definition mostly just confirms the code implements
its own rule correctly; it's close to circular and isn't a real test of
whether the threshold is a *good* one.

This script instead defines ground truth independently of any time
window: an IP counts as "attacking" if it racked up a meaningful total
number of failed logins across the whole multi-day sample, full stop --
no window, no rate, nothing the detector's own logic depends on. That
makes "did the detector flag this IP" a real, non-circular question.

Usage: python scripts/independent_validation.py <converted.csv>
"""
import sys

import pandas as pd

sys.path.insert(0, ".")
from sentinellog.pipeline import load_events, run_pipeline

INDEPENDENT_ATTACK_THRESHOLD = 8  # total failed logins across the whole sample, any timing


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/real14.csv"
    df = load_events(path)

    fails = df[df["event"] == "login_failed"]
    total_per_ip = fails.groupby("src_ip").size()
    ground_truth_attackers = set(total_per_ip[total_per_ip >= INDEPENDENT_ATTACK_THRESHOLD].index)
    noise_ips = set(total_per_ip.index) - ground_truth_attackers

    print(f"Dataset: {len(df)} login events, {df['src_ip'].nunique()} distinct source IPs, "
          f"{fails['src_ip'].nunique()} with at least one failed login.")
    print(f"Independent ground truth (>= {INDEPENDENT_ATTACK_THRESHOLD} failed logins total, "
          f"no timing/window involved): {len(ground_truth_attackers)} IPs")
    print(f"IPs below that bar (treated as noise/recon, not a real attack campaign): {len(noise_ips)}")
    print()

    alerts = run_pipeline(df)
    flagged_ips = set()
    for a in alerts:
        ip = a.evidence.get("src_ip")
        if ip:
            flagged_ips.add(ip)
        # for the per-user axis, recover the src_ip of the matching failed logins
    # also recover src_ip for brute_force-axis alerts (keyed by user, not ip) via the
    # original data: find which IP(s) were failing against that user at that alert's time
    user_axis_alerts = [a for a in alerts if "user" in a.evidence]
    for a in user_axis_alerts:
        window = df[(df["user"] == a.user) & (df["event"] == "login_failed") &
                    (df["ts"] <= pd.Timestamp(a.ts)) &
                    (df["ts"] >= pd.Timestamp(a.ts) - pd.Timedelta(seconds=a.evidence.get("window_s", 120)))]
        flagged_ips.update(window["src_ip"].unique())

    true_positive_ips = flagged_ips & ground_truth_attackers
    false_negative_ips = ground_truth_attackers - flagged_ips
    false_positive_ips = flagged_ips & noise_ips

    recall = len(true_positive_ips) / len(ground_truth_attackers) if ground_truth_attackers else float("nan")
    precision = len(true_positive_ips) / len(flagged_ips) if flagged_ips else float("nan")

    print(f"=== Detector performance against independent ground truth ===")
    print(f"Flagged {len(flagged_ips)} distinct source IPs total.")
    print(f"Recall:    {len(true_positive_ips)}/{len(ground_truth_attackers)} real attackers caught "
          f"({recall*100:.0f}%)")
    print(f"Precision: {len(true_positive_ips)}/{len(flagged_ips)} flagged IPs were real attackers "
          f"({precision*100:.0f}%)")
    print()
    print("Missed attackers (>= threshold total failures, never flagged):")
    missed = total_per_ip[total_per_ip.index.isin(false_negative_ips)].sort_values(ascending=False)
    print(missed.to_string() if len(missed) else "  (none)")
    print()
    print("False positives (flagged but below the independent attack threshold):")
    fp = total_per_ip[total_per_ip.index.isin(false_positive_ips)].sort_values(ascending=False)
    print(fp.to_string() if len(fp) else "  (none)")


if __name__ == "__main__":
    main()
