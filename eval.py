#!/usr/bin/env python3
"""
Evaluates the pipeline against ground truth, at two levels:

  - Incident-level recall: did we raise >=1 alert somewhere inside each
    labeled attack incident? This is the metric that matters for a triage
    tool -- an analyst needs ONE alert to notice an incident, not one per
    log line, so judging "did we catch the attack" per-event would wrongly
    punish correct deduplication (see detectors.detect_bruteforce).
  - Event-level precision/FP audit: of the alerts we raised, how many
    landed on a genuinely benign event with no connection to any incident?

Usage: python eval.py
"""
import pandas as pd

from sentinellog.pipeline import load_events, run_pipeline


def main():
    df = load_events("data/auth_log.csv")
    labels = pd.read_csv("data/labels.csv").set_index("event_id")
    labels["attack_id"] = labels["attack_id"].where(labels["attack_id"].notna(), None)

    alerts = run_pipeline(df)
    alerted_ids = {a.event_id: a for a in alerts}

    # --- Incident-level recall ---
    incidents = labels[labels["attack_id"].notna()].groupby("attack_id")
    n_incidents = incidents.ngroups
    caught_incidents = 0
    by_type_total, by_type_caught = {}, {}
    for aid, g in incidents:
        atype = g["label"].iloc[0].replace("_aftershock", "")
        by_type_total[atype] = by_type_total.get(atype, 0) + 1
        hit = any(eid in alerted_ids for eid in g.index)
        if hit:
            caught_incidents += 1
            by_type_caught[atype] = by_type_caught.get(atype, 0) + 1

    print("=== Incident-level recall (did the analyst get >=1 alert per real incident?) ===")
    print(f"{caught_incidents}/{n_incidents} incidents caught ({caught_incidents/n_incidents*100:.0f}%)\n")
    for atype in sorted(by_type_total):
        c = by_type_caught.get(atype, 0)
        t = by_type_total[atype]
        print(f"  {atype:<22} {c}/{t} incidents caught ({c/t*100:.0f}%)")

    # --- Event-level precision / alert volume ---
    is_attack_related = labels["attack_id"].notna()
    n_total = len(labels)
    n_alerts = len(alerted_ids)
    tp_events = sum(1 for i in alerted_ids if is_attack_related.loc[i])
    fp_events = n_alerts - tp_events

    print(f"\n=== Alert volume (triage load) ===")
    print(f"{n_alerts}/{n_total} events alerted ({n_alerts/n_total*100:.1f}%) "
          f"-- this is what an analyst has to review instead of all {n_total} events")
    print(f"of those, {tp_events} touch a real incident, {fp_events} do not "
          f"(event-level precision={tp_events/n_alerts*100:.1f}%)")

    print("\n=== Sample of events alerted with no connection to any labeled incident ===")
    shown = 0
    for i, a in alerted_ids.items():
        if not is_attack_related.loc[i]:
            print(f"  event {i}: {a.detector} score={a.score} -- {a.reason}")
            shown += 1
            if shown >= 5:
                break
    if shown == 0:
        print("  (none)")


if __name__ == "__main__":
    main()
