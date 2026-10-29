# Real-data validation

The synthetic dataset (`data/generate_logs.py`) gives clean, checkable
ground truth, but it's calibrated from *published statistics about*
attacks, not from attacks themselves. This note covers what happened when
the unmodified pipeline was pointed at a real honeypot capture.

## Data source

A one-day slice (2019-12-04) of real Cowrie SSH/Telnet honeypot traffic
from [`0xsha/sweetie-data`](https://github.com/0xsha/sweetie-data) (MIT
licensed), a public three-month honeypot capture. Only `login.failed` /
`login.success` events are used; the committed sample
(`data/real_sample/cowrie_2019-12-04.sample.jsonl`) is pre-filtered to
those 1,465 events out of the much larger raw daily log. Converted to
SentinelLog's schema with `sentinellog/adapters/cowrie.py`.

Cowrie logs no geolocation, so this data only exercises the brute-force /
credential-stuffing detector -- impossible-travel and off-baseline-time
need lat/lon and a stable per-account identity, neither of which a
honeypot (attackers trying random usernames against one box) provides.
That's a real scope limit of this validation, not a bug: it tells you
whether the burst detector generalizes to genuine attacker traffic, not
whether the geo/time detectors do.

## What changed

The detector as originally calibrated (60s window, 6-failure threshold,
based on published automated-scanner rates of ~3-5 attempts/sec) caught
**zero** incidents on this real sample. Checking why: the densest real
burst in the whole day was 5 failures in 60 seconds. Real opportunistic
credential-stuffing here runs closer to ~1 attempt/sec with 4-5 guesses
per session, not the rapid-fire automated-scanner rate the synthetic data
was calibrated to.

A window/threshold sweep (`scripts/sweep_threshold.py`) over the real sample:

| window | thresh=3 | thresh=4 | thresh=5 | thresh=6 |
|---|---|---|---|---|
| 60s  | 26 IPs | 11 IPs | 1 IP | 0 IPs |
| 120s | 28 IPs | 13 IPs | 1 IP | 1 IP |
| 300s | 29 IPs | 14 IPs | 3 IPs | 3 IPs |

(out of 102 distinct source IPs in the sample)

`window=120s, threshold=4` was chosen: it catches a meaningfully larger
slice of real attacker IPs than the original setting without the
threshold getting so loose that occasional-failed-login noise would
start tripping it (threshold=3 roughly doubles the catch again, but
starts looking more like "logged in wrong more than twice," which is
closer to ordinary user error than an attack signal).

This is now the default in `config.yaml`. Re-running the full synthetic
eval (`eval.py`) after the change showed no regression -- synthetic
brute-force incidents are dense enough (25-90 rapid attempts) that they
still trip the looser threshold immediately, so the real-world retune
cost nothing on the calibration data it was originally checked against.

## Result on the real sample (post-retune)

```
$ python cli.py report data/real_sample/cowrie_2019-12-04.converted.csv
```

99 alerts across 1,465 login events (9 distinct attacking source IPs,
several of which mount repeated bursts through the day rather than one
continuous one -- e.g. source IP `144.91.113.246` alone accounts for
several separate incident-start alerts as it pauses and resumes). No
ground-truth labels exist for this data (a honeypot box receives no
legitimate traffic, so there's no benign baseline to compute precision
against) -- this validation checks generalization and realistic
threshold-setting, not precision/recall. That's the synthetic dataset's
job, and it's unaffected by this change (see `eval.py` output: still
38/40 incidents, 95%, after the retune).

## Honest limitations of this validation

- One day, one honeypot, no labels -- this confirms the detector reacts
  sensibly to real attacker behavior, not that 120s/4 is the universally
  correct setting. A production deployment would want this tuned against
  its own traffic.
- No impossible-travel or off-baseline-time validation against real data
  (no geo/stable-identity signal in honeypot logs, as noted above). That
  would need a different real source -- e.g. a real org's VPN or SSO logs
  -- which aren't publicly available for obvious reasons.
