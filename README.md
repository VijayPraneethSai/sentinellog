# SentinelLog

A triage tool for SSH authentication logs: turns a stream of raw login
events into a small, ranked list of alerts an analyst can actually review,
each with a plain-English reason attached.

The problem it targets: security teams get far more auth events than they
can manually look at. A useful triage tool doesn't need to catch everything
with 100% precision — it needs to turn "review 2,000 log lines" into
"review these 20, and here's why each one is here."

## How it works

Three independent, explainable detectors, each producing a scored `Alert`
with evidence:

- **Brute-force / credential-stuffing** — bursts of failed logins in a
  trailing time window, checked on two axes: per-target-user (classic
  brute force) and per-source-IP across multiple accounts (credential
  stuffing, which spreads load thin enough to dodge a per-user-only
  counter). Alerts once per incident, not once per failed attempt.
- **Impossible travel** — a successful login whose implied travel speed
  from that user's own previous login exceeds commercial-flight speed
  (generous on purpose — this is a triage signal, not an auto-block).
- **Off-baseline login time** — a login at an hour-of-day that's rare in
  that specific user's own history, using a trailing-window baseline built
  only from data strictly before the event (no future leakage).

Detectors are kept independent rather than fused into one model so every
alert stays individually explainable — "why did this fire" always has a
one-line answer.

## Why synthetic data, not a Kaggle dataset

Public labeled SSH-attack datasets are either multi-GB raw packet captures
that need heavy preprocessing (PANDAcap, Twente 2014 — several GB each) or
sit behind auth-gated platforms. Rather than wrestle with either, this repo
generates traffic calibrated to published honeypot statistics (brute-force
attempts cluster at 3–5/sec vs ~1 event/sec for normal connections — see
Wilkens & Fischer, *IEEE CNS* 2020), with a fully labeled ground truth
attached. This is a standard move in security research when clean labeled
data isn't available, and it means every number below is checked against a
known-correct answer rather than eyeballed.

Regenerate anytime with `python data/generate_logs.py` (seeded, so the
output is reproducible).

## Results

On the bundled dataset (2,475 events, 40 users, 14 days, 40 injected attack
incidents):

| Attack type | Incidents caught |
|---|---|
| Brute force | 18/18 (100%) |
| Impossible travel | 12/12 (100%) |
| Off-baseline login time | 8/10 (80%) |
| **Overall** | **38/40 (95%)** |

Alert volume: **8.6% of events** get an alert — an analyst reviews ~1 in 12
events instead of all of them. Event-level precision is lower (~23%),
because an incident that spans dozens of log lines only needs one of them
flagged to be "caught," while the eval still counts every unflagged line in
that incident as a miss if I only credited the first alert — see
`eval.py` for the full incident-vs-event breakdown.

**Known false-positive source**, found by reading the FP sample output: a
handful of alerts are benign users whose simulated "occasional travel"
logins land close together in time with no travel-time constraint in the
generator, which genuinely does look like impossible travel to the
detector. This mirrors a real false-positive source in production
impossible-travel detectors (VPN exit-node switches, mobile network
handoffs) — documented here rather than tuned away, since hiding it would
make the eval numbers meaningless.

## Real-data validation

Beyond the synthetic eval, the unmodified pipeline was run against real
Cowrie SSH honeypot traffic in two passes. First, a single real day
exposed a real gap: the detector's original threshold, calibrated from
published automated-scanner rates, caught **zero** incidents on real
traffic, because real credential-stuffing runs slower than the rapid-fire
rate it was tuned to. Re-tuned with a window/threshold sweep
(`scripts/sweep_threshold.py`) against that day, with no regression on
the synthetic eval afterward.

Second, a **14-day real sample (59,681 login events, 855 source IPs)**
was used for a non-circular validation (`scripts/independent_validation.py`):
ground truth defined purely by total failed-login volume, sharing no
logic with the detector's own window/threshold condition. Result:
**92% recall** against that independent ground truth, with one real
miss standing out -- a single IP made 386 failed attempts over two weeks
and never once triggered the burst window, the same "low-and-slow"
pattern found in the single-day sample, now confirmed at scale. Precision
against this ground truth measured lower (31%), but most of those
"false positives" turned out to be real 4-attempt bursts that just fell
short of an admittedly arbitrary volume bar for ground truth -- a
limitation of the validation's ground-truth definition, documented
rather than hidden.

Full writeup, including what each pass does and doesn't prove, in
[`docs/real_data_validation.md`](docs/real_data_validation.md).

## Configuration

All detector thresholds live in `config.yaml`, not in code — see
`sentinellog/config.py`. Each one is documented at the point it's set,
including why it's set there.

## Usage

```bash
pip install -r requirements.txt
python data/generate_logs.py            # (re)generate the sample dataset
python cli.py report data/auth_log.csv --top 20
python eval.py                           # precision/recall against ground truth
python -m pytest tests/ -q               # unit tests per detector

# real-data validation (single day)
python -m sentinellog.adapters.cowrie data/real_sample/cowrie_2019-12-04.sample.jsonl /tmp/real.csv
python cli.py report /tmp/real.csv --top 10

# real-data validation (14 days, non-circular)
python -m sentinellog.adapters.cowrie data/real_sample_14day/*.jsonl /tmp/real14.csv
python scripts/independent_validation.py /tmp/real14.csv
```

Sample report output:

```
score  ts                         user    detector            reason
1.00   2026-10-05 06:04:04.9...   user001 brute_force         24 failed logins in 60s (target user=user001, ~0.4/s) -- incident start
1.00   2026-10-13 15:35:34        user000 impossible_travel   13505 km from previous login (Hyderabad->San Francisco) in 0.71h => implied 19043 km/h
```

## Project layout

```
sentinellog/
  baseline.py      # per-user trailing baselines (login-hour histogram, home location)
  config.py        # loads config.yaml into typed detector settings
  detectors.py     # the three detectors + Alert dataclass
  pipeline.py      # loads data, builds baselines, runs detectors, merges/ranks alerts
  adapters/
    cowrie.py       # converts real Cowrie honeypot JSON logs into the pipeline's schema
data/
  generate_logs.py  # calibrated synthetic log + label generator
  real_sample/       # single real day, filtered + attribution (see docs below)
  real_sample_14day/ # 14 contiguous real days, filtered + attribution
docs/
  real_data_validation.md  # what changed when validated against real traffic, and why
config.yaml         # all detector thresholds, documented inline
cli.py              # `report` command
eval.py             # incident-level recall + event-level precision/FP audit
scripts/
  sweep_threshold.py        # window x threshold sweep used to re-tune against real data
  characterize_ips.py       # per-source-IP failed-login counts/timing on real data
  explain_unflagged.py      # splits real attacking IPs into dense-burst vs low-and-slow
  independent_validation.py # non-circular recall/precision vs volume-only ground truth
tests/               # unit tests per detector (dense vs sparse bursts, plausible
                       vs impossible travel, baseline-confidence gating)
.github/workflows/ci.yml  # runs tests + both evals on every push
```

## Limitations / what I'd add next

- **No low-and-slow brute-force detector.** The real-data validation
  found 7 real source IPs (out of 102) spreading hundreds of failed
  attempts over many hours specifically to stay under any reasonable
  burst threshold — found and named, not fixed. The fix is a second,
  independent detector on a much longer window (e.g. 50+ failures
  against one target over 24h, regardless of density), which the current
  burst detector deliberately doesn't try to also cover, since conflating
  the two would blur what each alert means.
- Detectors are independent rule-based signals, not a fused risk score —
  good for explainability, but a real system would want a calibrated way
  to combine them.
- No real network/geo data (uses a fixed city list instead of GeoIP
  lookups) — swapping in MaxMind GeoLite2 would be a small change to
  `baseline.py`'s location lookup.
- The real-data validation only covers the brute-force detector (see
  `docs/real_data_validation.md` for why) — the other two detectors are
  checked only against the synthetic dataset so far. Next step would be
  finding a real source with geo/stable-identity signal (a real org's
  VPN or SSO logs, none of which are public for obvious reasons) to
  validate those the same way.
