# Real-data validation

The synthetic dataset (`data/generate_logs.py`) gives clean, checkable
ground truth, but it's calibrated from *published statistics about*
attacks, not from attacks themselves. This note covers what happened when
the unmodified pipeline was pointed at real honeypot capture, first for
one day, then across a non-circular validation over two weeks.

## Data source

Real Cowrie SSH/Telnet honeypot traffic from
[`0xsha/sweetie-data`](https://github.com/0xsha/sweetie-data) (MIT
licensed), a public three-month honeypot capture. Two samples are used
here:

- `data/real_sample/` -- a single day (2019-12-04), used for the initial
  threshold re-tuning below.
- `data/real_sample_14day/` -- 14 contiguous days (2019-12-03 to
  2019-12-16), matching the synthetic dataset's own 14-day window, used
  for the independent validation further down. 59,681 login events
  across 855 distinct source IPs.

Only `login.failed` / `login.success` events are kept; converted to
SentinelLog's schema with `sentinellog/adapters/cowrie.py` (`convert_many`
combines multiple daily files into one chronological stream).

Cowrie logs no geolocation, so this data only exercises the brute-force /
credential-stuffing detector -- impossible-travel and off-baseline-time
need lat/lon and a stable per-account identity, neither of which a
honeypot (attackers trying random usernames against one box) provides.

## Step 1: threshold re-tuning (single day)

The detector as originally calibrated (60s window, 6-failure threshold,
based on published automated-scanner rates of ~3-5 attempts/sec) caught
**zero** incidents on the one-day sample -- the densest real burst was 5
failures in 60 seconds. A window/threshold sweep (`scripts/sweep_threshold.py`)
led to `window=120s, threshold=4`, now the default in `config.yaml`.

## Step 2: why the first "100%" result was misleading

An initial pass (`scripts/explain_unflagged.py`) reported the retuned
detector caught 100% of "dense-burst" attacking IPs. That number is close
to circular: "dense burst" was defined as *exactly* the detector's own
firing condition (>=4 failures in any 120s window), so the result mostly
confirmed the code correctly implements its own rule -- not that the rule
is a good one. It's not worthless (it did catch real implementation bugs
along the way: timezone handling, window-boundary off-by-ones), but it
isn't real validation of detection quality.

## Step 3: independent, non-circular validation (14 days)

`scripts/independent_validation.py` fixes this: it defines "this IP is a
real attacker" using a ground truth that shares **no logic** with the
detector -- total failed-login volume across the whole 14-day sample
(>=8 failed logins total, no window or rate involved at all), then
measures the detector's recall/precision against that independent label.

```
Independent ground truth (>= 8 failed logins total, 14 days): 73 IPs
Detector flagged: 214 distinct source IPs

Recall:    67/73 real attackers caught (92%)
Precision: 67/214 flagged IPs were real attackers (31%)
```

**Recall (92%) is the headline number** and it's a real one -- no shared
logic with the detector's firing condition.

**Precision (31%) looks weak in isolation but needs context.** Most of
the 147 "false positive" IPs made exactly 4 failed attempts in a tight
burst -- which is a real automated attack by any reasonable standard (no
human fails a password 4 times in 10 seconds); they just didn't reach the
*8-total-over-14-days* ground-truth bar. That bar measures sustained
campaign size, not whether any single incident is real, so a chunk of
these "false positives" are arguably correct detections that an
imperfect ground-truth definition mislabels as noise. The honest
takeaway is that the ground-truth threshold itself needs refinement (a
per-incident definition, not a volume-over-time one) before precision
here means what it looks like it means -- flagged as a next step below,
not quietly fixed by re-running until the number looks better.

**6 real misses, found and not hidden:**

| src_ip | total failed logins (14 days) |
|---|---|
| 165.227.140.120 | 386 |
| 185.146.87.99 | 161 |
| 116.110.80.6 | 18 |
| 167.172.227.233 | 13 |
| 45.95.168.105 | 11 |
| 46.217.248.7 | 8 |

The top miss made **386 failed attempts over two weeks and never once hit
4-in-120-seconds** -- the same low-and-slow pattern found in the
single-day sample, now confirmed at larger scale and higher attempt
counts.

## Honest limitations of this validation

- The ground-truth threshold (8 total failures) is a judgment call, not
  a derived constant -- a stricter or looser bar would move both recall
  and precision. The direction of the finding (real, substantial recall;
  a genuine low-and-slow blind spot) holds across reasonable choices of
  that bar; the exact percentages would shift.
- Precision against this ground truth undercounts correct detections (see
  above) -- a fairer precision measurement needs an independent
  per-incident label, not a volume-over-time one. That's real follow-up
  work, not a rounding error.
- Still no validation for impossible-travel or off-baseline-time (no
  geo/stable-identity signal in honeypot logs). That needs a different
  real source -- e.g. a real org's VPN or SSO logs -- which aren't
  publicly available for obvious reasons.
