import sys
import pandas as pd

path = sys.argv[1]
df = pd.read_csv(path)
df["ts"] = pd.to_datetime(df["ts"], format="ISO8601", utc=True)
fails = df[df["event"] == "login_failed"].sort_values("ts")

per_ip = fails.groupby("src_ip").agg(
    n_fails=("ts", "count"),
    span_sec=("ts", lambda s: (s.max() - s.min()).total_seconds()),
).reset_index()
per_ip = per_ip.sort_values("n_fails", ascending=False)

print("total distinct src_ip (any failed login):", len(per_ip))
print()
print("distribution of failed-login count per IP:")
print(per_ip["n_fails"].describe())
print()
print("how many IPs had only 1 failed login ever:", (per_ip["n_fails"] == 1).sum())
print("how many IPs had 2-3 failed logins:", per_ip["n_fails"].between(2, 3).sum())
print("how many IPs had 4+ failed logins:", (per_ip["n_fails"] >= 4).sum())
print()
print("top 20 IPs by failed-login count:")
print(per_ip.head(20).to_string(index=False))
