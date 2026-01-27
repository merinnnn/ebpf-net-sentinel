#!/usr/bin/env python3
import argparse, os
from datetime import datetime, timezone, timedelta
import pandas as pd

WINDOWS = {
    # Thursday
    "THU_WEB_BRUTE": ("2017-07-06", "09:10:00", "10:12:00", "WebAttack-BruteForce"),
    "THU_WEB_XSS":   ("2017-07-06", "10:13:00", "10:37:00", "WebAttack-XSS"),
    "THU_WEB_SQLI":  ("2017-07-06", "10:39:00", "10:45:00", "WebAttack-SQLi"),
    "THU_INFIL":     ("2017-07-06", "14:15:00", "15:50:00", "Infiltration"),
    # Friday
    "FRI_BOT":       ("2017-07-07", "09:30:00", "12:59:59", "Botnet"),
    "FRI_PORTSCAN":  ("2017-07-07", "12:30:00", "15:40:00", "PortScan"),
    "FRI_DDOS":      ("2017-07-07", "15:40:00", "16:30:00", "DDoS"),
}

def to_epoch(date_str: str, time_str: str, tz_offset_hours: int) -> float:
    dt_local = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
    tz = timezone(timedelta(hours=tz_offset_hours))
    return dt_local.replace(tzinfo=tz).timestamp()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_csv", required=True)
    ap.add_argument("--out_csv", required=True)
    ap.add_argument("--scenario", required=True, help=f"One of: {list(WINDOWS.keys())}")
    ap.add_argument("--tz_offset_hours", type=int, default=0,
                    help="If labeling rate looks wrong, adjust (try -5..+5).")
    ap.add_argument("--time_col", default="ts", help="Zeek ts column (epoch seconds)")
    args = ap.parse_args()

    if args.scenario not in WINDOWS:
        raise ValueError(f"Unknown scenario {args.scenario}. Options: {list(WINDOWS.keys())}")

    os.makedirs(os.path.dirname(args.out_csv), exist_ok=True)

    df = pd.read_csv(args.in_csv)
    ts = pd.to_numeric(df[args.time_col], errors="coerce")

    date_str, start_str, end_str, attack_name = WINDOWS[args.scenario]
    start_ep = to_epoch(date_str, start_str, args.tz_offset_hours)
    end_ep   = to_epoch(date_str, end_str, args.tz_offset_hours)

    df["is_attack"] = ((ts >= start_ep) & (ts <= end_ep)).astype(int)
    df["Label"] = df["is_attack"].map({0: "BENIGN", 1: attack_name})

    df.to_csv(args.out_csv, index=False)

    total = len(df)
    attacks = int(df["is_attack"].sum())
    print(f"Wrote: {args.out_csv}")
    print(f"Scenario: {args.scenario} => {attack_name}")
    print(f"Window: {date_str} {start_str} → {end_str} (tz_offset_hours={args.tz_offset_hours})")
    print(f"Attack rows: {attacks}/{total} ({attacks/total:.4f})")
    print("Zeek ts range:", float(ts.min()), "→", float(ts.max()))

if __name__ == "__main__":
    main()
