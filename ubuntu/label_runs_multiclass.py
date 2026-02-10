#!/usr/bin/env python3
import argparse
import glob
import json
import os

import pandas as pd

PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}


def norm_day_from_path(s: str) -> str:
    s = os.path.basename(str(s)).lower()
    for d in ["monday", "tuesday", "wednesday", "thursday", "friday"]:
        if d in s:
            return d.capitalize()
    return "Unknown"


def infer_day(run_dir: str, meta: dict) -> str:
    # 1) explicit day field if present
    for k in ("day", "Day"):
        if k in meta and meta[k]:
            d = str(meta[k]).strip()
            if d:
                return d.capitalize()

    # 2) infer from meta paths
    for k in ("pcap", "pcap_path", "pcap_in", "pcap_file"):
        v = meta.get(k, "")
        d = norm_day_from_path(v)
        if d != "Unknown":
            return d

    # 3) infer from any pcap in run dir
    for cand in glob.glob(os.path.join(run_dir, "*.pcap")):
        d = norm_day_from_path(cand)
        if d != "Unknown":
            return d

    # 4) infer from run_dir name
    d = norm_day_from_path(run_dir)
    return d


def label_family(label: str) -> str:
    if label is None:
        return "Unknown"
    x = str(label).strip().lower()
    if x in ("benign", "normal"):
        return "BENIGN"
    if "ddos" in x:
        return "DDoS"
    if "dos" in x:
        return "DoS"
    if "portscan" in x:
        return "PortScan"
    if "bot" in x:
        return "Bot"
    if "bruteforce" in x or "ssh" in x or "ftp" in x:
        return "BruteForce"
    if "web attack" in x or "webattack" in x or "sql injection" in x or "xss" in x:
        return "WebAttack"
    if "infiltration" in x:
        return "Infiltration"
    if "heartbleed" in x:
        return "Heartbleed"
    return "Other"


def read_csv_robust(fp: str) -> pd.DataFrame:
    for enc in ("utf-8", "cp1252", "latin1"):
        try:
            return pd.read_csv(fp, low_memory=False, encoding=enc)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(fp, low_memory=False, encoding="latin1")


def parse_cicids_timestamp_series(ts: pd.Series) -> pd.Series:
    s = ts.astype(str).str.strip()
    dt = pd.to_datetime(s, errors="coerce", dayfirst=True)
    if dt.isna().mean() > 0.5:
        dt2 = pd.to_datetime(s, errors="coerce", dayfirst=False)
        if dt2.notna().sum() > dt.notna().sum():
            dt = dt2
    out = (dt.astype("int64") / 1e9).where(dt.notna(), pd.NA)
    return out


def norm_proto_to_int(x) -> int:
    if pd.isna(x):
        return -1
    s = str(x).strip().lower()
    if s.isdigit():
        return int(s)
    return PROTO_MAP.get(s, -1)


def make_key(src_ip, src_port, dst_ip, dst_port, proto_i) -> pd.Series:
    return (
        src_ip.astype(str) + "|" + src_port.astype(str) + "|" +
        dst_ip.astype(str) + "|" + dst_port.astype(str) + "|" +
        proto_i.astype(str)
    )


def load_labels_for_day(labels_dir: str, day: str) -> pd.DataFrame:
    pat = os.path.join(labels_dir, f"*{day}*pcap_ISCX.csv")
    files = sorted(glob.glob(pat), key=lambda p: p.lower())
    if not files:
        pat2 = os.path.join(labels_dir, f"*{day.lower()}*pcap_ISCX.csv")
        files = sorted(glob.glob(pat2), key=lambda p: p.lower())
    if not files:
        raise FileNotFoundError(f"No label CSVs found for day={day} under {labels_dir}")

    dfs = []
    for fp in files:
        df = read_csv_robust(fp)
        df.columns = [str(c).strip() for c in df.columns]

        needed = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"]
        missing = [c for c in needed if c not in df.columns]
        if missing:
            raise ValueError(f"{fp} missing columns: {missing}")

        df = df[needed].copy()
        df["Source IP"] = df["Source IP"].astype(str).str.strip()
        df["Destination IP"] = df["Destination IP"].astype(str).str.strip()
        df["Source Port"] = pd.to_numeric(df["Source Port"], errors="coerce").fillna(0).astype("int64")
        df["Destination Port"] = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0).astype("int64")
        df["Protocol"] = pd.to_numeric(df["Protocol"], errors="coerce").fillna(-1).astype("int64")

        df["ts"] = parse_cicids_timestamp_series(df["Timestamp"])
        df = df.dropna(subset=["ts"]).copy()
        df["ts"] = df["ts"].astype("float64").round(0)

        df["label_raw"] = df["Label"].astype(str).str.strip()
        df["label_family"] = df["label_raw"].map(label_family)

        df["key"] = make_key(df["Source IP"], df["Source Port"], df["Destination IP"], df["Destination Port"], df["Protocol"])
        df["key_rev"] = make_key(df["Destination IP"], df["Destination Port"], df["Source IP"], df["Source Port"], df["Protocol"])

        dfs.append(df[["ts", "key", "key_rev", "label_family", "label_raw"]])

    lab = pd.concat(dfs, ignore_index=True)

    # Prefer attacks over benign when multiple candidates exist
    lab["is_attack"] = (lab["label_family"] != "BENIGN").astype("int8")
    lab = lab.sort_values(["is_attack"], ascending=False)

    # IMPORTANT: do NOT drop_duplicates by (ts,key) here; it kills candidates.
    return lab


def _stable_sort_for_asof(df: pd.DataFrame, by_cols):
    df = df.sort_values(by_cols, kind="mergesort")
    return df.reset_index(drop=True)


def estimate_offset_seconds(df_ts: pd.Series, lab_ts: pd.Series) -> int:
    # robust offsets from quantiles + median
    qs = [0.01, 0.05, 0.10, 0.50, 0.90]
    cands = []
    for q in qs:
        a = float(df_ts.quantile(q))
        b = float(lab_ts.quantile(q))
        if pd.notna(a) and pd.notna(b):
            cands.append(int(round(a - b)))
    a = float(df_ts.median())
    b = float(lab_ts.median())
    if pd.notna(a) and pd.notna(b):
        cands.append(int(round(a - b)))

    if not cands:
        return 0

    # pick the mode-ish (most frequent) after bucketing to 60s
    buckets = {}
    for x in cands:
        k = int(round(x / 60.0)) * 60
        buckets[k] = buckets.get(k, 0) + 1
    best = max(buckets.items(), key=lambda kv: kv[1])[0]
    return int(best)


def label_run(run_dir: str, labels_dir: str, out_dir: str, time_slop: int, tolerance_sec: int) -> str:
    run_meta = os.path.join(run_dir, "run_meta.json")
    merged_csv = os.path.join(run_dir, "merged.csv")

    with open(run_meta, "r") as f:
        meta = json.load(f)

    day = infer_day(run_dir, meta)
    lab = load_labels_for_day(labels_dir, day)

    df = pd.read_csv(merged_csv, low_memory=False)

    required = ["ts", "orig_h", "orig_p", "resp_h", "resp_p", "proto"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{merged_csv} missing columns: {missing}")

    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"]).copy()
    df["ts"] = df["ts"].astype("float64").round(0)

    df["src_ip"] = df["orig_h"].astype(str).str.strip()
    df["dst_ip"] = df["resp_h"].astype(str).str.strip()
    df["src_port"] = pd.to_numeric(df["orig_p"], errors="coerce").fillna(0).astype("int64")
    df["dst_port"] = pd.to_numeric(df["resp_p"], errors="coerce").fillna(0).astype("int64")
    df["proto_i"] = df["proto"].map(norm_proto_to_int).astype("int64")

    df["k"] = make_key(df["src_ip"], df["src_port"], df["dst_ip"], df["dst_port"], df["proto_i"]).astype(str)
    df = df.dropna(subset=["k", "ts"]).copy()

    # Better offset estimate
    offset = estimate_offset_seconds(df["ts"], lab["ts"])
    lab2 = lab.copy()
    lab2["ts_shift"] = (lab2["ts"].astype("float64") + float(offset)).astype("float64").round(0)

    # Normalize both directions into one column k
    fwd = lab2[["ts_shift", "key", "label_family", "label_raw", "is_attack"]].rename(columns={"key": "k"})
    rev = lab2[["ts_shift", "key_rev", "label_family", "label_raw", "is_attack"]].rename(columns={"key_rev": "k"})
    lab_any = pd.concat([fwd, rev], ignore_index=True)
    lab_any["k"] = lab_any["k"].astype(str)
    lab_any = lab_any.dropna(subset=["k", "ts_shift"]).copy()

    # STRICT sorting for merge_asof
    df2 = _stable_sort_for_asof(df, ["ts", "k"])
    lab_any = _stable_sort_for_asof(lab_any, ["ts_shift", "k"])

    tol = int(max(0, tolerance_sec + time_slop))

    # Two-stage join:
    # 1) Try matching ATTACK labels first (prevents benign swallowing near-misses)
    lab_attack = lab_any[lab_any["label_family"] != "BENIGN"].copy()
    lab_benign = lab_any[lab_any["label_family"] == "BENIGN"].copy()

    joined = pd.merge_asof(
        df2,
        lab_attack,
        left_on="ts",
        right_on="ts_shift",
        by="k",
        direction="nearest",
        tolerance=tol,
    )

    # 2) Fill remaining with BENIGN matches
    need = joined["label_family"].isna()
    if need.any():
        joined_need = joined.loc[need, :].copy()
        filled = pd.merge_asof(
            joined_need.drop(columns=["ts_shift", "label_family", "label_raw", "is_attack"], errors="ignore"),
            lab_benign,
            left_on="ts",
            right_on="ts_shift",
            by="k",
            direction="nearest",
            tolerance=tol,
        )
        # write back filled cols
        for c in ["ts_shift", "label_family", "label_raw", "is_attack"]:
            joined.loc[need, c] = filled[c].values

    joined["label_family"] = joined["label_family"].fillna("Unknown")
    joined["label_raw"] = joined["label_raw"].fillna("Unknown")
    joined["day"] = day
    joined["run_id"] = os.path.basename(run_dir.rstrip("/"))
    joined["label_time_offset_sec"] = int(offset)
    joined["label_tol_sec"] = int(tol)

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{joined['run_id'].iloc[0]}_labeled.parquet")
    joined.to_parquet(out_path, index=False)

    total = len(joined)
    known = (joined["label_family"] != "Unknown").sum()
    print(f"[*] {run_dir}: labeled {known}/{total} ({known/total*100:.2f}%) day={day} offset={offset}s tol={tol}s")
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--labels_dir", required=True)
    ap.add_argument("--out_dir", default="data/datasets/labeled_runs")
    ap.add_argument("--time_slop", type=int, default=10, help="extra cushion seconds on top of tolerance")
    ap.add_argument("--tolerance", type=int, default=600, help="asof tolerance in seconds (try 600-7200)")
    ap.add_argument("--combined_out", default="data/datasets/cicids2017_multiclass_zeek_ebpf.parquet")
    args = ap.parse_args()

    outs = []
    for r in args.runs:
        outs.append(label_run(r, args.labels_dir, args.out_dir, time_slop=args.time_slop, tolerance_sec=args.tolerance))

    df_all = pd.concat([pd.read_parquet(p) for p in outs], ignore_index=True)
    os.makedirs(os.path.dirname(args.combined_out), exist_ok=True)
    df_all.to_parquet(args.combined_out, index=False)
    print(f"[*] Wrote combined labeled dataset: {args.combined_out} rows={len(df_all)}")


if __name__ == "__main__":
    main()
