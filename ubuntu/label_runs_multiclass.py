#!/usr/bin/env python3
import argparse
import glob
import json
import os

import pandas as pd

PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}


def norm_day_from_path(s: str) -> str:
    s = os.path.basename(s).lower()
    for d in ["monday", "tuesday", "wednesday", "thursday", "friday"]:
        if d in s:
            return d.capitalize()
    return "Unknown"


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
        df["ts"] = df["ts"].astype("float64")

        df["label_raw"] = df["Label"].astype(str).str.strip()
        df["label_family"] = df["label_raw"].map(label_family)

        df["key"] = make_key(df["Source IP"], df["Source Port"], df["Destination IP"], df["Destination Port"], df["Protocol"])
        df["key_rev"] = make_key(df["Destination IP"], df["Destination Port"], df["Source IP"], df["Source Port"], df["Protocol"])

        dfs.append(df[["ts", "key", "key_rev", "label_family", "label_raw"]])

    lab = pd.concat(dfs, ignore_index=True)

    # Prefer attacks over benign for duplicates
    lab["is_attack"] = (lab["label_family"] != "BENIGN").astype("int8")
    lab = lab.sort_values(["is_attack"], ascending=False)

    lab = lab.drop_duplicates(subset=["ts", "key"], keep="first")
    lab = lab.drop_duplicates(subset=["ts", "key_rev"], keep="first")
    return lab


def _stable_sort_for_asof(df: pd.DataFrame, by_cols):
    # stable sort + reset index to satisfy merge_asof strictness
    df = df.sort_values(by_cols, kind="mergesort")
    return df.reset_index(drop=True)


def label_run(run_dir: str, labels_dir: str, out_dir: str, time_slop: int, tolerance_sec: int) -> str:
    run_meta = os.path.join(run_dir, "run_meta.json")
    merged_csv = os.path.join(run_dir, "merged.csv")

    with open(run_meta, "r") as f:
        meta = json.load(f)
    day = norm_day_from_path(meta.get("pcap", ""))

    lab = load_labels_for_day(labels_dir, day)

    df = pd.read_csv(merged_csv, low_memory=False)

    required = ["ts", "orig_h", "orig_p", "resp_h", "resp_p", "proto"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{merged_csv} missing columns: {missing}")

    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"]).copy()
    df["ts"] = df["ts"].astype("float64")

    df["src_ip"] = df["orig_h"].astype(str).str.strip()
    df["dst_ip"] = df["resp_h"].astype(str).str.strip()
    df["src_port"] = pd.to_numeric(df["orig_p"], errors="coerce").fillna(0).astype("int64")
    df["dst_port"] = pd.to_numeric(df["resp_p"], errors="coerce").fillna(0).astype("int64")
    df["proto_i"] = df["proto"].map(norm_proto_to_int).astype("int64")

    df["k"] = make_key(df["src_ip"], df["src_port"], df["dst_ip"], df["dst_port"], df["proto_i"]).astype(str)

    # Drop any weird empty keys
    df = df.dropna(subset=["k", "ts"]).copy()

    # Estimate offset (seconds)
    offset = int(round(float(df["ts"].min()) - float(lab["ts"].min())))
    lab2 = lab.copy()
    lab2["ts_shift"] = (lab2["ts"].astype("float64") + offset).astype("float64")

    # Normalize both directions into one column k
    fwd = lab2[["ts_shift", "key", "label_family", "label_raw"]].rename(columns={"key": "k"})
    rev = lab2[["ts_shift", "key_rev", "label_family", "label_raw"]].rename(columns={"key_rev": "k"})
    lab_any = pd.concat([fwd, rev], ignore_index=True)
    lab_any["k"] = lab_any["k"].astype(str)

    lab_any = lab_any.dropna(subset=["k", "ts_shift"]).copy()

    # STRICT sorting for merge_asof
    df = _stable_sort_for_asof(df, ["ts", "k"])
    lab_any = _stable_sort_for_asof(lab_any, ["ts_shift", "k"])

    tol = int(max(0, tolerance_sec + time_slop))

    joined = pd.merge_asof(
        df,
        lab_any,
        left_on="ts",
        right_on="ts_shift",
        by="k",
        direction="nearest",
        tolerance=tol,
    )

    joined["label_family"] = joined["label_family"].fillna("Unknown")
    joined["label_raw"] = joined["label_raw"].fillna("Unknown")
    joined["day"] = day
    joined["run_id"] = os.path.basename(run_dir.rstrip("/"))
    joined["label_time_offset_sec"] = offset
    joined["label_tol_sec"] = tol

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
    ap.add_argument("--tolerance", type=int, default=600, help="asof tolerance in seconds (try 300-1200)")
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
