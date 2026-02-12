#!/usr/bin/env python3
import argparse
import glob
import json
import os
import time
from typing import List, Tuple, Optional

import pandas as pd

PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
HALFDAY_SHIFTS = [0, 43200, -43200]


def norm_day_from_path(s: str) -> str:
    s = os.path.basename(str(s)).lower()
    for d in DAYS:
        if d.lower() in s:
            return d
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
    if "bruteforce" in x or "ssh" in x or "ftp" in x or "patator" in x:
        return "BruteForce"
    if "web attack" in x or "webattack" in x or "sql injection" in x or "xss" in x:
        return "WebAttack"
    if "infiltration" in x:
        return "Infiltration"
    if "heartbleed" in x:
        return "Heartbleed"
    return "Other"


def read_csv_robust(fp: str, usecols=None) -> pd.DataFrame:
    for enc in ("utf-8", "cp1252", "latin1"):
        try:
            return pd.read_csv(fp, low_memory=False, encoding=enc, usecols=usecols)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(fp, low_memory=False, encoding="latin1", usecols=usecols)


def parse_cicids_timestamp_series(ts: pd.Series) -> pd.Series:
    s = ts.astype(str).str.strip()
    dt1 = pd.to_datetime(s, errors="coerce", dayfirst=True)
    ok1 = int(dt1.notna().sum())
    dt2 = pd.to_datetime(s, errors="coerce", dayfirst=False)
    ok2 = int(dt2.notna().sum())
    dt = dt1 if ok1 >= ok2 else dt2
    out = (dt.astype("int64") / 1e9).where(dt.notna(), pd.NA)
    return out


def maybe_shift_afternoon_filename_12h(df: pd.DataFrame, src_fp: str) -> pd.DataFrame:
    """
    CICIDS2017 'Afternoon' label CSVs can encode 1pm..5pm as 1:00..5:00 (no AM/PM).
    If filename contains 'Afternoon' and the median hour < 12, shift by +12h.
    """
    base = os.path.basename(src_fp).lower()
    if "afternoon" not in base:
        return df

    dt = pd.to_datetime(df["Timestamp"].astype(str).str.strip(), errors="coerce", dayfirst=True)
    hrs = dt.dt.hour.dropna()
    if len(hrs) == 0:
        return df

    if float(hrs.median()) < 12.0:
        df = df.copy()
        df["ts"] = df["ts"].astype("float64") + 12.0 * 3600.0
        print(f"    [!] afternoon timestamp fix: +12h applied ({os.path.basename(src_fp)})")
    return df


def maybe_shift_workinghours_rows_12h(df: pd.DataFrame, src_fp: str) -> pd.DataFrame:
    """
    WorkingHours CSVs (Mon/Tue/Wed) can contain PM times written without AM/PM (e.g. 1:00 meaning 13:00).
    Safe fix: shift ONLY rows whose parsed hour is in [1..6] by +12h, BUT never apply this to 'Afternoon' files
    (those are handled by maybe_shift_afternoon_filename_12h).
    """
    base = os.path.basename(src_fp).lower()

    # Avoid double shifting Afternoon files
    if "afternoon" in base:
        return df

    # Trigger on 'workinghours' filenames
    if "workinghours" not in base.replace("-", ""):
        return df

    dt = pd.to_datetime(df["Timestamp"].astype(str).str.strip(), errors="coerce", dayfirst=True)
    hrs = dt.dt.hour
    if hrs.isna().all():
        return df

    suspicious = hrs.between(1, 6, inclusive="both")
    frac = float(suspicious.mean())

    # Only apply if it's a meaningful chunk (prevents accidental shifting)
    if frac < 0.03:
        return df

    df = df.copy()
    df.loc[suspicious.fillna(False), "ts"] = df.loc[suspicious.fillna(False), "ts"].astype("float64") + 12.0 * 3600.0
    print(f"    [!] workinghours row PM-fix: +12h applied to {int(suspicious.sum())} rows ({frac*100:.2f}%) ({os.path.basename(src_fp)})")
    return df


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


def _stable_sort_for_asof(df: pd.DataFrame, by_cols: List[str]) -> pd.DataFrame:
    df = df.sort_values(by_cols, kind="mergesort")
    return df.reset_index(drop=True)


def find_label_files_for_day(labels_dir: str, day: str) -> List[str]:
    pats = [
        os.path.join(labels_dir, f"*{day}*pcap_ISCX.csv"),
        os.path.join(labels_dir, f"*{day.lower()}*pcap_ISCX.csv"),
    ]
    out: List[str] = []
    for pat in pats:
        out.extend(glob.glob(pat))
    return sorted(set(out), key=lambda p: p.lower())


def load_labels_for_day(labels_dir: str, day: str) -> pd.DataFrame:
    files = find_label_files_for_day(labels_dir, day)
    if not files:
        raise FileNotFoundError(f"No label CSVs found for day={day} under {labels_dir}")

    print(f"[*] Loading labels for {day}: {len(files)} file(s)")
    dfs = []

    needed = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"]

    for fp in files:
        t0 = time.time()
        df = read_csv_robust(fp)
        df.columns = [str(c).strip() for c in df.columns]

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

        # timestamp fixes
        df = maybe_shift_afternoon_filename_12h(df, fp)
        df = maybe_shift_workinghours_rows_12h(df, fp)

        df["label_raw"] = df["Label"].astype(str).str.strip()
        df["label_family"] = df["label_raw"].map(label_family)
        df["is_attack"] = (df["label_family"] != "BENIGN").astype("int8")

        df["key"] = make_key(df["Source IP"], df["Source Port"], df["Destination IP"], df["Destination Port"], df["Protocol"])
        df["key_rev"] = make_key(df["Destination IP"], df["Destination Port"], df["Source IP"], df["Source Port"], df["Protocol"])

        fwd = df[["ts", "key", "label_family", "label_raw", "is_attack"]].rename(columns={"key": "k"})
        rev = df[["ts", "key_rev", "label_family", "label_raw", "is_attack"]].rename(columns={"key_rev": "k"})
        lab_any = pd.concat([fwd, rev], ignore_index=True)
        lab_any["k"] = lab_any["k"].astype(str)

        lab_any = lab_any.sort_values(["is_attack"], ascending=False)
        lab_any = lab_any.drop_duplicates(subset=["ts", "k"], keep="first")

        t1 = time.time()
        print(
            f"    - read {os.path.basename(fp)} rows={len(df)} ({t1 - t0:.1f}s) "
            f"range={lab_any['ts'].min():.0f}..{lab_any['ts'].max():.0f}"
        )

        dfs.append(lab_any)

    lab = pd.concat(dfs, ignore_index=True)
    attacks = int((lab["is_attack"] == 1).sum())
    print(f"[*] Labels loaded: rows={len(lab)} attacks={attacks}")
    return lab


def read_run_meta(run_dir: str) -> dict:
    meta_path = os.path.join(run_dir, "run_meta.json")
    with open(meta_path, "r") as f:
        return json.load(f)


def run_time_range(merged_csv: str) -> Tuple[float, float]:
    df = pd.read_csv(merged_csv, usecols=["ts"], low_memory=False)
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"])
    return float(df["ts"].min()), float(df["ts"].max())


def compute_offset(run_ts_min: float, lab_ts_min: float) -> int:
    return int(round(run_ts_min - lab_ts_min))


def merge_two_pass(df: pd.DataFrame, lab_any: pd.DataFrame, offset: int, tol_s: int) -> pd.DataFrame:
    """
    Two merges:
      - nearest match for flow start ts
      - nearest match for flow end t_end
    Choose better label:
      attack > benign > unknown.
    """
    lab = lab_any.copy()
    lab["ts_shift"] = (lab["ts"].astype("float64") + float(offset)).astype("float64")

    df_ts = _stable_sort_for_asof(df, ["ts", "k"])
    df_end = _stable_sort_for_asof(df, ["t_end", "k"])
    lab_s = _stable_sort_for_asof(lab, ["ts_shift", "k"])

    j1 = pd.merge_asof(
        df_ts,
        lab_s[["ts_shift", "k", "label_family", "label_raw", "is_attack"]],
        left_on="ts",
        right_on="ts_shift",
        by="k",
        direction="nearest",
        tolerance=tol_s,
    )

    j2 = pd.merge_asof(
        df_end,
        lab_s[["ts_shift", "k", "label_family", "label_raw", "is_attack"]],
        left_on="t_end",
        right_on="ts_shift",
        by="k",
        direction="nearest",
        tolerance=tol_s,
    )

    j1 = j1.sort_values("__row_id").reset_index(drop=True)
    j2 = j2.sort_values("__row_id").reset_index(drop=True)

    def score(fam):
        if pd.isna(fam):
            return 0
        if fam == "BENIGN":
            return 2
        if fam == "Unknown":
            return 0
        return 3

    s1 = j1["label_family"].map(score).fillna(0)
    s2 = j2["label_family"].map(score).fillna(0)
    pick2 = (s2 > s1)

    out = j1.copy()
    for col in ["label_family", "label_raw", "is_attack", "ts_shift"]:
        if col in j2.columns:
            out.loc[pick2, col] = j2.loc[pick2, col].values

    return out


def _sample_score_shift(
    merged_csv: str,
    lab_any: pd.DataFrame,
    halfday_shift_s: int,
    base_offset: int,
    tol_s: int,
    sample_rows: int,
) -> Tuple[int, int]:
    needed = ["ts", "duration", "orig_h", "orig_p", "resp_h", "resp_p", "proto"]
    df = pd.read_csv(merged_csv, low_memory=False, nrows=sample_rows, usecols=lambda c: c in set(needed))
    df = df.copy()
    df["__row_id"] = range(0, len(df))

    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df["duration"] = pd.to_numeric(df.get("duration", 0), errors="coerce").fillna(0.0)
    df = df.dropna(subset=["ts"]).copy()
    df["ts"] = df["ts"].astype("float64")
    df["duration"] = df["duration"].astype("float64").clip(lower=0.0)
    df["t_end"] = (df["ts"] + df["duration"]).astype("float64")

    df["src_ip"] = df["orig_h"].astype(str).str.strip()
    df["dst_ip"] = df["resp_h"].astype(str).str.strip()
    df["src_port"] = pd.to_numeric(df["orig_p"], errors="coerce").fillna(0).astype("int64")
    df["dst_port"] = pd.to_numeric(df["resp_p"], errors="coerce").fillna(0).astype("int64")
    df["proto_i"] = df["proto"].map(norm_proto_to_int).astype("int64")
    df["k"] = make_key(df["src_ip"], df["src_port"], df["dst_ip"], df["dst_port"], df["proto_i"]).astype(str)

    lab2 = lab_any.copy()
    lab2["ts"] = lab2["ts"].astype("float64") + float(halfday_shift_s)
    offset = int(round(base_offset - halfday_shift_s))

    joined = merge_two_pass(df, lab2, offset=offset, tol_s=tol_s)
    fam = joined["label_family"].fillna("Unknown").astype(str)
    known = int((fam != "Unknown").sum())
    attacks = int(((fam != "Unknown") & (fam != "BENIGN")).sum())
    return known, attacks


def choose_halfday_shift(
    merged_csv: str,
    lab_any: pd.DataFrame,
    run_ts_min: float,
    run_ts_max: float,
    base_offset: int,
    tol_s: int,
    sample_rows: int,
) -> Tuple[int, int]:
    lab_min = float(lab_any["ts"].min())
    lab_max = float(lab_any["ts"].max())

    def overlap(a0, a1, b0, b1) -> float:
        lo = max(a0, b0)
        hi = min(a1, b1)
        return max(0.0, hi - lo)

    best_shift = 0
    best_tuple = None  # (attacks, known, overlap)

    for sh in HALFDAY_SHIFTS:
        w0 = lab_min + sh
        w1 = lab_max + sh
        ov = overlap(run_ts_min, run_ts_max, w0, w1)
        known, attacks = _sample_score_shift(merged_csv, lab_any, sh, base_offset, tol_s, sample_rows)
        off = int(round(base_offset - sh))
        print(f"    [auto_halfday_shift] shift={sh:+6d}s offset={off:+6d}s overlap_h={ov/3600:.2f} sample_known={known}/{sample_rows} sample_attacks={attacks}")

        tup = (attacks, known, ov)
        if best_tuple is None or tup > best_tuple:
            best_tuple = tup
            best_shift = sh

    return int(best_shift), int(round(base_offset - best_shift))


def label_run_chunked(
    run_dir: str,
    labels_dir: str,
    out_dir: str,
    pre_slop: int,
    post_slop: int,
    chunksize: int,
    auto_halfday_shift: bool,
    shift_sample_rows: int,
) -> str:
    run_dir = run_dir.rstrip("/")
    merged_csv = os.path.join(run_dir, "merged.csv")
    meta = read_run_meta(run_dir)
    day = norm_day_from_path(meta.get("pcap", ""))

    if day == "Unknown":
        raise ValueError(f"Could not infer day from run_meta.json pcap={meta.get('pcap')}")

    lab_any = load_labels_for_day(labels_dir, day)

    rmin, rmax = run_time_range(merged_csv)
    base_offset = compute_offset(rmin, float(lab_any["ts"].min()))

    tol_s = int(max(0, max(pre_slop, post_slop)))

    halfday_shift = 0
    offset = base_offset

    if auto_halfday_shift:
        halfday_shift, offset = choose_halfday_shift(
            merged_csv=merged_csv,
            lab_any=lab_any,
            run_ts_min=rmin,
            run_ts_max=rmax,
            base_offset=base_offset,
            tol_s=tol_s,
            sample_rows=shift_sample_rows,
        )
        print(f"[*] {run_dir}: chose halfday_shift={halfday_shift}s offset={offset}s")

    print(
        f"[*] {run_dir}: run_ts={rmin:.0f}..{rmax:.0f} day={day} "
        f"halfday_shift={halfday_shift}s offset={offset}s window=[-{pre_slop},+{post_slop}] chunksize={chunksize}"
    )

    # Apply shift to labels for the full run
    lab_any = lab_any.copy()
    lab_any["ts"] = lab_any["ts"].astype("float64") + float(halfday_shift)

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{os.path.basename(run_dir)}_labeled.parquet")

    if os.path.exists(out_path):
        os.remove(out_path)

    required_cols = ["ts", "duration", "orig_h", "orig_p", "resp_h", "resp_p", "proto"]
    extra_keep = [
        "conn_state", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "start_ts", "end_ts",
        "ebpf_bytes_sent", "ebpf_bytes_recv", "ebpf_retransmits", "ebpf_state_changes",
        "ebpf_samples", "ebpf_pid", "ebpf_uid", "ebpf_comm",
    ]

    hdr = pd.read_csv(merged_csv, nrows=0)
    present = set([c.strip() for c in hdr.columns])
    usecols = [c for c in (required_cols + extra_keep) if c in present]

    total = 0
    known = 0
    attacks = 0

    import pyarrow as pa
    import pyarrow.parquet as pq

    writer: Optional[pq.ParquetWriter] = None

    for chunk in pd.read_csv(merged_csv, low_memory=False, chunksize=chunksize, usecols=usecols):
        chunk = chunk.copy()
        chunk["__row_id"] = range(total, total + len(chunk))

        chunk["ts"] = pd.to_numeric(chunk["ts"], errors="coerce")
        chunk["duration"] = pd.to_numeric(chunk.get("duration", 0), errors="coerce").fillna(0.0)
        chunk = chunk.dropna(subset=["ts"]).copy()
        chunk["ts"] = chunk["ts"].astype("float64")
        chunk["duration"] = chunk["duration"].astype("float64").clip(lower=0.0)

        chunk["t_end"] = (chunk["ts"] + chunk["duration"]).astype("float64")

        chunk["src_ip"] = chunk["orig_h"].astype(str).str.strip()
        chunk["dst_ip"] = chunk["resp_h"].astype(str).str.strip()
        chunk["src_port"] = pd.to_numeric(chunk["orig_p"], errors="coerce").fillna(0).astype("int64")
        chunk["dst_port"] = pd.to_numeric(chunk["resp_p"], errors="coerce").fillna(0).astype("int64")
        chunk["proto_i"] = chunk["proto"].map(norm_proto_to_int).astype("int64")

        chunk["k"] = make_key(
            chunk["src_ip"], chunk["src_port"], chunk["dst_ip"], chunk["dst_port"], chunk["proto_i"]
        ).astype(str)

        joined = merge_two_pass(chunk, lab_any, offset=offset, tol_s=tol_s)

        # Force stable schema across chunks
        joined["label_family"] = joined["label_family"].fillna("Unknown").astype(str)
        joined["label_raw"] = joined["label_raw"].fillna("Unknown").astype(str)
        joined["is_attack"] = pd.to_numeric(joined.get("is_attack", 0), errors="coerce").fillna(0).astype("int8")

        joined["day"] = day
        joined["run_id"] = os.path.basename(run_dir)
        joined["label_time_offset_sec"] = int(offset)
        joined["label_halfday_shift_sec"] = int(halfday_shift)
        joined["label_window_pre_slop_sec"] = int(pre_slop)
        joined["label_window_post_slop_sec"] = int(post_slop)

        total += len(joined)
        kcount = int((joined["label_family"] != "Unknown").sum())
        acount = int(((joined["label_family"] != "Unknown") & (joined["label_family"] != "BENIGN")).sum())
        known += kcount
        attacks += acount

        if total % max(1, (chunksize * 5)) == 0:
            print(f"    progress: rows={total} known={known} attacks={attacks}")

        joined = joined.drop(columns=["__row_id"], errors="ignore")
        joined = joined.drop(columns=["ts_shift"], errors="ignore")

        table = pa.Table.from_pandas(joined, preserve_index=False)

        if writer is None:
            writer = pq.ParquetWriter(out_path, table.schema, compression="snappy")
        writer.write_table(table)

    if writer is not None:
        writer.close()

    pct = (known / total * 100.0) if total else 0.0
    apct = (attacks / total * 100.0) if total else 0.0
    print(
        f"[*] {run_dir}: labeled {known}/{total} ({pct:.2f}%) attacks={attacks} ({apct:.2f}%) "
        f"day={day} halfday_shift={halfday_shift}s offset={offset}s -> {out_path}"
    )

    return out_path


def combine_parquets(out_files: List[str], combined_out: str) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    os.makedirs(os.path.dirname(combined_out), exist_ok=True)

    if os.path.exists(combined_out):
        os.remove(combined_out)

    writer = None
    rows = 0

    for fp in out_files:
        pf = pq.ParquetFile(fp)
        for batch in pf.iter_batches():
            table = pa.Table.from_batches([batch])
            if writer is None:
                writer = pq.ParquetWriter(combined_out, table.schema, compression="snappy")
            writer.write_table(table)
            rows += table.num_rows

    if writer is not None:
        writer.close()

    print(f"[*] Wrote combined labeled dataset: {combined_out} rows={rows}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True, help="run directories (each must contain merged.csv + run_meta.json)")
    ap.add_argument("--labels_dir", required=True, help="CICIDS2017 TrafficLabelling directory")
    ap.add_argument("--out_dir", default="data/datasets/labeled_runs", help="per-run labeled parquet output directory")
    ap.add_argument("--pre_slop", type=int, default=7200, help="seconds tolerance for matching (symmetric)")
    ap.add_argument("--post_slop", type=int, default=7200, help="kept for metadata (symmetric matching is used)")
    ap.add_argument("--chunksize", type=int, default=50000, help="CSV rows per chunk")
    ap.add_argument("--combined_out", default="data/datasets/cicids2017_multiclass_zeek_ebpf.parquet", help="combined parquet output path")
    ap.add_argument("--no_combine", action="store_true", help="only write per-run outputs, skip combined parquet")

    ap.add_argument("--auto_halfday_shift", action="store_true", help="try shifts {0,±12h} to improve alignment")
    ap.add_argument("--shift_sample_rows", type=int, default=200000, help="rows to sample from merged.csv when choosing halfday shift")

    args = ap.parse_args()

    outs: List[str] = []
    for r in args.runs:
        merged = os.path.join(r, "merged.csv")
        if not (os.path.exists(merged) and os.path.getsize(merged) > 0):
            print(f"[!] skipping {r}: merged.csv missing/empty")
            continue

        outs.append(
            label_run_chunked(
                r,
                args.labels_dir,
                args.out_dir,
                pre_slop=args.pre_slop,
                post_slop=args.post_slop,
                chunksize=args.chunksize,
                auto_halfday_shift=args.auto_halfday_shift,
                shift_sample_rows=args.shift_sample_rows,
            )
        )

    if args.no_combine:
        print(f"[*] Skipping combine (--no_combine). Per-run outputs are in: {args.out_dir}")
        return

    if not outs:
        print("[!] no per-run outputs produced; nothing to combine")
        return

    combine_parquets(outs, args.combined_out)


if __name__ == "__main__":
    main()
