#!/usr/bin/env python3

import argparse
import json
import os
import ipaddress
import pandas as pd
import sys
from collections import defaultdict

def ip_to_u32_maybe(ip: str):
    """Convert an IPv4 string to uint32. Returns NA for IPv6 or invalid addresses."""
    ip = str(ip).strip()
    if ":" in ip:
        return pd.NA
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return pd.NA

def flatten_meta(obj, prefix=""):
    """Recursively flatten a nested dict into a single-level dict."""
    out = {}
    if not isinstance(obj, dict):
        return out
    for k, v in obj.items():
        key = f"{prefix}{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(flatten_meta(v, prefix=key + "_"))
        elif isinstance(v, (list, tuple)):
            out[key] = json.dumps(v)
        else:
            out[key] = v
    return out

def load_zeek_conn(conn_csv: str) -> pd.DataFrame:
    """Load and normalise a Zeek conn.csv file."""
    required = [
        "ts", "orig_h", "resp_h", "orig_p", "resp_p", "proto", "duration",
        "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state",
    ]

    df = pd.read_csv(conn_csv)
    if not set(required).issubset(df.columns):
        df = pd.read_csv(conn_csv, header=None, names=required)

    if len(df) > 0 and str(df.iloc[0].get("ts", "")) == "ts":
        df = df.iloc[1:].copy()

    df["orig_p"] = pd.to_numeric(df["orig_p"], errors="coerce").fillna(0).astype(int)
    df["resp_p"] = pd.to_numeric(df["resp_p"], errors="coerce").fillna(0).astype(int)
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce").fillna(0.0)
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)

    for c in ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    df["proto"] = df["proto"].astype(str).str.upper()
    proto_map = {"TCP": 6, "UDP": 17}
    df["proto_num"] = df["proto"].map(proto_map).fillna(0).astype(int)

    df["start_ts"] = df["ts"]
    df["end_ts"] = df["ts"] + df["duration"]

    df["orig_ip_u32"] = df["orig_h"].apply(ip_to_u32_maybe)
    df["resp_ip_u32"] = df["resp_h"].apply(ip_to_u32_maybe)

    # Drop IPv6 rows; the eBPF collector only handles IPv4.
    before = len(df)
    df = df.dropna(subset=["orig_ip_u32", "resp_ip_u32"]).copy()
    dropped = before - len(df)
    if dropped:
        print(f"[*] Dropped {dropped} non-IPv4 Zeek rows (IPv6 not supported).")

    df["orig_ip_u32"] = df["orig_ip_u32"].astype("uint32")
    df["resp_ip_u32"] = df["resp_ip_u32"].astype("uint32")

    return df

def _process_ebpf_rows(rows: list) -> pd.DataFrame:
    """Convert raw eBPF JSONL dicts into the standard DataFrame format."""
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    if "saddr_str" in df.columns and "daddr_str" in df.columns:
        df["saddr_u32"] = df["saddr_str"].apply(ip_to_u32_maybe)
        df["daddr_u32"] = df["daddr_str"].apply(ip_to_u32_maybe)
    else:
        df["saddr_u32"] = df["saddr"].astype("uint32")
        df["daddr_u32"] = df["daddr"].astype("uint32")

    df = df.dropna(subset=["saddr_u32", "daddr_u32"]).copy()
    df["saddr_u32"] = df["saddr_u32"].astype("uint32")
    df["daddr_u32"] = df["daddr_u32"].astype("uint32")

    df["sport"] = pd.to_numeric(df["sport"], errors="coerce").fillna(0).astype(int)
    df["dport"] = pd.to_numeric(df["dport"], errors="coerce").fillna(0).astype(int)
    df["proto"] = pd.to_numeric(df["proto"], errors="coerce").fillna(0).astype(int)

    # Convert monotonic ns timestamps to epoch seconds using the flush wall-clock anchor.
    if "first_ts_s" not in df.columns and "first_ts_ns" in df.columns:
        if "flush_ts_s" in df.columns and "last_ts_ns" in df.columns:
            offset_ns = (df["flush_ts_s"].astype(float) * 1e9) - df["last_ts_ns"].astype(float)
            df["first_ts_s"] = (df["first_ts_ns"].astype(float) + offset_ns) / 1e9
            df["last_ts_s"] = (df["last_ts_ns"].astype(float) + offset_ns) / 1e9
        else:
            print("[!] eBPF JSONL missing epoch timestamps; time filtering may be invalid.")
            df["first_ts_s"] = df["first_ts_ns"].astype(float) / 1e9
            df["last_ts_s"] = df["last_ts_ns"].astype(float) / 1e9

    return df

def load_ebpf_agg(jsonl: str) -> pd.DataFrame:
    """Load eBPF aggregated flow data from a JSONL file."""
    rows = []
    with open(jsonl, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return _process_ebpf_rows(rows)

def detect_replay_scenario(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame, debug: bool = False):
    """
    Detect PCAP replay from time compression (Zeek span / eBPF span).
    Returns (is_replay, compression_ratio, replay_type).
    """
    zeek_span = zeek_df["end_ts"].max() - zeek_df["start_ts"].min()
    ebpf_span = ebpf_df["last_ts_s"].max() - ebpf_df["first_ts_s"].min()

    if ebpf_span < 1.0:
        ebpf_span = 1.0

    compression = zeek_span / ebpf_span

    if compression > 500:
        replay_type = "topspeed"
        is_replay = True
    elif compression > 100:
        replay_type = "fast"
        is_replay = True
    elif compression > 10:
        replay_type = "moderate"
        is_replay = True
    elif compression > 2:
        replay_type = "realtime"
        is_replay = True
    else:
        replay_type = "live"
        is_replay = False

    if debug:
        print(f"\n[DEBUG] Replay detection:")
        print(f"  Zeek time span:    {zeek_span:.1f}s ({zeek_span/3600:.1f} hours)")
        print(f"  eBPF capture span: {ebpf_span:.1f}s ({ebpf_span/60:.1f} minutes)")
        print(f"  Compression ratio: {compression:.1f}x")
        print(f"  Scenario: {replay_type.upper()} ({'REPLAY' if is_replay else 'LIVE'})")

    return is_replay, compression, replay_type

def synchronize_timestamps(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame, debug: bool = False):
    """Shift eBPF timestamps to align with the Zeek/PCAP timeline."""
    if ebpf_df.empty or zeek_df.empty:
        return ebpf_df

    zeek_min = zeek_df["start_ts"].min()
    zeek_max = zeek_df["end_ts"].max()
    ebpf_min = ebpf_df["first_ts_s"].min()
    ebpf_max = ebpf_df["last_ts_s"].max()

    offset = zeek_min - ebpf_min

    if debug:
        from datetime import datetime
        print(f"\n[DEBUG] Timestamp synchronization:")
        print(f"  Zeek timeline:  {zeek_min:.1f} to {zeek_max:.1f} (span: {zeek_max-zeek_min:.1f}s)")
        print(f"  eBPF timeline:  {ebpf_min:.1f} to {ebpf_max:.1f} (span: {ebpf_max-ebpf_min:.1f}s)")
        print(f"  Offset:         {offset:.1f}s ({offset/86400:.1f} days)")
        print(f"  Zeek start:     {datetime.fromtimestamp(zeek_min).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  eBPF start:     {datetime.fromtimestamp(ebpf_min).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  After adjust:   {datetime.fromtimestamp(ebpf_min + offset).strftime('%Y-%m-%d %H:%M:%S')}")

    ebpf_df = ebpf_df.copy()
    ebpf_df["first_ts_s"] = ebpf_df["first_ts_s"] + offset
    ebpf_df["last_ts_s"] = ebpf_df["last_ts_s"] + offset

    if debug:
        new_min = ebpf_df["first_ts_s"].min()
        new_max = ebpf_df["last_ts_s"].max()
        print(f"  Adjusted eBPF:  {new_min:.1f} to {new_max:.1f}")
        print(f"  Alignment error: {abs(zeek_min - new_min):.3f}s")

    return ebpf_df


def match_flows_with_deduplication(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame,
                                   is_replay: bool, debug: bool = False):
    """
    Match Zeek and eBPF flows on 5-tuple.
    Replay mode uses one-to-one matching to handle duplicate 5-tuples correctly.
    Live mode uses a standard pandas merge with deduplication.
    """
    zeek_df = zeek_df.copy()
    ebpf_df = ebpf_df.copy()

    zeek_df["key_fwd"] = (
        zeek_df["orig_ip_u32"].astype(str) + "_" +
        zeek_df["resp_ip_u32"].astype(str) + "_" +
        zeek_df["orig_p"].astype(str) + "_" +
        zeek_df["resp_p"].astype(str) + "_" +
        zeek_df["proto_num"].astype(str)
    )
    zeek_df["key_rev"] = (
        zeek_df["resp_ip_u32"].astype(str) + "_" +
        zeek_df["orig_ip_u32"].astype(str) + "_" +
        zeek_df["resp_p"].astype(str) + "_" +
        zeek_df["orig_p"].astype(str) + "_" +
        zeek_df["proto_num"].astype(str)
    )
    ebpf_df["key"] = (
        ebpf_df["saddr_u32"].astype(str) + "_" +
        ebpf_df["daddr_u32"].astype(str) + "_" +
        ebpf_df["sport"].astype(str) + "_" +
        ebpf_df["dport"].astype(str) + "_" +
        ebpf_df["proto"].astype(str)
    )

    if is_replay:
        print("[*] Using replay-aware matching (prevents duplicate 5-tuple issues)...")

        # Build a lookup from the first eBPF entry per 5-tuple.
        ebpf_lookup = {}
        for _, row in ebpf_df.iterrows():
            key = row["key"]
            if key not in ebpf_lookup:
                ebpf_lookup[key] = row

        if debug:
            dup_keys = len(ebpf_df) - len(ebpf_lookup)
            if dup_keys > 0:
                print(f"[DEBUG] Found {dup_keys} duplicate 5-tuples in eBPF (using first occurrence)")

        matched_data = []
        stats = {"fwd": 0, "rev": 0, "unmatched": 0}

        for _, zrow in zeek_df.iterrows():
            ebpf_match = None

            if zrow["key_fwd"] in ebpf_lookup:
                ebpf_match = ebpf_lookup[zrow["key_fwd"]]
                stats["fwd"] += 1
            elif zrow["key_rev"] in ebpf_lookup:
                ebpf_match = ebpf_lookup[zrow["key_rev"]]
                stats["rev"] += 1
            else:
                stats["unmatched"] += 1

            combined = zrow.to_dict()
            if ebpf_match is not None:
                for k, v in ebpf_match.items():
                    if k != "key":
                        combined[f"ebpf_{k}"] = v

            matched_data.append(combined)

        merged = pd.DataFrame(matched_data)
        print(f"[*] Matched: {stats['fwd']} forward, {stats['rev']} reverse, {stats['unmatched']} unmatched")

    else:
        print("[*] Using standard merge (live capture mode)...")

        # Dedup eBPF by 5-tuple; high-throughput flows (e.g. iperf3) can create many entries
        # and cause a one-to-many join explosion. Keep the entry with the most samples.
        key_cols = ["saddr_u32", "daddr_u32", "sport", "dport", "proto"]
        before_dedup = len(ebpf_df)
        if "samples" in ebpf_df.columns:
            ebpf_df = (ebpf_df
                       .sort_values("samples", ascending=False)
                       .drop_duplicates(subset=key_cols, keep="first")
                       .reset_index(drop=True))
        else:
            ebpf_df = ebpf_df.drop_duplicates(subset=key_cols, keep="first").reset_index(drop=True)
        removed = before_dedup - len(ebpf_df)
        if removed:
            print(f"[*] eBPF dedup: {before_dedup} -> {len(ebpf_df)} entries ({removed} removed)")

        zeek_fwd = zeek_df.copy()
        zeek_fwd["k_saddr"] = zeek_fwd["orig_ip_u32"]
        zeek_fwd["k_daddr"] = zeek_fwd["resp_ip_u32"]
        zeek_fwd["k_sport"] = zeek_fwd["orig_p"]
        zeek_fwd["k_dport"] = zeek_fwd["resp_p"]
        zeek_fwd["k_proto"] = zeek_fwd["proto_num"]

        zeek_rev = zeek_df.copy()
        zeek_rev["k_saddr"] = zeek_rev["resp_ip_u32"]
        zeek_rev["k_daddr"] = zeek_rev["orig_ip_u32"]
        zeek_rev["k_sport"] = zeek_rev["resp_p"]
        zeek_rev["k_dport"] = zeek_rev["orig_p"]
        zeek_rev["k_proto"] = zeek_rev["proto_num"]

        ebpf_keyed = ebpf_df.copy()
        ebpf_keyed["k_saddr"] = ebpf_keyed["saddr_u32"]
        ebpf_keyed["k_daddr"] = ebpf_keyed["daddr_u32"]
        ebpf_keyed["k_sport"] = ebpf_keyed["sport"]
        ebpf_keyed["k_dport"] = ebpf_keyed["dport"]
        ebpf_keyed["k_proto"] = ebpf_keyed["proto"]

        merge_keys = ["k_saddr", "k_daddr", "k_sport", "k_dport", "k_proto"]
        merged_fwd = zeek_fwd.merge(ebpf_keyed, on=merge_keys, how="left", suffixes=("", "_ebpf"))
        merged_rev = zeek_rev.merge(ebpf_keyed, on=merge_keys, how="left", suffixes=("", "_ebpf"))

        merged = merged_fwd.copy()
        unmatched_fwd = merged["first_ts_s"].isna()
        matched_rev = merged_rev["first_ts_s"].notna()
        use_reverse = unmatched_fwd & matched_rev

        if use_reverse.any():
            print(f"[*] Using reverse direction for {use_reverse.sum()} flows")
            merged.loc[use_reverse, merged.columns] = merged_rev.loc[use_reverse, merged.columns]

    return merged

def apply_time_filter(merged: pd.DataFrame, time_slop: float, is_replay: bool, debug: bool = False):
    """
    Apply a time window filter in live mode. Skipped in replay mode where 5-tuple matching is sufficient.
    """
    has_ebpf_col = "first_ts_s" in merged.columns or "ebpf_first_ts_s" in merged.columns
    if not has_ebpf_col:
        return merged

    ts_col = "ebpf_first_ts_s" if "ebpf_first_ts_s" in merged.columns else "first_ts_s"
    ts_end_col = "ebpf_last_ts_s" if "ebpf_last_ts_s" in merged.columns else "last_ts_s"

    has_ebpf = merged[ts_col].notna()
    if not has_ebpf.any():
        return merged

    if is_replay:
        print("[*] Skipping time filter (replay mode, using 5-tuple matching only)")
        return merged

    print(f"[*] Applying time window filter (+/-{time_slop}s)...")

    time_ok = (
        (merged[ts_col] <= merged["end_ts"] + time_slop) &
        (merged[ts_end_col] >= merged["start_ts"] - time_slop)
    )
    valid = ~has_ebpf | time_ok
    filtered_out = (~valid).sum()

    if filtered_out > 0:
        print(f"[*] Filtered out {filtered_out} flows due to time mismatch")
        if debug and filtered_out < 100:
            mismatched = merged[~valid][["orig_h", "resp_h", "orig_p", "resp_p", "proto",
                                         "start_ts", "end_ts", ts_col, ts_end_col]].head(10)
            print("[DEBUG] Sample time mismatches:")
            print(mismatched.to_string())

    return merged[valid].copy()


def _col(df, name, default):
    if f"ebpf_{name}" in df.columns:
        return df[f"ebpf_{name}"]
    if name in df.columns:
        return df[name]
    return pd.Series([default] * len(df), index=df.index)


def run_merge(
    zeek_csv: "str | None",
    ebpf_df: "pd.DataFrame",
    out: str,
    time_slop: float = 5.0,
    run_meta: str = "",
    debug: bool = False,
    force_replay_mode: bool = False,
    zeek_df: "pd.DataFrame | None" = None,
) -> None:
    """
    In-process merge entry point for the daemon.
    Accepts a pre-loaded eBPF DataFrame and optionally a pre-loaded Zeek DataFrame
    to avoid re-reading files on every poll cycle.
    """
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    if zeek_df is not None:
        z = zeek_df
    else:
        z = load_zeek_conn(zeek_csv)
    if z.empty:
        return

    e = ebpf_df.copy() if not ebpf_df.empty else pd.DataFrame()

    if e.empty:
        out_df = z.copy()
        for c in ["ebpf_bytes_sent", "ebpf_bytes_recv", "ebpf_retransmits",
                  "ebpf_state_changes", "ebpf_samples"]:
            out_df[c] = 0.0
        for c in ["ebpf_pid", "ebpf_uid"]:
            out_df[c] = 0
        out_df["ebpf_comm"] = ""
        out_df.to_csv(out, index=False)
        return

    is_replay, _, _ = detect_replay_scenario(z, e, debug=debug)
    if force_replay_mode:
        is_replay = True
    if is_replay:
        e = synchronize_timestamps(z, e, debug=debug)

    merged = match_flows_with_deduplication(z, e, is_replay=is_replay, debug=debug)
    merged = apply_time_filter(merged, time_slop, is_replay=is_replay, debug=debug)

    merged["ebpf_bytes_sent"]    = _col(merged, "bytes_sent",    0).fillna(0).astype(float)
    merged["ebpf_bytes_recv"]    = _col(merged, "bytes_recv",    0).fillna(0).astype(float)
    merged["ebpf_retransmits"]   = _col(merged, "retransmits",   0).fillna(0).astype(float)
    merged["ebpf_state_changes"] = _col(merged, "state_changes", 0).fillna(0).astype(float)
    merged["ebpf_samples"]       = _col(merged, "samples",       0).fillna(0).astype(float)
    merged["ebpf_pid"]           = _col(merged, "pid_mode",      0).fillna(0).astype(int)
    merged["ebpf_uid"]           = _col(merged, "uid_mode",      0).fillna(0).astype(int)
    merged["ebpf_comm"]          = _col(merged, "comm_mode",    "").fillna("").astype(str)

    run_meta_cols: list = []
    if run_meta and os.path.exists(run_meta):
        try:
            with open(run_meta) as f:
                meta = json.load(f)
            flat = flatten_meta(meta)
            for k, v in flat.items():
                col_name = "run_" + str(k)
                merged[col_name] = v
                run_meta_cols.append(col_name)
        except Exception:
            pass

    out_cols = [
        "ts", "duration", "orig_h", "resp_h", "orig_p", "resp_p", "proto", "conn_state",
        "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "start_ts", "end_ts",
        "ebpf_bytes_sent", "ebpf_bytes_recv", "ebpf_retransmits",
        "ebpf_state_changes", "ebpf_samples",
        "ebpf_pid", "ebpf_uid", "ebpf_comm",
    ] + run_meta_cols
    out_cols = [c for c in out_cols if c in merged.columns]
    merged[out_cols].to_csv(out, index=False)

def main():
    ap = argparse.ArgumentParser(description="Merge Zeek conn.csv and eBPF JSONL flows with replay detection")
    ap.add_argument("--zeek_conn", required=True, help="Zeek conn.csv file")
    ap.add_argument("--ebpf_agg", required=True, help="eBPF aggregated JSONL file")
    ap.add_argument("--out", required=True, help="output merged CSV file")
    ap.add_argument("--time_slop", type=float, default=5.0,
                    help="time window tolerance in seconds for live capture (default: 5.0)")
    ap.add_argument("--run_meta", default="", help="optional run metadata JSON")
    ap.add_argument("--debug", action="store_true", help="enable debug output")
    ap.add_argument("--force_replay_mode", action="store_true",
                    help="force replay mode even if auto-detection fails")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    print("[*] Loading Zeek connection log...")
    z = load_zeek_conn(args.zeek_conn)
    print(f"[*] Loaded {len(z)} Zeek flows")

    print("[*] Loading eBPF aggregated data...")
    e = load_ebpf_agg(args.ebpf_agg)

    if e.empty:
        print("[!] No eBPF data found, writing Zeek-only output...")
        out = z.copy()
        for c in ["ebpf_bytes_sent", "ebpf_bytes_recv", "ebpf_retransmits",
                  "ebpf_state_changes", "ebpf_samples"]:
            out[c] = 0.0
        for c in ["ebpf_pid", "ebpf_uid"]:
            out[c] = 0
        out["ebpf_comm"] = ""
        out.to_csv(args.out, index=False)
        print(f"[*] Wrote Zeek-only output: {args.out}")
        return

    print(f"[*] Loaded {len(e)} eBPF flows")

    is_replay, compression, replay_type = detect_replay_scenario(z, e, debug=args.debug)

    if args.force_replay_mode:
        print("[!] Force replay mode enabled")
        is_replay = True
        replay_type = "forced"

    if is_replay:
        print("[*] Synchronizing timestamps (replay mode)...")
        e = synchronize_timestamps(z, e, debug=args.debug)
    else:
        print("[*] Skipping timestamp sync (live capture, both sources use wall clock)")

    merged = match_flows_with_deduplication(z, e, is_replay=is_replay, debug=args.debug)
    merged = apply_time_filter(merged, args.time_slop, is_replay=is_replay, debug=args.debug)

    merged["ebpf_bytes_sent"]    = _col(merged, "bytes_sent",    0).fillna(0).astype(float)
    merged["ebpf_bytes_recv"]    = _col(merged, "bytes_recv",    0).fillna(0).astype(float)
    merged["ebpf_retransmits"]   = _col(merged, "retransmits",   0).fillna(0).astype(float)
    merged["ebpf_state_changes"] = _col(merged, "state_changes", 0).fillna(0).astype(float)
    merged["ebpf_samples"]       = _col(merged, "samples",       0).fillna(0).astype(float)
    merged["ebpf_pid"]           = _col(merged, "pid_mode",      0).fillna(0).astype(int)
    merged["ebpf_uid"]           = _col(merged, "uid_mode",      0).fillna(0).astype(int)
    merged["ebpf_comm"]          = _col(merged, "comm_mode",    "").fillna("").astype(str)

    run_meta_cols = []
    if args.run_meta and os.path.exists(args.run_meta):
        try:
            with open(args.run_meta, "r") as f:
                meta = json.load(f)
            flat = flatten_meta(meta)
            for k, v in flat.items():
                col_name = "run_" + str(k)
                merged[col_name] = v
                run_meta_cols.append(col_name)
            print(f"[*] Added {len(run_meta_cols)} metadata columns")
        except Exception as ex:
            print(f"[!] Failed to read run metadata: {ex}")

    out_cols = [
        "ts", "duration", "orig_h", "resp_h", "orig_p", "resp_p", "proto", "conn_state",
        "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "start_ts", "end_ts",
        "ebpf_bytes_sent", "ebpf_bytes_recv", "ebpf_retransmits",
        "ebpf_state_changes", "ebpf_samples",
        "ebpf_pid", "ebpf_uid", "ebpf_comm",
    ] + run_meta_cols
    out_cols = [c for c in out_cols if c in merged.columns]
    merged[out_cols].to_csv(args.out, index=False)

    total_flows = len(merged)
    enriched_flows = int((merged["ebpf_samples"] > 0).sum())
    flows_with_data = int((merged["ebpf_bytes_sent"] > 0).sum())
    enrichment_rate = (enriched_flows / total_flows * 100) if total_flows > 0 else 0
    data_rate = (flows_with_data / total_flows * 100) if total_flows > 0 else 0

    print(f"\n[*] Merge complete")
    print(f"[*] Scenario: {replay_type.upper()} ({'REPLAY' if is_replay else 'LIVE'})")
    print(f"[*] Total flows: {total_flows:,}")
    print(f"[*] Enriched with eBPF: {enriched_flows:,} ({enrichment_rate:.1f}%)")
    print(f"[*] Flows with packet data: {flows_with_data:,} ({data_rate:.1f}%)")
    print(f"[*] Output: {args.out}")

    if args.debug and flows_with_data > 0:
        print("\n[DEBUG] eBPF enrichment statistics:")
        print(f"  Flows with bytes_sent > 0: {flows_with_data:,}")
        print(f"  Flows with retransmits: {(merged['ebpf_retransmits'] > 0).sum():,}")
        total_bytes = merged["ebpf_bytes_sent"].sum() + merged["ebpf_bytes_recv"].sum()
        print(f"  Total bytes captured: {total_bytes:,.0f}")

        sample = merged[merged["ebpf_bytes_sent"] > 0][
            ["orig_h", "resp_h", "orig_p", "resp_p", "proto", "ebpf_bytes_sent", "ebpf_samples"]
        ].head(5)
        if len(sample) > 0:
            print(f"\n  Sample enriched flows:")
            print("  " + sample.to_string().replace("\n", "\n  "))

if __name__ == "__main__":
    main()
