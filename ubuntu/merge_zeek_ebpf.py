#!/usr/bin/env python3
import argparse
import json
import os
import ipaddress
import pandas as pd
import sys

def ip_to_u32_maybe(ip: str):
    """Convert IP string to uint32, return NA for IPv6"""
    ip = str(ip).strip()
    if ":" in ip:
        return pd.NA
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return pd.NA

def flatten_meta(obj, prefix=""):
    """Flatten nested dictionary for metadata columns"""
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
    """Load Zeek connection log"""
    required = [
        "ts","orig_h","resp_h","orig_p","resp_p","proto","duration",
        "orig_bytes","resp_bytes","orig_pkts","resp_pkts","conn_state",
    ]

    df = pd.read_csv(conn_csv)
    if not set(required).issubset(df.columns):
        df = pd.read_csv(conn_csv, header=None, names=required)

    # Remove potential header row in data
    if len(df) > 0 and str(df.iloc[0].get("ts", "")) == "ts":
        df = df.iloc[1:].copy()

    # Convert data types
    df["orig_p"] = pd.to_numeric(df["orig_p"], errors="coerce").fillna(0).astype(int)
    df["resp_p"] = pd.to_numeric(df["resp_p"], errors="coerce").fillna(0).astype(int)
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce").fillna(0.0)
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)

    for c in ["orig_bytes","resp_bytes","orig_pkts","resp_pkts"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    df["proto"] = df["proto"].astype(str).str.upper()
    proto_map = {"TCP": 6, "UDP": 17}
    df["proto_num"] = df["proto"].map(proto_map).fillna(0).astype(int)

    df["start_ts"] = df["ts"]
    df["end_ts"] = df["ts"] + df["duration"]

    # Convert IPs to uint32
    df["orig_ip_u32"] = df["orig_h"].apply(ip_to_u32_maybe)
    df["resp_ip_u32"] = df["resp_h"].apply(ip_to_u32_maybe)

    # Filter out IPv6
    before = len(df)
    df = df.dropna(subset=["orig_ip_u32","resp_ip_u32"]).copy()
    dropped = before - len(df)
    if dropped:
        print(f"[*] Dropped {dropped} non-IPv4 Zeek rows (IPv6 not supported by eBPF collector yet).")

    df["orig_ip_u32"] = df["orig_ip_u32"].astype("uint32")
    df["resp_ip_u32"] = df["resp_ip_u32"].astype("uint32")

    return df

def load_ebpf_agg(jsonl: str) -> pd.DataFrame:
    """Load eBPF aggregated flow data (now with correct byte order from Go)"""
    rows = []
    with open(jsonl, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    
    # The Go collector now outputs IPs in the correct byte order
    # We just need to read them as-is
    if "saddr_str" in df.columns and "daddr_str" in df.columns:
        # String IPs provided, convert to uint32
        df["saddr_u32"] = df["saddr_str"].apply(ip_to_u32_maybe)
        df["daddr_u32"] = df["daddr_str"].apply(ip_to_u32_maybe)
    else:
        # Use numeric IPs directly
        df["saddr_u32"] = df["saddr"].astype("uint32")
        df["daddr_u32"] = df["daddr"].astype("uint32")

    df = df.dropna(subset=["saddr_u32", "daddr_u32"]).copy()
    df["saddr_u32"] = df["saddr_u32"].astype("uint32")
    df["daddr_u32"] = df["daddr_u32"].astype("uint32")

    # Convert ports and protocol
    df["sport"] = pd.to_numeric(df["sport"], errors="coerce").fillna(0).astype(int)
    df["dport"] = pd.to_numeric(df["dport"], errors="coerce").fillna(0).astype(int)
    df["proto"] = pd.to_numeric(df["proto"], errors="coerce").fillna(0).astype(int)
    
    # Ensure we have timestamp columns
    if "first_ts_s" not in df.columns and "first_ts_ns" in df.columns:
        if "flush_ts_s" in df.columns and "last_ts_ns" in df.columns:
            # Calculate epoch timestamps from monotonic
            offset_ns = (df["flush_ts_s"].astype(float) * 1e9) - df["last_ts_ns"].astype(float)
            df["first_ts_s"] = (df["first_ts_ns"].astype(float) + offset_ns) / 1e9
            df["last_ts_s"]  = (df["last_ts_ns"].astype(float)  + offset_ns) / 1e9
        else:
            print("[!] eBPF JSONL missing epoch timestamps; time filtering may be invalid.")
            df["first_ts_s"] = df["first_ts_ns"].astype(float) / 1e9
            df["last_ts_s"]  = df["last_ts_ns"].astype(float)  / 1e9
    
    return df

def synchronize_timestamps(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame, debug: bool = False):
    """
    Align eBPF timestamps with PCAP timeline.
    
    During replay:
    - Zeek uses original PCAP timestamps (e.g., July 2017)
    - eBPF uses current wall-clock time (e.g., Feb 2026)
    
    We calculate the offset and adjust eBPF timestamps to match PCAP timeline.
    """
    if ebpf_df.empty or zeek_df.empty:
        return ebpf_df
    
    # Calculate time offset
    zeek_min = zeek_df['start_ts'].min()
    zeek_max = zeek_df['end_ts'].max()
    ebpf_min = ebpf_df['first_ts_s'].min()
    ebpf_max = ebpf_df['last_ts_s'].max()
    
    # Time offset = difference between when flows started
    offset = zeek_min - ebpf_min
    
    if debug:
        print(f"\n[DEBUG] Timestamp synchronization:")
        print(f"  Zeek timeline:  {zeek_min:.1f} to {zeek_max:.1f} (span: {zeek_max-zeek_min:.1f}s)")
        print(f"  eBPF timeline:  {ebpf_min:.1f} to {ebpf_max:.1f} (span: {ebpf_max-ebpf_min:.1f}s)")
        print(f"  Offset needed:  {offset:.1f}s ({offset/86400:.1f} days)")
        
        from datetime import datetime
        print(f"  Zeek start:     {datetime.fromtimestamp(zeek_min).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  eBPF start:     {datetime.fromtimestamp(ebpf_min).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  After adjust:   {datetime.fromtimestamp(ebpf_min + offset).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Apply offset to align timelines
    ebpf_df = ebpf_df.copy()
    ebpf_df['first_ts_s'] = ebpf_df['first_ts_s'] + offset
    ebpf_df['last_ts_s'] = ebpf_df['last_ts_s'] + offset
    
    if debug:
        new_min = ebpf_df['first_ts_s'].min()
        new_max = ebpf_df['last_ts_s'].max()
        print(f"  Adjusted eBPF:  {new_min:.1f} to {new_max:.1f}")
        print(f"  Alignment error: {abs(zeek_min - new_min):.3f}s")
    
    return ebpf_df

def create_flow_keys(df: pd.DataFrame, orig_to_src: bool = True) -> pd.DataFrame:
    """Create standardized flow keys for matching"""
    out = df.copy()
    
    if orig_to_src:
        # Forward direction: orig -> src
        out["k_saddr"] = out["orig_ip_u32"].astype("uint32")
        out["k_daddr"] = out["resp_ip_u32"].astype("uint32")
        out["k_sport"] = out["orig_p"].astype(int)
        out["k_dport"] = out["resp_p"].astype(int)
        out["k_proto"] = out["proto_num"].astype(int)
    else:
        # Reverse direction: resp -> src
        out["k_saddr"] = out["resp_ip_u32"].astype("uint32")
        out["k_daddr"] = out["orig_ip_u32"].astype("uint32")
        out["k_sport"] = out["resp_p"].astype(int)
        out["k_dport"] = out["orig_p"].astype(int)
        out["k_proto"] = out["proto_num"].astype(int)
    
    return out

def create_ebpf_keys(df: pd.DataFrame) -> pd.DataFrame:
    """Create flow keys from eBPF data"""
    out = df.copy()
    out["k_saddr"] = out["saddr_u32"].astype("uint32")
    out["k_daddr"] = out["daddr_u32"].astype("uint32")
    out["k_sport"] = out["sport"].astype(int)
    out["k_dport"] = out["dport"].astype(int)
    out["k_proto"] = out["proto"].astype(int)
    return out

def main():
    ap = argparse.ArgumentParser(description="Merge Zeek and eBPF flow data with timestamp sync")
    ap.add_argument("--zeek_conn", required=True, help="Zeek conn.csv file")
    ap.add_argument("--ebpf_agg", required=True, help="eBPF aggregated JSONL file")
    ap.add_argument("--out", required=True, help="Output merged CSV file")
    ap.add_argument("--time_slop", type=float, default=5.0, 
                    help="Time window tolerance in seconds (default: 5.0)")
    ap.add_argument("--run_meta", default="",
                    help="Optional run metadata JSON")
    ap.add_argument("--debug", action="store_true",
                    help="Enable debug output")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    print("[*] Loading Zeek connection log...")
    z = load_zeek_conn(args.zeek_conn)
    print(f"[*] Loaded {len(z)} Zeek flows")

    print("[*] Loading eBPF aggregated data...")
    e = load_ebpf_agg(args.ebpf_agg)
    
    if e.empty:
        print("[!] No eBPF data found. Creating Zeek-only output...")
        out = z.copy()
        for c in ["ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits",
                  "ebpf_state_changes","ebpf_samples"]:
            out[c] = 0.0
        for c in ["ebpf_pid","ebpf_uid"]:
            out[c] = 0
        out["ebpf_comm"] = ""
        out.to_csv(args.out, index=False)
        print(f"[!] Wrote Zeek-only output: {args.out}")
        return
    
    print(f"[*] Loaded {len(e)} eBPF flows")

    # Synchronize timestamps
    print("[*] Synchronizing timestamps...")
    e = synchronize_timestamps(z, e, debug=args.debug)

    # Create matching keys
    print("[*] Creating flow keys...")
    z_fwd = create_flow_keys(z, orig_to_src=True)
    z_rev = create_flow_keys(z, orig_to_src=False)
    e_keyed = create_ebpf_keys(e)

    # Match flows
    print("[*] Matching flows (forward direction)...")
    merged_fwd = z_fwd.merge(
        e_keyed,
        on=["k_saddr","k_daddr","k_sport","k_dport","k_proto"],
        how="left",
        suffixes=("", "_e"),
    )

    # Try reverse direction for unmatched flows
    print("[*] Matching flows (reverse direction)...")
    merged_rev = z_rev.merge(
        e_keyed,
        on=["k_saddr","k_daddr","k_sport","k_dport","k_proto"],
        how="left",
        suffixes=("", "_e"),
    )

    # Combine: prefer forward, use reverse for unmatched
    merged = merged_fwd.copy()
    unmatched_fwd = merged["first_ts_s"].isna()
    matched_rev = merged_rev["first_ts_s"].notna()
    use_reverse = unmatched_fwd & matched_rev
    
    if use_reverse.any():
        print(f"[*] Using reverse direction for {use_reverse.sum()} flows")
        merged.loc[use_reverse, merged.columns] = merged_rev.loc[use_reverse, merged.columns]

    # Apply time window filter
    has_ebpf = merged["first_ts_s"].notna()
    if has_ebpf.any():
        print(f"[*] Applying time window filter (±{args.time_slop}s)...")
        
        # Check if eBPF time overlaps with Zeek time window
        time_ok = (
            (merged["first_ts_s"] <= merged["end_ts"] + args.time_slop) &
            (merged["last_ts_s"]  >= merged["start_ts"] - args.time_slop)
        )
        
        # Only filter flows that have eBPF data
        valid = ~has_ebpf | time_ok
        filtered_out = (~valid).sum()
        
        if filtered_out > 0:
            print(f"[*] Filtered out {filtered_out} flows due to time mismatch")
            if args.debug and filtered_out < 100:
                mismatched = merged[~valid][["orig_h","resp_h","orig_p","resp_p","proto",
                                              "start_ts","end_ts","first_ts_s","last_ts_s"]].head(10)
                print("[DEBUG] Sample time mismatches:")
                print(mismatched.to_string())
        
        merged = merged[valid].copy()

    # Helper function for safe column access
    def col(df, name, default):
        if name in df.columns:
            return df[name]
        return pd.Series([default] * len(df), index=df.index)

    # Create output columns
    merged["ebpf_bytes_sent"] = col(merged, "bytes_sent", 0).fillna(0).astype(float)
    merged["ebpf_bytes_recv"] = col(merged, "bytes_recv", 0).fillna(0).astype(float)
    merged["ebpf_retransmits"] = col(merged, "retransmits", 0).fillna(0).astype(float)
    merged["ebpf_state_changes"] = col(merged, "state_changes", 0).fillna(0).astype(float)
    merged["ebpf_samples"] = col(merged, "samples", 0).fillna(0).astype(float)

    # Process context
    merged["ebpf_pid"] = col(merged, "pid_mode", 0).fillna(0).astype(int)
    merged["ebpf_uid"] = col(merged, "uid_mode", 0).fillna(0).astype(int)
    merged["ebpf_comm"] = col(merged, "comm_mode", "").fillna("").astype(str)

    # Add run metadata
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

    # Select output columns
    out_cols = [
        "ts","duration","orig_h","resp_h","orig_p","resp_p","proto","conn_state",
        "orig_bytes","resp_bytes","orig_pkts","resp_pkts",
        "start_ts","end_ts",
        "ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits",
        "ebpf_state_changes","ebpf_samples",
        "ebpf_pid","ebpf_uid","ebpf_comm",
    ]
    out_cols.extend(run_meta_cols)

    # Write output
    merged[out_cols].to_csv(args.out, index=False)
    
    # Calculate statistics
    total_flows = len(merged)
    enriched_flows = int(has_ebpf.sum())
    enrichment_rate = (enriched_flows / total_flows * 100) if total_flows > 0 else 0
    
    flows_with_data = int((merged['ebpf_bytes_sent'] > 0).sum())
    data_rate = (flows_with_data / total_flows * 100) if total_flows > 0 else 0
    
    print(f"\n[*] MERGE COMPLETE")
    print(f"[*] Total flows: {total_flows:,}")
    print(f"[*] Enriched with eBPF: {enriched_flows:,} ({enrichment_rate:.1f}%)")
    print(f"[*] Flows with packet data: {flows_with_data:,} ({data_rate:.1f}%)")
    print(f"[*] Output written to: {args.out}")
    
    # Debug statistics
    if args.debug and flows_with_data > 0:
        print("\n[DEBUG] eBPF enrichment statistics:")
        print(f"  - Flows with bytes_sent > 0: {flows_with_data:,}")
        print(f"  - Flows with retransmits: {(merged['ebpf_retransmits'] > 0).sum():,}")
        print(f"  - Total bytes captured: {merged['ebpf_bytes_sent'].sum() + merged['ebpf_bytes_recv'].sum():,.0f}")
        
        sample = merged[merged['ebpf_bytes_sent'] > 0][["orig_h","resp_h","orig_p","resp_p","proto",
                                                          "ebpf_bytes_sent","ebpf_samples"]].head(5)
        if len(sample) > 0:
            print(f"\n  Sample enriched flows:")
            print("  " + sample.to_string().replace("\n", "\n  "))

if __name__ == "__main__":
    main()
