#!/usr/bin/env python3
import argparse
import json
import os
import ipaddress
import pandas as pd
import sys
from collections import defaultdict

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
    """Load eBPF aggregated flow data"""
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
    
    # Handle timestamp conversion
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

def detect_replay_scenario(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame, debug: bool = False):
    """
    Detect if this is a PCAP replay scenario based on time compression.
    
    Returns:
        tuple: (is_replay, compression_ratio, replay_type)
            is_replay: bool
            compression_ratio: float (zeek_span / ebpf_span)
            replay_type: str ('topspeed', 'fast', 'moderate', 'realtime', 'live')
    """
    zeek_span = zeek_df['end_ts'].max() - zeek_df['start_ts'].min()
    ebpf_span = ebpf_df['last_ts_s'].max() - ebpf_df['first_ts_s'].min()
    
    # Avoid division by zero
    if ebpf_span < 1.0:
        ebpf_span = 1.0
    
    compression = zeek_span / ebpf_span
    
    # Classify scenario
    if compression > 500:
        replay_type = 'topspeed'
        is_replay = True
    elif compression > 100:
        replay_type = 'fast'
        is_replay = True
    elif compression > 10:
        replay_type = 'moderate'
        is_replay = True
    elif compression > 2:
        replay_type = 'realtime'
        is_replay = True
    else:
        replay_type = 'live'
        is_replay = False
    
    if debug:
        print(f"\n[DEBUG] Replay detection:")
        print(f"  Zeek time span:    {zeek_span:.1f}s ({zeek_span/3600:.1f} hours)")
        print(f"  eBPF capture span: {ebpf_span:.1f}s ({ebpf_span/60:.1f} minutes)")
        print(f"  Compression ratio: {compression:.1f}x")
        print(f"  Scenario: {replay_type.upper()} {'(REPLAY)' if is_replay else '(LIVE)'}")
    
    return is_replay, compression, replay_type

def synchronize_timestamps(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame, debug: bool = False):
    """Align eBPF timestamps with PCAP timeline"""
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
        from datetime import datetime
        print(f"\n[DEBUG] Timestamp synchronization:")
        print(f"  Zeek timeline:  {zeek_min:.1f} to {zeek_max:.1f} (span: {zeek_max-zeek_min:.1f}s)")
        print(f"  eBPF timeline:  {ebpf_min:.1f} to {ebpf_max:.1f} (span: {ebpf_max-ebpf_min:.1f}s)")
        print(f"  Offset needed:  {offset:.1f}s ({offset/86400:.1f} days)")
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

def match_flows_with_deduplication(zeek_df: pd.DataFrame, ebpf_df: pd.DataFrame, 
                                   is_replay: bool, debug: bool = False):
    """
    Match flows with intelligent duplicate handling.
    
    For replay scenarios: Uses one-to-one matching to prevent duplicate 5-tuple issues.
    For live capture: Uses standard merge with time window filtering.
    """
    # Create 5-tuple keys
    zeek_df = zeek_df.copy()
    ebpf_df = ebpf_df.copy()
    
    # Forward direction keys
    zeek_df["key_fwd"] = (
        zeek_df["orig_ip_u32"].astype(str) + "_" +
        zeek_df["resp_ip_u32"].astype(str) + "_" +
        zeek_df["orig_p"].astype(str) + "_" +
        zeek_df["resp_p"].astype(str) + "_" +
        zeek_df["proto_num"].astype(str)
    )
    
    # Reverse direction keys
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
        # Replay mode: One-to-one matching to handle duplicates correctly
        print("[*] Using replay-aware matching (prevents duplicate 5-tuple issues)...")
        
        # Build eBPF lookup dict (key -> first occurrence)
        ebpf_lookup = {}
        for idx, row in ebpf_df.iterrows():
            key = row['key']
            if key not in ebpf_lookup:
                ebpf_lookup[key] = row
        
        if debug:
            dup_keys = len(ebpf_df) - len(ebpf_lookup)
            if dup_keys > 0:
                print(f"[DEBUG] Found {dup_keys} duplicate 5-tuples in eBPF (using first occurrence)")
        
        # Match Zeek flows to eBPF
        matched_data = []
        stats = {'fwd': 0, 'rev': 0, 'unmatched': 0}
        
        for idx, zrow in zeek_df.iterrows():
            ebpf_match = None
            direction = None
            
            # Try forward match
            if zrow['key_fwd'] in ebpf_lookup:
                ebpf_match = ebpf_lookup[zrow['key_fwd']]
                direction = 'forward'
                stats['fwd'] += 1
            # Try reverse match
            elif zrow['key_rev'] in ebpf_lookup:
                ebpf_match = ebpf_lookup[zrow['key_rev']]
                direction = 'reverse'
                stats['rev'] += 1
            else:
                stats['unmatched'] += 1
            
            # Combine Zeek and eBPF data
            combined = zrow.to_dict()
            if ebpf_match is not None:
                for k, v in ebpf_match.items():
                    if k not in ['key']:  # Don't copy the key itself
                        combined[f'ebpf_{k}'] = v
            
            matched_data.append(combined)
        
        merged = pd.DataFrame(matched_data)
        
        print(f"[*] Matched: {stats['fwd']} forward, {stats['rev']} reverse, {stats['unmatched']} unmatched")
        
    else:
        # Live mode: Standard pandas merge
        print("[*] Using standard merge (live capture mode)...")
        
        zeek_fwd = zeek_df.copy()
        zeek_fwd['k_saddr'] = zeek_fwd['orig_ip_u32']
        zeek_fwd['k_daddr'] = zeek_fwd['resp_ip_u32']
        zeek_fwd['k_sport'] = zeek_fwd['orig_p']
        zeek_fwd['k_dport'] = zeek_fwd['resp_p']
        zeek_fwd['k_proto'] = zeek_fwd['proto_num']
        
        zeek_rev = zeek_df.copy()
        zeek_rev['k_saddr'] = zeek_rev['resp_ip_u32']
        zeek_rev['k_daddr'] = zeek_rev['orig_ip_u32']
        zeek_rev['k_sport'] = zeek_rev['resp_p']
        zeek_rev['k_dport'] = zeek_rev['orig_p']
        zeek_rev['k_proto'] = zeek_rev['proto_num']
        
        ebpf_keyed = ebpf_df.copy()
        ebpf_keyed['k_saddr'] = ebpf_keyed['saddr_u32']
        ebpf_keyed['k_daddr'] = ebpf_keyed['daddr_u32']
        ebpf_keyed['k_sport'] = ebpf_keyed['sport']
        ebpf_keyed['k_dport'] = ebpf_keyed['dport']
        ebpf_keyed['k_proto'] = ebpf_keyed['proto']
        
        merged_fwd = zeek_fwd.merge(
            ebpf_keyed,
            on=["k_saddr","k_daddr","k_sport","k_dport","k_proto"],
            how="left",
            suffixes=("", "_ebpf")
        )
        
        merged_rev = zeek_rev.merge(
            ebpf_keyed,
            on=["k_saddr","k_daddr","k_sport","k_dport","k_proto"],
            how="left",
            suffixes=("", "_ebpf")
        )
        
        # Prefer forward, use reverse for unmatched
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
    Apply time window filter intelligently.
    
    For replay scenarios with high compression: Skip time filtering (use 5-tuple only).
    For live/moderate replay: Apply standard time window filter.
    """
    # Detect if we have eBPF data
    has_ebpf_col = 'first_ts_s' in merged.columns or 'ebpf_first_ts_s' in merged.columns
    
    if not has_ebpf_col:
        return merged
    
    # Normalize column names
    ts_col = 'ebpf_first_ts_s' if 'ebpf_first_ts_s' in merged.columns else 'first_ts_s'
    ts_end_col = 'ebpf_last_ts_s' if 'ebpf_last_ts_s' in merged.columns else 'last_ts_s'
    
    has_ebpf = merged[ts_col].notna()
    
    if not has_ebpf.any():
        return merged
    
    if is_replay:
        # Replay mode: Skip time filter, rely on 5-tuple matching
        print(f"[*] Skipping time filter (replay scenario - using 5-tuple matching only)")
        if debug:
            print(f"[DEBUG] In replay mode, time filtering would incorrectly reject valid matches")
            print(f"[DEBUG] All matched flows retained based on 5-tuple")
        return merged
    else:
        # Live mode: Apply time window filter
        print(f"[*] Applying time window filter (±{time_slop}s)...")
        
        time_ok = (
            (merged[ts_col] <= merged["end_ts"] + time_slop) &
            (merged[ts_end_col] >= merged["start_ts"] - time_slop)
        )
        
        valid = ~has_ebpf | time_ok
        filtered_out = (~valid).sum()
        
        if filtered_out > 0:
            print(f"[*] Filtered out {filtered_out} flows due to time mismatch")
            if debug and filtered_out < 100:
                mismatched = merged[~valid][["orig_h","resp_h","orig_p","resp_p","proto",
                                              "start_ts","end_ts",ts_col,ts_end_col]].head(10)
                print("[DEBUG] Sample time mismatches:")
                print(mismatched.to_string())
        
        return merged[valid].copy()

def main():
    ap = argparse.ArgumentParser(description="Bulletproof Zeek-eBPF merge with intelligent replay detection")
    ap.add_argument("--zeek_conn", required=True, help="Zeek conn.csv file")
    ap.add_argument("--ebpf_agg", required=True, help="eBPF aggregated JSONL file")
    ap.add_argument("--out", required=True, help="Output merged CSV file")
    ap.add_argument("--time_slop", type=float, default=5.0, 
                    help="Time window tolerance in seconds for live capture (default: 5.0)")
    ap.add_argument("--run_meta", default="", help="Optional run metadata JSON")
    ap.add_argument("--debug", action="store_true", help="Enable debug output")
    ap.add_argument("--force_replay_mode", action="store_true",
                    help="Force replay mode (skip time filter) even if auto-detection fails")
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

    # Detect replay scenario
    is_replay, compression, replay_type = detect_replay_scenario(z, e, debug=args.debug)
    
    if args.force_replay_mode:
        print("[!] Force replay mode enabled")
        is_replay = True
        replay_type = 'forced'

    # Match flows with appropriate strategy
    merged = match_flows_with_deduplication(z, e, is_replay=is_replay, debug=args.debug)

    # Apply time filter (or skip for replay)
    merged = apply_time_filter(merged, args.time_slop, is_replay=is_replay, debug=args.debug)

    # Helper function for safe column access
    def col(df, name, default):
        # Try with ebpf_ prefix first
        if f'ebpf_{name}' in df.columns:
            return df[f'ebpf_{name}']
        if name in df.columns:
            return df[name]
        return pd.Series([default] * len(df), index=df.index)

    # Create standardized output columns
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

    # Filter to columns that exist
    out_cols = [c for c in out_cols if c in merged.columns]
    
    # Write output
    merged[out_cols].to_csv(args.out, index=False)
    
    # Calculate statistics
    total_flows = len(merged)
    enriched_flows = int((merged['ebpf_samples'] > 0).sum())
    flows_with_data = int((merged['ebpf_bytes_sent'] > 0).sum())
    
    enrichment_rate = (enriched_flows / total_flows * 100) if total_flows > 0 else 0
    data_rate = (flows_with_data / total_flows * 100) if total_flows > 0 else 0
    
    print(f"\n[*] MERGE COMPLETE")
    print(f"[*] Scenario: {replay_type.upper()} ({'REPLAY' if is_replay else 'LIVE CAPTURE'})")
    print(f"[*] Total flows: {total_flows:,}")
    print(f"[*] Enriched with eBPF: {enriched_flows:,} ({enrichment_rate:.1f}%)")
    print(f"[*] Flows with packet data: {flows_with_data:,} ({data_rate:.1f}%)")
    print(f"[*] Output written to: {args.out}")
    
    # Debug statistics
    if args.debug and flows_with_data > 0:
        print("\n[DEBUG] eBPF enrichment statistics:")
        print(f"  - Flows with bytes_sent > 0: {flows_with_data:,}")
        print(f"  - Flows with retransmits: {(merged['ebpf_retransmits'] > 0).sum():,}")
        total_bytes = merged['ebpf_bytes_sent'].sum() + merged['ebpf_bytes_recv'].sum()
        print(f"  - Total bytes captured: {total_bytes:,.0f}")
        
        sample = merged[merged['ebpf_bytes_sent'] > 0][["orig_h","resp_h","orig_p","resp_p","proto",
                                                          "ebpf_bytes_sent","ebpf_samples"]].head(5)
        if len(sample) > 0:
            print(f"\n  Sample enriched flows:")
            print("  " + sample.to_string().replace("\n", "\n  "))

if __name__ == "__main__":
    main()
