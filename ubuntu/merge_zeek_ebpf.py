#!/usr/bin/env python3
import argparse
import json
import os
import ipaddress
import pandas as pd

# Zeek can emit IPv6 in real networks; our eBPF collector is IPv4-only for now.
# We drop non-IPv4 rows during merge.
def normalize_key_cols(
    df: pd.DataFrame,
    *,
    saddr_col: str,
    daddr_col: str,
    sport_col: str,
    dport_col: str,
    proto_col: str,
) -> pd.DataFrame:
    out = df.copy()

    def to_u32(series: pd.Series) -> pd.Series:
        if series.dtype == object:
            return series.apply(ip_to_u32_maybe)
        # already numeric
        return pd.to_numeric(series, errors="coerce")

    out["k_saddr"] = to_u32(out[saddr_col]).astype("uint32")
    out["k_daddr"] = to_u32(out[daddr_col]).astype("uint32")
    out["k_sport"] = pd.to_numeric(out[sport_col], errors="coerce").fillna(0).astype(int)
    out["k_dport"] = pd.to_numeric(out[dport_col], errors="coerce").fillna(0).astype(int)

    if out[proto_col].dtype == object:
        m = {"tcp": 6, "udp": 17, "icmp": 1}
        out["k_proto"] = out[proto_col].astype(str).str.lower().map(m).fillna(0).astype(int)
    else:
        out["k_proto"] = pd.to_numeric(out[proto_col], errors="coerce").fillna(0).astype(int)

    return out

def ip_to_u32_maybe(ip: str):
    ip = str(ip).strip()
    if ":" in ip:
        return pd.NA
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return pd.NA

def ntohl_u32(u: int) -> int:
    u = int(u) & 0xFFFFFFFF
    return int.from_bytes(u.to_bytes(4, "little"), "big")

def flatten_meta(obj, prefix=""):
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
    required = [
        "ts","orig_h","resp_h","orig_p","resp_p","proto","duration",
        "orig_bytes","resp_bytes","orig_pkts","resp_pkts","conn_state",
    ]

    df = pd.read_csv(conn_csv)
    if not set(required).issubset(df.columns):
        df = pd.read_csv(conn_csv, header=None, names=required)

    # Some malformed/headerless reads can still leave a header as the first data row.
    if len(df) > 0 and str(df.iloc[0].get("ts", "")) == "ts":
        df = df.iloc[1:].copy()

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

    df["orig_ip_u32"] = df["orig_h"].apply(ip_to_u32_maybe)
    df["resp_ip_u32"] = df["resp_h"].apply(ip_to_u32_maybe)

    before = len(df)
    df = df.dropna(subset=["orig_ip_u32","resp_ip_u32"]).copy()
    dropped = before - len(df)
    if dropped:
        print(f"[*] Dropped {dropped} non-IPv4 Zeek rows (IPv6 not supported by eBPF collector yet).")

    df["orig_ip_u32"] = df["orig_ip_u32"].astype("uint32")
    df["resp_ip_u32"] = df["resp_ip_u32"].astype("uint32")

    return df

def load_ebpf_agg(jsonl: str) -> pd.DataFrame:
    rows = []
    with open(jsonl, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    if "saddr_str" in df.columns and "daddr_str" in df.columns:
        df["saddr_u32"] = df["saddr_str"].apply(ip_to_u32_maybe)
        df["daddr_u32"] = df["daddr_str"].apply(ip_to_u32_maybe)
        df["ip_decode"] = "str"
        variants = [df]
    else:
        raw = df.copy()
        raw["saddr_u32"] = raw["saddr"].astype("uint32")
        raw["daddr_u32"] = raw["daddr"].astype("uint32")
        raw["ip_decode"] = "raw"

        swapped = df.copy()
        swapped["saddr_u32"] = swapped["saddr"].astype("uint32").apply(ntohl_u32)
        swapped["daddr_u32"] = swapped["daddr"].astype("uint32").apply(ntohl_u32)
        swapped["ip_decode"] = "swapped"

        variants = [raw, swapped]

    df = pd.concat(variants, ignore_index=True)

    df = df.dropna(subset=["saddr_u32", "daddr_u32"]).copy()
    df["saddr_u32"] = df["saddr_u32"].astype("uint32")
    df["daddr_u32"] = df["daddr_u32"].astype("uint32")

    df["sport"] = pd.to_numeric(df["sport"], errors="coerce").fillna(0).astype(int)
    df["dport"] = pd.to_numeric(df["dport"], errors="coerce").fillna(0).astype(int)
    df["proto"] = pd.to_numeric(df["proto"], errors="coerce").fillna(0).astype(int)
    
    if "first_ts_s" not in df.columns and "first_ts_ns" in df.columns:
        if "flush_ts_s" in df.columns and "last_ts_ns" in df.columns:
            # offset_ns ≈ epoch_at_flush - mono_last
            offset_ns = (df["flush_ts_s"].astype(float) * 1e9) - df["last_ts_ns"].astype(float)
            df["first_ts_s"] = (df["first_ts_ns"].astype(float) + offset_ns) / 1e9
            df["last_ts_s"]  = (df["last_ts_ns"].astype(float)  + offset_ns) / 1e9
        else:
            print("[!] eBPF JSONL missing first_ts_s/last_ts_s and cannot reconstruct; time filtering may be invalid.")
            df["first_ts_s"] = df["first_ts_ns"].astype(float) / 1e9
            df["last_ts_s"]  = df["last_ts_ns"].astype(float)  / 1e9
    return df

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek_conn", required=True)
    ap.add_argument("--ebpf_agg", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--time_slop", type=float, default=5.0)
    ap.add_argument(
        "--run_meta",
        default="",
        help="Optional run-level metadata JSON (e.g., from run_capture.sh). If present, its fields are appended as constant columns (prefixed 'run_').",
    )
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    z = load_zeek_conn(args.zeek_conn)
    e = load_ebpf_agg(args.ebpf_agg)

    if e.empty:
        out = z.copy()
        for c in ["ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits","ebpf_state_changes","ebpf_samples"]:
            out[c] = 0.0
        out.to_csv(args.out, index=False)
        print(f"[!] No eBPF data. Wrote Zeek-only: {args.out}")
        return

    # Build forward/reverse keyed views WITHOUT destroying Zeek's original columns.
    z_fwd = z.copy()
    z_fwd["saddr_u32"] = z_fwd["orig_ip_u32"].astype("uint32")
    z_fwd["daddr_u32"] = z_fwd["resp_ip_u32"].astype("uint32")
    z_fwd["sport"] = z_fwd["orig_p"].astype(int)
    z_fwd["dport"] = z_fwd["resp_p"].astype(int)
    z_fwd["proto_key"] = z_fwd["proto_num"].astype(int)

    z_rev = z.copy()
    z_rev["saddr_u32"] = z_rev["resp_ip_u32"].astype("uint32")
    z_rev["daddr_u32"] = z_rev["orig_ip_u32"].astype("uint32")
    z_rev["sport"] = z_rev["resp_p"].astype(int)
    z_rev["dport"] = z_rev["orig_p"].astype(int)
    z_rev["proto_key"] = z_rev["proto_num"].astype(int)

    # Normalise keys WITHOUT overwriting Zeek's string proto column.
    z_fwd = normalize_key_cols(
        z_fwd,
        saddr_col="saddr_u32",
        daddr_col="daddr_u32",
        sport_col="sport",
        dport_col="dport",
        proto_col="proto_key",
    )
    z_rev = normalize_key_cols(
        z_rev,
        saddr_col="saddr_u32",
        daddr_col="daddr_u32",
        sport_col="sport",
        dport_col="dport",
        proto_col="proto_key",
    )
    e = normalize_key_cols(
        e,
        saddr_col="saddr_u32",
        daddr_col="daddr_u32",
        sport_col="sport",
        dport_col="dport",
        proto_col="proto",
    )

    merged_fwd = z_fwd.merge(
        e,
        on=["k_saddr","k_daddr","k_sport","k_dport","k_proto"],
        how="left",
        suffixes=("", "_e"),
    )
    merged_rev = z_rev.merge(
        e,
        on=["k_saddr","k_daddr","k_sport","k_dport","k_proto"],
        how="left",
        suffixes=("", "_e"),
    )

    merged = merged_fwd.copy()
    choose_rev = merged["first_ts_s"].isna() & merged_rev["first_ts_s"].notna()
    merged.loc[choose_rev, merged.columns] = merged_rev.loc[choose_rev, merged.columns]

    has = merged["first_ts_s"].notna()
    ok = (
        ~has |
        ((merged["first_ts_s"] <= merged["end_ts"] + args.time_slop) &
         (merged["last_ts_s"]  >= merged["start_ts"] - args.time_slop))
    )
    merged = merged[ok].copy()

    merged["ebpf_bytes_sent"] = merged.get("bytes_sent", 0).fillna(0).astype(float)
    merged["ebpf_bytes_recv"] = merged.get("bytes_recv", 0).fillna(0).astype(float)
    merged["ebpf_retransmits"] = merged.get("retransmits", 0).fillna(0).astype(float)
    merged["ebpf_state_changes"] = merged.get("state_changes", 0).fillna(0).astype(float)
    merged["ebpf_samples"] = merged.get("samples", 0).fillna(0).astype(float)

    # Process context (mode of last-seen process for the flow)
    merged["ebpf_pid"] = merged.get("pid_mode", 0).fillna(0).astype(int)
    merged["ebpf_uid"] = merged.get("uid_mode", 0).fillna(0).astype(int)
    merged["ebpf_comm"] = merged.get("comm_mode", "").fillna("").astype(str)

    # Optional run metadata (tcpreplay, interface, etc.)
    run_meta_cols = []
    if args.run_meta:
        try:
            with open(args.run_meta, "r") as f:
                meta = json.load(f)
            flat = flatten_meta(meta)
            for k, v in flat.items():
                col = "run_" + str(k)
                merged[col] = v
                run_meta_cols.append(col)
        except FileNotFoundError:
            print(f"[!] --run_meta not found: {args.run_meta} (skipping)")
        except Exception as ex:
            print(f"[!] Failed to read --run_meta {args.run_meta}: {ex} (skipping)")

    out_cols = [
        "ts","duration","orig_h","resp_h","orig_p","resp_p","proto","conn_state",
        "orig_bytes","resp_bytes","orig_pkts","resp_pkts",
        "start_ts","end_ts",
        "ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits","ebpf_state_changes","ebpf_samples",
        "ebpf_pid","ebpf_uid","ebpf_comm",
    ]
    out_cols.extend(run_meta_cols)
    merged[out_cols].to_csv(args.out, index=False)
    print(f"[*] Wrote enriched flows: {args.out}")
    print(f"[*] Enriched matches: {int(has.sum())}/{len(merged)}")

if __name__ == "__main__":
    main()
