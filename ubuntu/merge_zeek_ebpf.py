#!/usr/bin/env python3
import argparse, json, os, ipaddress
import pandas as pd

# Zeek can emit IPv6 in real networks; our eBPF collector is IPv4-only for now.
# We drop non-IPv4 rows during merge.

def ip_to_u32_maybe(ip: str):
    ip = str(ip).strip()
    if ":" in ip:
        return pd.NA
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return pd.NA

def u32be_to_u32(u: int) -> int:
    return int(ipaddress.IPv4Address(u.to_bytes(4, "big")))

def load_zeek_conn(conn_csv: str) -> pd.DataFrame:
    cols = ["ts","orig_h","resp_h","orig_p","resp_p","proto","duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts","conn_state"]
    df0 = pd.read_csv(conn_csv, header=None, names=cols)
    df = df0.copy()

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
    df["saddr_u32"] = df["saddr"].astype("uint32").apply(u32be_to_u32)
    df["daddr_u32"] = df["daddr"].astype("uint32").apply(u32be_to_u32)
    df["sport"] = df["sport"].astype(int)
    df["dport"] = df["dport"].astype(int)
    df["proto"] = df["proto"].astype(int)
    df["first_ts_s"] = df["first_ts_ns"].astype(float) / 1e9
    df["last_ts_s"] = df["last_ts_ns"].astype(float) / 1e9
    return df

def normalize_key(df: pd.DataFrame, prefix: str = "") -> pd.DataFrame:
    df = df.copy()
    df["k_saddr"] = df[f"{prefix}saddr_u32"].astype("uint32")
    df["k_daddr"] = df[f"{prefix}daddr_u32"].astype("uint32")
    df["k_sport"] = df[f"{prefix}sport"].astype(int)
    df["k_dport"] = df[f"{prefix}dport"].astype(int)
    df["k_proto"] = df[f"{prefix}proto"].astype(int)
    return df

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek_conn", required=True)
    ap.add_argument("--ebpf_agg", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--time_slop", type=float, default=5.0)
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

    # Drop Zeek string proto column during keying to avoid duplicate name issues
    z_key = z.drop(columns=["proto"], errors="ignore")

    z_fwd = z_key.rename(columns={
        "orig_ip_u32": "saddr_u32",
        "resp_ip_u32": "daddr_u32",
        "orig_p": "sport",
        "resp_p": "dport",
        "proto_num": "proto",
    })
    z_rev = z_key.rename(columns={
        "orig_ip_u32": "daddr_u32",
        "resp_ip_u32": "saddr_u32",
        "orig_p": "dport",
        "resp_p": "sport",
        "proto_num": "proto",
    })

    z_fwd = normalize_key(z_fwd)
    z_rev = normalize_key(z_rev)
    e = normalize_key(e)

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

    merged["ebpf_bytes_sent"] = merged["bytes_sent"].fillna(0).astype(float)
    merged["ebpf_bytes_recv"] = merged["bytes_recv"].fillna(0).astype(float)
    merged["ebpf_retransmits"] = merged["retransmits"].fillna(0).astype(float)
    merged["ebpf_state_changes"] = merged["state_changes"].fillna(0).astype(float)
    merged["ebpf_samples"] = merged["samples"].fillna(0).astype(float)

    out_cols = [
        "ts","duration","orig_h","resp_h","orig_p","resp_p","proto","conn_state",
        "orig_bytes","resp_bytes","orig_pkts","resp_pkts",
        "start_ts","end_ts",
        "ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits","ebpf_state_changes","ebpf_samples"
    ]
    merged[out_cols].to_csv(args.out, index=False)
    print(f"[*] Wrote enriched flows: {args.out}")
    print(f"[*] Enriched matches: {int(has.sum())}/{len(merged)}")

if __name__ == "__main__":
    main()
