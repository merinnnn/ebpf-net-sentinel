#!/usr/bin/env python3
import argparse, json, os, ipaddress
import pandas as pd

def ip_to_u32(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))

def u32be_to_u32(u: int) -> int:
    return int(ipaddress.IPv4Address(u.to_bytes(4, "big")))

def load_zeek_conn(conn_csv: str) -> pd.DataFrame:
    cols = ["ts","orig_h","resp_h","orig_p","resp_p","proto","duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts","conn_state"]
    df = pd.read_csv(conn_csv, header=None, names=cols)
    df["orig_p"] = df["orig_p"].astype(int)
    df["resp_p"] = df["resp_p"].astype(int)
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce").fillna(0.0)
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)
    for c in ["orig_bytes","resp_bytes","orig_pkts","resp_pkts"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    df["proto"] = df["proto"].astype(str).str.upper()
    df["start_ts"] = df["ts"]
    df["end_ts"] = df["ts"] + df["duration"]
    df["orig_ip_u32"] = df["orig_h"].apply(ip_to_u32)
    df["resp_ip_u32"] = df["resp_h"].apply(ip_to_u32)
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

def add_ebpf_cols(df: pd.DataFrame) -> pd.DataFrame:
    df["ebpf_bytes_sent"] = df["bytes_sent"].fillna(0).astype(float)
    df["ebpf_bytes_recv"] = df["bytes_recv"].fillna(0).astype(float)
    df["ebpf_retransmits"] = df["retransmits"].fillna(0).astype(float)
    df["ebpf_state_changes"] = df["state_changes"].fillna(0).astype(float)
    df["ebpf_samples"] = df["samples"].fillna(0).astype(float)
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

    proto_map = {"TCP": 6, "UDP": 17}
    z["proto_num"] = z["proto"].map(proto_map).fillna(0).astype(int)

    if e.empty:
        out = z.copy()
        for c in ["ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits","ebpf_state_changes","ebpf_samples"]:
            out[c] = 0.0
        out.to_csv(args.out, index=False)
        print(f"[!] No eBPF data. Wrote Zeek-only: {args.out}")
        return

    z = z.reset_index(drop=True)
    z["zeek_row"] = z.index.astype(int)

    # Direction A: Zeek orig->resp matches eBPF saddr->daddr
    m1 = z.merge(
        e,
        left_on=["orig_ip_u32","resp_ip_u32","orig_p","resp_p","proto_num"],
        right_on=["saddr_u32","daddr_u32","sport","dport","proto"],
        how="left"
    )
    m1["match_dir"] = "orig_resp"

    # Direction B: Zeek orig->resp matches eBPF daddr->saddr (swapped)
    m2 = z.merge(
        e,
        left_on=["orig_ip_u32","resp_ip_u32","orig_p","resp_p","proto_num"],
        right_on=["daddr_u32","saddr_u32","dport","sport","proto"],
        how="left"
    )
    m2["match_dir"] = "resp_orig"

    merged = pd.concat([m1, m2], ignore_index=True)

    has = merged["first_ts_s"].notna()
    ok = (
        ~has |
        ((merged["first_ts_s"] <= merged["end_ts"] + args.time_slop) &
         (merged["last_ts_s"]  >= merged["start_ts"] - args.time_slop))
    )
    merged = merged[ok].copy()

    # If multiple eBPF rows match one Zeek row, keep the one with best time overlap
    # overlap = min(end_ts, last_ts_s) - max(start_ts, first_ts_s)
    merged["overlap"] = 0.0
    has = merged["first_ts_s"].notna()
    merged.loc[has, "overlap"] = (
        (merged.loc[has, ["end_ts","last_ts_s"]].min(axis=1)) -
        (merged.loc[has, ["start_ts","first_ts_s"]].max(axis=1))
    )

    merged = merged.sort_values(["zeek_row","overlap"], ascending=[True, False])
    merged = merged.drop_duplicates(subset=["zeek_row"], keep="first").copy()

    merged = add_ebpf_cols(merged)

    out_cols = [
        "ts","duration","orig_h","resp_h","orig_p","resp_p","proto","conn_state",
        "orig_bytes","resp_bytes","orig_pkts","resp_pkts",
        "start_ts","end_ts",
        "ebpf_bytes_sent","ebpf_bytes_recv","ebpf_retransmits","ebpf_state_changes","ebpf_samples",
        "match_dir"
    ]
    merged[out_cols].to_csv(args.out, index=False)
    print(f"[*] Wrote enriched flows: {args.out}")

if __name__ == "__main__":
    main()
