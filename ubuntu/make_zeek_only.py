#!/usr/bin/env python3
import argparse
import os
import pandas as pd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_csv", required=True)
    ap.add_argument("--out_csv", required=True)
    args = ap.parse_args()

    out_dir = os.path.dirname(args.out_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    df = pd.read_csv(args.in_csv)

    ebpf_cols = [c for c in df.columns if c.startswith("ebpf_")]
    out = df.drop(columns=ebpf_cols, errors="ignore")

    out.to_csv(args.out_csv, index=False)
    print(f"Wrote: {args.out_csv} (dropped {len(ebpf_cols)} ebpf_* columns)")

if __name__ == "__main__":
    main()
