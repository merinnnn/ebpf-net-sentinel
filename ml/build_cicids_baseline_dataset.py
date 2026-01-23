import argparse
import os
import glob
import re
import pandas as pd
import numpy as np

def parse_arguments():
    parser = argparse.ArgumentParser(description="Build CICIDS Baseline Dataset")
    parser.add_argument('--csv_dir', type=str, required=True, help='Directory containing raw CSV files')
    parser.add_argument('--output_dir', type=str, required=True, help='Output directory for the baseline dataset')
    parser.add_argument("--max_rows", type=int, default=0, help="Optional cap for quick tests")
    parser.add_argument("--seed", type=int, default=42, help="Seed for sampling")
    parser.add_argument("--format", choices=["csv", "parquet"], default="csv", help="Output format")
    parser.add_argument("--out_name", type=str, default="cicids2017_baseline_clean", help="Base output filename (no ext)")
    return parser.parse_args()

def clean_column_names(cols):
    out = []
    for c in cols:
        c = str(c).strip()
        c = re.sub(r"\s+", "_", c)
        c = c.replace("/", "_").replace("-", "_")
        out.append(c)
    return out

def load_and_concatenate_csvs(csv_dir) -> pd.DataFrame:
    all_files = sorted(glob.glob(os.path.join(csv_dir, "*.csv")))
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in directory: {csv_dir}")

    df_list = []
    for file in all_files:
        df = pd.read_csv(file, encoding="utf-8", low_memory=False)
        df.columns = clean_column_names(df.columns)
        df_list.append(df)
        # log each file
        print(f"Loaded {os.path.basename(file)} -> {df.shape}")

    combined_df = pd.concat(df_list, ignore_index=True)
    print("Concatenated:", combined_df.shape)
    return combined_df

def pick_label_col(df: pd.DataFrame) -> str:
    for cand in ["Label", "label"]:
        if cand in df.columns:
            return cand
    raise ValueError("No Label column found in CICIDS files.")

def main():
    args = parse_arguments()
    os.makedirs(args.output_dir, exist_ok=True)

    print("Loading and concatenating CSV files...")
    df = load_and_concatenate_csvs(args.csv_dir)

    if args.max_rows and args.max_rows > 0:
        df = df.sample(n=args.max_rows, random_state=args.seed).reset_index(drop=True)
        print("Sampled:", df.shape)
    else:
        print("Dataset loaded with shape:", df.shape)

    label_col = pick_label_col(df)
    print(f"Using '{label_col}' as the label column.")
    df[label_col] = df[label_col].astype(str).str.strip()
    df["is_attack"] = (df[label_col].str.upper() != "BENIGN").astype(int)
    
    # TODO: Further feature engineering can be added here
    drop_like = {
        "Flow_ID", "Src_IP", "Dst_IP", "Timestamp", "Fwd_Header_Length",
        "Bwd_Header_Length", "Fwd_PSH_Flags", "Bwd_PSH_Flags",
        "Fwd_URG_Flags", "Bwd_URG_Flags"
    }
    feat_df = df.drop(columns=[c for c in df.columns if c in drop_like], errors="ignore")

    feat_df = feat_df.replace([np.inf, -np.inf], np.nan)

    numeric_cols = []
    for col in feat_df.columns:
        if pd.api.types.is_numeric_dtype(feat_df[col]):
            numeric_cols.append(col)
        else:
            coerced = pd.to_numeric(feat_df[col], errors='coerce')
            if coerced.notna().mean() > 0.95:
                feat_df[col] = coerced
                numeric_cols.append(col)

    feat_df = feat_df[numeric_cols].fillna(0.0)

    out = feat_df.copy()
    out["Label"] = df[label_col]
    out["is_attack"] = df["is_attack"]

    out_path = os.path.join(args.output_dir, f"{args.out_name}.{args.format}")
    if args.format == "csv":
        out.to_csv(out_path, index=False)
    else:
        out.to_parquet(out_path, index=False)

    cols_path = os.path.join(args.output_dir, "cicids_baseline_columns.txt")
    with open(cols_path, "w") as f:
        for c in feat_df.columns:
            f.write(c + "\n")

    print(f"Wrote: {out_path}")
    print(f"Wrote: {cols_path}")
    print("Final shape:", out.shape)
    print("Attack rate:", float(out["is_attack"].mean()))

if __name__ == "__main__":
    main()
