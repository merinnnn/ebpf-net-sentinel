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
    return parser.parse_args()

def clean_column_names(cols: pd.DataFrame) -> pd.DataFrame:
    out = []
    for c in cols:
        c = str(c).strip()
        c = re.sub(r"\s+", "_", c)
        c = c.replace("/", "_").replace("-", "_")
        out.append(c)
    return out

def load_and_concatenate_csvs(csv_dir, max_rows=0) -> pd.DataFrame:
    all_files = sorted(glob.glob(os.path.join(csv_dir, "*.csv")))
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in directory: {csv_dir}")
    df_list = []
    for file in all_files:
        df = pd.read_csv(file, encoding="utf-8", low_memory=False)
        df.columns = clean_column_names(df.columns)
        df_list.append(df)
    combined_df = pd.concat(df_list, ignore_index=True)
    if max_rows > 0:
        combined_df = combined_df.head(max_rows)
    return combined_df

def main():
    args = parse_arguments()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    print("Loading and concatenating CSV files...")
    df = load_and_concatenate_csvs(args.csv_dir, args.max_rows)
    
    print("Dataset loaded with shape:", df.shape)
    
    output_path = os.path.join(args.output_dir, "cicids_baseline_dataset.csv")
    df.to_csv(output_path, index=False)
    
    print(f"Baseline dataset saved to {output_path}")

if __name__ == "__main__":
    main()