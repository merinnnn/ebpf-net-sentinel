#!/usr/bin/env python3
"""
Add 'has_process_context' feature to fix the DDoS detection problem
"""
import pandas as pd

# Load the eBPF-enhanced dataset
input_file = 'data/datasets/cicids2017_multiclass_zeek_plus_ebpf.parquet'
output_file = 'data/datasets/cicids2017_multiclass_zeek_plus_ebpf_v2.parquet'

print(f"\n[*] Loading: {input_file}")
df = pd.read_parquet(input_file)

print(f"[*] Original dataset: {len(df):,} rows, {len(df.columns)} columns")

# Add binary feature indicating whether eBPF process context is meaningful
if 'ebpf_pid' in df.columns:
    df['has_process_context'] = (df['ebpf_pid'] > 0).astype(int)
    
    # Statistics
    with_context = (df['has_process_context'] == 1).sum()
    without_context = (df['has_process_context'] == 0).sum()
    
    print(f"\n[*] Process context statistics:")
    print(f"  Samples WITH process context (pid>0):    {with_context:>10,} ({with_context/len(df)*100:5.1f}%)")
    print(f"  Samples WITHOUT process context (pid=0): {without_context:>10,} ({without_context/len(df)*100:5.1f}%)")
    
    # Per attack type
    if 'label_family' in df.columns:
        print(f"\n[*] Process context by attack type:")
        print(f"  {'Attack':<20} {'Total':>10} {'With Context':>15} {'%':>8}")
        print(f"  {'-'*55}")
        
        for attack in sorted(df['label_family'].unique()):
            mask = df['label_family'] == attack
            total = mask.sum()
            with_ctx = (mask & (df['has_process_context'] == 1)).sum()
            pct = (with_ctx / total * 100) if total > 0 else 0
            print(f"  {attack:<20} {total:>10,} {with_ctx:>15,} {pct:>7.1f}%")
    
    # Save updated dataset
    print(f"\n[*] Saving: {output_file}")
    df.to_parquet(output_file, index=False)
    
    print(f"[*] New dataset: {len(df):,} rows, {len(df.columns)} columns")
else:
    print("\n[!] ERROR: 'ebpf_pid' column not found!")
    print("Available columns:", df.columns.tolist())
