#!/usr/bin/env python3
"""Random Forest for Network Anomaly Detection"""
import argparse, json, os, time, joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

def prepare_data(df):
    drop = ['label_family','is_attack','day','label_raw','run_id','ts','start_ts','end_ts','t_end','orig_h','resp_h','src_ip','dst_ip','k','label_time_offset_sec','label_halfday_shift_sec','label_window_pre_slop_sec','label_window_post_slop_sec']
    X = df.drop(columns=drop, errors='ignore')
    numeric = [c for c in X.columns if X[c].dtype in ['int64','float64']]
    return X[numeric].fillna(0), (df['is_attack']==1).astype(int), df['label_family'].astype(str)

def evaluate(y_true, y_pred, y_prob=None):
    m = {'accuracy':float(accuracy_score(y_true,y_pred)), 'precision':float(precision_score(y_true,y_pred,zero_division=0)), 'recall':float(recall_score(y_true,y_pred)), 'f1':float(f1_score(y_true,y_pred))}
    if y_prob is not None:
        try: m['roc_auc'] = float(roc_auc_score(y_true, y_prob))
        except: m['roc_auc'] = None
    return m

def per_attack(labels, y_true, y_pred):
    r = {}
    for a in sorted(labels.unique()):
        if a == "BENIGN": continue
        mask = (labels == a).to_numpy()
        if mask.sum() == 0: continue
        det = (y_pred[mask]==1).sum()
        r[a] = {'count':int(mask.sum()), 'detected':int(det), 'detection_rate':float(det/mask.sum())}
    return r

def plot_cm(cm, out):
    plt.figure(figsize=(8,6))
    cm_n = cm.astype('float') / cm.sum(axis=1)[:,np.newaxis]
    plt.imshow(cm_n, cmap='Blues')
    plt.title('Confusion Matrix')
    plt.colorbar()
    for i in range(2):
        for j in range(2):
            plt.text(j,i,f'{cm[i,j]}\n({cm_n[i,j]:.2%})', ha="center", va="center", color="white" if cm_n[i,j]>0.5 else "black")
    plt.ylabel('True'); plt.xlabel('Predicted')
    plt.xticks([0,1],['BENIGN','ATTACK']); plt.yticks([0,1],['BENIGN','ATTACK'])
    plt.tight_layout(); plt.savefig(out, dpi=200); plt.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--splits_dir", required=True)
    p.add_argument("--run_name", required=True)
    p.add_argument("--out_models_dir", default="data/models")
    p.add_argument("--out_reports_dir", default="data/reports")
    p.add_argument("--n_estimators", type=int, default=200)
    p.add_argument("--max_depth", type=int, default=20)
    p.add_argument("--balance_classes", action="store_true", default=True)
    args = p.parse_args()
    os.makedirs(args.out_models_dir, exist_ok=True)
    os.makedirs(args.out_reports_dir, exist_ok=True)
    
    print(f"[*] Random Forest: {args.run_name}")
    
    train_df = pd.read_parquet(f"{args.splits_dir}/train.parquet")
    val_df = pd.read_parquet(f"{args.splits_dir}/val.parquet")
    test_df = pd.read_parquet(f"{args.splits_dir}/test.parquet")
    
    X_train, y_train, _ = prepare_data(train_df)
    X_val, y_val, _ = prepare_data(val_df)
    X_test, y_test, labels_test = prepare_data(test_df)
    
    print(f"\nTrain: {len(X_train):,} ({(y_train==1).sum():,} attacks)")
    print(f"Val:   {len(X_val):,} ({(y_val==1).sum():,} attacks)")
    print(f"Test:  {len(X_test):,} ({(y_test==1).sum():,} attacks)")
    print(f"Features: {len(X_train.columns)}")
    
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)
    
    print(f"\n[*] Training Random Forest (n={args.n_estimators}, depth={args.max_depth})...")
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=args.n_estimators, max_depth=args.max_depth, class_weight='balanced' if args.balance_classes else None, random_state=42, n_jobs=-1, verbose=0)
    rf.fit(X_train_s, y_train)
    train_time = time.time() - t0
    print(f"[*] Training completed in {train_time:.1f}s")
    
    y_val_pred = rf.predict(X_val_s)
    y_test_pred = rf.predict(X_test_s)
    y_val_prob = rf.predict_proba(X_val_s)[:,1]
    y_test_prob = rf.predict_proba(X_test_s)[:,1]
    
    val_m = evaluate(y_val, y_val_pred, y_val_prob)
    test_m = evaluate(y_test, y_test_pred, y_test_prob)
    
    print("[*] VALIDATION METRICS:")
    for k,v in val_m.items(): print(f"  {k:12s}: {v:.4f}" if v else f"  {k:12s}: N/A")
    
    print("[*] TEST METRICS:")
    for k,v in test_m.items(): print(f"  {k:12s}: {v:.4f}" if v else f"  {k:12s}: N/A")
    
    pa = per_attack(labels_test, y_test.to_numpy(), y_test_pred)
    print("[*] PER-ATTACK DETECTION:")
    for a,s in sorted(pa.items()): print(f"  {a:15s}: {s['detected']:>5}/{s['count']:>6} ({s['detection_rate']:>5.1%})")
    
    cm = confusion_matrix(y_test, y_test_pred)
    cm_png = f"{args.out_reports_dir}/{args.run_name}_rf_confusion.png"
    plot_cm(cm, cm_png)
    
    fi = pd.DataFrame({'feature':X_train.columns, 'importance':rf.feature_importances_}).sort_values('importance', ascending=False)
    print("\n[*] Top 10 Features:")
    for _,r in fi.head(10).iterrows(): print(f"  {r['feature']:30s}: {r['importance']:.4f}")
    
    model_path = f"{args.out_models_dir}/{args.run_name}_rf.joblib"
    joblib.dump({'model':rf, 'scaler':scaler, 'features':X_train.columns.tolist()}, model_path)
    
    results = {'timestamp':datetime.utcnow().isoformat()+"Z", 'run_name':args.run_name, 'model':'RandomForest', 'params':{'n_estimators':args.n_estimators,'max_depth':args.max_depth,'class_weight':'balanced' if args.balance_classes else None}, 'training_time_seconds':float(train_time), 'features':X_train.columns.tolist(), 'validation':val_m, 'test':test_m, 'per_attack_detection':pa, 'feature_importance':fi.head(20).to_dict('records'), 'model_path':model_path, 'confusion_png':cm_png}
    
    summary_path = f"{args.out_reports_dir}/{args.run_name}_rf_summary.json"
    with open(summary_path, "w") as f: json.dump(results, f, indent=2)
    
    print(f"\nModel: {model_path}")
    print(f"Summary: {summary_path}")
    print(f"Confusion: {cm_png}")

if __name__ == "__main__": main()
from pathlib import Path