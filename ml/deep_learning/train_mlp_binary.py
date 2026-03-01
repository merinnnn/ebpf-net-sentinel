#!/usr/bin/env python3
"""
Binary MLP on tabular flow features (GPU-capable).
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from ml.methods.logging_utils import (
    print_artifacts,
    print_feature_summary,
    print_metrics_block,
    print_per_attack_block,
    print_preprocessing_summary,
    print_run_header,
    print_split_summary,
    print_tuning_summary,
)

def load_split(split_dir: str, split_name: str) -> pd.DataFrame:
    p = os.path.join(split_dir, f"{split_name}.parquet")
    if not os.path.exists(p):
        raise SystemExit(f"[!] Missing split: {p}")
    return pd.read_parquet(p)

def get_numeric_features(df: pd.DataFrame):
    exclude = {"is_attack", "label_family", "label_raw", "day"}
    cols = []
    for c in df.columns:
        if c in exclude:
            continue
        if pd.api.types.is_numeric_dtype(df[c]) and not df[c].isna().all():
            cols.append(c)
    return cols

def per_attack_metrics(labels: pd.Series, y_pred: np.ndarray) -> dict:
    rows = {}
    for attack in sorted(labels.astype(str).unique()):
        if attack == "BENIGN":
            continue
        mask = (labels.astype(str) == attack).to_numpy()
        if mask.sum() == 0:
            continue
        detected = int((y_pred[mask] == 1).sum())
        rows[attack] = {
            "count": int(mask.sum()),
            "detected": detected,
            "detection_rate": float(detected / mask.sum()),
        }
    return rows


def plot_confusion(y_true: np.ndarray, y_pred: np.ndarray, out_path: str) -> None:
    from sklearn.metrics import confusion_matrix

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    cm_n = cm.astype("float") / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.imshow(cm_n, cmap="Blues")
    ax.set_title("Confusion Matrix (tuned threshold)")
    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                f"{cm[i, j]}\n({cm_n[i, j]:.2%})",
                ha="center",
                va="center",
                color="white" if cm_n[i, j] > 0.5 else "black",
            )
    ax.set_xticks([0, 1], ["BENIGN", "ATTACK"])
    ax.set_yticks([0, 1], ["BENIGN", "ATTACK"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits_dir", required=True)
    ap.add_argument("--run_name", default="dl_mlp")
    ap.add_argument("--out_models_dir", required=True)
    ap.add_argument("--out_reports_dir", required=True)

    ap.add_argument("--hidden", default="256,128", help="comma-separated hidden sizes")
    ap.add_argument("--dropout", type=float, default=0.2)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--batch_size", type=int, default=4096)
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--patience", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    print_run_header(
        model_name="MLP",
        run_name=args.run_name,
        splits_dir=args.splits_dir,
        out_models_dir=args.out_models_dir,
        out_reports_dir=args.out_reports_dir,
        params={
            "hidden": args.hidden,
            "dropout": args.dropout,
            "lr": args.lr,
            "batch_size": args.batch_size,
            "epochs": args.epochs,
            "patience": args.patience,
            "seed": args.seed,
        },
    )

    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except Exception as e:
        raise SystemExit(
            "[!] PyTorch not available in this environment. Install it first (CUDA build if desired). "
            f"Original error: {e}"
        )

    torch.manual_seed(args.seed)

    train = load_split(args.splits_dir, "train")
    val = load_split(args.splits_dir, "val")
    test = load_split(args.splits_dir, "test")

    feats = get_numeric_features(train)
    print("[*] Split sizes")
    print_split_summary("train", len(train), int(train["is_attack"].sum()))
    print_split_summary("val", len(val), int(val["is_attack"].sum()))
    print_split_summary("test", len(test), int(test["is_attack"].sum()))
    print_feature_summary(feats)

    X_tr = train[feats].to_numpy(dtype=np.float32, copy=False)
    y_tr = train["is_attack"].astype(int).to_numpy(dtype=np.float32)
    X_va = val[feats].to_numpy(dtype=np.float32, copy=False)
    y_va = val["is_attack"].astype(int).to_numpy(dtype=np.float32)
    X_te = test[feats].to_numpy(dtype=np.float32, copy=False)
    y_te = test["is_attack"].astype(int).to_numpy(dtype=np.float32)
    labels_te = test["label_family"].astype(str)

    # Simple standardisation (mean/std from train)
    mu = X_tr.mean(axis=0)
    sig = X_tr.std(axis=0) + 1e-6
    X_tr = (X_tr - mu) / sig
    X_va = (X_va - mu) / sig
    X_te = (X_te - mu) / sig
    print_preprocessing_summary("standardize numeric features with train mean/std only")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print_tuning_summary(
        "Runtime",
        [
            f"device           : {device}",
        ],
    )

    hidden = [int(x) for x in args.hidden.split(",") if x.strip()]
    d_in = X_tr.shape[1]

    layers = []
    prev = d_in
    for h in hidden:
        layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(args.dropout)]
        prev = h
    layers += [nn.Linear(prev, 1)]
    model = nn.Sequential(*layers).to(device)

    # Class imbalance weight
    pos = float((y_tr == 1).sum())
    neg = float((y_tr == 0).sum())
    pos_weight = torch.tensor([neg / max(1.0, pos)], device=device)

    crit = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)

    def make_loader(X, y, shuffle: bool):
        ds = TensorDataset(torch.from_numpy(X), torch.from_numpy(y).unsqueeze(1))
        return DataLoader(ds, batch_size=args.batch_size, shuffle=shuffle, num_workers=0)

    tr_loader = make_loader(X_tr, y_tr, shuffle=True)
    va_loader = make_loader(X_va, y_va, shuffle=False)
    te_loader = make_loader(X_te, y_te, shuffle=False)

    def eval_loader(loader):
        model.eval()
        ys, ps = [], []
        with torch.no_grad():
            for xb, yb in loader:
                xb = xb.to(device)
                logits = model(xb)
                prob = torch.sigmoid(logits).detach().cpu().numpy().reshape(-1)
                ys.append(yb.numpy().reshape(-1))
                ps.append(prob)
        y = np.concatenate(ys)
        p = np.concatenate(ps)
        return y, p

    def metrics(y, p, thr=0.5):
        pred = (p >= thr).astype(int)
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score
        out = {
            "accuracy": float(accuracy_score(y, pred)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
        }
        try:
            out["roc_auc"] = float(roc_auc_score(y, p))
        except Exception:
            out["roc_auc"] = None
        try:
            out["pr_auc"] = float(average_precision_score(y, p))
        except Exception:
            out["pr_auc"] = None
        return out

    best_val = -1.0
    best_state = None
    bad = 0
    best_thr = 0.5
    best_val_metrics = None

    print("[*] Training")
    for epoch in range(1, args.epochs + 1):
        model.train()
        total = 0.0
        for xb, yb in tr_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            opt.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = crit(logits, yb)
            loss.backward()
            opt.step()
            total += float(loss.item()) * xb.size(0)
        tr_loss = total / max(1, len(tr_loader.dataset))

        yv, pv = eval_loader(va_loader)
        # threshold tune on val for F1
        ts = np.linspace(0.01, 0.99, 99)
        f1s = [metrics(yv, pv, t)["f1"] for t in ts]
        thr = float(ts[int(np.argmax(f1s))])
        mv = metrics(yv, pv, thr)

        print(
            f"  epoch={epoch:02d} train_loss={tr_loss:.4f} "
            f"val_f1={mv['f1']:.4f} val_pr_auc={mv['pr_auc'] if mv['pr_auc'] is not None else 'N/A'} "
            f"thr={thr:.2f}"
        )

        if mv["f1"] > best_val:
            best_val = mv["f1"]
            best_thr = thr
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            best_val_metrics = mv
            bad = 0
        else:
            bad += 1
            if bad >= args.patience:
                print(f"  early_stopping   : triggered at epoch {epoch}")
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    ytr, ptr = eval_loader(tr_loader)
    yv, pv = eval_loader(va_loader)
    yt, pt = eval_loader(te_loader)
    mtr = metrics(ytr, ptr, best_thr)
    mva = metrics(yv, pv, best_thr)
    mt = metrics(yt, pt, best_thr)
    y_pred_test = (pt >= best_thr).astype(int)
    per_attack = per_attack_metrics(labels_te, y_pred_test)

    print_tuning_summary(
        "Threshold selection",
        [
            "strategy         : maximize validation F1 during training",
            f"threshold        : {best_thr:.5f}",
            f"best_val_f1      : {best_val:.4f}",
            f"epochs_ran       : {epoch}",
        ],
    )
    print_metrics_block("Train metrics", mtr)
    print_metrics_block("Validation metrics", mva)
    print_metrics_block("Test metrics", mt)
    print_per_attack_block("Per-attack detection (test)", per_attack)

    out_model = os.path.join(args.out_models_dir, f"{args.run_name}_mlp.pt")
    out_rep = os.path.join(args.out_reports_dir, f"{args.run_name}_mlp_summary.json")
    out_cm = os.path.join(args.out_reports_dir, f"{args.run_name}_mlp_confusion.png")
    os.makedirs(os.path.dirname(out_model), exist_ok=True)
    os.makedirs(os.path.dirname(out_rep), exist_ok=True)
    plot_confusion(yt.astype(int), y_pred_test, out_cm)

    torch.save(
        {
            "state_dict": model.state_dict(),
            "features": feats,
            "mu": mu,
            "sig": sig,
            "threshold": best_thr,
            "hidden": hidden,
            "dropout": args.dropout,
            "selected_model_name": "mlp",
        },
        out_model,
    )

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_name": args.run_name,
        "model": "MLP",
        "device": str(device),
        "features": feats,
        "hidden": hidden,
        "dropout": args.dropout,
        "lr": args.lr,
        "batch_size": args.batch_size,
        "epochs_ran": epoch,
        "best_val_f1": float(best_val),
        "threshold": float(best_thr),
        "train": mtr,
        "validation": mva,
        "test": mt,
        "test_metrics": mt,
        "per_attack_detection": per_attack,
        "confusion_png": out_cm,
        "model_path": out_model,
    }
    with open(out_rep, "w") as f:
        json.dump(summary, f, indent=2)

    print_artifacts(
        model_path=out_model,
        summary_path=out_rep,
        extras={"confpng": out_cm},
    )

if __name__ == "__main__":
    main()
