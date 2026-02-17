#!/usr/bin/env python3
"""Binary MLP on tabular flow features (GPU-capable).
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass

import numpy as np
import pandas as pd


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

    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except Exception as e:
        raise SystemExit(
            "[!] PyTorch not available in this environment. Install it first (CUDA build if desired). "
            f"Original error: {e}"
        )

    rng = np.random.default_rng(args.seed)
    torch.manual_seed(args.seed)

    train = load_split(args.splits_dir, "train")
    val = load_split(args.splits_dir, "val")
    test = load_split(args.splits_dir, "test")

    feats = get_numeric_features(train)
    X_tr = train[feats].to_numpy(dtype=np.float32, copy=False)
    y_tr = train["is_attack"].astype(int).to_numpy(dtype=np.float32)
    X_va = val[feats].to_numpy(dtype=np.float32, copy=False)
    y_va = val["is_attack"].astype(int).to_numpy(dtype=np.float32)
    X_te = test[feats].to_numpy(dtype=np.float32, copy=False)
    y_te = test["is_attack"].astype(int).to_numpy(dtype=np.float32)

    # Simple standardisation (mean/std from train)
    mu = X_tr.mean(axis=0)
    sig = X_tr.std(axis=0) + 1e-6
    X_tr = (X_tr - mu) / sig
    X_va = (X_va - mu) / sig
    X_te = (X_te - mu) / sig

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("[*] Device:", device)

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

        print(f"[epoch {epoch:02d}] train_loss={tr_loss:.4f} val_f1={mv['f1']:.4f} val_pr_auc={mv['pr_auc']}")

        if mv["f1"] > best_val:
            best_val = mv["f1"]
            best_thr = thr
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            bad = 0
        else:
            bad += 1
            if bad >= args.patience:
                print("[*] Early stopping")
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    yt, pt = eval_loader(te_loader)
    mt = metrics(yt, pt, best_thr)

    out_model = os.path.join(args.out_models_dir, f"{args.run_name}_mlp.pt")
    out_rep = os.path.join(args.out_reports_dir, f"{args.run_name}_mlp_summary.json")
    os.makedirs(os.path.dirname(out_model), exist_ok=True)
    os.makedirs(os.path.dirname(out_rep), exist_ok=True)

    torch.save(
        {
            "state_dict": model.state_dict(),
            "features": feats,
            "mu": mu,
            "sig": sig,
            "threshold": best_thr,
            "hidden": hidden,
            "dropout": args.dropout,
        },
        out_model,
    )

    summary = {
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
        "test_metrics": mt,
    }
    with open(out_rep, "w") as f:
        json.dump(summary, f, indent=2)

    print("[*] TEST METRICS:")
    for k, v in mt.items():
        print(f"  {k:12s}: {v}")
    print("Model:", out_model)
    print("Summary:", out_rep)


if __name__ == "__main__":
    main()
