#!/usr/bin/env python3
import argparse, json

def grab(run, model):
    t = run["models"][model]["test"]
    return t["accuracy"], t["macro_f1"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="metrics_summary.json for run A")
    ap.add_argument("--b", required=True, help="metrics_summary.json for run B")
    args = ap.parse_args()

    A = json.load(open(args.a))
    B = json.load(open(args.b))

    print("A:", args.a)
    print("B:", args.b)

    for model in sorted(set(A["models"].keys()) & set(B["models"].keys())):
        acc_a, f1_a = grab(A, model)
        acc_b, f1_b = grab(B, model)
        print(f"\n{model}:")
        print(f"A acc={acc_a:.4f}  macroF1={f1_a:.4f}")
        print(f"B acc={acc_b:.4f}  macroF1={f1_b:.4f}")

    print("\nPer-day (TEST):")
    for model in sorted(set(A["models"].keys()) & set(B["models"].keys())):
        da = A["models"][model].get("test_per_day", {})
        db = B["models"][model].get("test_per_day", {})
        days = sorted(set(da.keys()) | set(db.keys()))
        print(f"\n--- {model} ---")
        for d in days:
            aa = da.get(d)
            bb = db.get(d)
            if aa and bb:
                print(f"{d:10s}  acc {aa['accuracy']:.4f}->{bb['accuracy']:.4f}   macroF1 {aa['macro_f1']:.4f}->{bb['macro_f1']:.4f}")
            else:
                print(f"{d:10s}  missing in one run")

if __name__ == "__main__":
    main()
