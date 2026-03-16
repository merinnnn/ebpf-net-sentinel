# Data capture pipeline

This directory contains all scripts for the data capture and labelling pipeline.
The full pipeline turns raw PCAP files into a labelled, merged dataset ready for ML.

**Pipeline overview:**

``` bash
PCAPs  -->  run_capture.sh  -->  merge_zeek_ebpf.py  -->  label_runs_multiclass.py  -->  labeled .parquet
```

---

## System requirements

**OS**: Ubuntu 20.04+ (tested on 20.04)

**Must have:**

* Root/sudo access (loading eBPF programs + tcpreplay)
* Linux kernel with eBPF support
* Build tools: `make`, `clang`, `llvm`, `bpftool`, `libbpf-dev`, `golang`
* Traffic tooling: `zeek`, `tcpreplay`, `iproute2`
* PCAP tooling: `tshark` (recommended) and `editcap` (from `wireshark-common`, used for MTU/frame-size fixes)
* Python 3 + deps: `pandas`, `pyarrow`

Quick install (recommended):

```bash
bash ubuntu/setup.sh
```

---

## Data directory structure

``` bash
data
├── cicids2017_csv
│   └── GeneratedLabelledFlows
│       └── TrafficLabelling
│           ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
│           ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│           ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│           ├── Monday-WorkingHours.pcap_ISCX.csv
│           ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│           ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│           ├── Tuesday-WorkingHours.pcap_ISCX.csv
│           └── Wednesday-workingHours.pcap_ISCX.csv
└── cicids2017_pcap
    ├── Friday-WorkingHours.pcap
    ├── Monday-WorkingHours.pcap
    ├── Thursday-WorkingHours.pcap
    ├── Tuesday-WorkingHours.pcap
    └── Wednesday-WorkingHours.pcap
```

---

## Commands

### 1) Create a veth pair (recommended for safe replay)

**What it does**: creates two virtual ethernet interfaces.
Packets sent into `veth0` appear as received packets on `veth1` (and vice-versa).

**Manual:**

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

**Automatic:**

```bash
sudo bash ubuntu/setup_veth.sh veth0 veth1 9000
```

**Expected output:**

```bash
ip link show veth0
ip link show veth1
```

Both interfaces should show `state UP`. If you used the helper with `9000`, both should show `mtu 9000`.

---

### 2) Offline run: Zeek + netmon + tcpreplay (single PCAP)

**What it does:**

* Runs Zeek over the PCAP: `zeek/conn.log` + `zeek/conn.csv`
* Starts the eBPF collector (`netmon`) and attaches the socket filter to `REPLAY_IFACE`
* Replays the PCAP into the replay interface with `tcpreplay`
* Stops `netmon` and leaves a complete run folder in `data/runs/<timestamp>/`

**Example (recommended veth replay):**

```bash
# Replay into veth0, capture on veth1, at ~10 Mbps
REPLAY_IFACE=veth0 SET_MTU=9000 bash ubuntu/run_capture.sh Monday-WorkingHours.pcap veth1 10
```

Notes:

* `SET_MTU=9000` is optional but helps avoid tcpreplay "Message too long" on veth.
* The capture interface is the second argument (`veth1` above). The eBPF socket filter attaches to `REPLAY_IFACE`.
* The capture script preprocesses PCAPs to avoid MTU/jumbo frame issues via `editcap`.
* If you change eBPF/Go code or see unexpected netmon failures, rebuild cleanly:

  ```bash
  REPLAY_IFACE=veth0 SET_MTU=9000 FORCE_BUILD=1 bash ubuntu/run_capture.sh Monday-WorkingHours.pcap veth1 10
  ```

**Expected output**: a timestamped run folder containing:

* `zeek/conn.csv` (Zeek flows)
* `ebpf_agg.jsonl` (eBPF aggregated flow features)
* `ebpf_events.jsonl` (raw events; may be empty in `MODE=flow`)
* `netmon.log` (collector logs)
* `tcpreplay.log` (replay stats)
* `run_meta.json` (metadata used for merge timestamp alignment)

---

### 3) Live capture: Zeek + netmon on a real interface

**What it does**: starts Zeek and the eBPF collector on a real interface until you press **Ctrl+C**.
While running it continuously refreshes:

* `zeek/conn.csv` (live Zeek flow output)
* `merged.csv` (live Zeek + eBPF flow output)
* `data/runtime/live_capture_state.json` (current run + file paths for the web app)

```bash
sudo bash ubuntu/run_live.sh <IFACE>
```

**Expected output:**

* A run folder printed at start (e.g. `data/runs/live_YYYY-MM-DD_HHMMSS`)
* `netmon.log` should show periodic `progress:` lines
* `zeek/conn.csv` should appear during capture
* `merged.csv` should appear once both Zeek and eBPF data are available

---

### 4) Merge Zeek + eBPF features into one dataset

**What it does**: joins Zeek flow rows with eBPF aggregated rows using a 5-tuple key
(src/dst IP, src/dst port, protocol). IPv6 rows are dropped (collector is IPv4-only).
Uses `run_meta.json` to synchronise timestamps between PCAP time and capture time.

```bash
python3 ubuntu/merge_zeek_ebpf.py \
  --zeek_conn data/runs/<YYYY-MM-DD_HHMMSS>/zeek/conn.csv \
  --ebpf_agg  data/runs/<YYYY-MM-DD_HHMMSS>/ebpf_agg.jsonl \
  --run_meta  data/runs/<YYYY-MM-DD_HHMMSS>/run_meta.json \
  --out       data/runs/<YYYY-MM-DD_HHMMSS>/merged.csv \
  --time_slop 5
```

Optional debug flag: `--debug`

**Expected output:** merge stats printed to stdout + `merged.csv` written to `--out`.

---

### 5) Label the merged dataset (assign CICIDS2017 ground-truth labels)

**What it does**: matches each merged flow against the CICIDS2017 ground-truth label CSVs
using a 5-tuple key (src/dst IP, src/dst port, protocol) and a temporal fuzzy join with
configurable tolerance. Two-pass matching (flow start + flow end) picks the attack label
over benign when both match. Outputs a labelled `.parquet` per run, then combines all
runs into one combined parquet.

Key flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--runs` | (required) | One or more run directories, each containing `merged.csv` + `run_meta.json` |
| `--labels_dir` | (required) | Path to CICIDS2017 `TrafficLabelling/` directory |
| `--out_dir` | `data/datasets/labeled_runs` | Per-run labeled parquet output directory |
| `--combined_out` | `data/datasets/cicids2017_multiclass_zeek_ebpf.parquet` | Combined output path |
| `--pre_slop` | `7200` | Timestamp tolerance in seconds for label matching |
| `--auto_halfday_shift` | off | Try +-12 h shifts to fix CICIDS2017 AM/PM timestamp ambiguity |

**Single run:**

```bash
python3 ubuntu/label_runs_multiclass.py \
  --runs      data/runs/<YYYY-MM-DD_HHMMSS> \
  --labels_dir data/cicids2017_csv/GeneratedLabelledFlows/TrafficLabelling \
  --out_dir   data/datasets/labeled_runs \
  --combined_out data/datasets/cicids2017_multiclass_zeek_ebpf.parquet \
  --auto_halfday_shift
```

**Expected output:**

``` bash
[*] Loading labels for Monday: 1 file(s)
[*] Labels loaded: rows=... attacks=...
[*] data/runs/...: labeled 123456/130000 (95.04%) attacks=4500 (3.46%) day=Monday ...
[*] Wrote combined labeled dataset: data/datasets/cicids2017_multiclass_zeek_ebpf.parquet rows=...
```

Each flow gets the following columns added:

* `label_family`: attack family (`BENIGN`, `DDoS`, `DoS`, `PortScan`, `Bot`, `BruteForce`, `WebAttack`, `Infiltration`, `Heartbleed`, `Unknown`)
* `label_raw`: original raw label string from the CICIDS2017 CSV
* `is_attack`: 0/1 binary label
* `day`: inferred day of week
* `label_time_offset_sec` / `label_halfday_shift_sec`: alignment metadata

---

### 6) Run the full pipeline for all 5 days

**What it does**: replays all 5 PCAPs, merges each, then labels all runs in one call.

```bash
RUN_DIRS=()

for DAY in Monday Tuesday Wednesday Thursday Friday; do
  echo "Processing $DAY"

  LOG="$(mktemp)"
  REPLAY_IFACE=veth0 SET_MTU=9000 bash ubuntu/run_capture.sh \
    "${DAY}-WorkingHours.pcap" veth1 topspeed | tee "$LOG"

  OUT="$(awk -F= '/^RUN_DIR=/{print $2; exit}' "$LOG")"
  rm -f "$LOG"

  python3 ubuntu/merge_zeek_ebpf.py \
    --zeek_conn "$OUT/zeek/conn.csv" \
    --ebpf_agg  "$OUT/ebpf_agg.jsonl" \
    --run_meta  "$OUT/run_meta.json" \
    --out       "$OUT/merged.csv" \
    --time_slop 5

  RUN_DIRS+=( "$OUT" )
done

python3 ubuntu/label_runs_multiclass.py \
  --runs      "${RUN_DIRS[@]}" \
  --labels_dir data/cicids2017_csv/GeneratedLabelledFlows/TrafficLabelling \
  --out_dir   data/datasets/labeled_runs \
  --combined_out data/datasets/cicids2017_multiclass_zeek_ebpf.parquet \
  --auto_halfday_shift
```

**Expected output:** 5 per-run `.parquet` files under `data/datasets/labeled_runs/` plus
the combined `data/datasets/cicids2017_multiclass_zeek_ebpf.parquet`, which is the input
to the ML notebooks.
