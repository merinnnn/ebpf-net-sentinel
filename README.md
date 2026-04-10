# eBPF Net Sentinel

A research prototype of an intrusion detection system based on eBPF networks that includes Zeek flow features enhanced with eBPF kernel telemetry, tested using the CICIDS2017 dataset.

## Reproducibility

| Component | Tested on |
| --------- | --------- |
| Data collection pipeline | Ubuntu 20.04 LTS, kernel 5.15, Python 3.8.10, Go 1.21.13 |
| ML notebooks | Ubuntu 20.04 LTS, Python 3.10.12 |
| Webapp (Docker) | Ubuntu 20.04 LTS, kernel 5.15, Docker 26.1.3 |

Data collection pipeline and web app need a **Linux native host** supporting eBPF (kernel 5.15). They have been tested under Ubuntu 20.04 LTS. Windows Subsystem for Linux (WSL), macOS, and Windows hosts are currently unsupported. The machine learning Jupyter notebooks will work on any platform using Python 3.10.12+.

## Folder Structure

```text
ebpf-net-sentinel/
├── app/
│   ├── app.py
│   ├── pages/
│   │   └── live_monitor.py
│   └── requirements.txt
│
├── ubuntu/
│   ├── data_collection/
│   │   ├── run_capture.sh
│   │   ├── merge_zeek_ebpf.py
│   │   ├── label_runs_multiclass.py
│   │   └── zeek_conn_to_csv.py
│   ├── live/
│   │   ├── run_live.sh
│   │   └── live_capture_daemon.py
│   ├── setup/
│   │   ├── setup.sh
│   │   ├── setup_veth.sh
│   │   └── setup_research_net.sh
│   └── test/
│       ├── install_tools.sh
│       ├── _common.sh
│       ├── benign.sh
│       ├── brute_force.sh
│       ├── portscan.sh
│       ├── syn_flood.sh
│       └── web_attacks.sh
│
├── ml/
│   ├── data_prep/
│   │   ├── make_datasets.py
│   │   ├── split_1_group_stratified.py
│   │   ├── split_2_balanced_quota.py
│   │   ├── split_3_train_resampled.py
│   │   ├── split_4_dual_eval.py
│   │   └── split_5_kfold.py
│   ├── methods/
│   │   ├── logging_utils.py
│   │   ├── supervised_rf/
│   │   │   └── train_random_forest.py
│   │   └── unsupervised_iforest/
│   │       └── train_iforest.py
│   ├── notebooks/
│   │   ├── 00_data_preparation.ipynb
│   │   ├── 01_baseline_vs_ebpf.ipynb
│   │   ├── 02_feature_importance.ipynb
│   │   ├── 03_per_attack_analysis.ipynb
│   │   ├── 04_generalisation.ipynb
│   │   ├── 05_overheads.ipynb
│   │   ├── modeling_pipeline.py
│   │   └── experiment_config.py
│   ├── benchmarks/
│   │   └── overheads.py
│   └── requirements.txt
│
├── ebpf_core/
│   ├── bpf/
│   │   ├── netmon.bpf.c
│   │   └── vmlinux.h
│   ├── cmd/
│   │   └── netmon/
│   └── Makefile
│
├── docker/
│   ├── entrypoint.sh
│   └── install_live_deps.sh
│
├── data/
│   ├── cicids2017_csv/
│   ├── cicids2017_pcap/
│   ├── datasets/
│   ├── models/
│   ├── reports/
│   ├── runs/
│   └── runtime/
│
├── docker-compose.yml
├── Dockerfile
├── .streamlit/config.toml
└── .gitignore
```

## Part 1: Data Collection Pipeline

### Data Collection Requirements

| Requirement | Detail |
| ----------- | ------ |
| OS | Ubuntu 20.04 LTS (native Linux, not WSL) |
| Kernel | 5.15 |
| Privileges | Root / sudo required throughout |
| Python | 3.8.10 |
| Go | 1.21.13 (to build `netmon`) |
| System tools | `make`, `clang`, `llvm`, `bpftool`, `libbpf-dev`, `zeek`, `tcpreplay`, `tshark`, `editcap` |

### Data Collection Python Dependencies

```bash
pip install pandas==2.3.3 pyarrow==23.0.0
```

### Setup

```bash
# Install all system dependencies
bash ubuntu/setup/setup.sh

# Build the eBPF collector (netmon)
cd ebpf_core && make && cd ..

# Create a virtual ethernet pair for safe PCAP replay
sudo bash ubuntu/setup/setup_veth.sh veth0 veth1 9000
```

Download the CICIDS2017 dataset from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) and place the PCAPs and label CSVs at: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

### Running the Full Pipeline (all 5 days)

Replays all 5 PCAPs, merges each run, then labels all runs in one call:

```bash
RUN_DIRS=()

for DAY in Monday Tuesday Wednesday Thursday Friday; do
  echo "Processing $DAY"

  LOG="$(mktemp)"
  REPLAY_IFACE=veth0 SET_MTU=9000 bash ubuntu/data_collection/run_capture.sh \
    "${DAY}-WorkingHours.pcap" veth1 topspeed | tee "$LOG"

  OUT="$(awk -F= '/^RUN_DIR=/{print $2; exit}' "$LOG")"
  rm -f "$LOG"

  python3 ubuntu/data_collection/merge_zeek_ebpf.py \
    --zeek_conn "$OUT/zeek/conn.csv" \
    --ebpf_agg  "$OUT/ebpf_agg.jsonl" \
    --run_meta  "$OUT/run_meta.json" \
    --out       "$OUT/merged.csv" \
    --time_slop 5

  RUN_DIRS+=( "$OUT" )
done

python3 ubuntu/data_collection/label_runs_multiclass.py \
  --runs      "${RUN_DIRS[@]}" \
  --labels_dir data/cicids2017_csv/GeneratedLabelledFlows/TrafficLabelling \
  --out_dir   data/datasets/labeled_runs \
  --combined_out data/datasets/cicids2017_multiclass_zeek_ebpf.parquet \
  --auto_halfday_shift
```

**Expected output:** 5 per-run `.parquet` files under `data/datasets/labeled_runs/` plus the combined `data/datasets/cicids2017_multiclass_zeek_ebpf.parquet` (input to the ML notebooks).

## Part 2: ML Model Training

### ML Requirements

| Requirement | Detail |
| ----------- | ------ |
| OS | Any (Linux, macOS, Windows) |
| Python | 3.10.12 |
| RAM | 8 GB minimum recommended (16 GB for full dataset) |
| Disk | ~2 GB disk space |

### ML Python Dependencies

From [ml/requirements.txt](ml/requirements.txt):

```text
pandas==2.3.3
pyarrow==23.0.0
scikit-learn==1.7.2
joblib==1.5.3
matplotlib==3.10.8
shap==0.49.1
numpy==2.2.6
scipy==1.15.3
jupyterlab==4.5.4
ipykernel==7.2.0
psutil==7.2.2
```

### Running the ML Pipeline

#### Step 0: Set up a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate.bat       # Windows

pip install -r ml/requirements.txt
pip install -e .
```

#### Step 1: Run the notebooks

Use any method to run the jupyter notebooks. (For this project, VSCode with the Jupyter extension have been used)

Run the notebooks in order:

| Notebook | Purpose |
| -------- | ------- |
| `00_data_preparation.ipynb` | Generate train/test splits |
| `01_baseline_vs_ebpf.ipynb` | Train models and evaluate baseline vs ebpf |
| `02_feature_importance.ipynb` | SHAP feature importance analysis |
| `03_per_attack_analysis.ipynb` | Per-attack-type performance |
| `04_generalisation.ipynb` | Test generalisation across days |
| `05_overheads.ipynb` | Runtime and memory overhead measurements |

### Hyperparameters

All model hyperparameters are configured in [ml/notebooks/experiment_config.py](ml/notebooks/experiment_config.py). Update the file before running the notebooks.

To change them:

```python
# HistGradientBoosting
HGB_PARAMS = dict(
    max_iter=500,
    max_depth=8,
    learning_rate=0.05,
    ...
)

# Random Forest
RF_PARAMS = dict(
    n_estimators=200,
    max_depth=20,
    ...
)

# Isolation Forest
IFOREST_PARAMS = dict(
    n_estimators=100,
    ...
)
```

## Part 3: Web Application (Docker Compose)

The Streamlit dashboard visualises live network flow data and model predictions.

### Web App Requirements

| Requirement | Detail |
| ----------- | ------ |
| Docker | 26.1.3 with Docker Compose v2 |
| OS | Ubuntu 20.04 LTS, kernel 5.15 |
| Privileges | `--privileged` / host PID + network namespace |
| Python (in container) | 3.11 (managed by Miniforge, installed automatically) |

### Web App Python Dependencies

Automatically installed inside the Docker image using [app/requirements.txt](app/requirements.txt):

```text
streamlit==1.54.0
plotly==6.5.2
pandas==2.3.3
numpy==2.2.6
scikit-learn==1.7.2
joblib==1.5.3
pyarrow==23.0.0
```

### Running the Web App (Docker Compose)

```bash
# From the repo root
docker compose up --build
```

Open [http://localhost:8501](http://localhost:8501) in your browser and navigate to **Live Monitor**.

Inside the Docker container, `/sys/kernel/btf`, `/sys/kernel/tracing`, `/sys/fs/bpf`, `/lib/modules`, and `/usr/src` will be mounted, so that eBPF programs can be loaded. The host’s network namespace is also shared to allow Zeek to capture live traffic. The two headline `.joblib` files are required inside the `data/models/` folder.

### Running Tests with Attack Scenarios

The test scripts in `ubuntu/test/` generate traffic within an isolated network namespace to view the dashboard's reactions to various attacks in real-time.

#### Step 1: Install attack tools (run once on the host)

```bash
sudo bash ubuntu/test/install_tools.sh
```

Installs `nmap`, `hping3`, `hydra`, `slowhttptest`, `netcat`, `iperf3`, and other tools used by the test scripts.

#### Step 2: Bring up the isolated test network

```bash
sudo bash ubuntu/setup/setup_research_net.sh up
```

Creates an isolated network namespace (`ns-research`) with the help of a veth pair: host side `ns0` (`10.99.0.1`) and namespace side `ns1` (`10.99.0.2`). Inside the container, Zeek captures traffic on `ns0`.

#### Step 3: Start the web app

```bash
docker compose up --build
```

#### Step 4: Run a test script to replicate an attack scenario

Each script sends traffic from inside the namespace toward the host, triggering detections visible on the Live Monitor dashboard:

| Script | Attack scenario |
| ------ | --------------- |
| `sudo bash ubuntu/test/portscan.sh` | Port scan (nmap SYN scan) |
| `sudo bash ubuntu/test/syn_flood.sh` | SYN flood |
| `sudo bash ubuntu/test/brute_force.sh ssh` | SSH brute-force |
| `sudo bash ubuntu/test/brute_force.sh ftp` | FTP brute-force |
| `sudo bash ubuntu/test/web_attacks.sh` | Web attacks (XSS, SQLi, brute force) |
| `sudo bash ubuntu/test/benign.sh` | Benign traffic baseline |

#### Teardown

```bash
sudo bash ubuntu/setup/setup_research_net.sh down
docker compose down
```
