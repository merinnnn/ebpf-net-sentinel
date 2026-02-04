# eBPF Net Sentinel (PCAP replay + Zeek + eBPF flows)

This repo gives you a repeatable pipeline to:

1) Extract flow features from a PCAP with **Zeek** (`conn.log` -> `conn.csv`)
2) Collect kernel-level per-flow features with an **eBPF** collector (`netmon`)
3) **Replay** the PCAP into a test interface with `tcpreplay`
4) Merge Zeek + eBPF features into one dataset (with timestamp synchronisation)

---

## System requirements

**OS**: Ubuntu 20.04+ (tested on 20.04)

**Must have**

* Root/sudo access (loading eBPF programs + tcpreplay)
* Linux kernel with eBPF support
* Build tools: `make`, `clang`, `llvm`, `bpftool`, `libbpf-dev`, `golang`
* Traffic tooling: `zeek`, `tcpreplay`, `iproute2`
* PCAP tooling: `tshark` (recommended) and `editcap` (from `wireshark-common`, used for MTU/frame-size fixes)
* Python 3 + deps for dataset work (`pandas`; `pyarrow` recommended if writing Parquet)

Quick install (recommended):

```bash
bash ubuntu/setup.sh
```

---

## Commands

### 1) Create a veth pair (recommended for safe replay)

**What it does**: creates two virtual ethernet interfaces on your machine.
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

**Expected output**:

```bash
ip link show veth0
ip link show veth1
```

You should see both interfaces in `state UP`. If you used the helper with `9000`, both should show `mtu 9000`.

---

### 2) Offline run: Zeek + netmon + tcpreplay (single PCAP)

**What it does**

* Runs Zeek over the PCAP -> `zeek/conn.log` + `zeek/conn.csv`
* Starts the eBPF collector (`netmon`) and attaches the socket filter to **REPLAY_IFACE**
  (the interface where `tcpreplay` sends)
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
* The capture script may preprocess PCAPs to avoid MTU/jumbo frame issues (e.g. via `editcap`).
* If you change eBPF/Go code or see unexpected netmon failures, rebuild cleanly:
  ```bash
  REPLAY_IFACE=veth0 SET_MTU=9000 FORCE_BUILD=1 bash ubuntu/run_capture.sh Monday-WorkingHours.pcap veth1 10
  ```

**Expected output**

The script prints a run folder like:

```text
Run folder: /home/merin/.../data/runs/2026-01-31_114048
```

Inside that folder you should see (names may vary slightly):

* `zeek/conn.csv` (Zeek flows)
* `ebpf_agg.jsonl` (eBPF aggregated flow features)
* `ebpf_events.jsonl` (raw events; may be empty in `MODE=flow`)
* `netmon.log` (collector logs, progress lines)
* `tcpreplay.log` (replay stats)
* `run_meta.json` (run metadata used for merge alignment)

---

### 3) Offline Zeek extraction only

**What it does**: runs Zeek over a PCAP and converts `conn.log` to `conn.csv`.

```bash
bash ubuntu/zeek_extract.sh Monday-WorkingHours.pcap data/tmp_zeek
```

**Expected output**:

* `data/tmp_zeek/conn.log`
* `data/tmp_zeek/conn.csv`
* `data/tmp_zeek/zeek_extract.log`

---

### 4) Live capture: Zeek + netmon on a real interface

**What it does**: starts Zeek and the eBPF collector on a real interface until you press **Ctrl+C**.

```bash
sudo bash ubuntu/run_live.sh eth0
```

**Expected output**:

* A run folder printed at start (e.g. `data/runs/live_YYYY-MM-DD_HHMMSS`)
* `netmon.log` should show periodic `progress:` lines
* Zeek logs written under `zeek/`

---

### 5) Merge Zeek + eBPF features into one dataset

**What it does**: joins Zeek flow rows with eBPF aggregated rows using a 5-tuple key
(src/dst IP, src/dst port, protocol). IPv6 rows are dropped (collector is IPv4-oriented).
The merge uses `run_meta.json` to **synchronise timestamps** between PCAP time and capture time.

```bash
python3 ubuntu/merge_zeek_ebpf.py \
  --zeek_conn data/runs/2026-02-01_002734/zeek/conn.csv \
  --ebpf_agg  data/runs/2026-02-01_002734/ebpf_agg.jsonl \
  --run_meta  data/runs/2026-02-01_002734/run_meta.json \
  --out       data/runs/2026-02-01_002734/merged.parquet
```

(Optional debug)
```bash
python3 ubuntu/merge_zeek_ebpf.py ... --debug
```

**Expected output**

The script prints merge stats and writes the merged dataset to your `--out` path.

---

## Troubleshooting (fast)

* **`tcpreplay ... Message too long`**: use a higher MTU on veth
  (`SET_MTU=9000`) or let the capture script preprocess the PCAP (frame-size clamp).
* **`map create: operation not permitted (MEMLOCK...)`**: run as root and ensure memlock is not constrained.
  The scripts already attempt `ulimit -l unlimited` when launching `netmon`.
* **Low enrichment / few matches**:
  * Check `tcpreplay.log` for "Successful packets"
  * Confirm the eBPF socket filter attaches to `REPLAY_IFACE` (see `netmon.log`)
  * Ensure you pass the correct `--run_meta` so timestamp sync can be applied
