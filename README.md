# eBPF Net Sentinel

This project so far replays a **CICIDS2017** PCAP into a local **veth** interface, extracts **Zeek** flow logs, runs an eBPF collector (**`netmon`**) on the capture interface, and writes **JSONL** outputs for downstream analysis.

---

## System Requirements

### OS
- Ubuntu 20.04+ (tested on Ubuntu 20.04)

### Kernel
- Linux kernel with eBPF enabled (typical on Ubuntu)

### Tools / Packages
- `sudo` access (required)
- `iproute2` (`ip link`, `ip -s link`)
- `tcpreplay`
- `zeek`
- `python3`
- Build tooling for `netmon`: `make`, `clang`, `llvm`, and required eBPF/libbpf headers/libs (whatever your `ebpf_core/Makefile` expects)

### Dataset
- Put PCAPs in: `data/cicids2017_pcap/`
  - Example: `data/cicids2017_pcap/Monday-WorkingHours.pcap`

---

## One-time setup (recommended)

If you’re on a fresh Ubuntu install, run the project bootstrap script:

```bash
chmod +x ubuntu/setup.sh
sudo bash ubuntu/setup.sh
```

### What `ubuntu/setup.sh` does (high level)

This script is intended to prepare the machine for the end-to-end pipeline by installing and configuring the required system dependencies. In our Ubuntu 20.04 setup, it:

- Ensures required apt components (e.g., `universe`) are enabled
- Adds the Zeek apt repository (if needed) and updates package lists
- Installs the core tooling used by the pipeline (e.g., Zeek, tcpreplay, and the eBPF build toolchain expected by `ebpf_core/Makefile`)

### What “success” looks like

It’s normal to see output like:

- `'<component>' distribution component is already enabled for all sources`
- `... is already the newest version`
- `0 to upgrade, 0 to newly install, 0 to remove ...`

As long as the script exits without errors, you’re good to continue to the **Quickstart** section.

### If the script fails

Common things to try:

- Re-run with a clean apt state:
  ```bash
  sudo apt update
  sudo apt -f install
  ```
- If Zeek repo / key steps fail, re-run `ubuntu/setup.sh` (it should be mostly idempotent).
- If you’re inside a container or restricted environment, eBPF requirements (kernel headers, privileges, memlock) may not be satisfiable—run on a full Ubuntu host/VM.


---

## What the main script does

`ubuntu/run_capture.sh` runs an end-to-end pipeline:

1. **Zeek** reads the PCAP and produces `zeek/conn.log`
2. Converts `conn.log` → `zeek/conn.csv`
3. Builds the eBPF collector (`make -C ebpf_core`)
4. Starts **netmon** (eBPF collector) on the capture interface
5. Replays the PCAP using **tcpreplay** into the replay interface
6. Waits for flush, stops netmon, writes outputs

---

## Outputs (per run)

Each run creates:

- `data/runs/YYYY-MM-DD_HHMMSS/`

Expected key files:

- `zeek/conn.csv` — Zeek flow records (CSV)
- `ebpf_agg.jsonl` — aggregated eBPF flow features (JSON Lines)
- `ebpf_events.jsonl` — raw events (may be empty depending on mode/config)
- `netmon.log` — netmon runtime log (progress + counters)
- `tcpreplay.log` — replay stats / errors
- `run_meta.json` — run metadata

---

## Quickstart (recommended)

### 1) Create the veth interfaces (local test setup)

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

**What it does:** Creates a virtual ethernet pair. Packets injected into `veth0` appear on `veth1`.

**Expected output:** No output on success.

**Verify:**

```bash
ip link show veth0
ip link show veth1
```

You should see state `UP` and `LOWER_UP`.

---

### 2) Run capture + replay (end-to-end)

```bash
SET_MTU=9000 REPLAY_IFACE=veth0 bash ubuntu/run_capture.sh Monday-WorkingHours.pcap veth1 10
```

**What it does:**
- Captures on `veth1` (`netmon -pkt_iface veth1`)
- Replays PCAP into `veth0` (`tcpreplay --intf1 veth0`)
- Sets MTU to 9000 (helps avoid tcpreplay “Message too long” on veth)

**Arguments:**
- `Monday-WorkingHours.pcap` = PCAP file name in `data/cicids2017_pcap/` (or a full path)
- `veth1` = capture interface
- `10` = replay rate in Mbps

**Expected terminal output:**
- `[1/5] Zeek flow extraction`
- `[2/5] Build eBPF collector`
- `[3/5] Start eBPF collector (netmon)`
- `[4/5] Replay PCAP (tcpreplay)`
- `[5/5] Waiting ... to allow netmon to flush...`
- `Done. Run folder: ...`

---

## Useful commands (inspect results)

### Find the latest run folder

```bash
RUN="data/runs/$(ls -1 data/runs | tail -n 1)"
echo "$RUN"
```

### List the expected outputs

```bash
ls -lah "$RUN/zeek/conn.csv" "$RUN/ebpf_agg.jsonl" "$RUN/ebpf_events.jsonl"   "$RUN/netmon.log" "$RUN/tcpreplay.log" "$RUN/run_meta.json"
```

**Expected result:**
- `zeek/conn.csv` should exist (often large)
- `ebpf_agg.jsonl` should be non-empty on a successful capture
- `netmon.log` + `tcpreplay.log` should exist

### Check tcpreplay stats

```bash
tail -n 80 "$RUN/tcpreplay.log"
```

**Expected result:**
- `Successful packets: ...`
- `Failed packets: 0` (ideal)

If you see **“Message too long”**, keep `SET_MTU=9000` or manually set MTU.

### Check netmon progress

```bash
tail -n 80 "$RUN/netmon.log"
```

**Expected result:**
- progress lines like `events=... flushed=...`
- `events` should be `> 0` during replay
- `flushed` should be `> 0` by the end

### Confirm traffic hit the interfaces

```bash
ip -s link show veth0
ip -s link show veth1
```

**Expected result:**
- `veth0` TX increases
- `veth1` RX increases

---

## Environment variables (optional)

You can control the script with env vars:

- `REPLAY_IFACE=<iface>`  
  Where `tcpreplay` sends packets (default = capture iface)
- `SET_MTU=9000`  
  Sets MTU on both capture and replay ifaces (best-effort)
- `FLUSH_SECS=5`  
  Netmon flush period in seconds (default 5)
- `MODE=flow`  
  Netmon mode (default `flow`)
- `DISABLE_KPROBES=1`  
  Default `1` (keeps kprobes disabled)

**Example:**

```bash
SET_MTU=9000 REPLAY_IFACE=veth0 FLUSH_SECS=5 MODE=flow DISABLE_KPROBES=1   bash ubuntu/run_capture.sh Monday-WorkingHours.pcap veth1 10
```

---

## Common issues

### tcpreplay: “Message too long”

Fix by increasing MTU:

```bash
sudo ip link set dev veth0 mtu 9000
sudo ip link set dev veth1 mtu 9000
```

Or run with:

```bash
SET_MTU=9000 ...
```

### netmon: “operation not permitted (MEMLOCK may be too low...)”

The script starts netmon with `ulimit -l unlimited` under `sudo`.

If it still happens, you may be in a restricted environment (container / locked-down kernel).

Check:

```bash
sudo bash -c 'ulimit -l unlimited; ulimit -a | grep locked'
```

---

## Full copy/paste example

```bash
# create veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

# run capture+replay
SET_MTU=9000 REPLAY_IFACE=veth0 bash ubuntu/run_capture.sh Monday-WorkingHours.pcap veth1 10

# inspect outputs
RUN="data/runs/$(ls -1 data/runs | tail -n 1)"
ls -lah "$RUN/zeek/conn.csv" "$RUN/ebpf_agg.jsonl" "$RUN/netmon.log" "$RUN/tcpreplay.log" "$RUN/run_meta.json"
tail -n 40 "$RUN/netmon.log"
tail -n 40 "$RUN/tcpreplay.log"
ip -s link show veth0
ip -s link show veth1
```
