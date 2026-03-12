# NetSentinel Live Monitor

Single Streamlit app for the live Zeek + eBPF monitor.

## Quick start

```bash
# From inside ebpf-net-sentinel repo root:
pip install -r app/requirements.txt
streamlit run app/app.py
```

If your repo is elsewhere:

```bash
NETSENTINEL_ROOT=/path/to/ebpf-net-sentinel streamlit run app/app.py
```

## Page

| Page | What it shows |
| ---- | ------------- |
| **Live Monitor** | Real-time Zeek + eBPF capture state, raw event stream, attach status, and capture controls |

## Data it reads automatically

All paths are relative to `NETSENTINEL_ROOT` (the repo root):

``` bash
data/
  runtime/
    live_capture_state.json
    live_capture_daemon.log
  runs/
    live_<timestamp>/
      ebpf_events.jsonl
      ebpf_agg.jsonl
      merged.csv
      run_meta.json
      zeek/
        conn.csv
```
