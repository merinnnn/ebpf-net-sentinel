# eBPF Net Sentinel

An eBPF-based network intrusion detection research system using Zeek flow features augmented with kernel-level eBPF telemetry, evaluated against the CICIDS2017 dataset.

## Repository structure

| Directory | Contents |
| --- | --- |
| [`ubuntu/`](ubuntu/README.md) | Data capture pipeline: Zeek + netmon + tcpreplay + labelling |
| [`ml/`](ml/README.md) | ML notebooks and model training (baseline vs eBPF feature sets) |
| [`app/`](app/README.md) | Streamlit web app for live monitoring and scoring |
| [`ebpf_core/`](ebpf_core/) | eBPF/Go collector (`netmon`) source |
| [`docker/`](docker/) | Docker + docker-compose for the full stack |
| [`data/`](data/) | Reports, models, and runtime artifacts (datasets not committed) |

## Quick start

See [`ubuntu/README.md`](ubuntu/README.md) for the full data capture and labelling pipeline.

See [`app/README.md`](app/README.md) for the web app and Docker setup.
