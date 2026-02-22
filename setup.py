from setuptools import setup, find_packages

setup(
    name="ml",
    version="0.1.0",
    packages=find_packages(),
    description="Kernel-Level Network Anomaly Detection: eBPF vs Baseline ML experiments",
    python_requires=">=3.10",
)