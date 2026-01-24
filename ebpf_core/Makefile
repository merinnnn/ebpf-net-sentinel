BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
VMLINUX_H := bpf/vmlinux.h

all: vmlinux

vmlinux: $(VMLINUX_H)

# Ensure bpf/ exists before writing vmlinux.h
$(VMLINUX_H):
	mkdir -p $(dir $@)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

clean:
	rm -f netmon netmon.bpf.o $(VMLINUX_H)

