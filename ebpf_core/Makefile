BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_DIR := bpf
VMLINUX_H := $(BPF_DIR)/vmlinux.h

# Ensure Go is found even in non-interactive shells (make)
export PATH := /usr/local/go/bin:$(PATH)

GO ?= go

all: $(VMLINUX_H) netmon.bpf.o netmon

$(VMLINUX_H):
	mkdir -p $(BPF_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

netmon.bpf.o: $(VMLINUX_H) bpf/netmon.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -I./bpf -c bpf/netmon.bpf.c -o netmon.bpf.o

netmon:
	cd cmd/netmon && $(GO) mod tidy && $(GO) build -o ../../netmon .

clean:
	rm -f netmon.bpf.o netmon $(VMLINUX_H)
