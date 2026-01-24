BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
VMLINUX_H := bpf/vmlinux.h

all: $(VMLINUX_H) netmon.bpf.o

$(VMLINUX_H):
	mkdir -p $(dir $@)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

netmon.bpf.o: $(VMLINUX_H) bpf/netmon.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -I./bpf -c bpf/netmon.bpf.c -o netmon.bpf.o

clean:
	rm -f netmon netmon.bpf.o $(VMLINUX_H)

