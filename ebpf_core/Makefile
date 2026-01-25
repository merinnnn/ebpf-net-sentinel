BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
VMLINUX_H := bpf/vmlinux.h

all: $(VMLINUX_H) netmon.bpf.o netmon

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

netmon.bpf.o: $(VMLINUX_H) bpf/netmon.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -I./bpf -c bpf/netmon.bpf.c -o netmon.bpf.o

netmon:
	cd cmd/netmon && go mod tidy && go build -o ../../netmon .

clean:
	rm -f netmon.bpf.o netmon $(VMLINUX_H)