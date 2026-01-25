// netmon.bpf.c (CO-RE)
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  __u64 ts_ns;
  __u32 pid;
  __u32 uid;
  __u32 saddr;     // __be32 (network order)
  __u32 daddr;     // __be32
  __u16 sport;     // host order
  __u16 dport;     // host order
  __u8  proto;     // 6 TCP
  __u8  evtype;    // 1=state
  __u32 state_old;
  __u32 state_new;
  __u64 bytes;
  char comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB
} rb SEC(".maps");

static __always_inline int fill_flow_from_sock(struct sock *sk, struct event *e) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET) return 0;

  e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

  e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  return 1;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  if (ctx->protocol != IPPROTO_TCP) return 0;

  struct sock *sk = (struct sock *)ctx->skaddr;

  struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) return 0;

  e->ts_ns = bpf_ktime_get_ns();
  e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  e->uid = (__u32)bpf_get_current_uid_gid();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->proto = IPPROTO_TCP;

  if (!fill_flow_from_sock(sk, e)) {
    bpf_ringbuf_discard(e, 0);
    return 0;
  }

  e->evtype = 1;
  e->state_old = ctx->oldstate;
  e->state_new = ctx->newstate;
  e->bytes = 0;

  bpf_ringbuf_submit(e, 0);
  return 0;
}
