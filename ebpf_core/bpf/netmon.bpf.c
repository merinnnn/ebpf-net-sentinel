// netmon.bpf.c (CO-RE minimal)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  __u64 ts_ns;
  __u32 pid;
  __u32 oldstate;
  __u32 newstate;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  if (ctx->protocol != IPPROTO_TCP) return 0;

  struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) return 0;

  e->ts_ns = bpf_ktime_get_ns();
  e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  e->oldstate = ctx->oldstate;
  e->newstate = ctx->newstate;

  bpf_ringbuf_submit(e, 0);
  return 0;
}
