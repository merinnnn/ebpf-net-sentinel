// netmon.bpf.c (CO-RE)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  __u64 ts_ns;
  __u64 sock_cookie;

  __u32 pid;
  __u32 uid;

  __u32 saddr;     // __be32 from kernel struct sock
  __u32 daddr;     // __be32
  __u16 sport;     // host order
  __u16 dport;     // host order
  __u8  proto;

  __u8  evtype;    // 1=state, 2=send, 3=recv, 4=retrans
  __u32 state_old;
  __u32 state_new;

  __u64 bytes;
  __u32 retransmits;
  char  comm[16];
};

struct flow_key {
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8  proto;
};

struct flow_val {
  __u64 first_ts_ns;
  __u64 last_ts_ns;
  __u64 bytes_sent;
  __u64 bytes_recv;
  __u32 retransmits;
  __u32 state_changes;
  __u64 samples;

  __u32 pid_last;
  __u32 uid_last;
  char  comm_last[16];
};

struct proc_info {
  __u32 pid;
  __u32 uid;
  char  comm[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 262144);
  __type(key, struct flow_key);
  __type(value, struct flow_val);
} flows SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 262144);
  __type(key, __u64);
  __type(value, struct proc_info);
} proc_by_cookie SEC(".maps");

static __always_inline int fill_flow_from_sock(struct sock *sk, struct event *e, struct flow_key *k) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET) return 0;

  __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);          // host order
  __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);        // network order

  e->saddr = saddr;
  e->daddr = daddr;
  e->sport = sport;
  e->dport = bpf_ntohs(dport);
  e->proto = IPPROTO_TCP;

  k->saddr = saddr;
  k->daddr = daddr;
  k->sport = sport;
  k->dport = bpf_ntohs(dport);
  k->proto = IPPROTO_TCP;

  return 1;
}

static __always_inline void fill_proc_from_cookie(struct sock *sk, struct event *e, int update) {
  __u64 cookie = bpf_get_socket_cookie(sk);
  e->sock_cookie = cookie;

  struct proc_info *pi = bpf_map_lookup_elem(&proc_by_cookie, &cookie);
  if (pi) {
    e->pid = pi->pid;
    e->uid = pi->uid;
    __builtin_memcpy(e->comm, pi->comm, sizeof(e->comm));
  } else {
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
  }

  if (update) {
    struct proc_info n = {};
    n.pid = e->pid;
    n.uid = e->uid;
    __builtin_memcpy(n.comm, e->comm, sizeof(n.comm));
    bpf_map_update_elem(&proc_by_cookie, &cookie, &n, BPF_ANY);
  }
}

static __always_inline void update_flow(struct flow_key *k, struct event *e) {
  struct flow_val *v = bpf_map_lookup_elem(&flows, k);
  if (!v) {
    struct flow_val init = {};
    init.first_ts_ns = e->ts_ns;
    init.last_ts_ns = e->ts_ns;
    init.pid_last = e->pid;
    init.uid_last = e->uid;
    __builtin_memcpy(init.comm_last, e->comm, sizeof(init.comm_last));
    bpf_map_update_elem(&flows, k, &init, BPF_ANY);
    v = bpf_map_lookup_elem(&flows, k);
    if (!v) return;
  }

  v->last_ts_ns = e->ts_ns;
  v->samples += 1;

  v->pid_last = e->pid;
  v->uid_last = e->uid;
  __builtin_memcpy(v->comm_last, e->comm, sizeof(v->comm_last));

  if (e->evtype == 1) {
    v->state_changes += 1;
  } else if (e->evtype == 2) {
    v->bytes_sent += e->bytes;
  } else if (e->evtype == 3) {
    v->bytes_recv += e->bytes;
  } else if (e->evtype == 4) {
    v->retransmits += e->retransmits;
  }
}

static __always_inline void emit_event(struct event *e) {
  struct event *out = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!out) return;
  __builtin_memcpy(out, e, sizeof(*e));
  bpf_ringbuf_submit(out, 0);
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  struct sock *sk = (struct sock *)ctx->skaddr;
  if (!sk) return 0;

  struct event e = {};
  struct flow_key k = {};

  e.ts_ns = bpf_ktime_get_ns();
  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_from_cookie(sk, &e, 0);

  e.evtype = 1;
  e.state_old = ctx->oldstate;
  e.state_new = ctx->newstate;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kp_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  if (!sk) return 0;

  struct event e = {};
  struct flow_key k = {};

  e.ts_ns = bpf_ktime_get_ns();
  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_from_cookie(sk, &e, 1);

  e.evtype = 2;
  e.bytes = (__u64)size;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kp_tcp_cleanup_rbuf, struct sock *sk, int copied) {
  if (!sk) return 0;
  if (copied <= 0) return 0;

  struct event e = {};
  struct flow_key k = {};

  e.ts_ns = bpf_ktime_get_ns();
  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_from_cookie(sk, &e, 0);

  e.evtype = 3;
  e.bytes = (__u64)copied;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(kp_tcp_retransmit_skb, struct sock *sk) {
  if (!sk) return 0;

  struct event e = {};
  struct flow_key k = {};

  e.ts_ns = bpf_ktime_get_ns();
  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_from_cookie(sk, &e, 0);

  e.evtype = 4;
  e.retransmits = 1;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}
