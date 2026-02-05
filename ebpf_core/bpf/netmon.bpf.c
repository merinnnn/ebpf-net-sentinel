// netmon.bpf.c (CO-RE)
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef PACKET_OUTGOING
#define PACKET_OUTGOING 4
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  __u64 ts_ns;

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

  // Explicit tail padding so user-space struct layout is deterministic.
  __u32 pad_end;
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

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 2097152);  // 2M entries
  __type(key, struct flow_key);
  __type(value, struct flow_val);
} flows SEC(".maps");

static __always_inline void fill_proc_current(struct event *e) {
  e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  e->uid = (__u32)bpf_get_current_uid_gid();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void fill_proc_sock_packet(struct event *e, struct __sk_buff *skb) {
  e->pid = 0;
  e->uid = (__u32)bpf_get_socket_uid(skb);
  __builtin_memset(e->comm, 0, sizeof(e->comm));
}

static __always_inline int fill_flow_from_sock(struct sock *sk, struct event *e, struct flow_key *k) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET) return 0;

  __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);   // host order
  __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport); // network order

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

  if (e->ts_ns < v->first_ts_ns) v->first_ts_ns = e->ts_ns;
  if (e->ts_ns > v->last_ts_ns)  v->last_ts_ns  = e->ts_ns;

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
  } else if (e->evtype == 5) {
    // Packet-based accounting: we stash skb->pkt_type in state_old.
    // PACKET_OUTGOING means egress; otherwise treat as ingress.
    if (e->state_old == PACKET_OUTGOING)
      v->bytes_sent += e->bytes;
    else
      v->bytes_recv += e->bytes;
  }
}

static __always_inline void emit_event(struct event *e) {
  struct event *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
  if (!out) return;
  __builtin_memcpy(out, e, sizeof(*out));
  bpf_ringbuf_submit(out, 0);
}

// tcpreplay injects frames at L2 and does NOT exercise the TCP socket stack,
// so kprobes/tracepoints like tcp_sendmsg won't fire. A socket filter lets us
// observe replayed traffic and aggregate by 5-tuple.
SEC("socket")
int sock_packet(struct __sk_buff *skb) {
  // Ethernet header
  struct ethhdr eth = {};
  if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
    return 0;

  if (eth.h_proto != bpf_htons(ETH_P_IP))
    return 0;

  // IPv4 header (base)
  struct iphdr iph = {};
  int off = (int)sizeof(eth);
  if (bpf_skb_load_bytes(skb, off, &iph, sizeof(iph)) < 0)
    return 0;

  if (iph.version != 4)
    return 0;

  __u32 ihl = (__u32)iph.ihl * 4;
  if (ihl < sizeof(struct iphdr))
    return 0;

  __u8 proto = iph.protocol;
  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
    return 0;

  // L4 header offset
  int l4off = off + (int)ihl;

  __u16 sport = 0, dport = 0;
  if (proto == IPPROTO_TCP) {
    struct tcphdr th = {};
    if (bpf_skb_load_bytes(skb, l4off, &th, sizeof(th)) < 0)
      return 0;
    sport = bpf_ntohs(th.source);
    dport = bpf_ntohs(th.dest);
  } else {
    struct udphdr uh = {};
    if (bpf_skb_load_bytes(skb, l4off, &uh, sizeof(uh)) < 0)
      return 0;
    sport = bpf_ntohs(uh.source);
    dport = bpf_ntohs(uh.dest);
  }

  struct event e = {};
  struct flow_key k = {};

  // Use a monotonic clock
  e.ts_ns = bpf_ktime_get_ns();

  // IMPORTANT: socket_filter cannot use bpf_get_current_pid_tgid on current kernel.
  fill_proc_sock_packet(&e, skb);

  e.saddr = iph.saddr; // __be32
  e.daddr = iph.daddr; // __be32
  e.sport = sport;
  e.dport = dport;
  e.proto = proto;

  // Packet-based accounting event
  e.evtype = 5;
  e.bytes = (__u64)skb->len;
  e.retransmits = 0;
  e.state_old = skb->pkt_type; // reuse for direction
  e.state_new = 0;

  k.saddr = iph.saddr;
  k.daddr = iph.daddr;
  k.sport = sport;
  k.dport = dport;
  k.proto = proto;

  update_flow(&k, &e);
  emit_event(&e);

  return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  if (ctx->protocol != IPPROTO_TCP) return 0;

  struct sock *sk = (struct sock *)ctx->skaddr;
  if (!sk) return 0;

  struct event e = {};
  struct flow_key k = {};

  e.ts_ns = bpf_ktime_get_ns();
  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_current(&e);

  e.evtype = 1;
  e.state_old = ctx->oldstate;
  e.state_new = ctx->newstate;
  e.bytes = 0;
  e.retransmits = 0;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}

SEC("kprobe/tcp_sendmsg")
int kp_tcp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  size_t size = (size_t)PT_REGS_PARM3(ctx); // tcp_sendmsg(sk, msg, size)
  if (!sk) return 0;

  struct flow_key k = {};
  struct event e = {};

  e.ts_ns = bpf_ktime_get_ns();

  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_current(&e);

  e.evtype = 2;
  e.bytes = (__u64)size;
  e.retransmits = 0;
  e.state_old = 0;
  e.state_new = 0;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kp_tcp_cleanup_rbuf(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  int copied = (int)PT_REGS_PARM2(ctx); // tcp_cleanup_rbuf(sk, copied)
  if (!sk) return 0;
  if (copied <= 0) return 0;

  struct flow_key k = {};
  struct event e = {};

  e.ts_ns = bpf_ktime_get_ns();

  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_current(&e);

  e.evtype = 3;
  e.bytes = (__u64)copied;
  e.retransmits = 0;
  e.state_old = 0;
  e.state_new = 0;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int kp_tcp_retransmit_skb(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  if (!sk) return 0;

  struct flow_key k = {};
  struct event e = {};

  e.ts_ns = bpf_ktime_get_ns();

  if (!fill_flow_from_sock(sk, &e, &k)) return 0;
  fill_proc_current(&e);

  e.evtype = 4;
  e.bytes = 0;
  e.retransmits = 1;
  e.state_old = 0;
  e.state_new = 0;

  update_flow(&k, &e);
  emit_event(&e);
  return 0;
}
