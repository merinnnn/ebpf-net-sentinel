// netmon.bpf.c (CO-RE)
// This is the kernel-side program.
// It watches network activity, builds small event records,
// and sends those records to user space.
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
  __u64 ts_ns;     // time when this event was recorded

  __u32 pid;       // process id linked to this event
  __u32 uid;       // user id linked to this event

  __u32 saddr;     // source IP address
  __u32 daddr;     // destination IP address
  __u16 sport;     // source port number
  __u16 dport;     // destination port number
  __u8  proto;     // network protocol, like TCP or UDP

  __u8  evtype;    // what kind of network event this is
  __u32 state_old; // earlier TCP state, or packet direction for packet events
  __u32 state_new; // new TCP state after the change

  __u64 bytes;       // byte count tied to this event
  __u32 retransmits; // how many retransmits this event adds
  char  comm[16];    // short process name

  // Extra space at the end keeps this layout matching on both sides.
  __u32 pad_end;
};

struct flow_key {
  __u32 saddr;     // source IP used to identify one flow
  __u32 daddr;     // destination IP used to identify one flow
  __u16 sport;     // source port used to identify one flow
  __u16 dport;     // destination port used to identify one flow
  __u8  proto;     // protocol used to identify one flow
};

struct flow_val {
  __u64 first_ts_ns;   // first time we saw this flow
  __u64 last_ts_ns;    // most recent time we saw this flow
  __u64 bytes_sent;    // total sent bytes for this flow
  __u64 bytes_recv;    // total received bytes for this flow
  __u32 retransmits;   // total retransmit count for this flow
  __u32 state_changes; // how many TCP state changes we saw
  __u64 samples;       // how many events were added to this flow

  __u32 pid_last;      // last process id we saw for this flow
  __u32 uid_last;      // last user id we saw for this flow
  char  comm_last[16]; // last process name we saw for this flow
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF); // says this map is a ring buffer
  __uint(max_entries, 1 << 24); // space used to hand events to user space
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH); // says this map is a hash table with old-entry cleanup
  __uint(max_entries, 2097152);  // stores recent flow summaries
  __type(key, struct flow_key);   // each entry is looked up by flow details
  __type(value, struct flow_val); // each entry stores the running totals for that flow
} flows SEC(".maps");

// Fill in process details when the kernel lets us ask for them directly.
static __always_inline void fill_proc_current(struct event *e) {
  e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  e->uid = (__u32)bpf_get_current_uid_gid();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Packet filter programs cannot always see the current process.
// Here we keep what we can and leave the rest blank.
static __always_inline void fill_proc_sock_packet(struct event *e, struct __sk_buff *skb) {
  e->pid = 0;
  e->uid = (__u32)bpf_get_socket_uid(skb);
  __builtin_memset(e->comm, 0, sizeof(e->comm));
}

// Read the socket and copy the basic flow details into both the event
// we will send out and the map key we use for counting.
static __always_inline int fill_flow_from_sock(struct sock *sk, struct event *e, struct flow_key *k) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET) return 0;

  __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

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

// Update the running totals for one flow.
// If this is the first time we have seen the flow, create a new entry.
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
    // For packet events, state_old is reused to tell us direction.
    // Outgoing packets count as sent bytes. Everything else counts as received.
    if (e->state_old == PACKET_OUTGOING)
      v->bytes_sent += e->bytes;
    else
      v->bytes_recv += e->bytes;
  }
}

// Send one finished event to user space through the ring buffer.
static __always_inline void emit_event(struct event *e) {
  struct event *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
  if (!out) return;
  __builtin_memcpy(out, e, sizeof(*out));
  bpf_ringbuf_submit(out, 0);
}

// This path watches raw packets on an interface.
// It exists so replayed traffic can still be seen even when normal TCP hooks do not run.
SEC("socket")
int sock_packet(struct __sk_buff *skb) {
  // Read the ethernet header first so we can see what kind of packet this is.
  struct ethhdr eth = {};
  if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
    return 0;

  if (eth.h_proto != bpf_htons(ETH_P_IP))
    return 0;

  // Next, read the start of the IPv4 header.
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

  // Work out where the TCP or UDP header begins.
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

  // Save the current kernel time.
  e.ts_ns = bpf_ktime_get_ns();

  // This program type cannot safely ask for the current process id here,
  // so we fill in only the fields we can get from the packet context.
  fill_proc_sock_packet(&e, skb);

  e.saddr = iph.saddr;
  e.daddr = iph.daddr;
  e.sport = sport;
  e.dport = dport;
  e.proto = proto;

  // Mark this as a packet event and store the packet size.
  e.evtype = 5;
  e.bytes = (__u64)skb->len;
  e.retransmits = 0;
  e.state_old = skb->pkt_type; // reused here to remember packet direction
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

// This hook runs when a TCP socket changes state, like going from connect to established.
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

// This hook runs when the kernel sends TCP data.
SEC("kprobe/tcp_sendmsg")
int kp_tcp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  size_t size = (size_t)PT_REGS_PARM3(ctx); // third argument is the byte count
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

// This hook runs after TCP data is copied up to user space,
// so we treat that as received bytes.
SEC("kprobe/tcp_cleanup_rbuf")
int kp_tcp_cleanup_rbuf(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  int copied = (int)PT_REGS_PARM2(ctx); // second argument is the number of copied bytes
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

// This hook runs when the kernel has to send a TCP packet again.
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
