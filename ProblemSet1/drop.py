from bcc import BPF
import sys

device = "eth0"
if len(sys.argv) > 1:
    device = sys.argv[1] 
port = 4040
if len(sys.argv) > 2:
    port = int(sys.argv[2]) 

bpf_program = f"""
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp_drop_tcp_port")
int xdp_drop_tcp_port(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == __constant_htons({port}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""

b = BPF(text=bpf_program)
fn = b.load_func("xdp_drop_tcp_port", BPF.XDP)
b.attach_xdp(device, fn, 0)

print(f"Dropping TCP packets on port {port} via XDP on {device}")
try:
    while True:
        pass
except KeyboardInterrupt:
    b.remove_xdp(device, 0)
    print("\nDetached XDP program.")
