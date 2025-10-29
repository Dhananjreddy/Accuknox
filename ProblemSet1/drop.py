from bcc import BPF
import sys, time

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

SEC("xdp")
int xdp_drop_tcp_port(struct xdp_md *ctx)
{{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {{
        struct iphdr *iph = data + sizeof(struct ethhdr);

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
            return XDP_PASS;

        if (iph->protocol == IPPROTO_TCP)
        {{
            int ip_hdr_len = iph->ihl * 4;
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + ip_hdr_len;

            if ((void *)tcph + sizeof(struct tcphdr) > data_end)
                return XDP_PASS;

            if (bpf_ntohs(tcph->dest) == {port})
                return XDP_DROP;
        }}
    }}

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
        time.sleep(1)
except KeyboardInterrupt:
    b.remove_xdp(device, 0)
    print("Detached XDP program.")
