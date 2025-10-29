# Accuknox

This repository contains my solutions for the Accuknox problem statements:
- Problem 1: Drop TCP packets using eBPF.
- Problem 3: Explain the Go concurrency code snippet.

## Problem 1 — eBPF Packet Drop
- Created an XDP-based eBPF program that inspects incoming packets.
- If the packet is TCP and the destination port matches the configured port (default 4040), the packet is dropped.
- Used a BPF map (BPF_MAP_TYPE_ARRAY) to store the port number, making it configurable from userspace.
- Core logic:
  ```
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)(ip + 1);
    __u16 dport = bpf_ntohs(tcp->dest);
    if (dport == drop_port)
        return XDP_DROP;
  }
  ```
### Why I Could Not Demo the Working Code
- The program doesn't compile, it requires kernel-level privileges and a full Linux kernel with eBPF support.
- My person Linux environment is WSL2, which is missing kernel headers and eBPF permissions.
- I also tried to demo the code in GitHub Codespaces. Codespaces runs inside Docker containers without root kernel privileges. bpf() and XDP hooks are unavailable.
- eBPF programs require a real Linux environment (bare-metal or VM) with root privileges, matching kernel headers, and networking interfaces that support XDP or tc attachment.

## Problem 3 — Go Concurrency Explanation
The main function exits before the goroutine reads and executes the function from the channel.
Go does not wait for goroutines to finish unless you use synchronization (e.g., sync.WaitGroup). The simplest solution is to just wait for the code to execute.




Author: Dhananjay Reddy
Date: 29 October 2025
Contact: dhananjreddy@gmail.com
