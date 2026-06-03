# Python MTU & TCP-MSS Tester

A professional network diagnostic tool written in Python to perform **Path MTU (Maximum Transmission Unit) Sweeping** and **TCP-MSS (Maximum Segment Size) Validation**. Identifies the exact MTU along a network path and detects active MSS clamping by intermediate routers, VPNs, or firewalls.

---

## Key Features

- **Binary-Search Path MTU Sweep** — Uses ICMP Echo Requests with the DF (Don't Fragment) bit set to find the bottleneck MTU.
- **Baseline Responsiveness Validation** — Probes the target with small ICMP packets first to verify ICMP responsiveness, preventing noisy pings on hosts that block ICMP completely.
- **Robust Binary Search Logic** — Resilient to transient packet loss and rate-limiting. Uses retries and abort thresholds to prevent false PMTU reductions.
- **Fallback TCP-MSS Analysis** — Proceeds to retrieve `TCP_MAXSEG` and analyze TCP clamping even if the host blocks ICMP or PMTU cannot be determined.
- **ICMP Frag Needed Validation** — Extracts next-hop MTU feedback from ICMP Destination Unreachable replies, supporting verified quotes and truncated RFC1191 responses.
- **TCP-MSS Handshake Negotiation** — Connects via TCP and reads the kernel's negotiated `TCP_MAXSEG` socket option.
- **Jumbo Frame Support** — Configurable maximum MTU boundaries (e.g. 9000) for testing high-bandwidth jumbo fabrics.
- **Cross-Platform** — Native support for Linux, macOS, and Windows (via WSL or Admin powershell).
- **Zero External Dependencies** — Pure Python standard library only.

---

## How It Works

### 1. Path MTU (PMTU) Sweeping

The script constructs custom ICMP Echo Requests using raw sockets with the DF bit enforced:

- **Linux / WSL**: `IP_MTU_DISCOVER` with `IP_PMTUDISC_DO` (value 2)
- **macOS**: `IP_DONTFRAG` socket option (value 28)
- **Windows**: `IP_DONTFRAGMENT` option (value 14)

1. **ICMP Baseline Probe**: The script first tests the target with baseline ICMP packets to verify if it responds to ping. If the target does not respond, PMTU discovery is skipped, and it falls back immediately to TCP Analysis.
2. **Adaptive Binary Search**: A binary search sweeps payload sizes from 500 up to the configured limit (default: 1500 bytes).
3. **Robust Loss Handling**: If a packet exceeds the path MTU, routers ideally return ICMP Type 3 Code 4 (Fragmentation Needed). If no reply is received (a timeout), the search is retried with backoff. If three consecutive probes at different sizes result in unconfirmed timeouts, the search is gracefully aborted with a warning to the operator (relying on the best verified MTU so far) rather than making a false reduction.

```
MTU = Optimal Payload + 8 (ICMP Header) + 20 (IPv4 Header)
```

### 2. TCP-MSS Validation & Fallback

A standard TCP socket connects to the target host:port. After the three-way handshake, the negotiated `TCP_MAXSEG` socket option is read. This runs even if PMTU discovery is skipped.

Expected MSS:
- **IPv4**: MTU - 40 (20 IP + 20 TCP)
- **IPv6**: MTU - 60 (40 IP + 20 TCP)

---

## Prerequisites & Privileges

- **Superuser privileges** — Raw ICMP sockets require root/administrator privileges on all supported operating systems.
- **Open port** — TCP validation requires a reachable port on the target (e.g., 80, 443).

---

## Usage

### Linux & macOS

```bash
# Defaults to 8.8.8.8 port 443 with a max MTU limit of 1500
sudo python3 mtu-mss-tester-linux.py

# Custom target and port
sudo python3 mtu-mss-tester-linux.py example.com 443

# Testing Jumbo frame networks (specifying 9000 max MTU limit)
sudo python3 mtu-mss-tester-linux.py 10.0.0.1 443 9000
```

### Windows (via WSL)

Since raw sockets on Windows have strict limitations, it is recommended to run the script inside Windows Subsystem for Linux (WSL):

```powershell
# Run using WSL with root permissions
wsl sudo python3 mtu-mss-tester-linux.py 8.8.8.8 443

# Jumbo MTU test under WSL
wsl sudo python3 mtu-mss-tester-linux.py 10.0.0.1 443 9000
```

---

## Example Output

```text
============================================================
PMTU & TCP_MAXSEG ANALYZER
============================================================
Target Host : www.google.com
Target Port : 443
Max MTU Limit: 1500

Discovering Path MTU (Max limit: 1500)...

Verifying target ICMP responsiveness...
Target is ICMP responsive. Starting binary search...

Resolved IP : 142.251.150.119
Path MTU    : 1420

Theoretical MSS Values
----------------------
IPv4 MSS = 1380
IPv6 MSS = 1360

TCP Analysis
------------
Local Address : 172.17.224.164
Remote Address: 142.251.156.119
TCP_MAXSEG    : 1368
Difference    : 12
TCP_MAXSEG lower than theoretical PMTU MSS.
Possible tunnel, VPN, stack tuning, or MSS clamping.

NOTE:
TCP_MAXSEG reflects the local kernel MSS.
This tool cannot definitively prove MSS rewriting by a firewall or load balancer.
For authoritative MSS-clamp detection, inspect SYN/SYN-ACK packets with Scapy, tcpdump, Wireshark, or packet capture.
============================================================
```


---

## Interpreting Results & Virtualization Notes

When analyzing output (especially when comparing native environments versus virtualization stacks like WSL), you may observe differences between the Path MTU discovery and `TCP_MAXSEG` values:

### Common Observations

1. **WSL vs. Native Host Discrepancies**:
   - **Local Address differences**: WSL uses a Hyper-V/NAT virtual network adapter (typically in the `172.17.x.x` space), which introduces virtualization overhead and different TCP stack default policies.
   - **PMTU variance**: The virtual switch might pass or segment raw ICMP DF packets differently compared to native host adapters, resulting in lower reported PMTUs (e.g. `1420` on WSL vs. `1480` on native).
2. **DNS Load Balancing Effects**:
   - Querying a hostname like `www.google.com` can resolve to different IP addresses across runs. Since server-side load balancers and intermediate routing paths might differ, always test using a **fixed target IP address** (e.g. `8.8.8.8`) to remove DNS noise.
3. **TCP_MAXSEG Stability**:
   - If the estimated PMTU increases significantly (e.g., from `1420` to `1480`) but the negotiated `TCP_MAXSEG` barely changes, the limitation is likely a fixed local network adapter or TCP stack setting on the host machine rather than path-based MSS clamping.

### Recommended Troubleshooting Commands

To isolate issues and confirm the measurements:

* **Independent PMTU Validation (Linux/WSL)**:
  ```bash
  tracepath 8.8.8.8
  ```
* **Manual MTU Verification (Windows Command Prompt)**:
  ```cmd
  ping -f -l 1472 8.8.8.8
  ```
* **Check Host Adapter MTUs (Windows PowerShell)**:
  ```powershell
  netsh interface ipv4 show subinterfaces
  ```
* **Check WSL Virtual Interface MTU (Linux)**:
  ```bash
  ip link show eth0
  ```

---

## License

Open-source and free to use. Use responsibly for network auditing and diagnostic purposes.

