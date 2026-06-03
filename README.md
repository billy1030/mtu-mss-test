# Python MTU & TCP-MSS Tester

A professional network diagnostic tool written in Python to perform **Path MTU (Maximum Transmission Unit) Sweeping** and **TCP-MSS (Maximum Segment Size) Validation**. Identifies the exact MTU along a network path and detects active MSS clamping by intermediate routers, VPNs, or firewalls.

---

## Key Features

- **Binary-Search Path MTU Sweep** — Uses ICMP Echo Requests with the DF (Don't Fragment) bit set to find the bottleneck MTU.
- **Robust Binary Search Logic** — Resilient to transient packet loss and rate-limiting. Uses retries and abort thresholds to prevent false PMTU reductions.
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

A binary search sweeps payload sizes from 500 up to the configured limit (default: 1500 bytes). If a packet exceeds the path MTU, the router drops it and ideally returns ICMP Type 3 Code 4.

```
MTU = Optimal Payload + 8 (ICMP Header) + 20 (IPv4 Header)
```

### 2. TCP-MSS Validation

A standard TCP socket connects to the target host:port. After the three-way handshake, the negotiated `TCP_MAXSEG` socket option is read.

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

```
============================================================
PMTU & TCP_MAXSEG ANALYZER
============================================================
Target Host : 8.8.8.8
Target Port : 443
Max MTU Limit: 1500

Discovering Path MTU (Max limit: 1500)...

Resolved IP : 8.8.8.8
Path MTU    : 1500

Theoretical MSS Values
----------------------
IPv4 MSS = 1460
IPv6 MSS = 1440

TCP Analysis
------------
Local Address : 192.168.1.50
Remote Address: 8.8.8.8
TCP_MAXSEG    : 1460
Difference    : 0
Consistent with PMTU.
============================================================
```

---

## License

Open-source and free to use. Use responsibly for network auditing and diagnostic purposes.
