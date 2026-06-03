# Python MTU & TCP-MSS Tester

A professional network diagnostic tool written in Python to perform **Path MTU (Maximum Transmission Unit) Sweeping** and **TCP-MSS (Maximum Segment Size) Validation**. Identifies the exact MTU along a network path and detects active MSS clamping by intermediate routers, VPNs, or firewalls.

---

## Key Features

- **Binary-Search Path MTU Sweep** — Uses ICMP Echo Requests with the DF (Don't Fragment) bit set to find the bottleneck MTU.
- **Baseline Responsiveness Validation** — Probes the target with small ICMP packets first to verify ICMP responsiveness, preventing noisy pings on hosts that block ICMP completely.
- **Robust Binary Search & Silent Drop Detection** — Resilient to transient packet loss and rate-limiting. If the target is verified as ICMP-responsive, persistent timeouts at larger sizes are treated as silent drops (MTU exceeded) rather than aborting.
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
3. **Silent Drop Handling**: If a packet exceeds the path MTU, routers ideally return ICMP Type 3 Code 4 (Fragmentation Needed). If no reply is received (a timeout), but the host was verified as ICMP-responsive, the tool treats it as a silent drop, adjusting search bounds downward (`high = mid - 1`) rather than failing.

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
  PYTHON MTU & TCP-MSS TESTER
============================================================
  Target Host: www.google.com
  TCP Port:    443
  Timestamp:   2026-06-03 13:21:58
------------------------------------------------------------
  Sweeping Path MTU to www.google.com...
  Sweeping payload sizes [500 to 1500]...

  DETECTED PATH MTU: 1420 bytes

--- Verifying MTU with ICMP Frag Needed ---
  Could not determine exact MTU from ICMP feedback

--- Attempting to locate clamping point ---
  Establishing TCP handshake to www.google.com:443...

  DETAILED PATH ANALYSIS
------------------------------------------------------------
  Local Address:     172.17.224.164
  Remote Address:    142.251.155.119
  Detected Path MTU: 1420 bytes
  Clamping Router:   Not identified (no ICMP Unreachable received)
  IP Version:        IPv4
  Negotiated TCP-MSS: 1400 bytes
  Expected IPv4 MSS:  1380 bytes (MTU-40)
  Expected IPv6 MSS:  1360 bytes (MTU-60)
  TCP-MSS Overhead:  -20 bytes

  ANALYSIS:
------------------------------------------------------------
  Path MTU = 1420
  MSS      = 1400
  Expected = 1380
  Gap      = -20 bytes

  MSS reduced by 4 bytes - consistent with 802.1Q VLAN tag.

  No ICMP 'Frag needed' response received - the clamping point
  may silently drop oversized packets or rewrite MSS without ICMP.

  MTU reduced from 1500 to 1420 (80 bytes lost)
  MSS clamp matches MTU reduction exactly.
============================================================
```


---

## License

Open-source and free to use. Use responsibly for network auditing and diagnostic purposes.
