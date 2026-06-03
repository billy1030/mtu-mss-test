# Python MTU & TCP-MSS Tester

A professional network diagnostic tool written in Python to perform **Path MTU (Maximum Transmission Unit) Sweeping** and **TCP-MSS (Maximum Segment Size) Validation**. Identifies the exact MTU along a network path and detects active MSS clamping by intermediate routers, VPNs, or firewalls.

---

## Key Features

- **Binary-Search Path MTU Sweep** — Uses ICMP Echo Requests with the DF (Don't Fragment) bit set to find the bottleneck MTU
- **ICMP Frag Needed Verification** — Validates sweep results by probing with decreasing payloads to capture exact router MTU feedback
- **Clamping Router Identification** — Attempts to locate the specific hop returning ICMP "Frag Needed" messages
- **TCP-MSS Handshake Negotiation** — Reads the OS-negotiated TCP_MAXSEG value from a real TCP connection
- **IP Family Detection** — Automatically detects IPv4 vs IPv6
- **Active MSS Clamping Detection** — Analyzes the gap between Path MTU and Negotiated MSS, separating MTU reduction from extra firewall clamping
- **Unreachable/DF-Drop Diagnostics** — Detects whether a non-responsive host blocks ICMP entirely or only drops packets with DF set
- **Cross-Platform** — macOS (IP_DONTFRAG) and Linux (IP_MTU_DISCOVER) support
- **Zero External Dependencies** — Pure Python standard library only

---

## How It Works

### 1. Path MTU (PMTU) Sweeping

The script constructs custom ICMP Echo Requests using raw sockets with the DF bit enforced:

- **macOS**: `IP_DONTFRAG` socket option (value 28)
- **Linux**: `IP_MTU_DISCOVER` with `IP_PMTUDISC_DO` (value 2)

A binary search sweeps payload sizes from 500 to 1500 bytes. If a packet exceeds the path MTU, it's silently dropped and the search range narrows.

```
MTU = Optimal Payload + 8 (ICMP Header) + 20 (IPv4 Header)
```

### 2. ICMP Frag Needed Verification

After the binary sweep, the script sends oversized probes from 1500 bytes downward. When a router responds with ICMP type 3 ("Frag Needed"), the embedded next-hop MTU is extracted and used to correct the sweep result. This catches cases where the binary sweep is off due to retries or edge network behavior.

### 3. TCP-MSS Validation

A standard TCP socket connects to the target host:port. After the three-way handshake, the negotiated `TCP_MAXSEG` socket option is read.

Expected MSS:
- **IPv4**: MTU - 40 (20 IP + 20 TCP)
- **IPv6**: MTU - 60 (40 IP + 20 TCP)

---

## Prerequisites & Privileges

- **Superuser privileges** — Raw ICMP sockets require `sudo` on both macOS and Linux
- **Open port** — TCP validation requires a reachable port on the target (e.g., 80, 443)

---

## Usage

```bash
# Defaults to 8.8.8.8 port 80
sudo python3 mtu-mss-tester-linux.py

# Custom target
sudo python3 mtu-mss-tester-linux.py example.com

# Custom target and port
sudo python3 mtu-mss-tester-linux.py example.com 443
```

---

## Example Output

```
============================================================
  PYTHON MTU & TCP-MSS TESTER
============================================================
  Target Host: www.google.com
  TCP Port:    443
  Timestamp:   2026-06-03 02:06:29
------------------------------------------------------------
  Sweeping Path MTU to www.google.com...
  Sweeping payload sizes [500 to 1500]...

  DETECTED PATH MTU: 1497 bytes

--- Verifying MTU with ICMP Frag Needed ---
  Payload 1452 succeeded -> MTU >= 1480
  Correcting MTU from 1497 to 1480 based on ICMP feedback

--- Attempting to locate clamping point ---
  Establishing TCP handshake to www.google.com:443...

  DETAILED PATH ANALYSIS
------------------------------------------------------------
  Local Address:     172.16.2.30
  Remote Address:    142.251.151.119
  Detected Path MTU: 1480 bytes
  Clamping Router:   Not identified
  IP Version:        IPv4
  Negotiated TCP-MSS: 1338 bytes
  Expected IPv4 MSS:  1440 bytes (MTU-40)
  Expected IPv6 MSS:  1420 bytes (MTU-60)
  TCP-MSS Overhead:  102 bytes

  ANALYSIS:
------------------------------------------------------------
  Path MTU = 1480
  MSS      = 1338
  Expected = 1440
  Gap      = 102 bytes

  MSS reduced by 102 bytes - consistent with WireGuard, OpenVPN,
  multi-layer tunneling, or a firewall MSS clamp policy.

  No ICMP 'Frag needed' response received - the clamping point
  may silently drop oversized packets or rewrite MSS without ICMP.

  MTU reduced from 1500 to 1480 (20 bytes lost)
  MTU overhead:       20 bytes (encapsulation)
  Extra MSS clamping: 82 bytes (firewall/VPN policy)
  The MSS is clamped MORE than the MTU reduction alone accounts for.
============================================================
```

---

## Diagnostic Reference

### Overhead Interpretation

| Gap Range | Likely Cause |
| :--- | :--- |
| 0 bytes | Standard Ethernet, no clamping |
| 4 bytes | 802.1Q VLAN tag |
| 8 bytes | PPPoE or GRE encapsulation |
| 12 bytes | 802.1Q + PPPoE or IPsec transport mode |
| 16 bytes | IPsec tunnel mode (ESP) |
| 20 bytes | L2TP/IPsec or IPsec + GRE |
| > 20 bytes | WireGuard, OpenVPN, multi-layer tunneling, or firewall MSS clamp policy |

### Host Unreachable Diagnostics

| Sweep Result | DF-Test Result | Meaning |
| :--- | :--- | :--- |
| No response | Responds without DF | Host drops DF packets (security hardening, e.g. github.com) |
| No response | No response either | Host blocks all ICMP (e.g. amazon.com, netflix.com) |

---

## License

Open-source and free to use. Use responsibly for network auditing and diagnostic purposes.
