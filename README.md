# 🌐 Python MTU & TCP-MSS Tester

A professional network diagnostic tool written in Python to perform **Path MTU (Maximum Transmission Unit) Sweeping** and **TCP-MSS (Maximum Segment Size) Validation**. 

This tool is designed to identify the exact MTU along a network path and determine if intermediate routers, VPNs, or firewalls are actively clamping your TCP maximum segment size.

---

## 🚀 Key Features

* **Binary-Search Path MTU Sweep**: Dynamically determines the path's bottleneck MTU using **ICMP Echo Requests** with the `DF` (Don't Fragment) bit set.
* **TCP-MSS Handshake Negotiation**: Establishes a standard TCP handshake to query the operating system's negotiated Maximum Segment Size (`TCP_MAXSEG`).
* **Active MSS Clamping Detection**: Automatically analyzes the difference between Path MTU and Negotiated MSS to identify VPN overhead or traffic-shaping middleboxes.
* **Zero External Dependencies**: Pure Python implementation using only the standard library (`socket`, `struct`, `select`).

---

## 🛠️ How It Works

### 1. Path MTU (PMTU) Sweeping
To find the maximum packet size supported by the network path without fragmentation:
1. The script utilizes **raw ICMP sockets** to send custom ICMP Echo Requests.
2. It sets the IP header option `IP_DONTFRAG` (DF bit) to prevent the packet from being fragmented by hops along the way.
3. A **binary search** sweeps payload sizes from **500 to 1500 bytes**.
4. If a packet is too large, the destination fails to reply (or intermediate hops drop it). The script registers a timeout and narrows the search range.
5. The final Path MTU is computed as:
   $$\text{MTU} = \text{Optimal Payload} + 8\text{ bytes (ICMP Header)} + 20\text{ bytes (IPv4 Header)}$$

### 2. TCP-MSS Validation
1. The script opens a standard TCP stream socket (`SOCK_STREAM`) to the target host and port.
2. During the 3-way handshake, both hosts advertise their maximum segment size capability, and they agree on a negotiated MSS.
3. Once connected, the tool queries the socket options for `TCP_MAXSEG` to retrieve this negotiated value.
4. **Expected MSS formula**:
   * **IPv4**: $\text{MTU} - 40\text{ bytes}$ (20-byte IP header + 20-byte TCP header)
   * **IPv6**: $\text{MTU} - 60\text{ bytes}$ (40-byte IP header + 20-byte TCP header)

---

## 📋 Prerequisites & Privileges

* **Superuser Privileges**: The Path MTU sweeping mechanism constructs raw ICMP packets. This requires administrative rights (`sudo` on macOS and Linux).
* **Open Port**: The TCP validation step requires an reachable port on the target host (e.g., standard HTTP port `80`, HTTPS port `443`, or custom).

---

## 💻 Usage

Run the script with `sudo` and pass the target host name or IP address as an argument. Optionally, specify a custom port for the TCP MSS validation.

```bash
# Basic usage (defaults to TCP port 80 and target host 8.8.8.8)
sudo python3 mtu-mss-tester

# Specify custom target host
sudo python3 mtu-mss-tester example.com

# Specify custom target host and port (e.g., HTTPS port 443)
sudo python3 mtu-mss-tester example.com 443
```

---

## 📊 Example Output

```text
====================================================
 🌐 Python MTU & TCP-MSS Tester Tool
====================================================
Target Host: example.com
TCP Port:    443
----------------------------------------------------
🔍 Sweeping Path MTU to example.com...
⚡️ Sweeping payload sizes [500 to 1500]...

✅ DETECTED PATH MTU: 1500 bytes
🔗 Establishing TCP handshake to example.com:443...

✅ NEGOTIATED TCP-MSS: 1460 bytes

📊 ANALYSIS REPORT:
----------------------------------------------------
• Detected Path MTU:  1500 bytes
• Negotiated TCP-MSS: 1460 bytes
• Expected IPv4 MSS:  1460 bytes (MTU-40)
• Expected IPv6 MSS:  1440 bytes (MTU-60)
----------------------------------------------------
✨ Your connection is using standard optimal IPv4 MSS limits!
====================================================
```

### Understanding the Diagnostic Results

| Result Case | Meaning | Recommended Action |
| :--- | :--- | :--- |
| **`Negotiated TCP-MSS == Expected MSS`** | Optimal configuration. No packet fragmentation or clamping is occurring. | None. |
| **`Negotiated TCP-MSS < Expected MSS`** | **MSS Clamping Detected**. An intermediate VPN, PPPoE connection, or router is capping your segment size to prevent fragmentation overhead. | Normal for VPN tunnel interfaces (e.g. WireGuard, IPSec). No action needed if speed is fine. |
| **`Host did not respond to sweep`** | ICMP is likely blocked by target host or network firewalls. | Try a different target host that responds to pings. |

---

## 🛡️ License

This project is open-source and free to use. Use responsibly for network auditing and diagnostic purposes.
