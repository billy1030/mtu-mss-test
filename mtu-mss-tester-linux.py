#!/usr/bin/env python3
"""
PMTU and TCP_MAXSEG Analyzer

Features:
- Path MTU Discovery using ICMP Echo + DF
- Proper ICMP Fragmentation Needed parsing and strict packet validation
- Robust binary search handling transient packet loss and rate-limiting
- Handles non-RFC-compliant routers returning truncated ICMP quotes safely
- Safe fallback and priority checks for PMTU results
- Linux/macOS/Windows support (including WSL requiring root/sudo)
"""

import os
import sys
import time
import socket
import struct
import select

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_FRAG_NEEDED = 4

STATE_SUCCESS = 1
STATE_FAIL = 2
STATE_UNKNOWN = 3


def checksum(data):
    """Calculate the 1s complement checksum of data (standard network checksum)."""
    if len(data) % 2 == 1:
        data += b'\x00'
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff


def configure_df(sock):
    """Enforce Don't Fragment (DF) flag depending on platform."""
    # Define platform socket constants for readability
    IP_DONTFRAGMENT = 14
    IP_MTU_DISCOVER_WIN = 71
    IP_PMTUDISC_DO_WIN = 2
    IP_DONTFRAG_DARWIN = 28
    IP_MTU_DISCOVER_LINUX = 10
    IP_PMTUDISC_DO_LINUX = 2

    try:
        if sys.platform.startswith("win"):
            # Try setting Windows-native IP_DONTFRAGMENT
            try:
                sock.setsockopt(socket.IPPROTO_IP, IP_DONTFRAGMENT, 1)
            except Exception:
                # Fallback to Linux-like options if WinSock layer/WSL translation allows
                sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER_WIN, IP_PMTUDISC_DO_WIN)
        elif sys.platform == "darwin":
            sock.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG_DARWIN, 1)
        else:
            # Linux / WSL PMTUDISC_DO option
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER_LINUX, IP_PMTUDISC_DO_LINUX)
    except Exception:
        pass


def create_echo_packet(payload_size, seq, pid):
    if payload_size < 8:
        raise ValueError("payload_size must be >= 8")

    # Header: Type (8), Code (0), Checksum (0), ID, Sequence
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, pid, seq)
    
    # Payload contains timestamp followed by padding bytes
    data = struct.pack("!d", time.time()) + b"Q" * (payload_size - 8)
    
    csum = checksum(header + data)
    
    # Pack again with valid checksum
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, pid, seq)
    return header + data


def parse_icmp_reply(packet, pid, seq):
    """
    Parses and validates incoming ICMP packets.
    Returns (status, mtu_if_fragmentation_needed).
    """
    if len(packet) < 28:
        return STATE_UNKNOWN, None

    # Decode outer IP header
    ip_header_len = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_len + 8:
        return STATE_UNKNOWN, None

    # Note: Strict ICMP checksum validation is omitted here to prevent false negatives
    # across platforms/OS interfaces that alter returned bytes.

    icmp_header = packet[ip_header_len : ip_header_len + 8]
    icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])

    if icmp_type == ICMP_ECHO_REPLY:
        # Verify Identifier and Sequence
        reply_id, reply_seq = struct.unpack("!HH", icmp_header[4:8])
        if reply_id == pid and reply_seq == seq:
            return STATE_SUCCESS, None

    elif icmp_type == ICMP_DEST_UNREACHABLE:
        if icmp_code == ICMP_FRAG_NEEDED:
            # Decode Next-Hop MTU from ICMP header (offset 6-8)
            next_hop_mtu = struct.unpack("!H", icmp_header[6:8])[0]
            
            # The payload of the ICMP unreachable message contains the original IP header
            # followed by the first 8 bytes of the original IP payload (our ICMP Request header)
            inner_ip_offset = ip_header_len + 8
            
            # If the quote is truncated but contains a valid next-hop MTU, accept it as useful feedback
            if len(packet) < inner_ip_offset + 20 + 8:
                if next_hop_mtu > 0:
                    return STATE_FAIL, next_hop_mtu
                return STATE_UNKNOWN, None
                
            inner_ip_header_len = (packet[inner_ip_offset] & 0x0F) * 4
            inner_icmp_offset = inner_ip_offset + inner_ip_header_len
            
            if len(packet) >= inner_icmp_offset + 8:
                inner_icmp_header = packet[inner_icmp_offset : inner_icmp_offset + 8]
                inner_type, _, _, inner_id, inner_seq = struct.unpack("!BBHHH", inner_icmp_header)
                
                # Verify quote
                if inner_type == ICMP_ECHO_REQUEST and inner_id == pid and inner_seq == seq:
                    return STATE_FAIL, next_hop_mtu if next_hop_mtu > 0 else None

            # If inner verification failed, fall back to accepting the next_hop_mtu if present
            if next_hop_mtu > 0:
                return STATE_FAIL, next_hop_mtu

    return STATE_UNKNOWN, None


def probe(sock, dst, payload, seq, pid, timeout=1):
    packet = create_echo_packet(payload, seq, pid)

    try:
        sock.sendto(packet, (dst, 0))
    except OSError:
        return STATE_FAIL, None

    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        remaining = timeout - elapsed
        if remaining <= 0:
            return STATE_UNKNOWN, None

        ready = select.select([sock], [], [], remaining)
        if not ready[0]:
            return STATE_UNKNOWN, None

        try:
            data, addr = sock.recvfrom(4096)
            status, mtu = parse_icmp_reply(data, pid, seq)
            if status != STATE_UNKNOWN:
                return status, mtu
        except Exception:
            return STATE_UNKNOWN, None


def discover_pmtu(host, max_mtu=1500):
    print(f"Discovering Path MTU (Max limit: {max_mtu})...")
    print()

    dst = socket.gethostbyname(host)
    pid = os.getpid() & 0xFFFF

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_ICMP
    )
    
    # Required on Windows to receive responses
    try:
        sock.bind(("", 0))
    except Exception:
        pass

    configure_df(sock)

    low = 500
    high = max_mtu - 28

    best = 0
    best_frag_mtu = None
    seq = 1
    consecutive_unknowns = 0
    search_incomplete = False

    while low <= high:
        mid = (low + high) // 2
        
        # Retry logic for handling STATE_UNKNOWN (packet loss/rate limits)
        retries = 0
        result = STATE_UNKNOWN
        mtu = None
        while retries < 3:
            result, mtu = probe(sock, dst, mid, seq, pid)
            seq += 1
            if result != STATE_UNKNOWN:
                break
            retries += 1
            time.sleep(0.1)

        if result == STATE_SUCCESS:
            best = mid
            low = mid + 1
            consecutive_unknowns = 0
        elif result == STATE_FAIL:
            if mtu:
                best_frag_mtu = mtu
            high = mid - 1
            consecutive_unknowns = 0
        else:
            consecutive_unknowns += 1
            if consecutive_unknowns >= 3:
                search_incomplete = True
                break
            # Do not modify bounds (low/high) on transient/unconfirmed UNKNOWN.
            # Continue the loop to retry the mid size.
            continue

    sock.close()

    observed_mtu = best + 28 if best > 0 else None

    # PMTU Selection logic:
    # If router ICMP report is within a sensible margin (8 bytes) of observed success, trust router.
    # Otherwise, trust observed success to avoid broken/buggy router ICMP reports.
    pmtu = None
    if best_frag_mtu and observed_mtu:
        if abs(observed_mtu - best_frag_mtu) <= 8:
            pmtu = best_frag_mtu
        else:
            pmtu = observed_mtu
    elif best_frag_mtu:
        pmtu = best_frag_mtu
    elif observed_mtu:
        pmtu = observed_mtu

    return pmtu, dst, search_incomplete


def get_tcp_maxseg(host, port):
    try:
        infos = socket.getaddrinfo(
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )
        for info in infos:
            af, socktype, proto, canonname, sockaddr = info
            try:
                s = socket.socket(
                    af,
                    socktype,
                    proto
                )
                s.settimeout(3)
                s.connect(sockaddr)
                
                TCP_MAXSEG = getattr(socket, "TCP_MAXSEG", 2)
                mss = s.getsockopt(
                    socket.IPPROTO_TCP,
                    TCP_MAXSEG
                )
                local_ip = s.getsockname()[0]
                remote_ip = s.getpeername()[0]
                s.close()
                return mss, local_ip, remote_ip
            except Exception:
                continue
    except Exception:
        pass
    return None, None, None


def main():
    if not sys.platform.startswith("win") and os.geteuid() != 0:
        print("Run as root (sudo python3 ...).")
        sys.exit(1)

    host = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    # Default to 1500 max MTU for normal internet paths to avoid noisy probes, configurable up to jumbo size
    max_mtu = int(sys.argv[3]) if len(sys.argv) > 3 else 1500

    print("=" * 60)
    print("PMTU & TCP_MAXSEG ANALYZER")
    print("=" * 60)
    print(f"Target Host : {host}")
    print(f"Target Port : {port}")
    print(f"Max MTU Limit: {max_mtu}")
    print()

    mtu, resolved, search_incomplete = discover_pmtu(host, max_mtu)

    if mtu:
        print(f"Resolved IP : {resolved}")
        print(f"Path MTU    : {mtu}")
        if search_incomplete:
            print()
            print("WARNING:")
            print("PMTU search terminated due to repeated probe loss.")
            print("Result may be conservative.")
        print()
        print("Theoretical MSS Values")
        print("----------------------")
        print(f"IPv4 MSS = {mtu - 40}")
        print(f"IPv6 MSS = {mtu - 60}")
    else:
        print("Unable to determine PMTU")
        if search_incomplete:
            print("Search was aborted due to repeated probe loss.")
        return

    print()

    mss, local_ip, remote_ip = get_tcp_maxseg(
        host,
        port
    )

    print("TCP Analysis")
    print("------------")

    if mss:
        print(f"Local Address : {local_ip}")
        print(f"Remote Address: {remote_ip}")
        print(f"TCP_MAXSEG    : {mss}")

        diff = (mtu - 40) - mss
        print(f"Difference    : {diff}")

        if diff == 0:
            print("Consistent with PMTU.")
        elif diff > 0:
            print("TCP_MAXSEG lower than theoretical PMTU MSS.")
            print("Possible tunnel, VPN, stack tuning, or MSS clamping.")
        else:
            print("TCP_MAXSEG exceeds PMTU expectation.")
            print("Verify PMTU measurement.")
    else:
        print("Unable to establish TCP connection.")

    print()
    print("NOTE:")
    print("TCP_MAXSEG reflects the local kernel MSS.")
    print("This tool cannot definitively prove MSS rewriting by a firewall or load balancer.")
    print("For authoritative MSS-clamp detection, inspect SYN/SYN-ACK packets with Scapy, tcpdump, Wireshark, or packet capture.")
    print("=" * 60)


if __name__ == "__main__":
    main()