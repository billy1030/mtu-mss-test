#!/usr/bin/env python3
import os
import sys
import socket
import struct
import select
import time
import subprocess
import re

def compute_checksum(source_string):
    sum_val = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum_val = sum_val + this_val
        sum_val = sum_val & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum_val = sum_val + source_string[len(source_string) - 1]
        sum_val = sum_val & 0xffffffff
    sum_val = (sum_val >> 16) + (sum_val & 0xffff)
    sum_val = sum_val + (sum_val >> 16)
    answer = ~sum_val
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def send_icmp_ping(sock, dest_addr, payload_size, seq_num):
    my_id = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", 8, 0, 0, my_id, seq_num)
    data = struct.pack("d", time.time()) + (b"Q" * (payload_size - 8))
    my_checksum = compute_checksum(header + data)
    header = struct.pack("bbHHh", 8, 0, socket.htons(my_checksum), my_id, seq_num)
    packet = header + data
    try:
        sock.sendto(packet, (dest_addr, 1))
        return True
    except OSError as e:
        if e.errno == 40 or "too long" in str(e).lower():
            return False
        raise

def receive_icmp_reply(sock, timeout=1.0):
    ready = select.select([sock], [], [], timeout)
    if ready[0] == []:
        return False
    try:
        rec_packet, addr = sock.recvfrom(2048)
        return True
    except socket.timeout:
        return False
    except OSError:
        return False

def sweep_mtu(target_host, timeout=1.0):
    print(f"  Sweeping Path MTU to {target_host}...")
    try:
        dest_addr = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"  Cannot resolve host: {target_host}")
        return None

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("  Permission Denied: Raw sockets require root privileges.")
        print("  Please run the script using: sudo python3 tester.py <host>")
        sys.exit(1)

    if sys.platform == "darwin":
        IP_DONTFRAG = 28
        raw_sock.setsockopt(socket.IPPROTO_IP, IP_DONTFRAG, 1)
    else:
        IP_MTU_DISCOVER = 10
        IP_PMTUDISC_DO = 2
        raw_sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
    raw_sock.settimeout(timeout)

    low = 500
    high = 1500
    best_payload = 0
    seq_num = 1

    print(f"  Sweeping payload sizes [{low} to {high}]...")
    while low <= high:
        mid = (low + high) // 2
        success = False
        for _ in range(2):
            if send_icmp_ping(raw_sock, dest_addr, mid, seq_num):
                seq_num += 1
                if receive_icmp_reply(raw_sock, timeout):
                    success = True
                    break
            time.sleep(0.02)

        if success:
            best_payload = mid
            low = mid + 1
        else:
            high = mid - 1

    if best_payload == 0:
        raw_sock.close()
        print(f"  Host did not respond to any DF sweep probes.")
        print(f"  Checking if host responds to ICMP at all...")
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            raw_sock.settimeout(timeout)
        except PermissionError:
            print(f"  Cannot create ICMP socket (need root).")
            print(f"  Host does not respond to ICMP (or ICMP is blocked).")
            return None
        test_success = False
        for _ in range(2):
            if send_icmp_ping(raw_sock, dest_addr, 500, seq_num):
                seq_num += 1
                if receive_icmp_reply(raw_sock, timeout):
                    test_success = True
                    break
            time.sleep(0.02)
        raw_sock.close()
        if test_success:
            print(f"  Host responds to ICMP but DROPS packets with DF bit set.")
            print(f"  This is expected behavior (security hardening on some hosts).")
        else:
            print(f"  Host does not respond to ICMP at all (likely blocked by firewall).")
        return None

    raw_sock.close()
    detected_mtu = best_payload + 8 + 20
    return detected_mtu, dest_addr

def verify_mtu_with_frag_needed(dest_addr, timeout=2.0):
    print(f"\n--- Verifying MTU with ICMP Frag Needed ---")
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if sys.platform == "darwin":
            raw_sock.setsockopt(socket.IPPROTO_IP, 28, 1)
        else:
            raw_sock.setsockopt(socket.IPPROTO_IP, 10, 2)
        raw_sock.settimeout(timeout)

        test_payloads = [1500, 1490, 1480, 1472, 1465, 1460, 1455, 1452, 1450, 1440, 1430, 1420, 1410, 1400]
        my_id = os.getpid() & 0xFFFF

        for payload in test_payloads:
            header = struct.pack("bbHHh", 8, 0, 0, my_id, 9000)
            data = struct.pack("d", time.time()) + (b"Q" * (payload - 8))
            checksum = compute_checksum(header + data)
            header = struct.pack("bbHHh", 8, 0, socket.htons(checksum), my_id, 9000)
            packet = header + data

            try:
                raw_sock.sendto(packet, (dest_addr, 1))
            except OSError:
                continue

            for _ in range(2):
                try:
                    rec_packet, addr = raw_sock.recvfrom(2048)
                    icmp_type = rec_packet[20]
                    if icmp_type == 3:
                        embedded_ip = rec_packet[28:48]
                        embedded_proto = rec_packet[28 + 9]
                        if embedded_proto == 1:
                            next_mtu = struct.unpack("!H", rec_packet[38:40])[0]
                            print(f"  Router {addr[0]} reports MTU = {next_mtu}")
                            raw_sock.close()
                            return next_mtu, addr[0]
                    elif icmp_type == 0:
                        raw_sock.close()
                        mtu = payload + 8 + 20
                        print(f"  Payload {payload} succeeded -> MTU >= {mtu}")
                        return mtu, None
                except socket.timeout:
                    continue

        raw_sock.close()
    except Exception as e:
        print(f"  Frag needed scan error: {e}")

    print(f"  Could not determine exact MTU from ICMP feedback")
    return None, None

def find_clamping_hop(dest_addr):
    print(f"\n--- Attempting to locate clamping point ---")
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if sys.platform == "darwin":
            raw_sock.setsockopt(socket.IPPROTO_IP, 28, 1)
        else:
            raw_sock.setsockopt(socket.IPPROTO_IP, 10, 2)
        raw_sock.settimeout(2.0)

        oversized_payload = 1500
        my_id = os.getpid() & 0xFFFF
        header = struct.pack("bbHHh", 8, 0, 0, my_id, 9999)
        data = struct.pack("d", time.time()) + (b"Q" * (oversized_payload - 8))
        checksum = compute_checksum(header + data)
        header = struct.pack("bbHHh", 8, 0, socket.htons(checksum), my_id, 9999)
        packet = header + data

        try:
            raw_sock.sendto(packet, (dest_addr, 1))
        except OSError:
            pass

        for _ in range(3):
            try:
                rec_packet, addr = raw_sock.recvfrom(2048)
                icmp_type = rec_packet[20]
                if icmp_type == 3:
                    raw_sock.close()
                    return addr[0]
            except socket.timeout:
                continue
        raw_sock.close()
    except Exception:
        pass
    return None

def validate_tcp_mss(target_host, port=80):
    print(f"  Establishing TCP handshake to {target_host}:{port}...")
    try:
        for family in [socket.AF_INET, socket.AF_INET6]:
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect((target_host, port))
                TCP_MAXSEG = 2
                mss_val = s.getsockopt(socket.IPPROTO_TCP, TCP_MAXSEG)
                local_ip = s.getsockname()[0]
                peer_ip = s.getpeername()[0]
                s.close()
                return mss_val, family == socket.AF_INET6, local_ip, peer_ip
            except Exception:
                continue
        print(f"  TCP connection failed to all address families")
        return None, False, None, None
    except Exception as e:
        print(f"  TCP connection failed: {e}")
        return None, False, None, None

def main():
    if len(sys.argv) < 2:
        host = "8.8.8.8"
    else:
        host = sys.argv[1]

    port = 80
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            pass

    print("=" * 60)
    print("  PYTHON MTU & TCP-MSS TESTER")
    print("=" * 60)
    print(f"  Target Host: {host}")
    print(f"  TCP Port:    {port}")
    print(f"  Timestamp:   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    result = sweep_mtu(host)
    if not result:
        return
    mtu, dest_ip = result
    print(f"\n  DETECTED PATH MTU: {mtu} bytes")

    frag_mtu, frag_router = verify_mtu_with_frag_needed(dest_ip)
    if frag_mtu and frag_mtu != mtu:
        if abs(frag_mtu - mtu) > 5:
            print(f"  Correcting MTU from {mtu} to {frag_mtu} based on ICMP feedback")
            mtu = frag_mtu

    clamping_hop = find_clamping_hop(dest_ip)
    if not clamping_hop and frag_router:
        clamping_hop = frag_router

    mss, is_ipv6, local_ip, peer_ip = validate_tcp_mss(host, port)

    print(f"\n  DETAILED PATH ANALYSIS")
    print("-" * 60)
    print(f"  Local Address:     {local_ip or 'N/A'}")
    print(f"  Remote Address:    {peer_ip or dest_ip}")
    print(f"  Detected Path MTU: {mtu} bytes")
    if clamping_hop:
        print(f"  Clamping Router:   {clamping_hop}")
    else:
        print(f"  Clamping Router:   Not identified (no ICMP Unreachable received)")

    calc_ipv4 = mtu - 40
    calc_ipv6 = mtu - 60

    if mss:
        ip_version = "IPv6" if is_ipv6 else "IPv4"
        print(f"  IP Version:        {ip_version}")
        print(f"  Negotiated TCP-MSS: {mss} bytes")
        print(f"  Expected IPv4 MSS:  {calc_ipv4} bytes (MTU-40)")
        print(f"  Expected IPv6 MSS:  {calc_ipv6} bytes (MTU-60)")

        overhead = calc_ipv4 - mss

        print(f"  TCP-MSS Overhead:  {overhead} bytes")

        print("\n  ANALYSIS:")
        print("-" * 60)
        print(f"  Path MTU = {mtu}")
        print(f"  MSS      = {mss}")
        print(f"  Expected = {calc_ipv4}")
        print(f"  Gap      = {overhead} bytes")
        print()

        if mss == calc_ipv4:
            print("  No MSS clamping detected. Standard Ethernet path.")
        elif mss == calc_ipv6:
            print("  MSS matches IPv6 expected value (MTU-60).")
        elif overhead <= 4:
            print("  MSS reduced by 4 bytes - consistent with 802.1Q VLAN tag.")
        elif overhead <= 8:
            print("  MSS reduced by 8 bytes - consistent with PPPoE or GRE.")
        elif overhead <= 12:
            print("  MSS reduced by 12 bytes - consistent with 802.1Q+PPPoE or IPsec transport.")
        elif overhead <= 16:
            print("  MSS reduced by 16 bytes - consistent with IPsec tunnel mode.")
        elif overhead <= 20:
            print("  MSS reduced by 20 bytes - consistent with L2TP/IPsec or IPsec+GRE.")
        elif overhead > 20:
            print(f"  MSS reduced by {overhead} bytes - consistent with WireGuard, OpenVPN,")
            print("  multi-layer tunneling, or a firewall MSS clamp policy.")

        if clamping_hop:
            print()
            print(f"  Router {clamping_hop} returned ICMP 'Frag needed' confirming")
            print(f"  a sub-1500 MTU link on the path.")
        else:
            print()
            print("  No ICMP 'Frag needed' response received - the clamping point")
            print("  may silently drop oversized packets or rewrite MSS without ICMP.")

        mtu_reduction = 1500 - mtu if mtu < 1500 else 0
        extra_clamp = overhead - mtu_reduction if overhead > mtu_reduction else 0

        if mtu_reduction > 0:
            print(f"\n  MTU reduced from 1500 to {mtu} ({mtu_reduction} bytes lost)")
            if extra_clamp > 0:
                print(f"  MTU overhead:       {mtu_reduction} bytes (encapsulation)")
                print(f"  Extra MSS clamping: {extra_clamp} bytes (firewall/VPN policy)")
                print("  The MSS is clamped MORE than the MTU reduction alone accounts for.")
            else:
                print("  MSS clamp matches MTU reduction exactly.")
        else:
            print(f"  MTU is standard 1500 but MSS is clamped by {overhead} bytes.")
            print("  This is firewall-enforced MSS clamping (not tunnel overhead).")
    else:
        print(f"\n  Cannot compute MSS analysis (TCP connection failed).")
        print(f"  Path MTU: {mtu} bytes")
        if clamping_hop:
            print(f"  Router {clamping_hop} reported MTU {mtu} via ICMP.")

    print("=" * 60)

if __name__ == "__main__":
    main()
