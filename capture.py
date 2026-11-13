"""Packet capture helper for the system visualizer.

Sniffs IPv4 packets on every local interface with Windows raw sockets (SIO_RCVALL), groups them
into 200 ms bundles per flow, and posts the bundles to the visualizer server on localhost.
Only headers are read (addresses, ports, lengths); payloads are never stored or sent.
Needs administrator rights: when started without them it asks Windows to relaunch it elevated.
"""
import ctypes
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
URL = "http://127.0.0.1:%d/api/ingest" % PORT
WINDOW = 0.2
flows, lock = {}, threading.Lock()


def sniff(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print("capturing on", ip, flush=True)
    while True:
        try:
            pkt = s.recvfrom(65535)[0]
        except OSError:
            continue
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            continue
        ihl = (pkt[0] & 15) * 4
        length = struct.unpack_from("!H", pkt, 2)[0] or len(pkt)
        proto = pkt[9]
        src, dst = socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20])
        sp = dp = 0
        if proto in (6, 17) and len(pkt) >= ihl + 4:
            sp, dp = struct.unpack_from("!HH", pkt, ihl)
        name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "IP/%d" % proto)
        if src == ip:
            key = (name, src, sp, dst, dp, "o")
        else:
            key = (name, dst, dp, src, sp, "i")
        with lock:
            f = flows.get(key)
            if f:
                f[0] += length
                f[1] += 1
            else:
                flows[key] = [length, 1]


def main():
    ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
    for ip in ips:
        threading.Thread(target=sniff, args=(ip,), daemon=True).start()
    print("posting bundles to", URL, "- close this window to stop capturing", flush=True)
    fails = 0
    while True:
        time.sleep(WINDOW)
        with lock:
            batch = [list(k) + v for k, v in flows.items()]
            flows.clear()
        try:
            req = urllib.request.Request(URL, json.dumps(batch).encode(), {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2).read()
            fails = 0
        except OSError:
            fails += 1
            if fails == 25:
                print("visualizer server not reachable - still trying", flush=True)


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Asking Windows for administrator rights (needed for raw packet capture)...")
        args = '"%s" %d' % (os.path.abspath(__file__), PORT)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
        sys.exit(0)
    try:
        main()
    except Exception as e:  # keep the elevated window open so the error is readable
        print("capture failed:", e)
        input("press Enter to close")
