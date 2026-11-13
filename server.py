"""System visualizer backend: collects live process / socket / memory data and serves it on localhost."""
import base64
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
NCPU = os.cpu_count() or 1
state = {"snap": None, "err": "collector starting"}
cap = {"seq": 0, "last": 0.0, "buf": [], "tcp": {}, "tcpl": {}, "udp": {}, "known": {}}
cap_lock = threading.Lock()


def ingest(batch):
    """Attribute captured flow bundles to processes via the socket tables and queue them for the page."""
    out = []
    for f in batch:
        proto, lip, lp, rip, rp, d, nbytes, n = f
        key = (proto, lp, rip, rp)
        if proto == "TCP":
            pid = cap["tcp"].get((lp, rip, rp)) or cap["tcpl"].get(lp)
        elif proto == "UDP":
            pid = cap["udp"].get(lp)
        else:
            pid = None
        if pid is None:
            pid = cap["known"].get(key, -1)   # connection already gone from the table
        else:
            cap["known"][key] = pid
        out.append([pid, proto, lip, lp, rip, rp, d, nbytes, n])
    with cap_lock:
        cap["seq"] += 1
        cap["last"] = time.time()
        cap["buf"].append((cap["seq"], out))
        del cap["buf"][:-20]
        if len(cap["known"]) > 20000:
            cap["known"].clear()


def num(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def collector():
    with open(os.path.join(HERE, "collector.ps1"), encoding="utf-8") as f:
        script = "$parentPid=%d\n%s" % (os.getpid(), f.read())
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    proc = subprocess.Popen(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        encoding="utf-8", errors="replace",
    )
    prev, prev_t, prev_nic = {}, None, None
    rows = []
    for line in proc.stdout:
        line = line.rstrip("\r\n")
        if line != "E":
            rows.append(line.split("\t"))
            continue
        now = time.time()
        dt = (now - prev_t) if prev_t else 0
        procs, cur, svc, tcp, udp = [], {}, {}, [], []
        mem = {"total": 0, "free": 0}
        nic_rx = nic_tx = 0
        for r in rows:
            k = r[0]
            if k == "P" and len(r) >= 13:
                pid = num(r[1])
                cur[pid] = dict(pid=pid, ppid=num(r[2]), name=r[3], ws=num(r[4]), pv=num(r[5]),
                                _rd=num(r[6]), _wr=num(r[7]), th=num(r[8]), hd=num(r[9]),
                                _cpu=num(r[10]), _ct=num(r[11]), cmd=r[12])
            elif k == "S" and len(r) >= 3:
                svc[num(r[1])] = r[2]
            elif k == "T" and len(r) >= 7:
                tcp.append([r[1], num(r[2]), r[3], num(r[4]), r[5], num(r[6])])
            elif k == "U" and len(r) >= 4:
                udp.append([r[1], num(r[2]), num(r[3])])
            elif k == "M" and len(r) >= 3:
                mem = {"total": num(r[1]) * 1024, "free": num(r[2]) * 1024}
            elif k == "N" and len(r) >= 4:
                nic_rx += num(r[2])
                nic_tx += num(r[3])
        rows = []
        for pid, p in cur.items():
            par = cur.get(p["ppid"])
            # Windows reuses PIDs: a "parent" created after its child is not the real parent.
            if not par or p["ppid"] == pid or (par["_ct"] and p["_ct"] and par["_ct"] > p["_ct"]):
                p["ppid"] = 0
            old = prev.get(pid)
            cpu = rd = wr = 0.0
            if old and old["_ct"] == p["_ct"] and dt > 0:
                cpu = max(0.0, (p["_cpu"] - old["_cpu"]) / 1e7 / dt * 100 / NCPU)
                rd = max(0.0, (p["_rd"] - old["_rd"]) / dt)
                wr = max(0.0, (p["_wr"] - old["_wr"]) / dt)
            out = {k: v for k, v in p.items() if not k.startswith("_")}
            out.update(cpu=round(cpu, 2), rd=round(rd), wr=round(wr), svc=svc.get(pid, ""))
            procs.append(out)
        nic = {"rx": 0, "tx": 0}
        if prev_nic and dt > 0:
            nic = {"rx": max(0, round((nic_rx - prev_nic[0]) / dt)), "tx": max(0, round((nic_tx - prev_nic[1]) / dt))}
        prev, prev_t, prev_nic = cur, now, (nic_rx, nic_tx)
        cap["tcp"] = {(c[1], c[2], c[3]): c[5] for c in tcp if c[4] != "Listen"}
        cap["tcpl"] = {c[1]: c[5] for c in tcp}
        cap["udp"] = {u[1]: u[2] for u in udp}
        state["snap"] = json.dumps({"t": now, "ncpu": NCPU, "host": socket.gethostname(), "mem": mem,
                                    "nic": nic, "procs": procs, "tcp": tcp, "udp": udp}).encode()
        state["err"] = None
    state["err"] = "collector stopped"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/snapshot":
            if state["snap"] is None:
                self.send(503, "application/json", json.dumps({"err": state["err"]}).encode())
            else:
                self.send(200, "application/json", state["snap"])
        elif path == "/api/packets":
            try:
                since = int(self.path.split("since=")[1])
            except (IndexError, ValueError):
                since = 0
            with cap_lock:
                on = time.time() - cap["last"] < 3
                flows = [f for seq, fs in cap["buf"] if seq > since for f in fs] if since else []
                body = {"seq": cap["seq"], "on": on, "flows": flows}
            self.send(200, "application/json", json.dumps(body).encode())
        elif path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self.send(200, "text/html; charset=utf-8", f.read())
        else:
            self.send(404, "text/plain", b"not found")


    def do_POST(self):
        # Only the local capture helper posts here; refuse anything a web page could send cross-site.
        if self.path != "/api/ingest" or self.headers.get("Origin") or self.headers.get("Content-Type") != "application/json":
            return self.send(403, "text/plain", b"forbidden")
        try:
            ingest(json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)))))
            self.send(200, "text/plain", b"ok")
        except (ValueError, TypeError):
            self.send(400, "text/plain", b"bad batch")


if __name__ == "__main__":
    threading.Thread(target=collector, daemon=True).start()
    print("System visualizer: http://127.0.0.1:%d" % PORT, flush=True)
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
