// Live system data: processes, sockets, memory, NIC counters, and (when elevated) network capture.
#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <shellapi.h>
#include <winsvc.h>
#include <algorithm>
#include <array>
#include <deque>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>

struct Proc {
    int pid = 0, ppid = 0, th = 0, hd = 0;
    std::string name, svc;
    uint64_t ws = 0, pv = 0, cpuT = 0, rdT = 0, wrT = 0, ct = 0;
    double cpu = 0, rd = 0, wr = 0;
};
struct Tcp { std::string la, ra; int lp, rp, state, pid; };
struct Udp { std::string la; int lp, pid; };
struct Snapshot {
    std::vector<Proc> procs;
    std::vector<Tcp> tcp;
    std::vector<Udp> udp;
    uint64_t memTotal = 0, memFree = 0;
    double rx = 0, tx = 0, t = 0;
    std::string host;
    std::unordered_map<int, int> idx;
    const Proc* get(int pid) const { auto it = idx.find(pid); return it == idx.end() ? nullptr : &procs[it->second]; }
};
// One bundle of captured traffic for a single flow and direction (200 ms window).
struct Flow { int pid, proto, lp, rp, n; bool out; uint64_t bytes; std::string lip, rip; double t; };

struct DiskIo { int pid; std::string path; uint64_t rd, wr; double t; };   // bytes read / written to one file by one process in a 200 ms window
struct FileH { int pid; std::string path; };
// One captured IPv4 packet: addresses in network order, the first bytes of the packet (headers + start of payload).
struct Pkt { double t; int pid; uint32_t lip, rip; uint16_t lp, rp, len, cap; uint8_t proto, out; uint8_t data[512]; };
inline std::mutex g_pkMx; inline std::deque<Pkt> g_pkts;
inline std::atomic<bool> g_wantPkts{false};   // true only while the packet viewer is open
inline bool g_allowPayload = false;           // set by the elevated app; the background service never reads packet contents                             // one open disk-file handle

inline std::mutex g_snapMx, g_flowMx, g_tblMx, g_accMx, g_fhMx;
inline std::vector<DiskIo> g_disk;                       // guarded by g_flowMx
inline std::shared_ptr<std::vector<FileH>> g_fileHandles; // guarded by g_fhMx
inline std::atomic<bool> g_wantFiles{false};
inline std::atomic<int> g_fhDenied{0};
inline std::shared_ptr<Snapshot> g_snap;
inline std::vector<Flow> g_flows;
inline std::atomic<int> g_capMode{0};          // 0 off, 1 ETW kernel network events, 2 raw sockets
inline std::atomic<bool> g_quit{false};
inline std::unordered_map<uint64_t, int> g_tcpExact;   // (lport, rport, remote v4) -> pid, for raw capture
inline std::unordered_map<int, int> g_tcpPort, g_udpPort;

inline std::string narrow(const wchar_t* w, int n = -1) {
    if (!w || n == 0) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, n, nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, n, s.data(), len, nullptr, nullptr);
    if (n < 0 && !s.empty()) s.pop_back();
    return s;
}
inline std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), len);
    return w;
}
inline std::string ip4s(const void* a) { char b[64] = ""; inet_ntop(AF_INET, (void*)a, b, 64); return b; }
inline std::string ip6s(const void* a) { char b[64] = ""; inet_ntop(AF_INET6, (void*)a, b, 64); return b; }
inline bool isElevated() {
    HANDLE tok; TOKEN_ELEVATION e{}; DWORD n = 0; bool r = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) { r = GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n) && e.TokenIsElevated; CloseHandle(tok); }
    return r;
}
inline double nowSec() { static LARGE_INTEGER f, s; if (!f.QuadPart) { QueryPerformanceFrequency(&f); QueryPerformanceCounter(&s); } LARGE_INTEGER c; QueryPerformanceCounter(&c); return double(c.QuadPart - s.QuadPart) / f.QuadPart; }

// ---------------------------------------------------------------- collector
struct SPI {   // SYSTEM_PROCESS_INFORMATION, full x64 layout
    ULONG NextEntryOffset, NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; ULONG HardFaultCount, NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime; LARGE_INTEGER CreateTime, UserTime, KernelTime; UNICODE_STRING ImageName; LONG BasePriority;
    HANDLE UniqueProcessId, InheritedFromUniqueProcessId; ULONG HandleCount, SessionId; ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize, VirtualSize; ULONG PageFaultCount; SIZE_T PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage,
        QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
};

inline void collectorThread() {
    std::unordered_map<int, Proc> prev;
    std::unordered_map<int, std::string> svc;
    std::vector<BYTE> buf(1 << 20), tb(1 << 16);
    double prevT = 0; uint64_t prx = 0, ptx = 0; int tick = 0;
    SYSTEM_INFO si; GetSystemInfo(&si); int ncpu = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
    char host[256] = "this PC"; DWORD hn = 256; GetComputerNameA(host, &hn);
    while (!g_quit) {
        auto s = std::make_shared<Snapshot>(); s->host = host;
        double t = nowSec(), dt = prevT ? t - prevT : 0; s->t = t;
        if (tick++ % 15 == 0) {   // service names per host process
            svc.clear();
            if (SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE)) {
                DWORD need = 0, cnt = 0, resume = 0; std::vector<BYTE> sb(1 << 18);
                for (int tries = 0; tries < 3; tries++) {
                    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, sb.data(), (DWORD)sb.size(), &need, &cnt, &resume, nullptr)) {
                        auto* e = (ENUM_SERVICE_STATUS_PROCESSW*)sb.data();
                        for (DWORD i = 0; i < cnt; i++) { auto& x = svc[(int)e[i].ServiceStatusProcess.dwProcessId]; if (!x.empty()) x += ", "; x += narrow(e[i].lpServiceName); }
                        break;
                    }
                    if (GetLastError() != ERROR_MORE_DATA) break;
                    sb.resize(sb.size() + need + 4096); resume = 0;
                }
                CloseServiceHandle(scm);
            }
        }
        // processes
        ULONG ret = 0; NTSTATUS st;
        while ((st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, buf.data(), (ULONG)buf.size(), &ret)) == (NTSTATUS)0xC0000004) buf.resize(buf.size() * 2);
        std::unordered_map<int, Proc> cur;
        if (st >= 0) {
            for (BYTE* p = buf.data();;) {
                SPI* e = (SPI*)p; Proc q;
                q.pid = (int)(ULONG_PTR)e->UniqueProcessId; q.ppid = (int)(ULONG_PTR)e->InheritedFromUniqueProcessId;
                q.name = q.pid == 0 ? "System Idle Process" : narrow(e->ImageName.Buffer, e->ImageName.Length / 2);
                if (q.name.empty()) q.name = "pid " + std::to_string(q.pid);
                q.ws = e->WorkingSetSize; q.pv = e->PrivatePageCount; q.th = e->NumberOfThreads; q.hd = e->HandleCount;
                q.cpuT = q.pid == 0 ? 0 : e->UserTime.QuadPart + e->KernelTime.QuadPart; q.ct = e->CreateTime.QuadPart;
                q.rdT = e->ReadTransferCount.QuadPart; q.wrT = e->WriteTransferCount.QuadPart;
                cur[q.pid] = q;
                if (!e->NextEntryOffset) break; p += e->NextEntryOffset;
            }
        }
        for (auto& [pid, q] : cur) {
            auto par = cur.find(q.ppid);   // PIDs are reused: a "parent" created after its child is not the real parent
            if (par == cur.end() || q.ppid == pid || (par->second.ct && q.ct && par->second.ct > q.ct)) q.ppid = 0;
            auto old = prev.find(pid);
            if (old != prev.end() && old->second.ct == q.ct && dt > 0) {
                q.cpu = (q.cpuT >= old->second.cpuT ? double(q.cpuT - old->second.cpuT) : 0) / 1e7 / dt * 100 / ncpu;
                q.rd = (q.rdT >= old->second.rdT ? double(q.rdT - old->second.rdT) : 0) / dt;
                q.wr = (q.wrT >= old->second.wrT ? double(q.wrT - old->second.wrT) : 0) / dt;
            }
            auto sv = svc.find(pid); if (sv != svc.end()) q.svc = sv->second;
            s->idx[pid] = (int)s->procs.size(); s->procs.push_back(q);
        }
        prev = cur;
        // sockets
        std::unordered_map<uint64_t, int> ex; std::unordered_map<int, int> tp, up;
        auto table = [&](int which, ULONG af) -> bool {
            for (int i = 0; i < 4; i++) {
                DWORD sz = (DWORD)tb.size();
                DWORD r = which == 0 ? GetExtendedTcpTable(tb.data(), &sz, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0) : GetExtendedUdpTable(tb.data(), &sz, FALSE, af, UDP_TABLE_OWNER_PID, 0);
                if (r == NO_ERROR) return true;
                if (r != ERROR_INSUFFICIENT_BUFFER) return false;
                tb.resize(sz + 4096);
            }
            return false;
        };
        if (table(0, AF_INET)) { auto* t4 = (MIB_TCPTABLE_OWNER_PID*)tb.data();
            for (DWORD i = 0; i < t4->dwNumEntries; i++) { auto& r = t4->table[i]; int lp = ntohs((u_short)r.dwLocalPort), rp = ntohs((u_short)r.dwRemotePort);
                s->tcp.push_back({ ip4s(&r.dwLocalAddr), ip4s(&r.dwRemoteAddr), lp, r.dwState == MIB_TCP_STATE_LISTEN ? 0 : rp, (int)r.dwState, (int)r.dwOwningPid });
                tp[lp] = r.dwOwningPid; if (r.dwState != MIB_TCP_STATE_LISTEN) ex[(uint64_t(lp) << 48) | (uint64_t(rp) << 32) | r.dwRemoteAddr] = r.dwOwningPid; } }
        if (table(0, AF_INET6)) { auto* t6 = (MIB_TCP6TABLE_OWNER_PID*)tb.data();
            for (DWORD i = 0; i < t6->dwNumEntries; i++) { auto& r = t6->table[i];
                s->tcp.push_back({ ip6s(r.ucLocalAddr), ip6s(r.ucRemoteAddr), ntohs((u_short)r.dwLocalPort), r.dwState == MIB_TCP_STATE_LISTEN ? 0 : ntohs((u_short)r.dwRemotePort), (int)r.dwState, (int)r.dwOwningPid }); } }
        if (table(1, AF_INET)) { auto* u4 = (MIB_UDPTABLE_OWNER_PID*)tb.data();
            for (DWORD i = 0; i < u4->dwNumEntries; i++) { auto& r = u4->table[i]; int lp = ntohs((u_short)r.dwLocalPort); s->udp.push_back({ ip4s(&r.dwLocalAddr), lp, (int)r.dwOwningPid }); up[lp] = r.dwOwningPid; } }
        if (table(1, AF_INET6)) { auto* u6 = (MIB_UDP6TABLE_OWNER_PID*)tb.data();
            for (DWORD i = 0; i < u6->dwNumEntries; i++) { auto& r = u6->table[i]; s->udp.push_back({ ip6s(r.ucLocalAddr), ntohs((u_short)r.dwLocalPort), (int)r.dwOwningPid }); } }
        { std::lock_guard<std::mutex> l(g_tblMx); g_tcpExact.swap(ex); g_tcpPort.swap(tp); g_udpPort.swap(up); }
        // memory, NICs
        MEMORYSTATUSEX ms{ sizeof(ms) }; GlobalMemoryStatusEx(&ms); s->memTotal = ms.ullTotalPhys; s->memFree = ms.ullAvailPhys;
        uint64_t rx = 0, tx = 0; PMIB_IF_TABLE2 it = nullptr;
        if (GetIfTable2(&it) == NO_ERROR) { for (ULONG i = 0; i < it->NumEntries; i++) { auto& r = it->Table[i]; if (r.InterfaceAndOperStatusFlags.HardwareInterface && r.OperStatus == IfOperStatusUp) { rx += r.InOctets; tx += r.OutOctets; } } FreeMibTable(it); }
        if (dt > 0 && rx >= prx && tx >= ptx) { s->rx = double(rx - prx) / dt; s->tx = double(tx - ptx) / dt; }
        prx = rx; ptx = tx; prevT = t;
        { std::lock_guard<std::mutex> l(g_snapMx); g_snap = s; }
        for (int i = 0; i < 10 && !g_quit; i++) Sleep(100);
    }
}

// ---------------------------------------------------------------- capture (needs administrator rights)
struct FK { uint8_t l[16], r[16]; uint16_t lp, rp; uint8_t v6, proto, out, pad; int32_t pid;
    bool operator<(const FK& o) const { return memcmp(this, &o, sizeof(FK)) < 0; } };
struct FV { uint64_t bytes = 0; int n = 0; };
inline std::map<FK, FV> g_acc;
inline std::vector<std::vector<uint8_t>> g_local;   // local unicast addresses (4 or 16 bytes)
inline const wchar_t* ETW_NAME = L"MatrixSysNetCapture";

inline bool isLocalAddr(const uint8_t* a, int len) {
    if (len == 4 && a[0] == 127) return true;
    static const uint8_t lo6[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
    if (len == 16 && !memcmp(a, lo6, 16)) return true;
    for (auto& x : g_local) if ((int)x.size() == len && !memcmp(x.data(), a, len)) return true;
    return false;
}
inline void account(const uint8_t* s, const uint8_t* d, int alen, uint16_t sp, uint16_t dp, int proto, int outHint, int pid, uint32_t size) {
    // outHint: 1 send, 0 receive, -1 unknown (raw capture: decide by which side is ours)
    bool sl = isLocalAddr(s, alen), dl = isLocalAddr(d, alen);
    if (sl && dl) return;   // loopback traffic is shown as local socket lanes instead
    bool localIsSrc = sl || !dl;
    FK k; memset(&k, 0, sizeof(k));
    memcpy(k.l, localIsSrc ? s : d, alen); memcpy(k.r, localIsSrc ? d : s, alen);
    k.lp = localIsSrc ? sp : dp; k.rp = localIsSrc ? dp : sp; k.v6 = alen == 16; k.proto = (uint8_t)proto;
    k.out = (uint8_t)(outHint < 0 ? (localIsSrc ? 1 : 0) : outHint); k.pid = pid;
    std::lock_guard<std::mutex> l(g_accMx); auto& v = g_acc[k]; v.bytes += size; v.n++;
}
// Microsoft-Windows-Kernel-File: Create gives file object -> name, Read / Write give file object + size.
inline const GUID KF_GUID = { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 } };
inline std::map<std::pair<int, std::string>, std::array<uint64_t, 2>> g_dacc;   // guarded by g_accMx
inline std::unordered_map<uint64_t, std::string> g_foName;                      // guarded by g_accMx
inline std::vector<std::pair<std::wstring, std::wstring>> g_devMap;             // \Device\HarddiskVolume3 -> C:
inline void fileEvent(PEVENT_RECORD r) {
    int id = r->EventHeader.EventDescriptor.Id; const uint8_t* p = (const uint8_t*)r->UserData; int len = r->UserDataLength;
    if (id == 12) {
        if (len < 28) return; uint64_t fo; memcpy(&fo, p + 8, 8);
        for (int o = 16; o + 6 <= len; o += 2) {   // the name is the trailing UTF-16 string and starts with a backslash
            if (p[o] != '\\' || p[o + 1] || !p[o + 2] || p[o + 3]) continue;
            const wchar_t* w = (const wchar_t*)(p + o); int mx = (len - o) / 2, n = 0; while (n < mx && w[n]) n++;
            std::wstring ws(w, n);
            for (auto& [dev, drv] : g_devMap) if (ws.size() > dev.size() && !_wcsnicmp(ws.c_str(), dev.c_str(), dev.size()) && ws[dev.size()] == L'\\') { ws = drv + ws.substr(dev.size()); break; }
            std::lock_guard<std::mutex> l(g_accMx); if (g_foName.size() > 300000) g_foName.clear(); g_foName[fo] = narrow(ws.c_str(), (int)ws.size()); return;
        }
        return;
    }
    if ((id == 15 || id == 16) && len >= 40) {
        uint64_t fo; uint32_t size; memcpy(&fo, p + 16, 8); memcpy(&size, p + 36, 4); if (!size || size > (1u << 30)) return;
        std::lock_guard<std::mutex> l(g_accMx); auto it = g_foName.find(fo);
        auto& v = g_dacc[{ (int)r->EventHeader.ProcessId, it == g_foName.end() ? std::string() : it->second }]; v[id == 16 ? 1 : 0] += size;
    }
}
// Microsoft-Windows-Kernel-Network: one event per TCP/UDP send or receive, already attributed to a PID.
inline void WINAPI etwEvent(PEVENT_RECORD r) {
    if (IsEqualGUID(r->EventHeader.ProviderId, KF_GUID)) { fileEvent(r); return; }
    int id = r->EventHeader.EventDescriptor.Id; const uint8_t* p = (const uint8_t*)r->UserData; int len = r->UserDataLength;
    bool v4 = id == 10 || id == 11 || id == 42 || id == 43, v6 = id == 26 || id == 27 || id == 58 || id == 59;
    if (!v4 && !v6) return;
    int alen = v4 ? 4 : 16; if (len < 8 + 2 * alen + 4) return;
    uint32_t pid, size; memcpy(&pid, p, 4); memcpy(&size, p + 4, 4);
    const uint8_t* d = p + 8; const uint8_t* s = d + alen; uint16_t dp, sp; memcpy(&dp, s + alen, 2); memcpy(&sp, s + alen + 2, 2);
    bool send = id == 10 || id == 26 || id == 42 || id == 58;
    account(s, d, alen, ntohs(sp), ntohs(dp), (id == 42 || id == 43 || id == 58 || id == 59) ? 17 : 6, send ? 1 : 0, (int)pid, size);
}
inline void rawSniff(std::vector<uint8_t> ip, bool payloadOnly) {
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP); if (s == INVALID_SOCKET) return;
    sockaddr_in a{}; a.sin_family = AF_INET; memcpy(&a.sin_addr, ip.data(), 4);
    DWORD on = 1, out = 0; BOOL hdr = TRUE;
    if (bind(s, (sockaddr*)&a, sizeof(a)) || setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&hdr, sizeof(hdr)) || WSAIoctl(s, SIO_RCVALL, &on, sizeof(on), nullptr, 0, &out, nullptr, nullptr)) { closesocket(s); return; }
    if (!payloadOnly) g_capMode = 2;
    std::vector<uint8_t> b(65536);
    while (!g_quit) {
        int n = recv(s, (char*)b.data(), (int)b.size(), 0); if (n < 20 || (b[0] >> 4) != 4) continue;
        int ihl = (b[0] & 15) * 4, proto = b[9]; uint16_t tl = (uint16_t)((b[2] << 8) | b[3]); if (!tl) tl = (uint16_t)n;
        uint16_t sp = 0, dp = 0; if ((proto == 6 || proto == 17) && n >= ihl + 4) { sp = (uint16_t)((b[ihl] << 8) | b[ihl + 1]); dp = (uint16_t)((b[ihl + 2] << 8) | b[ihl + 3]); }
        if (!payloadOnly) account(&b[12], &b[16], 4, sp, dp, proto, -1, -1, tl);
        if (g_wantPkts) {
            Pkt p{}; p.t = nowSec(); p.pid = -1; p.proto = (uint8_t)proto; bool out = !memcmp(&b[12], ip.data(), 4); p.out = out;
            memcpy(&p.lip, &b[out ? 12 : 16], 4); memcpy(&p.rip, &b[out ? 16 : 12], 4); p.lp = out ? sp : dp; p.rp = out ? dp : sp; p.len = tl; p.cap = (uint16_t)std::min(n, 512); memcpy(p.data, b.data(), p.cap);
            { std::lock_guard<std::mutex> l(g_tblMx);
                if (proto == 6) { auto e = g_tcpExact.find((uint64_t(p.lp) << 48) | (uint64_t(p.rp) << 32) | p.rip); if (e != g_tcpExact.end()) p.pid = e->second; else { auto q = g_tcpPort.find(p.lp); if (q != g_tcpPort.end()) p.pid = q->second; } }
                else if (proto == 17) { auto q = g_udpPort.find(p.lp); if (q != g_udpPort.end()) p.pid = q->second; } }
            std::lock_guard<std::mutex> l(g_pkMx); g_pkts.push_back(p); if (g_pkts.size() > 3000) g_pkts.pop_front();
        }
    }
}
inline void captureThread() {
    g_local.clear(); g_devMap.clear();
    for (wchar_t d = L'A'; d <= L'Z'; d++) { wchar_t drv[3] = { d, L':', 0 }, dev[512]; if (QueryDosDeviceW(drv, dev, 512)) g_devMap.push_back({ dev, drv }); }
    // local addresses, to tell which end of a flow is this machine
    ULONG sz = 1 << 16; std::vector<BYTE> ab(sz);
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, (IP_ADAPTER_ADDRESSES*)ab.data(), &sz) == NO_ERROR)
        for (auto* a = (IP_ADAPTER_ADDRESSES*)ab.data(); a; a = a->Next) for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            auto* sa = u->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) { auto* p = (uint8_t*)&((sockaddr_in*)sa)->sin_addr; g_local.emplace_back(p, p + 4); }
            else if (sa->sa_family == AF_INET6) { auto* p = (uint8_t*)&((sockaddr_in6*)sa)->sin6_addr; g_local.emplace_back(p, p + 16); }
        }
    struct Props { EVENT_TRACE_PROPERTIES p; wchar_t name[128]; };
    auto init = [](Props& s) { memset(&s, 0, sizeof(s)); s.p.Wnode.BufferSize = sizeof(s); s.p.Wnode.Flags = WNODE_FLAG_TRACED_GUID; s.p.Wnode.ClientContext = 1; s.p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE; s.p.LoggerNameOffset = offsetof(Props, name); };
    static const GUID KN = { 0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 } };
    Props st; init(st); ControlTraceW(0, ETW_NAME, &st.p, EVENT_TRACE_CONTROL_STOP);   // clear a session left by a crash
    Props pr; init(pr); TRACEHANDLE h = 0;
    if (StartTraceW(&h, ETW_NAME, &pr.p) == ERROR_SUCCESS && EnableTraceEx2(h, &KN, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x30 /* IPv4 | IPv6 */, 0, 0, nullptr) == ERROR_SUCCESS) {
        EnableTraceEx2(h, &KF_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x390 /* filename | create | read | write */, 0, 0, nullptr);
        EVENT_TRACE_LOGFILEW lf{}; lf.LoggerName = (LPWSTR)ETW_NAME; lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; lf.EventRecordCallback = etwEvent;
        TRACEHANDLE th = OpenTraceW(&lf);
        if (th != INVALID_PROCESSTRACE_HANDLE) { g_capMode = 1;
            if (g_allowPayload) for (auto& ip : g_local) if (ip.size() == 4 && ip[0] != 127) std::thread(rawSniff, ip, true).detach();   // contents for the packet viewer
            ProcessTrace(&th, 1, nullptr, nullptr); CloseTrace(th); g_capMode = 0; return; }
    }
    // fallback: raw IPv4 sockets, PIDs resolved from the socket tables
    for (auto& ip : g_local) if (ip.size() == 4 && ip[0] != 127) std::thread(rawSniff, ip, false).detach();
}
inline void stopCapture() {
    struct Props { EVENT_TRACE_PROPERTIES p; wchar_t name[128]; } s; memset(&s, 0, sizeof(s));
    s.p.Wnode.BufferSize = sizeof(s); s.p.LoggerNameOffset = offsetof(Props, name);
    if (g_capMode == 1) ControlTraceW(0, ETW_NAME, &s.p, EVENT_TRACE_CONTROL_STOP);
}
// Every 200 ms, turn the accumulated per-flow counters into bundles for the renderer.
inline void flushThread() {
    while (!g_quit) {
        Sleep(200);
        std::map<FK, FV> acc; std::map<std::pair<int, std::string>, std::array<uint64_t, 2>> dacc;
        { std::lock_guard<std::mutex> l(g_accMx); acc.swap(g_acc); dacc.swap(g_dacc); }
        if (!dacc.empty()) { std::lock_guard<std::mutex> l(g_flowMx); if (g_disk.size() < 20000) for (auto& [k, v] : dacc) g_disk.push_back({ k.first, k.second, v[0], v[1], 0 }); }
        if (acc.empty()) continue;
        std::vector<Flow> out; double t = nowSec();
        { std::lock_guard<std::mutex> l(g_tblMx);
            for (auto& [k, v] : acc) {
                Flow f; f.pid = k.pid; f.proto = k.proto; f.lp = k.lp; f.rp = k.rp; f.out = k.out != 0; f.bytes = v.bytes; f.n = v.n; f.t = t;
                f.lip = k.v6 ? ip6s(k.l) : ip4s(k.l); f.rip = k.v6 ? ip6s(k.r) : ip4s(k.r);
                if (f.pid < 0 && !k.v6) {
                    uint32_t ra; memcpy(&ra, k.r, 4);
                    if (k.proto == 6) { auto e = g_tcpExact.find((uint64_t(k.lp) << 48) | (uint64_t(k.rp) << 32) | ra); if (e != g_tcpExact.end()) f.pid = e->second; else { auto p = g_tcpPort.find(k.lp); if (p != g_tcpPort.end()) f.pid = p->second; } }
                    else if (k.proto == 17) { auto p = g_udpPort.find(k.lp); if (p != g_udpPort.end()) f.pid = p->second; }
                }
                out.push_back(std::move(f));
            } }
        std::lock_guard<std::mutex> l(g_flowMx);
        if (g_flows.size() < 20000) g_flows.insert(g_flows.end(), out.begin(), out.end());
    }
}
