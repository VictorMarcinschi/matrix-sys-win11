// trace.h - active trace of the route and the conversation between this computer and a target.
// Steps: name resolution (raw DNS over UDP to the configured server), hop discovery (ICMP echo with rising TTL),
// then the chosen protocol: ICMP echo, TCP connect + greeting, HTTP, HTTPS (Schannel), or DNS record queries.
// Every request and every response is recorded as a message with decoded fields and the bytes that were seen.
#pragma once
#include "data.h"
#include <icmpapi.h>
#include <wincrypt.h>
#include <functional>
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <security.h>
#include <schannel.h>
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
using std::string; using std::vector;

enum { TP_ICMP, TP_TCP, TP_HTTP, TP_HTTPS, TP_DNS };
enum { TK_DNSQ, TK_DNSR, TK_PROBE, TK_TTLX, TK_ECHOQ, TK_ECHOR, TK_SYN, TK_SYNACK, TK_REFUSED, TK_TLSC, TK_TLSS, TK_HTTPQ, TK_HTTPR, TK_BANNER, TK_FIN, TK_LOST, TK_INFO };
enum { TN_ME, TN_DNS, TN_HOP, TN_SILENT, TN_TARGET };
typedef vector<std::pair<string, string>> TrFields;
struct TrMsg { double t = 0, ms = -1; int from = 0, to = 0, kind = 0, pair = -1, phase = 0; bool out = true; string title, body, url, page, ctype, csp; TrFields f; /* url, page, ctype, csp: an HTML response kept whole for the rendered view */ vector<uint8_t> raw; size_t rawTotal = 0; };
struct TrNode { int kind = 0, ttl = 0; string ip, name, note; double ms = -1; };
struct Trace { int ver = 0, proto = 0, port = 0; bool running = false; bool live = false; string input, host, path, status, err; double took = 0; vector<TrNode> nodes; vector<TrMsg> msgs; vector<int> chain; vector<std::pair<int, int>> links; };
inline Trace g_tr; inline std::mutex g_trMx; inline std::atomic<int> g_trGen{ 0 };

// Step-by-step runs: the trace thread waits at a gate before every real network step until the view hands it a permit.
inline std::atomic<int> g_trPermits{ 0 }; inline std::atomic<bool> g_trWaiting{ false };
struct TrRun { int gen; double t0; bool live = false; mutable double held = 0; };   // held: time spent waiting at the gate, kept out of the timings
inline bool trLive(const TrRun& r) { return g_trGen == r.gen && !g_quit; }
inline double trT(const TrRun& r) { return nowSec() - r.t0 - r.held; }
inline void trGate(const TrRun& r) {
    if (!r.live) return; double t = nowSec();
    while (trLive(r)) { g_trWaiting = true; int p = g_trPermits.load(); if (p > 0 && g_trPermits.compare_exchange_strong(p, p - 1)) break; Sleep(12); }
    g_trWaiting = false; r.held += nowSec() - t;
}
inline void trSet(const TrRun& r, const std::function<void(Trace&)>& fn) { std::lock_guard<std::mutex> l(g_trMx); if (g_trGen != r.gen) return; fn(g_tr); g_tr.ver++; }
inline int trAddNode(const TrRun& r, int kind, const string& ip, const string& name = "", int ttl = 0) {
    std::lock_guard<std::mutex> l(g_trMx); if (g_trGen != r.gen) return 0;
    if (kind != TN_HOP && kind != TN_SILENT) for (size_t i = 0; i < g_tr.nodes.size(); i++) if (g_tr.nodes[i].ip == ip && (g_tr.nodes[i].kind == TN_DNS || g_tr.nodes[i].kind == TN_TARGET) && !ip.empty()) return (int)i;
    TrNode n; n.kind = kind; n.ip = ip; n.name = name; n.ttl = ttl; g_tr.nodes.push_back(n); g_tr.ver++; return (int)g_tr.nodes.size() - 1;
}
inline int trAddMsg(const TrRun& r, TrMsg m) {
    std::lock_guard<std::mutex> l(g_trMx); if (g_trGen != r.gen) return -1;
    m.rawTotal = m.raw.size(); if (m.raw.size() > 4096) m.raw.resize(4096); g_tr.msgs.push_back(std::move(m)); g_tr.ver++; return (int)g_tr.msgs.size() - 1;
}
inline TrMsg trMk(double t, int from, int to, int kind, int phase, bool out, const string& title, int pair = -1, double ms = -1) {
    TrMsg m; m.t = t; m.from = from; m.to = to; m.kind = kind; m.phase = phase; m.out = out; m.title = title; m.pair = pair; m.ms = ms; return m;
}
inline void trLink(const TrRun& r, int a, int b) { trSet(r, [&](Trace& t) { for (auto& l : t.links) if (l.first == a && l.second == b) return; for (int c : t.chain) if (c == b && b != 0) return; t.links.push_back({ a, b }); }); }
inline string trLower(string s) { for (auto& c : s) c = (char)tolower((unsigned char)c); return s; }
inline string trBytes(double b) { char s[32]; if (b < 1024) snprintf(s, 32, "%.0f bytes", b); else if (b < 1048576) snprintf(s, 32, "%.1f KB", b / 1024); else snprintf(s, 32, "%.1f MB", b / 1048576); return s; }
inline string trMs(double ms) { char s[32]; if (ms < 1) return "<1 ms"; snprintf(s, 32, ms < 10 ? "%.1f ms" : "%.0f ms", ms); return s; }
inline string trHex(unsigned v, int w = 4) { char s[16]; snprintf(s, 16, "0x%0*X", w, v); return s; }
inline string trText(const uint8_t* d, size_t n) {   // printable rendering of bytes for a preview
    string o; o.reserve(n); for (size_t i = 0; i < n; i++) { uint8_t c = d[i]; if (c == '\r') continue; o += (c == '\n' || c == '\t' || c >= 32) && c != 127 ? (char)c : '.'; } return o;
}

// ---------------------------------------------------------------- what the user typed
struct TrTarget { int proto = TP_ICMP, port = 0; string host, path = "/", server; };
// protocol implied by a scheme prefix such as "https://", or -1
inline int trSchemeProto(const string& in, int* port = nullptr) {
    size_t p = in.find("://"); if (p == string::npos || p == 0) return -1; string s = trLower(in.substr(0, p)); size_t b = s.find_first_not_of(" \t"); if (b == string::npos) return -1; s = s.substr(b);
    static const struct { const char* s; int proto, port; } T[] = { {"http",TP_HTTP,80},{"ws",TP_HTTP,80},{"https",TP_HTTPS,443},{"wss",TP_HTTPS,443},{"tcp",TP_TCP,0},{"icmp",TP_ICMP,0},{"ping",TP_ICMP,0},{"dns",TP_DNS,53},
        {"ssh",TP_TCP,22},{"sftp",TP_TCP,22},{"ftp",TP_TCP,21},{"smtp",TP_TCP,25},{"telnet",TP_TCP,23},{"imap",TP_TCP,143},{"pop3",TP_TCP,110},{"rdp",TP_TCP,3389},{"mysql",TP_TCP,3306},{"redis",TP_TCP,6379},{"vnc",TP_TCP,5900} };
    for (auto& t : T) if (s == t.s) { if (port) *port = t.port; return t.proto; }
    return -1;
}
inline bool trParse(string in, int protoSel, TrTarget& o, string& err) {
    size_t b = in.find_first_not_of(" \t"), e = in.find_last_not_of(" \t"); if (b == string::npos) { err = "Type a host name, an IPv4 address or a URL."; return false; } in = in.substr(b, e - b + 1);
    int defPort = 0, sp = trSchemeProto(in, &defPort); o.proto = sp >= 0 ? sp : protoSel; size_t sc = in.find("://");
    if (sc != string::npos) { if (sp < 0) { err = "Unknown scheme \"" + in.substr(0, sc) + "\". Known: http, https, tcp, icmp, dns, ssh, ftp, smtp."; return false; } in = in.substr(sc + 3); }
    if (o.proto == TP_DNS) {   // name@server, or dns://server/name
        size_t at = in.find('@'), sl = in.find('/');
        if (at != string::npos) { o.server = trLower(in.substr(at + 1)); in = in.substr(0, at); }
        else if (sl != string::npos && sl + 1 < in.size()) { o.server = trLower(in.substr(0, sl)); in = in.substr(sl + 1); }
        while (!in.empty() && (in.back() == '/' || in.back() == '.')) in.pop_back();
    } else {
        size_t sl = in.find_first_of("/?#"); if (sl != string::npos) { o.path = in[sl] == '/' ? in.substr(sl) : "/" + in.substr(sl); in = in.substr(0, sl); }
        size_t hs = o.path.find('#'); if (hs != string::npos) o.path = o.path.substr(0, hs);
        size_t at = in.rfind('@'); if (at != string::npos) in = in.substr(at + 1);
    }
    if (!in.empty() && in[0] == '[') { err = "IPv6 targets are not supported yet; use a name or an IPv4 address."; return false; }
    size_t col = in.rfind(':'); if (col != string::npos && col + 1 < in.size() && in.find_first_not_of("0123456789", col + 1) == string::npos && in.find(':') == col) { o.port = atoi(in.c_str() + col + 1); in = in.substr(0, col); }
    else if (col != string::npos) { err = "IPv6 targets are not supported yet; use a name or an IPv4 address."; return false; }
    o.host = trLower(in); while (!o.host.empty() && o.host.back() == '.') o.host.pop_back();
    if (o.host.empty()) { err = "Type a host name, an IPv4 address or a URL."; return false; }
    for (unsigned char c : o.host) if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c >= 128)) { err = string("The host name contains a character that is not allowed: '") + (char)c + "'."; return false; }
    if (o.port <= 0 || o.port > 65535) o.port = defPort ? defPort : o.proto == TP_HTTPS ? 443 : o.proto == TP_DNS ? 53 : 80;
    return true;
}

// ---------------------------------------------------------------- DNS wire format
inline const char* dnsTypeName(int t) { switch (t) { case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA"; case 12: return "PTR"; case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"; case 41: return "OPT"; case 65: return "HTTPS"; } static thread_local char b[16]; snprintf(b, 16, "TYPE%d", t); return b; }
inline const char* dnsRcode(int r) { switch (r) { case 0: return "NOERROR"; case 1: return "FORMERR (malformed query)"; case 2: return "SERVFAIL (server failure)"; case 3: return "NXDOMAIN (no such name)"; case 4: return "NOTIMP (not implemented)"; case 5: return "REFUSED"; } return "error"; }
inline vector<uint8_t> dnsBuild(uint16_t id, const string& name, uint16_t type) {
    vector<uint8_t> d = { (uint8_t)(id >> 8), (uint8_t)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }; size_t s = 0;
    while (s < name.size()) { size_t e = name.find('.', s); if (e == string::npos) e = name.size(); size_t n = std::min<size_t>(63, e - s); if (n) { d.push_back((uint8_t)n); d.insert(d.end(), name.begin() + s, name.begin() + s + n); } s = e + 1; }
    d.push_back(0); d.push_back((uint8_t)(type >> 8)); d.push_back((uint8_t)type); d.push_back(0); d.push_back(1); return d;
}
inline bool dnsReadName(const vector<uint8_t>& d, size_t& off, string& out) {   // follows compression pointers
    size_t p = off; bool jumped = false; int guard = 0; out.clear();
    while (p < d.size() && guard++ < 128) { uint8_t l = d[p];
        if (!l) { if (!jumped) off = p + 1; if (out.empty()) out = "."; return true; }
        if ((l & 0xC0) == 0xC0) { if (p + 1 >= d.size()) return false; if (!jumped) off = p + 2; jumped = true; p = ((size_t)(l & 0x3F) << 8) | d[p + 1]; continue; }
        if (p + 1 + l > d.size()) return false; if (!out.empty()) out += '.'; out.append((const char*)&d[p + 1], l); p += 1 + (size_t)l; }
    return false;
}
struct DnsRR { string name, val; int type = 0, sec = 0; uint32_t ttl = 0; };
struct DnsMsg { int id = 0, rcode = 0, qtype = 0; bool aa = false, tc = false, ra = false; string qname; vector<DnsRR> rr; };
inline bool dnsParse(const vector<uint8_t>& d, DnsMsg& m) {
    if (d.size() < 12) return false; auto be = [&](size_t o) { return (int)((d[o] << 8) | d[o + 1]); };
    m.id = be(0); m.aa = (d[2] & 4) != 0; m.tc = (d[2] & 2) != 0; m.ra = (d[3] & 0x80) != 0; m.rcode = d[3] & 15; int qd = be(4), cnt[3] = { be(6), be(8), be(10) }; size_t o = 12;
    for (int i = 0; i < qd; i++) { if (!dnsReadName(d, o, m.qname) || o + 4 > d.size()) return false; m.qtype = be(o); o += 4; }
    for (int sec = 0; sec < 3; sec++) for (int i = 0; i < cnt[sec]; i++) { DnsRR r; r.sec = sec; if (!dnsReadName(d, o, r.name) || o + 10 > d.size()) return false;
        r.type = be(o); r.ttl = ((uint32_t)be(o + 4) << 16) | (uint32_t)be(o + 6); size_t len = (size_t)be(o + 8); o += 10; if (o + len > d.size()) return false; size_t ro = o; char b[80] = "";
        switch (r.type) {
        case 1: if (len == 4) { inet_ntop(AF_INET, &d[ro], b, 80); r.val = b; } break;
        case 28: if (len == 16) { inet_ntop(AF_INET6, &d[ro], b, 80); r.val = b; } break;
        case 2: case 5: case 12: { size_t p = ro; dnsReadName(d, p, r.val); } break;
        case 15: if (len > 2) { size_t p = ro + 2; string n; dnsReadName(d, p, n); r.val = n + " (preference " + std::to_string(be(ro)) + ")"; } break;
        case 16: { size_t p = ro; while (p < ro + len) { size_t l = d[p++]; if (p + l > ro + len) break; if (!r.val.empty()) r.val += ' '; r.val += '"' + trText(&d[p], l) + '"'; p += l; } } break;
        case 6: { size_t p = ro; string mn, rn; if (dnsReadName(d, p, mn) && dnsReadName(d, p, rn) && p + 20 <= d.size()) r.val = "primary " + mn + ", contact " + rn + ", serial " + std::to_string(((uint32_t)be(p) << 16) | (uint32_t)be(p + 2)); } break;
        }
        if (r.val.empty()) r.val = std::to_string(len) + " bytes of data"; o = ro + len; m.rr.push_back(r); }
    return true;
}
inline string saStr(const sockaddr_storage& s) { char b[80] = ""; if (s.ss_family == AF_INET) inet_ntop(AF_INET, &((const sockaddr_in*)&s)->sin_addr, b, 80); else if (s.ss_family == AF_INET6) inet_ntop(AF_INET6, &((const sockaddr_in6*)&s)->sin6_addr, b, 80); return b; }
// DNS servers of the active adapters: those on an adapter with a gateway first, IPv4 before IPv6
inline vector<sockaddr_storage> trDnsServers() {
    vector<sockaddr_storage> a, b, c; ULONG n = 32768; vector<uint8_t> buf(n); const ULONG fl = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, fl, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &n); if (rc == ERROR_BUFFER_OVERFLOW) { buf.resize(n); rc = GetAdaptersAddresses(AF_UNSPEC, fl, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &n); }
    if (rc != NO_ERROR) return a;
    for (auto* ad = (IP_ADAPTER_ADDRESSES*)buf.data(); ad; ad = ad->Next) { if (ad->OperStatus != IfOperStatusUp || ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* d = ad->FirstDnsServerAddress; d; d = d->Next) { sockaddr_storage ss{}; memcpy(&ss, d->Address.lpSockaddr, std::min<size_t>(sizeof(ss), (size_t)d->Address.iSockaddrLength));
            if (ss.ss_family == AF_INET) (ad->FirstGatewayAddress ? a : b).push_back(ss);
            else if (ss.ss_family == AF_INET6) { const uint8_t* x = ((sockaddr_in6*)&ss)->sin6_addr.u.Byte; if (x[0] == 0xfe && (x[1] & 0xc0) == 0xc0) continue; c.push_back(ss); } } }   // fec0:: entries are placeholders
    a.insert(a.end(), b.begin(), b.end()); a.insert(a.end(), c.begin(), c.end());
    vector<sockaddr_storage> out; for (auto& s : a) { bool dup = false; for (auto& o : out) if (saStr(o) == saStr(s)) dup = true; if (!dup) out.push_back(s); }
    return out;
}
// one question to one server over UDP; records the query, the answer (decoded) or the silence
inline bool trDnsQuery(const TrRun& r, int node, const sockaddr_storage& srv, const string& name, int type, int phase, DnsMsg& out) {
    static std::atomic<uint16_t> idc{ (uint16_t)GetTickCount() }; SOCKET s = socket(srv.ss_family, SOCK_DGRAM, IPPROTO_UDP); if (s == INVALID_SOCKET) return false;
    sockaddr_storage to = srv; int tolen = srv.ss_family == AF_INET ? (int)sizeof(sockaddr_in) : (int)sizeof(sockaddr_in6); if (srv.ss_family == AF_INET) ((sockaddr_in*)&to)->sin_port = htons(53); else ((sockaddr_in6*)&to)->sin6_port = htons(53);
    string sv = saStr(srv); bool ok = false;
    for (int attempt = 0; attempt < 2 && trLive(r) && !ok; attempt++) {
        trGate(r); uint16_t id = ++idc; vector<uint8_t> q = dnsBuild(id, name, (uint16_t)type); double t = trT(r);
        TrMsg m = trMk(t, 0, node, TK_DNSQ, phase, true, string("DNS query: ") + name + " " + dnsTypeName(type) + "?");
        m.f = { { "question", name + "  type " + dnsTypeName(type) + "  class IN" }, { "transaction id", trHex(id) }, { "flags", "standard query, recursion desired" }, { "sent to", sv + " port 53 over UDP" }, { "size", trBytes((double)q.size()) } }; m.raw = q; int qi = trAddMsg(r, m);
        sendto(s, (const char*)q.data(), (int)q.size(), 0, (sockaddr*)&to, tolen);
        fd_set fs; FD_ZERO(&fs); FD_SET(s, &fs); timeval tv{ 2, 0 }; vector<uint8_t> b(4096); int n = select(0, &fs, nullptr, nullptr, &tv) > 0 ? recvfrom(s, (char*)b.data(), 4096, 0, nullptr, nullptr) : -1; double t2 = trT(r);
        DnsMsg dm; if (n >= 12) { b.resize(n); if (dnsParse(b, dm) && dm.id == id) {
            int na = 0; string first; for (auto& x : dm.rr) if (x.sec == 0) { if (!na || (x.type == type && first.find(dnsTypeName(type)) != 0)) first = string(dnsTypeName(x.type)) + " " + x.val; na++; }
            TrMsg a = trMk(t2, node, 0, TK_DNSR, phase, false, "", qi, (t2 - t) * 1000);
            a.title = dm.rcode ? string("DNS answer: ") + dnsRcode(dm.rcode) : na ? "DNS answer: " + first + (na > 1 ? "  (+" + std::to_string(na - 1) + " more)" : "") : string("DNS answer: no ") + dnsTypeName(type) + " record for this name";
            a.f.push_back({ "result", string(dnsRcode(dm.rcode)) + " \xC2\xB7 " + std::to_string(na) + " answer record(s) \xC2\xB7 " + trMs(a.ms) });
            a.f.push_back({ "flags", string(dm.aa ? "authoritative answer" : "non-authoritative (from a resolver's cache or recursion)") + (dm.ra ? ", recursion available" : "") + (dm.tc ? ", TRUNCATED (too large for UDP)" : "") });
            static const char* secN[] = { "answer", "authority", "additional" };
            for (auto& x : dm.rr) if (x.type != 41) a.f.push_back({ string(secN[x.sec]) + " " + dnsTypeName(x.type), x.name + " \xE2\x86\x92 " + x.val + "   (valid " + std::to_string(x.ttl) + " s)" });
            a.f.push_back({ "size", trBytes((double)b.size()) }); a.raw = b; trAddMsg(r, a); out = dm; ok = true; } }
        if (!ok) { TrMsg l = trMk(t2, node, node, TK_LOST, phase, false, "No DNS answer from " + sv + " within 2 s", qi); l.f = { { "what happened", "The query was sent but nothing came back. The server may be down, or UDP port 53 is blocked." } }; trAddMsg(r, l); }
    }
    closesocket(s); return ok;
}
// name -> IPv4 address. Asks the configured DNS servers directly so that the exchange can be shown; falls back to the Windows resolver.
inline bool trResolve(const TrRun& r, const string& host, int phase, uint32_t& ip4, string& err, bool alsoV6 = true) {
    in_addr lit; if (inet_pton(AF_INET, host.c_str(), &lit) == 1) { ip4 = lit.s_addr; return true; }
    auto servers = trDnsServers(); int tried = 0;
    for (auto& srv : servers) { if (tried++ >= 2 || !trLive(r)) break; int node = trAddNode(r, TN_DNS, saStr(srv), "DNS server"); trLink(r, 0, node);
        DnsMsg dm; if (!trDnsQuery(r, node, srv, host, 1, phase, dm)) continue;
        bool got = false; for (auto& x : dm.rr) if (x.sec == 0 && x.type == 1 && !got) { in_addr a; if (inet_pton(AF_INET, x.val.c_str(), &a) == 1) { ip4 = a.s_addr; got = true; } }
        if (alsoV6 && dm.rcode == 0) { DnsMsg d6; trDnsQuery(r, node, srv, host, 28, phase, d6); }
        if (got) return true;
        if (dm.rcode == 3) { err = "The name " + host + " does not exist (NXDOMAIN)."; return false; }
        if (dm.rcode == 0) { err = host + " has no IPv4 address (no A record). IPv6-only targets are not supported yet."; return false; }
    }
    // the Windows resolver may know more (hosts file, local names, encrypted DNS)
    int node = trAddNode(r, TN_DNS, "system", "Windows resolver"); trLink(r, 0, node); trGate(r); double t = trT(r);
    int qi = trAddMsg(r, trMk(t, 0, node, TK_DNSQ, phase, true, "Ask Windows to resolve " + host));
    addrinfo hints{}, *res = nullptr; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res); double t2 = trT(r);
    if (rc == 0 && res) { ip4 = ((sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);
        TrMsg a = trMk(t2, node, 0, TK_DNSR, phase, false, "Windows resolver: " + host + " is " + ip4s(&ip4), qi, (t2 - t) * 1000);
        a.f = { { "address", ip4s(&ip4) }, { "note", "Answered by the system resolver (its cache, the hosts file, a local name service or encrypted DNS). The exchange behind it is not visible to this trace." } }; trAddMsg(r, a); return true; }
    trAddMsg(r, trMk(t2, node, node, TK_LOST, phase, false, "Windows could not resolve " + host, qi)); err = "The name " + host + " could not be resolved."; return false;
}

// ---------------------------------------------------------------- route (ICMP echo with a limited TTL)
struct TrHop { DWORD status = 0xFFFFFFFF; uint32_t addr = 0; double ms = -1; int rttl = 0; bool got = false; };
// `exact`: the caller runs one probe at a time, so the wall-clock time is the round trip. Parallel probes use the stack's own (whole-millisecond) figure.
inline TrHop trProbe(uint32_t dst, int ttl, DWORD timeout, bool exact = false) {
    TrHop h; HANDLE ic = IcmpCreateFile(); if (ic == INVALID_HANDLE_VALUE) return h; char data[32]; memcpy(data, "MatrixSys route trace probe ....", 32);
    IP_OPTION_INFORMATION o{}; o.Ttl = (UCHAR)ttl; BYTE buf[sizeof(ICMP_ECHO_REPLY) + 32 + 64] = {}; double t = nowSec();
    DWORD n = IcmpSendEcho(ic, dst, data, 32, &o, buf, sizeof(buf), timeout); double el = (nowSec() - t) * 1000; ICMP_ECHO_REPLY* rp = (ICMP_ECHO_REPLY*)buf;
    if (n > 0 || (rp->Address && rp->Status)) { h.got = true; h.status = rp->Status; h.addr = rp->Address; h.ms = exact ? el : rp->RoundTripTime > 0 ? (double)rp->RoundTripTime : std::min(el, .9); h.rttl = rp->Options.Ttl; } else h.status = GetLastError();
    IcmpCloseHandle(ic); return h;
}
inline string icmpText(DWORD s) { switch (s) { case 0: return "echo reply"; case 11002: return "destination network unreachable"; case 11003: return "destination host unreachable"; case 11004: return "destination protocol unreachable"; case 11005: return "destination port unreachable"; case 11010: return "no answer (timed out)"; case 11013: return "TTL expired in transit"; case 11018: return "bad destination"; } return "ICMP status " + std::to_string(s); }
// Discovers the hops to dst; each joins the chain as it is found, then the node that stands for dst.
// Full speed: all probes leave in one burst. Step by step: one probe at a time, each waiting at the gate.
inline void trRoute(const TrRun& r, uint32_t dst, int endNode) {
    const int MAXH = 30; string dsts = ip4s(&dst); bool endInChain = false, unreachable = false;
    auto join = [&](int node) { trSet(r, [&](Trace& t) { t.chain.push_back(node); for (size_t i = 0; i < t.links.size();) { if (t.links[i].second == node) t.links.erase(t.links.begin() + i); else i++; } }); };
    auto emit = [&](int ttl, const TrHop& h, double tq) { bool isEnd = h.got && h.status == 0; string hip = h.got ? ip4s(&h.addr) : "";
        int node = isEnd ? endNode : h.got ? trAddNode(r, TN_HOP, hip, "", ttl) : trAddNode(r, TN_SILENT, "", "", ttl); join(node);
        TrMsg q = trMk(tq, 0, node, TK_PROBE, 1, true, "ICMP echo request with TTL " + std::to_string(ttl) + (isEnd ? " \xE2\x80\x94 reaches the target" : ""));
        q.f = { { "destination", dsts }, { "TTL (hop limit)", std::to_string(ttl) + " \xE2\x80\x94 the packet is dropped by hop " + std::to_string(ttl) + ", which reports back" }, { "payload", "32 bytes" } }; int qi = trAddMsg(r, q);
        if (h.got) { TrMsg a = trMk(tq + h.ms / 1000, node, 0, isEnd ? TK_ECHOR : TK_TTLX, 1, false, "", qi, h.ms);
            a.title = isEnd ? "Echo reply from the target " + hip + " in " + trMs(h.ms) : h.status == 11013 ? "Hop " + std::to_string(ttl) + ": " + hip + " answers \"TTL exceeded\" in " + trMs(h.ms) : "Hop " + std::to_string(ttl) + ": " + hip + " answers \"" + icmpText(h.status) + "\"";
            a.f = { { "from", hip }, { "ICMP message", icmpText(h.status) }, { "round trip", trMs(h.ms) } }; if (isEnd) a.f.push_back({ "TTL of the reply", std::to_string(h.rttl) }); trAddMsg(r, a);
            trSet(r, [&](Trace& t) { t.nodes[node].ms = h.ms; t.nodes[node].ttl = ttl; if (!isEnd && h.status != 11013) t.nodes[node].note = "reports: " + icmpText(h.status); }); }
        else { TrMsg l = trMk(tq + 1.5, node, node, TK_LOST, 1, false, "Hop " + std::to_string(ttl) + " does not answer (2 probes, 1.5 s each)", qi); l.f = { { "what this means", "Many routers forward traffic but are configured not to send ICMP errors. The path continues through it." } }; trAddMsg(r, l); }
        if (isEnd) endInChain = true; if (h.got && h.status >= 11002 && h.status <= 11005) unreachable = true; };
    if (r.live) {
        int silent = 0; for (int ttl = 1; ttl <= MAXH && !endInChain && !unreachable && silent < 5; ttl++) { trGate(r); if (!trLive(r)) return; double tq = trT(r); TrHop h = trProbe(dst, ttl, 1500, true); if (!h.got) h = trProbe(dst, ttl, 1500, true);
            silent = h.got ? 0 : silent + 1; emit(ttl, h, tq); }
    } else {
        vector<TrHop> hops(MAXH + 1); double tb = trT(r);
        { vector<std::thread> th; for (int ttl = 1; ttl <= MAXH; ttl++) { th.emplace_back([&hops, dst, ttl] { hops[ttl] = trProbe(dst, ttl, 1500); }); Sleep(10); } for (auto& t : th) t.join(); }   // a short gap between probes keeps their timings honest
        if (!trLive(r)) return;
        int reached = 0, stop = 0, lastGot = 0; for (int ttl = 1; ttl <= MAXH; ttl++) { const TrHop& h = hops[ttl]; if (!h.got) continue; lastGot = ttl; if (h.status == 0 && !reached) reached = ttl; if (h.status >= 11002 && h.status <= 11005 && !stop) stop = ttl; }
        int last = reached ? reached : stop ? stop : lastGot; if (stop && reached && stop < reached) last = stop;
        { vector<std::thread> th; for (int ttl = 1; ttl < last; ttl++) if (!hops[ttl].got) th.emplace_back([&hops, dst, ttl] { hops[ttl] = trProbe(dst, ttl, 1500); }); for (auto& t : th) t.join(); }   // silent hops get a second chance
        if (!trLive(r)) return;
        for (int ttl = 1; ttl <= last && !endInChain; ttl++) emit(ttl, hops[ttl], tb + (ttl - 1) * .01);
    }
    if (!trLive(r)) return;
    if (!endInChain) { join(endNode); trSet(r, [&](Trace& t) { t.nodes[endNode].note = unreachable ? "A router on the way reports the destination as unreachable." : "Does not answer ICMP echo. The hops after the last reply are unknown; the target may still accept other protocols."; }); }
}

// ---------------------------------------------------------------- TCP
inline int sockRead(SOCKET s, vector<uint8_t>& to, int timeoutMs) {   // >0 bytes appended, 0 closed by the peer, -1 nothing within the timeout
    fd_set f; FD_ZERO(&f); FD_SET(s, &f); timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 }; if (select(0, &f, nullptr, nullptr, &tv) <= 0) return -1;
    char b[16384]; int n = recv(s, b, sizeof(b), 0); if (n > 0) to.insert(to.end(), b, b + n); return n <= 0 ? 0 : n;
}
inline bool sockWrite(SOCKET s, const uint8_t* d, size_t n) { while (n) { int k = send(s, (const char*)d, (int)std::min<size_t>(n, 65536), 0); if (k <= 0) return false; d += k; n -= (size_t)k; } return true; }
inline SOCKET trConnect(const TrRun& r, int node, uint32_t ip, int port, int phase) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) return s; u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = ip; a.sin_port = htons((u_short)port); trGate(r); double t = trT(r); connect(s, (sockaddr*)&a, sizeof(a));
    fd_set w, e; FD_ZERO(&w); FD_ZERO(&e); FD_SET(s, &w); FD_SET(s, &e); timeval tv{ 6, 0 }; int rc = select(0, nullptr, &w, &e, &tv); double t2 = trT(r), ms = (t2 - t) * 1000;
    sockaddr_in l{}; int ll = sizeof(l); getsockname(s, (sockaddr*)&l, &ll); string local = ip4s(&l.sin_addr) + ":" + std::to_string(ntohs(l.sin_port)), remote = ip4s(&ip) + ":" + std::to_string(port);
    TrMsg q = trMk(t, 0, node, TK_SYN, phase, true, "TCP SYN \xE2\x86\x92 " + remote + "  (open a connection)");
    q.f = { { "from", local }, { "to", remote }, { "note", "Reported by the socket interface. The handshake packets themselves are not captured by this trace." } }; int qi = trAddMsg(r, q);
    if (rc > 0 && FD_ISSET(s, &w)) { TrMsg m = trMk(t2, node, 0, TK_SYNACK, phase, false, "TCP SYN/ACK \xE2\x80\x94 port " + std::to_string(port) + " is open, connected in " + trMs(ms), qi, ms); m.f = { { "connection", local + " \xE2\x86\x94 " + remote }, { "time to connect", trMs(ms) } }; trAddMsg(r, m); nb = 0; ioctlsocket(s, FIONBIO, &nb); return s; }
    int soerr = 0, sl = sizeof(soerr); getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &sl);
    if (rc > 0) { TrMsg m = trMk(t2, node, 0, TK_REFUSED, phase, false, soerr == WSAECONNREFUSED ? "TCP RST \xE2\x80\x94 port " + std::to_string(port) + " is closed (connection refused)" : soerr == WSAENETUNREACH || soerr == WSAEHOSTUNREACH ? "Unreachable \xE2\x80\x94 no route to " + remote : "Connection failed (socket error " + std::to_string(soerr) + ")", qi, ms); trAddMsg(r, m); }
    else { TrMsg m = trMk(t2, node, node, TK_LOST, phase, false, "No answer to the SYN within 6 s (filtered by a firewall, or the host is down)", qi); trAddMsg(r, m); }
    closesocket(s); return INVALID_SOCKET;
}

// ---------------------------------------------------------------- TLS (Schannel)
struct TrIo { SOCKET s = INVALID_SOCKET; bool tls = false, haveCred = false, haveCtx = false; CredHandle cred{}; CtxtHandle ctx{}; SecPkgContext_StreamSizes sz{}; DWORD fl = 0; vector<uint8_t> enc; size_t wireIn = 0, wireOut = 0; };
struct TlsRd { const uint8_t* p; size_t n, o = 0; bool ok = true;
    uint32_t u(int bytes) { if (o + bytes > n) { ok = false; o = n; return 0; } uint32_t v = 0; for (int i = 0; i < bytes; i++) v = (v << 8) | p[o++]; return v; }
    void skip(size_t k) { if (o + k > n) { ok = false; o = n; } else o += k; } };
inline string tlsVer(int v) { switch (v) { case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0"; case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2"; case 0x0304: return "TLS 1.3"; } return trHex((unsigned)v); }
inline string tlsSuite(int id) { switch (id) { case 0x1301: return "TLS_AES_128_GCM_SHA256"; case 0x1302: return "TLS_AES_256_GCM_SHA384"; case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0xC02B: return "ECDHE_ECDSA_AES_128_GCM_SHA256"; case 0xC02C: return "ECDHE_ECDSA_AES_256_GCM_SHA384"; case 0xC02F: return "ECDHE_RSA_AES_128_GCM_SHA256"; case 0xC030: return "ECDHE_RSA_AES_256_GCM_SHA384";
    case 0xCCA8: return "ECDHE_RSA_CHACHA20_POLY1305"; case 0xCCA9: return "ECDHE_ECDSA_CHACHA20_POLY1305"; case 0x009C: return "RSA_AES_128_GCM_SHA256"; case 0x009D: return "RSA_AES_256_GCM_SHA384";
    case 0xC013: return "ECDHE_RSA_AES_128_CBC_SHA"; case 0xC014: return "ECDHE_RSA_AES_256_CBC_SHA"; case 0xC027: return "ECDHE_RSA_AES_128_CBC_SHA256"; case 0xC028: return "ECDHE_RSA_AES_256_CBC_SHA384"; case 0x002F: return "RSA_AES_128_CBC_SHA"; case 0x0035: return "RSA_AES_256_CBC_SHA"; }
    return "cipher suite " + trHex((unsigned)id); }
// Names the TLS records in a flight and decodes the hello messages. `enc` remembers that this direction switched to encryption.
inline string tlsDescribe(const uint8_t* d, size_t n, bool& enc, TrFields& f) {
    vector<string> names; int encRecs = 0; size_t o = 0;
    while (o + 5 <= n) { int type = d[o]; size_t len = ((size_t)d[o + 3] << 8) | d[o + 4]; const uint8_t* b = d + o + 5; size_t avail = std::min(len, n - o - 5); string nm;
        if (type == 20) { nm = "ChangeCipherSpec"; enc = true; }
        else if (type == 21) { nm = "Alert"; if (!enc && avail >= 2) nm += b[1] == 0 ? " (close notify)" : " (code " + std::to_string(b[1]) + (b[0] == 2 ? ", fatal)" : ")"); }
        else if (type == 23) { encRecs++; nm = "encrypted record"; }
        else if (type == 22 && enc) { nm = "Finished (encrypted)"; }
        else if (type == 22) { size_t p = 0; while (p + 4 <= avail) { int ht = b[p]; size_t hl = ((size_t)b[p + 1] << 16) | ((size_t)b[p + 2] << 8) | b[p + 3]; TlsRd rd{ b + p + 4, std::min(hl, avail - p - 4) }; string hn;
                switch (ht) { case 1: hn = "ClientHello"; break; case 2: hn = "ServerHello"; break; case 4: hn = "NewSessionTicket"; break; case 11: hn = "Certificate"; break; case 12: hn = "ServerKeyExchange"; break; case 13: hn = "CertificateRequest"; break; case 14: hn = "ServerHelloDone"; break; case 16: hn = "ClientKeyExchange"; break; case 20: hn = "Finished"; break; case 22: hn = "CertificateStatus"; break; default: hn = "handshake message " + std::to_string(ht); }
                if (ht == 1) { int ver = (int)rd.u(2); rd.skip(32); rd.skip(rd.u(1)); size_t cs = rd.u(2); rd.skip(cs); rd.skip(rd.u(1)); size_t el = rd.u(2), end = std::min(rd.n, rd.o + el); string sni, alpn, vers;
                    while (rd.ok && rd.o + 4 <= end) { int et = (int)rd.u(2); size_t xl = rd.u(2); TlsRd x{ rd.p + rd.o, std::min(xl, rd.n - rd.o) }; rd.skip(xl);
                        if (et == 0) { x.skip(2); x.skip(1); size_t l = x.u(2); if (x.ok && x.o + l <= x.n) sni.assign((const char*)x.p + x.o, l); }
                        else if (et == 16) { x.skip(2); while (x.ok && x.o < x.n) { size_t l = x.u(1); if (x.o + l > x.n) break; if (!alpn.empty()) alpn += ", "; alpn.append((const char*)x.p + x.o, l); x.skip(l); } }
                        else if (et == 43) { size_t l = x.u(1); for (size_t i = 0; i + 1 < l && x.ok; i += 2) { int v = (int)x.u(2); if ((v & 0x0f0f) == 0x0a0a) continue; if (!vers.empty()) vers += ", "; vers += tlsVer(v); } } }
                    f.push_back({ "ClientHello", "offers " + std::to_string(cs / 2) + " cipher suites" + (vers.empty() ? ", version " + tlsVer(ver) : ", versions " + vers) }); if (!sni.empty()) f.push_back({ "server name (SNI)", sni + "  \xE2\x80\x94 sent unencrypted" }); if (!alpn.empty()) f.push_back({ "application protocols (ALPN)", alpn }); }
                if (ht == 2) { int ver = (int)rd.u(2); rd.skip(32); rd.skip(rd.u(1)); int suite = (int)rd.u(2); rd.skip(1); size_t el = rd.u(2), end = std::min(rd.n, rd.o + el);
                    while (rd.ok && rd.o + 4 <= end) { int et = (int)rd.u(2); size_t xl = rd.u(2); if (et == 43 && xl == 2) { TlsRd x{ rd.p + rd.o, std::min(xl, rd.n - rd.o) }; ver = (int)x.u(2); } rd.skip(xl); }
                    if (rd.ok || suite) f.push_back({ "ServerHello", "server chose " + tlsVer(ver) + " with " + tlsSuite(suite) }); }
                if (!nm.empty()) nm += ", "; nm += hn; p += 4 + hl; }
            if (nm.empty()) nm = "handshake (continued)"; }
        else { nm = "record type " + std::to_string(type); }
        if (type != 23) names.push_back(nm); f.push_back({ "record", nm + " \xC2\xB7 " + std::to_string(len) + " bytes" }); o += 5 + len; }
    if (encRecs) names.push_back(std::to_string(encRecs) + (encRecs > 1 ? " encrypted records" : " encrypted record"));
    string t; for (auto& s : names) { if (!t.empty()) t += ", "; t += s; } if (t.empty()) t = trBytes((double)n); f.push_back({ "size", trBytes((double)n) }); return t;
}
inline string tlsErr(SECURITY_STATUS ss) { switch ((unsigned)ss) { case 0x80090326: return "the server sent something that is not a valid TLS message (it may not speak TLS on this port)"; case 0x80090331: return "no TLS version or cipher in common with the server"; case 0x80090304: return "internal security error"; case 0x80090308: return "invalid token from the server"; case 0x8009030C: return "logon denied"; }
    return "TLS handshake failed (" + trHex((unsigned)ss, 8) + ")"; }
// what the handshake produced: protocol, cipher, the server's certificate and whether Windows trusts it
inline void trTlsInfo(const TrRun& r, int node, TrIo& io, const string& host, int phase) {
    TrMsg m = trMk(trT(r), node, node, TK_INFO, phase, false, ""); string proto, subj, verdict = "not checked"; bool trusted = false;
    SecPkgContext_CipherInfo ci{}; if (QueryContextAttributesW(&io.ctx, SECPKG_ATTR_CIPHER_INFO, &ci) == SEC_E_OK) { proto = tlsVer((int)ci.dwProtocol); m.f.push_back({ "protocol", proto }); m.f.push_back({ "cipher suite", narrow(ci.szCipherSuite) });
        string kx = narrow(ci.szExchange); if (!kx.empty()) m.f.push_back({ "key exchange", kx + (ci.dwMinExchangeLen ? " (" + std::to_string(ci.dwMinExchangeLen) + " bits)" : "") }); }
    PCCERT_CONTEXT pc = nullptr;
    if (QueryContextAttributesW(&io.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pc) == SEC_E_OK && pc) { wchar_t b[512];
        if (CertGetNameStringW(pc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, b, 512) > 1) { subj = narrow(b); m.f.push_back({ "certificate issued to", subj }); }
        if (CertGetNameStringW(pc, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, b, 512) > 1) m.f.push_back({ "issued by", narrow(b) });
        auto date = [](FILETIME ft) { SYSTEMTIME st; FileTimeToSystemTime(&ft, &st); char s[32]; snprintf(s, 32, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay); return string(s); };
        LONG tv = CertVerifyTimeValidity(nullptr, pc->pCertInfo); m.f.push_back({ "valid", date(pc->pCertInfo->NotBefore) + " to " + date(pc->pCertInfo->NotAfter) + (tv > 0 ? "  \xE2\x80\x94 EXPIRED" : tv < 0 ? "  \xE2\x80\x94 not valid yet" : "") });
        if (PCERT_EXTENSION e = CertFindExtension(szOID_SUBJECT_ALT_NAME2, pc->pCertInfo->cExtension, pc->pCertInfo->rgExtension)) { DWORD sz = 0; CERT_ALT_NAME_INFO* ai = nullptr;
            if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, e->Value.pbData, e->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &ai, &sz) && ai) { string names; int cnt = 0;
                for (DWORD i = 0; i < ai->cAltEntry; i++) if (ai->rgAltEntry[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME) { if (cnt < 12) { if (!names.empty()) names += ", "; names += narrow(ai->rgAltEntry[i].pwszDNSName); } cnt++; }
                if (cnt) m.f.push_back({ "covers the names", names + (cnt > 12 ? "  (+" + std::to_string(cnt - 12) + " more)" : "") }); LocalFree(ai); } }
        CERT_CHAIN_PARA cp{}; cp.cbSize = sizeof(cp); PCCERT_CHAIN_CONTEXT ch = nullptr;
        if (CertGetCertificateChain(nullptr, pc, nullptr, pc->hCertStore, &cp, 0, nullptr, &ch) && ch) { std::wstring wh = widen(host);
            if (ch->cChain && ch->rgpChain[0]) { string path; for (DWORD i = 0; i < ch->rgpChain[0]->cElement; i++) { if (CertGetNameStringW(ch->rgpChain[0]->rgpElement[i]->pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, b, 512) > 1) { if (!path.empty()) path += "  \xE2\x86\x90  "; path += narrow(b); } } m.f.push_back({ "chain of trust", path }); }
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA sp{}; sp.cbSize = sizeof(sp); sp.dwAuthType = AUTHTYPE_SERVER; sp.pwszServerName = (WCHAR*)wh.c_str(); CERT_CHAIN_POLICY_PARA pp{}; pp.cbSize = sizeof(pp); pp.pvExtraPolicyPara = &sp; CERT_CHAIN_POLICY_STATUS st{}; st.cbSize = sizeof(st);
            if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, ch, &pp, &st)) { trusted = st.dwError == 0;
                verdict = trusted ? "trusted by Windows for " + host : (unsigned)st.dwError == 0x800B0101 ? "NOT TRUSTED: the certificate has expired" : (unsigned)st.dwError == 0x800B0109 ? "NOT TRUSTED: the issuer is not a trusted root (self-signed or private authority)" : (unsigned)st.dwError == 0x800B010F ? "NOT TRUSTED: the certificate is for a different name than " + host : (unsigned)st.dwError == 0x80092010 ? "NOT TRUSTED: the certificate has been revoked" : "NOT TRUSTED (" + trHex(st.dwError, 8) + ")"; }
            CertFreeCertificateChain(ch); }
        m.f.push_back({ "verdict", verdict }); CertFreeCertificateContext(pc); }
    m.title = "Secure channel ready \xE2\x80\x94 " + (proto.empty() ? string("TLS") : proto) + (subj.empty() ? "" : ", certificate for " + subj) + (trusted ? " (trusted)" : verdict.rfind("NOT", 0) == 0 ? " \xE2\x80\x94 NOT TRUSTED" : "");
    m.f.push_back({ "note", "The trace continues even when the certificate is not trusted, so that you can see what the server answers. A browser would stop here." }); m.ms = trusted ? 1 : 0; trAddMsg(r, m);
}
inline bool trTls(const TrRun& r, int node, TrIo& io, const string& host, int phase, string& err) {
    TimeStamp ts; const DWORD cf = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    SCH_CREDENTIALS c{}; c.dwVersion = SCH_CREDENTIALS_VERSION; c.dwFlags = cf; SECURITY_STATUS ss = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &c, nullptr, nullptr, &io.cred, &ts);
    if (ss != SEC_E_OK) { SCHANNEL_CRED o{}; o.dwVersion = SCHANNEL_CRED_VERSION; o.dwFlags = cf; ss = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &o, nullptr, nullptr, &io.cred, &ts); }
    if (ss != SEC_E_OK) { err = "TLS is not available on this system (" + trHex((unsigned)ss, 8) + ")"; return false; }
    io.haveCred = true; std::wstring wh = widen(host); io.fl = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION; DWORD attrs = 0;
    bool encC = false, encS = false, first = true, done = false; vector<uint8_t> in, flight; double tFlight = 0;
    auto emitS = [&] { if (flight.empty()) return; TrMsg m = trMk(tFlight, node, 0, TK_TLSS, phase, false, ""); m.title = "TLS \xE2\x86\x90 " + tlsDescribe(flight.data(), flight.size(), encS, m.f); m.raw = flight; trAddMsg(r, m); flight.clear(); };
    auto readMore = [&]() -> bool { size_t before = in.size(); int n = sockRead(io.s, in, 8000); if (n <= 0) { err = n == 0 ? "the server closed the connection during the TLS handshake" : "the TLS handshake timed out"; return false; }
        if (flight.empty()) tFlight = trT(r); flight.insert(flight.end(), in.begin() + before, in.end()); io.wireIn += (size_t)n; return true; };
    for (int guard = 0; guard < 60 && trLive(r) && !done; guard++) {
        SecBuffer ib[2] = { { (ULONG)in.size(), SECBUFFER_TOKEN, in.data() }, { 0, SECBUFFER_EMPTY, nullptr } }; SecBufferDesc id{ SECBUFFER_VERSION, 2, ib }; SecBuffer ob{ 0, SECBUFFER_TOKEN, nullptr }; SecBufferDesc od{ SECBUFFER_VERSION, 1, &ob };
        ss = InitializeSecurityContextW(&io.cred, first ? nullptr : &io.ctx, (SEC_WCHAR*)wh.c_str(), io.fl, 0, 0, first ? nullptr : &id, 0, first ? &io.ctx : nullptr, &od, &attrs, &ts);
        if (first && (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_OK)) io.haveCtx = true; first = false;
        if (ss == SEC_E_INCOMPLETE_MESSAGE) { if (!readMore()) { emitS(); return false; } continue; }
        if (ob.cbBuffer && ob.pvBuffer) { emitS(); trGate(r); double t = trT(r); sockWrite(io.s, (const uint8_t*)ob.pvBuffer, ob.cbBuffer); io.wireOut += ob.cbBuffer;
            TrMsg m = trMk(t, 0, node, TK_TLSC, phase, true, ""); m.title = "TLS \xE2\x86\x92 " + tlsDescribe((const uint8_t*)ob.pvBuffer, ob.cbBuffer, encC, m.f); m.raw.assign((const uint8_t*)ob.pvBuffer, (const uint8_t*)ob.pvBuffer + ob.cbBuffer); trAddMsg(r, m); }
        if (ob.pvBuffer) FreeContextBuffer(ob.pvBuffer);
        if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) { emitS(); err = tlsErr(ss); return false; }
        if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer && ib[1].cbBuffer <= in.size()) in.erase(in.begin(), in.end() - ib[1].cbBuffer); else in.clear();
        if (ss == SEC_E_OK) { emitS(); io.enc = in; io.tls = true; done = true; break; }
        if (in.empty() && !readMore()) { emitS(); return false; }
    }
    if (!done) { if (err.empty()) err = "the TLS handshake did not complete"; return false; }
    QueryContextAttributesW(&io.ctx, SECPKG_ATTR_STREAM_SIZES, &io.sz); trTlsInfo(r, node, io, host, phase); return true;
}
inline void ioClose(TrIo& io) { if (io.haveCtx) DeleteSecurityContext(&io.ctx); if (io.haveCred) FreeCredentialsHandle(&io.cred); if (io.s != INVALID_SOCKET) closesocket(io.s); io = TrIo(); }
inline bool ioSend(TrIo& io, const string& data) {
    if (!io.tls) { io.wireOut += data.size(); return sockWrite(io.s, (const uint8_t*)data.data(), data.size()); }
    size_t o = 0; while (o < data.size()) { size_t n = std::min<size_t>(data.size() - o, io.sz.cbMaximumMessage); vector<uint8_t> b(io.sz.cbHeader + n + io.sz.cbTrailer); memcpy(b.data() + io.sz.cbHeader, data.data() + o, n);
        SecBuffer sb[4] = { { io.sz.cbHeader, SECBUFFER_STREAM_HEADER, b.data() }, { (ULONG)n, SECBUFFER_DATA, b.data() + io.sz.cbHeader }, { io.sz.cbTrailer, SECBUFFER_STREAM_TRAILER, b.data() + io.sz.cbHeader + n }, { 0, SECBUFFER_EMPTY, nullptr } }; SecBufferDesc d{ SECBUFFER_VERSION, 4, sb };
        if (EncryptMessage(&io.ctx, 0, &d, 0) != SEC_E_OK) return false; size_t tot = (size_t)sb[0].cbBuffer + sb[1].cbBuffer + sb[2].cbBuffer; io.wireOut += tot; if (!sockWrite(io.s, b.data(), tot)) return false; o += n; }
    return true;
}
inline int ioRecv(TrIo& io, vector<uint8_t>& out, int timeoutMs) {   // >0 plain bytes appended, 0 closed, -1 nothing within the timeout
    if (!io.tls) { int n = sockRead(io.s, out, timeoutMs); if (n > 0) io.wireIn += (size_t)n; return n; }
    for (int guard = 0; guard < 400; guard++) {
        if (!io.enc.empty()) {
            SecBuffer sb[4] = { { (ULONG)io.enc.size(), SECBUFFER_DATA, io.enc.data() }, { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr } }; SecBufferDesc d{ SECBUFFER_VERSION, 4, sb };
            SECURITY_STATUS ss = DecryptMessage(&io.ctx, &d, 0, nullptr);
            if (ss == SEC_E_OK || ss == SEC_I_RENEGOTIATE) { size_t got = 0; vector<uint8_t> extra;
                for (auto& b : sb) { if (b.BufferType == SECBUFFER_DATA && b.cbBuffer && ss == SEC_E_OK) { out.insert(out.end(), (uint8_t*)b.pvBuffer, (uint8_t*)b.pvBuffer + b.cbBuffer); got += b.cbBuffer; } if (b.BufferType == SECBUFFER_EXTRA && b.cbBuffer) extra.assign((uint8_t*)b.pvBuffer, (uint8_t*)b.pvBuffer + b.cbBuffer); }
                if (ss == SEC_I_RENEGOTIATE) {   // TLS 1.3 post-handshake message (a session ticket): the handshake code consumes it, then data continues
                    if (extra.empty()) extra = io.enc;
                    SecBuffer ib[2] = { { (ULONG)extra.size(), SECBUFFER_TOKEN, extra.data() }, { 0, SECBUFFER_EMPTY, nullptr } }; SecBufferDesc id{ SECBUFFER_VERSION, 2, ib }; SecBuffer ob{ 0, SECBUFFER_TOKEN, nullptr }; SecBufferDesc od{ SECBUFFER_VERSION, 1, &ob }; DWORD at = 0; TimeStamp ts;
                    SECURITY_STATUS s2 = InitializeSecurityContextW(&io.cred, &io.ctx, nullptr, io.fl, 0, 0, &id, 0, nullptr, &od, &at, &ts);
                    if (ob.pvBuffer) { if (ob.cbBuffer) sockWrite(io.s, (const uint8_t*)ob.pvBuffer, ob.cbBuffer); FreeContextBuffer(ob.pvBuffer); }
                    if (s2 != SEC_E_OK && s2 != SEC_I_CONTINUE_NEEDED) return 0;
                    vector<uint8_t> rest; if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer && ib[1].cbBuffer <= extra.size()) rest.assign(extra.end() - ib[1].cbBuffer, extra.end()); extra.swap(rest); }
                io.enc.swap(extra); if (got) return (int)got; continue; }
            if (ss != SEC_E_INCOMPLETE_MESSAGE) return 0;   // closed (close notify) or broken
        }
        vector<uint8_t> more; int n = sockRead(io.s, more, timeoutMs); if (n <= 0) return n; io.wireIn += (size_t)n; io.enc.insert(io.enc.end(), more.begin(), more.end());
    }
    return -1;
}

// ---------------------------------------------------------------- HTTP
struct TrHttp { int status = 0; string location; };
inline bool trHttp(const TrRun& r, int node, TrIo& io, const string& host, int port, const string& path, bool tls, int phase, TrHttp& res) {
    string hostHdr = host + (port != (tls ? 443 : 80) ? ":" + std::to_string(port) : "");
    TrFields hd = { { "Host", hostHdr }, { "User-Agent", "MatrixSys/1.0 (route and protocol trace)" }, { "Accept", "*/*" }, { "Accept-Encoding", "identity" }, { "Connection", "close" } };
    string req = "GET " + path + " HTTP/1.1\r\n"; for (auto& h : hd) req += h.first + ": " + h.second + "\r\n"; req += "\r\n";
    trGate(r); size_t w0 = io.wireOut; double t = trT(r); bool sent = ioSend(io, req);
    TrMsg q = trMk(t, 0, node, TK_HTTPQ, phase, true, "HTTP request: GET " + path); q.f.push_back({ "request line", "GET " + path + " HTTP/1.1" }); for (auto& h : hd) q.f.push_back(h);
    q.f.push_back({ "on the wire", tls ? "encrypted inside TLS, " + trBytes((double)(io.wireOut - w0)) + " (shown here before encryption)" : "plain text, " + trBytes((double)req.size()) + " \xE2\x80\x94 readable by every hop on the way" });
    q.raw.assign(req.begin(), req.end()); int qi = trAddMsg(r, q);
    if (!sent) { trAddMsg(r, trMk(trT(r), node, node, TK_LOST, phase, false, "The request could not be sent (connection lost)", qi)); return false; }
    const size_t CAP = 512 * 1024; vector<uint8_t> buf; size_t wi0 = io.wireIn; double tFirst = -1; bool closed = false, complete = false, cut = false; size_t hdrEnd = string::npos; long long clen = -1; bool chunked = false;
    while (trLive(r)) { int n = ioRecv(io, buf, buf.empty() ? 10000 : 4000); if (n > 0 && tFirst < 0) tFirst = trT(r); if (n == 0) { closed = true; break; } if (n < 0) break;
        if (hdrEnd == string::npos) { for (size_t i = 0; i + 3 < buf.size(); i++) if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') { hdrEnd = i; break; }
            if (hdrEnd != string::npos) { string h = trLower(string(buf.begin(), buf.begin() + hdrEnd)); size_t p = h.find("\ncontent-length:"); if (p != string::npos) clen = atoll(h.c_str() + p + 16); chunked = h.find("\ntransfer-encoding: chunked") != string::npos || h.find("\ntransfer-encoding:chunked") != string::npos; } }
        if (hdrEnd != string::npos) { size_t body = buf.size() - hdrEnd - 4; if (clen >= 0 && (long long)body >= clen) { complete = true; break; }
            if (chunked && buf.size() >= 5 && memcmp(&buf[buf.size() - 5], "0\r\n\r\n", 5) == 0) { complete = true; break; } }
        if (buf.size() > CAP) { cut = true; break; } }
    double t2 = tFirst < 0 ? trT(r) : tFirst;
    if (buf.empty()) { trAddMsg(r, trMk(t2, node, node, TK_LOST, phase, false, closed ? "The server closed the connection without answering" : "No HTTP response within 10 s", qi)); return false; }
    if (hdrEnd == string::npos || buf.size() < 5 || memcmp(buf.data(), "HTTP/", 5) != 0) { TrMsg m = trMk(t2, node, 0, TK_BANNER, phase, false, "The reply is not HTTP (" + trBytes((double)buf.size()) + ")", qi, (t2 - t) * 1000); m.body = trText(buf.data(), std::min<size_t>(buf.size(), 2000)); m.raw = buf; trAddMsg(r, m); return false; }
    string head(buf.begin(), buf.begin() + hdrEnd); TrMsg m = trMk(t2, node, 0, TK_HTTPR, phase, false, "", qi, (t2 - t) * 1000); string statusLine, ctype; size_t ls = 0; bool firstLine = true;
    while (ls <= head.size()) { size_t le = head.find("\r\n", ls); if (le == string::npos) le = head.size(); string line = head.substr(ls, le - ls); ls = le + 2;
        if (firstLine) { statusLine = line; size_t sp = line.find(' '); res.status = sp == string::npos ? 0 : atoi(line.c_str() + sp + 1); m.f.push_back({ "status", line }); firstLine = false; continue; }
        size_t c = line.find(':'); if (c == string::npos) continue; string k = line.substr(0, c), v = line.substr(c + 1); size_t vb = v.find_first_not_of(" \t"); v = vb == string::npos ? "" : v.substr(vb); m.f.push_back({ k, v });
        string lk = trLower(k); if (lk == "location") res.location = v; if (lk == "content-type") ctype = v; if (lk == "content-security-policy") m.csp += (m.csp.empty() ? "" : ", ") + v; }
    vector<uint8_t> body(buf.begin() + hdrEnd + 4, buf.end());
    if (chunked) { vector<uint8_t> de; size_t p = 0; while (p < body.size()) { size_t e = p; while (e + 1 < body.size() && !(body[e] == '\r' && body[e + 1] == '\n')) e++; if (e + 1 >= body.size()) break; size_t sz = strtoul(string(body.begin() + p, body.begin() + e).c_str(), nullptr, 16); p = e + 2; if (!sz) break; size_t take = std::min(sz, body.size() - p); de.insert(de.end(), body.begin() + p, body.begin() + p + take); p += take + 2; } body.swap(de); }
    string lct = trLower(ctype); bool texty = lct.find("text") != string::npos || lct.find("json") != string::npos || lct.find("xml") != string::npos || lct.find("javascript") != string::npos || lct.find("html") != string::npos;
    if (!texty && !body.empty()) { size_t pr = 0, n = std::min<size_t>(body.size(), 512); for (size_t i = 0; i < n; i++) if (body[i] >= 32 || body[i] == '\n' || body[i] == '\r' || body[i] == '\t') pr++; texty = pr * 100 >= n * 95; }
    if (texty) m.body = trText(body.data(), std::min<size_t>(body.size(), 8000));
    if (!body.empty() && (lct.find("html") != string::npos || (ctype.empty() && body[0] == '<'))) { m.page.assign(body.begin(), body.end()); m.ctype = ctype; m.url = string(tls ? "https://" : "http://") + hostHdr + path; }
    m.f.push_back({ "body", body.empty() ? string("empty") : trBytes((double)body.size()) + (texty ? "" : " of binary data (not shown as text)") + (body.size() > 8000 && texty ? ", first 8000 characters shown" : "") + (cut ? " \xE2\x80\x94 download stopped at 512 KB" : !complete && !closed ? " \xE2\x80\x94 incomplete (the server stopped sending)" : "") });
    m.f.push_back({ "time to first byte", trMs((t2 - t) * 1000) }); m.f.push_back({ "on the wire", tls ? "encrypted inside TLS, " + trBytes((double)(io.wireIn - wi0)) + " (shown here after decryption)" : "plain text, " + trBytes((double)buf.size()) });
    size_t sc = ctype.find(';'); string ct = sc == string::npos ? ctype : ctype.substr(0, sc);
    m.title = statusLine + (ct.empty() ? "" : " \xC2\xB7 " + ct) + (body.empty() ? "" : " \xC2\xB7 " + trBytes((double)body.size())) + (res.status >= 300 && res.status < 400 && !res.location.empty() ? "  \xE2\x86\x92 " + res.location : "");
    m.raw = buf; trAddMsg(r, m); return true;
}
// greeting of a server that speaks first (SSH, SMTP, FTP, ...)
inline void trBanner(const TrRun& r, int node, SOCKET s, int port, int phase) {
    vector<uint8_t> b; double t = trT(r); int n = sockRead(s, b, 1500); double t2 = trT(r);
    if (n > 0) { string txt = trText(b.data(), std::min<size_t>(b.size(), 2000)), line = txt.substr(0, txt.find('\n')), what;
        if (txt.rfind("SSH-", 0) == 0) what = "SSH server identifies itself: " + line; else if (txt.rfind("220", 0) == 0) what = string(port == 21 ? "FTP" : "SMTP") + " greeting: " + line; else if (txt.rfind("+OK", 0) == 0) what = "POP3 greeting: " + line;
        else if (txt.rfind("* OK", 0) == 0) what = "IMAP greeting: " + line; else if (txt.rfind("RFB ", 0) == 0) what = "VNC server, protocol " + line.substr(4); else if (txt.rfind("HTTP/", 0) == 0) what = "HTTP reply: " + line;
        else if (b.size() > 5 && b[4] == 0x0a) what = "MySQL / MariaDB handshake, server version " + string((const char*)&b[5], strnlen((const char*)&b[5], b.size() - 5)); else what = "The server speaks first: " + trBytes((double)b.size()) + " of data";
        TrMsg m = trMk(t2, node, 0, TK_BANNER, phase, false, what, -1, (t2 - t) * 1000); m.f = { { "received", trBytes((double)b.size()) + " " + trMs((t2 - t) * 1000) + " after connecting" } }; m.body = txt; m.raw = b; trAddMsg(r, m); }
    else if (n == 0) trAddMsg(r, trMk(t2, node, 0, TK_FIN, phase, false, "The server closed the connection right away"));
    else { TrMsg m = trMk(t2, node, node, TK_INFO, phase, false, "No greeting within 1.5 s \xE2\x80\x94 this service waits for the client to speak first"); m.f = { { "what this means", "The port is open. Protocols such as HTTP and TLS expect the client to send the first message; use HTTP or HTTPS to see such an exchange." } }; trAddMsg(r, m); }
}

// ---------------------------------------------------------------- the whole run
inline void trRun(int gen, string input, int protoSel, bool live) {
    TrRun r{ gen, nowSec(), live }; TrTarget tg; string err;
    auto finish = [&](const string& e) { trSet(r, [&](Trace& t) { t.err = e; t.running = false; t.status = e.empty() ? "done" : "stopped"; t.took = trT(r); }); };
    if (!trParse(input, protoSel, tg, err)) { finish(err); return; }
    { char hn[256] = ""; gethostname(hn, 256); trSet(r, [&](Trace& t) { t.proto = tg.proto; t.port = tg.port; t.host = tg.host; t.path = tg.path; TrNode me; me.kind = TN_ME; me.name = hn; t.nodes.push_back(me); t.chain = { 0 }; t.status = "resolving the name"; }); }
    auto setLocal = [&](uint32_t dst) { SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = dst; a.sin_port = htons(53);
        if (connect(u, (sockaddr*)&a, sizeof(a)) == 0) { sockaddr_in l{}; int ll = sizeof(l); if (getsockname(u, (sockaddr*)&l, &ll) == 0) { string ip = ip4s(&l.sin_addr); trSet(r, [&](Trace& t) { t.nodes[0].ip = ip; }); } } closesocket(u); };
    if (tg.proto == TP_DNS) {
        sockaddr_storage srv{}; bool have = false;
        if (!tg.server.empty()) { uint32_t sip = 0; if (!trResolve(r, tg.server, 0, sip, err, false)) { finish("DNS server " + tg.server + ": " + err); return; } auto* a = (sockaddr_in*)&srv; a->sin_family = AF_INET; a->sin_addr.s_addr = sip; have = true; }
        else { auto sv = trDnsServers(); for (auto& s : sv) if (s.ss_family == AF_INET && !have) { srv = s; have = true; } if (!have && !sv.empty()) { srv = sv[0]; have = true; } }
        if (!have) { finish("No DNS server is configured on this computer."); return; }
        int node = trAddNode(r, TN_DNS, saStr(srv), tg.server.empty() ? "DNS server" : tg.server);
        if (srv.ss_family == AF_INET) { uint32_t sip = ((sockaddr_in*)&srv)->sin_addr.s_addr; setLocal(sip); trSet(r, [&](Trace& t) { t.status = "tracing the route to the DNS server " + saStr(srv); }); trRoute(r, sip, node); } else trLink(r, 0, node);
        trSet(r, [&](Trace& t) { t.status = "asking the DNS server"; });
        in_addr lit; if (inet_pton(AF_INET, tg.host.c_str(), &lit) == 1) { const uint8_t* b = (const uint8_t*)&lit; char rev[64]; snprintf(rev, 64, "%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]); DnsMsg dm; trDnsQuery(r, node, srv, rev, 12, 2, dm); }
        else { const int types[] = { 1, 28, 5, 15, 2, 16, 6 }; for (int ty : types) { if (!trLive(r)) break; DnsMsg dm; if (!trDnsQuery(r, node, srv, tg.host, ty, 2, dm)) break; if (dm.rcode == 3) break; } }
        finish(""); return;
    }
    uint32_t ip = 0; if (!trResolve(r, tg.host, 0, ip, err)) { finish(err); return; }
    if (!trLive(r)) return; setLocal(ip); string ips = ip4s(&ip); bool literal = ips == tg.host;
    int target = trAddNode(r, TN_TARGET, ips, literal ? "" : tg.host);
    trSet(r, [&](Trace& t) { t.status = "tracing the route to " + ips; }); trRoute(r, ip, target); if (!trLive(r)) return;
    if (tg.proto == TP_ICMP) {
        trSet(r, [&](Trace& t) { t.status = "pinging " + ips; }); int got = 0; double mn = 1e9, mx = 0, sum = 0;
        for (int i = 0; i < 4 && trLive(r); i++) { trGate(r); double t = trT(r); TrHop h = trProbe(ip, 128, 2000, true); TrMsg q = trMk(t, 0, target, TK_ECHOQ, 2, true, "ICMP echo request #" + std::to_string(i + 1) + " \xE2\x86\x92 " + ips); q.f = { { "payload", "32 bytes" }, { "TTL", "128" } }; int qi = trAddMsg(r, q);
            if (h.got && h.status == 0) { got++; mn = std::min(mn, h.ms); mx = std::max(mx, h.ms); sum += h.ms; TrMsg a = trMk(t + h.ms / 1000, target, 0, TK_ECHOR, 2, false, "Echo reply #" + std::to_string(i + 1) + " in " + trMs(h.ms) + "  (TTL " + std::to_string(h.rttl) + ")", qi, h.ms);
                a.f = { { "round trip", trMs(h.ms) }, { "TTL of the reply", std::to_string(h.rttl) + (h.rttl > 128 ? " \xE2\x80\x94 started at 255 (typical for network equipment)" : h.rttl > 64 ? " \xE2\x80\x94 started at 128 (typical for Windows)" : " \xE2\x80\x94 started at 64 (typical for Linux, macOS, phones)") } }; trAddMsg(r, a); }
            else trAddMsg(r, trMk(trT(r), target, target, TK_LOST, 2, false, "Echo request #" + std::to_string(i + 1) + ": " + icmpText(h.status), qi));
            Sleep(250); }
        TrMsg s = trMk(trT(r), target, target, TK_INFO, 2, false, "Ping summary: 4 sent, " + std::to_string(got) + " answered" + (got ? ", " + trMs(mn) + " / " + trMs(sum / got) + " / " + trMs(mx) + " (min / avg / max)" : "")); s.ms = got ? 1 : 0; trAddMsg(r, s);
        finish(""); return;
    }
    if (tg.proto == TP_TCP) {
        trSet(r, [&](Trace& t) { t.status = "connecting to " + ips + ":" + std::to_string(tg.port); });
        SOCKET s = trConnect(r, target, ip, tg.port, 2); if (s != INVALID_SOCKET) { trBanner(r, target, s, tg.port, 2); trGate(r); double t = trT(r); closesocket(s); trAddMsg(r, trMk(t, 0, target, TK_FIN, 2, true, "TCP FIN \xE2\x80\x94 this computer closes the connection")); }
        finish(""); return;
    }
    // HTTP / HTTPS, following redirects
    string host = tg.host, path = tg.path; int port = tg.port, node = target; bool tls = tg.proto == TP_HTTPS; uint32_t cip = ip;
    for (int step = 0; step < 6 && trLive(r); step++) {
        trSet(r, [&](Trace& t) { t.status = string(tls ? "HTTPS" : "HTTP") + " exchange with " + host; });
        TrIo io; io.s = trConnect(r, node, cip, port, 2); if (io.s == INVALID_SOCKET) break; bool ok = true; string e;
        if (tls && !trTls(r, node, io, host, 2, e)) { ok = false; TrMsg m = trMk(trT(r), node, node, TK_LOST, 2, false, "TLS failed: " + e); trAddMsg(r, m); }
        TrHttp h; if (ok) ok = trHttp(r, node, io, host, port, path, tls, 2, h);
        trGate(r); double t = trT(r); ioClose(io); trAddMsg(r, trMk(t, 0, node, TK_FIN, 2, true, "TCP FIN \xE2\x80\x94 connection closed"));
        if (!ok || h.status < 300 || h.status >= 400 || h.location.empty()) break;
        if (step == 5) { trAddMsg(r, trMk(trT(r), node, node, TK_INFO, 2, false, "Stopped after 5 redirects")); break; }
        string loc = h.location, nh = host; int np = port; bool ntls = tls; size_t sc = loc.find("://");
        if (sc != string::npos || loc.rfind("//", 0) == 0) { if (sc != string::npos) { string s = trLower(loc.substr(0, sc)); if (s != "http" && s != "https") break; ntls = s == "https"; loc = loc.substr(sc + 3); } else loc = loc.substr(2);
            size_t sl = loc.find_first_of("/?#"); string hp = sl == string::npos ? loc : loc.substr(0, sl); path = sl == string::npos ? "/" : loc[sl] == '/' ? loc.substr(sl) : "/" + loc.substr(sl); np = ntls ? 443 : 80;
            size_t at = hp.rfind('@'); if (at != string::npos) hp = hp.substr(at + 1); size_t col = hp.rfind(':'); if (col != string::npos && hp.find(']') == string::npos) { np = atoi(hp.c_str() + col + 1); hp = hp.substr(0, col); } nh = trLower(hp); }
        else if (!loc.empty() && loc[0] == '/') path = loc; else { size_t q = path.find('?'); string base = q == string::npos ? path : path.substr(0, q); size_t ls = base.rfind('/'); path = (ls == string::npos ? "/" : base.substr(0, ls + 1)) + loc; }
        size_t hs = path.find('#'); if (hs != string::npos) path = path.substr(0, hs); if (np <= 0 || np > 65535 || nh.empty()) break;
        if (nh != host) { uint32_t nip = 0; if (!trResolve(r, nh, 2, nip, e)) { trAddMsg(r, trMk(trT(r), node, node, TK_INFO, 2, false, "The redirect target cannot be resolved: " + e)); break; }
            if (nip != cip) { string nips = ip4s(&nip); node = trAddNode(r, TN_TARGET, nips, nh); trLink(r, 0, node); trSet(r, [&](Trace& t) { if (t.nodes[node].note.empty() && node != target) t.nodes[node].note = "Reached through a redirect. The route to it was not traced hop by hop."; }); cip = nip; } }
        host = nh; port = np; tls = ntls;
    }
    finish("");
}
inline void traceStart(const string& input, int proto, bool live = false) {
    int gen = ++g_trGen; g_trPermits = 0; { std::lock_guard<std::mutex> l(g_trMx); int v = g_tr.ver + 1; g_tr = Trace(); g_tr.ver = v; g_tr.running = true; g_tr.live = live; g_tr.input = input; g_tr.status = "starting"; }
    std::thread(trRun, gen, input, proto, live).detach();
}
inline void traceStop() { ++g_trGen; std::lock_guard<std::mutex> l(g_trMx); if (g_tr.running) { g_tr.running = false; g_tr.status = "stopped"; g_tr.err = "Stopped."; g_tr.ver++; } }
