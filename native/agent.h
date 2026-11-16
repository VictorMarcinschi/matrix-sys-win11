// agent.h - the agent's settings, its connection to a model server on this computer, and the question / answer exchange.
// Only a server on 127.0.0.1 or localhost is used in this milestone; nothing else is contacted. The protocol is the
// OpenAI-compatible chat API that Ollama and LM Studio both serve.
#pragma once
#include "data.h"
#include "svc.h"
#include <winhttp.h>
#include <fstream>
#include <mutex>
#include <atomic>
#include <thread>
#pragma comment(lib, "winhttp.lib")

struct AgentSettings {
    string prompt = "Answer briefly: a few short sentences, no preamble, no repetition. Give more detail only when asked.";
    string endpoint = "http://127.0.0.1:11434/v1";   // Ollama's default; LM Studio listens on 1234
    string model;
    double temperature = 0.6, topP = 0.95;
    int maxTokens = 512, reasoning = 1, turns = 6;   // reasoning: 0 low, 1 medium, 2 high; turns: earlier question-and-answer pairs sent along
};
inline AgentSettings g_ag;
inline std::mutex g_agMx;
inline string g_agReply, g_agError, g_agInfo;
inline bool g_agDone = false, g_agInfoNew = false;
inline std::atomic<bool> g_agBusy{ false };

// ---------------------------------------------------------------- settings file (%APPDATA%\MatrixSys\agent.ini)
inline std::wstring agentIniPath() { std::wstring d = knownFolder(FOLDERID_RoamingAppData) + L"\\MatrixSys"; CreateDirectoryW(d.c_str(), nullptr); return d + L"\\agent.ini"; }
inline string agentEsc(const string& s) { string o; for (char c : s) { if (c == '\\') o += "\\\\"; else if (c == '\n') o += "\\n"; else o += c; } return o; }
inline string agentUnesc(const string& s) { string o; for (size_t i = 0; i < s.size(); i++) { if (s[i] == '\\' && i + 1 < s.size()) { char c = s[++i]; o += c == 'n' ? '\n' : c; } else o += s[i]; } return o; }
inline void agentSave() {
    FILE* f = _wfopen(agentIniPath().c_str(), L"w"); if (!f) return;
    fprintf(f, "prompt=%s\nendpoint=%s\nmodel=%s\ntemperature=%.3f\ntop_p=%.3f\nmax_tokens=%d\nreasoning=%d\nturns=%d\n",
        agentEsc(g_ag.prompt).c_str(), g_ag.endpoint.c_str(), g_ag.model.c_str(), g_ag.temperature, g_ag.topP, g_ag.maxTokens, g_ag.reasoning, g_ag.turns);
    fclose(f);
}
inline void agentLoad() {
    std::ifstream f(agentIniPath()); if (!f) return; string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('='); if (eq == string::npos) continue; string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "prompt") g_ag.prompt = agentUnesc(v); else if (k == "endpoint") g_ag.endpoint = v; else if (k == "model") g_ag.model = v;
        else if (k == "temperature") g_ag.temperature = std::clamp(atof(v.c_str()), 0.0, 2.0);
        else if (k == "top_p") g_ag.topP = std::clamp(atof(v.c_str()), 0.05, 1.0);
        else if (k == "max_tokens") g_ag.maxTokens = std::clamp(atoi(v.c_str()), 64, 4096);
        else if (k == "reasoning") g_ag.reasoning = std::clamp(atoi(v.c_str()), 0, 2);
        else if (k == "turns") g_ag.turns = std::clamp(atoi(v.c_str()), 0, 20);
    }
}

// ---------------------------------------------------------------- endpoint: local addresses only
struct LocalUrl { string host, path; int port = 0; bool ok = false; };
inline LocalUrl agentLocal(const string& ep, const char* route) {
    LocalUrl u; string p = ep; if (p.rfind("http://", 0) != 0) return u; p = p.substr(7);
    size_t sl = p.find('/'); string hp = sl == string::npos ? p : p.substr(0, sl), base = sl == string::npos ? string() : p.substr(sl);
    size_t col = hp.find(':'); u.host = col == string::npos ? hp : hp.substr(0, col); u.port = col == string::npos ? 80 : atoi(hp.c_str() + col + 1);
    if (u.host != "127.0.0.1" && u.host != "localhost") return u;
    while (!base.empty() && base.back() == '/') base.pop_back();
    u.path = base + route; u.ok = u.port > 0 && u.port < 65536; return u;
}

// ---------------------------------------------------------------- minimal JSON reader (answers only; keys and values are kept as written)
struct JV { int t = 0; /* 0 null, 1 bool, 2 number, 3 string, 4 array, 5 object */ string s; vector<JV> a; vector<string> k; vector<JV> v;
    const JV* get(const char* key) const { for (size_t i = 0; i < k.size(); i++) if (k[i] == key) return &v[i]; return nullptr; } };
struct JP {
    const char* p; const char* e; bool bad = false;
    void ws() { while (p < e && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++; }
    string str() {
        string r; p++;
        while (p < e && *p != '"') {
            if (*p != '\\' || p + 1 >= e) { r += *p++; continue; }
            p++; char c = *p++;
            if (c == 'n') r += '\n'; else if (c == 't') r += '\t'; else if (c == 'r' || c == 'b' || c == 'f') {}
            else if (c == 'u') { size_t n = std::min<size_t>(4, (size_t)(e - p)); unsigned v = strtoul(string(p, n).c_str(), nullptr, 16); p += n;
                if (v < 0x80) r += (char)v; else if (v < 0x800) { r += (char)(0xC0 | (v >> 6)); r += (char)(0x80 | (v & 0x3F)); }
                else { r += (char)(0xE0 | (v >> 12)); r += (char)(0x80 | ((v >> 6) & 0x3F)); r += (char)(0x80 | (v & 0x3F)); } }
            else r += c;
        }
        if (p < e) p++; else bad = true;
        return r;
    }
    JV val() {
        ws(); JV v; if (p >= e) { bad = true; return v; }
        if (*p == '"') { v.t = 3; v.s = str(); }
        else if (*p == '{') { v.t = 5; p++; ws();
            while (!bad && p < e && *p != '}') { ws(); if (p >= e || *p != '"') { bad = true; break; } string key = str(); ws(); if (p >= e || *p != ':') { bad = true; break; } p++;
                JV x = val(); v.k.push_back(key); v.v.push_back(x); ws(); if (p < e && *p == ',') p++; }
            if (p < e) p++; else bad = true; }
        else if (*p == '[') { v.t = 4; p++; ws();
            while (!bad && p < e && *p != ']') { v.a.push_back(val()); ws(); if (p < e && *p == ',') p++; }
            if (p < e) p++; else bad = true; }
        else if (e - p >= 4 && !strncmp(p, "true", 4)) { v.t = 1; p += 4; }
        else if (e - p >= 5 && !strncmp(p, "false", 5)) { v.t = 1; p += 5; }
        else if (e - p >= 4 && !strncmp(p, "null", 4)) p += 4;
        else { char* q = nullptr; strtod(p, &q); if (q == p || q > e) bad = true; else { v.t = 2; p = q; } }
        return v;
    }
};
inline bool agentParseReply(const string& body, string& content, string& err) {
    JP jp{ body.c_str(), body.c_str() + body.size() }; JV root = jp.val();
    if (jp.bad || root.t != 5) { err = "the model server's reply was not understood"; return false; }
    if (const JV* e = root.get("error")) { const JV* m = e->get("message"); err = m && m->t == 3 ? m->s : string("the model server returned an error"); return false; }
    const JV* ch = root.get("choices"); if (!ch || ch->t != 4 || ch->a.empty()) { err = "the reply had no answer"; return false; }
    const JV* msg = ch->a[0].get("message"); const JV* c = msg ? msg->get("content") : nullptr;
    content = c && c->t == 3 ? c->s : string(); return true;
}

// ---------------------------------------------------------------- HTTP to the local server (WinHTTP, no proxy)
inline bool agentHttp(const LocalUrl& u, const wchar_t* verb, const string& body, string& out, string& err) {
    HINTERNET s = WinHttpOpen(L"MatrixSys/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) { err = "the network stack is unavailable"; return false; }
    WinHttpSetTimeouts(s, 3000, 3000, 10000, 900000);   // a reasoning model can take minutes
    HINTERNET c = WinHttpConnect(s, widen(u.host).c_str(), (INTERNET_PORT)u.port, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, verb, widen(u.path).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;
    bool ok = false; DWORD code = 0;
    if (r && WinHttpSendRequest(r, L"Content-Type: application/json\r\n", (DWORD)-1, body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0) && WinHttpReceiveResponse(r, nullptr)) {
        DWORD sz = sizeof(code); WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        ok = true; DWORD avail = 0;
        for (;;) { if (!WinHttpQueryDataAvailable(r, &avail)) { ok = false; break; } if (!avail) break; vector<char> b(avail); DWORD got = 0; if (!WinHttpReadData(r, b.data(), avail, &got)) { ok = false; break; } out.append(b.data(), got); }
    }
    if (ok && code >= 300) {
        ok = false; err = "the model server answered HTTP " + std::to_string(code);
        JP jp{ out.c_str(), out.c_str() + out.size() }; JV root = jp.val();
        if (const JV* e = root.get("error")) if (const JV* m = e->get("message")) if (m->t == 3) err += ": " + m->s;
    }
    if (!ok && err.empty()) err = "no answer from the model server (is it running on this address?)";
    if (r) WinHttpCloseHandle(r); if (c) WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    return ok;
}

// ---------------------------------------------------------------- requests and answers
inline string agentJsonStr(const string& s) {
    string o = "\""; for (unsigned char c : s) { if (c == '"') o += "\\\""; else if (c == '\\') o += "\\\\"; else if (c == '\n') o += "\\n"; else if (c == '\r') o += "\\r"; else if (c == '\t') o += "\\t";
        else if (c < 32) { char b[8]; snprintf(b, 8, "\\u%04x", c); o += b; } else o += (char)c; }
    return o + "\"";
}
inline string agentBody(const AgentSettings& st, const vector<std::pair<string, string>>& msgs) {
    char num[64]; string b = "{\"model\":" + agentJsonStr(st.model) + ",\"stream\":false";
    snprintf(num, 64, "%.3f", st.temperature); b += ",\"temperature\":" + string(num);
    snprintf(num, 64, "%.3f", st.topP); b += ",\"top_p\":" + string(num);
    b += ",\"max_tokens\":" + std::to_string(st.maxTokens) + ",\"reasoning_effort\":\"" + (st.reasoning == 0 ? "low" : st.reasoning == 2 ? "high" : "medium") + "\"";
    b += ",\"messages\":[";
    for (size_t i = 0; i < msgs.size(); i++) b += string(i ? "," : "") + "{\"role\":" + agentJsonStr(msgs[i].first) + ",\"content\":" + agentJsonStr(msgs[i].second) + "}";
    return b + "]}";
}
// Reasoning models may put their thinking inside <think> tags; it is counted, not shown.
inline string agentStripThinking(const string& s, size_t& hidden) {
    string o = s; hidden = 0;
    for (;;) { size_t a = o.find("<think>"); if (a == string::npos) break; size_t b = o.find("</think>", a); size_t end = b == string::npos ? o.size() : b + 8; hidden += end - a; o.erase(a, end - a); }
    size_t p = o.find_first_not_of(" \n\r\t"); return p == string::npos ? string() : o.substr(p);
}
// Sends one request on a worker thread; the answer is picked up by the UI through g_agDone / g_agReply / g_agError.
inline void agentAsk(const string& body, const LocalUrl& u) {
    std::thread([body, u] {
        string out, err, content; bool ok = agentHttp(u, L"POST", body, out, err) && agentParseReply(out, content, err);
        size_t hidden = 0; string shown = agentStripThinking(content, hidden);
        { std::lock_guard<std::mutex> l(g_agMx);
          g_agError = ok ? string() : err; g_agReply = ok ? (shown.empty() ? string("(no answer)") : shown) : string();
          if (ok && hidden) g_agReply += "\n(reasoning hidden: " + std::to_string(hidden) + " characters)";
          g_agDone = true; }
        g_agBusy = false;
    }).detach();
}
// Asks the server which models it has; the result is shown on the settings page.
inline void agentTest(const AgentSettings& st) {
    LocalUrl u = agentLocal(st.endpoint, "/models");
    std::thread([u] {
        string out, err, info;
        if (!u.ok) info = "the endpoint must look like http://127.0.0.1:11434/v1 (local addresses only)";
        else if (!agentHttp(u, L"GET", string(), out, err)) info = err.empty() ? string("could not reach the model server") : err;
        else {
            JP jp{ out.c_str(), out.c_str() + out.size() }; JV root = jp.val(); const JV* d = root.get("data"); string names; int n = 0;
            if (d && d->t == 4) for (auto& m : d->a) { const JV* id = m.get("id"); if (id && id->t == 3) { if (n < 6) names += string(n ? ", " : "") + id->s; n++; } }
            info = n ? "connected: " + std::to_string(n) + " model(s): " + names : string("connected, but the server lists no models");
        }
        std::lock_guard<std::mutex> l(g_agMx); g_agInfo = info; g_agInfoNew = true;
    }).detach();
}
