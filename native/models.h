// models.h - the model catalogue, the hardware check that recommends one, and the download of a model file with a SHA-256 check.
// Nothing is downloaded here unless the user chose it. Files are checked against the hash in this catalogue before they are used.
#pragma once
#include "data.h"
#include <winhttp.h>
#include <dxgi.h>
#include <bcrypt.h>
#include <atomic>
#include <cstdio>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "dxgi.lib")

struct ModelOption {
    const char* id; const char* name; const char* file; const char* url; uint64_t size; const char* sha256;
    double ramGB; double vramGB; const char* license; const char* note;
};
// Verified on Hugging Face in November 2026: sizes and SHA-256 are the files' own values.
inline const ModelOption MODEL_OPTIONS[] = {
    { "small", "Qwen3-8B (Q4_K_M)", "Qwen3-8B-Q4_K_M.gguf", "https://huggingface.co/unsloth/Qwen3-8B-GGUF/resolve/main/Qwen3-8B-Q4_K_M.gguf",
      5027784512ull, "120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4", 8, 0, "Apache-2.0",
      "reasoning and tool calling; runs on the processor when there is no graphics memory" },
    { "medium", "Qwen3-14B (Q4_K_M)", "Qwen3-14B-Q4_K_M.gguf", "https://huggingface.co/Qwen/Qwen3-14B-GGUF/resolve/main/Qwen3-14B-Q4_K_M.gguf",
      9001752960ull, "500a8806e85ee9c83f3ae08420295592451379b4f8cf2d0f41c15dffeb6b81f0", 16, 8, "Apache-2.0",
      "stronger answers than 8B; needs 16 GB of memory or 8 GB of graphics memory" },
    { "large", "gpt-oss-20b (MXFP4)", "gpt-oss-20b-MXFP4.gguf", "https://huggingface.co/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf",
      12109566624ull, "27cd6c432c7672cb812a92f611cf3ba7bbc35928262bb1e1253ff4ee6ae35901", 16, 12, "Apache-2.0",
      "mixture of experts: quick for its size; wants 16 GB of memory" },
    { "alt", "DeepSeek-R1-Distill-Qwen-14B (Q4_K_M)", "DeepSeek-R1-Distill-Qwen-14B-Q4_K_M.gguf", "https://huggingface.co/unsloth/DeepSeek-R1-Distill-Qwen-14B-GGUF/resolve/main/DeepSeek-R1-Distill-Qwen-14B-Q4_K_M.gguf",
      8988109984ull, "67a7933cf2ad596a393c8e13b30bc4da2d50b283e250b78554aed18817eca31c", 16, 8, "Apache-2.0",
      "reasoning-focused; tool calling is weaker than the Qwen models" },
};

// ---------------------------------------------------------------- this computer
struct HwInfo { double ramGB = 0; int cores = 0; double vramGB = 0; string gpu; };
inline HwInfo hwDetect() {
    HwInfo h; MEMORYSTATUSEX ms{ sizeof(ms) }; GlobalMemoryStatusEx(&ms); h.ramGB = ms.ullTotalPhys / 1073741824.0;
    SYSTEM_INFO si; GetSystemInfo(&si); h.cores = (int)si.dwNumberOfProcessors;
    IDXGIFactory1* f = nullptr;
    if (SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&f))) {
        for (UINT i = 0;; i++) { IDXGIAdapter1* a = nullptr; if (f->EnumAdapters1(i, &a) == DXGI_ERROR_NOT_FOUND) break;
            DXGI_ADAPTER_DESC1 d{}; a->GetDesc1(&d);
            if (!(d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) && d.DedicatedVideoMemory / 1073741824.0 > h.vramGB) { h.vramGB = d.DedicatedVideoMemory / 1073741824.0; h.gpu = narrow(d.Description); }
            a->Release(); }
        f->Release();
    }
    return h;
}
// The recommended option for this computer, by its memory (graphics memory counts when there is a lot of it).
inline const ModelOption& hwRecommend(const HwInfo& h) {
    if (h.vramGB >= 12 || h.ramGB >= 32) return MODEL_OPTIONS[2];
    if (h.vramGB >= 8 || h.ramGB >= 16) return MODEL_OPTIONS[1];
    return MODEL_OPTIONS[0];
}
inline bool hwFits(const ModelOption& m, const HwInfo& h) { return h.ramGB >= m.ramGB || h.vramGB >= m.vramGB; }

// ---------------------------------------------------------------- SHA-256 of a file
inline bool sha256File(const std::wstring& path, string& hexOut) {
    FILE* f = _wfopen(path.c_str(), L"rb"); if (!f) return false;
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE h = nullptr; DWORD objLen = 0, got = 0; vector<uint8_t> obj, buf(1 << 20);
    bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0;
    if (ok && BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &got, 0) == 0) { obj.resize(objLen); ok = BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) == 0; } else ok = false;
    size_t n;
    while (ok && (n = fread(buf.data(), 1, buf.size(), f)) > 0) ok = BCryptHashData(h, buf.data(), (ULONG)n, 0) == 0;
    uint8_t out[32] = {};
    if (ok) ok = BCryptFinishHash(h, out, 32, 0) == 0;
    if (h) BCryptDestroyHash(h); if (alg) BCryptCloseAlgorithmProvider(alg, 0); fclose(f);
    if (!ok) return false;
    char hex[65]; for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", out[i]);
    hexOut = hex; return true;
}

// ---------------------------------------------------------------- download (HTTPS, follows redirects, progress, cancel)
struct DlProgress { std::atomic<uint64_t> done{ 0 }, total{ 0 }; std::atomic<bool> cancel{ false }; };
// Fetches url into dest.part, then checks the SHA-256 and renames it to dest. On any problem the partial file is removed.
inline bool downloadVerified(const string& url, const std::wstring& dest, const string& sha256, DlProgress& pr, string& err) {
    if (url.rfind("https://", 0) != 0) { err = "only HTTPS downloads are allowed"; return false; }
    size_t sl = url.find('/', 8); string host = url.substr(8, sl - 8), path = url.substr(sl);
    std::wstring part = dest + L".part"; DeleteFileW(part.c_str());
    HINTERNET s = WinHttpOpen(L"MatrixSys/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) { err = "the network stack is unavailable"; return false; }
    WinHttpSetTimeouts(s, 15000, 15000, 30000, 60000);
    HINTERNET c = WinHttpConnect(s, widen(host).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, L"GET", widen(path).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    bool ok = r && WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) && WinHttpReceiveResponse(r, nullptr);
    DWORD code = 0; if (ok) { DWORD sz = sizeof(code); WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX); ok = code == 200; }
    if (!ok) err = "the download could not start" + (code ? " (HTTP " + std::to_string(code) + ")" : string());
    uint64_t total = 0;
    if (ok) { wchar_t cl[64]; DWORD sz = sizeof(cl); if (WinHttpQueryHeaders(r, WINHTTP_QUERY_CUSTOM, L"Content-Length", cl, &sz, WINHTTP_NO_HEADER_INDEX)) total = _wcstoui64(cl, nullptr, 10); pr.total = total; }
    FILE* f = ok ? _wfopen(part.c_str(), L"wb") : nullptr; if (ok && !f) { ok = false; err = "the file could not be created"; }
    if (ok) {
        vector<char> b(1 << 16); DWORD avail = 0;
        for (;;) {
            if (pr.cancel) { ok = false; err = "cancelled"; break; }
            if (!WinHttpQueryDataAvailable(r, &avail)) { ok = false; err = "the connection was lost"; break; }
            if (!avail) break;
            if (avail > b.size()) b.resize(avail);
            DWORD got = 0; if (!WinHttpReadData(r, b.data(), avail, &got)) { ok = false; err = "the connection was lost"; break; }
            if (fwrite(b.data(), 1, got, f) != got) { ok = false; err = "the disk is full or not writable"; break; }
            pr.done += got;
        }
    }
    if (f) fclose(f);
    if (r) WinHttpCloseHandle(r); if (c) WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    if (ok && total && pr.done != total) { ok = false; err = "the file is incomplete"; }
    if (ok) { string got; if (!sha256File(part, got)) { ok = false; err = "the file could not be checked"; } else if (got != sha256) { ok = false; err = "the file does not match the expected checksum; it was discarded"; } }
    if (ok) { DeleteFileW(dest.c_str()); ok = MoveFileExW(part.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING) != 0; if (!ok) err = "the file could not be saved"; }
    if (!ok) DeleteFileW(part.c_str());
    return ok;
}
