// Folder-size scanner for the Disks view. Walks every fixed / removable drive once and keeps a size tree.
#pragma once
#include "data.h"

struct DNode {
    std::wstring name; uint64_t size = 0, own = 0; uint32_t files = 0;   // size / files include everything below; own = files directly here
    DNode* parent = nullptr; std::vector<std::unique_ptr<DNode>> kids;
};
struct Drive { std::wstring root, label, fs; uint64_t total = 0, free = 0; std::unique_ptr<DNode> node; };

inline std::mutex g_dkMx;                     // guards g_drives, every DNode and g_dkNow
inline std::vector<Drive> g_drives;
inline std::wstring g_dkNow;
inline std::atomic<bool> g_wantDisks{false}, g_dkRescan{false};
inline std::atomic<int> g_dkState{0};          // 0 not started, 1 scanning, 2 done
inline std::atomic<uint64_t> g_dkFiles{0};
inline std::wstring g_dkRescanOne;             // folder to rescan on its own (guarded by g_dkMx)

inline DNode* dkFindW(const std::wstring& w, int* depth) {   // caller holds g_dkMx
    size_t p = w.find(L'\\'); std::wstring dr = w.substr(0, p); DNode* n = nullptr; *depth = 0;
    for (auto& d : g_drives) if (!_wcsicmp(d.root.c_str(), dr.c_str())) n = d.node.get();
    while (n && p != std::wstring::npos) { size_t q = w.find(L'\\', p + 1); std::wstring part = w.substr(p + 1, q == std::wstring::npos ? std::wstring::npos : q - p - 1); DNode* nx = nullptr;
        for (auto& k : n->kids) if (!_wcsicmp(k->name.c_str(), part.c_str())) { nx = k.get(); break; } n = nx; p = q; (*depth)++; }
    return n;
}

inline void dkScanDir(DNode* n, std::wstring& path, int depth) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW((path + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;   // not readable: shows up as unattributed space on the drive
    uint64_t own = 0; uint32_t nf = 0; std::vector<std::wstring> subs;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;   // junctions and links would double-count or loop
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            subs.push_back(fd.cFileName);
        } else { own += (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow; nf++; }
    } while (FindNextFileW(h, &fd));
    FindClose(h); g_dkFiles += nf;
    bool keep = depth < 8;   // deeper folders are folded into their depth-8 ancestor to bound memory
    {
        std::lock_guard<std::mutex> l(g_dkMx); n->own += own;
        for (DNode* p = n; p; p = p->parent) { p->size += own; p->files += nf; }
        if (keep) { n->kids.reserve(subs.size()); for (auto& s : subs) { auto k = std::make_unique<DNode>(); k->name = s; k->parent = n; n->kids.push_back(std::move(k)); } }
    }
    size_t base = path.size();
    for (size_t i = 0; i < subs.size() && !g_quit && !g_dkRescan; i++) { path += L"\\"; path += subs[i]; dkScanDir(keep ? n->kids[i].get() : n, path, depth + 1); path.resize(base); }
}
inline void diskScanThread() {
    int tick = 0;
    while (!g_quit) {
        if (!g_wantDisks) { Sleep(250); continue; }
        if (g_dkState == 0 || g_dkRescan) {
            g_dkRescan = false; g_dkFiles = 0; std::vector<Drive> ds; DWORD mask = GetLogicalDrives();
            for (int i = 0; i < 26; i++) {
                if (!(mask & (1u << i))) continue; wchar_t root[4] = { wchar_t(L'A' + i), L':', L'\\', 0 };
                UINT type = GetDriveTypeW(root); if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
                ULARGE_INTEGER fr, tot; if (!GetDiskFreeSpaceExW(root, nullptr, &tot, &fr)) continue;
                wchar_t label[128] = L"", fs[32] = L""; GetVolumeInformationW(root, label, 128, nullptr, nullptr, nullptr, fs, 32);
                Drive d; d.root = std::wstring(root, 2); d.label = label; d.fs = fs; d.total = tot.QuadPart; d.free = fr.QuadPart; d.node = std::make_unique<DNode>(); d.node->name = d.root; ds.push_back(std::move(d));
            }
            { std::lock_guard<std::mutex> l(g_dkMx); g_drives = std::move(ds); }
            g_dkState = 1;
            { std::lock_guard<std::mutex> l(g_dkMx); g_dkNow = std::to_wstring(g_drives.size()) + L" partitions"; }
            std::vector<std::thread> th;   // one walker per partition; the tree is only touched under g_dkMx
            for (size_t i = 0; i < g_drives.size(); i++) th.emplace_back([i] { std::wstring path = L"\\\\?\\" + g_drives[i].root; dkScanDir(g_drives[i].node.get(), path, 0); });
            for (auto& t : th) t.join();
            if (!g_dkRescan) g_dkState = 2;
        } else {
            Sleep(500);
            std::wstring one; DNode* n = nullptr; int depth = 0;
            { std::lock_guard<std::mutex> l(g_dkMx); one.swap(g_dkRescanOne);
                if (!one.empty() && (n = dkFindW(one, &depth)) != nullptr) { uint64_t os = n->size; uint32_t of = n->files; for (DNode* p = n; p; p = p->parent) { p->size -= os; p->files -= of; } n->kids.clear(); n->own = 0; } }
            if (n) { g_dkState = 1; std::wstring path = L"\\\\?\\" + one; dkScanDir(n, path, depth); g_dkState = 2; }
            if (++tick % 6 == 0) { std::lock_guard<std::mutex> l(g_dkMx); for (auto& d : g_drives) { ULARGE_INTEGER fr, tot; if (GetDiskFreeSpaceExW((d.root + L"\\").c_str(), nullptr, &tot, &fr)) { d.total = tot.QuadPart; d.free = fr.QuadPart; } } }
        }
    }
}
