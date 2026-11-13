// Open-file-handle scanner, background capture service (named pipe server), its client, and install/uninstall helpers.
#pragma once
#include "data.h"
#include <sddl.h>
#include <shlobj.h>
#include <set>
#pragma comment(lib, "ole32.lib")

inline const wchar_t* SVC_NAME = L"MatrixSysSvc";
inline const wchar_t* SVC_PIPE = L"\\\\.\\pipe\\MatrixSysSvc";
inline const wchar_t* UNINST_KEY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MatrixSys";
inline std::atomic<bool> g_svcConnected{false};

// ---------------------------------------------------------------- open file handles
// Asking a pipe handle for its name can block forever, so every query runs on a worker that is abandoned on timeout.
inline HANDLE g_nmReq, g_nmDone, g_nmThread, g_nmH; inline wchar_t g_nmPath[2048]; inline DWORD g_nmLen;
inline DWORD WINAPI nameWorker(LPVOID) {
    for (;;) { WaitForSingleObject(g_nmReq, INFINITE); g_nmLen = 0;
        if (GetFileType(g_nmH) == FILE_TYPE_DISK) g_nmLen = GetFinalPathNameByHandleW(g_nmH, g_nmPath, 2048, VOLUME_NAME_DOS);
        SetEvent(g_nmDone); }
}
inline int queryName(HANDLE h, std::string& out) {   // 1 disk file, 0 not a disk file, -1 timed out
    static std::mutex one; std::lock_guard<std::mutex> lk(one);   // the worker handles one request at a time
    if (!g_nmReq) { g_nmReq = CreateEventW(nullptr, FALSE, FALSE, nullptr); g_nmDone = CreateEventW(nullptr, FALSE, FALSE, nullptr); }
    if (!g_nmThread) { ResetEvent(g_nmReq); ResetEvent(g_nmDone); g_nmThread = CreateThread(nullptr, 0, nameWorker, nullptr, 0, nullptr); }
    g_nmH = h; SetEvent(g_nmReq);
    if (WaitForSingleObject(g_nmDone, 30) != WAIT_OBJECT_0) { TerminateThread(g_nmThread, 0); CloseHandle(g_nmThread); g_nmThread = nullptr; return -1; }
    if (!g_nmLen || g_nmLen >= 2048) return 0;
    const wchar_t* p = g_nmPath; int n = (int)g_nmLen; if (n > 4 && !wcsncmp(p, L"\\\\?\\", 4)) { p += 4; n -= 4; }
    out = narrow(p, n); return 1;
}
struct SHTE { PVOID Object; ULONG_PTR Pid; ULONG_PTR Handle; ULONG Access; USHORT Trace; USHORT Type; ULONG Attr; ULONG Reserved; };
struct SHIE { ULONG_PTR Count; ULONG_PTR Reserved; SHTE H[1]; };
inline void fileScanThread() {
    struct CE { PVOID obj; ULONG access; int state; std::string path; };
    std::unordered_map<uint64_t, CE> cache; std::vector<BYTE> buf(8 << 20);
    HANDLE probe = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD self = GetCurrentProcessId();
    while (!g_quit) {
        if (!g_wantFiles) { Sleep(250); continue; }
        ULONG ret = 0; NTSTATUS st;
        while ((st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, buf.data(), (ULONG)buf.size(), &ret)) == (NTSTATUS)0xC0000004) buf.resize(std::max<size_t>(buf.size() * 2, ret + (1 << 20)));
        if (st < 0) { Sleep(2000); continue; }
        SHIE* info = (SHIE*)buf.data(); USHORT fileType = 0;
        for (ULONG_PTR i = 0; i < info->Count; i++) if (info->H[i].Pid == self && (HANDLE)info->H[i].Handle == probe) { fileType = info->H[i].Type; break; }
        std::unordered_map<DWORD, HANDLE> procs; std::unordered_map<uint64_t, CE> next; std::set<std::pair<int, std::string>> seen; int denied = 0;
        auto out = std::make_shared<std::vector<FileH>>();
        for (ULONG_PTR i = 0; i < info->Count && !g_quit && fileType; i++) {
            SHTE& e = info->H[i]; if (e.Type != fileType || e.Pid == self || e.Pid <= 4) continue;
            uint64_t key = (uint64_t(e.Pid) << 32) ^ uint64_t(e.Handle); CE ce{ e.Object, e.Access, 0, "" };
            auto c = cache.find(key);
            if (c != cache.end() && c->second.obj == e.Object && c->second.access == e.Access) ce = c->second;
            else {
                auto pi = procs.find((DWORD)e.Pid);
                if (pi == procs.end()) { HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)e.Pid); if (!hp) denied++; pi = procs.emplace((DWORD)e.Pid, hp).first; }
                if (!pi->second) continue;
                HANDLE dup = nullptr;
                if (DuplicateHandle(pi->second, (HANDLE)e.Handle, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) { ce.state = queryName(dup, ce.path); CloseHandle(dup); }
            }
            next[key] = ce;
            if (ce.state == 1 && seen.insert({ (int)e.Pid, ce.path }).second) out->push_back({ (int)e.Pid, ce.path });
        }
        for (auto& [pid, h] : procs) if (h) CloseHandle(h);
        cache.swap(next); g_fhDenied = denied;
        { std::lock_guard<std::mutex> l(g_fhMx); g_fileHandles = out; }
        for (int i = 0; i < 40 && !g_quit && g_wantFiles; i++) Sleep(100);
    }
}

// Closes every handle a process holds on one file, from outside the process. Returns the number closed, -1 if the process cannot be opened.
inline int closeFileHandles(int pid, const std::string& path) {
    HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid); if (!hp) return -1;
    HANDLE probe = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    std::vector<BYTE> buf(8 << 20); ULONG ret = 0; NTSTATUS st; int closed = 0; DWORD self = GetCurrentProcessId();
    while ((st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, buf.data(), (ULONG)buf.size(), &ret)) == (NTSTATUS)0xC0000004) buf.resize(std::max<size_t>(buf.size() * 2, ret + (1 << 20)));
    if (st >= 0) { SHIE* info = (SHIE*)buf.data(); USHORT ft = 0;
        for (ULONG_PTR i = 0; i < info->Count; i++) if (info->H[i].Pid == self && (HANDLE)info->H[i].Handle == probe) { ft = info->H[i].Type; break; }
        for (ULONG_PTR i = 0; i < info->Count && ft; i++) { SHTE& e = info->H[i]; if (e.Pid != (ULONG_PTR)pid || e.Type != ft) continue; HANDLE dup = nullptr;
            if (!DuplicateHandle(hp, (HANDLE)e.Handle, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;
            std::string nm; int r = queryName(dup, nm); CloseHandle(dup);
            if (r == 1 && !_stricmp(nm.c_str(), path.c_str())) { HANDLE d2 = nullptr; if (DuplicateHandle(hp, (HANDLE)e.Handle, GetCurrentProcess(), &d2, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) { CloseHandle(d2); closed++; } } } }
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe); CloseHandle(hp); return closed;
}
// ---------------------------------------------------------------- service: pipe server
inline std::mutex g_clMx; inline std::vector<HANDLE> g_clients;
inline void acceptThread() {
    // SYSTEM and administrators: full; interactively logged-on users: read. Remote clients are rejected.
    SECURITY_ATTRIBUTES sa{ sizeof(sa) };
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr);
    while (!g_quit) {
        HANDLE p = CreateNamedPipeW(SVC_PIPE, PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 1 << 20, 0, 0, &sa);
        if (p == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); bool ok = false;
        if (ConnectNamedPipe(p, &ov)) ok = true;
        else if (GetLastError() == ERROR_PIPE_CONNECTED) ok = true;
        else if (GetLastError() == ERROR_IO_PENDING) { while (!g_quit && WaitForSingleObject(ov.hEvent, 500) != WAIT_OBJECT_0) {} ok = !g_quit; }
        CloseHandle(ov.hEvent);
        if (ok) { std::lock_guard<std::mutex> l(g_clMx); g_clients.push_back(p); } else CloseHandle(p);
    }
}
inline void broadcast(const std::string& s) {
    std::lock_guard<std::mutex> l(g_clMx);
    for (size_t i = 0; i < g_clients.size();) {
        HANDLE h = g_clients[i]; OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); DWORD w = 0; bool ok = true;
        if (!WriteFile(h, s.data(), (DWORD)s.size(), &w, &ov)) {
            if (GetLastError() == ERROR_IO_PENDING) { if (WaitForSingleObject(ov.hEvent, 1500) != WAIT_OBJECT_0) { CancelIo(h); ok = false; } else ok = GetOverlappedResult(h, &ov, &w, FALSE) != 0; }
            else ok = false;
        }
        CloseHandle(ov.hEvent);
        if (ok) i++; else { DisconnectNamedPipe(h); CloseHandle(h); g_clients.erase(g_clients.begin() + i); }
    }
}
// Captures only while a viewer is connected; idle otherwise.
inline void serviceRun() {
    ETW_NAME = L"MatrixSysSvcCapture";   // separate session, so an elevated viewer cannot knock the service's capture over
    std::thread(acceptThread).detach(); std::thread(flushThread).detach(); std::thread(fileScanThread).detach();
    bool capturing = false; int tick = 0; size_t lastN = 0; std::shared_ptr<std::vector<FileH>> sent;
    while (!g_quit) {
        Sleep(200); size_t n; { std::lock_guard<std::mutex> l(g_clMx); n = g_clients.size(); }
        if (n && !capturing) { std::thread(captureThread).detach(); capturing = true; }
        if (!n && capturing && g_capMode == 1) { stopCapture(); capturing = false; }
        g_wantFiles = n > 0;
        std::vector<Flow> fl; std::vector<DiskIo> dk; { std::lock_guard<std::mutex> l(g_flowMx); fl.swap(g_flows); dk.swap(g_disk); }
        if (!n) { lastN = 0; continue; }
        std::string out;
        if (tick++ % 5 == 0) out += "M\t" + std::to_string((int)g_capMode) + "\n";
        for (auto& f : fl) out += "F\t" + std::to_string(f.pid) + "\t" + std::to_string(f.proto) + "\t" + f.lip + "\t" + std::to_string(f.lp) + "\t" + f.rip + "\t" + std::to_string(f.rp) + "\t" + (f.out ? "1" : "0") + "\t" + std::to_string(f.bytes) + "\t" + std::to_string(f.n) + "\n";
        for (auto& d : dk) out += "D\t" + std::to_string(d.pid) + "\t" + std::to_string(d.rd) + "\t" + std::to_string(d.wr) + "\t" + d.path + "\n";
        std::shared_ptr<std::vector<FileH>> fh; { std::lock_guard<std::mutex> l(g_fhMx); fh = g_fileHandles; }
        if (fh && (fh != sent || n > lastN)) { for (auto& h : *fh) out += "H\t" + std::to_string(h.pid) + "\t" + h.path + "\n"; out += "HE\t" + std::to_string((int)g_fhDenied) + "\n"; sent = fh; }
        lastN = n;
        if (!out.empty()) broadcast(out);
    }
}
// ---------------------------------------------------------------- viewer side: read from the service if it is installed
inline void svcClientThread() {
    while (!g_quit) {
        HANDLE h = CreateFileW(SVC_PIPE, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Sleep(2000); continue; }
        g_svcConnected = true; std::string buf; std::vector<char> tmp(1 << 16); DWORD n; auto fh = std::make_shared<std::vector<FileH>>();
        while (!g_quit && ReadFile(h, tmp.data(), (DWORD)tmp.size(), &n, nullptr) && n) {
            buf.append(tmp.data(), n); size_t pos = 0, nl;
            while ((nl = buf.find('\n', pos)) != std::string::npos) {
                std::vector<std::string> a; size_t s = pos; for (size_t i = pos; i <= nl; i++) if (i == nl || buf[i] == '\t') { a.push_back(buf.substr(s, i - s)); s = i + 1; }
                pos = nl + 1; if (a.empty()) continue;
                if (a[0] == "F" && a.size() >= 10) { Flow f; f.pid = atoi(a[1].c_str()); f.proto = atoi(a[2].c_str()); f.lip = a[3]; f.lp = atoi(a[4].c_str()); f.rip = a[5]; f.rp = atoi(a[6].c_str()); f.out = a[7] == "1"; f.bytes = strtoull(a[8].c_str(), nullptr, 10); f.n = atoi(a[9].c_str()); f.t = 0;
                    std::lock_guard<std::mutex> l(g_flowMx); if (g_flows.size() < 20000) g_flows.push_back(f); }
                else if (a[0] == "D" && a.size() >= 5) { DiskIo d{ atoi(a[1].c_str()), a[4], strtoull(a[2].c_str(), nullptr, 10), strtoull(a[3].c_str(), nullptr, 10), 0 }; std::lock_guard<std::mutex> l(g_flowMx); if (g_disk.size() < 20000) g_disk.push_back(d); }
                else if (a[0] == "H" && a.size() >= 3) fh->push_back({ atoi(a[1].c_str()), a[2] });
                else if (a[0] == "HE") { if (a.size() >= 2) g_fhDenied = atoi(a[1].c_str()); { std::lock_guard<std::mutex> l(g_fhMx); g_fileHandles = fh; } fh = std::make_shared<std::vector<FileH>>(); }
                else if (a[0] == "M" && a.size() >= 2) g_capMode = atoi(a[1].c_str()) ? 3 : 0;
            }
            buf.erase(0, pos);
        }
        CloseHandle(h); g_svcConnected = false; g_capMode = 0;
    }
}
// ---------------------------------------------------------------- service plumbing
inline SERVICE_STATUS_HANDLE g_ssh;
inline void svcState(DWORD s) { SERVICE_STATUS st{}; st.dwServiceType = SERVICE_WIN32_OWN_PROCESS; st.dwCurrentState = s; st.dwControlsAccepted = s == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0; SetServiceStatus(g_ssh, &st); }
inline DWORD WINAPI svcCtrl(DWORD c, DWORD, LPVOID, LPVOID) { if (c == SERVICE_CONTROL_STOP || c == SERVICE_CONTROL_SHUTDOWN) { svcState(SERVICE_STOP_PENDING); g_quit = true; } return NO_ERROR; }
inline void WINAPI svcMain(DWORD, LPWSTR*) { g_ssh = RegisterServiceCtrlHandlerExW(SVC_NAME, svcCtrl, nullptr); svcState(SERVICE_RUNNING); serviceRun(); stopCapture(); svcState(SERVICE_STOPPED); }
inline int runService() { SERVICE_TABLE_ENTRYW t[] = { { (LPWSTR)SVC_NAME, svcMain }, { nullptr, nullptr } }; return StartServiceCtrlDispatcherW(t) ? 0 : 1; }
inline std::wstring exePath() { wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH); return p; }
inline bool uninstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); if (!scm) return false;
    SC_HANDLE s = OpenServiceW(scm, SVC_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS); bool ok = true;
    if (s) { SERVICE_STATUS st; ControlService(s, SERVICE_CONTROL_STOP, &st);
        for (int i = 0; i < 40 && QueryServiceStatus(s, &st) && st.dwCurrentState != SERVICE_STOPPED; i++) Sleep(100);
        ok = DeleteService(s) != 0; CloseServiceHandle(s); }
    CloseServiceHandle(scm); return ok;
}
inline bool installService() {
    uninstallService();
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE); if (!scm) return false;
    std::wstring cmd = L"\"" + exePath() + L"\" --service"; SC_HANDLE s = nullptr;
    for (int i = 0; i < 20 && !s; i++) { s = CreateServiceW(scm, SVC_NAME, L"MatrixSys capture service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr); if (!s) Sleep(150); }
    if (s) { SERVICE_DESCRIPTIONW d{ (LPWSTR)L"Collects network, disk and file-handle activity for the MatrixSys visualizer. Idle unless the viewer is open." }; ChangeServiceConfig2W(s, SERVICE_CONFIG_DESCRIPTION, &d); StartServiceW(s, 0, nullptr); CloseServiceHandle(s); }
    CloseServiceHandle(scm); return s != nullptr;
}
inline bool relaunchElevated(const wchar_t* args) { std::wstring e = exePath(); SHELLEXECUTEINFOW sei{ sizeof(sei) }; sei.lpVerb = L"runas"; sei.lpFile = e.c_str(); sei.lpParameters = args; sei.nShow = SW_SHOWNORMAL; return ShellExecuteExW(&sei) != 0; }
inline std::wstring knownFolder(REFKNOWNFOLDERID id) { PWSTR p = nullptr; std::wstring r; if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) r = p; CoTaskMemFree(p); return r; }
inline int doUninstall() {
    if (!isElevated()) { relaunchElevated(L"--uninstall"); return 0; }
    if (MessageBoxW(nullptr, L"Remove MatrixSys and its background service from this computer?", L"MatrixSys", MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
    uninstallService();
    DeleteFileW((knownFolder(FOLDERID_CommonPrograms) + L"\\MatrixSys.lnk").c_str()); DeleteFileW((knownFolder(FOLDERID_PublicDesktop) + L"\\MatrixSys.lnk").c_str());
    // only remove the folder the installer registered, never wherever this exe happens to be
    wchar_t loc[MAX_PATH] = L""; DWORD sz = sizeof(loc); RegGetValueW(HKEY_LOCAL_MACHINE, UNINST_KEY, L"InstallLocation", RRF_RT_REG_SZ, nullptr, loc, &sz);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, UNINST_KEY); RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"MatrixSys");
    std::wstring dir = exePath(); dir = dir.substr(0, dir.find_last_of(L'\\'));
    if (*loc && !_wcsicmp(loc, dir.c_str())) {
        std::wstring cmd = L"cmd.exe /c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"" + dir + L"\""; STARTUPINFOW si{ sizeof(si) }; PROCESS_INFORMATION pi{};
        wchar_t sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, sys, &si, &pi)) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
    }
    MessageBoxW(nullptr, L"MatrixSys has been removed.", L"MatrixSys", MB_OK | MB_ICONINFORMATION); return 0;
}
