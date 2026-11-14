// MatrixSys-Setup - self-contained installer. MatrixSys.exe is embedded as a resource; nothing is downloaded.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winsvc.h>
#include <string>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

static const wchar_t* UNINST_KEY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MatrixSys";
static HWND cbStart, cbDesk, cbSvc, cbWeb, cbRun, btnGo, lblStatus;
static HFONT font, fontBig;

static std::wstring knownFolder(REFKNOWNFOLDERID id) { PWSTR p = nullptr; std::wstring r; if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) r = p; CoTaskMemFree(p); return r; }
static bool shortcut(const std::wstring& lnk, const std::wstring& target, const std::wstring& dir) {
    IShellLinkW* sl = nullptr; bool ok = false;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&sl)))) {
        sl->SetPath(target.c_str()); sl->SetWorkingDirectory(dir.c_str()); sl->SetDescription(L"3D visualizer of processes, network traffic, files and memory");
        IPersistFile* pf = nullptr; if (SUCCEEDED(sl->QueryInterface(IID_PPV_ARGS(&pf)))) { ok = SUCCEEDED(pf->Save(lnk.c_str(), TRUE)); pf->Release(); }
        sl->Release();
    }
    return ok;
}
static bool run(const std::wstring& exe, const std::wstring& args, bool wait) {
    std::wstring cmd = L"\"" + exe + L"\" " + args; STARTUPINFOW si{ sizeof(si) }; PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return false;
    DWORD code = 0; if (wait) { WaitForSingleObject(pi.hProcess, 30000); GetExitCodeProcess(pi.hProcess, &code); }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return code == 0;
}
static void stopService() {   // so an upgrade can overwrite the exe
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); if (!scm) return;
    if (SC_HANDLE s = OpenServiceW(scm, L"MatrixSysSvc", SERVICE_STOP | SERVICE_QUERY_STATUS)) { SERVICE_STATUS st; ControlService(s, SERVICE_CONTROL_STOP, &st);
        for (int i = 0; i < 40 && QueryServiceStatus(s, &st) && st.dwCurrentState != SERVICE_STOPPED; i++) Sleep(100); CloseServiceHandle(s); }
    CloseServiceHandle(scm);
}
static std::wstring install(bool start, bool desk, bool svc, bool web) {
    std::wstring dir = knownFolder(FOLDERID_ProgramFiles) + L"\\MatrixSys", exe = dir + L"\\MatrixSys.exe";
    CreateDirectoryW(dir.c_str(), nullptr); stopService();
    HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(2), RT_RCDATA); if (!res) return L"The installer is damaged (no payload).";
    HGLOBAL hg = LoadResource(nullptr, res); DWORD size = SizeofResource(nullptr, res), wr = 0;
    HANDLE f = INVALID_HANDLE_VALUE; for (int i = 0; i < 20 && f == INVALID_HANDLE_VALUE; i++) { f = CreateFileW(exe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr); if (f == INVALID_HANDLE_VALUE) Sleep(150); }
    if (f == INVALID_HANDLE_VALUE) return L"Could not write " + exe + L".\nClose MatrixSys if it is running and try again.";
    bool ok = WriteFile(f, LockResource(hg), size, &wr, nullptr) && wr == size; CloseHandle(f); if (!ok) return L"Could not write the program file.";
    // optional component: the page renderer's loader. Without it the app shows web pages as text.
    std::wstring dll = dir + L"\\WebView2Loader.dll"; DeleteFileW(dll.c_str());
    if (web) { HRSRC r3 = FindResourceW(nullptr, MAKEINTRESOURCEW(3), RT_RCDATA); HGLOBAL g3 = r3 ? LoadResource(nullptr, r3) : nullptr; DWORD s3 = r3 ? SizeofResource(nullptr, r3) : 0, w3 = 0;
        HANDLE d = g3 ? CreateFileW(dll.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) : INVALID_HANDLE_VALUE;
        if (d == INVALID_HANDLE_VALUE) return L"MatrixSys was installed, but the page renderer component could not be written.";
        bool ok3 = WriteFile(d, LockResource(g3), s3, &w3, nullptr) && w3 == s3; CloseHandle(d); if (!ok3) return L"MatrixSys was installed, but the page renderer component could not be written."; size += s3; }
    DeleteFileW((knownFolder(FOLDERID_CommonPrograms) + L"\\MatrixSys.lnk").c_str()); DeleteFileW((knownFolder(FOLDERID_PublicDesktop) + L"\\MatrixSys.lnk").c_str());
    if (start) shortcut(knownFolder(FOLDERID_CommonPrograms) + L"\\MatrixSys.lnk", exe, dir);
    if (desk) shortcut(knownFolder(FOLDERID_PublicDesktop) + L"\\MatrixSys.lnk", exe, dir);
    HKEY k; if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, UNINST_KEY, 0, nullptr, 0, KEY_WRITE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        auto set = [&](const wchar_t* n, const std::wstring& v) { RegSetValueExW(k, n, 0, REG_SZ, (const BYTE*)v.c_str(), (DWORD)(v.size() + 1) * 2); };
        set(L"DisplayName", L"MatrixSys"); set(L"DisplayVersion", L"0.4.0"); set(L"Publisher", L"MatrixSys"); set(L"DisplayIcon", exe); set(L"InstallLocation", dir);
        set(L"UninstallString", L"\"" + exe + L"\" --uninstall");
        DWORD one = 1, kb = size / 1024; RegSetValueExW(k, L"NoModify", 0, REG_DWORD, (BYTE*)&one, 4); RegSetValueExW(k, L"NoRepair", 0, REG_DWORD, (BYTE*)&one, 4); RegSetValueExW(k, L"EstimatedSize", 0, REG_DWORD, (BYTE*)&kb, 4);
        RegCloseKey(k);
    }
    if (svc) { if (!run(exe, L"--install-service", true)) return L"MatrixSys was installed, but the background service could not be registered."; }
    else run(exe, L"--uninstall-service", true);
    return L"";
}
static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_COMMAND: if (LOWORD(wp) == 1) {
        EnableWindow(btnGo, FALSE); SetWindowTextW(lblStatus, L"Installing..."); UpdateWindow(h);
        bool runAfter = SendMessageW(cbRun, BM_GETCHECK, 0, 0) == BST_CHECKED;
        std::wstring err = install(SendMessageW(cbStart, BM_GETCHECK, 0, 0) == BST_CHECKED, SendMessageW(cbDesk, BM_GETCHECK, 0, 0) == BST_CHECKED, SendMessageW(cbSvc, BM_GETCHECK, 0, 0) == BST_CHECKED, SendMessageW(cbWeb, BM_GETCHECK, 0, 0) == BST_CHECKED);
        if (!err.empty()) { MessageBoxW(h, err.c_str(), L"MatrixSys Setup", MB_OK | MB_ICONWARNING); SetWindowTextW(lblStatus, L""); EnableWindow(btnGo, TRUE); return 0; }
        MessageBoxW(h, L"MatrixSys is installed.\n\nTo remove it later, use Settings > Apps > Installed apps.", L"MatrixSys Setup", MB_OK | MB_ICONINFORMATION);
        // start the app through Explorer so it runs with the normal user rights, not the installer's
        if (runAfter) { std::wstring exe = L"\"" + knownFolder(FOLDERID_ProgramFiles) + L"\\MatrixSys\\MatrixSys.exe\""; ShellExecuteW(nullptr, L"open", L"explorer.exe", exe.c_str(), nullptr, SW_SHOWNORMAL); }
        DestroyWindow(h);
    } else if (LOWORD(wp) == 2) DestroyWindow(h); return 0;
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)wp, TRANSPARENT); return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR, int) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); SetProcessDPIAware();
    HDC dc = GetDC(nullptr); float s = GetDeviceCaps(dc, LOGPIXELSX) / 96.f; ReleaseDC(nullptr, dc); auto S = [&](int v) { return (int)(v * s); };
    WNDCLASSW wc{}; wc.lpfnWndProc = proc; wc.hInstance = hi; wc.lpszClassName = L"MatrixSysSetup"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.hbrBackground = GetSysColorBrush(COLOR_WINDOW); wc.hIcon = LoadIconW(hi, MAKEINTRESOURCEW(1)); RegisterClassW(&wc);
    int W = S(520), H = S(478); RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    HWND w = CreateWindowExW(0, L"MatrixSysSetup", L"MatrixSys Setup", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, (wa.left + wa.right - W) / 2, (wa.top + wa.bottom - H) / 2, W, H, nullptr, nullptr, hi, nullptr);
    font = CreateFontW(-S(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI"); fontBig = CreateFontW(-S(22), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int cw, int ch, int id, HFONT f) { HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, S(x), S(y), S(cw), S(ch), w, (HMENU)(INT_PTR)id, hi, nullptr); SendMessageW(c, WM_SETFONT, (WPARAM)f, TRUE); return c; };
    HWND ic = mk(L"STATIC", nullptr, SS_ICON, 24, 20, 48, 48, 0, font); SendMessageW(ic, STM_SETICON, (WPARAM)LoadImageW(hi, MAKEINTRESOURCEW(1), IMAGE_ICON, S(48), S(48), 0), 0);
    mk(L"STATIC", L"Install MatrixSys", 0, 88, 20, 400, 30, 0, fontBig);
    mk(L"STATIC", L"3D visualizer of processes, network traffic, open files and memory.\nInstalls to Program Files\\MatrixSys.", 0, 88, 54, 410, 40, 0, font);
    cbStart = mk(L"BUTTON", L"Add a Start menu shortcut", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 112, 460, 24, 10, font);
    cbDesk = mk(L"BUTTON", L"Add a desktop shortcut", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 140, 460, 24, 11, font);
    cbSvc = mk(L"BUTTON", L"Install the background capture service (starts with Windows)", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 168, 460, 24, 12, font);
    mk(L"STATIC", L"The service runs as SYSTEM and lets the app show real network and disk traffic without an administrator prompt each time. It stays idle while the app is closed. Anyone signed in on this PC can read that activity while it runs.", 0, 46, 194, 440, 74, 0, font);
    cbWeb = mk(L"BUTTON", L"Install the web page renderer (optional)", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 272, 460, 24, 14, font);
    mk(L"STATIC", L"Lets the Trace tab show HTML responses as rendered pages, using the Microsoft Edge WebView2 runtime that is part of Windows. Without it they are shown as text.", 0, 46, 298, 440, 52, 0, font);
    cbRun = mk(L"BUTTON", L"Start MatrixSys when setup finishes", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 352, 460, 24, 13, font);
    lblStatus = mk(L"STATIC", L"", 0, 28, 400, 240, 24, 0, font);
    btnGo = mk(L"BUTTON", L"Install", BS_DEFPUSHBUTTON | WS_TABSTOP, 284, 394, 100, 32, 1, font); mk(L"BUTTON", L"Cancel", WS_TABSTOP, 392, 394, 100, 32, 2, font);
    SendMessageW(cbStart, BM_SETCHECK, BST_CHECKED, 0); SendMessageW(cbRun, BM_SETCHECK, BST_CHECKED, 0); SendMessageW(cbWeb, BM_SETCHECK, BST_CHECKED, 0);
    ShowWindow(w, SW_SHOW);
    MSG msg; while (GetMessageW(&msg, nullptr, 0, 0)) { if (!IsDialogMessageW(w, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
    return 0;
}
