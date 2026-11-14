// web.h - optional rendered view of an HTML response captured by the trace, using the Microsoft Edge WebView2 runtime.
// The loader (WebView2Loader.dll) is an optional component next to the exe; without it, or without the runtime, the app shows text.
// The page that is shown is the captured response itself: the document request is answered from memory, never fetched again.
// Everything else the page asks for goes through one filter that applies the options below.
#pragma once
#include "data.h"
#include "svc.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <wrl/client.h>
#include <functional>
#include <set>
#include "webview2/WebView2.h"
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

struct WebOpts { bool js = false, cookies = false, resources = false, thirdParty = false, xssGuard = true; };
struct WebState {
    bool tried = false, available = false, creating = false, ready = false, failed = false, visible = false, wantClose = false, serveNext = false, loaded = false, loadOk = false;
    std::string why, pageUrl, pageHost, pageType, pageCsp, page; std::wstring blockedNav; int navAllowed = 0, blocked = 0, loadedN = 0, cookieCount = -1; std::set<std::string> blockedHosts;
    WebOpts o; RECT rc{}; HWND parent = nullptr; HMODULE loader = nullptr; bool pending = false; std::wstring cookieScript;   // id of the script that hides document.cookie
    Microsoft::WRL::ComPtr<ICoreWebView2Environment> env; Microsoft::WRL::ComPtr<ICoreWebView2Controller> ctl; Microsoft::WRL::ComPtr<ICoreWebView2> view;
};
inline WebState g_web;

// a COM callback around a lambda (what WRL's Callback<> does, without the WebView2 helper headers)
template <class I, class... A> struct WvCb : I {
    std::function<HRESULT(A...)> f; ULONG rc = 1; explicit WvCb(std::function<HRESULT(A...)> fn) : f(std::move(fn)) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** p) override { if (riid == IID_IUnknown || riid == __uuidof(I)) { *p = static_cast<I*>(this); AddRef(); return S_OK; } *p = nullptr; return E_NOINTERFACE; }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++rc; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG r = --rc; if (!r) delete this; return r; }
    HRESULT STDMETHODCALLTYPE Invoke(A... a) override { return f(a...); }
};
template <class T> struct WvId { typedef T type; };   // keeps the lambda argument out of template deduction
template <class I, class... A> Microsoft::WRL::ComPtr<I> wvCb(typename WvId<std::function<HRESULT(A...)>>::type fn) { Microsoft::WRL::ComPtr<I> p; p.Attach(new WvCb<I, A...>(std::move(fn))); return p; }

inline std::string webLower(std::string s) { for (auto& c : s) c = (char)tolower((unsigned char)c); return s; }
inline std::string webHostOf(const std::string& url) {   // "" for addresses that do not touch the network (data:, blob:, about:)
    size_t p = url.find("://"); if (p == std::string::npos) return ""; std::string sc = webLower(url.substr(0, p)); if (sc != "http" && sc != "https" && sc != "ws" && sc != "wss") return "";
    size_t s = p + 3, e = url.find_first_of("/?#", s); std::string h = url.substr(s, e == std::string::npos ? std::string::npos : e - s); size_t at = h.rfind('@'); if (at != std::string::npos) h = h.substr(at + 1);
    size_t col = h.rfind(':'); if (col != std::string::npos && h.find(']') == std::string::npos) h = h.substr(0, col); return webLower(h);
}
// the registrable part of a host name, roughly: example.com for www.example.com, example.co.uk for www.example.co.uk
inline std::string webSite(const std::string& host) {
    std::vector<std::string> l; size_t s = 0; while (s <= host.size()) { size_t e = host.find('.', s); if (e == std::string::npos) e = host.size(); l.push_back(host.substr(s, e - s)); s = e + 1; }
    if (l.size() <= 2 || (l.back().find_first_not_of("0123456789") == std::string::npos)) return host;   // short names and IP addresses stand for themselves
    size_t keep = l.back().size() == 2 && l[l.size() - 2].size() <= 3 ? 3 : 2; std::string r; for (size_t i = l.size() - std::min(keep, l.size()); i < l.size(); i++) { if (!r.empty()) r += '.'; r += l[i]; } return r;
}
inline bool webSameSite(const std::string& host) { return host == g_web.pageHost || webSite(host) == webSite(g_web.pageHost); }

// Is the renderer there? Looks for the loader next to the exe (never on the search path) and asks it for the runtime.
inline bool webAvailable() {
    WebState& w = g_web; if (w.tried) return w.available; w.tried = true;
    std::wstring dir = exePath(); dir = dir.substr(0, dir.find_last_of(L'\\')); std::wstring dll = dir + L"\\WebView2Loader.dll";
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) { w.why = "The page renderer is not installed. It is an optional component of MatrixSys Setup."; return false; }
    w.loader = LoadLibraryExW(dll.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH); if (!w.loader) { w.why = "The page renderer component could not be loaded."; return false; }
    typedef HRESULT(STDAPICALLTYPE * VerFn)(PCWSTR, LPWSTR*); auto ver = (VerFn)GetProcAddress(w.loader, "GetAvailableCoreWebView2BrowserVersionString"); LPWSTR v = nullptr;
    if (!ver || FAILED(ver(nullptr, &v)) || !v) { w.why = "The Microsoft Edge WebView2 runtime is not installed on this computer."; return false; }
    CoTaskMemFree(v); w.available = true; return true;
}
inline void webApplySettings() {
    WebState& w = g_web; Microsoft::WRL::ComPtr<ICoreWebView2Settings> s; if (!w.view || FAILED(w.view->get_Settings(&s))) return;
    s->put_IsScriptEnabled(w.o.js); s->put_AreDefaultScriptDialogsEnabled(FALSE); s->put_IsWebMessageEnabled(FALSE); s->put_AreDevToolsEnabled(FALSE); s->put_AreDefaultContextMenusEnabled(FALSE);
    s->put_IsStatusBarEnabled(FALSE); s->put_AreHostObjectsAllowed(FALSE); s->put_IsBuiltInErrorPageEnabled(FALSE);
    Microsoft::WRL::ComPtr<ICoreWebView2Settings4> s4; if (SUCCEEDED(s.As(&s4))) { s4->put_IsPasswordAutosaveEnabled(FALSE); s4->put_IsGeneralAutofillEnabled(FALSE); }
}
inline void webClearCookies() { Microsoft::WRL::ComPtr<ICoreWebView2_2> v2; Microsoft::WRL::ComPtr<ICoreWebView2CookieManager> cm; if (g_web.view && SUCCEEDED(g_web.view.As(&v2)) && SUCCEEDED(v2->get_CookieManager(&cm))) cm->DeleteAllCookies(); g_web.cookieCount = 0; }
inline void webCountCookies() {   // after a page has loaded: how many cookies are in the store; with cookies off the store is emptied again
    Microsoft::WRL::ComPtr<ICoreWebView2_2> v2; Microsoft::WRL::ComPtr<ICoreWebView2CookieManager> cm; if (!g_web.view || FAILED(g_web.view.As(&v2)) || FAILED(v2->get_CookieManager(&cm))) return;
    cm->GetCookies(L"", wvCb<ICoreWebView2GetCookiesCompletedHandler, HRESULT, ICoreWebView2CookieList*>([](HRESULT hr, ICoreWebView2CookieList* list) -> HRESULT {
        UINT n = 0; if (SUCCEEDED(hr) && list) list->get_Count(&n); g_web.cookieCount = (int)n; if (!g_web.o.cookies && n) webClearCookies(); return S_OK; }).Get());
}
inline void webNavigate() {   // shows the captured page with the current options
    WebState& w = g_web; if (!w.ready || !w.view) { w.pending = true; return; } w.pending = false;
    webApplySettings(); if (!w.o.cookies) webClearCookies();
    auto go = [] { WebState& w = g_web; if (!w.view || !w.visible) return; w.blocked = w.loadedN = 0; w.blockedHosts.clear(); w.loaded = false; w.cookieCount = -1; w.serveNext = true; w.navAllowed = 1;
        w.view->CallDevToolsProtocolMethod(L"Network.clearBrowserCache", L"{}", nullptr); w.view->Navigate(widen(w.pageUrl).c_str()); };
    // with cookies off, scripts also get a document without cookies (the store itself is emptied before and after the page)
    if (!w.o.cookies && w.cookieScript.empty()) w.view->AddScriptToExecuteOnDocumentCreated(L"try { Object.defineProperty(document, 'cookie', { get: function () { return ''; }, set: function () {} }); } catch (e) {}",
        wvCb<ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler, HRESULT, LPCWSTR>([go](HRESULT, LPCWSTR id) -> HRESULT { if (id) g_web.cookieScript = id; go(); return S_OK; }).Get());
    else { if (w.o.cookies && !w.cookieScript.empty()) { w.view->RemoveScriptToExecuteOnDocumentCreated(w.cookieScript.c_str()); w.cookieScript.clear(); } go(); }
}
inline void webWire() {   // one-time event handlers: this is where every policy is enforced
    WebState& w = g_web; EventRegistrationToken tk;
    w.view->AddWebResourceRequestedFilter(L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL);
    // no HTTP cache: a cached copy would be used without passing the filter below
    w.view->CallDevToolsProtocolMethod(L"Network.enable", L"{}", nullptr); w.view->CallDevToolsProtocolMethod(L"Network.setCacheDisabled", L"{\"cacheDisabled\":true}", nullptr);
    w.view->add_WebResourceRequested(wvCb<ICoreWebView2WebResourceRequestedEventHandler, ICoreWebView2*, ICoreWebView2WebResourceRequestedEventArgs*>([](ICoreWebView2*, ICoreWebView2WebResourceRequestedEventArgs* a) -> HRESULT {
        WebState& w = g_web; Microsoft::WRL::ComPtr<ICoreWebView2WebResourceRequest> rq; LPWSTR u = nullptr; if (FAILED(a->get_Request(&rq)) || FAILED(rq->get_Uri(&u)) || !u) return S_OK; std::string url = narrow(u); CoTaskMemFree(u);
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT cx = COREWEBVIEW2_WEB_RESOURCE_CONTEXT_OTHER; a->get_ResourceContext(&cx);
        Microsoft::WRL::ComPtr<ICoreWebView2WebResourceResponse> rs;
        if (w.serveNext && cx == COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT) {   // the page itself: answered from the captured bytes
            w.serveNext = false; Microsoft::WRL::ComPtr<IStream> st; st.Attach(SHCreateMemStream((const BYTE*)w.page.data(), (UINT)w.page.size()));
            std::string h = "Content-Type: " + (w.pageType.empty() ? std::string("text/html") : w.pageType) + "\r\nCache-Control: no-store";
            if (!w.pageCsp.empty()) h += "\r\nContent-Security-Policy: " + w.pageCsp;   // the site's own policy stays in force
            if (w.o.xssGuard) h += "\r\nContent-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self'";   // inline and foreign scripts cannot run
            if (SUCCEEDED(w.env->CreateWebResourceResponse(st.Get(), 200, L"OK", widen(h).c_str(), &rs))) a->put_Response(rs.Get()); return S_OK; }
        std::string host = webHostOf(url); if (host.empty()) return S_OK;   // data:, blob:, about: stay inside the page
        bool allow = w.o.resources && (w.o.thirdParty || webSameSite(host));
        if (allow) { w.loadedN++; return S_OK; }
        w.blocked++; if (w.blockedHosts.size() < 200) w.blockedHosts.insert(host);
        if (SUCCEEDED(w.env->CreateWebResourceResponse(nullptr, 403, L"Blocked", L"", &rs))) a->put_Response(rs.Get()); return S_OK; }).Get(), &tk);
    w.view->add_NavigationStarting(wvCb<ICoreWebView2NavigationStartingEventHandler, ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs*>([](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* a) -> HRESULT {
        WebState& w = g_web; LPWSTR u = nullptr; a->get_Uri(&u); std::wstring url = u ? u : L""; CoTaskMemFree(u);
        if (url == L"about:blank") return S_OK; if (w.navAllowed > 0) { w.navAllowed--; return S_OK; }
        a->put_Cancel(TRUE); w.blockedNav = url; return S_OK; }).Get(), &tk);   // links, forms and script redirects go nowhere
    w.view->add_NavigationCompleted(wvCb<ICoreWebView2NavigationCompletedEventHandler, ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs*>([](ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs* a) -> HRESULT {
        BOOL ok = FALSE; a->get_IsSuccess(&ok); g_web.loaded = true; g_web.loadOk = ok != FALSE; webCountCookies(); return S_OK; }).Get(), &tk);
    w.view->add_NewWindowRequested(wvCb<ICoreWebView2NewWindowRequestedEventHandler, ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs*>([](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* a) -> HRESULT {
        LPWSTR u = nullptr; a->get_Uri(&u); if (u) { g_web.blockedNav = u; CoTaskMemFree(u); } a->put_Handled(TRUE); return S_OK; }).Get(), &tk);   // no popups, no new windows
    w.view->add_PermissionRequested(wvCb<ICoreWebView2PermissionRequestedEventHandler, ICoreWebView2*, ICoreWebView2PermissionRequestedEventArgs*>([](ICoreWebView2*, ICoreWebView2PermissionRequestedEventArgs* a) -> HRESULT {
        a->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY); return S_OK; }).Get(), &tk);   // camera, microphone, location, notifications, clipboard
    Microsoft::WRL::ComPtr<ICoreWebView2_4> v4; if (SUCCEEDED(w.view.As(&v4))) v4->add_DownloadStarting(wvCb<ICoreWebView2DownloadStartingEventHandler, ICoreWebView2*, ICoreWebView2DownloadStartingEventArgs*>([](ICoreWebView2*, ICoreWebView2DownloadStartingEventArgs* a) -> HRESULT {
        a->put_Cancel(TRUE); a->put_Handled(TRUE); return S_OK; }).Get(), &tk);
    w.ctl->add_AcceleratorKeyPressed(wvCb<ICoreWebView2AcceleratorKeyPressedEventHandler, ICoreWebView2Controller*, ICoreWebView2AcceleratorKeyPressedEventArgs*>([](ICoreWebView2Controller*, ICoreWebView2AcceleratorKeyPressedEventArgs* a) -> HRESULT {
        UINT k = 0; COREWEBVIEW2_KEY_EVENT_KIND kind; a->get_VirtualKey(&k); a->get_KeyEventKind(&kind); if (k == VK_ESCAPE && kind == COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN) { g_web.wantClose = true; a->put_Handled(TRUE); } return S_OK; }).Get(), &tk);
}
inline void webCreate(HWND parent) {
    WebState& w = g_web; if (w.creating || w.ready || w.failed || !webAvailable()) return; w.creating = true; w.parent = parent;
    typedef HRESULT(STDAPICALLTYPE * EnvFn)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
    auto mk = (EnvFn)GetProcAddress(w.loader, "CreateCoreWebView2EnvironmentWithOptions"); std::wstring data = knownFolder(FOLDERID_LocalAppData) + L"\\MatrixSys"; CreateDirectoryW(data.c_str(), nullptr); data += L"\\WebView";
    auto fail = [](const char* why) { g_web.failed = true; g_web.creating = false; g_web.available = false; g_web.why = why; };
    HRESULT hr = mk ? mk(nullptr, data.c_str(), nullptr, wvCb<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, HRESULT, ICoreWebView2Environment*>([fail](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
        if (FAILED(hr) || !env) { fail("The page engine could not be started."); return S_OK; } g_web.env = env;
        env->CreateCoreWebView2Controller(g_web.parent, wvCb<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler, HRESULT, ICoreWebView2Controller*>([fail](HRESULT hr, ICoreWebView2Controller* c) -> HRESULT {
            WebState& w = g_web; if (FAILED(hr) || !c || FAILED(c->get_CoreWebView2(&w.view))) { fail("The page engine could not open a view."); return S_OK; }
            w.ctl = c; webWire(); w.ctl->put_Bounds(w.rc); w.ctl->put_IsVisible(w.visible); w.creating = false; w.ready = true; if (w.pending) webNavigate(); return S_OK; }).Get());
        return S_OK; }).Get()) : E_FAIL;
    if (FAILED(hr)) fail("The page engine could not be started.");
}
// Shows the captured page inside rc (client pixels of parent).
inline void webShow(HWND parent, RECT rc, const std::string& url, const std::string& ctype, const std::string& csp, const std::string& page) {
    WebState& w = g_web; w.pageUrl = url; w.pageHost = webHostOf(url); w.pageType = ctype; w.pageCsp = csp; w.page = page; w.rc = rc; w.visible = true; w.wantClose = false; w.blockedNav.clear();
    if (w.ready) { w.ctl->put_Bounds(rc); w.ctl->put_IsVisible(TRUE); webNavigate(); } else { w.pending = true; webCreate(parent); }
}
inline void webBounds(RECT rc) { WebState& w = g_web; if (memcmp(&rc, &w.rc, sizeof(rc)) == 0) return; w.rc = rc; if (w.ready) w.ctl->put_Bounds(rc); }
inline void webHide() { WebState& w = g_web; if (!w.visible) return; w.visible = false; w.pending = false; if (w.ready) { w.ctl->put_IsVisible(FALSE); w.view->Navigate(L"about:blank"); if (!w.o.cookies) webClearCookies(); } }
inline void webShutdown() { if (g_web.ctl) g_web.ctl->Close(); g_web.view.Reset(); g_web.ctl.Reset(); g_web.env.Reset(); }
