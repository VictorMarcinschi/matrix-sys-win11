// Hardware device tree (as Device Manager shows it "by connection"), per-device traffic counters where Windows
// keeps them (disks, network adapters), and the machines seen on the local network behind each adapter.
#pragma once
#include "data.h"
#include <winioctl.h>
#include <cfgmgr32.h>
#include <devpropdef.h>
#include <objbase.h>
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "ole32.lib")

struct Dev { std::string inst, name, cls, mfg, guid; int parent = -1; bool problem = false, counters = false; uint64_t cumIn = 0, cumOut = 0; double rateIn = 0, rateOut = 0; };   // in = towards the PC
struct Nb { int dev; std::string ip, mac; bool gw; };
struct DevSnap { std::vector<Dev> devs; std::vector<Nb> nbs; double t = 0; };
inline std::mutex g_dvMx; inline std::shared_ptr<DevSnap> g_devSnap; inline std::atomic<bool> g_wantDevs{false};

inline const DEVPROPKEY DPK_DESC = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 2 };
inline const DEVPROPKEY DPK_CLASS = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 9 };
inline const DEVPROPKEY DPK_MFG = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 13 };
inline const DEVPROPKEY DPK_FRIENDLY = { { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 14 };
inline const GUID DISK_IFACE = { 0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b } };

inline std::string dvProp(DEVINST d, const DEVPROPKEY& k) {
    DEVPROPTYPE t; wchar_t buf[512]; ULONG sz = sizeof(buf);
    if (CM_Get_DevNode_PropertyW(d, &k, &t, (PBYTE)buf, &sz, 0) == CR_SUCCESS && t == DEVPROP_TYPE_STRING) return narrow(buf);
    return "";
}
inline void dvWalk(DEVINST d, int parent, DevSnap& s, std::vector<DEVINST>& insts) {
    wchar_t id[MAX_DEVICE_ID_LEN]; if (CM_Get_Device_IDW(d, id, MAX_DEVICE_ID_LEN, 0) != CR_SUCCESS) return;
    Dev v; v.inst = narrow(id); v.name = dvProp(d, DPK_FRIENDLY); if (v.name.empty()) v.name = dvProp(d, DPK_DESC); if (v.name.empty()) v.name = v.inst;
    v.cls = dvProp(d, DPK_CLASS); v.mfg = dvProp(d, DPK_MFG); v.parent = parent;
    ULONG st = 0, pr = 0; if (CM_Get_DevNode_Status(&st, &pr, d, 0) == CR_SUCCESS) v.problem = (st & DN_HAS_PROBLEM) != 0;
    if (v.cls == "Net") { HKEY hk; if (CM_Open_DevNode_Key(d, KEY_READ, 0, RegDisposition_OpenExisting, &hk, CM_REGISTRY_SOFTWARE) == CR_SUCCESS) { wchar_t g[64]; DWORD sz = sizeof(g); if (RegGetValueW(hk, nullptr, L"NetCfgInstanceId", RRF_RT_REG_SZ, nullptr, g, &sz) == ERROR_SUCCESS) v.guid = narrow(g); RegCloseKey(hk); } }
    int me = (int)s.devs.size(); s.devs.push_back(v); insts.push_back(d);
    DEVINST c; if (CM_Get_Child(&c, d, 0) == CR_SUCCESS) do { dvWalk(c, me, s, insts); } while (CM_Get_Sibling(&c, c, 0) == CR_SUCCESS);
}
inline void deviceThread() {
    std::unordered_map<std::string, HANDLE> disks; std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> prev; double prevT = 0;
    while (!g_quit) {
        if (!g_wantDevs) { Sleep(250); prevT = 0; continue; }
        auto s = std::make_shared<DevSnap>(); std::vector<DEVINST> insts; s->t = nowSec();
        DEVINST root; if (CM_Locate_DevNodeW(&root, nullptr, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS) dvWalk(root, -1, *s, insts);
        // network adapters: byte counters by interface GUID
        std::unordered_map<uint64_t, int> byLuid; PMIB_IF_TABLE2 it = nullptr;
        if (GetIfTable2(&it) == NO_ERROR) {
            for (ULONG i = 0; i < it->NumEntries; i++) { auto& r = it->Table[i]; wchar_t g[64]; StringFromGUID2(r.InterfaceGuid, g, 64); std::string gs = narrow(g);
                for (size_t k = 0; k < s->devs.size(); k++) if (!s->devs[k].guid.empty() && !_stricmp(s->devs[k].guid.c_str(), gs.c_str())) { s->devs[k].counters = true; s->devs[k].cumIn = r.InOctets; s->devs[k].cumOut = r.OutOctets; byLuid[r.InterfaceLuid.Value] = (int)k; } }
            FreeMibTable(it);
        }
        // disks: bytes read / written per physical drive
        for (size_t k = 0; k < s->devs.size(); k++) { Dev& d = s->devs[k]; if (d.cls != "DiskDrive") continue;
            auto h = disks.find(d.inst);
            if (h == disks.end()) { HANDLE fh = INVALID_HANDLE_VALUE; std::wstring id = widen(d.inst); ULONG len = 0;
                if (CM_Get_Device_Interface_List_SizeW(&len, (LPGUID)&DISK_IFACE, (DEVINSTID_W)id.c_str(), CM_GET_DEVICE_INTERFACE_LIST_PRESENT) == CR_SUCCESS && len > 1) { std::vector<wchar_t> buf(len);
                    if (CM_Get_Device_Interface_ListW((LPGUID)&DISK_IFACE, (DEVINSTID_W)id.c_str(), buf.data(), len, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) == CR_SUCCESS && buf[0]) fh = CreateFileW(buf.data(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr); }
                h = disks.emplace(d.inst, fh).first; }
            if (h->second != INVALID_HANDLE_VALUE) { DISK_PERFORMANCE dp{}; DWORD n = 0; if (DeviceIoControl(h->second, IOCTL_DISK_PERFORMANCE, nullptr, 0, &dp, sizeof(dp), &n, nullptr)) { d.counters = true; d.cumIn = dp.BytesRead.QuadPart; d.cumOut = dp.BytesWritten.QuadPart; } } }
        double dt = prevT ? s->t - prevT : 0;
        for (auto& d : s->devs) if (d.counters) { auto p = prev.find(d.inst); if (p != prev.end() && dt > 0) { d.rateIn = d.cumIn >= p->second.first ? double(d.cumIn - p->second.first) / dt : 0; d.rateOut = d.cumOut >= p->second.second ? double(d.cumOut - p->second.second) / dt : 0; } prev[d.inst] = { d.cumIn, d.cumOut }; }
        prevT = s->t;
        // machines on the local network (ARP cache), attached to the adapter that sees them
        std::set<std::string> gws; { ULONG sz = 1 << 16; std::vector<BYTE> ab(sz);
            if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, (IP_ADAPTER_ADDRESSES*)ab.data(), &sz) == NO_ERROR)
                for (auto* a = (IP_ADAPTER_ADDRESSES*)ab.data(); a; a = a->Next) for (auto* g = a->FirstGatewayAddress; g; g = g->Next) if (g->Address.lpSockaddr->sa_family == AF_INET) gws.insert(ip4s(&((sockaddr_in*)g->Address.lpSockaddr)->sin_addr)); }
        PMIB_IPNET_TABLE2 nt = nullptr; std::set<std::string> seen;
        if (GetIpNetTable2(AF_INET, &nt) == NO_ERROR) {
            for (ULONG i = 0; i < nt->NumEntries; i++) { auto& r = nt->Table[i]; auto dv = byLuid.find(r.InterfaceLuid.Value); if (dv == byLuid.end()) continue;
                if (r.State == NlnsUnreachable || r.State == NlnsIncomplete || r.PhysicalAddressLength != 6) continue; const UCHAR* m = r.PhysicalAddress; const UCHAR* a = (const UCHAR*)&r.Address.Ipv4.sin_addr;
                if ((a[0] >= 224) || a[3] == 255 || (m[0] & 1) || !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5])) continue;   // multicast, broadcast
                char mac[24]; snprintf(mac, 24, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]); std::string ip = ip4s(a);
                if (seen.insert(ip).second) s->nbs.push_back({ dv->second, ip, mac, gws.count(ip) > 0 }); }
            FreeMibTable(nt);
        }
        { std::lock_guard<std::mutex> l(g_dvMx); g_devSnap = s; }
        for (int i = 0; i < 10 && !g_quit && g_wantDevs; i++) Sleep(100);
    }
}
