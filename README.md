# MatrixSys

A native, fully offline 3D visualizer of a Windows 11 machine: processes, the data they exchange, network traffic, memory, open files, disks and devices, with controls to act on what it shows. Dark scene, glowing blue-cyan wireframes.

![icon](native/matrixsys.png)

## Views

- **Processes** – the process tree in 3D, with lanes for data exchanged between processes.
- **Network** – processes, their ports and remote hosts; one dot per packet when capture is live.
- **Memory** – treemap of physical memory by program.
- **Files** – which process has which files open.
- **Disks** – every partition, used and free space, broken down by folder recursively.
- **Devices** – connected hardware, network neighbours, and traffic between them.

Also: lists of processes by lane traffic and of open ports, a packet viewer with hex dump, a process memory viewer, reverse DNS and owner lookup for remote addresses, and actions (suspend, kill, priority, firewall block, close connection, recycle folder, eject device, and more). Dangerous actions are red and ask for confirmation.

## Build

Requires Visual Studio with the C++ tools and Python 3 (only to generate the icon). No third-party dependencies.

```bat
native\build.bat
```

Output goes to `native\out\`:

- `MatrixSys.exe` – the app.
- `MatrixSys-Setup.exe` – the installer (shortcuts, optional background service started at boot, uninstaller).

## Privileges

The app runs unprivileged and shows estimated traffic. **REQUEST ADMIN** relaunches it elevated to capture real packets. The optional service does the accounting at boot so the unprivileged app gets real numbers; the service never captures packet contents.

Command-line switches: `--tray`, `--select <pid>`, `--memory <pid>`, `--size <0|1|2>` (size processes by memory, lane traffic or CPU load), `--demo-packets`, `--install-service`, `--uninstall-service`, `--service-console`, `--uninstall`.

## Layout

| Path | What |
|---|---|
| `native/main.cpp` | scene, layout, rendering (Direct3D 11), UI (Direct2D), actions |
| `native/data.h` | process, socket and capture collection (ETW, raw sockets) |
| `native/svc.h` | background service, named-pipe protocol, install/uninstall |
| `native/disks.h` | disk scan |
| `native/devs.h` | device tree and counters |
| `native/setup.cpp` | installer |
| `native/make_icon.py` | icon generator |
| `index.html`, `server.py`, `collector.ps1`, `capture.py` | the first, web-based prototype (superseded by the native app) |
| `MatrixSys-macOS-prompt.md` | specification for a macOS port |

## License

[MIT](LICENSE)
