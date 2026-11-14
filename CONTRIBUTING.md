# Contributing to MatrixSys

Thanks for wanting to help. Bug reports, ideas, screenshots of odd behaviour and pull requests are all welcome.

## Ways to help

- **Report a bug**: open an issue with the *Bug report* form. Say which tab you were on, whether the app ran as administrator or with the service, and attach a screenshot if you can.
- **Suggest a feature**: use the *Feature request* form, or start a thread in Discussions if it is still an idea.
- **Try it on other hardware**: different network adapters, disks, many monitors, Windows 10, ARM64. Tell us what breaks.
- **Send a fix or a feature**: see below.

## Building

You need Windows 10 or 11, 64-bit, and Visual Studio 2022 or later with the *Desktop development with C++* workload. Python 3 is only needed if you change the icon.

```bat
native\build.bat
```

The app and the installer land in `native\out\`. There are no other dependencies: everything uses the Windows SDK, except the optional page renderer, which uses Microsoft's WebView2 files checked in under `native/webview2/`.

Useful switches while developing:

| Switch | What it does |
|---|---|
| `--select <pid>` | starts with a process selected |
| `--memory <pid>` | opens the memory viewer on a process |
| `--size 0\|1\|2` | sizes processes by memory, lane traffic or CPU load |
| `--trace <target> [icmp\|tcp\|http\|https\|dns] [step]` | opens the Trace tab and starts a trace |
| `--demo-packets` | fills the packet viewer with synthetic packets, no administrator rights needed |
| `--service-console` | runs the capture service in the foreground |

## How the code is laid out

| File | What is in it |
|---|---|
| `native/main.cpp` | the scene model and layouts, rendering (Direct3D 11), the UI overlay (Direct2D), panels, actions and the window |
| `native/data.h` | collection: processes, sockets, ETW and raw-socket capture |
| `native/trace.h` | the Trace tab's engine: DNS, hop discovery, TCP, TLS (Schannel), HTTP |
| `native/web.h` | the optional rendered page view (WebView2) and its safety switches |
| `native/svc.h` | the background service, its named-pipe protocol, install and uninstall |
| `native/disks.h`, `native/devs.h` | the disk scan and the device tree |
| `native/setup.cpp` | the installer |

The UI is immediate mode: each frame, `drawUi()` draws the panels and reacts to the mouse, and buttons are plain function calls (`button(x, y, label, on)`). Actions go through one dispatcher with string keys such as `act:kill:<pid>`; anything destructive opens the red confirmation first.

## Pull requests

- Keep each pull request to one change, and describe what you tested and on which Windows version.
- Match the existing style: compact C++17, no new libraries without a good reason.
- Anything that ends processes, changes system settings or sends data off the machine needs a confirmation step and a clear label, like the existing actions.
- The build runs on every pull request; please make sure it passes.

## Security issues

Please do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is released under the [MIT License](LICENSE).
