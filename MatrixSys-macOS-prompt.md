# Build MatrixSys for macOS

I have a Windows utility called **MatrixSys**: a native, fully offline 3D visualizer of everything running on the machine — processes, the data they exchange, network traffic, memory, open files, disks and devices — with controls to act on what it shows. I want the same utility for macOS, as close to the Windows one as the platform allows.

This prompt describes the Windows app in full: what it does, how it looks, the decisions that were made and the mistakes that were already paid for. Treat the feature set, the look and the interaction model as the specification. Treat the Windows APIs as illustration only.

**macOS-specific changes are welcome and required.** Wherever macOS works differently (permissions, privileged helpers, menu bar, APFS, no CPU affinity, protected processes, app bundles), do it the Mac way rather than imitating Windows. Where a Windows feature has no honest Mac equivalent, replace it with the closest useful Mac feature or leave it out, and tell me which and why. Do not fake data to keep a feature.

If a folder named `windows-reference/` exists in the working directory, it holds the Windows source (`main.cpp`, `data.h`, `svc.h`, `disks.h`, `devs.h`, `setup.cpp`, `make_icon.py`). Read it for exact layout maths, colours and panel contents. If it is absent, this prompt is enough.

## Ground rules

- **Native and offline.** No web view, no Electron, no bundled runtime, no third-party dependencies beyond the macOS SDK. The only network traffic the app itself makes is reverse DNS (system resolver) and the owner lookup, and the owner lookup happens only when I press its button.
- **Real data only.** Every number and every moving dot must come from the system. When exact per-packet data is unavailable (no privileges), the app says so on screen and shows estimates labelled as estimates.
- **Start by checking the toolchain** (Xcode or the command line tools, Swift version, macOS version, Apple silicon or Intel) and choose accordingly. My recommendation: Swift + AppKit + Metal, built by a script (`swiftc` or SwiftPM plus a small bundling script) so that no hand-maintained Xcode project is needed. If you judge another choice better, make it and say why.
- **Build in stages and run each stage.** The Windows app grew in this order and it worked well: process view → network → memory → real capture and privileges → pan and camera → files → time windows → background service → menu bar → disks → devices → hex viewers → ports list and host names → actions → lists, sorting, keyboard navigation. Launch the app after each stage and look at it (a screenshot of its window) before moving on.
- **Report honestly.** At the end of each stage say what you ran and saw, and what you could not test (anything needing my password, a permission prompt, or a destructive action). Never run destructive actions on real targets to test them: use a throwaway process such as `ping` or `sleep`, a temp folder, and so on.
- Ask me only for decisions that are mine: signing identity (Developer ID or ad hoc), whether to install the privileged helper, permission prompts. Otherwise pick the sensible default and carry on.

## Look and feel

The scene is "the Internet visualizer from Neuromancer": a dark void with glowing blue-cyan wireframe structures.

- Background almost black-blue: RGB (1, 6, 15). Dominant colour cyan `#4fe3ff`, secondary blue `#2a7fff`.
- Additive blending for everything in the 3D scene, so overlapping lines glow. Anti-aliased (MSAA) rendering. Distance fog towards the background colour.
- Palette: text `#bfefff`, cyan `#4fe3ff`, dim `#5d8aa8`, inbound `#5ff2ff`, outbound `#ff4fd8` (magenta), warning `#ffb347` (amber), white, safe `#3dffc8` (green), danger `#ff4b5c` (red).
- Nodes are wireframe solids (boxes, octahedra); lanes are lines between them; traffic is small bright dots travelling along the lanes, one dot per packet or per bundle of packets, coloured by direction.
- UI is a monospaced, immediate-mode overlay drawn over the scene: a top bar with the view tabs and status, a right-hand detail panel for the selection, a legend with a stats line, tooltips on hover, toasts for results. Flat translucent dark panels with thin cyan borders. No standard system controls inside the window.
- The Windows renderer is deliberately simple: one dynamic vertex buffer refilled every frame with lines and triangles, one shader, plus a 2D text/rect overlay. Keep that simplicity in Metal.
- Icon: a glowing cyan wireframe octahedron on a dark rounded square. Generate it with a script and produce a proper `.icns`.

## Camera and input

- Left-drag orbits. Right-drag, middle-drag or Shift+left-drag pans. Scroll zooms (distance clamped to 6…1500). On a Mac also support trackpad gestures: two-finger scroll and pinch to zoom, and a sensible pan.
- Arrow keys: left/right pan, up/down move forward/back along the view. Page Up/Down pan vertically. Home resets the framing and clears the selection.
- Click selects a node; the camera flies to it. Esc closes, in order: an open confirmation, an open list window, then the search text and selection.
- Typing filters by name (up to 24 characters, Backspace deletes). **While a list window is open, typing and the navigation keys belong to the list**, not to the filter or the 3D view. This was a bug the first time: arrows panned the scene behind the list.
- `[` and `]` change the time window (see below).
- UI hit-testing takes priority: a click or scroll over a panel never reaches the camera.

## The six views (tabs)

Each view is a layer with its own nodes, lanes and framing. The first time a view receives data it frames itself.

1. **Processes.** The process tree as a 3D cone tree: parents below, children one level up on a ring. Lanes between processes show data exchange (pipes, local sockets, disk activity). Selecting a process shows its sub-elements and its own lanes, and expands its ring so that individual lanes can be told apart.
2. **Network.** Processes with sockets on one side, remote hosts on the other, lanes per connection, listeners and open ports shown. Selecting a process shows its ports and peers; selecting a remote host block shows its address, resolved host name and connections.
3. **Memory.** A treemap of physical memory grouped by process name (all instances of one program form a group), sized by resident memory, with system-wide totals.
4. **Files.** Which process has which files open, with lanes from processes to files. Shared files are highlighted. Keep it sparse: tight rings, a cap on files and lanes shown per process.
5. **Disks.** Every volume with used and free space, broken down by folder recursively as a treemap (the memory treemap, but for the file system). Click a folder to descend, with a way back up.
6. **Devices.** The tree of connected hardware (buses, controllers, USB, storage, network interfaces, displays) plus network neighbours and gateways, with traffic between them: bytes per interface, bytes per disk.

Every node has a hover tooltip with its statistics.

### Layout lessons (important)

- A plain cone tree doubles its radius at every level, and the scene ends up thousands of units wide and lost in fog. Fix: the **spine rule**. When one child has a much bigger subtree than the rest (radius above about 2.5 leaf radii) it sits straight above its parent and its siblings ring around it. Leaf radius about 1.9, level height about 10.
- Top-level trees are packed on a golden-angle spiral (radius ∝ √k, angle k × 2.39996 rad), testing each candidate against the trees already placed. Search far enough (the Windows app tries 200 000 steps), and if nothing fits place the tree just outside everything. **Never fall back to a shared point**: that produced a pile of processes stacked on one spot with lanes fanning out of it.
- Pack roots using a stable radius that ignores the selection, so expanding a ring on click does not reshuffle the whole scene.
- Only rebuild a layout when the structure changes (hash the pid/parent pairs); otherwise animate towards targets.

## Time window

All "how much data" figures are for a selectable window: 1, 5, 10, 30 or 60 seconds, default 1 s, changed with buttons in the panel or `[` `]`. It applies to network (per process, per connection, per port), disk (per process) and memory changes, and to device traffic. Keep short histories of snapshots and of captured flows to answer these.

## Real traffic and privileges

On Windows the app runs unprivileged by default and shows estimates; a **REQUEST ADMIN** button relaunches it elevated, after which it captures real packets and attributes them to processes, and the status shows "CAPTURE LIVE". A background service can do the same capture at boot so the unprivileged app gets real numbers without elevation ("CAPTURE LIVE (service)").

Keep that three-level model on the Mac, done the Mac way:

- **Unprivileged:** whatever is available without root (process list, own-user sockets and file descriptors, interface counters, per-process disk bytes from `proc_pid_rusage`). Label anything estimated.
- **A button to get full access.** A running Mac app cannot elevate itself, so this installs or starts a privileged helper (a LaunchDaemon, preferably registered with `SMAppService` on macOS 13+) or, as a fallback, relaunches a root capture process after an authorisation prompt. Choose the cleanest approach that works with the signing situation, and explain it in the UI in one line.
- **Background service, optional, started at boot:** the same helper as a LaunchDaemon. The app talks to it over XPC or a Unix domain socket restricted to admin and the console user. The Windows protocol is plain text lines (snapshot, flow, disk, handle records) and that was easy to debug. **The service never captures packet contents**, only accounting; payloads are read only by the app itself, only with privileges, and only while the packet viewer is open.
- Candidate sources, for you to verify rather than trust: BPF / libpcap for packets, and the `pktap` pseudo-interface for per-packet process attribution (what `tcpdump -k` uses); `libproc` (`proc_listallpids`, `proc_pidinfo`, `PROC_PIDLISTFDS`, socket and vnode fd info) for processes, sockets and open files; the mechanism behind `nettop` for per-process byte counts; `kdebug`/`fs_usage`-style tracing for live file activity. Prefer public API; if you use a private one, isolate it and degrade gracefully when it is missing.
- **Mac permissions (TCC):** Full Disk Access is needed to scan much of the disk and to see some files; say so on screen with a button that opens the right System Settings pane, and work with partial results until it is granted.

## List and viewer windows

These open over the scene as overlay windows. All are keyboard navigable: Up/Down, Page Up/Down, Home/End move the cursor; Enter activates; Left/Right switch between the two columns where there are two; Esc closes. The focused column is marked with a brighter rule.

- **Processes by lane traffic.** Every process with totals for all lanes, network in/out, disk and pipes in/out, local sockets. Sort buttons: ALL LANES, NETWORK, DISK READS, DISK WRITES. Enter or click selects the process in the scene.
- **Open ports.** Every listening port (TCP and UDP) with owning process and packets/bytes in and out within the time window. Ports reachable from outside are shown in amber, loopback-only in normal text. Opening a port shows its packets.
- **Packet viewer.** Left column, top: the list of processes involved in captured traffic with in/out counts ("all processes" first, an "unknown process" row for unattributed packets); selecting one filters the packets. Buttons filter IN + OUT / IN / OUT. Left column, bottom: the packet list (newest first, up to 500). Moving through packets with the keyboard freezes the list so it does not slide away under the cursor. Right: the selected packet's details and a hex + ASCII dump, headers dim and payload bright, with a note that TLS payloads are ciphertext. The detail pane shows the remote address with its **host name** (reverse DNS, looked up when the packet is selected) and two buttons: **WHO OWNS IT** and **COPY ADDRESS**.
- **Process memory viewer.** Left: the process's memory regions (address, size, protection, type). Right: a live hex dump of the selected region that re-reads periodically, with paging. On macOS this needs `task_for_pid`, which requires root and is refused for system and hardened processes while SIP is on: show a clear message for those instead of failing silently, and tell me what the realistic coverage is.

### Address lookups

- **Reverse DNS** on a background thread with a cache; "resolving…" until it answers, "none" when there is no name. Shown for remote host blocks in the Network view and in the packet viewer.
- **Owner lookup (whois)** only on demand: query `whois.iana.org` on port 43, follow its referral only if it is one of the five regional registries (ARIN, RIPE, APNIC, LACNIC, AFRINIC), then take the first of these fields: `orgname`, `org-name`, `organization`, `organisation`, `owner`, `descr`, `netname`. The `organisation` spelling matters: IANA uses it for reserved ranges (loopback, multicast), which otherwise report "no owner record found". Cache results per address.

## Actions

Selecting something shows buttons for what can be done to it. Rules that apply to all of them:

- **Dangerous actions are red and need confirmation** in a red modal that states exactly what will happen and to what. Harmless actions (copy, reveal, ping, lookup) run immediately.
- **Guards refuse the catastrophic cases** with an explanation: system-critical processes (on macOS for example `kernel_task`, `launchd`, `WindowServer`, `loginwindow`, and the app and its helper themselves), the system volume, system folders, essential services.
- Results appear as a toast, including failures with the system's error text. Actions needing privileges say so instead of failing mysteriously.
- All actions go through one dispatcher with string keys (`act:<verb>:<target>`), which made confirmation, guards and testing uniform. Keep that design.

The Windows set, with the Mac direction for each:

| Area | Windows action | macOS |
|---|---|---|
| Process | suspend / resume | `SIGSTOP` / `SIGCONT` |
| Process | end, kill, kill tree | `SIGTERM`, `SIGKILL`, and the same over descendants |
| Process | priority (five levels) | nice value / `setpriority`; consider background QoS via `taskpolicy` |
| Process | CPU affinity | not available on macOS: drop it, or offer efficiency-core/background clamp if that is real |
| Process | trim working set | no honest equivalent: drop |
| Process | bring window to front | `NSRunningApplication.activate` |
| Process | stop / restart its service | `launchctl` (stop, kickstart) for launchd jobs |
| Process | close all its connections | see connection row |
| Network | close a connection, close all to a host | no direct API; investigate `pfctl -k` state killing and report what works |
| Network | firewall block / unblock host, block port | `pf` rules in a dedicated anchor owned by the app, removable in one step |
| Network | ping, whois, copy address | same |
| Files | reveal in Explorer, copy path | reveal in Finder, copy path |
| Files | force-close a handle in another process | not possible on macOS: drop |
| Disks | open folder, terminal here, rescan folder | Finder, Terminal, rescan |
| Disks | move folder to recycle bin, empty bin | move to Trash (`FileManager.trashItem`), empty Trash |
| Devices | properties, enable / disable, eject | System Information where useful; eject/unmount via DiskArbitration; interface up/down; generic device disable does not exist, so drop it |

Suggest further Mac-only actions that fit (for example quit an app gracefully with an Apple event before offering kill, sample a process, flush DNS cache) and add the ones that are clearly useful.

## Disks specifics

- One scan thread per volume, results streamed into the treemap as they arrive, depth capped (8 on Windows), never following symlinks or other volumes' mount points.
- Mac-specific traps to handle: APFS volumes in one container share free space (show it per container, do not sum it); the read-only system volume and the Data volume are joined by firmlinks, so do not count `/System/Volumes/Data` twice; use allocated size, not logical size, so clones and sparse files do not inflate totals; skip `/dev`, `/Volumes` loops and network mounts unless asked; Time Machine local snapshots take space that no folder accounts for, so show the remainder as its own block.

## Devices specifics

Walk the IOKit registry for the hardware tree, read per-interface byte counters and per-disk read/write counters for the traffic, and list network neighbours (ARP/NDP table) and default gateways as nodes hanging off the interface they are reached through.

## Menu bar, packaging, startup

- **Menu bar item** (the Mac counterpart of the Windows tray icon): show/hide the window, capture status, quit. Closing the window can leave the app running in the menu bar; make that a visible choice.
- **Packaging:** a proper `MatrixSys.app` bundle with the icon, delivered as a `.dmg` (or `.pkg` if the helper needs it). Include a clean uninstall that removes the helper, the launchd plist, the pf anchor and any settings.
- **Signing:** ask me whether I have a Developer ID. Without one, sign ad hoc, explain the Gatekeeper consequence in the README, and make sure the helper approach you chose still works unsigned.
- Optional "start at login" for the app, separate from the boot-time helper.

## Engineering lessons from the Windows build

- Collect on background threads into immutable snapshots; the render thread swaps a pointer. Never block the frame on a system call. Calls that can hang on a single object (resolving the name of some handles did) need a worker with a short timeout.
- The service and the app must not share a capture session identity: starting one stopped the other.
- Capture payloads only when the packet viewer is open; keep at most a few thousand packets, 512 bytes each.
- Keep the build output outside the source folder, and make rebuilding work while the app is running.
- Add command-line test hooks from the start; they made unattended verification possible: `--select <pid>`, `--memory <pid>`, `--demo-packets` (clearly labelled synthetic packets shaped like the machine's real connections, so the packet viewer can be exercised without privileges; the title says DEMO), `--service-console` (run the helper in the foreground), and install/uninstall switches.
- For self-testing, screenshot only the app's own window and send clicks to that window only. I may be using the machine at the same time, so an occasional missed click is my mouse, not a bug. Screen capture needs the Screen Recording permission: ask once.
- Keep the source small and readable: a handful of files (scene and UI, data collection, helper/IPC, disks, devices), not a framework.

## What done looks like

- `MatrixSys.app` launches offline, shows all six views with live data, and every list, viewer and action described above either works or is listed as intentionally changed or dropped for macOS, with the reason.
- With the helper installed, the status shows live capture and the packet viewer shows real packets attributed to processes.
- A `.dmg`, an uninstaller, a short README (what needs which permission, what differs from Windows), and a build script that reproduces everything from source.
- A final summary table: feature, state on macOS (same / adapted / dropped), tested by you or not.
