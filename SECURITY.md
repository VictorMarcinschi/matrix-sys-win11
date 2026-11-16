# Security

MatrixSys is a system tool: it can run as administrator, it installs an optional service that runs as SYSTEM, and it can end processes, close connections and change firewall rules when you ask it to. Security reports are taken seriously.

## Reporting a vulnerability

Please report it privately through GitHub: on the repository page, open **Security → Report a vulnerability**. Do not open a public issue.

Include what an attacker could do, the steps to reproduce it, and the version or commit you tested. You will get an answer as soon as possible; fixes are released as a new version.

## What the app does that matters for security

- **The background service** (optional, chosen in the installer) runs as LocalSystem and only collects traffic and disk counters. It never captures packet contents. It talks to the app over a local named pipe that administrators and SYSTEM can write to and signed-in users can only read.
- **Packet contents** are read only by the app itself, only when it runs as administrator, and only while the packet viewer is open.
- **Network traffic the app causes itself:** reverse DNS lookups of addresses on screen (through the Windows resolver); owner lookups, sent to the public whois registries only when you press *Who owns it*; and, in the Trace tab, the probes and requests of a trace you start. A rendered page fetches nothing unless you turn on *Load resources*.
- **The agent** (Trace and every tab, from this milestone on) talks only to a model server on this computer: `127.0.0.1` or `localhost`. Your questions and the screen data they include are sent to that server and nowhere else. Other endpoints are refused.
- **Nothing is uploaded** anywhere else. There is no telemetry and no update check.

## Supported versions

Only the latest release receives fixes.
