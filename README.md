# Airset — Router Social Engineering Toolkit

Airset is a WPA/WPA2 "evil twin" toolkit: it clones a target Wi-Fi network,
knocks its clients offline, and serves a fake captive portal (router firmware
update or ISP login page) to trick a user into typing the real Wi-Fi password,
which is then validated against the captured handshake.

Originally by **Alef Carvalho [W4R10CK]** — https://youtube.com/c/alefcarvalhobr
Modifications are allowed as long as credit to the original author is kept.

> ## ⚠️ Authorized use only
> This is an offensive wireless-attack tool. Use it **only** against networks you
> own or have explicit written permission to test. Capturing handshakes, deauthing
> clients, or phishing credentials on networks you do not control is illegal in most
> countries. You are solely responsible for how you use it.

## Requirements

- **Parrot OS 7** (Debian Bookworm) or equivalent, running as **root**
- A **graphical session (X11)** — the tool spawns `xterm` windows
- A Wi-Fi adapter that supports **monitor mode** and **packet injection**

## Install

Install all dependencies with the bundled installer:

```bash
sudo ./setup
```

It checks and installs the full toolchain: the aircrack-ng suite, `hostapd`,
`lighttpd` + `php-cgi`, `dnsmasq`, `mdk4`, `reaver`, `bully`, `macchanger`,
`hashcat`, `hcxtools`, `nmap`, and supporting utilities.

## Run

```bash
sudo ./airset
```

Then follow the on-screen menu: pick the adapter, scan for the target, capture the
handshake (deauth to force a reconnect), choose a captive-portal template, and wait
for the victim to submit the password. Captured passwords are saved to
`~/<SSID>-password.txt` and logged under `/root/pwlog/`.

Captive-portal templates live in `web_interfaces/` (`neutra`, `velox`, `virtua`).

## Web control panel (new)

Prefer a browser over the `xterm` menus? `airset-web.py` is a stdlib-only web panel
that drives the whole flow — no Flask, no pip:

```bash
sudo python3 airset-web.py            # -> http://127.0.0.1:8092
```

Steps map to cards in the UI: pick the adapter and enable **monitor mode**, **scan**
networks, click a **target**, **capture the handshake** (airodump + deauth), then raise
the **fake AP + captive portal** with a chosen template. A live panel shows connected
clients, password attempts, and the captured Wi-Fi password (validated against the
handshake with aircrack-ng). The theme matches the CLI banner (hacker dark).

It binds to `127.0.0.1` and requires an `X-Airset-Token` header issued to the page, so
a random localhost tab cannot drive your radio. `Ctrl+C` (or **Cleanup total**) tears
everything down and restarts NetworkManager. Needs root, like the CLI.

## 2026 modernization

This fork updates the toolkit to run on current Parrot/Kali, where several Kali
tools it relied on were removed or replaced:

| Old (removed/EOL) | Replacement | Why |
|---|---|---|
| `mdk3` | `mdk4` | mdk3 dropped from the repos; mdk4 is the maintained fork |
| `isc-dhcp-server` (`dhcpd`) | `dnsmasq` | ISC DHCP is end-of-life; dnsmasq is the standard for rogue-AP DHCP |
| `pyrit` | `aircrack-ng` / `wpaclean` | pyrit was removed from the repos; aircrack-ng validates the handshake |
| Python 2 | Python 3 | Python 2 was removed from the distro; `fakedns` is now Python 3 |
| `ifconfig` / `netstat` | `ip` / `ss` | net-tools is deprecated; modern `iproute2` is used, with a fallback |

> Note: `mdk4` mode mapping for the WPS lockout-recovery paths (mdk3 `x 0` → mdk4
> `e`) should be verified against your hardware in the field.

## License

See [`LICENSE`](LICENSE). Credit to the original author must be preserved.
