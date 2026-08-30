# NTPSense InetGateway — Community Edition (CE)

**A FreeBSD-native network gateway appliance for home office, branch office, and school environments — free, self-hosted, and yours to run on hardware you already own.**

[![License](https://img.shields.io/badge/license-Apache%202.0-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-FreeBSD%2014.3-red.svg)](https://www.freebsd.org/)
[![Made with Rust](https://img.shields.io/badge/daemon-Rust-black.svg)](https://www.rust-lang.org/)

[Website](https://ntpsense.com) · [Download](https://ntpsense.com/download.html) · [Documentation](https://ntpsense.com/support.html) · [CE vs Pro](https://ntpsense.com/compare.html)

---

## What is NTPSense?

NTPSense InetGateway is a firewall, DHCP server, and VPN appliance built **from scratch** on FreeBSD — not a repackaged distro. A single Rust daemon (`ntpsense-configd`) governs `pf`, Kea DHCP, WireGuard, Squid, Suricata, strongSwan, and FreeRADIUS through one Unix-socket control plane, configured through a web interface or a full-featured console menu.

Community Edition (CE) is free, open-source (Apache License 2.0), and designed to run on commodity x86 hardware — the same class of Atom/N-series/Core boards you'd use for any small-office router.

## Features

- **Firewall** — `pf`-based, zone/interface-aware, custom rules, NAT, port forwarding
- **DHCP server** — Kea DHCP, per-interface pools, static reservations, live lease viewer
- **VPN** — WireGuard (remote access), OpenVPN (certificate-based, TCP/443-friendly), IPsec/strongSwan (site-to-site)
- **IDS/IPS** — Suricata, curated rule sources (ET Open, OISF Traffic ID, Abuse.ch), custom rules
- **Proxy** — Squid with categorized blocklists, bandwidth accounting, Basic Auth
- **Authentication** — FreeRADIUS server, LDAP client support
- **Zero-interaction install** — boot the ISO, walk away; the gateway configures itself
- **Console + Web UI** — full admin console menu (SSH/serial) alongside the web interface, both backed by the same role-based access control (Administrator / Network Operator / Auditor)

## Hardware requirements

| | Minimum |
|---|---|
| Network interfaces | 2× wired Ethernet (LAN + WAN) |
| Memory | 4 GB RAM |
| Disk | 20 GB+ |
| Architecture | amd64 |

Runs on bare metal or in a VM (VMware, Proxmox, VirtualBox all tested).

## Getting started

Most people should **not** build from source — download the ready-to-use ISO instead:

👉 **[Download NTPSense CE](https://ntpsense.com/download.html)**

1. Write the ISO to a USB drive (`dd`, Rufus, or balenaEtcher)
2. Boot it — installation is fully automated, no prompts
3. Connect a device to the LAN port and open `https://<gateway-ip>/`
4. Log in with `admin` / `admin` (you'll be asked to change it immediately)

## Repository contents

This repository contains the complete CE source — everything needed to build the daemon, the web UI, and a bootable installer ISO from scratch.

| File | Purpose |
|---|---|
| `main.rs` | Core of `ntpsense-configd` — the Rust control-plane daemon (firewall, DHCP, dashboard, console integration, and more) |
| `security.rs` | Suricata IDS/IPS integration |
| `proxy.rs` | Squid proxy integration |
| `multiwan.rs` | Multi-WAN gateway/failover logic |
| `openvpn.rs` | OpenVPN (PKI, clients, site-to-site) integration |
| `webui-ce.tar.gz` | The PHP web interface (`public/`, `lib/`, `templates/`) |
| `install-gateway-2eth-v2.sh` | Runs on first boot — detects NICs, installs packages, configures the gateway with zero interaction |
| `installerconfig-2eth` | FreeBSD scripted-install config (disk partitioning, base system) |
| `build-custom-iso-2eth.sh` | Builds the bootable ISO from a stock FreeBSD 14.3 image + this repo's files |
| `ntpsense-console-menu.sh` | The console/SSH admin menu (role-filtered, pfSense-style) |
| `ntpsense-sync-os-accounts.sh` | Syncs Web UI accounts to OS-level console accounts |
| `console-set-password.php` | CLI bridge so the console menu can update the Web UI's password hash |
| `gfx-ntpsensebrand.lua` / `gfx-hexagon.lua` | Custom FreeBSD boot loader branding |

## Building from source

You'll need a FreeBSD 14.3 build host (matching the target release) with Rust installed.

```sh
# 1. Compile the daemon
cargo build --release

# 2. Build the ISO — needs a stock FreeBSD 14.3-RELEASE-amd64-disc1.iso
#    in the same directory (downloaded automatically on first run),
#    plus every file from this repo present alongside the script.
sh build-custom-iso-2eth.sh install-gateway-2eth-v2.sh <sha256-of-your-binary>
```

The build script extracts the stock FreeBSD ISO, injects the compiled binary, the web UI, the installer scripts, and the boot branding, then repacks it into a bootable image — reproducible from this repository alone.

## Architecture at a glance

```
┌───────────────────────────────────────────────┐
│              Web UI (PHP/lighttpd)            │
│         Console menu (SSH/serial, Rust)       │
└───────────────────┬───────────────────────────┘
                     │ Unix socket (NDJSON)
┌───────────────────▼─────────────────────────────┐
│         ntpsense-configd (Rust daemon)          │
│   pf · Kea DHCP · WireGuard · Squid · Suricata  │
│      strongSwan · FreeRADIUS · OpenVPN          │
└─────────────────────────────────────────────────┘
                     │
              FreeBSD 14.3 kernel
```

## CE vs. Pro

NTPSense Pro adds Site Mesh VPN (self-hosted multi-branch mesh), multi-WAN failover management at scale, high-availability clustering, and centralized management — and is licensed separately (not Apache 2.0). See **[ntpsense.com/compare.html](https://ntpsense.com/compare.html)** for details.

## License

NTPSense CE is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE). You're free to use, modify, and redistribute it, including commercially, without asking us first.

Third-party components bundled with NTPSense (Squid, Suricata, strongSwan, FreeRADIUS, OpenVPN, Kea, WireGuard, and others) are licensed separately under their own upstream terms — see **[ntpsense.com/open-source.html](https://ntpsense.com/open-source.html)** for the full list and GPL source-code compliance details.

## Support & community

- **Issues / bugs**: use this repository's [Issues](../../issues) tab
- **Documentation**: [ntpsense.com/support.html](https://ntpsense.com/support.html)
- **Commercial support / Pro inquiries**: [ntpsense.com/contact.php](https://ntpsense.com/contact.php)

---

<sub>NTPSense InetGateway is built by NTPRO TEKNOLOGI JAYA, Jakarta, Indonesia.</sub>
