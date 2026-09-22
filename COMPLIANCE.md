# NTPSense InetGateway CE — Compliance & NGFW Readiness

**Version:** 0.1 (Community Edition)  
**Last updated:** 2026-09-23  
**Scope:** This document describes the current security, audit, and Next-Generation Firewall (NGFW) related controls present in NTPSense CE, and explicitly lists known gaps. It is intended for internal use, customer due-diligence, and roadmap planning.

---

## 1. Purpose

NTPSense CE is a FreeBSD-native network gateway (firewall, DHCP, VPN, IDS/IPS, proxy).  
This document maps existing controls against common expectations for:

- Traditional + Next-Generation Firewall capabilities
- Basic information-security compliance readiness (logging, access control, configuration integrity, secure management)

It does **not** claim certification against any formal standard (ISO 27001, PCI-DSS, NIST, etc.). It is a transparent readiness statement.

---

## 2. Current Control Summary

| Domain | Control | Status in CE | Notes |
|--------|---------|--------------|-------|
| **Network Firewall** | Stateful packet filtering (pf) | Implemented | Zone/interface aware, NAT, port forwarding, custom rules, anti-lockout |
| **Intrusion Detection / Prevention** | Suricata IDS + pilot IPS (netmap) | Implemented | ET Open, OISF Traffic ID, optional abuse.ch sources; policy disable + custom rules; RAM guard for IPS |
| **Application Visibility / Control** | Deep application identification | Not in CE | Removed from CE scope; available in Pro roadmap |
| **URL / Content Filtering** | Squid + categorized blocklists | Implemented | Categories, whitelist, manual blacklist, Basic Auth |
| **VPN** | WireGuard, OpenVPN, IPsec/strongSwan | Implemented | Remote access + site-to-site options |
| **Identity / Authentication** | Local users + FreeRADIUS + LDAP client | Partial | Web UI supports 2FA (TOTP); RADIUS/LDAP for services |
| **Access Control (RBAC)** | Role-based (Administrator / Network Operator / Auditor) | Implemented | Applied to both Web UI and console menu |
| **Secure Management** | HTTPS-only Web UI, forced password change, lockout, CAPTCHA, 2FA | Implemented | Self-signed cert on first boot; session hardening present |
| **Audit Logging** | Login events, EULA acceptance, some operational events | Basic | Not yet a full change-audit trail for every configuration object |
| **Configuration Integrity** | Atomic writes in daemon, JSON configs | Partial | No signed config, no full version history / diff in CE |
| **Logging & Retention** | Local system logs + Suricata EVE + multiwan event log | Basic | No formal retention policy or remote syslog configuration UI yet |
| **IPv6** | Limited | Partial | Primarily IPv4-focused in current CE |
| **High Availability** | Clustering / failover pair | Not in CE | Pro feature |
| **Centralized Management** | Multi-device policy | Not in CE | Pro feature |

---

## 3. Strengths Relevant to Compliance

- **Privilege separation**: Web UI (PHP) talks to a privileged Rust daemon (`ntpsense-configd`) over a Unix socket with peer-credential checks and an action whitelist. Free-form command execution from the UI is not possible.
- **Fail-closed design** in several modules (empty Suricata interface list disables the service; IPS pilot refuses to start on insufficient RAM).
- **RBAC** already distinguishes read-oriented (Auditor) from change-capable roles.
- **Authentication hardening** on the management plane (lockout, CAPTCHA, optional 2FA, forced password change on first login).
- **Open source (Apache 2.0)** allows independent review of the control plane.

---

## 4. Known Gaps (CE)

The following are intentionally out of scope for the current Community Edition or only partially implemented:

1. **Full configuration change audit trail**  
   Who changed which firewall rule / gateway / VPN object, old vs new value, source IP, timestamp — not yet recorded for every object.

2. **Configuration versioning & signed backups**  
   Export/import exists in limited form; cryptographic integrity and long-term version history are not present.

3. **Remote logging (syslog/SIEM) configuration**  
   Logs remain local; no first-class UI/CLI for reliable remote syslog with TLS.

4. **Formal log retention & rotation policy**  
   Rotation exists for some files via newsyslog; no administrator-facing retention policy.

5. **Application Control / SSL Inspection**  
   Not included in CE.

6. **IPv6 feature parity**  
   Addressing, filtering, and multi-WAN behaviour for IPv6 are not yet at parity with IPv4.

7. **High Availability and central management**  
   Reserved for Pro.

---

## 5. Recommended Hardening Checklist (Post-Install)

Operators should verify the following after every installation or major upgrade:

- [ ] Default `admin` password has been changed
- [ ] 2FA is enabled for administrative accounts (recommended)
- [ ] Only required management access is allowed (LAN / dedicated management network)
- [ ] Suricata rule sources are updated and auto-update is enabled if desired
- [ ] Unused services / packages are not installed
- [ ] TLS certificate is replaced with a trusted certificate if the device is reachable beyond a lab network
- [ ] Regular configuration backup is performed and stored offline
- [ ] System time is synchronized (NTP)
- [ ] Log files are monitored for disk space

---

## 6. Roadmap Alignment (CE → stronger compliance posture)

Short-term improvements planned for CE (non-exhaustive):

- Richer audit logging for configuration changes
- Simple configuration export with checksum
- Basic remote syslog support
- Improved IPv6 coverage
- Clearer operator documentation for logging and retention

Longer-term / Pro items remain: Application Control, full HA, central management, advanced reporting, and formal certification efforts if required by customers.

---

## 7. Disclaimer

This document is provided for transparency. Presence of a control does not guarantee that a particular deployment meets any regulatory or contractual obligation. Operators remain responsible for correct configuration, monitoring, and evidence collection required by their own compliance programmes.

---

*NTPSense InetGateway is developed by NTPRO TEKNOLOGI JAYA, Jakarta, Indonesia.*
