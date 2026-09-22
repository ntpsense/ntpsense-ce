// security.rs — NTPSense Tier 2, Suricata IDS/IPS plugin
// Phase 1 scope: IDS-only (PCAP capture), per-zone interface toggle,
// ET Open + OISF Traffic ID rule sources via suricata-update, EVE JSON alert
// viewer. Policy tuning + custom rules deliberately deferred to Phase 2
// (see Doc 7 discussion — Phase 1 stays observational, zero blocking risk).
//
// Integration note: this module is written standalone against the same
// conventions already established in main.rs (fail-closed auth handled
// by the existing dispatch layer, atomic file writes, verify-after-restart,
// startup unconditional reapply). Merge the action match arms into the
// existing dispatch match block; reuse existing helpers where named below
// (get_interface_cidr, normalize_network_cidr, run_privileged_restart, etc.)
// rather than duplicating them.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub const SURICATA_BIN: &str = "/usr/local/bin/suricata";
pub const SURICATA_UPDATE_BIN: &str = "/usr/local/bin/suricata-update";
// Reserved for Phase 2 (custom HOME_NET / af-packet tuning). Phase 1 needs
// zero hand-edits to suricata.yaml itself - multi-interface capture is
// handled entirely via SURICATA_RC_CONF_D (see build_suricata_interface_line).
#[allow(dead_code)]
pub const SURICATA_YAML: &str = "/usr/local/etc/suricata/suricata.yaml";
pub const SURICATA_RC_CONF_D: &str = "/etc/rc.conf.d/suricata";
pub const SURICATA_CONFIG_JSON: &str = "/usr/local/etc/ntpsense/security-config.json";
pub const EVE_JSON_LOG: &str = "/var/log/suricata/eve.json";
// Fase 2 additions: stable, self-contained locations (not suricata-update's
// own cache dir under --data-dir) for the two hand-maintained config files
// that persist across every update run - disable.conf (Policy tab, group:
// category disables) and local.rules (Custom rules tab, admin-authored
// signatures, merged in by suricata-update's own --local flag and
// validated by the same 'suricata -T' check the pipeline already runs).
pub const SURICATA_DISABLE_CONF: &str = "/usr/local/etc/suricata/disable.conf";
pub const SURICATA_LOCAL_RULES: &str = "/usr/local/etc/suricata/rules/local.rules";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneSecurityToggle {
    pub zone_alias: String,   // e.g. "WAN1"
    pub physical_if: String,  // e.g. "em0"
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleSourceConfig {
    pub et_open: bool,
    // RCA (dikonfirmasi dari 'suricata-update list-sources' sungguhan di
    // VM user): 'Snort GPLv2 Community' yang jadi asumsi awal riset
    // TIDAK ADA di index resmi OISF/suricata-update sama sekali - Snort
    // Community Rules didistribusikan langsung dari snort.org, terpisah
    // dari tool ini. Diganti ke source yang BENAR-BENAR ADA di index
    // (dibuktikan dari output list-sources nyata): oisf/trafficid -
    // resmi dari OISF sendiri, MIT license, melengkapi ET Open tanpa
    // tumpang tindih.
    pub oisf_trafficid: bool,
    // Fase 2 - dua kandidat yang disepakati bro, KEDUANYA dikonfirmasi
    // benar-benar ada di 'suricata-update list-sources' asli (bukan
    // tebakan seperti snort/community dulu) - source id persis:
    // abuse.ch/sslbl-ja3 dan abuse.ch/urlhaus.
    #[serde(default)]
    pub abuse_ch_ja3: bool,
    #[serde(default)]
    pub abuse_ch_urlhaus: bool,
}

impl Default for RuleSourceConfig {
    fn default() -> Self {
        // ET Open + OISF Traffic ID tetap default ON (baseline Fase 1).
        // Dua source Fase 2 default OFF - admin opt-in eksplisit, supaya
        // admin yang sudah puas dengan baseline Fase 1 tidak tiba-tiba
        // dapat source tambahan tanpa sepengetahuannya setelah upgrade.
        RuleSourceConfig { et_open: true, oisf_trafficid: true, abuse_ch_ja3: false, abuse_ch_urlhaus: false }
    }
}

// Fase 2 - Policy tab: bulk per-category enable/disable via suricata-update's
// own disable.conf "group:<filename>" mechanism (confirmed from OISF's own
// suricata-update documentation - NOT a guess this time, learned from the
// RCA-13 lesson). Kurasi 8 kategori ET Open yang paling relevan untuk
// keputusan admin non-IPS (noise reduction, bukan security-critical) -
// mekanisme backend generik, bisa menerima nama grup APAPUN kalau admin
// (lewat Custom rules atau permintaan lanjutan) butuh kategori lain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub disabled_categories: Vec<String>,
}

// IPS/netmap inline pilot (post-Fase 2). SCOPE DECISION, agreed with bro
// explicitly after the divert(4)/ipfw research finding (a real OPNsense bug
// report confirmed pf always processes traffic before ipfw, so divert-based
// IPS silently never blocks anything on a pf-based firewall like this one -
// netmap inline mode is the only architecture that actually works here,
// confirmed from Suricata's own netmap docs: it sits in front of pf, no
// ordering conflict). Deliberately scoped to ONE pilot interface at a time
// (WAN1 first, chosen specifically because it is NOT MGMT - a misconfigured
// netmap section can cause full connectivity loss per Suricata's own docs,
// so the pilot interface must never be the one admin access depends on).
// While IPS pilot is active it takes over Suricata's capture mode entirely
// (netmap, not PCAP) - Fase 1 per-zone IDS toggles are paused for the
// duration, since the simple rc.d suricata_interface/suricata_netmap flag
// scheme is if/elif, not a per-interface mix of both modes at once.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct IpsPilotConfig {
    #[serde(default)]
    pub enabled: bool,
    // DEPRECATED - dipertahankan HANYA untuk migrasi config lama (single
    // interface, era WAN1-only). Field aktif yang sesungguhnya dipakai
    // sekarang adalah pilot_interfaces di bawah - lihat migrasi di
    // load_security_config().
    #[serde(default)]
    pub pilot_interface: String,
    // Perluasan WAN1 -> WAN1+WAN2 (diminta bro setelah App Control
    // ketahuan celah cakupan: traffic round-robin Multi-WAN bisa lewat
    // WAN2 yang dulu tidak diawasi sama sekali). PENTING - konsekuensi
    // memori NYATA (bukan teori): riset/RCA sebelumnya mengonfirmasi
    // OOM crash sungguhan di VM 2GB RAM saat netmap PERTAMA diaktifkan
    // (butuh ~320MB+ alokasi buffer khusus per interface) - menambah
    // interface KEDUA kira-kira MENGGANDAKAN kebutuhan itu. Peringatan
    // ini WAJIB tetap tampil di UI, bukan cuma di komentar kode.
    #[serde(default)]
    pub pilot_interfaces: Vec<String>, // physical ifs, e.g. ["em5", "em4"] - kosong = tidak dikonfigurasi
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityConfig {
    pub zones: Vec<ZoneSecurityToggle>,
    pub rule_sources: RuleSourceConfig,
    pub auto_update_enabled: bool,
    pub last_rule_update: Option<String>, // ISO8601, set after a verified successful run_suricata_rule_update()
    // Fase 2 - #[serde(default)] wajib di sini: config.json yang sudah
    // tersimpan dari Fase 1 tidak punya field ini sama sekali - tanpa
    // default, deserialize config lama akan gagal total begitu binary
    // baru dijalankan (pola #[serde(default)] yang sudah jadi konvensi
    // wajib di project ini sejak Tier 2 awal - lihat Doc 7 §1.3).
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub custom_rules_text: String,
    #[serde(default)]
    pub ips: IpsPilotConfig,
}

// ---------------------------------------------------------------------
// Core logic (unit-tested below; mirrors the Python pre-validation pass)
// ---------------------------------------------------------------------

/// Builds the space-separated interface list for rc.conf's suricata_interface.
/// FreeBSD's official ports rc.d script (security/suricata/files/suricata.in)
/// iterates this as a shell word-split list and emits one --pcap=IFACE flag
/// per entry — so multi-zone capture needs nothing more than this one line,
/// no hand-written pcap: array in suricata.yaml required for Phase 1.
/// Returns an empty string if no zone has security enabled — this is
/// intentional and matches upstream behavior: an empty suricata_interface
/// is documented as mandatory-for-IDS-mode, so leaving it unset here means
/// the generated rc.conf.d snippet disables the service outright rather
/// than silently falling through to IPS/divert mode (fail-closed).
pub fn build_suricata_interface_line(zones: &[ZoneSecurityToggle]) -> String {
    zones
        .iter()
        .filter(|z| z.enabled)
        .map(|z| z.physical_if.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EveAlert {
    pub timestamp: String,
    pub severity: Option<i64>,
    pub signature: Option<String>,
    pub category: Option<String>,
    pub src_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub proto: Option<String>,
    pub in_iface: Option<String>,
}

/// Parses raw EVE JSON lines (one JSON object per line, Suricata's native
/// format), keeps only event_type=="alert" entries, sorts newest-first,
/// truncates to `limit`. Malformed lines are skipped rather than failing
/// the whole read — a single corrupt line (e.g. from a killed-mid-write
/// process) must not blank out the entire Alerts tab.
pub fn parse_eve_alerts(lines: &[String], limit: usize) -> Vec<EveAlert> {
    let mut alerts: Vec<EveAlert> = Vec::new();
    for line in lines {
        let val: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if val.get("event_type").and_then(|v| v.as_str()) != Some("alert") {
            continue;
        }
        let alert = val.get("alert").cloned().unwrap_or(serde_json::Value::Null);
        alerts.push(EveAlert {
            timestamp: val.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            severity: alert.get("severity").and_then(|v| v.as_i64()),
            signature: alert.get("signature").and_then(|v| v.as_str()).map(String::from),
            category: alert.get("category").and_then(|v| v.as_str()).map(String::from),
            src_ip: val.get("src_ip").and_then(|v| v.as_str()).map(String::from),
            dest_ip: val.get("dest_ip").and_then(|v| v.as_str()).map(String::from),
            proto: val.get("proto").and_then(|v| v.as_str()).map(String::from),
            in_iface: val.get("in_iface").and_then(|v| v.as_str()).map(String::from),
        });
    }
    alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    alerts.truncate(limit);
    alerts
}

/// Fase "IPS pilot" - finds the netmap: top-level key in suricata.yaml and
/// replaces its entire block (up to the next unindented top-level key) with
/// either TWO active pilot-interface stanzas (copy-mode: ips) forming a
/// symmetric host-stack-mode pair, or a harmless no-op placeholder when
/// disabled.
///
/// RCA (real-world test, corrected twice): the first implementation used a
/// single stanza with copy-iface pointed at "<if>+" - this syntax was taken
/// from the real shipped suricata.yaml's own inline comment ("add a plus
/// sign at the end, e.g. eth0+"), which turned out to be misleading for
/// this use case. A LAN client behind NAT got 100% packet loss even after
/// adding a second, symmetric "+"-based stanza: outbound (client-initiated)
/// traffic never made it back through pf's NAT/state tracking, while
/// gateway-originated traffic (e.g. the Squid proxy's own connections)
/// worked fine - confirmed via tcpdump showing ICMP hitting em5 at the BPF
/// filter level but never being delivered to userspace, and pfctl showing
/// zero ICMP state entries, meaning pf never saw the traffic at all.
/// Cross-checked against Suricata's own official docs (multiple versions)
/// and a real OPNsense production netmap config (confirmed directly by an
/// OPNsense/pfSense maintainer) - both consistently use a CARET "^"
/// suffix, not "+", to select netmap's "host stack mode": this is not just
/// a naming difference, "^" specifically opens the host-stack rings that
/// integrate with the OS's normal forwarding path (where pf does NAT);
/// "+" does not reliably do the same. Switched to "^" to match the
/// confirmed-working real-world reference rather than the shipped file's
/// own (apparently stale/misleading) inline comment.
pub fn regenerate_netmap_section(yaml_text: &str, physical_ifs: &[String], enabled: bool) -> Result<String, String> {
    let lines: Vec<&str> = yaml_text.split('\n').collect();
    let mut start_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("netmap:") {
            start_idx = Some(i);
            continue;
        }
        if start_idx.is_some() && end_idx.is_none() {
            let is_top_level_key = !line.is_empty()
                && !line.starts_with(char::is_whitespace)
                && !line.starts_with('#');
            if is_top_level_key {
                end_idx = Some(i);
                break;
            }
        }
    }
    let start = start_idx.ok_or_else(|| {
        "netmap: key not found in suricata.yaml - refusing to guess an insertion point".to_string()
    })?;
    let end = end_idx.unwrap_or(lines.len());

    let new_block: Vec<String> = if enabled && !physical_ifs.is_empty() {
        let mut block = vec!["netmap:".to_string()];
        // Satu pasang stanza forward+return PER interface pilot (WAN1,
        // dan sekarang opsional WAN2 juga) - masing-masing interface
        // butuh KEDUANYA (bukan cuma satu arah), persis alasan yang
        // sama dengan komentar RCA asli di bawah (traffic balik/
        // forwarded tidak akan sampai ke pf tanpa stanza return).
        for physical_if in physical_ifs {
            // Outbound: physical interface -> host-stack ring.
            block.push(format!(" - interface: {physical_if}"));
            block.push("   copy-mode: ips".to_string());
            block.push(format!("   copy-iface: {physical_if}^"));
            // Return path: host-stack ring -> physical interface. Without
            // this second, symmetric stanza (and without the correct "^"
            // host-stack-mode suffix), response/forwarded traffic never
            // makes it back through to pf - confirmed via real LAN-client
            // testing (tcpdump + pfctl state evidence, see doc comment).
            block.push(format!(" - interface: {physical_if}^"));
            block.push("   copy-mode: ips".to_string());
            block.push(format!("   copy-iface: {physical_if}"));
        }
        block.push(" - interface: default".to_string());
        block
    } else {
        // Disabled: revert to a harmless placeholder-only stanza, matching
        // the shipped template's own no-op default - never leave a stale
        // copy-mode: ips pointed at a real interface behind after disable.
        vec!["netmap:".to_string(), " - interface: default".to_string()]
    };

    let mut result_lines: Vec<String> = lines[..start].iter().map(|s| s.to_string()).collect();
    result_lines.extend(new_block);
    result_lines.extend(lines[end..].iter().map(|s| s.to_string()));
    Ok(result_lines.join("\n"))
}

/// RCA (real OOM crash on the test VM, 2GB RAM): enabling IPS pilot mode
/// triggered "swap_pager: out of swap space" and the kernel OOM-killed the
/// suricata process mid-netmap-init ("Unable to create cluster ... for
/// 'netmap_buf' allocator") - confirmed via FreeBSD-net mailing list and an
/// identically-titled OPNsense forum report to be a well-known, genuine
/// memory-capacity issue, not a config bug: netmap's buffer pool needs a
/// substantial dedicated allocation (~320MB+ per FreeBSD's own netmap
/// memory-config trace: "100 KB for interfaces, 7200 KB for rings and
/// 320 MB for bu[ffers]") on top of an already-heavy baseline (Suricata's
/// own signature-matching engine with 80,000+ active rules, plus Squid,
/// Kea, and WireGuard all resident at the same time). A 2GB VM was already
/// tight before adding netmap's overhead - this guard checks hw.physmem
/// and refuses to enable IPS pilot mode below a safe threshold, rather
/// than letting the same OOM/connectivity-loss sequence repeat silently.
fn check_ram_sufficient_for_ips(interface_count: usize) -> Result<(), String> {
    // 3 GB dasar untuk SATU interface netmap (RCA asli - OOM crash
    // sungguhan di VM 2GB). Interface KEDUA dst kira-kira MENGGANDAKAN
    // kebutuhan alokasi buffer netmap - tambahkan headroom eksplisit
    // per interface tambahan, bukan cuma pakai angka dasar yang sama
    // untuk berapa pun banyaknya interface pilot yang diaktifkan.
    let extra_gb = interface_count.saturating_sub(1) as u64;
    let min_bytes: u64 = (3 + extra_gb) * 1024 * 1024 * 1024;
    let out = Command::new("sysctl")
        .args(["-n", "hw.physmem"])
        .output()
        .map_err(|e| format!("could not query hw.physmem: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let physmem: u64 = text.trim().parse().map_err(|_| {
        format!("could not parse hw.physmem output: {:?}", text.trim())
    })?;
    if physmem < min_bytes {
        return Err(format!(
            "IPS pilot mode refused: system has {:.1} GB RAM, below the {} GB minimum for {} pilot interface(s). \
             A real OOM crash was confirmed on a 2 GB test VM (kernel killed Suricata mid-netmap-init, \
             WAN1 lost connectivity until reboot) - netmap's buffer pool needs meaningful headroom PER \
             interface on top of Suricata/Squid/Kea/WireGuard's existing baseline. Increase VM RAM before \
             enabling this many interfaces, or enable fewer.",
            physmem as f64 / (1024.0 * 1024.0 * 1024.0),
            3 + extra_gb,
            interface_count,
        ));
    }
    Ok(())
}

pub fn apply_ips_pilot_yaml(cfg: &SecurityConfig) -> Result<(), String> {
    // App Control DIHAPUS dari CE (permintaan user - fitur ini tetap
    // Pro-only) - netmap scoping kembali ke pilot_interfaces WAN/post-
    // NAT murni saja, PERSIS perilaku sebelum App Control per-zona
    // ditambahkan (lihat riwayat komentar sebelumnya di titik ini).
    let combined_ifaces: Vec<String> = cfg.ips.pilot_interfaces.clone();

    if cfg.ips.enabled {
        // RAM check pakai HITUNGAN GABUNGAN (WAN + LAN scoped), bukan
        // cuma pilot_interfaces WAN - setiap interface netmap tambahan
        // (LAN sekalipun) tetap menambah beban buffer pool netmap yang
        // sama, RCA OOM asli tetap relevan penuh di sini.
        check_ram_sufficient_for_ips(combined_ifaces.len())?;
    }
    let existing = fs::read_to_string(SURICATA_YAML)
        .map_err(|e| format!("failed to read {}: {}", SURICATA_YAML, e))?;
    let updated = regenerate_netmap_section(&existing, &combined_ifaces, cfg.ips.enabled)?;
    // Backup before ever touching the live file - this is the one config
    // file in this project where "misconfiguration can lead to
    // connectivity loss" is Suricata's OWN documented warning, not just
    // our usual caution.
    let _ = fs::copy(SURICATA_YAML, format!("{SURICATA_YAML}.ntpsense-backup"));
    write_atomic(SURICATA_YAML, &updated).map_err(|e| format!("failed to write {}: {}", SURICATA_YAML, e))
}

/// Builds the rc.conf.d/suricata snippet content. Written atomically
/// (temp file + rename) by the caller, same pattern as every other
/// generated config file in this daemon.
pub fn generate_rc_conf_snippet(cfg: &SecurityConfig) -> String {
    // IPS pilot mode takes over Suricata's capture mode entirely (netmap,
    // not PCAP) while active - see IpsPilotConfig doc comment for why this
    // isn't mixed with Fase 1's per-zone PCAP toggles. suricata_interface
    // MUST be left unset here (not just empty-string) so the rc.d script's
    // if/elif falls through to the netmap branch, per FreeBSD ports'
    // security/suricata/files/suricata.in.
    if cfg.ips.enabled && !cfg.ips.pilot_interfaces.is_empty() {
        return "suricata_enable=\"YES\"\n\
                suricata_netmap=\"YES\"\n\
                suricata_flags=\"-D\"\n"
            .to_string();
    }

    let iface_line = build_suricata_interface_line(&cfg.zones);
    if iface_line.is_empty() {
        // No zone enabled: explicitly disable rather than leaving stale
        // rc.conf state that might auto-fallback into IPS/divert mode.
        return "suricata_enable=\"NO\"\n".to_string();
    }
    format!(
        "suricata_enable=\"YES\"\n\
         suricata_interface=\"{iface}\"\n\
         suricata_netmap=\"NO\"\n\
         suricata_flags=\"-D\"\n",
        iface = iface_line
    )
}

/// Writes a file atomically: temp file in the same directory, then rename.
/// Matches the "download to temp -> rename" principle used for blocklist
/// downloads and backup restore in this project.
fn write_atomic(path: &str, content: &str) -> std::io::Result<()> {
    let path = Path::new(path);
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(content.as_bytes())?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn is_installed(bin_path: &str) -> bool {
    Path::new(bin_path).exists()
}

/// Applies the security config: writes rc.conf.d snippet, restarts the
/// service if a package is installed, and VERIFIES actual running state
/// afterward (via `service suricata status`, not just the restart exit
/// code) — same verification discipline already applied to Squid/Kea/WireGuard.
/// Tolerant of the package not being installed: prints a warning and
/// returns Ok rather than failing the whole daemon, consistent with the
/// unconditional-startup-reapply pattern adopted for Squid/Kea/WireGuard
/// after the WireGuard reapply RCA earlier this Tier.
pub fn apply_security_conf(cfg: &SecurityConfig) -> Result<(), String> {
    if !is_installed(SURICATA_BIN) {
        eprintln!("[security] suricata not installed, skipping apply (not fatal)");
        return Ok(());
    }

    // IPS pilot: rewrite the netmap: section in suricata.yaml BEFORE the
    // rc.conf.d snippet + restart below, so the two never disagree about
    // which mode is active (a mismatch here is exactly the kind of
    // misconfiguration Suricata's own docs warn can cause connectivity
    // loss - do this deterministically, not best-effort).
    if Path::new(SURICATA_YAML).exists() {
        apply_ips_pilot_yaml(cfg)?;
    }

    let snippet = generate_rc_conf_snippet(cfg);
    write_atomic(SURICATA_RC_CONF_D, &snippet)
        .map_err(|e| format!("failed to write {}: {}", SURICATA_RC_CONF_D, e))?;

    let iface_line = build_suricata_interface_line(&cfg.zones);
    let ips_active = cfg.ips.enabled && !cfg.ips.pilot_interfaces.is_empty();

    // RCA (ditemukan lewat testing nyata bro - IPS Pilot dicentang,
    // config tersimpan benar, /etc/rc.conf.d/suricata BERSIH dan BENAR
    // (netmap="YES"), TAPI Suricata tetap start PCAP mode bukan netmap):
    // generate_rc_conf_snippet() SENGAJA cuma menulis variabel yang
    // RELEVAN untuk mode saat ini (mis. mode IPS cuma menulis
    // suricata_netmap="YES", TIDAK menulis suricata_interface sama
    // sekali) - tapi "tidak menulis di file BARU" TIDAK SAMA DENGAN
    // "menghapus nilai LAMA" yang mungkin sudah tersimpan di
    // /etc/rc.conf UTAMA (dari sebelum project ini pindah ke pola
    // rc.conf.d, atau dari sesi konfigurasi manual/PCAP sebelumnya).
    // rc.conf.d cuma BISA menimpa variabel yang disebut eksplisit -
    // tidak bisa "mengosongkan" variabel dari sumber lain.
    //
    // RCA LANJUTAN (giliran KEDUA bug kelas yang SAMA ditemukan -
    // sebelumnya cuma suricata_interface yang dibersihkan, TERNYATA
    // suricata_netmap sendiri JUGA bisa basi dengan cara yang SAMA
    // persis: nilai "NO" lama tersisa di /etc/rc.conf dari sesi PCAP
    // sebelum IPS Pilot pernah diaktifkan - App Control DROP rule
    // tampak benar ter-generate dan ter-scope, tapi TIDAK PERNAH
    // benar-benar memblokir apa pun karena Suricata jalan mode alert-
    // only/PCAP, bukan netmap inline yang bisa drop paket).
    //
    // Fix MENYELURUH: bersihkan KEDUA variabel dari /etc/rc.conf utama
    // TANPA SYARAT setiap kali apply (bukan cuma salah satu tergantung
    // mode aktif) - snippet rc.conf.d/suricata yang BARU DITULIS di
    // atas SELALU jadi satu-satunya sumber kebenaran untuk variabel
    // mana pun yang relevan ke mode saat ini, jadi TIDAK ADA nilai
    // basi dari file manapun yang boleh dibiarkan hidup berdampingan
    // dengannya, apa pun mode yang sedang aktif.
    let _ = Command::new("sysrc").args(["-x", "suricata_interface"]).status();
    let _ = Command::new("sysrc").args(["-x", "suricata_netmap"]).status();

    let restart_result = if iface_line.is_empty() && !ips_active {
        Command::new("/usr/sbin/service").args(["suricata", "stop"]).status()
    } else {
        Command::new("/usr/sbin/service").args(["suricata", "restart"]).status()
    };
    restart_result.map_err(|e| format!("service suricata restart failed to spawn: {}", e))?;

    // Verify actual state (parse text output, not exit code alone).
    let status_out = Command::new("/usr/sbin/service")
        .args(["suricata", "status"])
        .output()
        .map_err(|e| format!("could not query service status: {}", e))?;
    let status_text = String::from_utf8_lossy(&status_out.stdout);
    let expected_running = !iface_line.is_empty() || ips_active;
    let actually_running = status_text.contains("is running");
    if expected_running != actually_running {
        return Err(format!(
            "post-apply verification mismatch: expected running={}, service status text={}",
            expected_running,
            status_text.trim()
        ));
    }
    Ok(())
}

/// Fase 2 - builds disable.conf content from the admin's disabled-category
/// list, using suricata-update's own documented "group:<filename>" bulk
/// disable mechanism (confirmed from OISF's own suricata-update docs).
pub fn generate_disable_conf(disabled_categories: &[String]) -> String {
    disabled_categories.iter().map(|c| format!("group:{c}\n")).collect()
}

/// Small helper to avoid repeating the same enable-source/warning-capture
/// boilerplate 4 times now that Fase 2 adds two more sources on top of
/// Fase 1's et_open + oisf_trafficid.
fn enable_source(data_dir: &str, source_id: &str, warnings: &mut Vec<String>) {
    let out = Command::new(SURICATA_UPDATE_BIN)
        .args(["--data-dir", data_dir, "enable-source", source_id])
        .output();
    match out {
        Ok(o) if !o.status.success() => {
            warnings.push(format!(
                "failed to enable-source {source_id}: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => warnings.push(format!("failed to spawn enable-source {source_id}: {e}")),
        _ => {}
    }
}

/// Runs suricata-update for the configured sources. Standalone function so
/// it can be shared between the socket action and a future cron flag,
/// same "single source of truth" pattern as run_blocklist_update().
/// suricata-update ships bundled inside the suricata package itself
/// (no separate whitelist dependency needed).
pub fn run_suricata_rule_update(cfg: &SecurityConfig) -> Result<String, String> {
    if !Path::new(SURICATA_UPDATE_BIN).exists() {
        return Err("suricata-update not found (package not installed?)".to_string());
    }

    // RCA SUSULAN #2 (dikonfirmasi dari source code resmi suricata-update
    // di GitHub, BUKAN tebakan lagi setelah fix --data-dir sebelumnya
    // ternyata masih salah - malah bikin path dobel "update/update"
    // karena saya keliru menambah "/update" padahal DEFAULT_DATA_DIRECTORY
    // resminya memang cuma "/var/lib/suricata"):
    //   - SOURCE_DIRECTORY = os.path.join("update", "sources") relatif ke
    //     data-dir -> path sebenarnya: <data-dir>/update/sources
    //   - enable-source memanggil get_sources_from_dir() yang isinya
    //     next(os.walk(source_dir)) - os.walk() pada folder yang BELUM
    //     ADA mengembalikan generator KOSONG, dan next() pada generator
    //     kosong TANPA default value SELALU melempar StopIteration.
    //   - update-sources (dipanggil di atas) HANYA membuat folder cache
    //     index (update/cache), TIDAK PERNAH membuat folder
    //     update/sources - itulah kenapa fix sebelumnya (cuma bootstrap
    //     update-sources) tidak cukup.
    // Fix DEFINITIF: pakai data-dir DEFAULT resmi (jangan override lagi
    // sama sekali - override sebelumnya salah), dan mkdir -p folder
    // update/sources secara eksplisit SEBELUM enable-source dipanggil.
    const DATA_DIR: &str = "/var/lib/suricata";
    let _ = fs::create_dir_all(format!("{DATA_DIR}/update/sources"));

    // RCA (log user, fresh-install VM): "enable-source oisf/trafficid" crash
    // dengan StopIteration Python - root cause: source index belum pernah
    // di-inisialisasi sama sekali (tidak ada ~/.config/suricata/update/sources
    // di sistem baru), suricata-update sendiri cetak petunjuknya di log:
    // "Please run suricata-update update-sources." - enable-source lama-lama
    // coba os.walk() direktori yang belum ada sama sekali, error TIDAK
    // tertangkap, exit non-zero, TAPI kode sebelumnya `let _ = ...` membuang
    // hasilnya diam-diam - jadi rule tambahan gagal ditambahkan tanpa
    // ada tanda apa pun ke admin (rule count yang muncul di Status murni
    // dari ET Open saja). Fix: bootstrap index dulu (idempotent, aman
    // dipanggil setiap run), dan JANGAN buang error enable-source lagi.
    let bootstrap = Command::new(SURICATA_UPDATE_BIN)
        .args(["--data-dir", DATA_DIR, "update-sources"])
        .status();
    if let Err(e) = bootstrap {
        return Err(format!("suricata-update update-sources failed to spawn: {}", e));
    }

    let mut warnings: Vec<String> = Vec::new();

    if cfg.rule_sources.oisf_trafficid {
        enable_source(DATA_DIR, "oisf/trafficid", &mut warnings);
    }
    // Fase 2 - dua source tambahan, ID dikonfirmasi PERSIS dari output
    // 'suricata-update list-sources' asli (bukan tebakan seperti
    // snort/community dulu, RCA-13): abuse.ch/sslbl-ja3 dan
    // abuse.ch/urlhaus.
    if cfg.rule_sources.abuse_ch_ja3 {
        enable_source(DATA_DIR, "abuse.ch/sslbl-ja3", &mut warnings);
    }
    if cfg.rule_sources.abuse_ch_urlhaus {
        enable_source(DATA_DIR, "abuse.ch/urlhaus", &mut warnings);
    }
    // RCA SUSULAN #3 (dikonfirmasi dari log user - rule count anjlok dari
    // 52044 ke 408 TEPAT setelah oisf/trafficid berhasil di-enable): ET
    // Open TIDAK PERNAH di-enable-source secara eksplisit di sini -
    // sebelumnya "berhasil" cuma karena suricata-update punya fallback
    // implisit "no sources configured -> pakai ET Open" (persis pesan
    // yang muncul di log test paling awal). Begitu ADA source lain yang
    // di-enable eksplisit (oisf/trafficid), fallback implisit itu tidak
    // berlaku lagi - ET Open jadi butuh di-enable-source SENDIRI, sama
    // seperti source lainnya, bukan cuma "dibiarkan karena default".
    // Fix: enable-source et/open SELALU dipanggil eksplisit kalau admin
    // menghendakinya - jangan lagi mengandalkan default implisit yang
    // ternyata rapuh begitu source lain ikut aktif.
    if cfg.rule_sources.et_open {
        enable_source(DATA_DIR, "et/open", &mut warnings);
    } else {
        let out = Command::new(SURICATA_UPDATE_BIN)
            .args(["--data-dir", DATA_DIR, "disable-source", "et/open"])
            .output();
        if let Ok(o) = &out {
            if !o.status.success() {
                warnings.push(format!(
                    "failed to disable-source et/open: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
        }
    }

    // Fase 2 - Policy: tulis disable.conf dari daftar kategori yang
    // di-nonaktifkan admin, mekanisme "group:<filename>" dikonfirmasi
    // resmi dari dokumentasi suricata-update sendiri (bukan tebakan).
    // SELALU ditulis ulang (walau kosong) supaya kategori yang baru
    // di-ENABLE-kan lagi oleh admin benar-benar hilang dari file, bukan
    // basi dari run sebelumnya.
    let disable_conf_content = generate_disable_conf(&cfg.policy.disabled_categories);
    if let Some(parent) = Path::new(SURICATA_DISABLE_CONF).parent() {
        let _ = fs::create_dir_all(parent);
    }
    write_atomic(SURICATA_DISABLE_CONF, &disable_conf_content)
        .map_err(|e| format!("failed to write {}: {}", SURICATA_DISABLE_CONF, e))?;

    // Fase 2 - Custom rules: tulis local.rules dari textarea admin, di-merge
    // oleh suricata-update sendiri lewat --local dan divalidasi otomatis
    // via 'suricata -T' yang SUDAH jadi bagian pipeline suricata-update -
    // tidak perlu validasi syntax terpisah di sisi kita, cukup pastikan
    // exit code suricata-update di bawah tetap diperiksa seperti biasa.
    if let Some(parent) = Path::new(SURICATA_LOCAL_RULES).parent() {
        let _ = fs::create_dir_all(parent);
    }
    // App Control DIHAPUS dari CE (permintaan user - fitur ini tetap
    // Pro-only) - local.rules sekarang cuma berisi custom_rules_text
    // admin sendiri, tanpa konkatenasi rule auto-generated apa pun.
    let combined_rules = format!("{}\n", cfg.custom_rules_text);
    write_atomic(SURICATA_LOCAL_RULES, &combined_rules)
        .map_err(|e| format!("failed to write {}: {}", SURICATA_LOCAL_RULES, e))?;

    let mut cmd = Command::new(SURICATA_UPDATE_BIN);
    cmd.args([
        "--data-dir", DATA_DIR,
        "--suricata", SURICATA_BIN,
        "--disable-conf", SURICATA_DISABLE_CONF,
        "--local", SURICATA_LOCAL_RULES,
    ]);
    let output = cmd.output().map_err(|e| format!("suricata-update failed to spawn: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "suricata-update exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut result = String::from_utf8_lossy(&output.stdout).to_string();

    // RCA (test nyata, custom rule drop test yang tidak pernah match
    // traffic sama sekali walau rule sudah benar dan sudah ter-load ke
    // suricata.rules): suricata-update HANYA menulis file
    // /var/lib/suricata/rules/suricata.rules yang baru - TIDAK PERNAH
    // memberi tahu proses Suricata yang SEDANG BERJALAN untuk baca ulang
    // file itu. Proses yang sudah start sebelumnya terus pakai ruleset
    // versi lamanya sampai ada trigger terpisah (restart service, atau
    // reboot) - yang selama pengujian sebelumnya SELALU kebetulan
    // terjadi berdekatan waktu (banyak reboot/redeploy), menutupi gap
    // ini sampai baru ketahuan lewat test drop-rule yang presisi
    // waktunya. Fix: kirim SIGUSR2 ke proses Suricata yang sedang jalan
    // setelah suricata-update sukses - ini mekanisme RESMI Suricata
    // untuk live rule reload (dikonfirmasi dari docs.suricata.io,
    // BUKAN restart layanan penuh) - tidak ada gangguan capture sama
    // sekali, penting khusus untuk mode IPS supaya tidak ada jendela
    // waktu traffic lewat tanpa terinspeksi.
    match fs::read_to_string("/var/run/suricata.pid") {
        Ok(pid_str) => {
            let pid = pid_str.trim();
            let reload_status = Command::new("kill").args(["-USR2", pid]).status();
            match reload_status {
                Ok(s) if s.success() => {
                    result.push_str(&format!("\n\nLive rule reload signal (SIGUSR2) sent to Suricata (pid {pid}) - new ruleset now active without restart.\n"));
                }
                Ok(s) => warnings.push(format!("kill -USR2 {pid} exited non-zero: {s}")),
                Err(e) => warnings.push(format!("failed to spawn kill -USR2 {pid}: {e}")),
            }
        }
        Err(e) => {
            warnings.push(format!(
                "could not read /var/run/suricata.pid to send live-reload signal ({e}) - ruleset was written to disk \
                 but the RUNNING Suricata process may still be using the OLD ruleset until it is restarted manually."
            ));
        }
    }

    // Diagnostik eksplisit - supaya admin bisa lihat source mana yang
    // BENAR-BENAR aktif tanpa perlu SSH (masalah nyata: rule count tidak
    // berubah setelah enable-source, tanpa ini admin tidak punya cara
    // konfirmasi apakah source memang aktif tapi kebetulan overlap penuh
    // dengan ET Open, atau diam-diam gagal ter-enable).
    let enabled_sources_out = Command::new(SURICATA_UPDATE_BIN)
        .args(["--data-dir", DATA_DIR, "list-enabled-sources"])
        .output();
    if let Ok(o) = enabled_sources_out {
        result.push_str("\n\n--- suricata-update list-enabled-sources ---\n");
        result.push_str(&String::from_utf8_lossy(&o.stdout));
    }

    if !warnings.is_empty() {
        result.push_str("\n\nWARNING:\n");
        result.push_str(&warnings.join("\n"));
    }
    Ok(result)
}

// ---------------------------------------------------------------------
// Config persistence (mirrors existing JSON-file-per-feature pattern)
// ---------------------------------------------------------------------

pub fn load_security_config() -> SecurityConfig {
    let mut cfg: SecurityConfig = fs::read_to_string(SURICATA_CONFIG_JSON)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(SecurityConfig {
            zones: vec![],
            rule_sources: RuleSourceConfig::default(),
            auto_update_enabled: true,
            last_rule_update: None,
            policy: PolicyConfig::default(),
            custom_rules_text: String::new(),
            ips: IpsPilotConfig::default(),
        });
    // Migrasi config lama (single pilot_interface, era WAN1-only) ke
    // pilot_interfaces - dijalankan SETIAP load, tapi cuma benar-benar
    // mengubah apa pun kalau field baru masih kosong DAN field lama
    // punya nilai (idempotent, aman dipanggil berkali-kali).
    if cfg.ips.pilot_interfaces.is_empty() && !cfg.ips.pilot_interface.is_empty() {
        cfg.ips.pilot_interfaces = vec![cfg.ips.pilot_interface.clone()];
    }
    cfg
}

pub fn save_security_config(cfg: &SecurityConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    write_atomic(SURICATA_CONFIG_JSON, &json).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------
// Unit tests — mirrors the Python pre-validation pass 1:1
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_zones() -> Vec<ZoneSecurityToggle> {
        vec![
            ZoneSecurityToggle { zone_alias: "MGMT".into(), physical_if: "em2".into(), enabled: false },
            ZoneSecurityToggle { zone_alias: "WAN1".into(), physical_if: "em0".into(), enabled: true },
            ZoneSecurityToggle { zone_alias: "LAN1".into(), physical_if: "em1".into(), enabled: false },
            ZoneSecurityToggle { zone_alias: "OPT1".into(), physical_if: "em3".into(), enabled: true },
        ]
    }

    #[test]
    fn test_interface_line_multi_zone() {
        let line = build_suricata_interface_line(&sample_zones());
        assert_eq!(line, "em0 em3");
    }

    #[test]
    fn test_interface_line_none_enabled_is_fail_closed() {
        let zones = vec![ZoneSecurityToggle { zone_alias: "LAN1".into(), physical_if: "em1".into(), enabled: false }];
        let line = build_suricata_interface_line(&zones);
        assert_eq!(line, "");
    }

    #[test]
    fn test_rc_conf_snippet_disables_when_empty() {
        let cfg = SecurityConfig {
            zones: vec![ZoneSecurityToggle { zone_alias: "LAN1".into(), physical_if: "em1".into(), enabled: false }],
            rule_sources: RuleSourceConfig::default(),
            auto_update_enabled: true,
            last_rule_update: None,
            policy: PolicyConfig::default(),
            custom_rules_text: String::new(),
            ips: IpsPilotConfig::default(),
        };
        let snippet = generate_rc_conf_snippet(&cfg);
        assert_eq!(snippet, "suricata_enable=\"NO\"\n");
    }

    #[test]
    fn test_rc_conf_snippet_multi_interface() {
        let cfg = SecurityConfig {
            zones: sample_zones(),
            rule_sources: RuleSourceConfig::default(),
            auto_update_enabled: true,
            last_rule_update: None,
            policy: PolicyConfig::default(),
            custom_rules_text: String::new(),
            ips: IpsPilotConfig::default(),
        };
        let snippet = generate_rc_conf_snippet(&cfg);
        assert!(snippet.contains("suricata_enable=\"YES\""));
        assert!(snippet.contains("suricata_interface=\"em0 em3\""));
        assert!(snippet.contains("suricata_netmap=\"NO\""));
    }

    #[test]
    fn test_parse_eve_alerts_sorts_and_filters() {
        let lines = vec![
            r#"{"timestamp":"2026-07-18T10:00:00.0000","event_type":"flow"}"#.to_string(),
            r#"{"timestamp":"2026-07-18T10:01:00.0000","event_type":"alert","alert":{"severity":2,"signature":"ET SCAN Nmap Scripting Engine","category":"Attempted Information Leak"},"src_ip":"203.0.113.5","dest_ip":"192.168.10.20","proto":"TCP","in_iface":"em0"}"#.to_string(),
            r#"{"timestamp":"2026-07-18T09:55:00.0000","event_type":"alert","alert":{"severity":1,"signature":"ET MALWARE Suspicious C2 beacon","category":"Malware Command and Control"},"src_ip":"192.168.10.20","dest_ip":"198.51.100.9","proto":"TCP","in_iface":"em0"}"#.to_string(),
            "not even json {{{".to_string(),
        ];
        let result = parse_eve_alerts(&lines, 50);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].signature.as_deref(), Some("ET SCAN Nmap Scripting Engine"));
        assert_eq!(result[1].severity, Some(1));
    }

    #[test]
    fn test_parse_eve_alerts_respects_limit() {
        let mut lines = vec![];
        for i in 0..10 {
            lines.push(format!(
                r#"{{"timestamp":"2026-07-18T10:{:02}:00.0000","event_type":"alert","alert":{{"severity":3,"signature":"test {}"}}}}"#,
                i, i
            ));
        }
        let result = parse_eve_alerts(&lines, 3);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_generate_disable_conf_empty() {
        let content = generate_disable_conf(&[]);
        assert_eq!(content, "");
    }

    #[test]
    fn test_generate_disable_conf_multi_category() {
        let categories = vec!["emerging-chat.rules".to_string(), "emerging-p2p.rules".to_string()];
        let content = generate_disable_conf(&categories);
        assert_eq!(content, "group:emerging-chat.rules\ngroup:emerging-p2p.rules\n");
    }

    // Real excerpt from the actual suricata.yaml shipped on the test VM
    // (confirmed via SSH before writing this logic - not an assumed
    // structure). Trimmed to the minimum needed to validate the block
    // boundaries; the real file has ~2100 unrelated lines before this.
    fn sample_suricata_yaml() -> String {
        "some:\n  earlier: config\n\n\
         # built-in Netmap support or compile and install the Netmap module\n\
         netmap:\n\
         \x20  # To specify OS endpoint add plus sign at the end (e.g. \"eth0+\")\n\
         \x20- interface: eth2\n\
         \x20  #threads: auto\n\
         \x20  #copy-mode: tap\n\
         \x20  #copy-iface: eth3\n\
         \x20#- interface: eth3\n\
         \x20  #threads: auto\n\
         \x20- interface: default\n\
         # PF_RING configuration: for use with native PF_RING support\n\
         pfring:\n\
         \x20 - interface: eth0\n\
         \x20   threads: auto\n".to_string()
    }

    #[test]
    fn test_regenerate_netmap_section_enable_pilot() {
        let result = regenerate_netmap_section(&sample_suricata_yaml(), "em5", true).unwrap();
        assert!(result.contains("- interface: em5"));
        assert!(result.contains("copy-mode: ips"));
        assert!(result.contains("copy-iface: em5^"), "outbound stanza (physical -> host-stack ring) missing");
        assert!(result.contains("- interface: em5^"), "return-path stanza (host-stack ring -> physical) missing - this is the bug that broke LAN client traffic in real testing");
        assert!(result.contains("copy-iface: em5"), "return-path copy-iface must point back at the physical interface");
        assert!(!result.contains("eth2"), "stale placeholder interface must be gone");
        assert!(result.contains("pfring:"), "next section must be untouched");
        assert!(result.contains("- interface: eth0"), "pfring content must be untouched");
    }

    #[test]
    fn test_regenerate_netmap_section_disable_is_safe_noop() {
        let result = regenerate_netmap_section(&sample_suricata_yaml(), "em5", false).unwrap();
        assert!(!result.contains("copy-mode: ips"));
        assert!(!result.contains("em5"));
        assert!(result.contains("pfring:"));
    }

    #[test]
    fn test_regenerate_netmap_section_missing_key_errors_instead_of_guessing() {
        let no_netmap_key = "some:\n  config: here\npfring:\n  - interface: eth0\n".to_string();
        let result = regenerate_netmap_section(&no_netmap_key, "em5", true);
        assert!(result.is_err(), "must refuse rather than guess an insertion point");
    }
}
