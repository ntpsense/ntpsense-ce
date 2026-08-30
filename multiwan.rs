// multiwan.rs — NTPSense Tier 2, Multi-WAN / SD-WAN-lite plugin
//
// Diriset dulu sebelum satu baris kode pun ditulis (permintaan bro
// eksplisit + prinsip project ini): pfSense Gateway Groups, FortiGate
// SD-WAN, Palo Alto, Sangfor, dan FreeBSD pf.conf(5) langsung. Temuan
// paling menentukan desain modul ini:
//
// 1. `route-to`/`reply-to` di pf HANYA berlaku untuk traffic TRANSIT
//    (lewat router) - TIDAK berlaku untuk traffic yang berasal/berakhir
//    DI router itu sendiri (dikonfirmasi dari banyak sumber independen,
//    termasuk thread Netgate yang eksplisit: "route-to dan reply-to
//    tidak mengalahkan routing table default untuk traffic yang
//    originates/terminates di router itu sendiri"). Makanya modul ini
//    py dua mekanisme TERPISAH:
//      a. route-to injection ke Firewall custom rule (traffic klien
//         LAN/OPT) - lewat compute_route_to_clause().
//      b. System default gateway switching (traffic milik NTPSense
//         sendiri: update check, NTP sync, DNS) - lewat
//         apply_system_default_gateway(), HANYA mode failover (pfSense
//         sendiri eksplisit: "This function is not compatible with
//         load balancing, only failover" - traffic asal-router terlalu
//         kecil volumenya untuk ada gunanya di-load-balance).
//
// 2. FreeBSD pf SUDAH native dukung round-robin multi-gateway:
//    `route-to { (if1 gw1), (if2 gw2) } round-robin sticky-address`
//    (dikonfirmasi dipakai orang di forum FreeBSD, BUKAN cuma sintaks
//    OpenBSD). Ini artinya Failover dan Load Balancing BISA pakai SATU
//    mekanisme yang sama: kumpulkan semua gateway Up di tier TERENDAH
//    yang masih punya anggota Up - kalau cuma 1 anggota, hasilnya
//    otomatis functionally-failover; kalau 2+, otomatis jadi
//    round-robin/load-balance. Tidak perlu kode terpisah per mode.
//    CATATAN: FreeBSD pf TIDAK dukung 'weight N' (itu sintaks
//    OpenBSD-only, dikonfirmasi dari forum FreeBSD) - load balancing
//    kita SELALU proporsi rata (unweighted), bukan persentase custom
//    per WAN.
//
// 3. `dpinger` (daemon monitoring pfSense) TIDAK ada di FreeBSD stock -
//    monitor sendiri dibangun di modul ini (run_monitor_cycle(),
//    dipanggil looping dari thread terpisah di main()).
//
// 4. Dua RCA nyata dari histori bug pfSense (BUKAN hipotetis - dibaca
//    langsung dari bug tracker mereka) yang SENGAJA dihindari sejak
//    desain awal, bukan ditambal belakangan:
//      a. Bug #11960: ping monitoring untuk gateway yang sedang TIDAK
//         aktif bisa ikut lewat interface yang SEDANG aktif (default
//         route), bikin status "loss" nyangkut 100% permanen meski
//         gateway itu sudah pulih. Fix: setiap ping monitor WAJIB
//         di-bind ke source IP interface-nya SENDIRI (`ping -S <ip>`),
//         bukan mengandalkan default route saat itu.
//      b. Bug #11570 (regression): gateway yang sempat turun tidak
//         selalu di-monitor ulang setelah interface event, bikin
//         default gateway GAGAL switch balik meski gateway utama sudah
//         pulih. Fix: monitor SEMUA gateway TANPA SYARAT tiap cycle,
//         terlepas dari status aktif/tidaknya saat ini - jangan pernah
//         berhenti mengecek gateway yang sedang down.
//
// 5. Site Mesh VPN (Headscale/Tailscale) WAN preference (fitur baru,
//    Agustus 2026) - PENTING dipahami: traffic tailscaled adalah
//    traffic ASAL-ROUTER (proses berjalan DI gateway itu sendiri,
//    persis seperti NTP sync/DNS/update check) - BUKAN traffic
//    transit klien LAN. Artinya traffic ini SUDAH DARI AWAL mengikuti
//    mekanisme 1.b (apply_system_default_gateway()), BUKAN mekanisme
//    1.a (route-to) - TIDAK PERLU jalur routing baru sama sekali.
//    Begitu admin susun System Default Gateway Group dengan tier
//    dedicated-WAN di angka lebih kecil (prioritas lebih tinggi) dari
//    tier shared/NAT-WAN, Site Mesh VPN OTOMATIS ikut prefer dedicated
//    - persis seperti NTP/DNS/update sudah otomatis begitu sejak awal.
//    Gap SESUNGGUHNYA yang ditemukan: TIDAK ADA konsep "dedicated vs
//    shared" di data model Gateway sama sekali, sehingga TIDAK ADA
//    cara memvalidasi/memperingatkan admin kalau tier System Default
//    Gateway Group tersusun terbalik (shared WAN ditaruh di tier lebih
//    prioritas dari dedicated WAN) - kesalahan konfigurasi yang mudah
//    terjadi dan sulit disadari admin sampai insiden nyata (failover
//    WAN dedicated tapi Site Mesh VPN/NTP/DNS ternyata tetap lewat WAN
//    shared/NAT karena tier salah susun). Fix: tambah field
//    `link_type` ke Gateway + validasi peringatan (BUKAN blocking -
//    admin mungkin punya alasan sengaja) saat System Default Gateway
//    Group di-set/diupdate.
use std::collections::HashMap;
use std::fs;
use std::process::{Command, Stdio};
use serde::{Deserialize, Serialize};
pub const GATEWAYS_FILE: &str = "/usr/local/etc/ntpsense/multiwan-gateways.json";
pub const GATEWAY_GROUPS_FILE: &str = "/usr/local/etc/ntpsense/multiwan-groups.json";
pub const MULTIWAN_STATUS_FILE: &str = "/usr/local/etc/ntpsense/webui/multiwan-status.json";
pub const MULTIWAN_EVENT_LOG: &str = "/var/log/ntpsense-multiwan.log";
const ROUTE_OPS_LOG: &str = "/var/log/ntpsense-route-ops.log";
const DEFAULT_INTERVAL_SECS: u64 = 5;
const DEFAULT_FAIL_THRESHOLD: u32 = 3;
const DEFAULT_RECOVER_THRESHOLD: u32 = 3;
const PING_TIMEOUT_SECS: u32 = 2;
const PING_BURST_COUNT: u32 = 5;
pub const SETTINGS_FILE: &str = "/usr/local/etc/ntpsense/multiwan-settings.json";
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckSettings {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_fail_threshold")]
    pub fail_threshold: u32,
    #[serde(default = "default_recover_threshold")]
    pub recover_threshold: u32,
}
fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}
fn default_fail_threshold() -> u32 {
    DEFAULT_FAIL_THRESHOLD
}
fn default_recover_threshold() -> u32 {
    DEFAULT_RECOVER_THRESHOLD
}
impl Default for HealthCheckSettings {
    fn default() -> Self {
        HealthCheckSettings {
            interval_secs: DEFAULT_INTERVAL_SECS,
            fail_threshold: DEFAULT_FAIL_THRESHOLD,
            recover_threshold: DEFAULT_RECOVER_THRESHOLD,
        }
    }
}
pub fn load_settings() -> HealthCheckSettings {
    fs::read_to_string(SETTINGS_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}
pub fn save_settings(interval_secs: u64, fail_threshold: u32, recover_threshold: u32) -> Result<(), String> {
    if !(1..=60).contains(&interval_secs) {
        return Err("Interval must be between 1 and 60 seconds.".to_string());
    }
    if !(1..=10).contains(&fail_threshold) {
        return Err("Fail threshold must be between 1 and 10.".to_string());
    }
    if !(1..=10).contains(&recover_threshold) {
        return Err("Recover threshold must be between 1 and 10.".to_string());
    }
    let settings = HealthCheckSettings { interval_secs, fail_threshold, recover_threshold };
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(SETTINGS_FILE, json).map_err(|e| e.to_string())?;
    log_event(&format!(
        "Health-check settings updated: interval={interval_secs}s, fail_threshold={fail_threshold}, recover_threshold={recover_threshold}"
    ));
    Ok(())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub name: String,
    pub interface: String,
    pub gateway_ip: String,
    #[serde(default)]
    pub monitor_ip: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    // BARU (Agustus 2026, fitur Site Mesh VPN WAN preference) -
    // "dedicated" (link fiber sendiri, IP publik sendiri) atau "shared"
    // (link NAT/wireless yang dipakai bersama, biasanya backup) -
    // dipakai MURNI untuk validasi/peringatan susunan tier System
    // Default Gateway Group (lihat validate_system_default_ordering())
    // - TIDAK mengubah mekanisme routing apa pun dengan sendirinya,
    // cuma metadata untuk membantu admin susun tier dengan benar.
    // Default "dedicated" untuk backward-compat (data lama tanpa field
    // ini dianggap semua dedicated - asumsi paling aman, tidak memicu
    // peringatan palsu untuk instalasi yang sudah ada).
    #[serde(default = "default_link_type")]
    pub link_type: String,
}
fn default_true() -> bool {
    true
}
fn default_link_type() -> String {
    "dedicated".to_string()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayGroupMember {
    pub gateway_name: String,
    pub tier: u8,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayGroup {
    pub name: String,
    pub members: Vec<GatewayGroupMember>,
    #[serde(default)]
    pub is_system_default: bool,
    #[serde(default = "default_routing_mode")]
    pub routing_mode: String,
    #[serde(default)]
    pub sla_max_latency_ms: Option<f64>,
    #[serde(default)]
    pub sla_max_jitter_ms: Option<f64>,
    #[serde(default)]
    pub sla_max_packet_loss_pct: Option<f64>,
}
fn default_routing_mode() -> String {
    "static".to_string()
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct GatewaysFile {
    #[serde(default)]
    gateways: Vec<Gateway>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct GroupsFile {
    #[serde(default)]
    groups: Vec<GatewayGroup>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayLiveStatus {
    up: bool,
    consecutive_success: u32,
    consecutive_fail: u32,
    last_checked_ts: u64,
    #[serde(default)]
    avg_latency_ms: Option<f64>,
    #[serde(default)]
    jitter_ms: Option<f64>,
    #[serde(default)]
    packet_loss_pct: Option<f64>,
}
impl Default for GatewayLiveStatus {
    fn default() -> Self {
        GatewayLiveStatus {
            up: true,
            consecutive_success: 0,
            consecutive_fail: 0,
            last_checked_ts: 0,
            avg_latency_ms: None,
            jitter_ms: None,
            packet_loss_pct: None,
        }
    }
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct StatusFile {
    #[serde(default)]
    gateways: HashMap<String, GatewayLiveStatus>,
}
fn load_gateways_file() -> GatewaysFile {
    fs::read_to_string(GATEWAYS_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}
fn save_gateways_file(data: &GatewaysFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(GATEWAYS_FILE, json).map_err(|e| e.to_string())
}
fn load_groups_file() -> GroupsFile {
    fs::read_to_string(GATEWAY_GROUPS_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}
fn save_groups_file(data: &GroupsFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(GATEWAY_GROUPS_FILE, json).map_err(|e| e.to_string())
}
fn load_status_file() -> StatusFile {
    fs::read_to_string(MULTIWAN_STATUS_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}
fn save_status_file(data: &StatusFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    if let Some(dir) = std::path::Path::new(MULTIWAN_STATUS_FILE).parent() {
        if !dir.exists() {
            let _ = fs::create_dir_all(dir);
        }
    }
    fs::write(MULTIWAN_STATUS_FILE, json).map_err(|e| e.to_string())
}
fn log_event(message: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{} {message}\n", format_unix_ts(ts));
    if let Ok(mut existing) = fs::OpenOptions::new().create(true).append(true).open(MULTIWAN_EVENT_LOG) {
        use std::io::Write as _;
        let _ = existing.write_all(line.as_bytes());
    }
}
fn route_log_stdio() -> Stdio {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ROUTE_OPS_LOG)
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null())
}
pub fn ensure_route_log_rotation() {
    let content = fs::read_to_string("/etc/newsyslog.conf").unwrap_or_default();
    if content.contains(ROUTE_OPS_LOG) {
        return;
    }
    let line = format!("{ROUTE_OPS_LOG}\t\t\t\t644  90    *    $D0   Z\n");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open("/etc/newsyslog.conf") {
        use std::io::Write as _;
        let _ = f.write_all(line.as_bytes());
    }
}
fn format_unix_ts(ts: u64) -> String {
    let days_since_epoch = ts / 86400;
    let secs_of_day = ts % 86400;
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
    let mut days = days_since_epoch as i64;
    let mut year = 1970i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for md in month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    format!("{year:04}-{month:02}-{:02} {h:02}:{m:02}:{s:02}", days + 1)
}
pub fn eligible_wan_interfaces() -> Vec<String> {
    let (_mgmt_if, _lan1_if, opt_ifaces) = super::parse_pf_conf_zones();
    let wan1_if = super::get_wan1_interface();
    let roles = super::load_roles();
    let mut result: Vec<String> = Vec::new();
    if let Some(w) = wan1_if {
        result.push(w);
    }
    for o in opt_ifaces {
        if roles.get(&o).map(|r| r == "WAN").unwrap_or(false) {
            result.push(o);
        }
    }
    result
}
pub fn list_gateways() -> Vec<Gateway> {
    load_gateways_file().gateways
}
fn sync_monitor_route(old_monitor_ip: &str, new_gateway_ip: &str, new_monitor_ip: &str) {
    if !old_monitor_ip.is_empty() && old_monitor_ip != new_monitor_ip {
        let _ = Command::new("route").args(["delete", "-host", old_monitor_ip]).stdout(route_log_stdio()).stderr(route_log_stdio()).status();
    }
    if !new_monitor_ip.is_empty() && new_monitor_ip != old_monitor_ip {
        let _ = Command::new("route").args(["add", "-host", new_monitor_ip, new_gateway_ip]).stdout(route_log_stdio()).stderr(route_log_stdio()).status();
    }
}
pub fn reapply_monitor_routes() {
    for gw in list_gateways() {
        if !gw.monitor_ip.is_empty() {
            sync_monitor_route("", &gw.gateway_ip, &gw.monitor_ip);
        }
    }
}
pub fn create_gateway(name: &str, interface: &str, gateway_ip: &str, monitor_ip: &str, link_type: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Gateway name cannot be empty.".to_string());
    }
    if super::parse_ipv4(gateway_ip).is_none() {
        return Err(format!("'{gateway_ip}' is not a valid IPv4 gateway address."));
    }
    if !monitor_ip.is_empty() && super::parse_ipv4(monitor_ip).is_none() {
        return Err(format!("'{monitor_ip}' is not a valid IPv4 monitor address."));
    }
    if link_type != "dedicated" && link_type != "shared" {
        return Err("link_type must be 'dedicated' or 'shared'.".to_string());
    }
    if !eligible_wan_interfaces().contains(&interface.to_string()) {
        return Err(format!(
            "'{interface}' is not eligible as a Multi-WAN gateway interface - it must be WAN1, or an OPT/LAGG/VLAN interface with Role set to WAN first."
        ));
    }
    let mut data = load_gateways_file();
    if !monitor_ip.is_empty() && data.gateways.iter().any(|g| !g.monitor_ip.is_empty() && g.monitor_ip == monitor_ip) {
        return Err(format!(
            "Monitor IP '{monitor_ip}' is already used by another gateway - each gateway needs its own unique Monitor IP (or leave it empty to monitor the gateway IP directly, which is always safe to share since it never needs a separate route)."
        ));
    }
    if data.gateways.iter().any(|g| g.name.eq_ignore_ascii_case(name)) {
        return Err(format!("A gateway named '{name}' already exists."));
    }
    if data.gateways.iter().any(|g| g.interface == interface) {
        return Err(format!("Interface '{interface}' is already used by another gateway."));
    }
    data.gateways.push(Gateway {
        name: name.to_string(),
        interface: interface.to_string(),
        gateway_ip: gateway_ip.to_string(),
        monitor_ip: monitor_ip.to_string(),
        enabled: true,
        link_type: link_type.to_string(),
    });
    save_gateways_file(&data)?;
    sync_monitor_route("", gateway_ip, monitor_ip);
    log_event(&format!("Gateway '{name}' created ({interface}, next-hop {gateway_ip}, link_type={link_type})"));
    Ok(())
}
pub fn update_gateway(name: &str, gateway_ip: &str, monitor_ip: &str, enabled: bool, link_type: &str) -> Result<(), String> {
    if super::parse_ipv4(gateway_ip).is_none() {
        return Err(format!("'{gateway_ip}' is not a valid IPv4 gateway address."));
    }
    if !monitor_ip.is_empty() && super::parse_ipv4(monitor_ip).is_none() {
        return Err(format!("'{monitor_ip}' is not a valid IPv4 monitor address."));
    }
    if link_type != "dedicated" && link_type != "shared" {
        return Err("link_type must be 'dedicated' or 'shared'.".to_string());
    }
    let mut data = load_gateways_file();
    if !monitor_ip.is_empty() && data.gateways.iter().any(|g| g.name != name && !g.monitor_ip.is_empty() && g.monitor_ip == monitor_ip) {
        return Err(format!(
            "Monitor IP '{monitor_ip}' is already used by another gateway - each gateway needs its own unique Monitor IP (or leave it empty to monitor the gateway IP directly)."
        ));
    }
    let Some(gw) = data.gateways.iter_mut().find(|g| g.name == name) else {
        return Err(format!("Gateway '{name}' not found."));
    };
    let old_monitor_ip = gw.monitor_ip.clone();
    gw.gateway_ip = gateway_ip.to_string();
    gw.monitor_ip = monitor_ip.to_string();
    gw.enabled = enabled;
    gw.link_type = link_type.to_string();
    save_gateways_file(&data)?;
    sync_monitor_route(&old_monitor_ip, gateway_ip, monitor_ip);
    check_and_log_system_default_ordering();
    Ok(())
}
pub fn delete_gateway(name: &str) -> Result<(), String> {
    let groups = load_groups_file().groups;
    let in_use: Vec<String> = groups
        .iter()
        .filter(|g| g.members.iter().any(|m| m.gateway_name == name))
        .map(|g| g.name.clone())
        .collect();
    if !in_use.is_empty() {
        return Err(format!(
            "Cannot delete gateway '{name}' - still a member of group(s): {}. Remove it from those groups first.",
            in_use.join(", ")
        ));
    }
    let mut data = load_gateways_file();
    let existing = data.gateways.iter().find(|g| g.name == name).cloned();
    let before = data.gateways.len();
    data.gateways.retain(|g| g.name != name);
    if data.gateways.len() == before {
        return Err(format!("Gateway '{name}' not found."));
    }
    save_gateways_file(&data)?;
    if let Some(gw) = existing {
        sync_monitor_route(&gw.monitor_ip, &gw.gateway_ip, "");
    }
    let mut status = load_status_file();
    status.gateways.remove(name);
    let _ = save_status_file(&status);
    log_event(&format!("Gateway '{name}' deleted"));
    Ok(())
}
pub fn list_groups() -> Vec<GatewayGroup> {
    load_groups_file().groups
}
pub fn create_group(
    name: &str,
    members: Vec<GatewayGroupMember>,
    routing_mode: &str,
    sla_max_latency_ms: Option<f64>,
    sla_max_jitter_ms: Option<f64>,
    sla_max_packet_loss_pct: Option<f64>,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Group name cannot be empty.".to_string());
    }
    if members.is_empty() {
        return Err("A gateway group needs at least one member.".to_string());
    }
    if routing_mode != "static" && routing_mode != "quality" {
        return Err("routing_mode must be 'static' or 'quality'.".to_string());
    }
    let known_gateways: Vec<String> = list_gateways().iter().map(|g| g.name.clone()).collect();
    for m in &members {
        if !known_gateways.contains(&m.gateway_name) {
            return Err(format!("Gateway '{}' does not exist.", m.gateway_name));
        }
    }
    let mut data = load_groups_file();
    if data.groups.iter().any(|g| g.name.eq_ignore_ascii_case(name)) {
        return Err(format!("A group named '{name}' already exists."));
    }
    data.groups.push(GatewayGroup {
        name: name.to_string(),
        members,
        is_system_default: false,
        routing_mode: routing_mode.to_string(),
        sla_max_latency_ms,
        sla_max_jitter_ms,
        sla_max_packet_loss_pct,
    });
    save_groups_file(&data)?;
    log_event(&format!("Gateway Group '{name}' created (routing_mode={routing_mode})"));
    Ok(())
}
pub fn update_group(
    name: &str,
    members: Vec<GatewayGroupMember>,
    routing_mode: &str,
    sla_max_latency_ms: Option<f64>,
    sla_max_jitter_ms: Option<f64>,
    sla_max_packet_loss_pct: Option<f64>,
) -> Result<(), String> {
    if members.is_empty() {
        return Err("A gateway group needs at least one member.".to_string());
    }
    if routing_mode != "static" && routing_mode != "quality" {
        return Err("routing_mode must be 'static' or 'quality'.".to_string());
    }
    let known_gateways: Vec<String> = list_gateways().iter().map(|g| g.name.clone()).collect();
    for m in &members {
        if !known_gateways.contains(&m.gateway_name) {
            return Err(format!("Gateway '{}' does not exist.", m.gateway_name));
        }
    }
    let mut data = load_groups_file();
    let Some(group) = data.groups.iter_mut().find(|g| g.name == name) else {
        return Err(format!("Group '{name}' not found."));
    };
    group.members = members;
    group.routing_mode = routing_mode.to_string();
    group.sla_max_latency_ms = sla_max_latency_ms;
    group.sla_max_jitter_ms = sla_max_jitter_ms;
    group.sla_max_packet_loss_pct = sla_max_packet_loss_pct;
    save_groups_file(&data)?;
    log_event(&format!("Gateway Group '{name}' updated (routing_mode={routing_mode})"));
    apply_system_default_gateway()?;
    check_and_log_system_default_ordering();
    Ok(())
}
pub fn delete_group(name: &str, rules_using_groups: &[(String, String)]) -> Result<(), String> {
    let in_use: Vec<String> = rules_using_groups
        .iter()
        .filter(|(_, g)| g == name)
        .map(|(desc, _)| desc.clone())
        .collect();
    if !in_use.is_empty() {
        return Err(format!(
            "Cannot delete group '{name}' - still used by Firewall rule(s): {}. Remove it from those rules first.",
            in_use.join(", ")
        ));
    }
    let mut data = load_groups_file();
    let target = data.groups.iter().find(|g| g.name == name).cloned();
    if let Some(t) = &target {
        if t.is_system_default {
            return Err(format!(
                "Cannot delete group '{name}' - it is currently set as the System Default Gateway. Assign a different group as system default first."
            ));
        }
    }
    let before = data.groups.len();
    data.groups.retain(|g| g.name != name);
    if data.groups.len() == before {
        return Err(format!("Group '{name}' not found."));
    }
    save_groups_file(&data)?;
    log_event(&format!("Gateway Group '{name}' deleted"));
    Ok(())
}
pub fn set_system_default_group(name: &str) -> Result<(), String> {
    let mut data = load_groups_file();
    if !name.is_empty() && !data.groups.iter().any(|g| g.name == name) {
        return Err(format!("Group '{name}' not found."));
    }
    for g in data.groups.iter_mut() {
        g.is_system_default = g.name == name;
    }
    save_groups_file(&data)?;
    apply_system_default_gateway()?;
    log_event(&format!(
        "System Default Gateway set to group '{}'",
        if name.is_empty() { "(none)" } else { name }
    ));
    check_and_log_system_default_ordering();
    Ok(())
}
/// BARU (Agustus 2026, fitur Site Mesh VPN WAN preference) - cek apakah
/// susunan tier grup System Default Gateway saat ini "masuk akal" dari
/// sisi link_type: SEMUA gateway "dedicated" yang enabled seharusnya
/// berada di tier LEBIH RENDAH ATAU SAMA (prioritas lebih tinggi atau
/// setara) dibanding SETIAP gateway "shared" yang enabled. Kalau ada
/// gateway "shared" di tier LEBIH RENDAH (prioritas lebih tinggi) dari
/// ada gateway "dedicated" - itu tanda kuat kesalahan konfigurasi:
/// traffic asal-router (termasuk Site Mesh VPN/NTP/DNS/update) akan
/// prefer WAN shared/NAT walau WAN dedicated masih hidup sehat.
///
/// SENGAJA hanya PERINGATAN (return Option<String>, dicatat ke log +
/// dibaca Web UI untuk banner), BUKAN blocking save - admin mungkin
/// punya alasan sengaja susun begitu (mis. testing, atau WAN dedicated
/// sedang bermasalah kualitas meski status Up), konsisten prinsip
/// project ini: validasi mengingatkan, tidak memaksa, kecuali ada
/// risiko teknis nyata yang tidak bisa dipulihkan (beda dari kasus itu).
pub fn validate_system_default_ordering() -> Option<String> {
    let groups = load_groups_file().groups;
    let default_group = groups.iter().find(|g| g.is_system_default)?;
    let gateways = list_gateways();
    let gw_by_name: HashMap<&str, &Gateway> = gateways.iter().map(|g| (g.name.as_str(), g)).collect();
    let dedicated_tiers: Vec<u8> = default_group
        .members
        .iter()
        .filter_map(|m| gw_by_name.get(m.gateway_name.as_str()).filter(|g| g.enabled && g.link_type == "dedicated").map(|_| m.tier))
        .collect();
    let shared_tiers: Vec<(u8, &str)> = default_group
        .members
        .iter()
        .filter_map(|m| gw_by_name.get(m.gateway_name.as_str()).filter(|g| g.enabled && g.link_type == "shared").map(|_| (m.tier, m.gateway_name.as_str())))
        .collect();
    if dedicated_tiers.is_empty() || shared_tiers.is_empty() {
        return None; // Tidak ada campuran dedicated+shared - tidak ada yang perlu diperingatkan.
    }
    let min_dedicated_tier = *dedicated_tiers.iter().min().unwrap();
    let offending: Vec<&str> = shared_tiers.iter().filter(|(t, _)| *t < min_dedicated_tier).map(|(_, name)| *name).collect();
    if offending.is_empty() {
        return None;
    }
    Some(format!(
        "System Default Gateway group '{}': shared/NAT gateway(s) {} are set to a HIGHER priority tier than a dedicated gateway. This means router-originated traffic (Site Mesh VPN, NTP sync, DNS, update checks) will prefer the shared/NAT link even while a dedicated link is healthy. Consider moving dedicated gateways to a lower tier number (higher priority) than shared/NAT ones.",
        default_group.name,
        offending.join(", ")
    ))
}
fn check_and_log_system_default_ordering() {
    if let Some(warning) = validate_system_default_ordering() {
        log_event(&format!("WARNING: {warning}"));
    }
}
struct QualityProbe {
    reachable: bool,
    avg_latency_ms: Option<f64>,
    jitter_ms: Option<f64>,
    packet_loss_pct: f64,
}
fn ping_gateway(gw: &Gateway) -> QualityProbe {
    let target = if gw.monitor_ip.is_empty() { &gw.gateway_ip } else { &gw.monitor_ip };
    let Some(src_ip) = super::get_interface_ip(&gw.interface) else {
        return QualityProbe { reachable: false, avg_latency_ms: None, jitter_ms: None, packet_loss_pct: 100.0 };
    };
    if !gw.monitor_ip.is_empty() {
        let _ = Command::new("route").args(["add", "-host", &gw.monitor_ip, &gw.gateway_ip]).stdout(route_log_stdio()).stderr(route_log_stdio()).status();
    }
    let output = Command::new("/sbin/ping")
        .args(["-S", &src_ip, "-c", &PING_BURST_COUNT.to_string(), "-t", &PING_TIMEOUT_SECS.to_string(), "-q", target])
        .output();
    let Ok(output) = output else {
        return QualityProbe { reachable: false, avg_latency_ms: None, jitter_ms: None, packet_loss_pct: 100.0 };
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut packet_loss_pct: f64 = 100.0;
    for line in text.lines() {
        if let Some(pct_str) = line.split('%').next() {
            if line.contains("packet loss") {
                if let Some(last_token) = pct_str.split_whitespace().last() {
                    if let Ok(pct) = last_token.parse::<f64>() {
                        packet_loss_pct = pct;
                    }
                }
            }
        }
    }
    let mut avg_latency_ms: Option<f64> = None;
    let mut jitter_ms: Option<f64> = None;
    for line in text.lines() {
        if line.contains("round-trip") || line.contains("min/avg/max") {
            if let Some(values_part) = line.split('=').nth(1) {
                let values: Vec<f64> = values_part
                    .split('/')
                    .filter_map(|v| v.trim().trim_end_matches("ms").trim().parse::<f64>().ok())
                    .collect();
                if values.len() >= 4 {
                    avg_latency_ms = Some(values[1]);
                    jitter_ms = Some(values[3]);
                }
            }
        }
    }
    QualityProbe {
        reachable: packet_loss_pct < 100.0,
        avg_latency_ms,
        jitter_ms,
        packet_loss_pct,
    }
}
pub fn run_monitor_cycle() -> bool {
    let gateways = list_gateways();
    if gateways.is_empty() {
        return false;
    }
    let settings = load_settings();
    let mut status = load_status_file();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut any_transition = false;
    for gw in &gateways {
        if !gw.enabled {
            continue;
        }
        let probe = ping_gateway(gw);
        let entry = status.gateways.entry(gw.name.clone()).or_default();
        let was_up = entry.up;
        if probe.reachable {
            entry.consecutive_success += 1;
            entry.consecutive_fail = 0;
            if !entry.up && entry.consecutive_success >= settings.recover_threshold {
                entry.up = true;
            }
        } else {
            entry.consecutive_fail += 1;
            entry.consecutive_success = 0;
            if entry.up && entry.consecutive_fail >= settings.fail_threshold {
                entry.up = false;
            }
        }
        entry.last_checked_ts = now;
        entry.avg_latency_ms = probe.avg_latency_ms;
        entry.jitter_ms = probe.jitter_ms;
        entry.packet_loss_pct = Some(probe.packet_loss_pct);
        if was_up != entry.up {
            any_transition = true;
            log_event(&format!(
                "Gateway '{}' ({}) transitioned {} -> {}",
                gw.name,
                gw.interface,
                if was_up { "UP" } else { "DOWN" },
                if entry.up { "UP" } else { "DOWN" }
            ));
            if was_up && !entry.up {
                let _ = Command::new("pfctl").args(["-i", &gw.interface, "-F", "state"]).status();
                log_event(&format!("Flushed pf states on {} to force affected flows onto the surviving gateway immediately", gw.interface));
            }
        }
    }
    let _ = save_status_file(&status);
    any_transition
}
pub fn quality_selection_changed() -> bool {
    let groups = list_groups();
    let quality_groups: Vec<&GatewayGroup> = groups.iter().filter(|g| g.routing_mode == "quality").collect();
    if quality_groups.is_empty() {
        return false;
    }
    static LAST_SELECTION_HASH: std::sync::OnceLock<std::sync::Mutex<u64>> = std::sync::OnceLock::new();
    let hash_cell = LAST_SELECTION_HASH.get_or_init(|| std::sync::Mutex::new(0));
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for g in &quality_groups {
        g.name.hash(&mut hasher);
        let mut names: Vec<String> = active_tier_members(g).iter().map(|m| m.name.clone()).collect();
        names.sort();
        names.hash(&mut hasher);
    }
    let new_hash = hasher.finish();
    let mut last = hash_cell.lock().unwrap();
    let changed = *last != new_hash;
    *last = new_hash;
    changed
}
fn is_gateway_up(name: &str, status: &StatusFile) -> bool {
    status.gateways.get(name).map(|s| s.up).unwrap_or(true)
}
fn active_tier_members(group: &GatewayGroup) -> Vec<Gateway> {
    let status = load_status_file();
    let gateways = list_gateways();
    let gw_by_name: HashMap<&str, &Gateway> = gateways.iter().map(|g| (g.name.as_str(), g)).collect();
    let mut tiers: Vec<u8> = group.members.iter().map(|m| m.tier).collect();
    tiers.sort_unstable();
    tiers.dedup();
    let is_quality_mode = group.routing_mode == "quality";
    for tier in tiers {
        let mut up_members: Vec<Gateway> = group
            .members
            .iter()
            .filter(|m| m.tier == tier)
            .filter_map(|m| gw_by_name.get(m.gateway_name.as_str()).copied())
            .filter(|g| g.enabled && is_gateway_up(&g.name, &status))
            .cloned()
            .collect();
        if up_members.is_empty() {
            continue;
        }
        if !is_quality_mode {
            return up_members;
        }
        if group.sla_max_latency_ms.is_some() || group.sla_max_jitter_ms.is_some() || group.sla_max_packet_loss_pct.is_some() {
            up_members.retain(|g| {
                let Some(qs) = status.gateways.get(&g.name) else { return true };
                if let (Some(max), Some(val)) = (group.sla_max_latency_ms, qs.avg_latency_ms) {
                    if val > max {
                        return false;
                    }
                }
                if let (Some(max), Some(val)) = (group.sla_max_jitter_ms, qs.jitter_ms) {
                    if val > max {
                        return false;
                    }
                }
                if let (Some(max), Some(val)) = (group.sla_max_packet_loss_pct, qs.packet_loss_pct) {
                    if val > max {
                        return false;
                    }
                }
                true
            });
            if up_members.is_empty() {
                continue;
            }
        }
        let score = |g: &Gateway| -> f64 {
            let Some(qs) = status.gateways.get(&g.name) else { return f64::MAX };
            let latency = qs.avg_latency_ms.unwrap_or(0.0);
            let jitter = qs.jitter_ms.unwrap_or(0.0);
            let loss = qs.packet_loss_pct.unwrap_or(0.0);
            latency + (jitter * 2.0) + (loss * 10.0)
        };
        up_members.sort_by(|a, b| score(a).partial_cmp(&score(b)).unwrap_or(std::cmp::Ordering::Equal));
        let best_score = score(&up_members[0]);
        let tolerance = best_score * 0.15;
        up_members.retain(|g| score(g) <= best_score + tolerance);
        return up_members;
    }
    Vec::new()
}
pub fn compute_route_to_clause(group_name: &str) -> Option<String> {
    let groups = load_groups_file().groups;
    let group = groups.iter().find(|g| g.name == group_name)?;
    let members = active_tier_members(group);
    if members.is_empty() {
        return None;
    }
    if members.len() == 1 {
        let m = &members[0];
        Some(format!(" route-to ({} {})", m.interface, m.gateway_ip))
    } else {
        let pool = members.iter().map(|m| format!("({} {})", m.interface, m.gateway_ip)).collect::<Vec<_>>().join(", ");
        Some(format!(" route-to {{ {pool} }} round-robin sticky-address"))
    }
}
/// System default gateway switching - mekanisme TERPISAH dari
/// route-to (lihat poin 1.b di komentar header modul). HANYA failover
/// (ambil member PERTAMA dari tier aktif, tidak round-robin) - pfSense
/// sendiri eksplisit mengonfirmasi ini "not compatible with load
/// balancing". Dipanggil setiap kali status gateway berubah DAN grup
/// yang berubah itu adalah system default saat ini.
///
/// PENTING (fitur Site Mesh VPN WAN preference, Agustus 2026): fungsi
/// INI JUGA yang menentukan WAN mana dipakai Site Mesh VPN/tailscaled -
/// TIDAK ADA jalur terpisah untuk itu, dan MEMANG TIDAK PERLU ada
/// (traffic tailscaled adalah traffic asal-router, persis NTP/DNS/
/// update - lihat komentar header modul poin 5). Prioritas dedicated
/// vs shared murni ditentukan oleh URUTAN TIER yang admin susun di
/// System Default Gateway Group - fungsi ini sendiri TIDAK peduli
/// link_type sama sekali (agnostik, sesuai desain lama), validasi
/// link_type ada TERPISAH di validate_system_default_ordering() supaya
/// admin diperingatkan kalau susun tier-nya terbalik.
pub fn apply_system_default_gateway() -> Result<(), String> {
    let groups = load_groups_file().groups;
    let Some(default_group) = groups.iter().find(|g| g.is_system_default) else {
        return Ok(());
    };
    let members = active_tier_members(default_group);
    let Some(primary) = members.first() else {
        log_event(&format!(
            "WARNING: System Default Gateway group '{}' has NO reachable member - system default route left unchanged (better a stale route than none at all).",
            default_group.name
        ));
        return Ok(());
    };
    let _ = Command::new("route").args(["delete", "default"]).stdout(route_log_stdio()).stderr(route_log_stdio()).status();
    let add_status = Command::new("route").args(["add", "default", &primary.gateway_ip]).stdout(route_log_stdio()).stderr(route_log_stdio()).status();
    if add_status.map(|s| !s.success()).unwrap_or(true) {
        return Err(format!("Failed to set system default route to {} via {}", primary.gateway_ip, primary.interface));
    }
    let _ = Command::new("sysrc").arg(format!("defaultrouter={}", primary.gateway_ip)).status();
    log_event(&format!(
        "System default route -> {} via {} (group '{}')",
        primary.gateway_ip, primary.interface, default_group.name
    ));
    Ok(())
}
pub fn regenerate_outbound_nat() -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    let start_marker = "# NTPSENSE_MULTIWAN_NAT_START";
    let end_marker = "# NTPSENSE_MULTIWAN_NAT_END";
    let wan_interfaces = eligible_wan_interfaces();
    let mut nat_lines = vec![start_marker.to_string()];
    for iface in &wan_interfaces {
        nat_lines.push(format!("nat on {iface} from ! ({iface}) to any -> ({iface})"));
    }
    nat_lines.push(end_marker.to_string());
    let nat_block = nat_lines.join("\n");
    let new_content = if content.contains(start_marker) {
        let start_idx = content.find(start_marker).unwrap();
        let end_idx = content.find(end_marker).map(|i| i + end_marker.len()).unwrap_or(content.len());
        format!("{}{}{}", &content[..start_idx], nat_block, &content[end_idx..])
    } else {
        if let Some(old_line_start) = content.find("nat on $wan1_if") {
            let line_end = content[old_line_start..].find('\n').map(|i| old_line_start + i).unwrap_or(content.len());
            format!("{}{}{}", &content[..old_line_start], nat_block, &content[line_end..])
        } else {
            let anchor = "\nblock log all\n";
            match content.find(anchor) {
                Some(idx) => {
                    let insert_at = idx + anchor.len();
                    format!("{}\n{nat_block}\n\n{}", &content[..insert_at], &content[insert_at..])
                }
                None => return Err("Could not find insertion point for NAT block in /etc/pf.conf".to_string()),
            }
        }
    };
    let tmp_path = "/tmp/pf.conf.multiwan-nat";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed for outbound NAT changes, NOT applied. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}
pub fn get_status_summary() -> serde_json::Value {
    let gateways = list_gateways();
    let status = load_status_file();
    let groups = load_groups_file().groups;
    let gateway_details: Vec<serde_json::Value> = gateways
        .iter()
        .map(|g| {
            let s = status.gateways.get(&g.name);
            serde_json::json!({
                "name": g.name,
                "interface": g.interface,
                "gateway_ip": g.gateway_ip,
                "monitor_ip": if g.monitor_ip.is_empty() { &g.gateway_ip } else { &g.monitor_ip },
                "enabled": g.enabled,
                "link_type": g.link_type,
                "up": s.map(|x| x.up).unwrap_or(true),
                "last_checked_ts": s.map(|x| x.last_checked_ts).unwrap_or(0),
                "avg_latency_ms": s.and_then(|x| x.avg_latency_ms),
                "jitter_ms": s.and_then(|x| x.jitter_ms),
                "packet_loss_pct": s.and_then(|x| x.packet_loss_pct),
            })
        })
        .collect();
    let group_details: Vec<serde_json::Value> = groups
        .iter()
        .map(|g| {
            let active = active_tier_members(g);
            serde_json::json!({
                "name": g.name,
                "is_system_default": g.is_system_default,
                "members": g.members.iter().map(|m| serde_json::json!({"gateway_name": m.gateway_name, "tier": m.tier})).collect::<Vec<_>>(),
                "mode": if active.len() > 1 { "load_balance" } else { "failover" },
                "active_gateways": active.iter().map(|g| g.name.clone()).collect::<Vec<_>>(),
                "routing_mode": g.routing_mode,
                "sla_max_latency_ms": g.sla_max_latency_ms,
                "sla_max_jitter_ms": g.sla_max_jitter_ms,
                "sla_max_packet_loss_pct": g.sla_max_packet_loss_pct,
            })
        })
        .collect();
    serde_json::json!({
        "gateways": gateway_details,
        "groups": group_details,
        "system_default_ordering_warning": validate_system_default_ordering(),
    })
}
pub fn get_event_log(limit: usize) -> Vec<String> {
    let content = fs::read_to_string(MULTIWAN_EVENT_LOG).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    if lines.len() > limit {
        lines = lines.split_off(lines.len() - limit);
    }
    lines
}
