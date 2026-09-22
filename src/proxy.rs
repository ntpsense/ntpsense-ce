// ============================================================
// Proxy (Squid) - diekstrak dari main.rs (roadmap - main.rs sempat
// tumbuh sampai 537KB+, satu-satunya fitur besar yang belum dipisah
// modul seperti app_control/security/multiwan/ha/openvpn/threat_intel).
// Struct/konstanta/fungsi di modul ini SEMUA persis sama logikanya
// dengan versi lama di main.rs - murni pemindahan lokasi kode, BUKAN
// perubahan perilaku. Helper jaringan/pf yang dipakai BERSAMA banyak
// fitur lain (parse_pf_conf_zones, get_interface_cidr,
// normalize_network_cidr, load_roles, load_custom_rules, dst) TETAP
// tinggal di main.rs, dipanggil dari sini lewat 'super::' - konsisten
// pola yang sudah dipakai app_control.rs/security.rs/multiwan.rs untuk
// hal yang sama.
// ============================================================

use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

pub const SQUID_CONF: &str = "/usr/local/etc/squid/squid.conf";
pub const PROXY_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/proxy-config.json";
pub const BLOCKLIST_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/proxy-blocklist-config.json";
pub const BLOCKLIST_DIR: &str = "/usr/local/etc/squid/blocklists";
pub const ACL_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/proxy-acl-config.json";
pub const AUTH_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/proxy-auth-config.json";
pub const SQUID_PASSWD_FILE: &str = "/usr/local/etc/squid/passwd";
pub const BASIC_NCSA_AUTH_HELPER: &str = "/usr/local/libexec/squid/basic_ncsa_auth";

pub const VALID_CATEGORIES: [&str; 8] = ["ads", "malware", "phishing", "gambling", "porn", "tracking", "social_media", "file_transfer"];

/// Config Squid Fase 1+2 (General + Local cache - ACLs/Authentication
/// disimpan di file/struct TERPISAH, lihat AclRule/AuthConfig di bawah -
/// Blocklist juga terpisah, lihat BlocklistConfig).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_squid_port")]
    pub port: u16,
    #[serde(default = "default_cache_size_mb")]
    pub cache_size_mb: u32,
    // --- Local cache (Fase 2) ---
    #[serde(default = "default_cache_mem_mb")]
    pub cache_mem_mb: u32,
    #[serde(default = "default_max_object_size_mb")]
    pub maximum_object_size_mb: u32,
}
fn default_squid_port() -> u16 {
    3128
}
fn default_cache_size_mb() -> u32 {
    1000
}
fn default_cache_mem_mb() -> u32 {
    // Default Squid resmi adalah 256 MB - dipilih sebagai default kita
    // juga (bukan angka sembarang), cukup untuk beban SMB/branch office
    // tanpa terlalu rakus RAM pada hardware mini-PC target produk ini.
    256
}
fn default_max_object_size_mb() -> u32 {
    4
}
impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: false,
            port: default_squid_port(),
            cache_size_mb: default_cache_size_mb(),
            cache_mem_mb: default_cache_mem_mb(),
            maximum_object_size_mb: default_max_object_size_mb(),
        }
    }
}
pub fn load_proxy_config() -> ProxyConfig {
    fs::read_to_string(PROXY_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
pub fn save_proxy_config(cfg: &ProxyConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(PROXY_CONFIG_FILE, json).map_err(|e| e.to_string())
}

/// Config Blocklist - meniru arsitektur Tier 1 (Doc 6 Bab 7.3-7.5,
/// sudah teruji produksi): blocklist KATEGORI (dari Block List Project,
/// sumber URL HARDCODED bukan parameter), WHITELIST (allow, menang di
/// atas SEMUA deny lain), BLACKLIST-MANUAL (deny, domain spesifik admin
/// yang tidak tercakup kategori otomatis manapun). Kategori "Fakenews"
/// SENGAJA tidak diimplementasikan (keputusan Tier 1: tidak ada sumber
/// blocklist netral untuk kategori ini, subjektif/berisiko bias).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist_manual: Vec<String>,
}
pub fn load_blocklist_config() -> BlocklistConfig {
    fs::read_to_string(BLOCKLIST_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
pub fn save_blocklist_config(cfg: &BlocklistConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(BLOCKLIST_CONFIG_FILE, json).map_err(|e| e.to_string())
}

/// 8 kategori Tier 1, dipetakan ke nama file ASLI di Block List Project
/// (dikonfirmasi via riset - beberapa kategori gabungan >1 file). CATATAN:
/// "twitter.txt" TIDAK dikonfirmasi ada lagi di versi project saat ini,
/// jadi "Social Media" cuma facebook.txt+tiktok.txt (bukan 3 file
/// seperti Tier 1 lama) - kalau nanti dikonfirmasi ada lagi, tinggal
/// tambah ke Vec di bawah.
pub fn category_source_files(category: &str) -> Vec<&'static str> {
    match category {
        "ads" => vec!["ads.txt"],
        "malware" => vec!["malware.txt"],
        "phishing" => vec!["phishing.txt"],
        "gambling" => vec!["gambling.txt"],
        "porn" => vec!["porn.txt"],
        "tracking" => vec!["tracking.txt"],
        "social_media" => vec!["facebook.txt", "tiktok.txt"],
        "file_transfer" => vec!["torrent.txt", "piracy.txt"],
        _ => vec![],
    }
}

/// Validasi format domain - Lapis 2 (defense in depth, TIDAK PERCAYA
/// validasi PHP begitu saja, pola Tier 1 Bab 7.5.2): label dipisah
/// titik, 1-63 karakter per label, alfanumerik+hubung, tidak diawali/
/// diakhiri hubung. Baris yang tidak lolos di SINI dibuang senyap
/// (bukan tempat melaporkan error - PHP sudah memberi kesempatan admin
/// memperbaiki SEBELUM mencapai daemon).
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Download/update file kategori dari Block List Project untuk SEMUA
/// kategori yang SEDANG AKTIF (state file, bukan parameter) - DIEKSTRAK
/// jadi fungsi standalone (bukan inline di action) supaya bisa dipanggil
/// dari DUA jalur: (1) action socket "proxy.blocklist_update" (dipicu
/// klik admin dari Web UI), (2) CLI flag --cron-blocklist-update
/// (dipicu cron harian, TANPA lewat socket sama sekali - cron jalan
/// sebagai root langsung, tidak perlu autentikasi peer credential).
/// Return (updated, failed) - daftar nama kategori.
pub fn run_blocklist_update() -> (Vec<String>, Vec<String>) {
    let blocklist_cfg = load_blocklist_config();
    if blocklist_cfg.categories.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let _ = fs::create_dir_all(BLOCKLIST_DIR);
    let mut updated = Vec::new();
    let mut failed = Vec::new();
    for category in &blocklist_cfg.categories {
        let source_files = category_source_files(category);
        if source_files.is_empty() {
            continue;
        }
        let mut domains: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut ok = true;
        for file in &source_files {
            let url = format!("https://blocklistproject.github.io/Lists/{file}");
            let output = Command::new("fetch").arg("-q").arg("-o").arg("-").arg(&url).output();
            match output {
                Ok(o) if o.status.success() => {
                    let text = String::from_utf8_lossy(&o.stdout);
                    let trimmed = text.trim_start();
                    if trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<html") || text.len() < 100 {
                        ok = false;
                        break;
                    }
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        if let Some(domain) = line.split_whitespace().last() {
                            if !domain.is_empty() && seen.insert(domain.to_string()) {
                                domains.push(domain.to_string());
                            }
                        }
                    }
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !domains.is_empty() {
            let merged = domains.join("\n") + "\n";
            let dest = format!("{BLOCKLIST_DIR}/{category}.txt");
            let tmp = format!("{dest}.new");
            if fs::write(&tmp, &merged).is_ok() && fs::rename(&tmp, &dest).is_ok() {
                updated.push(category.clone());
            } else {
                failed.push(category.clone());
            }
        } else {
            failed.push(category.clone());
        }
    }
    // RCA (Tier 1 RCA #6 pattern - blocklist TERLIHAT jalan tapi tidak
    // pernah benar2 blokir): generate_squid_conf() cuma tulis ACL
    // kategori KALAU file-nya sudah ada di disk - kalau admin Save DULU
    // (sebelum file ada) baru Update setelahnya, ACL tidak pernah
    // tertulis KECUALI Update ini juga regenerate+apply ulang squid.conf.
    if !updated.is_empty() && std::path::Path::new("/usr/local/sbin/squid").exists() {
        let proxy_cfg = load_proxy_config();
        if let Ok(conf_text) = generate_squid_conf(&proxy_cfg) {
            let tmp_path = "/tmp/squid.conf.new";
            if fs::write(tmp_path, &conf_text).is_ok() {
                let parse_ok = Command::new("/usr/local/sbin/squid")
                    .arg("-k")
                    .arg("parse")
                    .arg("-f")
                    .arg(tmp_path)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if parse_ok && fs::copy(tmp_path, SQUID_CONF).is_ok() && proxy_cfg.enabled {
                    let _ = Command::new("service").arg("squid").arg("restart").status();
                }
            }
        }
    }
    (updated, failed)
}

/// ACL custom Fase 2 Proxy - mirip pola CustomRule Firewall (source/
/// destination/action), TAPI untuk kontrol akses level PROXY (bukan
/// level paket seperti pf). Time-based restriction SENGAJA DITUNDA
/// (kompleksitas tersendiri, syntax 'acl time' Squid) - Fase 2 ini
/// cuma source+destination+action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    pub source: String,      // CIDR atau "any"
    pub destination: String, // domain atau "any"
    pub action: String,      // "allow" | "deny"
    #[serde(default)]
    pub description: String,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AclRulesFile {
    #[serde(default)]
    pub rules: Vec<AclRule>,
}
pub fn load_acl_rules() -> AclRulesFile {
    fs::read_to_string(ACL_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
pub fn save_acl_rules(data: &AclRulesFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(ACL_CONFIG_FILE, json).map_err(|e| e.to_string())
}

/// Basic Authentication Fase 2 - HANYA simpan USERNAME di config kita
/// sendiri (persyaratan minimal untuk list-users di Web UI), password
/// hash SUNGGUHAN hidup di SQUID_PASSWD_FILE (format NCSA/htpasswd
/// standar, dibaca langsung oleh basic_ncsa_auth) - BUKAN didobel-
/// simpan di dua tempat yang bisa tidak sinkron.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub usernames: Vec<String>,
}
pub fn load_auth_config() -> AuthConfig {
    fs::read_to_string(AUTH_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
pub fn save_auth_config(cfg: &AuthConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(AUTH_CONFIG_FILE, json).map_err(|e| e.to_string())
}

/// Validasi username - alfanumerik+underscore+hubung saja, TIDAK BOLEH
/// mengandung ':' (pemisah field format NCSA passwd, kalau username
/// bisa mengandung ':' bisa merusak struktur file passwd/menyuntik
/// baris palsu).
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Hash password pakai 'openssl passwd -apr1' - format APR1-MD5 yang
/// DIKONFIRMASI didukung basic_ncsa_auth (riset resmi: "MD5 - with
/// optional salt and magic strings"), BUKAN format DES (default
/// historis htpasswd - PUNYA BATASAN keras 8 karakter password,
/// silent truncate tanpa peringatan). openssl adalah tool SISTEM DASAR
/// FreeBSD (bukan paket pkg terpisah) - PATH-nya reliable, tidak kena
/// gotcha rc.d PATH yang sudah kita alami dengan squid/kea-dhcp4.
pub fn hash_password_apr1(password: &str) -> Result<String, String> {
    let output = Command::new("openssl")
        .arg("passwd")
        .arg("-apr1")
        .arg(password)
        .output()
        .map_err(|e| format!("Failed to run 'openssl passwd': {e}"))?;
    if !output.status.success() {
        return Err("openssl passwd command failed".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Generate squid.conf - STRUKTUR MENIRU Tier 1 (Doc 6 Bab 7, sudah
/// teruji produksi): Safe_ports SENGAJA cuma 80+443 (TIDAK PERNAH
/// menambahkan port 21/FTP - itu satu-satunya jalan CVE Squidbleed
/// relevan, lihat catatan Tier 1), http_access urut deny-dulu-baru-
/// allow (first-match-wins, PENTING posisinya jangan sampai tertukar).
/// PENYESUAIAN Tier 2 (multi-zone, beda dari Tier 1 single-zone):
/// 'acl localnet' dibangun dari SEMUA subnet zona ber-role LAN/DMZ
/// yang terdeteksi LIVE sekarang (LAN1 selalu ikut, OPT ikut HANYA
/// kalau role-nya LAN atau DMZ) - bukan satu LAN_NET tetap.
pub fn generate_squid_conf(cfg: &ProxyConfig) -> Result<String, String> {
    let (lan1_if, _wan1_if, opt_ifaces) = super::parse_pf_conf_zones();
    let roles = super::load_roles();
    let mut localnets: Vec<String> = Vec::new();
    if let Some(l) = &lan1_if {
        if let Some(cidr) = super::get_interface_cidr(l).and_then(|c| super::normalize_network_cidr(&c)) {
            localnets.push(cidr);
        }
    }
    for opt in &opt_ifaces {
        let role = roles.get(opt).cloned().unwrap_or_else(|| "Undefined".to_string());
        if role == "LAN" || role == "DMZ" {
            if let Some(cidr) = super::get_interface_cidr(opt).and_then(|c| super::normalize_network_cidr(&c)) {
                localnets.push(cidr);
            }
        }
    }
    if localnets.is_empty() {
        return Err("No LAN/DMZ-role interface with a live IP was found to build the proxy's allowed network list".to_string());
    }
    let mut conf = String::new();
    conf.push_str("# NTPSense InetGateway Tier 2 - squid.conf\n");
    conf.push_str("# AUTO-GENERATED by ntpsense-configd - do not edit manually.\n\n");
    // Set eksplisit supaya Squid TIDAK mencoba rDNS lookup nama host
    // (yang pasti gagal untuk hostname gateway lokal tanpa DNS publik) -
    // ditemukan dari warning nyata: "rDNS test failed... Could not
    // determine this machines public hostname."
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "gateway.local".to_string());
    conf.push_str(&format!("visible_hostname {hostname}\n\n"));
    for net in &localnets {
        conf.push_str(&format!("acl localnet src {net}\n"));
    }
    conf.push('\n');
    // Safe_ports SENGAJA HANYA 80+443 - JANGAN tambahkan port 21 (FTP)
    // di sini, itu satu-satunya jalan CVE Squidbleed (Tier 1 Bab 7.2)
    // jadi relevan terhadap gateway ini.
    conf.push_str("acl SSL_ports port 443\n");
    conf.push_str("acl Safe_ports port 80\n");
    conf.push_str("acl Safe_ports port 443\n");
    conf.push_str("acl CONNECT method CONNECT\n\n");
    conf.push_str("http_access deny !Safe_ports\n");
    conf.push_str("http_access deny CONNECT !SSL_ports\n");
    // ------------------------------------------------------------
    // BASIC AUTH (Fase 2) - SENGAJA diposisikan PALING AWAL dari semua
    // blok kontrol akses lain (sebelum ACL custom, sebelum whitelist/
    // blacklist/blocklist) - auth adalah GERBANG yang harus dilewati
    // SEBELUM aturan lain apa pun dievaluasi, bukan salah satu dari
    // banyak kondisi setara. Kalau auth_config.enabled=false, blok ini
    // TIDAK ditulis sama sekali (tidak ada perubahan perilaku).
    // ------------------------------------------------------------
    let auth_cfg = load_auth_config();
    if auth_cfg.enabled && !auth_cfg.usernames.is_empty() {
        conf.push_str(&format!("auth_param basic program {BASIC_NCSA_AUTH_HELPER} {SQUID_PASSWD_FILE}\n"));
        conf.push_str("auth_param basic children 5\n");
        conf.push_str("auth_param basic realm NTPSense Proxy\n");
        conf.push_str("auth_param basic credentialsttl 2 hours\n");
        conf.push_str("acl ntpsense_auth proxy_auth REQUIRED\n");
        conf.push_str("http_access deny !ntpsense_auth\n");
    }
    // ------------------------------------------------------------
    // ACL CUSTOM (Fase 2) - kontrol akses eksplisit admin, diposisikan
    // SEBELUM whitelist/blacklist/blocklist supaya admin punya kendali
    // paling spesifik/eksplisit (dievaluasi dalam URUTAN yang admin
    // atur di Web UI - first-match-wins Squid, sama seperti bagian
    // whitelist/blacklist di bawah).
    // ------------------------------------------------------------
    let acl_rules = load_acl_rules();
    for rule in &acl_rules.rules {
        let acl_name = format!("ntpsense_acl_{}", rule.id);
        let action = if rule.action == "allow" { "allow" } else { "deny" };
        // RCA (ditemukan bro langsung, dua putaran):
        // (1) Squid 'src' ACL TIDAK PERNAH mengenal kata "any" sebagai
        // nilai (beda dari pf) - percobaan pertama pakai CIDR eksplisit
        // 0.0.0.0/0 SEMPAT lolos parse, TAPI Squid 7.4 di gateway ini
        // sudah men-deprecate bentuk itu juga ("needs to be replaced by
        // the term 'all'", auto-override dengan warning tiap reload).
        // (2) 'acl NAME src X dst Y' (dua tipe berbeda dalam SATU baris
        // acl) TIDAK PERNAH terkonfirmasi sebagai syntax resmi Squid di
        // riset manapun - pola yang benar-benar didokumentasikan adalah
        // ACL TERPISAH per tipe, digabung lewat 'http_access allow
        // ACL_A ACL_B' (AND semantics - request harus cocok KEDUANYA).
        // Fix menyeluruh: bangun daftar NAMA ACL yang perlu di-AND-kan
        // di http_access, deklarasikan tiap dimensi (src/dst) sebagai
        // ACL TERPISAH HANYA kalau bukan "any" - kalau memang "any",
        // dimensi itu tidak usah dideklarasikan/direferensikan sama
        // sekali (paling bersih: "match apa pun" = tidak ada filter
        // untuk dimensi itu, bukan filter eksplisit "cocok segalanya").
        let mut acl_names: Vec<String> = Vec::new();
        if rule.source != "any" {
            let src_name = format!("{acl_name}_src");
            conf.push_str(&format!("acl {src_name} src {}\n", rule.source));
            acl_names.push(src_name);
        }
        if rule.destination != "any" {
            // RCA (ditemukan proaktif saat memperbaiki bug 'src any' di
            // atas, sebelum sempat jadi laporan error terpisah): field
            // 'destination' didokumentasikan menerima DOMAIN ("google.com"
            // dst, komentar struct AclRule di atas), tapi kode SEBELUMNYA
            // pakai tipe ACL 'dst' - itu IP-based (persis seperti 'src'),
            // BUKAN domain-based, akan gagal parse persis sama dengan bug
            // "any" kalau admin isi domain di situ. 'dstdomain' (tipe yang
            // SAMA sudah dipakai project ini untuk whitelist/blacklist di
            // bawah) yang benar untuk domain.
            let dst_name = format!("{acl_name}_dst");
            conf.push_str(&format!("acl {dst_name} dstdomain {}\n", rule.destination));
            acl_names.push(dst_name);
        }
        if acl_names.is_empty() {
            // Source DAN destination sama-sama "any" - tidak ada
            // dimensi yang perlu difilter sama sekali, pakai ACL
            // bawaan Squid 'all' langsung (tidak perlu deklarasi acl
            // apa pun, dan tidak kena masalah deprecation apa pun
            // karena ini genuinely nama ACL built-in, bukan nilai CIDR
            // yang kita tulis sendiri).
            conf.push_str(&format!("http_access {action} all\n"));
        } else {
            conf.push_str(&format!("http_access {action} {}\n", acl_names.join(" ")));
        }
    }
    // ------------------------------------------------------------
    // CATATAN KRITIS SOAL POSISI DI BAWAH - JANGAN PINDAHKAN (Tier 1
    // RCA #6, bug PALING SIGNIFIKAN di seluruh riwayat fitur Proxy):
    // Squid evaluasi 'http_access' dari ATAS ke BAWAH dan BERHENTI di
    // match PERTAMA (first-match-wins), BUKAN evaluasi semua baris lalu
    // ambil keputusan akhir. SEMUA blok whitelist/blacklist-manual/
    // blocklist-kategori di bawah ini HARUS berada SEBELUM 'http_access
    // allow localnet' - kalau dipindah ke SETELAHNYA, 'allow localnet'
    // akan SELALU match duluan untuk semua request dari LAN, dan blok
    // deny/allow manapun di bawah TIDAK PERNAH dievaluasi sama sekali -
    // blocklist/whitelist akan TERLIHAT aktif (ACL ada di file) tapi
    // TIDAK PERNAH benar-benar berefek. Ini bug NYATA yang pernah
    // terjadi di produksi, bukan kekhawatiran teoretis.
    //
    // Urutan ANTAR blok di bawah ini JUGA penting:
    //   1. WHITELIST (allow)       - menang di atas SEMUA deny lain
    //   2. BLACKLIST-MANUAL (deny) - domain spesifik admin
    //   3. BLOCKLIST kategori (deny) - dari Block List Project
    // ------------------------------------------------------------
    let blocklist_cfg = load_blocklist_config();
    if !blocklist_cfg.whitelist.is_empty() {
        let domains: Vec<String> = blocklist_cfg.whitelist.iter().map(|d| format!(".{d}")).collect();
        conf.push_str(&format!("acl ntpsense_whitelist dstdomain {}\n", domains.join(" ")));
        conf.push_str("http_access allow ntpsense_whitelist\n");
    }
    if !blocklist_cfg.blacklist_manual.is_empty() {
        let domains: Vec<String> = blocklist_cfg.blacklist_manual.iter().map(|d| format!(".{d}")).collect();
        conf.push_str(&format!("acl ntpsense_blacklist_manual dstdomain {}\n", domains.join(" ")));
        conf.push_str("http_access deny ntpsense_blacklist_manual\n");
    }
    for category in &blocklist_cfg.categories {
        if !VALID_CATEGORIES.contains(&category.as_str()) {
            continue;
        }
        let file_path = format!("{BLOCKLIST_DIR}/{category}.txt");
        if std::path::Path::new(&file_path).is_file() {
            conf.push_str(&format!("acl ntpsense_blocklist_{category} dstdomain \"{file_path}\"\n"));
            conf.push_str(&format!("http_access deny ntpsense_blocklist_{category}\n"));
        }
    }
    conf.push_str("http_access allow localnet\n");
    conf.push_str("http_access allow localhost\n");
    conf.push_str("http_access deny all\n\n");
    conf.push_str(&format!("http_port 0.0.0.0:{}\n\n", cfg.port));
    conf.push_str(&format!("cache_dir ufs /var/squid/cache {} 16 256\n", cfg.cache_size_mb));
    conf.push_str(&format!("cache_mem {} MB\n", cfg.cache_mem_mb));
    conf.push_str(&format!("maximum_object_size {} MB\n", cfg.maximum_object_size_mb));
    conf.push_str("coredump_dir /var/squid/cache\n\n");
    conf.push_str("logfile_rotate 30\n\n");
    conf.push_str("refresh_pattern ^ftp: 1440 20% 10080\n");
    conf.push_str("refresh_pattern ^gopher: 1440 0% 1440\n");
    conf.push_str("refresh_pattern -i (/cgi-bin/|\\?) 0 0% 0\n");
    conf.push_str("refresh_pattern . 0 20% 4320\n");
    Ok(conf)
}

/// Helper BERSAMA - generate squid.conf dari ProxyConfig SAAT INI,
/// validasi syntax ('squid -k parse'), apply ke lokasi final, restart
/// kalau proxy sedang enabled, verifikasi status SUNGGUHAN setelah
/// restart (pola sama seperti proxy.set_config/proxy.set_blocklist_config
/// sebelumnya) - DIEKSTRAK jadi satu fungsi supaya action baru (Local
/// cache/ACL/Auth) tidak menduplikasi logic validasi+apply yang sama
/// persis berkali-kali, dan supaya perilakunya SELALU konsisten.
pub fn apply_squid_conf() -> Result<(), String> {
    let cfg = load_proxy_config();
    let conf_text = generate_squid_conf(&cfg)?;
    let tmp_path = "/tmp/squid.conf.new";
    fs::write(tmp_path, &conf_text).map_err(|e| format!("Failed to write draft: {e}"))?;
    let parse_output = Command::new("/usr/local/sbin/squid").arg("-k").arg("parse").arg("-f").arg(tmp_path).output();
    match &parse_output {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let err_text = String::from_utf8_lossy(&o.stderr);
            return Err(format!("squid.conf failed syntax validation ('squid -k parse'): {err_text}"));
        }
        Err(e) => return Err(format!("Failed to run 'squid -k parse': {e}")),
    }
    fs::copy(tmp_path, SQUID_CONF).map_err(|e| format!("Failed to copy to {SQUID_CONF}: {e}"))?;
    if cfg.enabled {
        let restart_status = Command::new("service").arg("squid").arg("restart").status();
        if !matches!(restart_status, Ok(s) if s.success()) {
            let _ = Command::new("service").arg("squid").arg("start").status();
        }
        let status_check = Command::new("service").arg("squid").arg("status").status();
        if !matches!(status_check, Ok(s) if s.success()) {
            return Err("Squid failed to start after applying the new configuration - check /var/log/squid/cache.log".to_string());
        }
    }
    Ok(())
}

// ------------------------------------------------------------
// Squid access.log (format 'common' default Squid, spasi-separated,
// TIDAK dikutip/di-escape - lihat dokumentasi resmi Squid) - dipecah
// jadi kolom SUNGGUHAN (client IP, method, URL, status, size),
// bukan cuma timestamp+pesan generik, karena field-field ini jauh
// lebih berharga dipisah untuk admin daripada dibiarkan jadi satu
// baris teks panjang.
// ------------------------------------------------------------
#[derive(Debug, Serialize)]
pub struct SquidLogEntry {
    pub timestamp: String,
    pub client_ip: String,
    pub status: String,
    pub method: String,
    pub url: String,
    pub size: String,
}
pub fn parse_squid_access_line(line: &str) -> Option<SquidLogEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Format: <epoch.ms> <elapsed> <client_ip> <action>/<status> <size> <method> <url> <ident> <hier>/<from> <content_type>
    if parts.len() < 7 {
        return None;
    }
    let epoch: f64 = parts[0].parse().ok()?;
    let timestamp = super::format_unix_timestamp(epoch as i64);
    let client_ip = parts[2].to_string();
    let status = parts[3].split('/').nth(1).unwrap_or(parts[3]).to_string();
    let size = parts[4].to_string();
    let method = parts[5].to_string();
    let url = parts[6].to_string();
    Some(SquidLogEntry { timestamp, client_ip, status, method, url, size })
}

// ============================================================
// Historical Archive (Log Viewer + Bandwidth Usage) - permintaan bro
// langsung: admin bisa pilih retensi (max 6 bulan/180 hari), tombol
// Export CSV + date-range picker ("Make Report from ... to ...") di
// KEDUA tab. Arsitektur: cron harian (mendekati tengah malam) kelompokkan
// access.log SAAT INI per tanggal kalender (dari field epoch tiap
// baris - bukan asumsi "baris masuk hari ini" yang bisa salah kalau
// cron sempat telat/terlewat), simpan DUA bentuk:
//   1. Raw log ter-gzip per hari (Log Viewer historis - admin genuinely
//      butuh baris mentah untuk audit, bukan cuma ringkasan)
//   2. Agregat JSON per hari (Bandwidth Usage historis - JAUH lebih
//      murah dibaca ulang untuk rentang panjang daripada decompress+
//      parse ulang gzip mentah tiap kali admin buka satu rentang tanggal)
// Hari INI TIDAK PERNAH diarsipkan (masih berjalan, belum "selesai") -
// data hari ini untuk range yang mencakup hari ini dihitung LIVE dari
// access.log saat ini, digabung dengan arsip hari-hari sebelumnya.
// ============================================================
pub const ARCHIVE_SETTINGS_FILE: &str = "/usr/local/etc/ntpsense/proxy-archive-settings.json";
pub const LOG_ARCHIVE_DIR: &str = "/usr/local/etc/ntpsense/proxy-archive/log";
pub const BANDWIDTH_ARCHIVE_DIR: &str = "/usr/local/etc/ntpsense/proxy-archive/bandwidth";
const DEFAULT_RETENTION_DAYS: u32 = 30;
const MAX_RETENTION_DAYS: u32 = 180; // 6 bulan - batas keras diminta bro

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveSettings {
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}
fn default_retention_days() -> u32 {
    DEFAULT_RETENTION_DAYS
}
impl Default for ArchiveSettings {
    fn default() -> Self {
        ArchiveSettings { retention_days: DEFAULT_RETENTION_DAYS }
    }
}
pub fn load_archive_settings() -> ArchiveSettings {
    fs::read_to_string(ARCHIVE_SETTINGS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
pub fn save_archive_settings(retention_days: u32) -> Result<ArchiveSettings, String> {
    // Dibatasi keras 1-180 hari di SINI (bukan cuma validasi UI) -
    // konsisten prinsip project ini: batas yang genuinely penting
    // (di sini: cegah disk penuh dari retensi tidak terbatas) tidak
    // pernah cuma dipercayakan ke validasi PHP.
    let clamped = retention_days.clamp(1, MAX_RETENTION_DAYS);
    let cfg = ArchiveSettings { retention_days: clamped };
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    fs::write(ARCHIVE_SETTINGS_FILE, json).map_err(|e| e.to_string())?;
    Ok(cfg)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Format epoch (detik) jadi "YYYY-MM-DD" - reuse binari 'date' base
/// FreeBSD (pola sama seperti format_unix_timestamp() di main.rs, tidak
/// perlu crate chrono cuma untuk konversi ini).
fn date_string_from_epoch(epoch_secs: i64) -> String {
    Command::new("date")
        .args(["-r", &epoch_secs.to_string(), "+%Y-%m-%d"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Validasi format "YYYY-MM-DD" - dasar (bukan validasi tanggal
/// kalender penuh, mis. "2026-02-30" lolos di sini) tapi CUKUP untuk
/// mencegah path traversal/karakter aneh menembus ke nama file arsip
/// yang dibangun dari input ini (defense in depth, sama filosofi
/// is_valid_domain()/is_valid_username() di modul ini).
pub fn is_valid_date_string(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let bytes = s.as_bytes();
    let digit_positions = [0, 1, 2, 3, 5, 6, 8, 9];
    let sep_positions: [(usize, u8); 2] = [(4, b'-'), (7, b'-')];
    digit_positions.iter().all(|&p| bytes.get(p).map(u8::is_ascii_digit).unwrap_or(false))
        && sep_positions.iter().all(|&(p, c)| bytes.get(p) == Some(&c))
}

/// Hitung agregat zona/client/domain dari KUMPULAN baris access.log -
/// SATU sumber kebenaran dipakai bersama oleh (1) live view
/// (proxy.get_bandwidth_usage, seluruh isi file saat ini) dan (2) arsip
/// harian (run_daily_archive(), satu hari kalender saja) - supaya
/// keduanya SELALU pakai logic identik, tidak ada dua implementasi
/// yang bisa diam-diam berbeda hasil.
pub fn compute_bandwidth_aggregate(lines: &[&str]) -> serde_json::Value {
    let mut client_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut domain_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut domain_hits: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let client_ip = fields[2];
        let Ok(bytes) = fields[4].parse::<u64>() else {
            continue;
        };
        *client_bytes.entry(client_ip.to_string()).or_insert(0) += bytes;
        if let Some(domain) = extract_domain_from_squid_url(fields[6]) {
            *domain_bytes.entry(domain.clone()).or_insert(0) += bytes;
            *domain_hits.entry(domain).or_insert(0) += 1;
        }
    }

    let (lan1_if, _wan1_if, opt_ifaces) = super::parse_pf_conf_zones();
    let mut zone_subnets: Vec<(String, String)> = Vec::new();
    if let Some(l) = &lan1_if {
        if let Some(cidr) = super::get_interface_cidr(l).and_then(|c| super::normalize_network_cidr(&c)) {
            zone_subnets.push(("LAN1".to_string(), cidr));
        }
    }
    for (i, opt) in opt_ifaces.iter().enumerate() {
        if let Some(cidr) = super::get_interface_cidr(opt).and_then(|c| super::normalize_network_cidr(&c)) {
            zone_subnets.push((format!("OPT{}", i + 1), cidr));
        }
    }

    let mut zone_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (ip, bytes) in &client_bytes {
        for (label, cidr) in &zone_subnets {
            if super::cidr_overlaps(&format!("{ip}/32"), cidr) {
                *zone_bytes.entry(label.clone()).or_insert(0) += bytes;
                break;
            }
        }
    }

    serde_json::json!({
        "zones": zone_bytes.into_iter().map(|(l, b)| serde_json::json!({ "label": l, "bytes": b })).collect::<Vec<_>>(),
        "clients": client_bytes.into_iter().map(|(ip, b)| serde_json::json!({ "ip": ip, "bytes": b })).collect::<Vec<_>>(),
        "domains": domain_bytes.into_iter().map(|(d, b)| {
            let hits = domain_hits.get(&d).copied().unwrap_or(0);
            serde_json::json!({ "domain": d, "bytes": b, "hits": hits })
        }).collect::<Vec<_>>(),
    })
}

/// Urut+potong hasil agregat SETELAH digabung (baik live single-day
/// maupun gabungan multi-hari dari arsip) - dipisah dari
/// compute_bandwidth_aggregate() supaya penggabungan lintas-hari bisa
/// terjadi DULU (byte per client/domain/zona yang SAMA di hari
/// berbeda perlu dijumlahkan, bukan masing-masing di-top-N duluan lalu
/// digabung - itu akan salah kalau satu domain konsisten sedang-sedang
/// saja tiap hari tapi totalnya besar).
pub fn finalize_bandwidth_result(zone_bytes: std::collections::HashMap<String, u64>, client_bytes: std::collections::HashMap<String, u64>, domain_bytes: std::collections::HashMap<String, u64>, domain_hits: std::collections::HashMap<String, u64>) -> serde_json::Value {
    let mut zone_list: Vec<(String, u64)> = zone_bytes.into_iter().collect();
    zone_list.sort_by(|a, b| b.1.cmp(&a.1));

    let mut client_list: Vec<(String, u64)> = client_bytes.into_iter().collect();
    client_list.sort_by(|a, b| b.1.cmp(&a.1));
    client_list.truncate(10);

    let mut domain_list: Vec<(String, u64, u64)> = domain_bytes
        .into_iter()
        .map(|(d, b)| {
            let h = domain_hits.get(&d).copied().unwrap_or(0);
            (d, b, h)
        })
        .collect();
    domain_list.sort_by(|a, b| b.1.cmp(&a.1));
    domain_list.truncate(20);

    serde_json::json!({
        "zones": zone_list.iter().map(|(l, b)| serde_json::json!({ "label": l, "bytes": b })).collect::<Vec<_>>(),
        "clients": client_list.iter().map(|(ip, b)| serde_json::json!({ "ip": ip, "bytes": b })).collect::<Vec<_>>(),
        "domains": domain_list.iter().map(|(d, b, h)| serde_json::json!({ "domain": d, "bytes": b, "hits": h })).collect::<Vec<_>>(),
    })
}

/// Daftar tanggal (YYYY-MM-DD) inklusif dari from..=to - dihitung
/// mundur dari 'to' via pengurangan detik (86400/hari), BUKAN loop
/// naik dari 'from' (leap second/DST tidak relevan untuk perbandingan
/// string tanggal kalender biasa, tapi loop mundur dari epoch 'to'
/// yang sudah pasti valid lebih robust terhadap kemungkinan input
/// 'from' yang jauh di luar rentang data yang ada).
fn dates_in_range(from: &str, to: &str) -> Vec<String> {
    let mut result = Vec::new();
    if from > to {
        return result;
    }
    // Konversi 'to' ke epoch via 'date -j' (parse tanggal, FreeBSD date
    // mendukung ini) - mundur hari demi hari sampai < from atau batas
    // wajar (400 hari, jauh di atas MAX_RETENTION_DAYS) untuk mencegah
    // loop nyaris tak terbatas kalau input tanggal jauh di masa depan.
    let to_epoch = Command::new("date")
        .args(["-j", "-f", "%Y-%m-%d", to, "+%s"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<i64>().ok());
    let Some(mut cursor_epoch) = to_epoch else { return result };
    for _ in 0..400 {
        let day = date_string_from_epoch(cursor_epoch);
        if day.as_str() < from {
            break;
        }
        result.push(day);
        cursor_epoch -= 86400;
    }
    result.reverse();
    result
}

/// Gabungan agregat bandwidth untuk rentang tanggal - arsip harian
/// untuk hari-hari yang SUDAH lewat, live access.log (difilter ke
/// baris hari ini saja) kalau rentang mencakup hari ini.
pub fn get_bandwidth_range(from: &str, to: &str) -> serde_json::Value {
    if !is_valid_date_string(from) || !is_valid_date_string(to) {
        return serde_json::json!({ "zones": [], "clients": [], "domains": [], "error": "Invalid date format" });
    }
    let today = date_string_from_epoch(now_secs());
    let mut zone_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut client_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut domain_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut domain_hits: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    let merge_in = |v: &serde_json::Value, zb: &mut std::collections::HashMap<String, u64>, cb: &mut std::collections::HashMap<String, u64>, db: &mut std::collections::HashMap<String, u64>, dh: &mut std::collections::HashMap<String, u64>| {
        for z in v["zones"].as_array().cloned().unwrap_or_default() {
            if let (Some(label), Some(bytes)) = (z["label"].as_str(), z["bytes"].as_u64()) {
                *zb.entry(label.to_string()).or_insert(0) += bytes;
            }
        }
        for c in v["clients"].as_array().cloned().unwrap_or_default() {
            if let (Some(ip), Some(bytes)) = (c["ip"].as_str(), c["bytes"].as_u64()) {
                *cb.entry(ip.to_string()).or_insert(0) += bytes;
            }
        }
        for d in v["domains"].as_array().cloned().unwrap_or_default() {
            if let (Some(domain), Some(bytes)) = (d["domain"].as_str(), d["bytes"].as_u64()) {
                *db.entry(domain.to_string()).or_insert(0) += bytes;
                *dh.entry(domain.to_string()).or_insert(0) += d["hits"].as_u64().unwrap_or(0);
            }
        }
    };

    for day in dates_in_range(from, to) {
        if day == today {
            // Hari ini - hitung LIVE, filter ke baris yang tanggalnya
            // genuinely hari ini (access.log berisi SEMUA hari yang
            // belum di-rotate Squid, bukan cuma hari ini).
            if let Ok(content) = fs::read_to_string("/var/log/squid/access.log") {
                let today_lines: Vec<&str> = content
                    .lines()
                    .filter(|l| {
                        l.split_whitespace()
                            .next()
                            .and_then(|e| e.parse::<f64>().ok())
                            .map(|e| date_string_from_epoch(e as i64) == today)
                            .unwrap_or(false)
                    })
                    .collect();
                let agg = compute_bandwidth_aggregate(&today_lines);
                merge_in(&agg, &mut zone_bytes, &mut client_bytes, &mut domain_bytes, &mut domain_hits);
            }
            continue;
        }
        let archive_path = format!("{BANDWIDTH_ARCHIVE_DIR}/{day}.json");
        if let Ok(text) = fs::read_to_string(&archive_path) {
            if let Ok(agg) = serde_json::from_str::<serde_json::Value>(&text) {
                merge_in(&agg, &mut zone_bytes, &mut client_bytes, &mut domain_bytes, &mut domain_hits);
            }
        }
    }

    finalize_bandwidth_result(zone_bytes, client_bytes, domain_bytes, domain_hits)
}

/// Baris log mentah untuk rentang tanggal - arsip .log.gz (decompress
/// via 'gzip -dc', base FreeBSD, tidak perlu crate compression
/// tambahan) untuk hari lewat, live access.log difilter ke hari ini
/// untuk hari ini. Dibatasi 'limit' baris TOTAL (bukan per-hari) -
/// mengambil baris PALING BARU dalam rentang (potong dari akhir),
/// konsisten pola "tail" yang sudah dipakai live Log Viewer.
pub fn get_log_range(from: &str, to: &str, limit: usize) -> (Vec<String>, bool) {
    if !is_valid_date_string(from) || !is_valid_date_string(to) {
        return (Vec::new(), false);
    }
    let today = date_string_from_epoch(now_secs());
    let mut all_lines: Vec<String> = Vec::new();
    for day in dates_in_range(from, to) {
        if day == today {
            if let Ok(content) = fs::read_to_string("/var/log/squid/access.log") {
                for line in content.lines() {
                    let is_today = line
                        .split_whitespace()
                        .next()
                        .and_then(|e| e.parse::<f64>().ok())
                        .map(|e| date_string_from_epoch(e as i64) == today)
                        .unwrap_or(false);
                    if is_today {
                        all_lines.push(line.to_string());
                    }
                }
            }
            continue;
        }
        let archive_path = format!("{LOG_ARCHIVE_DIR}/{day}.log.gz");
        if !std::path::Path::new(&archive_path).is_file() {
            continue;
        }
        if let Ok(output) = Command::new("gzip").arg("-dc").arg(&archive_path).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                all_lines.extend(text.lines().map(|s| s.to_string()));
            }
        }
    }
    let truncated = all_lines.len() > limit;
    let start = all_lines.len().saturating_sub(limit);
    (all_lines.split_off(start), truncated)
}

/// Cron harian - kelompokkan access.log SAAT INI per tanggal kalender,
/// arsipkan hari-hari yang SUDAH SELESAI (bukan hari ini) yang BELUM
/// pernah punya arsip (idempotent - aman dipanggil berkali-kali per
/// hari kalau cron sempat jalan lebih dari sekali), lalu prune arsip
/// lebih tua dari retention_days.
pub fn run_daily_archive() -> String {
    let log_path = "/var/log/squid/access.log";
    let Ok(content) = fs::read_to_string(log_path) else {
        return "No access.log found - nothing to archive".to_string();
    };
    let today = date_string_from_epoch(now_secs());

    let mut by_day: std::collections::HashMap<String, Vec<&str>> = std::collections::HashMap::new();
    for line in content.lines() {
        let Some(epoch_str) = line.split_whitespace().next() else { continue };
        let Ok(epoch_f) = epoch_str.parse::<f64>() else { continue };
        let day = date_string_from_epoch(epoch_f as i64);
        if day.is_empty() {
            continue;
        }
        by_day.entry(day).or_default().push(line);
    }

    let _ = fs::create_dir_all(LOG_ARCHIVE_DIR);
    let _ = fs::create_dir_all(BANDWIDTH_ARCHIVE_DIR);

    let mut archived_days: Vec<String> = Vec::new();
    for (day, lines) in &by_day {
        if day == &today {
            continue;
        }
        let log_archive_path = format!("{LOG_ARCHIVE_DIR}/{day}.log.gz");
        if std::path::Path::new(&log_archive_path).is_file() {
            continue; // idempotent - sudah pernah diarsipkan
        }
        let tmp_raw = format!("/tmp/proxy-archive-{day}.log");
        let raw_text = lines.join("\n") + "\n";
        if fs::write(&tmp_raw, &raw_text).is_err() {
            continue;
        }
        let gzip_ok = Command::new("gzip").arg("-f").arg(&tmp_raw).status().map(|s| s.success()).unwrap_or(false);
        if !gzip_ok {
            let _ = fs::remove_file(&tmp_raw);
            continue;
        }
        let gz_tmp_path = format!("{tmp_raw}.gz");
        if fs::rename(&gz_tmp_path, &log_archive_path).is_err() {
            continue;
        }
        let aggregate = compute_bandwidth_aggregate(lines);
        let bandwidth_archive_path = format!("{BANDWIDTH_ARCHIVE_DIR}/{day}.json");
        let _ = fs::write(&bandwidth_archive_path, aggregate.to_string());
        archived_days.push(day.clone());
    }

    let settings = load_archive_settings();
    let pruned = prune_old_archives(settings.retention_days);

    format!("Archived {} day(s), pruned {} old archive(s)", archived_days.len(), pruned)
}

/// Hapus arsip (log+bandwidth) lebih tua dari retention_days - dicek
/// berdasarkan NAMA FILE (tanggal literal di nama, "YYYY-MM-DD.ext"),
/// bukan mtime filesystem - lebih robust terhadap file yang mtime-nya
/// mungkin berubah karena restore backup/copy manual, nama file adalah
/// sumber kebenaran yang genuinely tidak bisa nyasar.
fn prune_old_archives(retention_days: u32) -> usize {
    let cutoff_epoch = now_secs() - (retention_days as i64 * 86400);
    let cutoff_day = date_string_from_epoch(cutoff_epoch);
    let mut pruned = 0;
    for (dir, ext) in [(LOG_ARCHIVE_DIR, ".log.gz"), (BANDWIDTH_ARCHIVE_DIR, ".json")] {
        let Ok(entries) = fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let filename = entry.file_name().to_string_lossy().to_string();
            let Some(day_part) = filename.strip_suffix(ext) else { continue };
            if is_valid_date_string(day_part) && day_part < cutoff_day.as_str() {
                if fs::remove_file(entry.path()).is_ok() {
                    pruned += 1;
                }
            }
        }
    }
    pruned
}

/// Ekstrak domain (hostname polos, tanpa skema/path/port) dari URL
/// mentah di kolom access.log Squid - dipakai fitur Top Domains
/// (permintaan bro langsung setelah riset Lightsquid: satu-satunya
/// kapabilitas Lightsquid yang belum ketutup Bandwidth Usage yang
/// sudah ada adalah "situs mana yang paling sering diakses", bukan
/// cuma "siapa pakai berapa banyak"). DUA bentuk URL yang genuinely
/// muncul di access.log Squid, keduanya harus ditangani:
/// (1) Request HTTP biasa - "http://example.com/path/ke/halaman"
/// (2) CONNECT tunnel HTTPS - "example.com:443" TANPA skema sama
///     sekali (Squid mencatat method CONNECT dengan host:port polos,
///     bukan URL lengkap - ini mayoritas traffic web modern, jadi
///     WAJIB ditangani, bukan kasus langka).
/// Return None kalau baris genuinely tidak bisa diurai jadi hostname
/// yang masuk akal (mis. "-" untuk request yang gagal sebelum sempat
/// tahu tujuannya) - baris itu dilewati di caller, bukan dihitung
/// sebagai domain kosong.
pub fn extract_domain_from_squid_url(raw_url: &str) -> Option<String> {
    let mut s = raw_url.trim();
    if s.is_empty() || s == "-" {
        return None;
    }
    // Buang skema kalau ada ("http://", "https://", "ftp://") - CONNECT
    // tunnel TIDAK PERNAH punya skema sama sekali, jadi langkah ini
    // aman di-skip kalau tidak ketemu "://" (bukan tanda error).
    if let Some(idx) = s.find("://") {
        s = &s[idx + 3..];
    }
    // Buang path (semua setelah '/' pertama) dan query string kalau ada.
    if let Some(idx) = s.find('/') {
        s = &s[..idx];
    }
    // Buang userinfo kalau ada ("user:pass@host") - jarang di konteks
    // proxy korporat tapi valid secara syntax URL, jangan sampai ikut
    // masuk sebagai bagian hostname.
    if let Some(idx) = s.rfind('@') {
        s = &s[idx + 1..];
    }
    // Buang port (":443", ":8080") - baik dari CONNECT tunnel maupun
    // URL HTTP eksplisit yang menyebut port non-default.
    if let Some(idx) = s.rfind(':') {
        s = &s[..idx];
    }
    if s.is_empty() {
        return None;
    }
    Some(s.to_lowercase())
}
