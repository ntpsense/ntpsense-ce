// ============================================================
// OpenVPN - riset 4 vendor sebelum dibangun: FortiGate/Palo Alto/
// Sangfor SEMUANYA punya SSL-VPN proprietary sendiri (FortiClient,
// GlobalProtect, dst) - BUKAN literal OpenVPN. Cuma pfSense/OPNsense
// (basis FreeBSD yang sama dengan project ini) yang benar-benar pakai
// protokol OpenVPN terbuka - jadi pfSense jadi rujukan arsitektur
// paling relevan di sini, bukan sekadar salah satu dari empat.
//
// Kenapa OpenVPN masih relevan DI SAMPING WireGuard yang sudah ada:
// bisa jalan di TCP/443, menyamar seperti traffic HTTPS biasa - tembus
// firewall ketat/hotel/korporat yang blokir UDP (WireGuard UDP-only
// rentan diblokir di situasi itu). Nilainya di kompatibilitas/
// penetrasi firewall, bukan soal "lebih bagus" dari WireGuard.
//
// Dua mode DISEPAKATI dibangun sekaligus (bro eksplisit minta
// keduanya): Remote Access (road-warrior, 1 sertifikat per user,
// PERSIS pola per-user cert pfSense sendiri) dan Site-to-Site (1
// sertifikat per node remote, melengkapi IPsec yang sudah ada).
// Port/protokol admin-selectable (TCP/443 ATAU UDP/1194), bukan
// dipatok satu pilihan - shared key mode SENGAJA tidak didukung sama
// sekali (OpenVPN sendiri sudah men-deprecate itu resmi, SSL/TLS mode
// per-klien adalah satu-satunya jalur di sini).
// ============================================================

use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

pub const OPENVPN_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/vpn-openvpn-config.json";
pub const OPENVPN_PKI_DIR: &str = "/usr/local/etc/openvpn/pki";
pub const OPENVPN_SERVER_CONF: &str = "/usr/local/etc/openvpn/server.conf";
pub const OPENVPN_LOG: &str = "/var/log/openvpn.log";
pub const OPENVPN_MGMT_SOCK: &str = "/var/run/openvpn-mgmt.sock";
pub const OPENVPN_CCD_DIR: &str = "/usr/local/etc/openvpn/ccd";
pub const OPENVPN_RADIUS_VERIFY_SCRIPT: &str = "/usr/local/etc/openvpn/radius-verify.sh";
pub const OPENVPN_RADIUS_VERIFY_CONFIG: &str = "/usr/local/etc/openvpn/radius-verify-config.sh";
// File YANG SAMA persis ditulis ExternalAuth.php (Tahap 1) - satu
// sumber kebenaran untuk server RADIUS, TIDAK ADA config RADIUS
// terpisah khusus OpenVPN (sesuai riset pfSense yang disepakati bareng
// bro). Daemon Rust cuma BACA file ini (tidak pernah menulis), PHP
// yang tetap jadi satu-satunya penulis - mencegah dua sumber
// kebenaran yang bisa saling tidak sinkron.
const SHARED_EXTERNAL_AUTH_CONFIG: &str = "/usr/local/etc/ntpsense/webui/external-auth.json";
pub const OPENVPN_STATUS_LOG: &str = "/var/log/openvpn-status.log";
pub const OPENVPN_INTERFACE: &str = "tun0";
pub const OPENVPN_BIN: &str = "/usr/local/sbin/openvpn";
const PF_START_MARKER: &str = "# --- ntpsense-openvpn-autorule-start ---";
const PF_END_MARKER: &str = "# --- ntpsense-openvpn-autorule-end ---";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub remote_access_enabled: bool,
    #[serde(default)]
    pub site_to_site_enabled: bool,
    // "tcp" | "udp" - riset pfSense: TCP/443 paling umum dipilih untuk
    // tembus firewall ketat, UDP/1194 default OpenVPN kalau tidak ada
    // kendala jaringan tertentu. Admin pilih sendiri, tidak dipatok.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_port")]
    pub port: u16,
    // Subnet pool untuk client Remote Access (topology subnet, bukan
    // net30 lama yang boros alamat - default modern OpenVPN 2.1+).
    #[serde(default = "default_ra_subnet")]
    pub remote_access_subnet: String,
    #[serde(default)]
    pub pki_initialized: bool,
    // Tahap 2 roadmap RADIUS/LDAP (riset pfSense: OpenVPN reuse RADIUS
    // server yang SAMA dengan System > Authentication - Tahap 1, bukan
    // config RADIUS terpisah khusus OpenVPN). Kombinasi sertifikat
    // (sudah ada) + password RADIUS (kalau toggle ini aktif) = 2FA
    // sungguhan - "something you have" + "something you know", pola
    // yang sama dipakai vendor 2FA OpenVPN manapun (miniOrange/
    // Rublon/Protectimus, dikonfirmasi riset). Opsional per admin,
    // default false - tidak memaksa semua deployment pakai RADIUS.
    #[serde(default)]
    pub radius_auth_enabled: bool,
}

fn default_protocol() -> String {
    "udp".to_string()
}
fn default_port() -> u16 {
    1194
}
fn default_ra_subnet() -> String {
    "10.9.0.0/24".to_string()
}

impl Default for OpenVpnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            remote_access_enabled: false,
            site_to_site_enabled: false,
            protocol: default_protocol(),
            port: default_port(),
            remote_access_subnet: default_ra_subnet(),
            pki_initialized: false,
            radius_auth_enabled: false,
        }
    }
}

/// Client Remote Access (road-warrior) - 1 sertifikat per user, PERSIS
/// pola pfSense "Local User Access" (per-user cert dikelola penuh dari
/// GUI, bukan CA eksternal terpisah).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnClient {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub revoked: bool,
    // Toggle non-destruktif (roadmap - permintaan bro langsung),
    // TERPISAH dari 'revoked' (permanen, lewat CRL). Deactivate cuma
    // menolak koneksi BARU sementara - sertifikatnya sendiri tetap sah
    // secara kriptografis, gampang diaktifkan lagi kapan saja. Dipakai
    // untuk "istirahatkan" akses seseorang tanpa perlu keluarkan
    // sertifikat baru kalau nanti diaktifkan lagi.
    #[serde(default = "default_true")]
    pub active: bool,
    pub created_at: u64,
}

fn default_true() -> bool {
    true
}

/// Peer Site-to-Site - 1 sertifikat per node remote, melengkapi IPsec
/// yang sudah ada sebagai opsi lain untuk sambungan antar-site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnSite {
    pub id: String,
    pub name: String,
    pub remote_subnet: String,
    #[serde(default)]
    pub revoked: bool,
    pub created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OpenVpnState {
    #[serde(default)]
    pub clients: Vec<OpenVpnClient>,
    #[serde(default)]
    pub sites: Vec<OpenVpnSite>,
}

const OPENVPN_STATE_FILE: &str = "/usr/local/etc/ntpsense/vpn-openvpn-state.json";

pub fn load_config() -> OpenVpnConfig {
    fs::read_to_string(OPENVPN_CONFIG_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// RCA nyata (ditemukan bro langsung - hapus folder PKI manual lewat
/// console, Web UI TETAP bilang "PKI already initialized"): flag
/// pki_initialized cuma status TERSIMPAN di config JSON terpisah,
/// TIDAK PERNAH dicek ulang terhadap file yang SUNGGUHAN ada di disk.
/// Fungsi ini yang jadi sumber kebenaran SEBENARNYA - cek file inti
/// (ca.crt, server.crt, ta.key, crl.pem) benar-benar ada, bukan cuma
/// percaya flag. Dipanggil dari action openvpn.get_config, BUKAN
/// menggantikan field pki_initialized di struct (biar tidak perlu
/// migrasi skema), cuma dijadikan sumber kebenaran tambahan yang
/// dikirim terpisah ke UI.
pub fn pki_actually_exists() -> bool {
    let files = ["ca.crt", "ca.key", "server.crt", "server.key", "ta.key", "crl.pem"];
    files.iter().all(|f| std::path::Path::new(&format!("{OPENVPN_PKI_DIR}/{f}")).exists())
}

/// CA metadata untuk kartu status - tanggal terbit + expiry, supaya
/// admin bisa lihat langsung tanpa perlu buka terminal.
pub fn ca_info() -> Option<serde_json::Value> {
    if !pki_actually_exists() {
        return None;
    }
    let ca_crt = format!("{OPENVPN_PKI_DIR}/ca.crt");
    let not_before = Command::new("openssl").args(["x509", "-in", &ca_crt, "-noout", "-startdate"]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace("notBefore=", ""));
    let not_after = Command::new("openssl").args(["x509", "-in", &ca_crt, "-noout", "-enddate"]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace("notAfter=", ""));
    let fingerprint = Command::new("openssl").args(["x509", "-in", &ca_crt, "-noout", "-fingerprint", "-sha256"]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace("sha256 Fingerprint=", "").replace("SHA256 Fingerprint=", ""));
    Some(serde_json::json!({
        "not_before": not_before,
        "not_after": not_after,
        "fingerprint": fingerprint,
    }))
}

/// Hapus total PKI - dipanggil dari tombol "Delete & Reset PKI" di UI
/// (bukan cuma via console lagi). SEMUA client/site yang ada otomatis
/// jadi tidak valid setelah ini (CA-nya hilang) - peringatan eksplisit
/// soal ini ada di sisi PHP/JS sebelum tombol ini bisa ditekan.
pub fn reset_pki() -> Result<(), String> {
    let _ = Command::new("/usr/sbin/service").args(["openvpn", "stop"]).status();
    let _ = fs::remove_dir_all(OPENVPN_PKI_DIR);
    let _ = fs::remove_dir_all(OPENVPN_CCD_DIR);
    let mut cfg = load_config();
    cfg.pki_initialized = false;
    cfg.enabled = false;
    save_config(&cfg)?;
    // State client/site JUGA dikosongkan - sertifikat mereka semua
    // tidak berarti apa-apa lagi tanpa CA yang menandatanganinya,
    // membiarkan entri lama nangkring di daftar cuma akan
    // membingungkan (kelihatan "Active" padahal CA-nya sudah tidak
    // ada).
    save_state(&OpenVpnState::default())?;
    Ok(())
}

pub fn save_config(cfg: &OpenVpnConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    if let Some(parent) = std::path::Path::new(OPENVPN_CONFIG_FILE).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(OPENVPN_CONFIG_FILE, json).map_err(|e| e.to_string())
}

pub fn load_state() -> OpenVpnState {
    fs::read_to_string(OPENVPN_STATE_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn save_state(state: &OpenVpnState) -> Result<(), String> {
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    fs::write(OPENVPN_STATE_FILE, json).map_err(|e| e.to_string())
}

// ============================================================
// PKI - CA + server cert + DH params + tls-crypt key, sekali di awal.
// RSA 2048 (bukan ECDSA) SENGAJA dipilih - kompatibilitas klien paling
// luas (Android/iOS/Windows/router lama sekalipun) lebih penting di
// sini daripada kecepatan marjinal ECDSA, konsisten dengan tujuan
// OpenVPN di project ini (kompatibilitas maksimal, bukan performa).
// ============================================================

fn openssl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("openssl").args(args).output().map_err(|e| format!("failed to run openssl: {e}"))?;
    if !output.status.success() {
        return Err(format!("openssl {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

pub fn init_pki() -> Result<(), String> {
    fs::create_dir_all(OPENVPN_PKI_DIR).map_err(|e| format!("failed to create PKI dir: {e}"))?;
    fs::create_dir_all(format!("{OPENVPN_PKI_DIR}/issued")).map_err(|e| e.to_string())?;
    fs::create_dir_all(format!("{OPENVPN_PKI_DIR}/private")).map_err(|e| e.to_string())?;

    let ca_key = format!("{OPENVPN_PKI_DIR}/ca.key");
    let ca_crt = format!("{OPENVPN_PKI_DIR}/ca.crt");
    // CA - 10 tahun, self-signed, dipakai HANYA untuk menandatangani
    // sertifikat server/client project ini sendiri, bukan CA publik.
    openssl(&["genrsa", "-out", &ca_key, "2048"])?;
    openssl(&[
        "req", "-x509", "-new", "-nodes", "-key", &ca_key, "-sha256", "-days", "3650",
        "-out", &ca_crt, "-subj", "/CN=NTPSense-OpenVPN-CA",
    ])?;

    // RCA nyata (ditemukan bro langsung - client yang SUDAH DI-REVOKE
    // masih bisa connect penuh, VERIFY OK tetap muncul di log server):
    // versi awal PKI ini menandatangani sertifikat ad-hoc pakai
    // 'openssl x509 -req' (cuma tanda tangan langsung, TIDAK PERNAH
    // mencatat apa pun ke database CA manapun) - lalu "revoke" cuma
    // menghapus SALINAN file di server. Client tetap punya salinan
    // sertifikatnya SENDIRI (di dalam .ovpn yang sudah di-download),
    // dan OpenVPN memverifikasi TERHADAP RANTAI CA (masih valid, CA-nya
    // tidak berubah) - BUKAN terhadap "apakah file ini masih ada di
    // disk server". Menghapus salinan server sama sekali tidak
    // membuat sertifikat client jadi tidak valid secara kriptografis.
    //
    // Fix yang BENAR: bangun database CA OpenSSL sungguhan (index.txt/
    // serial/crlnumber) dari awal, supaya SETIAP sertifikat yang
    // diterbitkan tercatat resmi - baru dari situ revoke bisa
    // menghasilkan CRL (Certificate Revocation List) sungguhan, yang
    // dicek EKSPLISIT oleh server tiap ada yang connect (directive
    // 'crl-verify' di server.conf, lihat generate_server_conf()).
    fs::write(format!("{OPENVPN_PKI_DIR}/index.txt"), "").map_err(|e| e.to_string())?;
    fs::write(format!("{OPENVPN_PKI_DIR}/serial"), "01\n").map_err(|e| e.to_string())?;
    fs::write(format!("{OPENVPN_PKI_DIR}/crlnumber"), "01\n").map_err(|e| e.to_string())?;
    let ca_cnf = format!(
        "[ca]\ndefault_ca = CA_default\n\n\
         [CA_default]\n\
         dir = {OPENVPN_PKI_DIR}\n\
         database = $dir/index.txt\n\
         new_certs_dir = $dir/issued\n\
         certificate = $dir/ca.crt\n\
         private_key = $dir/ca.key\n\
         serial = $dir/serial\n\
         crlnumber = $dir/crlnumber\n\
         crl = $dir/crl.pem\n\
         default_days = 1825\n\
         default_crl_days = 3650\n\
         default_md = sha256\n\
         policy = policy_anything\n\
         copy_extensions = none\n\
         unique_subject = no\n\n\
         [policy_anything]\n\
         commonName = supplied\n\n\
         [req]\n\
         distinguished_name = req_distinguished_name\n\
         [req_distinguished_name]\n"
    );
    fs::write(format!("{OPENVPN_PKI_DIR}/ca.cnf"), ca_cnf).map_err(|e| e.to_string())?;

    // Server cert - ditandatangani lewat database CA yang sama (bukan
    // ad-hoc lagi) supaya konsisten tercatat, meski server cert sendiri
    // tidak realistis perlu di-revoke dalam skenario normal.
    let server_key = format!("{OPENVPN_PKI_DIR}/server.key");
    let server_csr = format!("{OPENVPN_PKI_DIR}/server.csr");
    let server_crt = format!("{OPENVPN_PKI_DIR}/server.crt");
    openssl(&["genrsa", "-out", &server_key, "2048"])?;
    openssl(&["req", "-new", "-key", &server_key, "-out", &server_csr, "-subj", "/CN=ntpsense-openvpn-server"])?;
    sign_with_ca(&server_csr, &server_crt)?;
    let _ = fs::remove_file(&server_csr);

    // DH params - 2048 bit, satu kali saja (proses ini genuinely lambat,
    // puluhan detik, TAPI cuma dijalankan sekali seumur PKI, bukan per
    // client/per request).
    let dh_path = format!("{OPENVPN_PKI_DIR}/dh.pem");
    openssl(&["dhparam", "-out", &dh_path, "2048"])?;

    // tls-crypt key - satu kunci statis tambahan (HMAC + enkripsi
    // control channel), riset pfSense: mode modern menggantikan
    // tls-auth lama, mengaburkan traffic OpenVPN dari deteksi DPI
    // pasif sekaligus proteksi DoS/port-scan.
    let ta_key = format!("{OPENVPN_PKI_DIR}/ta.key");
    if std::path::Path::new(OPENVPN_BIN).exists() {
        let status = Command::new(OPENVPN_BIN).args(["--genkey", "secret", &ta_key]).status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            return Err("openvpn --genkey secret failed to generate tls-crypt key".to_string());
        }
    } else {
        return Err(format!("{OPENVPN_BIN} not found - install the openvpn package first (pkg install openvpn)"));
    }

    // CRL awal - KOSONG (belum ada yang di-revoke), tapi harus ada
    // FILENYA sejak awal karena server.conf akan langsung menunjuk ke
    // sini lewat crl-verify - server gagal start kalau file itu belum
    // ada sama sekali.
    regenerate_crl()?;

    let mut cfg = load_config();
    cfg.pki_initialized = true;
    save_config(&cfg)?;
    Ok(())
}

fn ca_cnf_path() -> String {
    format!("{OPENVPN_PKI_DIR}/ca.cnf")
}

/// Tanda tangani CSR lewat database CA resmi (openssl ca, BUKAN
/// openssl x509 -req ad-hoc) - setiap pemanggilan INI yang membuat
/// index.txt bertambah baris, satu-satunya jalan revoke bisa benar-
/// benar berarti sesuatu nantinya.
fn sign_with_ca(csr_path: &str, out_crt_path: &str) -> Result<(), String> {
    let cnf = ca_cnf_path();
    let output = Command::new("openssl")
        .args(["ca", "-batch", "-config", &cnf, "-in", csr_path, "-out", out_crt_path, "-notext"])
        .output()
        .map_err(|e| format!("failed to run openssl ca: {e}"))?;
    if !output.status.success() {
        return Err(format!("openssl ca (sign) failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

/// Regenerasi CRL dari state index.txt SAAT INI - dipanggil setelah
/// init awal (CRL kosong) MAUPUN setelah setiap revoke (CRL berisi
/// entri baru yang barusan di-revoke).
fn regenerate_crl() -> Result<(), String> {
    let cnf = ca_cnf_path();
    let crl_path = format!("{OPENVPN_PKI_DIR}/crl.pem");
    let output = Command::new("openssl")
        .args(["ca", "-config", &cnf, "-gencrl", "-out", &crl_path])
        .output()
        .map_err(|e| format!("failed to run openssl ca -gencrl: {e}"))?;
    if !output.status.success() {
        return Err(format!("openssl ca -gencrl failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

/// Terbitkan sertifikat baru (client Remote Access ATAU peer
/// Site-to-Site - mekanismenya identik, cuma penamaan/penyimpanan
/// metadata yang beda) - dipakai issue_client() dan issue_site() di
/// bawah, satu sumber kebenaran untuk proses tanda-tangan CA.
fn issue_cert(common_name: &str) -> Result<(), String> {
    let key_path = format!("{OPENVPN_PKI_DIR}/private/{common_name}.key");
    let csr_path = format!("{OPENVPN_PKI_DIR}/{common_name}.csr");
    let crt_path = format!("{OPENVPN_PKI_DIR}/issued/{common_name}.crt");

    openssl(&["genrsa", "-out", &key_path, "2048"])?;
    openssl(&["req", "-new", "-key", &key_path, "-out", &csr_path, "-subj", &format!("/CN={common_name}")])?;
    sign_with_ca(&csr_path, &crt_path)?;
    let _ = fs::remove_file(&csr_path);
    Ok(())
}

/// Revoke SUNGGUHAN - menandai sertifikat sebagai revoked di database
/// CA (openssl ca -revoke), lalu regenerasi CRL supaya perubahan itu
/// benar-benar tercermin di file yang dibaca server (crl-verify).
/// Pemanggil (main.rs) WAJIB memicu reload/restart OpenVPN setelah
/// ini, supaya proses yang SEDANG JALAN membaca ulang CRL terbaru -
/// CRL baru di disk saja TIDAK OTOMATIS berlaku untuk proses yang
/// sudah lama hidup.
fn revoke_cert_files(common_name: &str) -> Result<(), String> {
    let crt_path = format!("{OPENVPN_PKI_DIR}/issued/{common_name}.crt");
    if !std::path::Path::new(&crt_path).exists() {
        // Sertifikat sudah tidak ada (mis. dobel-klik revoke, atau PKI
        // lama sebelum fix ini) - tidak ada yang bisa di-revoke lewat
        // database CA, tapi bukan error fatal - lanjutkan saja supaya
        // status client di UI tetap konsisten ter-set revoked=true.
        return Ok(());
    }
    let cnf = ca_cnf_path();
    let output = Command::new("openssl")
        .args(["ca", "-config", &cnf, "-revoke", &crt_path])
        .output()
        .map_err(|e| format!("failed to run openssl ca -revoke: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "already revoked" bukan error fatal - idempotent, aman
        // dipanggil ulang.
        if !stderr.contains("already revoked") {
            return Err(format!("openssl ca -revoke failed: {stderr}"));
        }
    }
    regenerate_crl()?;
    let _ = fs::remove_file(format!("{OPENVPN_PKI_DIR}/private/{common_name}.key"));
    Ok(())
}

pub fn create_client(name: &str) -> Result<OpenVpnClient, String> {
    if name.trim().is_empty() {
        return Err("Client name cannot be empty.".to_string());
    }
    let mut state = load_state();
    if state.clients.iter().any(|c| c.name == name && !c.revoked) {
        return Err(format!("A client named '{name}' already exists."));
    }
    let common_name = format!("client-{name}");
    issue_cert(&common_name)?;
    let client = OpenVpnClient {
        id: format!("ovc{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
        name: name.to_string(),
        revoked: false,
        active: true,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    };
    state.clients.push(client.clone());
    save_state(&state)?;
    Ok(client)
}

pub fn revoke_client(id: &str) -> Result<(), String> {
    let mut state = load_state();
    let Some(client) = state.clients.iter_mut().find(|c| c.id == id) else {
        return Err(format!("Client id '{id}' not found."));
    };
    client.revoked = true;
    let common_name = format!("client-{}", client.name.clone());
    save_state(&state)?;
    revoke_cert_files(&common_name)?;
    let _ = fs::remove_file(format!("{OPENVPN_CCD_DIR}/{common_name}")); // bersihkan CCD kalau ada, tidak relevan lagi buat cert yang sudah di-revoke permanen
    Ok(())
}

/// Toggle Active/Deactivate - TERPISAH dari revoke (lihat komentar di
/// struct OpenVpnClient). Pakai directive 'disable' di file
/// client-config-dir (CCD) OpenVPN - resmi, dirancang persis untuk
/// kasus ini (tolak koneksi client tertentu tanpa menyentuh
/// sertifikatnya sama sekali). File CCD dihapus saat diaktifkan lagi
/// (bukan ditulis 'enable' - defaultnya memang enabled kalau tidak
/// ada file CCD untuk CN itu sama sekali).
pub fn set_client_active(id: &str, active: bool) -> Result<(), String> {
    let mut state = load_state();
    let Some(client) = state.clients.iter_mut().find(|c| c.id == id) else {
        return Err(format!("Client id '{id}' not found."));
    };
    if client.revoked {
        return Err("Cannot activate/deactivate a revoked client - revocation is permanent.".to_string());
    }
    client.active = active;
    let common_name = format!("client-{}", client.name.clone());
    save_state(&state)?;
    fs::create_dir_all(OPENVPN_CCD_DIR).map_err(|e| e.to_string())?;
    let ccd_path = format!("{OPENVPN_CCD_DIR}/{common_name}");
    if active {
        let _ = fs::remove_file(&ccd_path);
    } else {
        fs::write(&ccd_path, "disable\n").map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Putuskan koneksi client yang SEDANG AKTIF sekarang juga - lewat
/// management interface OpenVPN (protokol socket sederhana berbasis
/// teks, 'kill <common_name>' memutus sesi itu). Ini TIDAK mencegah
/// client connect LAGI setelahnya (beda dari deactivate/revoke) -
/// murni "putuskan sesi yang sedang berlangsung sekarang", cocok
/// untuk kasus mis. admin lihat aktivitas mencurigakan dan mau putus
/// dulu sebelum investigasi lebih lanjut.
pub fn disconnect_client(common_name: &str) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(OPENVPN_MGMT_SOCK)
        .map_err(|e| format!("Could not connect to OpenVPN management interface at {OPENVPN_MGMT_SOCK}: {e} (is the server running with 'management' enabled?)"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    writeln!(stream, "kill {common_name}").map_err(|e| format!("failed to write to management socket: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    let mut line = String::new();
    // Baca beberapa baris respons (protokol manajemen OpenVPN kirim
    // balik status per baris, diakhiri "END" atau "SUCCESS"/"ERROR") -
    // dibatasi 10 baris supaya tidak menggantung tanpa batas kalau
    // formatnya tidak sesuai dugaan.
    for _ in 0..10 {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        response.push_str(&line);
        if line.trim_start().starts_with("SUCCESS") || line.trim_start().starts_with("ERROR") || line.trim() == "END" {
            break;
        }
    }
    Ok(response)
}

pub fn create_site(name: &str, remote_subnet: &str) -> Result<OpenVpnSite, String> {
    if name.trim().is_empty() {
        return Err("Site name cannot be empty.".to_string());
    }
    let mut state = load_state();
    if state.sites.iter().any(|s| s.name == name && !s.revoked) {
        return Err(format!("A site named '{name}' already exists."));
    }
    let common_name = format!("site-{name}");
    issue_cert(&common_name)?;
    let site = OpenVpnSite {
        id: format!("ovs{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
        name: name.to_string(),
        remote_subnet: remote_subnet.to_string(),
        revoked: false,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    };
    state.sites.push(site.clone());
    save_state(&state)?;
    Ok(site)
}

pub fn revoke_site(id: &str) -> Result<(), String> {
    let mut state = load_state();
    let Some(site) = state.sites.iter_mut().find(|s| s.id == id) else {
        return Err(format!("Site id '{id}' not found."));
    };
    site.revoked = true;
    let common_name = format!("site-{}", site.name.clone());
    save_state(&state)?;
    revoke_cert_files(&common_name)?;
    Ok(())
}

/// Bundling client .ovpn - CA cert + client cert + client key + tls-crypt
/// key SEMUA jadi satu file (inline lewat blok <ca>/<cert>/<key>/
/// <tls-crypt>), PERSIS pola "OpenVPN Client Export Package" pfSense -
/// admin tidak perlu distribusi 4 file terpisah, satu file .ovpn siap
/// import ke klien mana pun (Windows/Mac/Android/iOS/router).
pub fn build_client_ovpn(client_name: &str, cfg: &OpenVpnConfig, server_public_host: &str) -> Result<String, String> {
    let common_name = format!("client-{client_name}");
    let ca_crt = fs::read_to_string(format!("{OPENVPN_PKI_DIR}/ca.crt")).map_err(|e| format!("failed to read ca.crt: {e}"))?;
    let client_crt = fs::read_to_string(format!("{OPENVPN_PKI_DIR}/issued/{common_name}.crt")).map_err(|e| format!("failed to read client cert: {e}"))?;
    let client_key = fs::read_to_string(format!("{OPENVPN_PKI_DIR}/private/{common_name}.key")).map_err(|e| format!("failed to read client key: {e}"))?;
    let ta_key = fs::read_to_string(format!("{OPENVPN_PKI_DIR}/ta.key")).map_err(|e| format!("failed to read ta.key: {e}"))?;

    // Cert PEM dari 'openssl x509 -req' punya header CA-print di atas
    // blok BEGIN/END - dipotong supaya file .ovpn tetap bersih (klien
    // pemula sering bingung kalau ada teks aneh di luar blok PEM).
    let strip_to_pem = |raw: &str| -> String {
        let start = raw.find("-----BEGIN").unwrap_or(0);
        raw[start..].to_string()
    };

    let auth_user_pass_line = if cfg.radius_auth_enabled {
        // Tahap 2 roadmap - beritahu APLIKASI CLIENT untuk minta
        // username/password saat connect (selain sertifikat yang
        // sudah wajib lewat blok <cert>/<key> di bawah) - inilah yang
        // membuatnya jadi 2FA sungguhan dari sisi pengalaman user,
        // bukan cuma di server.
        "auth-user-pass\n"
    } else {
        ""
    };

    Ok(format!(
        "client\ndev tun\nproto {proto}\nremote {host} {port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\n{auth_user_pass}verb 3\n\n<ca>\n{ca}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n<tls-crypt>\n{ta}</tls-crypt>\n",
        proto = cfg.protocol,
        host = server_public_host,
        port = cfg.port,
        auth_user_pass = auth_user_pass_line,
        ca = strip_to_pem(&ca_crt),
        cert = strip_to_pem(&client_crt),
        key = client_key,
        ta = ta_key,
    ))
}

/// Server config - satu instance OpenVPN melayani KEDUA mode sekaligus
/// (Remote Access + Site-to-Site) lewat 'client-config-dir' per-CN,
/// bukan dua proses OpenVPN terpisah - lebih sederhana dikelola, dan
/// port/protocol yang sama bisa dipakai kedua mode tanpa konflik.
pub fn generate_server_conf(cfg: &OpenVpnConfig) -> String {
    let (subnet_ip, subnet_mask) = split_cidr(&cfg.remote_access_subnet);
    let mut conf = format!(
        "port {port}\n\
         proto {proto}\n\
         dev {iface}\n\
         ca {pki}/ca.crt\n\
         cert {pki}/server.crt\n\
         key {pki}/server.key\n\
         dh {pki}/dh.pem\n\
         tls-crypt {pki}/ta.key\n\
         crl-verify {pki}/crl.pem\n\
         client-config-dir {ccd}\n\
         management {mgmt} unix\n\
         topology subnet\n\
         server {subnet_ip} {subnet_mask}\n\
         keepalive 10 60\n\
         cipher AES-256-GCM\n\
         auth SHA256\n\
         persist-key\n\
         persist-tun\n\
         status {status_log}\n\
         log-append {log}\n\
         verb 3\n\
         explicit-exit-notify 1\n",
        port = cfg.port,
        proto = cfg.protocol,
        iface = OPENVPN_INTERFACE,
        pki = OPENVPN_PKI_DIR,
        ccd = OPENVPN_CCD_DIR,
        mgmt = OPENVPN_MGMT_SOCK,
        subnet_ip = subnet_ip,
        subnet_mask = subnet_mask,
        status_log = OPENVPN_STATUS_LOG,
        log = OPENVPN_LOG,
    );
    if cfg.radius_auth_enabled {
        // Tahap 2 roadmap - sertifikat (SUDAH wajib lewat ca/cert/key di
        // atas, TIDAK berubah) + password RADIUS = 2FA. 'via-env' -
        // OpenVPN kirim username/password ke script lewat environment
        // variable, bukan file sementara di disk (lebih aman - tidak
        // pernah tertulis ke disk sama sekali, bahkan sementara).
        conf.push_str(&format!("auth-user-pass-verify {} via-env\n", OPENVPN_RADIUS_VERIFY_SCRIPT));
        conf.push_str("script-security 3\n");
    }
    conf
}

fn split_cidr(cidr: &str) -> (String, String) {
    // "10.9.0.0/24" -> ("10.9.0.0", "255.255.255.0") - server directive
    // OpenVPN butuh format IP+netmask terpisah, bukan notasi CIDR.
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip = parts.first().unwrap_or(&"10.9.0.0").to_string();
    let prefix: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);
    let mask_bits: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let mask = format!(
        "{}.{}.{}.{}",
        (mask_bits >> 24) & 0xFF,
        (mask_bits >> 16) & 0xFF,
        (mask_bits >> 8) & 0xFF,
        mask_bits & 0xFF
    );
    (ip, mask)
}

fn sync_pf_rule(cfg: &OpenVpnConfig) -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    if content.contains(PF_START_MARKER) {
        return Ok(());
    }
    let anchor = "\nblock log all\n";
    let Some(idx) = content.find(anchor) else {
        return Err("Could not find 'block log all' anchor in /etc/pf.conf to insert OpenVPN marker".to_string());
    };
    let insert_at = idx + anchor.len();
    // Rule WAN (izinkan koneksi masuk ke port OpenVPN) + rule tun0
    // (traffic yang sudah masuk tunnel) - dua baris, pola sama dengan
    // wg0/enc0 sebelumnya.
    let rule_text = format!(
        "pass in quick proto {} to port {} keep state\npass quick on {} all keep state",
        cfg.protocol, cfg.port, OPENVPN_INTERFACE
    );
    let new_content = format!("{}\n{PF_START_MARKER}\n{rule_text}\n{PF_END_MARKER}\n\n{}", &content[..insert_at], &content[insert_at..]);
    let tmp_path = "/tmp/pf.conf.openvpn_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed - /etc/pf.conf NOT changed. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

/// Reapply penuh - config + pf + restart service, verifikasi status
/// SUNGGUHAN (bukan cuma percaya exit code service restart), pola
/// SAMA persis dengan apply_wireguard_conf()/apply_squid_conf().
/// Baca server RADIUS PERTAMA yang enabled dari file config bersama
/// (ditulis ExternalAuth.php, Tahap 1) - MVP Tahap 2 sengaja pakai satu
/// server saja dulu (bukan daftar+fallback), pola "mulai sederhana,
/// perluas nanti" yang sudah dipakai di banyak fitur lain project ini.
fn read_first_radius_server() -> Option<(String, String, String, String)> {
    let content = fs::read_to_string(SHARED_EXTERNAL_AUTH_CONFIG).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    if !json.get("radius_enabled")?.as_bool()? {
        return None;
    }
    let server = json.get("radius_servers")?.as_array()?.first()?;
    let host = server.get("host")?.as_str()?.to_string();
    let port = server.get("port").and_then(|v| v.as_str()).unwrap_or("1812").to_string();
    let secret = server.get("secret")?.as_str()?.to_string();
    let timeout = server.get("timeout").and_then(|v| v.as_str()).unwrap_or("5").to_string();
    if host.is_empty() || secret.is_empty() {
        return None;
    }
    Some((host, port, secret, timeout))
}

/// Generate script verify RADIUS untuk OpenVPN (--auth-user-pass-verify
/// ... via-env) - dipanggil setiap kali apply_openvpn_conf() jalan,
/// supaya perubahan server RADIUS di System > Authentication (Tahap 1)
/// otomatis ikut ter-refresh di sini juga tanpa langkah manual
/// terpisah. Dua file: config (KEY=VALUE sederhana, di-source oleh
/// script utama - shell TIDAK punya parser JSON bawaan di FreeBSD
/// base) + script verify itu sendiri (statis, isinya tidak pernah
/// berubah - cuma dibuat sekali kalau belum ada).
fn write_radius_verify_files() -> Result<(), String> {
    let (host, port, secret, timeout) = match read_first_radius_server() {
        Some(v) => v,
        None => {
            // Tidak ada server RADIUS ter-enable - tulis config KOSONG
            // (host="") supaya script verify SELALU menolak dengan
            // aman (fail closed) kalau somehow masih terpanggil,
            // daripada meninggalkan config lama yang basi.
            (String::new(), String::new(), String::new(), String::new())
        }
    };
    let config_content = format!(
        "RADIUS_HOST='{}'\nRADIUS_PORT='{}'\nRADIUS_SECRET='{}'\nRADIUS_TIMEOUT='{}'\n",
        host.replace('\'', "'\\''"),
        port.replace('\'', "'\\''"),
        secret.replace('\'', "'\\''"),
        timeout.replace('\'', "'\\''"),
    );
    fs::write(OPENVPN_RADIUS_VERIFY_CONFIG, config_content).map_err(|e| format!("failed to write {OPENVPN_RADIUS_VERIFY_CONFIG}: {e}"))?;
    // 0600 - berisi RADIUS shared secret, sama sensitifnya dengan
    // ta.key/ca.key - cuma root (yang menjalankan OpenVPN) yang perlu baca.
    let _ = Command::new("chmod").arg("600").arg(OPENVPN_RADIUS_VERIFY_CONFIG).status();

    // Script verify - statis, isinya tidak bergantung server RADIUS
    // mana pun (cuma source file config di atas) - ditulis ulang setiap
    // kali juga (idempotent, murah), bukan cuma sekali, supaya kalau
    // ada perbaikan script di versi daemon berikutnya otomatis ter-apply.
    let script_content = r#"#!/bin/sh
# ntpsense-openvpn-radius-verify.sh - AUTO-GENERATED oleh ntpsense-configd,
# JANGAN edit manual, akan tertimpa setiap apply_openvpn_conf() jalan.
# Dipanggil OpenVPN lewat --auth-user-pass-verify ... via-env - $username
# dan $password tersedia sebagai environment variable dari OpenVPN sendiri.
. /usr/local/etc/openvpn/radius-verify-config.sh

if [ -z "$RADIUS_HOST" ]; then
    # Tidak ada server RADIUS ter-enable - fail closed (tolak semua),
    # bukan fail open. Log alasannya supaya admin tidak bingung kenapa
    # semua client tertolak kalau toggle RADIUS aktif tapi lupa isi server.
    echo "$(date '+%Y-%m-%d %H:%M:%S') RADIUS auth REJECTED for '${username}': no RADIUS server configured" >> /var/log/openvpn.log
    exit 1
fi

INPUT=$(printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$username" "$password")
OUTPUT=$(echo "$INPUT" | /usr/local/bin/radclient -t "$RADIUS_TIMEOUT" -x "$RADIUS_HOST:$RADIUS_PORT" auth "$RADIUS_SECRET" 2>&1)

if echo "$OUTPUT" | grep -q "Access-Accept"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') RADIUS auth OK for '${username}'" >> /var/log/openvpn.log
    exit 0
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') RADIUS auth REJECTED for '${username}'" >> /var/log/openvpn.log
    exit 1
fi
"#;
    fs::write(OPENVPN_RADIUS_VERIFY_SCRIPT, script_content).map_err(|e| format!("failed to write {OPENVPN_RADIUS_VERIFY_SCRIPT}: {e}"))?;
    let _ = Command::new("chmod").arg("755").arg(OPENVPN_RADIUS_VERIFY_SCRIPT).status();
    Ok(())
}

pub fn apply_openvpn_conf() -> Result<(), String> {
    let cfg = load_config();
    if !cfg.enabled {
        let _ = Command::new("/usr/sbin/service").args(["openvpn", "stop"]).status();
        return Ok(());
    }
    if !pki_actually_exists() {
        return Err("PKI has not been initialized yet - run Initialize PKI first.".to_string());
    }
    if let Some(parent) = std::path::Path::new(OPENVPN_SERVER_CONF).parent() {
        let _ = fs::create_dir_all(parent);
    }
    // RCA nyata (ditemukan bro langsung - Save & Apply macet ~60 detik,
    // openvpn akhirnya TIDAK jalan sama sekali meski config tersimpan
    // benar): server.conf SELALU menyebut 'client-config-dir' (dipakai
    // mekanisme active/deactivate), tapi direktorinya cuma dibuat
    // secara LAZY di set_client_active() - kalau belum ada satu pun
    // client yang di-deactivate, direktori itu TIDAK PERNAH ada saat
    // OpenVPN pertama kali start, dan OpenVPN gagal/macet lama mencoba
    // baca direktori yang tidak ada itu. Dibuat UNCONDITIONAL di sini,
    // konsisten dengan prinsip "unconditional reapply" yang dipegang
    // di seluruh project ini - jangan pernah asumsikan langkah lain
    // sudah menyiapkan prasyarat yang kita sendiri butuhkan.
    fs::create_dir_all(OPENVPN_CCD_DIR).map_err(|e| format!("failed to create {OPENVPN_CCD_DIR}: {e}"))?;
    // Tahap 2 roadmap RADIUS - regenerasi TANPA SYARAT (bukan cuma
    // kalau radius_auth_enabled true) supaya file-nya selalu sinkron
    // dengan config RADIUS Tahap 1 terbaru, siap dipakai kapan pun
    // admin nyalakan toggle-nya nanti - konsisten prinsip "unconditional
    // reapply" yang sama seperti CCD directory di atas.
    write_radius_verify_files()?;
    let conf_text = generate_server_conf(&cfg);
    fs::write(OPENVPN_SERVER_CONF, conf_text).map_err(|e| format!("failed to write {OPENVPN_SERVER_CONF}: {e}"))?;

    let _ = Command::new("sysrc").arg("openvpn_enable=YES").status();
    let _ = Command::new("sysrc").arg(format!("openvpn_configfile={OPENVPN_SERVER_CONF}")).status();

    sync_pf_rule(&cfg)?;

    let restart = Command::new("/usr/sbin/service").args(["openvpn", "restart"]).status();
    if restart.map(|s| !s.success()).unwrap_or(true) {
        return Err("service openvpn restart failed to spawn".to_string());
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    if !Command::new("pgrep").args(["-q", "-f", OPENVPN_BIN]).status().map(|s| s.success()).unwrap_or(false) {
        return Err("OpenVPN did not stay running after restart - check /var/log/openvpn.log for details".to_string());
    }
    Ok(())
}

/// Status koneksi aktif - parse status log (format 'CLIENT_LIST' OpenVPN
/// native, bukan reimplementasi protokol manajemen terpisah). Dipakai
/// sebagai FALLBACK kalau management interface tidak bisa dihubungi -
/// lihat get_connected_clients_live() untuk jalur utama yang lebih
/// real-time.
pub fn get_connected_clients() -> Vec<serde_json::Value> {
    let Ok(content) = fs::read_to_string(OPENVPN_STATUS_LOG) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("CLIENT_LIST,") {
            let fields: Vec<&str> = rest.split(',').collect();
            if fields.len() >= 8 {
                result.push(serde_json::json!({
                    "common_name": fields[0],
                    "real_address": fields[1],
                    "virtual_address": fields[2],
                    "bytes_received": fields[4],
                    "bytes_sent": fields[5],
                    "connected_since": fields[6],
                }));
            }
        }
    }
    result
}

/// Sama seperti get_connected_clients(), TAPI query LANGSUNG ke proses
/// OpenVPN yang sedang jalan lewat management interface (perintah
/// 'status 3', mekanisme SAMA yang sudah terbukti jalan untuk
/// disconnect_client() - satu sumber koneksi, bukan dua cara berbeda
/// menghubungi management interface). Lebih real-time daripada baca
/// file log (yang cuma ditulis ulang periodik) - dipakai sebagai jalur
/// UTAMA, get_connected_clients() (baca file) jadi fallback kalau
/// management interface untuk sebab apa pun tidak bisa dihubungi.
pub fn get_connected_clients_live() -> Result<Vec<serde_json::Value>, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(OPENVPN_MGMT_SOCK)
        .map_err(|e| format!("Could not connect to OpenVPN management interface: {e}"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    writeln!(stream, "status 3").map_err(|e| format!("failed to write to management socket: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut result = Vec::new();
    let mut line = String::new();
    // Baca sampai baris "END" (penanda akhir output status di protokol
    // manajemen OpenVPN) - dibatasi 500 baris sebagai jaring pengaman
    // supaya tidak menggantung tanpa batas kalau formatnya berubah.
    for _ in 0..500 {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed == "END" {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("CLIENT_LIST\t") {
            // Format 'status 3' pakai TAB, beda dari file log yang pakai
            // koma - kolomnya: CN, Real Address, Virtual Address, Virtual
            // IPv6 Address, Bytes Received, Bytes Sent, Connected Since, ...
            let fields: Vec<&str> = rest.split('\t').collect();
            if fields.len() >= 7 {
                result.push(serde_json::json!({
                    "common_name": fields[0],
                    "real_address": fields[1],
                    "virtual_address": fields[2],
                    "bytes_received": fields[4],
                    "bytes_sent": fields[5],
                    "connected_since": fields[6],
                }));
            }
        }
    }
    Ok(result)
}

