// ntpsense-configd - NTPSense InetGateway Tier 2 privileged config daemon
//
// Spek IPC (sudah didesain & dibahas sebelumnya, diimplementasi di sini):
//   - Socket: /var/run/ntpsense-configd.sock, mode 0660, owner root:ntpsenseweb
//   - Model koneksi: one-shot per request (connect -> 1 baris JSON -> 1 baris
//     JSON balasan -> close), BUKAN persistent multiplexed - cocok untuk
//     PHP-FPM yang stateless per-request.
//   - Framing: newline-delimited JSON (NDJSON), satu objek per baris.
//   - Peer credential check: WAJIB, bukan opsional - permission file socket
//     saja TIDAK CUKUP (pelajaran dari CVE-2026-53657 Lima/QEMU: root
//     daemon dengan socket permissive tanpa verifikasi peer = privilege
//     escalation). Koneksi HANYA diterima dari root (uid 0) ATAU dari
//     proses yang primary GID-nya 'ntpsenseweb' (PHP-FPM pool nanti).
//   - Action whitelist: TIDAK PERNAH menjalankan command bebas dari
//     request - hanya action yang terdaftar statis di match arm di bawah.
//
// CATATAN PENTING soal verifikasi build (baca sebelum modifikasi):
// Fungsi 'peer_uid_gid()' di bawah punya DUA implementasi lewat
// #[cfg(target_os = "freebsd")]: versi FreeBSD sungguhan (pakai
// LOCAL_PEERCRED via crate 'nix') dan versi fallback non-FreeBSD.
// SEBABNYA: 'std::os::unix::net::UnixStream::peer_cred()' bawaan Rust
// TERNYATA MASIH NIGHTLY-ONLY (belum pernah stabil sejak 2017, dicek
// langsung dari dokumentasi resmi doc.rust-lang.org saat menulis file
// ini) - jadi TIDAK BISA dipakai di stable Rust sama sekali. Alternatif
// yang benar adalah LocalPeerCred sockopt dari crate 'nix', TAPI sockopt
// itu di-gate '#[cfg(freebsdlike)]' oleh nix sendiri, sehingga TIDAK
// BISA di-compile-test di sandbox Linux manapun. Bagian FreeBSD di bawah
// SUDAH ditulis berdasarkan riset dokumentasi resmi nix+libc (struct
// xucred: cr_uid, cr_ngroups, cr_groups[]), TAPI BELUM pernah benar-benar
// di-'cargo build' di FreeBSD sungguhan - WAJIB jadi hal PERTAMA yang
// diverifikasi ('cargo build' lalu baca pesan error kalau ada nama
// method yang meleset dari dugaan) begitu file ini dipindah ke VM.
//
// Desain SENGAJA pakai std::thread (bukan tokio/async) - daemon ini
// low-throughput (dipanggil Web UI, bukan API publik), thread-per-koneksi
// jauh lebih mudah dipahami untuk yang baru belajar Rust.

mod security;
mod multiwan;
mod proxy;
mod openvpn;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Digest;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::thread;

const SOCKET_PATH: &str = "/var/run/ntpsense-configd.sock";
const MGMT_LOCK_FILE: &str = "/usr/local/etc/ntpsense/mgmt-interface.lock";
const ALLOWED_GROUP: &str = "ntpsenseweb";
const CUSTOM_RULES_FILE: &str = "/usr/local/etc/ntpsense/firewall-custom-rules.json";
const LIMITERS_FILE: &str = "/usr/local/etc/ntpsense/bandwidth-limiters.json";
const DNCTL_CONF: &str = "/etc/dnctl.conf";
const WATCHDOG_LOG: &str = "/var/log/ntpsense-watchdog.log";
// RCA (ditemukan dari feedback bro langsung - "Restart All Services"
// tidak ada info apa pun di console): restart_all_services() dan
// perform_factory_reset() sebelumnya cuma jalankan command shell
// dengan output TIDAK dibungkam TAPI JUGA TIDAK diarahkan ke log mana
// pun - kalau daemon jalan normal via rc.d di background (bukan
// interaktif SSH, kondisi produksi yang sesungguhnya), output itu
// hilang total, tidak kelihatan di mana pun termasuk System Log. Fix:
// log_maintenance_event() menulis tiap langkah eksplisit ke file ini,
// pola sama dengan log_event() di Multi-WAN/HA.
const MAINTENANCE_LOG: &str = "/var/log/ntpsense-maintenance.log";
const ALIAS_FILE: &str = "/usr/local/etc/ntpsense/interface-aliases.json";
const DESCRIPTION_FILE: &str = "/usr/local/etc/ntpsense/interface-descriptions.json";
const PORT_STATUS_FILE: &str = "/usr/local/etc/ntpsense/port-status.json";
const ROLE_FILE: &str = "/usr/local/etc/ntpsense/interface-roles.json";
const DHCP_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/dhcp-server-config.json";
// Permintaan user - fitur "Make Static" (pola FortiGate/pfSense/
// OPNsense: convert dynamic lease jadi reservation permanen langsung
// dari tabel Leases) - disimpan terpisah dari DHCP_CONFIG_FILE (yang
// itu untuk pengaturan range/DNS/dst per-interface, BUKAN daftar
// reservation per-host).
const DHCP_RESERVATIONS_FILE: &str = "/usr/local/etc/ntpsense/dhcp-reservations.json";
const KEA_DHCP4_CONF: &str = "/usr/local/etc/kea/kea-dhcp4.conf";
// Path CUSTOM (BUKAN default Kea 'kea-leases4.csv') - dikonfirmasi
// LANGSUNG dari kea-dhcp4.conf yang genuinely digenerate project ini
// ('lease-database.name') dan data live nyata di mini PC, bukan
// asumsi dari dokumentasi generik Kea.
const KEA_LEASE_FILE: &str = "/var/db/kea/dhcp4.leases";

#[derive(Debug, Clone, serde::Serialize)]
struct DhcpLeaseEntry {
    ip: String,
    mac: String,
    hostname: String,
    lease_start: String,
    lease_expire: String,
    active: bool,
}

/// Parse file lease Kea - format kolom terverifikasi dari data live
/// nyata: address,hwaddr,client_id,valid_lifetime,expire,subnet_id,
/// fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id.
///
/// RCA (dikonfirmasi dari cek langsung file live): ini file JOURNAL-
/// STYLE - setiap kali lease diperpanjang, Kea MENAMBAH baris baru
/// untuk IP yang SAMA (bukan update baris lama di tempat, demi
/// performa - lihat dokumentasi resmi Kea soal alasan lfc-interval).
/// Ambil baris TERAKHIR per IP unik (paling baru menang, konsisten
/// sifat append-only file ini). State '0' = default/valid (aktif,
/// dikonfirmasi dari dokumentasi resmi Kea) - state lain (1=declined,
/// 2=expired-reclaimed) di-skip dari tampilan, bukan lease genuinely
/// aktif.
fn get_dhcp_leases() -> Vec<DhcpLeaseEntry> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // RCA NYATA (ditemukan dari test end-to-end, dikonfirmasi log Kea
    // sendiri): mekanisme LFC (Lease File Cleanup) Kea me-ROTASI file
    // lease - 'dhcp4.leases' (aktif, BISA GENUINELY KOSONG sesaat
    // setelah restart) dan 'dhcp4.leases.2' (backup kompaksi
    // sebelumnya, BERISI data valid). '.leases.1' cuma ada SEMENTARA
    // selama kompaksi aktif berlangsung - baca juga kalau genuinely
    // ada. Baca SEMUA kandidat, gabung per IP ambil 'expire' PALING
    // BESAR (paling baru) - BUKAN asumsi "baris terakhir dibaca
    // menang" (itu cuma valid untuk SATU file, salah untuk gabungan
    // multi-file yang urutan baca-nya tidak mencerminkan urutan waktu
    // sebenarnya).
    let mut latest_by_ip: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for candidate in [KEA_LEASE_FILE, "/var/db/kea/dhcp4.leases.2", "/var/db/kea/dhcp4.leases.1"] {
        let Ok(content) = fs::read_to_string(candidate) else {
            continue;
        };
        for (i, line) in content.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let fields: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
            if fields.len() < 10 {
                continue;
            }
            let ip = fields[0].clone();
            let this_expire: i64 = fields.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            let existing_expire: i64 = latest_by_ip.get(&ip)
                .and_then(|f: &Vec<String>| f.get(4))
                .and_then(|s| s.parse().ok())
                .unwrap_or(-1);
            if this_expire >= existing_expire {
                latest_by_ip.insert(ip, fields);
            }
        }
    }

    let mut result: Vec<DhcpLeaseEntry> = latest_by_ip.into_iter().filter_map(|(ip, fields)| {
        let mac = fields.get(1)?.clone();
        let valid_lifetime: i64 = fields.get(3)?.parse().ok()?;
        let expire: i64 = fields.get(4)?.parse().ok()?;
        let hostname = fields.get(8).cloned().unwrap_or_default();
        let state: i32 = fields.get(9).and_then(|s| s.parse().ok()).unwrap_or(0);

        if state != 0 {
            return None;
        }

        let lease_start_ts = expire - valid_lifetime;
        let active = expire > now;

        Some(DhcpLeaseEntry {
            ip,
            mac,
            hostname: if hostname.is_empty() { "-".to_string() } else { hostname },
            lease_start: format_unix_timestamp(lease_start_ts),
            lease_expire: format_unix_timestamp(expire),
            active,
        })
    }).collect();

    result.sort_by(|a, b| {
        let a_parts: Vec<u16> = a.ip.split('.').filter_map(|s| s.parse().ok()).collect();
        let b_parts: Vec<u16> = b.ip.split('.').filter_map(|s| s.parse().ok()).collect();
        a_parts.cmp(&b_parts)
    });

    result
}
const WG_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/vpn-wireguard-config.json";
const WG_CONF_PATH: &str = "/usr/local/etc/wireguard/wg0.conf";
const WG_INTERFACE: &str = "wg0";
const HMAC_KEY_FILE: &str = "/usr/local/etc/ntpsense/hmac.key";
const BACKUP_DIR: &str = "/usr/local/etc/ntpsense/backups";
const PACKAGE_INSTALL_LOG: &str = "/var/log/ntpsense-package-install.log";
const PACKAGE_UNINSTALL_LOG: &str = "/var/log/ntpsense-package-uninstall.log";
const SSL_DIR: &str = "/usr/local/etc/ntpsense/ssl";
const SSL_CERT_PATH: &str = "/usr/local/etc/ntpsense/ssl/webui.crt";
const SSL_KEY_PATH: &str = "/usr/local/etc/ntpsense/ssl/webui.key";
const SSL_PEM_PATH: &str = "/usr/local/etc/ntpsense/ssl/webui.pem";
const SSL_BACKUP_DIR: &str = "/usr/local/etc/ntpsense/ssl/backup";
const VLAN_DATABASE_FILE: &str = "/usr/local/etc/ntpsense/vlan-database.json";

/// Daftar file yang dimasukkan ke backup - (path_sumber, nama_di_arsip).
/// Nama di arsip SENGAJA flat/basename (bukan path lengkap) - pola sama
/// dengan Tier 1: entri arsip yang TIDAK ADA di daftar ini otomatis
/// dicurigai sebagai indikasi Tar Slip saat restore (lihat
/// system.backup_restore). webui-admin.json IKUT disertakan (disepakati
/// dengan user setelah riset pola industri - Fortinet/pfSense KEDUANYA
/// menyertakan kredensial di backup, SELALU dalam bentuk hash/terenkripsi
/// bukan plaintext - konsisten dengan cara kita SUDAH simpan password
/// (password_hash/bcrypt), jadi menyertakannya tidak menambah risiko baru).
fn backup_file_list() -> Vec<(&'static str, &'static str)> {
    #[cfg_attr(not(feature = "pro"), allow(unused_mut))]
    let mut list = vec![
        (ALIAS_FILE, "interface-aliases.json"),
        (DESCRIPTION_FILE, "interface-descriptions.json"),
        (ROLE_FILE, "interface-roles.json"),
        (PORT_STATUS_FILE, "port-status.json"),
        (CUSTOM_RULES_FILE, "firewall-custom-rules.json"),
        (LIMITERS_FILE, "bandwidth-limiters.json"),
        (multiwan::GATEWAYS_FILE, "multiwan-gateways.json"),
        (multiwan::GATEWAY_GROUPS_FILE, "multiwan-groups.json"),
        (multiwan::SETTINGS_FILE, "multiwan-settings.json"),
        (DHCP_CONFIG_FILE, "dhcp-server-config.json"),
        (proxy::PROXY_CONFIG_FILE, "proxy-config.json"),
        (proxy::BLOCKLIST_CONFIG_FILE, "proxy-blocklist-config.json"),
        (proxy::ACL_CONFIG_FILE, "proxy-acl-config.json"),
        (proxy::AUTH_CONFIG_FILE, "proxy-auth-config.json"),
        (proxy::SQUID_PASSWD_FILE, "proxy-passwd"),
        // CATATAN: file ini BEDA dari file lain di daftar ini - berisi
        // PRIVATE KEY server WireGuard dalam bentuk PLAINTEXT (bukan
        // hash seperti webui-admin.json/proxy-passwd - WireGuard pakai
        // kriptografi asimetris, tidak ada "hash" untuk private key,
        // itu memang harus tetap utuh untuk dipakai). Pengecualian
        // SADAR: TIDAK menyertakannya akan membuat SEMUA config client
        // peer yang sudah dibagikan admin jadi tidak valid lagi setelah
        // restore (server dapat identitas baru, client masih rujuk ke
        // public key server yang lama) - risiko itu dinilai lebih besar
        // daripada risiko menyertakan private key di backup yang sudah
        // ditandatangani HMAC + izin file root:ntpsenseweb.
        (WG_CONFIG_FILE, "vpn-wireguard-config.json"),
        ("/usr/local/etc/ntpsense/webui/webui-admin.json", "webui-admin.json"),
        // GAP DITEMUKAN (bukan disengaja sejak awal) - ketiga file ini
        // ditambahkan SETELAH backup_file_list() terakhir di-update,
        // jadi tidak pernah ikut ter-backup sejak fitur-fitur itu
        // dibangun. Ditemukan sewaktu membangun Factory Reset (yang
        // butuh daftar file LEBIH lengkap), diperbaiki di sini sekarang
        // supaya backup dan restore benar-benar konsisten mencakup
        // semuanya, bukan cuma sebagian.
        (VLAN_DATABASE_FILE, "vlan-database.json"),
        (ZONE_GROUPS_FILE, "zone-groups.json"),
        // IPsec config JSON (Tier 2) - berisi PSK (pre-shared key) tunnel
        // dalam bentuk PLAINTEXT (sama alasannya dengan WireGuard private
        // key di atas - IPsec butuh PSK utuh untuk dipakai lagi, tidak
        // ada bentuk "hash" yang bisa dipakai ulang).
        (IPSEC_CONFIG_FILE, "vpn-ipsec-config.json"),
        (security::SURICATA_CONFIG_JSON, "security-config.json"),
        (proxy::ARCHIVE_SETTINGS_FILE, "proxy-archive-settings.json"),
        ("/etc/pf.conf", "pf.conf.reference"),
    ];
    list
}

/// Daftar file yang DIHAPUS TOTAL saat Factory Reset - BUKAN daftar
/// yang sama persis dengan backup_file_list() di atas (meski keduanya
/// TUMPANG TINDIH besar). Sewaktu membangun fitur ini, ditemukan GAP
/// NYATA di backup_file_list(): VLAN Database, IPsec config, dan
/// Suricata config sempat belum pernah ditambahkan ke situ (fitur-
/// fitur itu dibangun SETELAH daftar backup terakhir di-update) -
/// SUDAH DIPERBAIKI di backup_file_list() di atas (revisi berikutnya
/// setelah Factory Reset ini pertama dibangun) - dicatat di sini
/// sebagai jejak riwayat, bukan gap yang masih terbuka.
fn factory_reset_file_list() -> Vec<&'static str> {
    #[cfg_attr(not(feature = "pro"), allow(unused_mut))]
    let mut list = vec![
        ALIAS_FILE,
        DESCRIPTION_FILE,
        ROLE_FILE,
        PORT_STATUS_FILE,
        CUSTOM_RULES_FILE,
        LIMITERS_FILE,
        multiwan::GATEWAYS_FILE,
        multiwan::GATEWAY_GROUPS_FILE,
        multiwan::SETTINGS_FILE,
        DHCP_CONFIG_FILE,
        proxy::PROXY_CONFIG_FILE,
        proxy::BLOCKLIST_CONFIG_FILE,
        proxy::ACL_CONFIG_FILE,
        proxy::AUTH_CONFIG_FILE,
        proxy::SQUID_PASSWD_FILE,
        WG_CONFIG_FILE,
        "/usr/local/etc/ntpsense/webui/webui-admin.json",
        VLAN_DATABASE_FILE,
        ZONE_GROUPS_FILE,
        IPSEC_CONFIG_FILE,
        security::SURICATA_CONFIG_JSON,
        proxy::ARCHIVE_SETTINGS_FILE,
    ];
    list
}

/// Restart TANPA reboot OS - pola persis "Restart Service" Sangfor /
/// "reroot" pfSense (dikonfirmasi lewat riset eksplisit sebelum
/// membangun ini): semua proses layanan dimatikan-hidupkan ulang,
/// TANPA reload kernel/hardware detection. Reuse LANGSUNG logic
/// startup-reapply yang sudah teruji (bukan menduplikasi) - restart
/// service lalu panggil ulang seluruh unconditional-reapply yang sama
/// dengan yang jalan saat daemon pertama kali hidup.
/// Format Unix timestamp jadi "YYYY-MM-DD HH:MM:SS" - duplikasi SENGAJA
/// dari fungsi yang sama persis di multiwan.rs/ha.rs (bukan diimpor
/// lintas modul) - konsisten pola self-contained yang sudah dipegang
/// di seluruh project ini.
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

fn log_maintenance_event(message: &str) {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let line = format!("{} {message}\n", format_unix_ts(ts));
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(MAINTENANCE_LOG) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn restart_all_services() {
    log_maintenance_event("Restart All Services requested");
    // RCA (ditemukan dari test bro langsung - 500 Internal Server Error,
    // countdown JS tidak sempat terkirim): lighttpd/php_fpm TIDAK BOLEH
    // direstart secara SYNCHRONOUS di sini - request PHP yang SEDANG
    // memproses tombol "Restart All Services" ini SENDIRI dilayani oleh
    // lighttpd+php_fpm. Merestart proses yang sedang menjawab request
    // itu sendiri memutus koneksi di tengah jalan, sebelum halaman
    // (termasuk JS countdown-nya) sempat terkirim ke browser. Fix:
    // service LAIN (yang tidak melayani request ini) direstart
    // SYNCHRONOUS seperti biasa, tapi lighttpd/php_fpm DITUNDA lewat
    // thread terpisah - pola SAMA yang sudah terbukti benar untuk
    // reboot/factory-reset (beri waktu response PHP selesai terkirim
    // dulu, baru proses yang mengganggu koneksi itu sendiri dijalankan).
    for (svc, label) in [
        ("squid", "Proxy (Squid)"),
        ("kea", "DHCP (Kea)"),
        ("suricata", "IDS/IPS (Suricata)"),
        ("strongswan", "IPsec (strongSwan)"),
    ] {
        let status = Command::new("service").arg(svc).arg("restart").status();
        match status {
            Ok(s) if s.success() => log_maintenance_event(&format!("  {label}: restarted OK")),
            Ok(s) => log_maintenance_event(&format!("  {label}: restart returned non-zero exit ({s})")),
            Err(e) => log_maintenance_event(&format!("  {label}: FAILED to run restart command: {e}")),
        }
    }
    let pf_status = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    match pf_status {
        Ok(s) if s.success() => log_maintenance_event("  Firewall (pf.conf reload): OK"),
        Ok(s) => log_maintenance_event(&format!("  Firewall (pf.conf reload): returned non-zero exit ({s})")),
        Err(e) => log_maintenance_event(&format!("  Firewall (pf.conf reload): FAILED: {e}")),
    }
    // WireGuard tidak punya rc.d service konvensional (dikelola
    // ifconfig langsung) - destroy+recreate dari config tersimpan.
    let _ = Command::new("ifconfig").args(["wg0", "destroy"]).status();
    let wg_status = Command::new("service").arg("wireguard").arg("start").status();
    match wg_status {
        Ok(s) if s.success() => log_maintenance_event("  VPN (WireGuard): recreated OK"),
        Ok(s) => log_maintenance_event(&format!("  VPN (WireGuard): start returned non-zero exit ({s})")),
        Err(e) => log_maintenance_event(&format!("  VPN (WireGuard): FAILED to recreate: {e}")),
    }
    log_maintenance_event("Restart All Services (backend) completed - Web UI (lighttpd/php-fpm) restart deferred 3s");

    // Web UI restart - DITUNDA, dijalankan setelah response ke browser
    // (termasuk JS countdown) sudah pasti terkirim.
    thread::spawn(|| {
        thread::sleep(std::time::Duration::from_secs(3));
        for (svc, label) in [("lighttpd", "Web UI (lighttpd)"), ("php_fpm", "Web UI (php-fpm)")] {
            let status = Command::new("service").arg(svc).arg("restart").status();
            match status {
                Ok(s) if s.success() => log_maintenance_event(&format!("  {label}: restarted OK (deferred)")),
                Ok(s) => log_maintenance_event(&format!("  {label}: restart returned non-zero exit ({s}) (deferred)")),
                Err(e) => log_maintenance_event(&format!("  {label}: FAILED to run restart command: {e} (deferred)")),
            }
        }
        log_maintenance_event("Restart All Services (Web UI) completed");
    });
}

/// Reset TOTAL ke kondisi baru instalasi - level yang SAMA dengan
/// `private-data-reset` Palo Alto (dikonfirmasi lewat riset: remote-
/// capable, TIDAK menyentuh OS/binary/package terinstall, cuma
/// menghapus config+data - beda dari full factory reset yang perlu
/// akses console/Maintenance Mode di semua 4 vendor rujukan). Selalu
/// diakhiri reboot otomatis (pola universal FortiGate/pfSense/Palo
/// Alto/Sangfor - tidak ada satu pun vendor yang factory-reset TANPA
/// reboot setelahnya).
fn perform_factory_reset() -> Result<(), String> {
    log_maintenance_event("Factory Reset requested (confirm_text matched)");

    // 1. Matikan service yang bergantung config SEBELUM file-nya
    // dihapus - mencegah service jalan dengan config setengah-hapus.
    for svc in ["squid", "kea", "suricata", "strongswan"] {
        let status = Command::new("service").arg(svc).arg("stop").status();
        log_maintenance_event(&format!("  stop {svc}: {}", status.map(|s| s.to_string()).unwrap_or_else(|e| format!("FAILED: {e}"))));
    }
    let _ = Command::new("ifconfig").args(["wg0", "destroy"]).status();
    log_maintenance_event("  wg0 destroyed");
    for key in ["squid_enable", "kea_enable", "suricata_enable", "strongswan_enable", "wireguard_enable"] {
        let _ = Command::new("sysrc").arg(format!("{key}=NO")).status();
    }
    let _ = Command::new("sysrc").arg("-x").arg("wireguard_interfaces").status();
    let _ = Command::new("sysrc").arg("-x").arg("cloned_interfaces").status();
    log_maintenance_event("  service auto-start flags cleared (squid/kea/suricata/strongswan/wireguard)");

    // 2. Hapus semua file config milik NTPSense sendiri.
    let mut removed_count = 0;
    for path in factory_reset_file_list() {
        if fs::remove_file(path).is_ok() {
            removed_count += 1;
        }
    }
    log_maintenance_event(&format!("  {removed_count}/{} NTPSense config file(s) removed", factory_reset_file_list().len()));
    // File config service yang DIGENERATE dari JSON di atas - dihapus
    // juga supaya tidak ada sisa config lama yang stale kalau service
    // dinyalakan manual lagi sebelum dikonfigurasi ulang dari awal.
    for path in [KEA_DHCP4_CONF, WG_CONF_PATH, SWANCTL_CONF_PATH] {
        let _ = fs::remove_file(path);
    }
    log_maintenance_event("  generated service config files (Kea/WireGuard/IPsec) cleared");

    // Arsip historis Proxy (Log Viewer + Bandwidth Usage) - DIREKTORI
    // berisi banyak file bertanggal (bulanan/6-bulanan), TIDAK bisa
    // masuk factory_reset_file_list() flat (itu daftar FILE, bukan
    // direktori) - dibersihkan eksplisit di sini via remove_dir_all.
    // Data historis genuinely termasuk "state yang terakumulasi",
    // sama filosofinya dengan file config lain yang di-reset - factory
    // reset yang cuma bersihkan setting retensi tapi bukan datanya
    // sendiri akan terasa setengah-selesai.
    let _ = fs::remove_dir_all(proxy::LOG_ARCHIVE_DIR);
    let _ = fs::remove_dir_all(proxy::BANDWIDTH_ARCHIVE_DIR);
    log_maintenance_event("  Proxy history archive (Log Viewer + Bandwidth Usage) cleared");

    // 3. Reset pf.conf - custom rules per interface kembali ke baseline
    // (reuse fungsi regenerate yang SAMA dipakai jalur normal, dengan
    // daftar rule KOSONG - bukan menduplikasi logic pf.conf generation).
    let (mgmt_if, lan1_if, opt_ifaces) = parse_pf_conf_zones();
    let wan1_if = get_wan1_interface();
    let mut all_ifaces: Vec<String> = Vec::new();
    all_ifaces.extend(mgmt_if);
    all_ifaces.extend(lan1_if);
    all_ifaces.extend(wan1_if);
    all_ifaces.extend(opt_ifaces);
    for iface in &all_ifaces {
        let _ = regenerate_pf_conf_for_interface(iface, &[]);
    }
    // Blok marker NAT Multi-WAN dan HA - panggil ulang fungsi
    // regenerate resminya (bukan tulis manual) - karena file JSON
    // sumbernya sudah dihapus di langkah 2, hasilnya otomatis blok
    // kosong (tidak ada gateway/VIP tersisa untuk di-generate).
    let _ = multiwan::regenerate_outbound_nat();
    log_maintenance_event(&format!("  pf.conf reset to baseline for {} interface(s)", all_ifaces.len()));

    // 4. Log event terakhir SEBELUM reboot - satu-satunya jejak bahwa
    // reset ini pernah terjadi, ditulis ke syslog (bukan log NTPSense
    // sendiri yang baru saja ikut ter-reset) supaya tetap tertelusuri.
    // MAINTENANCE_LOG sendiri TIDAK ikut terhapus (path-nya /var/log/,
    // bukan /usr/local/etc/ntpsense/ yang masuk factory_reset_file_list())
    // - jejak reset ini tetap ada setelah reboot untuk ditinjau lewat
    // System Logs.
    let _ = Command::new("logger").args(["-t", "ntpsense-configd", "Factory reset performed - rebooting"]).status();
    log_maintenance_event("Factory Reset completed - rebooting in 3 seconds");

    // 5. Reboot otomatis - DITUNDA beberapa detik lewat thread terpisah
    // supaya response sukses ke Web UI sempat terkirim dulu sebelum
    // koneksi terputus (pola sama dengan universal semua vendor rujukan:
    // factory reset SELALU diakhiri reboot, bukan opsional).
    thread::spawn(|| {
        thread::sleep(std::time::Duration::from_secs(3));
        let _ = Command::new("shutdown").args(["-r", "now"]).status();
    });

    Ok(())
}


// Version stamp - pola SAMA seperti SCRIPT_VERSION di install-gateway-v2.sh,
// yang terbukti sangat membantu diagnosa dari screenshot/log saja. Ditulis
// ke file /var/run/ntpsense-configd.version SETIAP startup (lihat main())
// supaya bisa diverifikasi INSTAN lewat 'cat', tanpa perlu menebak dari
// perilaku error action (yang gampang salah tafsir kalau binary basi).
const VERSION: &str = "0.1.0-r2-firewall-phase2";

/// Rule custom - skema diperluas menambahkan 'source' (align dengan
/// kolom Source pfSense) - #[serde(default)] supaya rule LAMA yang
/// tersimpan tanpa field ini (dari sebelum fitur ini ada) tetap bisa
/// di-deserialize tanpa error, otomatis default ke "any".
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomRule {
    id: String,
    interface: String,
    action: String,      // "pass" | "block"
    // Direction eksplisit - permintaan bro setelah RCA nyata (client
    // pfSense gagal ping ke client LAN1 asli, karena traffic forwarded
    // dari tunnel butuh KELUAR lewat em1, bukan cuma masuk). Default
    // "in" untuk backward-compat penuh - SEMUA rule yang sudah
    // tersimpan sebelum field ini ada akan tetap berperilaku PERSIS
    // sama seperti sebelumnya (single 'in' line), tidak ada perubahan
    // diam-diam. Admin yang eksplisit pilih "out" atau "both" untuk
    // skenario forwarding (VPN tunnel, dst).
    #[serde(default = "default_direction_in")]
    direction: String, // "in" | "out" | "both"
    protocol: String,    // "any" | "tcp" | "udp" | "icmp"
    #[serde(default = "default_any")]
    source: String,      // "any" | CIDR
    destination: String, // "any" | CIDR
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default)]
    description: String,
    // NAT (Fase sekarang, Port Forward tab) - reuses the existing custom
    // rule CRUD/storage/pf.conf-splice infrastructure (already validated
    // 12/12 end-to-end) instead of a parallel system. Only meaningful when
    // both are Some: turns this rule into a combined pf nat+filter line
    // ("... rdr-to <ip> port <port>") rather than a plain pass/block line.
    // #[serde(default)] mandatory here too (Doc 7 §1.3 convention) - rules
    // saved before this field existed must keep deserializing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nat_redirect_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nat_redirect_port: Option<u16>,
    // Bandwidth Limiter (QoS) - riset FreeBSD 14+ pf+dummynet ("dnpipe")
    // + pola pfSense Limiters (stack IDENTIK: pf+dummynet, bukan ALTQ -
    // ALTQ dicoret karena tidak kompatibel driver NIC modern/iflib).
    // Referensi ke nama BandwidthLimiter, BUKAN duplikasi nilai
    // bandwidth di sini - satu limiter bisa dipakai banyak rule
    // sekaligus (sama filosofinya dengan Role di RBAC: objek bernama
    // reusable, bukan nilai mentah diulang-ulang di tiap tempat pakai).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limiter_name: Option<String>,
    // Multi-WAN policy routing - referensi ke nama GatewayGroup (bukan
    // duplikasi gateway_ip di sini, pola sama dengan limiter_name di
    // atas: objek bernama reusable). Kalau Some, generate_rule_line()
    // menyisipkan klausa 'route-to' berdasarkan anggota tier AKTIF grup
    // itu SAAT config di-regenerate - lihat multiwan::compute_route_to_clause().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_group_name: Option<String>,
    // Zone Groups (model additive pfSense - lihat blok komentar besar
    // dekat effective_rules_for_interface()). 'interface' di atas TETAP
    // diisi (nama grup, untuk tampilan) kalau field ini Some - keputusan
    // routing pf.conf sesungguhnya lewat field INI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zone_group: Option<String>,
    // Integrasi App Control (riset FortiGate - "Profile-based" model,
    // model KLASIK yang direkomendasikan untuk kebanyakan environment:
    // Application Control dikonfigurasi sebagai profile terpisah lalu
    // DITEMPELKAN ke firewall policy, BUKAN daftar aplikasi ditulis
    // ulang di tiap rule). Referensi by-name ke App Group yang sudah
    // Toggle Enable/Disable per-rule (roadmap item #1) - default true
    // via serde supaya rule LAMA yang sudah tersimpan (dari sebelum
    // field ini ada) otomatis dianggap enabled=true saat di-load,
    // BUKAN diam-diam jadi disabled - mencegah semua rule existing
    // tiba-tiba berhenti berlaku begitu field baru ini di-deploy.
    #[serde(default = "default_rule_enabled")]
    enabled: bool,
    // Floating Rule (roadmap item - "kemenangan cepat" setelah OpenVPN
    // selesai) - berlaku di SEMUA zona sekaligus (tanpa klausa 'on
    // <interface>' di pf sama sekali), bukan diwariskan per-member
    // seperti Zone Group (yang MATERIALIZE ke tiap interface anggota
    // secara terpisah). Kalau true, field 'interface' di atas TIDAK
    // dipakai untuk keputusan routing pf sama sekali (cuma nilai
    // placeholder buat kompatibilitas struct) - satu baris rule global
    // ditulis SEKALI ke marker khusus, bukan diduplikasi ke banyak
    // marker interface. default false via serde - rule lama yang
    // sudah tersimpan sebelum field ini ada tetap perilaku persis
    // sama (scoped ke interface aslinya).
    #[serde(default)]
    floating: bool,
}

fn default_rule_enabled() -> bool {
    true
}

fn default_any() -> String {
    "any".to_string()
}

fn default_direction_in() -> String {
    "in".to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CustomRulesFile {
    #[serde(default)]
    rules: Vec<CustomRule>,
}

/// Bandwidth Limiter - objek bernama reusable (pola sama dengan Role di
/// RBAC), disimpan TERPISAH dari CustomRule itu sendiri. Dua pipe ID
/// dummynet dialokasikan PERMANEN saat dibuat (bukan dihitung ulang
/// tiap kali generate config - supaya nomor pipe stabil di
/// /etc/dnctl.conf antar restart daemon, dan tidak collision dengan
/// limiter lain yang sudah ada).
/// State "sudah dibaca" per sumber alert - permintaan bro langsung:
/// begitu admin buka halaman tujuan alert (Watchdog log, Security
/// Alerts, Certificates), badge lonceng untuk sumber itu harus hilang
/// untuk kejadian yang SUDAH ada, dan cuma muncul lagi kalau ada
/// kejadian BARU setelah itu. Perbandingan "baru" dilakukan via string
/// comparison timestamp (BUKAN parsing tanggal ke tipe waktu asli) -
/// aman karena format timestamp watchdog log ("YYYY-MM-DD HH:MM:SS")
/// dan eve.json Suricata (ISO8601) keduanya SUDAH terbukti sortable
/// sebagai string biasa (lihat parse_eve_alerts() yang sudah pakai
/// `b.timestamp.cmp(&a.timestamp)` - pola yang sama, bukan diciptakan
/// baru di sini) - menghindari kebutuhan crate date/time tambahan.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AlertsAckState {
    #[serde(default)]
    watchdog_ack_ts: String,
    #[serde(default)]
    security_ack_ts: String,
    #[serde(default)]
    certificate_ack_key: String,
    #[serde(default)]
    multiwan_ack_key: String,
    // Atribusi (roadmap - halaman Alerts penuh) - SIAPA yang meng-ack
    // dan KAPAN, per sumber. Pendekatan pragmatis: granularitas per-
    // SUMBER (bukan per-baris-individual dengan ID unik masing-masing)
    // - satu baris log/alert dianggap "acknowledged" kalau timestamp-nya
    // <= watermark ack sumber itu, dan atribusi yang ditampilkan adalah
    // SIAPA yang terakhir kali meng-ack sumber itu. Ini pendekatan yang
    // jujur ("kategori ini dibersihkan oleh X pada waktu Y") tanpa
    // perlu skema ID unik per-alert yang jauh lebih besar scope-nya.
    #[serde(default)]
    watchdog_ack_by: Option<String>,
    #[serde(default)]
    watchdog_ack_at: Option<u64>,
    #[serde(default)]
    security_ack_by: Option<String>,
    #[serde(default)]
    security_ack_at: Option<u64>,
    #[serde(default)]
    certificate_ack_by: Option<String>,
    #[serde(default)]
    certificate_ack_at: Option<u64>,
    #[serde(default)]
    multiwan_ack_by: Option<String>,
    #[serde(default)]
    multiwan_ack_at: Option<u64>,
    // Perluasan monitoring (roadmap - riset FortiGate: daemon crash,
    // resource usage, VPN tunnel semua kategori alert standar
    // industri). Pola SAMA persis dengan certificate/multiwan di atas
    // - "kondisi saat ini", bukan daftar event historis.
    #[serde(default)]
    resource_ack_key: String,
    #[serde(default)]
    resource_ack_by: Option<String>,
    #[serde(default)]
    resource_ack_at: Option<u64>,
    #[serde(default)]
    vpn_ack_key: String,
    #[serde(default)]
    vpn_ack_by: Option<String>,
    #[serde(default)]
    vpn_ack_at: Option<u64>,
}

const ALERTS_ACK_FILE: &str = "/usr/local/etc/ntpsense/webui/alerts-ack.json";

fn load_alerts_ack() -> AlertsAckState {
    let mut data: AlertsAckState = fs::read_to_string(ALERTS_ACK_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    // Self-healing - kalau watchdog_ack_ts yang TERSIMPAN dari
    // sebelum fix ini sudah kadung rusak (bukan pola timestamp valid),
    // reset ke string kosong daripada dibiarkan macet permanen
    // membandingkan terhadap nilai sampah selamanya.
    if !data.watchdog_ack_ts.is_empty() && !is_watchdog_timestamp_line(&data.watchdog_ack_ts) {
        data.watchdog_ack_ts = String::new();
    }
    data
}

fn save_alerts_ack(data: &AlertsAckState) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(ALERTS_ACK_FILE, json).map_err(|e| e.to_string())
}

/// RCA nyata (ditemukan bro langsung - alert watchdog "tidak pernah
/// berhenti" meski sudah di-acknowledge berkali-kali): watchdog.log
/// TERNYATA juga memuat baris stdout/stderr APA ADANYA dari subprocess
/// yang dijalankannya (mis. output asli rc.d: "/etc/rc.d/ntpd: WARNING:
/// failed to start ntpd") - baris itu JUGA mengandung substring
/// "WARNING:", tapi 19 karakter pertamanya BUKAN timestamp
/// "YYYY-MM-DD HH:MM:SS" macam baris watchdog SENDIRI. Filter lama
/// (`contains("WARNING:")` doang) kadang menangkap baris SALAH ini,
/// men-set watchdog_ack_ts ke potongan teks acak - yang lebih kecil
/// secara alfabetis dari SEMUA timestamp asli, jadi HASIL PERBANDINGAN
/// > SELALU true untuk baris manapun berikutnya, tidak peduli berapa
/// kali di-acknowledge. Fix: validasi 19 karakter pertama benar-benar
/// berpola tanggal SEBELUM baris itu dianggap kandidat "timestamp
/// terakhir" - dipakai KONSISTEN di titik hitung (alerts_summary) MAUPUN
/// titik acknowledge (alerts_acknowledge), supaya keduanya selalu
/// sepakat baris mana yang valid.
fn is_watchdog_timestamp_line(line: &str) -> bool {
    let Some(prefix) = line.get(0..19) else { return false };
    let bytes = prefix.as_bytes();
    // Pola: DDDD-DD-DD DD:DD:DD (posisi digit vs pemisah tetap)
    let digit_positions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let separator_positions: [(usize, u8); 5] = [(4, b'-'), (7, b'-'), (10, b' '), (13, b':'), (16, b':')];
    for &pos in &digit_positions {
        if !bytes.get(pos).map(u8::is_ascii_digit).unwrap_or(false) {
            return false;
        }
    }
    for &(pos, expected) in &separator_positions {
        if bytes.get(pos) != Some(&expected) {
            return false;
        }
    }
    true
}

// ============================================================
// Perluasan monitoring alert (roadmap - riset FortiGate: daemon
// crash, HA event, resource usage, VPN tunnel down semua kategori
// alert standar industri). Tiga fungsi di bawah SATU-SATUNYA sumber
// kebenaran dipakai bersama oleh alerts_summary, alerts_list, DAN
// alerts_acknowledge - supaya ketiganya selalu sepakat kondisi
// "sekarang" yang persis sama, tidak ada logic ganda yang bisa
// berbeda hasil.
// ============================================================

/// (severity, message, current_key) - None kalau tidak ada masalah
/// sama sekali saat ini. current_key dipakai sebagai watermark ack
/// (pola sama dengan certificate_ack_key/multiwan_ack_key).
fn check_resource_alert() -> Option<(&'static str, String, String)> {
    let mut problems: Vec<String> = Vec::new();
    let mut worst_severity = "warning";

    // Disk - SEMUA filesystem lokal (bukan cuma root) - riset internal
    // (df -h project ini sendiri) menunjukkan /var bisa jadi PALING
    // penuh secara persentase (log + cache Squid), bukan cuma /.
    if let Ok(output) = Command::new("df").arg("-k").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let mount = fields[5];
            if !mount.starts_with('/') || fields[0] == "devfs" {
                continue;
            }
            let pct_str = fields[4].trim_end_matches('%');
            let Ok(pct) = pct_str.parse::<u32>() else { continue };
            if pct >= 95 {
                problems.push(format!("{mount} disk usage at {pct}%"));
                worst_severity = "critical";
            } else if pct >= 85 {
                problems.push(format!("{mount} disk usage at {pct}%"));
                if worst_severity != "critical" {
                    worst_severity = "warning";
                }
            }
        }
    }

    // Swap - ambang lebih ketat + jadi CRITICAL lebih cepat, sesuai
    // insiden nyata yang mendasari watchdog.sh sendiri ("19 Juli 2026,
    // VM kehabisan RAM+swap sekaligus, kernel OOM-kill Suricata/Squid/
    // php-fpm") - tujuannya memberi PERINGATAN DINI sebelum kejadian
    // itu terulang, bukan cuma mendeteksi setelah proses sudah mati
    // (itu peran watchdog.sh sendiri).
    if let Ok(output) = Command::new("swapinfo").arg("-k").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = text.lines().nth(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 {
                let pct_str = fields[4].trim_end_matches('%');
                if let Ok(pct) = pct_str.parse::<u32>() {
                    if pct >= 80 {
                        problems.push(format!("swap usage at {pct}% - the exact precondition that caused a real OOM-kill incident on this project before"));
                        worst_severity = "critical";
                    } else if pct >= 50 {
                        problems.push(format!("swap usage at {pct}%"));
                        if worst_severity != "critical" {
                            worst_severity = "warning";
                        }
                    }
                }
            }
        }
    }

    if problems.is_empty() {
        return None;
    }
    let message = problems.join("; ");
    let key = format!("{worst_severity}:{message}");
    Some((worst_severity, message, key))
}


fn check_vpn_alert() -> Option<(&'static str, String, String)> {
    let mut down: Vec<String> = Vec::new();

    let ipsec_cfg = load_ipsec_config();
    let ipsec_status = get_ipsec_tunnel_status();
    for conn in ipsec_cfg.tunnels.iter().filter(|c| c.enabled) {
        let established = ipsec_status.get(&conn.name).copied().unwrap_or(false);
        if !established {
            down.push(format!("IPsec '{}'", conn.name));
        }
    }

    let wg_cfg = load_wg_config();
    let enabled_peers: Vec<&WireguardPeer> = wg_cfg.peers.iter().filter(|p| p.enabled).collect();
    if wg_cfg.enabled && !enabled_peers.is_empty() {
        let mut handshake_by_pubkey: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        if let Ok(output) = Command::new("/usr/local/bin/wg").arg("show").arg(WG_INTERFACE).arg("dump").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for (i, line) in text.lines().enumerate() {
                    if i == 0 {
                        continue;
                    }
                    let fields: Vec<&str> = line.split('\t').collect();
                    if fields.len() < 5 {
                        continue;
                    }
                    let latest: u64 = fields[4].parse().unwrap_or(0);
                    handshake_by_pubkey.insert(fields[0].to_string(), latest);
                }
            }
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        for peer in &enabled_peers {
            let latest = handshake_by_pubkey.get(&peer.public_key).copied().unwrap_or(0);
            let connected = latest > 0 && now.saturating_sub(latest) < 180;
            if !connected {
                down.push(format!("WireGuard peer '{}'", peer.name));
            }
        }
    }

    if down.is_empty() {
        return None;
    }
    let message = format!("VPN tunnel(s) down or never connected: {}", down.join(", "));
    let key = down.join(",");
    Some(("warning", message, key))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BandwidthLimiter {
    name: String,
    download_mbps: f64,
    upload_mbps: f64,
    download_pipe_id: u32,
    upload_pipe_id: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LimitersFile {
    #[serde(default)]
    limiters: Vec<BandwidthLimiter>,
}

/// VLAN Database - katalog ID+Name MURNI, terpisah dari interface
/// aktual (vlan(4) pseudo-interface) yang mengikatnya ke parent - pola
/// ini SENGAJA meniru pemisahan Cisco "VLAN Database" (`vlan 10` +
/// `name dosen`, tanpa port apa pun) vs "SVI" (`interface vlan10` +
/// `ip address ...`, langkah terpisah) setelah bro tunjukkan ini
/// membingungkan kalau digabung jadi satu langkah saja. Entry di sini
/// BOLEH ada tanpa satu pun vlan(4) interface yang memakainya (persis
/// seperti Cisco - VLAN bisa didefinisikan duluan sebelum ada port
/// yang di-assign ke situ).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VlanDbEntry {
    id: u16,
    name: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VlanDatabaseFile {
    #[serde(default)]
    vlans: Vec<VlanDbEntry>,
}

fn load_vlan_database() -> VlanDatabaseFile {
    fs::read_to_string(VLAN_DATABASE_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_vlan_database(data: &VlanDatabaseFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(VLAN_DATABASE_FILE, json).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct Request {
    request_id: String,
    action: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct Response {
    request_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

impl Response {
    fn ok(request_id: String, data: serde_json::Value) -> Self {
        Response { request_id, status: "ok".to_string(), data: Some(data), error: None }
    }
    fn error(request_id: String, code: &str, message: &str) -> Self {
        Response {
            request_id,
            status: "error".to_string(),
            data: None,
            error: Some(ErrorBody { code: code.to_string(), message: message.to_string() }),
        }
    }
}

/// (uid, gid) dari peer yang connect ke socket. Return None kalau gagal
/// dibaca sama sekali - dipakai untuk fail-closed (tolak koneksi), BUKAN
/// fail-open, kalau credential tidak bisa diverifikasi.
/// (uid, daftar SEMUA gid termasuk supplementary groups) dari peer yang
/// connect ke socket. RCA: versi sebelumnya cuma ambil groups().first()
/// (GID PRIMARY saja) - tapi 'pw groupmod ntpsenseweb -m www' menambahkan
/// www sebagai anggota SUPPLEMENTARY (bukan mengubah primary group-nya),
/// sehingga GID ntpsenseweb muncul di posisi lain dalam daftar, bukan
/// pertama. Cek harus mencakup SELURUH daftar groups(), bukan cuma index
/// pertama - kalau tidak, keanggotaan grup 'ntpsenseweb' tidak pernah
/// terdeteksi walau 'pw groupmod' sudah benar dijalankan.
#[cfg(target_os = "freebsd")]
fn peer_uid_groups(stream: &UnixStream) -> Option<(u32, Vec<u32>)> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    let cred = getsockopt(stream, LocalPeerCred).ok()?;
    let uid = cred.uid();
    let groups = cred.groups().to_vec();
    Some((uid, groups))
}

#[cfg(not(target_os = "freebsd"))]
fn peer_uid_groups(_stream: &UnixStream) -> Option<(u32, Vec<u32>)> {
    eprintln!("PERINGATAN: peer credential check TIDAK didukung di platform ini (bukan FreeBSD) - koneksi ditolak by design");
    None
}

/// Cari GID grup 'ntpsenseweb' - pakai nix::unistd::Group di FreeBSD
/// (API bersih, tidak perlu shell out ke command eksternal).
#[cfg(target_os = "freebsd")]
fn resolve_group_gid(group_name: &str) -> Option<u32> {
    use nix::unistd::Group;
    Group::from_name(group_name).ok().flatten().map(|g| g.gid.as_raw())
}

#[cfg(not(target_os = "freebsd"))]
fn resolve_group_gid(_group_name: &str) -> Option<u32> {
    None
}

/// Verifikasi identitas peer - LAPIS PERTAHANAN KEDUA setelah permission
/// file socket (0660 root:ntpsenseweb). Kedua lapis WAJIB ada bersamaan
/// (defense in depth) - permission file saja tidak cukup (lihat catatan
/// CVE Lima/QEMU di komentar atas file).
fn is_peer_authorized(stream: &UnixStream, allowed_gid: Option<u32>) -> bool {
    match peer_uid_groups(stream) {
        Some((uid, groups)) => {
            if uid == 0 {
                return true;
            }
            if let Some(g) = allowed_gid {
                if groups.contains(&g) {
                    return true;
                }
            }
            eprintln!("PENOLAKAN: peer uid={uid} groups={groups:?} tidak diizinkan (bukan root, bukan anggota grup {ALLOWED_GROUP})");
            false
        }
        None => {
            eprintln!("GAGAL membaca peer credential - koneksi ditolak (fail-closed, bukan fail-open)");
            false
        }
    }
}

/// Action whitelist - TITIK PALING KRUSIAL di seluruh daemon ini. Setiap
/// action baru HARUS ditambahkan eksplisit di sini sebagai match arm -
/// TIDAK ADA jalur untuk menjalankan command bebas dari request manapun.
/// Ambil IP address live sebuah interface lewat 'ifconfig <if>' - dipakai
/// untuk network.zones supaya data yang ditampilkan Web UI selalu live
/// (bukan snapshot beku dari waktu instalasi).
fn get_interface_ip(iface: &str) -> Option<String> {
    let output = Command::new("ifconfig").arg(iface).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            return rest.split_whitespace().next().map(|s| s.to_string());
        }
    }
    None
}

/// Baca mode konfigurasi PERSISTEN sebuah interface dari rc.conf
/// ('ifconfig_<if>') - "dhcp" kalau nilainya persis "DHCP" (konvensi
/// FreeBSD, case-sensitive), selain itu "static". Dipakai
/// network.zones supaya Web UI tahu kapan harus grey-out DHCP Server
/// (tidak masuk akal menyajikan DHCP Server untuk subnet yang dinamis
/// dari DHCP client upstream).
fn get_interface_config_mode(iface: &str) -> &'static str {
    let output = Command::new("sysrc").args(["-n", &format!("ifconfig_{iface}")]).output().ok();
    let value = output.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    if value == "DHCP" {
        "dhcp"
    } else {
        "static"
    }
}

/// Deteksi status LINK FISIK (kabel terhubung atau tidak) via baris
/// 'status: active'/'status: no carrier' pada output ifconfig - dikonfirmasi
/// dari FreeBSD Handbook resmi: "status: no carrier status is normal when
/// an Ethernet cable is not plugged into the interface." INI TERPISAH dari
/// ada/tidaknya IP - interface bisa punya IP tapi kabelnya baru saja
/// dicabut (IP masih "menempel" sampai reconfigure), makanya perlu deteksi
/// eksplisit bukan cuma inferensi dari ip.is_some(). Return None kalau
/// baris 'status:' tidak ditemukan sama sekali (jarang - beberapa driver
/// tidak melaporkan status link).
fn get_interface_link_status(iface: &str) -> Option<bool> {
    let output = Command::new("ifconfig").arg(iface).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("status: ") {
            return Some(rest.trim() == "active");
        }
    }
    None
}

/// Ambil IP + netmask (format CIDR "X.X.X.X/YY") sebuah interface live
/// via 'ifconfig' - dipakai Fase B untuk tahu subnet SAAT INI sebelum
/// diganti (baik untuk validasi collision maupun untuk tahu apa yang
/// perlu di-scan di custom rule). FreeBSD ifconfig cetak netmask dalam
/// hex ('netmask 0xffffff00'), perlu dikonversi ke panjang prefix.
fn get_interface_cidr(iface: &str) -> Option<String> {
    let output = Command::new("ifconfig").arg(iface).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            let mut parts = rest.split_whitespace();
            let ip = parts.next()?;
            // format: 'inet X.X.X.X netmask 0xYYYYYYYY broadcast ...'
            let mut prefix: Option<u8> = None;
            let mut iter = parts;
            while let Some(tok) = iter.next() {
                if tok == "netmask" {
                    let hex = iter.next()?;
                    prefix = netmask_hex_to_prefix(hex);
                    break;
                }
            }
            return Some(format!("{}/{}", ip, prefix.unwrap_or(24)));
        }
    }
    None
}

fn netmask_hex_to_prefix(hex: &str) -> Option<u8> {
    let hex = hex.strip_prefix("0x")?;
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(value.count_ones() as u8)
}

/// Sama seperti retry Kea (RCA di system.cert_regenerate/upload
/// ditemukan bareng bro - 'service lighttpd restart' balik sukses cuma
/// berarti rc.d SUDAH SPAWN proses barunya, PID lama belum tentu benar-
/// benar mati dan proses baru belum tentu selesai bind ke port 443 pada
/// saat status check dipanggil TANPA jeda. Retry pendek 5x/500ms
/// (maks 2.5 detik) - sama persis pola yang sudah terbukti di Kea.
fn wait_for_lighttpd_running() -> bool {
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let status_output = Command::new("service").arg("lighttpd").arg("status").output();
        let running = match &status_output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("is running"),
            Err(_) => false,
        };
        if running {
            return true;
        }
    }
    false
}

/// Ambil HANYA prefix length (mis. 24, 30, 32) dari sebuah interface -
/// dipakai network.zones supaya Web UI (tabel Network zones DAN form
/// Manage Interface) bisa menampilkan/prefill prefix yang SUNGGUHAN
/// sedang aktif, bukan nilai hardcode "24" yang menyesatkan admin
/// (RCA nyata: admin ganti ke /30, backend sukses apply, tapi field
/// prefix di form tetap menunjukkan "24" setelah update - form dan
/// tabel sama sekali tidak pernah membaca prefix live).
fn get_interface_prefix(iface: &str) -> Option<u8> {
    let cidr = get_interface_cidr(iface)?;
    cidr.rsplit('/').next()?.parse::<u8>().ok()
}

fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

fn ipv4_to_u32(ip: [u8; 4]) -> u32 {
    ((ip[0] as u32) << 24) | ((ip[1] as u32) << 16) | ((ip[2] as u32) << 8) | (ip[3] as u32)
}

/// Parse "X.X.X.X/YY" jadi (network_addr_u32, prefix_len).
fn parse_cidr(cidr: &str) -> Option<(u32, u8)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip = ipv4_to_u32(parse_ipv4(ip_str)?);
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((ip & mask, prefix))
}

/// Ubah "IP host/prefix" (mis. "10.252.1.1/24", dari get_interface_cidr()
/// yang memang sengaja pakai IP interface sendiri) jadi "alamat
/// network/prefix" murni (mis. "10.252.1.0/24") - WAJIB dipakai setiap
/// kali kita MENULIS deklarasi subnet ke config EKSTERNAL (acl localnet
/// Squid, subnet4.subnet Kea) - ditemukan dari warning nyata Squid:
/// "Netmask masks away part of the specified IP" kalau host-bit tidak
/// di-nol-kan dulu. TIDAK dipakai untuk validasi/overlap-check
/// (cidr_overlaps sudah mask sendiri secara internal) atau tampilan IP
/// interface di halaman Network (di situ IP host memang yang ingin
/// ditampilkan, bukan alamat network).
fn normalize_network_cidr(cidr: &str) -> Option<String> {
    let (network_addr, prefix) = parse_cidr(cidr)?;
    let a = (network_addr >> 24) as u8;
    let b = (network_addr >> 16) as u8;
    let c = (network_addr >> 8) as u8;
    let d = network_addr as u8;
    Some(format!("{a}.{b}.{c}.{d}/{prefix}"))
}

/// Cek apakah dua CIDR TUMPANG TINDIH (overlap) - dipakai validasi Fase B
/// supaya subnet baru tidak bentrok dengan zona lain yang sudah ada
/// (MGMT, LAN1, WAN1 kalau static, OPT lain). Dua network overlap kalau
/// salah satu network address ada di dalam range yang lain.
fn cidr_overlaps(a: &str, b: &str) -> bool {
    let Some((a_net, a_prefix)) = parse_cidr(a) else { return false };
    let Some((b_net, b_prefix)) = parse_cidr(b) else { return false };
    let min_prefix = a_prefix.min(b_prefix);
    let mask = if min_prefix == 0 { 0 } else { u32::MAX << (32 - min_prefix) };
    (a_net & mask) == (b_net & mask)
}

/// Cek apakah sebuah IP host adalah alamat NETWORK atau BROADCAST dari
/// subnet-nya sendiri (host bits semua 0 atau semua 1) - keduanya
/// SECARA DEFINISI bukan alamat host yang valid untuk di-assign ke
/// interface mana pun, terlepas dari subnet apa pun itu.
fn is_network_or_broadcast_address(ip: [u8; 4], prefix: u8) -> bool {
    // /31 (RFC 3021 point-to-point) dan /32 (single host) TIDAK punya
    // network/broadcast address terpisah dari alamat host-nya sendiri
    // - alamatnya sendiri yang valid. Tanpa pengecualian ini, mask di
    // /32 jadi semua-1 sehingga network==broadcast==ip SELALU, membuat
    // setiap IP /32 (mis. loopback) salah ke-flag sebagai invalid -
    // bug nyata yang ketahuan waktu implementasi Loopback Interfaces.
    if prefix >= 31 {
        return false;
    }
    let ip_u32 = ipv4_to_u32(ip);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = ip_u32 & mask;
    let broadcast = network | !mask;
    ip_u32 == network || ip_u32 == broadcast
}

/// Cek apakah IP masuk range reserved/special yang TIDAK boleh
/// di-assign sebagai IP host biasa (loopback, multicast, reserved/
/// experimental) - SENGAJA TIDAK termasuk private range (10/8,
/// 172.16/12, 192.168/16) karena itu memang normal/diharapkan untuk
/// zona internal (MGMT/LAN1/OPT kita semua pakai 10.252.0.0/16).
fn is_reserved_ip(ip: [u8; 4]) -> bool {
    matches!(ip[0], 0 | 127 | 224..=255)
}

/// Deteksi konflik IP LIVE via ARP probe - dikonfirmasi dari
/// dokumentasi resmi Fortinet (mekanisme sama yang FortiGate sendiri
/// pakai sebelum assign IP statis): kirim satu ping cepat ke IP target,
/// kalau ADA perangkat lain yang menjawab, entry MAC address-nya akan
/// muncul di ARP cache OS - dicek lewat 'arp -n <ip>'. Sengaja pakai
/// 'ping' + 'arp' (base system FreeBSD, TIDAK perlu pkg install
/// arping) - konsisten prinsip project ini hindari dependency
/// tambahan kalau base system sudah cukup. Timeout pendek (1 detik,
/// 1 paket) - ini cuma probe cepat, bukan monitoring link quality.
fn detect_live_ip_conflict(ip: &str, own_interface: &str) -> Option<String> {
    let _ = Command::new("ping").args(["-c", "1", "-t", "1", ip]).output();
    let arp_output = Command::new("arp").args(["-n", ip]).output().ok()?;
    if !arp_output.status.success() {
        return None; // tidak ada entry ARP sama sekali = tidak ada yang menjawab
    }
    let text = String::from_utf8_lossy(&arp_output.stdout);
    // Format 'arp -n' FreeBSD: "<ip> (<ip>) at <mac> on <iface> ..."
    // Kalau baris menyebut interface KITA SENDIRI, itu bukan konflik -
    // itu cuma ARP cache dari IP yang MEMANG sudah kita assign sendiri
    // di interface itu (mis. re-save subnet yang sama, tidak berubah).
    if text.contains(" on ") && !text.contains(&format!(" on {own_interface}")) {
        // Ambil alamat MAC dari baris hasil untuk ditampilkan ke admin.
        let mac = text.split_whitespace().find(|s| s.contains(':')).unwrap_or("unknown");
        return Some(mac.to_string());
    }
    None
}

/// Parse /etc/pf.conf untuk ambil lan1_if, wan1_if (macro sederhana
/// 'nama = "nilai"'), dan daftar interface OPT (dari pola
/// 'block in quick on <if> to $mgmt_net' yang SELALU digenerate satu
/// baris per interface OPT - lihat install-gateway-v2.sh Bagian 6).
/// Parsing string manual (BUKAN regex crate) SENGAJA - pola yang
/// dicari sudah pasti sesuai format yang kita generate sendiri,
/// menghindari dependency tambahan untuk kasus sesederhana ini.
fn parse_pf_conf_zones() -> (Option<String>, Option<String>, Vec<String>) {
    let content = match fs::read_to_string("/etc/pf.conf") {
        Ok(c) => c,
        Err(_) => return (None, None, Vec::new()),
    };

    let extract_macro = |name: &str| -> Option<String> {
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix(&format!("{name} = \"")) {
                return rest.strip_suffix('"').map(|s| s.to_string());
            }
        }
        None
    };

    let mgmt_if = extract_macro("mgmt_if");
    let lan1_if = extract_macro("lan1_if");
    let wan1_if = extract_macro("wan1_if");

    // RCA (regresi ditemukan setelah migrasi default-deny simetris):
    // deteksi OPT sebelumnya scan pola teks "block in quick on X to
    // $mgmt_net" - baris ISOLASI yang SENGAJA dihapus oleh redesain
    // policy LAN1/OPT/VPN (Doc 7, keputusan bro soal FortiGate-style
    // implicit deny). Begitu baris itu hilang, Network page langsung
    // melaporkan "No OPT NICs detected" walau NIC fisiknya tetap ada -
    // signal deteksinya yang hilang, bukan interface-nya. Fix: scan
    // marker "# NTPSENSE_CUSTOM_RULES_<iface>_START" - marker ini SELALU
    // ada untuk setiap interface yang dikenal (LAN1/OPT/WAN1 semua
    // punya), independen dari rule apa pun yang ada DI DALAM marker itu
    // (kosong ataupun tidak). OPT = interface dengan marker itu YANG
    // BUKAN lan1_if/wan1_if/mgmt_if (MGMT tidak pernah punya marker ini
    // sama sekali - dia locked/fixed, tidak ada custom-rule
    // infrastructure untuknya).
    let mut opt_ifaces = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# NTPSENSE_CUSTOM_RULES_") {
            if let Some(iface) = rest.strip_suffix("_START") {
                let iface = iface.to_string();
                let is_lan1 = lan1_if.as_deref() == Some(iface.as_str());
                let is_wan1 = wan1_if.as_deref() == Some(iface.as_str());
                let is_mgmt = mgmt_if.as_deref() == Some(iface.as_str());
                // RCA (ditemukan nyata - Network page menampilkan enc0
                // sebagai "OPT1", Firewall page jadi dobel tab OPT1 dan
                // enc0(IPsec)): enc0 SENGAJA diberi marker penamaan
                // STANDAR (sama pola dengan OPT fisik) supaya tidak kena
                // bug RCA-26 (konflik kepemilikan marker wg0 dulu) - tapi
                // efek sampingnya, marker itu ikut cocok di sweep OPT ini
                // dan tidak pernah dikecualikan secara eksplisit. wg0
                // TIDAK kena masalah yang sama (markernya beda nama
                // sama sekali, NTPSENSE_WIREGUARD_PF_START, bukan pola
                // standar ini) - tapi tetap dikecualikan di sini juga
                // untuk jaga-jaga kalau pola marker wg0 pernah
                // diseragamkan di masa depan.
                let is_ipsec = iface == IPSEC_INTERFACE;
                let is_wireguard = iface == WG_INTERFACE;
                if !is_lan1 && !is_wan1 && !is_mgmt && !is_ipsec && !is_wireguard {
                    opt_ifaces.push(iface);
                }
            }
        }
    }

    (lan1_if, wan1_if, opt_ifaces)
}

/// Subnet (CIDR) sebuah interface SAAT INI, dari 'ifconfig' langsung -
/// SENGAJA query live, bukan dari file config manapun yang bisa basi
/// (RCA-38 dan sejenisnya - satu-satunya sumber kebenaran interface
/// yang benar-benar terpercaya adalah kernel itu sendiri). Dipakai
/// App Control per-zone scoping (roadmap - sekarang tidak terkunci lagi
/// setelah VLAN as Type selesai) - butuh subnet zona untuk membatasi
/// rule Suricata ke 'src net <subnet>' alih-alih 'any' global.
///
/// Parsing manual output 'ifconfig' (BUKAN regex crate) - pola output
/// FreeBSD stabil ("inet X.X.X.X netmask 0xYYYYYYYY"), sama filosofi
/// dengan parse_pf_conf_zones() di atas: hindari dependency tambahan
/// untuk pola yang sudah pasti bentuknya.
pub fn get_interface_subnet(iface: &str) -> Option<String> {
    let output = Command::new("ifconfig").arg(iface).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("inet ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let ip_str = parts.get(1)?;
        let netmask_idx = parts.iter().position(|&p| p == "netmask")?;
        let netmask_hex = parts.get(netmask_idx + 1)?;
        let netmask_val = u32::from_str_radix(netmask_hex.trim_start_matches("0x"), 16).ok()?;
        let prefix_len = netmask_val.count_ones();

        let ip_octets: Vec<u8> = ip_str.split('.').filter_map(|o| o.parse().ok()).collect();
        if ip_octets.len() != 4 {
            continue;
        }
        let ip_u32 = u32::from_be_bytes([ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]]);
        let network_u32 = ip_u32 & netmask_val;
        let network_octets = network_u32.to_be_bytes();
        return Some(format!(
            "{}.{}.{}.{}/{}",
            network_octets[0], network_octets[1], network_octets[2], network_octets[3], prefix_len
        ));
    }
    None
}

/// Alias (nama custom) per interface - format sederhana {"em2": "GUESTNET"}.
/// HashMap dipilih (bukan struct terpisah seperti CustomRulesFile) karena
/// datanya memang cuma pemetaan interface->label, tidak ada field lain.
/// Status enable/disable per interface - format {"em2": false} artinya
/// em2 SENGAJA dimatikan admin (administrative port shutdown, pola sama
/// dengan 'shutdown'/'no shutdown' Cisco atau enable/disable port
/// Fortinet/Sangfor). Interface yang TIDAK ada di map ini dianggap
/// enabled (default aman - map kosong berarti semua port hidup).
fn load_port_status() -> std::collections::HashMap<String, bool> {
    fs::read_to_string(PORT_STATUS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_port_status(data: &std::collections::HashMap<String, bool>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(PORT_STATUS_FILE, json).map_err(|e| e.to_string())
}

/// Role klasifikasi - TERPISAH dari "Zone" (yang di sistem kita berfungsi
/// sebagai identitas individual interface: MGMT/LAN1/WAN1/OPT1/OPT2/OPT3,
/// setara konsep "Zone" grouping FortiGate). Role di sini mengikuti pola
/// "Interface Role" FortiGate yang DIKONFIRMASI dari KB resmi: "Each
/// interface can be defined as one of the following roles: LAN, WAN, DMZ,
/// or Undefined" - HANYA 4 nilai tetap (kita tambah "MGMT" karena kita
/// punya zona MGMT permanen yang tidak ada padanan langsung di FortiGate).
/// MGMT/LAN1/WAN1 otomatis dapat role tetap sesuai namanya (tidak bisa
/// diubah admin) - HANYA interface OPT yang benar-benar bisa di-set lewat
/// action network.set_role, default "Undefined" kalau belum di-set.
fn load_roles() -> std::collections::HashMap<String, String> {
    fs::read_to_string(ROLE_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_roles(data: &std::collections::HashMap<String, String>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(ROLE_FILE, json).map_err(|e| e.to_string())
}

/// Config DHCP server Fase 1 (mengikuti field inti FortiOS: status
/// enable/disable, ip-range start/end, dns-server, lease-time) -
/// gateway TIDAK disimpan di sini, SELALU dihitung live dari IP
/// interface itu sendiri (persis default FortiGate: "Gateway IP:
/// usually the IP address of the FortiGate interface") - supaya
/// gateway tidak pernah nyasar/basi kalau IP interface berubah lewat
/// Fase B (network.set_subnet), tidak perlu sinkronisasi manual.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DhcpZoneConfig {
    enabled: bool,
    range_start: String,
    range_end: String,
    #[serde(default)]
    dns_servers: Vec<String>,
    #[serde(default = "default_lease_time")]
    lease_time: u32,
    // DHCP Option 43 - dipakai Cisco lightweight AP untuk discover WLC
    // lewat Layer 3 kalau WLC beda subnet dari AP (skenario NYATA bro:
    // WLC di subnet lain, 20 AP di beberapa gedung lewat VLAN native
    // trunk). #[serde(default)] WAJIB - config lama yang tersimpan
    // sebelum field ini ada tetap harus bisa dibaca tanpa error, sesuai
    // konvensi backward-compat project ini (Doc 7 §1.3).
    #[serde(default)]
    option43_wlc_ips: Vec<String>,
}

fn default_lease_time() -> u32 {
    604800 // 7 hari, konsisten dengan default FortiOS
}


/// Satu peer/client WireGuard - private key peer TIDAK PERNAH disimpan
/// di sini (cuma ditampilkan SEKALI ke admin saat dibuat, lalu dibuang -
/// pola sama dengan kunci HMAC backup: kita tidak pernah menyimpan
/// rahasia yang bukan milik kita untuk disimpan).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireguardPeer {
    id: String,
    name: String,
    public_key: String,
    allowed_ip: String,
    // Fase baru - Disable/Enable per-peer (bukan "Disconnect", yang
    // secara teknis tidak berarti apa-apa untuk WireGuard - protokolnya
    // connectionless, peer yang di-"disconnect" sesaat akan otomatis
    // re-handshake sendiri dalam hitungan detik selama key/endpoint-nya
    // masih valid). Disable yang genuine: keluarkan peer dari
    // [Peer]-block wg0.conf sepenuhnya (lihat generate_wg_conf) - server
    // benar-benar menolak handshake dari key itu, bukan cuma reset
    // sesaat. #[serde(default)] WAJIB di sini (Doc 7 §1.3) - peer lama
    // yang tersimpan sebelum field ini ada harus tetap enabled=true,
    // bukan tiba-tiba semua ke-disable diam-diam begitu binary baru
    // jalan.
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireguardConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_wg_port")]
    listen_port: u16,
    #[serde(default)]
    server_private_key: String,
    #[serde(default)]
    server_public_key: String,
    #[serde(default = "default_wg_subnet")]
    vpn_subnet: String,
    #[serde(default)]
    peers: Vec<WireguardPeer>,
}

fn default_wg_port() -> u16 {
    51820
}
fn default_wg_subnet() -> String {
    "10.66.66.0/24".to_string()
}

impl Default for WireguardConfig {
    fn default() -> Self {
        WireguardConfig {
            enabled: false,
            listen_port: default_wg_port(),
            server_private_key: String::new(),
            server_public_key: String::new(),
            vpn_subnet: default_wg_subnet(),
            peers: Vec::new(),
        }
    }
}

fn load_wg_config() -> WireguardConfig {
    fs::read_to_string(WG_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_wg_config(cfg: &WireguardConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(WG_CONFIG_FILE, json).map_err(|e| e.to_string())
}

/// Generate keypair WireGuard - private via 'wg genkey', public
/// DITURUNKAN dari private via 'wg pubkey' (pipe stdin) - DUA proses
/// terpisah, itu memang cara kerja resmi CLI 'wg' (tidak ada satu
/// command yang langsung hasilkan keduanya sekaligus).
fn generate_wg_keypair() -> Result<(String, String), String> {
    let genkey_output = Command::new("/usr/local/bin/wg").arg("genkey").output().map_err(|e| format!("Failed to run 'wg genkey': {e}"))?;
    if !genkey_output.status.success() {
        return Err("'wg genkey' command failed".to_string());
    }
    let private_key = String::from_utf8_lossy(&genkey_output.stdout).trim().to_string();

    let mut pubkey_child = Command::new("/usr/local/bin/wg")
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run 'wg pubkey': {e}"))?;
    {
        let stdin = pubkey_child.stdin.as_mut().ok_or_else(|| "Failed to open stdin for 'wg pubkey'".to_string())?;
        stdin.write_all(private_key.as_bytes()).map_err(|e| format!("Failed to write to 'wg pubkey' stdin: {e}"))?;
    }
    let pubkey_output = pubkey_child.wait_with_output().map_err(|e| format!("Failed to wait for 'wg pubkey': {e}"))?;
    if !pubkey_output.status.success() {
        return Err("'wg pubkey' command failed".to_string());
    }
    let public_key = String::from_utf8_lossy(&pubkey_output.stdout).trim().to_string();

    Ok((private_key, public_key))
}

/// Hitung IP server (host pertama di subnet, mis "10.66.66.0/24" ->
/// "10.66.66.1/24") - reuse math parse_cidr yang sudah ada+teruji dari
/// Fase B.
fn wg_server_ip(subnet: &str) -> String {
    if let Some((network_addr, prefix)) = parse_cidr(subnet) {
        let server_addr = network_addr + 1;
        let a = (server_addr >> 24) as u8;
        let b = (server_addr >> 16) as u8;
        let c = (server_addr >> 8) as u8;
        let d = server_addr as u8;
        format!("{a}.{b}.{c}.{d}/{prefix}")
    } else {
        subnet.to_string()
    }
}

/// Cari IP host BERIKUTNYA yang belum dipakai di dalam subnet VPN -
/// mulai dari .2 (.0=network, .1=server), skip yang sudah dipakai peer
/// lain. Return None kalau subnet penuh.
fn next_available_wg_ip(cfg: &WireguardConfig) -> Option<String> {
    let (network_addr, prefix) = parse_cidr(&cfg.vpn_subnet)?;
    let host_bits = 32 - prefix;
    let max_hosts = if host_bits >= 32 { u32::MAX } else { (1u32 << host_bits) - 1 };
    let used: Vec<String> = cfg.peers.iter().map(|p| p.allowed_ip.split('/').next().unwrap_or("").to_string()).collect();

    for host_num in 2..max_hosts {
        let candidate_addr = network_addr + host_num;
        let a = (candidate_addr >> 24) as u8;
        let b = (candidate_addr >> 16) as u8;
        let c = (candidate_addr >> 8) as u8;
        let d = candidate_addr as u8;
        let candidate_ip = format!("{a}.{b}.{c}.{d}");
        if !used.contains(&candidate_ip) {
            return Some(format!("{candidate_ip}/32"));
        }
    }
    None
}

/// Generate isi wg0.conf (format wg-quick, dipakai rc.d resmi paket
/// wireguard-tools - DIKONFIRMASI riset field 'Address' didukung
/// langsung di jalur ini, BEDA dari pendekatan manual 'wg setconf' yang
/// TIDAK mendukung Address).
fn generate_wg_conf(cfg: &WireguardConfig) -> String {
    let server_ip = wg_server_ip(&cfg.vpn_subnet);
    let mut conf = String::new();
    conf.push_str("# NTPSense InetGateway Tier 2 - wg0.conf\n");
    conf.push_str("# AUTO-GENERATED by ntpsense-configd - do not edit manually.\n\n");
    conf.push_str("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", cfg.server_private_key));
    conf.push_str(&format!("Address = {server_ip}\n"));
    conf.push_str(&format!("ListenPort = {}\n", cfg.listen_port));
    conf.push('\n');
    for peer in &cfg.peers {
        if !peer.enabled {
            // Peer di-disable admin - sengaja TIDAK ditulis ke [Peer]
            // block sama sekali, bukan cuma dikomentari. wg0.conf yang
            // di-reload server tidak akan mengenali key ini lagi -
            // genuinely ditolak, bukan reset sesaat yang bisa
            // re-handshake sendiri.
            continue;
        }
        conf.push_str(&format!("# {}\n", peer.name));
        conf.push_str("[Peer]\n");
        conf.push_str(&format!("PublicKey = {}\n", peer.public_key));
        conf.push_str(&format!("AllowedIPs = {}\n\n", peer.allowed_ip));
    }
    conf
}

const WG_FIREWALL_RULE_ID: &str = "wg_auto_punch";

/// Buka/tutup port WAN1 secara OTOMATIS mengikuti status enabled+port
/// WireGuard - REUSE infrastruktur CustomRule Firewall yang sudah ada
/// (bukan sistem marker terpisah baru) - id TETAP "wg_auto_punch" supaya
/// bisa dicari+diganti/dihapus lagi nanti kalau port berubah atau
/// WireGuard dimatikan, TANPA meninggalkan rule basi menumpuk. Admin
/// TETAP bisa lihat rule ini di tab Firewall > WAN1 (transparan, bukan
/// tersembunyi), deskripsinya eksplisit bilang "Auto" supaya tidak
/// disangka rule manual yang aman dihapus begitu saja.
fn sync_wireguard_firewall_rule(cfg: &WireguardConfig) -> Result<(), String> {
    let (_, wan1_if, _) = parse_pf_conf_zones();
    let Some(wan1_if) = wan1_if else {
        return Ok(());
    };

    let mut data = load_custom_rules();
    data.rules.retain(|r| r.id != WG_FIREWALL_RULE_ID);

    if cfg.enabled {
        data.rules.push(CustomRule {
            id: WG_FIREWALL_RULE_ID.to_string(),
            interface: wan1_if.clone(),
            action: "pass".to_string(),
            direction: "in".to_string(),
            protocol: "udp".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: Some(cfg.listen_port),
            description: "Auto: WireGuard VPN (managed automatically, do not edit)".to_string(),
            nat_redirect_ip: None,
            nat_redirect_port: None,
            limiter_name: None,
            gateway_group_name: None,
            zone_group: None,
            enabled: true,
            floating: false,
        });
    }

    save_custom_rules(&data)?;
    regenerate_pf_conf_for_interface(&wan1_if, &effective_rules_for_interface(&wan1_if))
}

const WG_PF_START_MARKER: &str = "# NTPSENSE_WIREGUARD_PF_START";
const WG_PF_END_MARKER: &str = "# NTPSENSE_WIREGUARD_PF_END";

/// RCA KRITIS (ditemukan dari test user - tunnel WireGuard TERBENTUK
/// sukses/handshake OK, tapi TIDAK ADA traffic yang bisa lewat sama
/// sekali - ping ke server/peer lain/LAN semua gagal): auto-punch
/// firewall SEBELUMNYA cuma buka port UDP di WAN1 (supaya paket
/// TERENKRIPSI bisa sampai ke daemon WireGuard) - tapi setelah paket
/// DIDEKRIPSI dan muncul di interface 'wg0', TIDAK PERNAH ada rule
/// pass yang mengizinkannya lewat firewall - 'block all' global (di
/// pf.conf, SEBELUM rule zona MGMT/LAN1/WAN1/OPT) diam-diam
/// memblokirnya, karena wg0 tidak pernah didaftarkan sebagai zona
/// dengan rule pass sama sekali. Beda dari WAN1 (yang sudah ada marker
/// dari install-gateway-v2.sh sejak awal), wg0 adalah interface VIRTUAL
/// yang HANYA ADA kalau plugin WireGuard di-install+enable belakangan -
/// jadi TIDAK ADA marker untuknya di pf.conf yang sudah ter-generate
/// sebelumnya. Fix: fungsi ini SISIPKAN marker baru (kalau belum ada)
/// tepat SETELAH baris 'block all' - posisi SAMA PERSIS dengan rule
/// zona lain (memanfaatkan last-match-wins pf: rule SETELAH 'block all'
/// yang menang) - baru splice rule pass on wg0 di antara markernya,
/// pola sama seperti regenerate_pf_conf_for_interface() tapi untuk
/// marker yang mungkin BELUM ADA di file (perlu tahap "insert dulu
/// kalau belum ada" yang tidak dibutuhkan zona fisik karena mereka
/// SELALU sudah py marker-nya sejak instalasi awal).
/// RCA KRITIS (ditemukan dari test user - tunnel WireGuard TERBENTUK
/// sukses/handshake OK, tapi TIDAK ADA traffic yang bisa lewat sama
/// sekali - ping ke server/peer lain/LAN semua gagal): auto-punch
/// firewall SEBELUMNYA cuma buka port UDP di WAN1 (supaya paket
/// TERENKRIPSI bisa sampai ke daemon WireGuard) - tapi setelah paket
/// DIDEKRIPSI dan muncul di interface 'wg0', TIDAK PERNAH ada rule
/// pass yang mengizinkannya lewat firewall - 'block all' global (di
/// pf.conf, SEBELUM rule zona MGMT/LAN1/WAN1/OPT) diam-diam
/// memblokirnya, karena wg0 tidak pernah didaftarkan sebagai zona
/// dengan rule pass sama sekali. Beda dari WAN1 (yang sudah ada marker
/// dari install-gateway-v2.sh sejak awal), wg0 adalah interface VIRTUAL
/// yang HANYA ADA kalau plugin WireGuard di-install+enable belakangan -
/// jadi TIDAK ADA marker untuknya di pf.conf yang sudah ter-generate
/// sebelumnya. Fix: fungsi ini SISIPKAN marker baru (kalau belum ada)
/// tepat SETELAH baris 'block all' - posisi SAMA PERSIS dengan rule
/// zona lain (memanfaatkan last-match-wins pf: rule SETELAH 'block all'
/// yang menang).
///
/// RCA SUSULAN (ditemukan proaktif saat membuka tab Firewall > wg0
/// untuk custom rule CRUD, BUKAN dari laporan bug - dicek sebelum bug
/// itu sempat terjadi ke user): fungsi ini SEBELUMNYA juga menulis ULANG
/// isi antara marker setiap kali VPN General disimpan (kosong kalau
/// disabled, kosong juga kalau enabled sejak redesain default-deny).
/// Begitu regenerate_pf_conf_for_interface() mulai bisa splice custom
/// rule admin ke marker YANG SAMA (lewat firewall.custom_rules.*), DUA
/// fungsi ini jadi rebutan kepemilikan isi marker - simpan VPN General
/// setelah admin tambah custom rule wg0 akan MENIMPA HABIS rule itu
/// diam-diam, kehilangan data tanpa pesan error apa pun. Fix: fungsi ini
/// sekarang HANYA memastikan marker itu ADA (insert sekali kalau belum),
/// TIDAK PERNAH lagi menyentuh ISINYA - custom-rules.json lewat
/// regenerate_pf_conf_for_interface() jadi SATU-SATUNYA pemilik konten
/// marker ini, persis pola yang sudah berlaku untuk semua interface
/// fisik (WAN1/LAN1/OPT) sejak awal.
fn sync_wireguard_pf_rule() -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;

    if content.contains(WG_PF_START_MARKER) {
        // Marker sudah ada - isinya (kosong atau berisi custom rule
        // admin) BUKAN urusan fungsi ini lagi, jangan disentuh.
        return Ok(());
    }

    // Anchor dibungkus newline di kedua sisi supaya HANYA cocok dengan
    // baris rule sungguhan ("block all" berdiri sendiri), bukan potongan
    // kata di dalam komentar prosa yang mungkin ada di sekitarnya.
    let anchor = "\nblock log all\n";
    let Some(idx) = content.find(anchor) else {
        return Err("Could not find 'block log all' anchor in /etc/pf.conf to insert WireGuard marker".to_string());
    };
    let insert_at = idx + anchor.len();
    let new_content = format!("{}\n{WG_PF_START_MARKER}\n{WG_PF_END_MARKER}\n\n{}", &content[..insert_at], &content[insert_at..]);

    let tmp_path = "/tmp/pf.conf.wireguard_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed - /etc/pf.conf NOT changed. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

/// Generate wg0.conf, apply via rc.d resmi paket wireguard-tools
/// ('service wireguard restart/stop'), sinkronkan firewall auto-punch,
/// verifikasi status SUNGGUHAN via 'wg show' (bukan cuma percaya exit
/// code service restart - pola sama seperti Squid/Kea sebelumnya).
fn apply_wireguard_conf() -> Result<(), String> {
    let cfg = load_wg_config();
    let conf_text = generate_wg_conf(&cfg);

    if let Some(parent) = std::path::Path::new(WG_CONF_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(WG_CONF_PATH, &conf_text).map_err(|e| format!("Failed to write {WG_CONF_PATH}: {e}"))?;
    // RCA (ditemukan dari log nyata user - wg-quick sendiri protes
    // "world accessible"): wg0.conf berisi PRIVATE KEY server dalam
    // bentuk plaintext - kunci ke 0600 (root only), pola sama dengan
    // file kunci HMAC backup.
    let _ = fs::set_permissions(WG_CONF_PATH, fs::Permissions::from_mode(0o600));

    sync_wireguard_firewall_rule(&cfg)?;
    sync_wireguard_pf_rule()?;

    if cfg.enabled {
        let _ = Command::new("sysrc").arg("wireguard_enable=YES").status();
        let _ = Command::new("sysrc").arg(format!("wireguard_interfaces={WG_INTERFACE}")).status();
        let restart_status = Command::new("service").arg("wireguard").arg("restart").status();
        if !matches!(restart_status, Ok(s) if s.success()) {
            let _ = Command::new("service").arg("wireguard").arg("start").status();
        }
        let show_output = Command::new("/usr/local/bin/wg").arg("show").arg(WG_INTERFACE).output();
        if !matches!(show_output, Ok(o) if o.status.success()) {
            return Err(format!(
                "WireGuard interface '{WG_INTERFACE}' failed to come up after applying the new configuration - check 'service wireguard status' and /var/log/messages"
            ));
        }
    } else {
        let _ = Command::new("service").arg("wireguard").arg("stop").status();
        let _ = Command::new("sysrc").arg("wireguard_enable=NO").status();
    }
    Ok(())
}

// ============================================================
// FreeRADIUS Server (net/freeradius3) - riset 4 komponen standar
// industri dari pfSense FreeRADIUS package (Interfaces, NAS/Clients,
// Users, Settings) sebelum desain - MVP di sini gabungkan jadi 3
// (General/Clients/Users, tanpa Interfaces custom - selalu listen di
// semua interface port default 1812/1813, cukup untuk kebanyakan
// deployment branch office, bisa diperluas nanti kalau perlu bind ke
// interface spesifik).
//
// Path dikonfirmasi dari output instalasi paket net/freeradius3
// FreeBSD resmi (poudriere test log, BUKAN tebakan):
//   - Config: /usr/local/etc/raddb/ (clients.conf, mods-config/files/users)
//   - Log: /var/log/radius.log (BUKAN /var/log/radius/radius.log)
//   - rc.conf: radiusd_enable="YES"
//
// RCA PENTING (ditemukan dari riset dokumentasi resmi FreeRADIUS,
// dikonfirmasi juga oleh panduan vendor SIEM Logmanager): server ini
// SECARA DEFAULT TIDAK mencatat hasil Access-Accept/Access-Reject ke
// radius.log sama sekali (radiusd.conf shipped dengan 'auth = no').
// Fix: ensure_radius_logging_enabled() menyalakan 'auth = yes' +
// 'auth_badpass = yes' (audit percobaan password SALAH) TAPI
// 'auth_goodpass' TETAP 'no' (jangan simpan password valid di log).
// ============================================================
const FREERADIUS_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/freeradius-config.json";
const RADDB_CLIENTS_CONF: &str = "/usr/local/etc/raddb/clients.conf";
const RADDB_USERS_FILE: &str = "/usr/local/etc/raddb/mods-config/files/users";
const RADIUSD_CONF_PATH: &str = "/usr/local/etc/raddb/radiusd.conf";
const RADIUS_LOG_FILE: &str = "/var/log/radius.log";
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RadiusClient {
    id: String,
    name: String,
    ip_cidr: String,
    secret: String,
    #[serde(default)]
    description: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RadiusUser {
    id: String,
    username: String,
    password: String,
    #[serde(default)]
    description: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FreeRadiusConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    clients: Vec<RadiusClient>,
    #[serde(default)]
    users: Vec<RadiusUser>,
}
fn load_freeradius_config() -> FreeRadiusConfig {
    fs::read_to_string(FREERADIUS_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
fn save_freeradius_config(cfg: &FreeRadiusConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(FREERADIUS_CONFIG_FILE, json).map_err(|e| e.to_string())
}
/// Generate isi clients.conf - char kutip lewat variabel {q}, BUKAN
/// escape backslash-kutip langsung (menghindari nested-escaping).
/// secret sudah divalidasi TIDAK mengandung tanda kutip di titik
/// input (freeradius.client_add), aman ditulis apa adanya.
fn generate_radius_clients_conf(clients: &[RadiusClient]) -> String {
    let q = '"';
    let mut out = String::from("# NTPSense InetGateway - AUTO-GENERATED by ntpsense-configd, do not edit manually.\n\n");
    for c in clients {
        out.push_str(&format!("client {} {{\n    ipaddr = {}\n    secret = {q}{}{q}\n}}\n\n", c.name, c.ip_cidr, c.secret));
    }
    out
}
/// Generate isi users file - format 'username Cleartext-Password :=
/// "password"' per baris, dikonfirmasi dari man page resmi (users(5)).
fn generate_radius_users_file(users: &[RadiusUser]) -> String {
    let q = '"';
    let mut out = String::from("# NTPSense InetGateway - AUTO-GENERATED by ntpsense-configd, do not edit manually.\n\n");
    for u in users {
        out.push_str(&format!("{} Cleartext-Password := {q}{}{q}\n\n", u.username, u.password));
    }
    out
}
/// Nyalakan logging Access-Accept/Reject di radiusd.conf - idempotent.
/// CATATAN JUJUR: pola teks berdasarkan radiusd.conf DEFAULT resmi
/// FreeRADIUS, BELUM divalidasi byte-persis di VM nyata - gagal diam
/// kalau pola tidak ditemukan (bukan error keras), perlu verifikasi
/// manual begitu di-deploy.
fn ensure_radius_logging_enabled() {
    let Ok(content) = fs::read_to_string(RADIUSD_CONF_PATH) else {
        return;
    };
    let mut new_content = content.clone();
    let mut changed = false;
    if new_content.contains("\tauth = no\n") {
        new_content = new_content.replacen("\tauth = no\n", "\tauth = yes\n", 1);
        changed = true;
    }
    if new_content.contains("\tauth_badpass = no\n") {
        new_content = new_content.replacen("\tauth_badpass = no\n", "\tauth_badpass = yes\n", 1);
        changed = true;
    }
    if changed {
        let _ = fs::write(RADIUSD_CONF_PATH, new_content);
    }
}
fn apply_freeradius_conf() -> Result<(), String> {
    let cfg = load_freeradius_config();
    let clients_conf = generate_radius_clients_conf(&cfg.clients);
    fs::write(RADDB_CLIENTS_CONF, &clients_conf).map_err(|e| format!("Failed to write {RADDB_CLIENTS_CONF}: {e}"))?;
    let users_content = generate_radius_users_file(&cfg.users);
    if let Some(parent) = std::path::Path::new(RADDB_USERS_FILE).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(RADDB_USERS_FILE, &users_content).map_err(|e| format!("Failed to write {RADDB_USERS_FILE}: {e}"))?;
    ensure_radius_logging_enabled();
    if cfg.enabled {
        let _ = Command::new("sysrc").arg("radiusd_enable=YES").status();
        let restart_status = Command::new("service").arg("radiusd").arg("restart").status();
        if !matches!(restart_status, Ok(s) if s.success()) {
            let _ = Command::new("service").arg("radiusd").arg("start").status();
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        let alive = Command::new("pgrep").arg("-x").arg("radiusd").output().map(|o| o.status.success() && !o.stdout.is_empty()).unwrap_or(false);
        if !alive {
            return Err("FreeRADIUS (radiusd) failed to start after applying the new configuration - check clients.conf/users syntax or /var/log/radius.log for details".to_string());
        }
    } else {
        let _ = Command::new("service").arg("radiusd").arg("stop").status();
        let _ = Command::new("sysrc").arg("radiusd_enable=NO").status();
    }
    Ok(())
}
/// Parse baris log FreeRADIUS untuk event autentikasi. CATATAN JUJUR:
/// pola teks berdasarkan dokumentasi resmi (msg_goodpass/msg_badpass
/// default), BELUM divalidasi terhadap radius.log nyata berisi data.
#[derive(Debug, Serialize)]
struct RadiusAuthEntry {
    timestamp: String,
    username: String,
    result: String,
    raw: String,
}
fn parse_radius_auth_log(lines: &[String]) -> Vec<RadiusAuthEntry> {
    let mut entries = Vec::new();
    for line in lines {
        let (result, marker) = if line.contains("Login OK") {
            ("accept", "Login OK")
        } else if line.contains("Login incorrect") {
            ("reject", "Login incorrect")
        } else {
            continue;
        };
        let timestamp = line.get(0..24).unwrap_or("").trim().to_string();
        let username = line
            .find(marker)
            .and_then(|idx| line[idx..].find('['))
            .and_then(|start| {
                let after = &line[line.find(marker).unwrap() + start..];
                after.find(']').map(|end| after[1..end].to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());
        entries.push(RadiusAuthEntry {
            timestamp,
            username,
            result: result.to_string(),
            raw: line.clone(),
        });
    }
    entries
}
// ============================================================
// IPsec Site-to-Site VPN (strongSwan) - riset dulu sebelum implementasi
// (pfSense/FortiGate/Palo Alto): IKEv2-only (best practice modern di
// semua vendor, IKEv1 cuma relevan untuk interop perangkat sangat lama -
// lihat catatan Doc 7). Model policy-based via interface enc0 (BUKAN
// route-based VTI/ipsec0) - ini yang dipakai pfSense sendiri (rujukan
// arsitektur pf terdekat kita), dan paling universal untuk interop
// lintas-vendor. Config modern strongSwan pakai swanctl.conf (BUKAN
// ipsec.conf/starter yang legacy) - dikonfirmasi dari docs.strongswan.org
// sebagai cara yang direkomendasikan saat ini.
//
// Phase1/Phase2 EKSPLISIT TERPISAH (bukan digabung flat seperti
// implementasi awal) - keputusan bro setelah lihat pfSense: satu Phase 1
// (satu IKE SA ke satu peer) bisa punya BANYAK Phase 2 (banyak pasangan
// subnet sekaligus dalam satu tunnel, tombol "+ Add P2" di pfSense).
// swanctl.conf's 'children {}' block SUDAH mendukung banyak child per
// connection secara native - model data kita sekarang mencerminkan itu
// langsung, bukan dipaksa satu-ke-satu seperti sebelumnya.
//
// CATATAN JUJUR: beberapa detail (path binary swanctl, format output
// 'swanctl --list-sas', interaksi persis multi-file strongswan.d/*.conf)
// divalidasi SEBAGIAN terhadap instalasi FreeBSD nyata sejauh sesi ini
// (path swanctl sudah dikonfirmasi /usr/local/sbin/swanctl dari test
// nyata) - detail lain (kombinasi proposal P1/P2 yang valid, filelog
// drop-in) masih perlu diverifikasi empiris begitu di-deploy.
// ============================================================

const IPSEC_CONFIG_FILE: &str = "/usr/local/etc/ntpsense/vpn-ipsec-config.json";
const SWANCTL_CONF_PATH: &str = "/usr/local/etc/swanctl/swanctl.conf";
const IPSEC_INTERFACE: &str = "enc0";
const IPSEC_LOG_FILE: &str = "/var/log/charon.log";
// File drop-in TERPISAH dari punya package (charon-logging.conf bawaan
// strongswan, isinya template kosong ter-comment semua) - lebih aman
// daripada modifikasi file mereka, memanfaatkan pola
// 'include strongswan.d/*.conf' yang sudah dikonfirmasi aktif di
// strongswan.conf.
const IPSEC_LOGGING_DROPIN: &str = "/usr/local/etc/strongswan.d/ntpsense-logging.conf";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpsecPhase2 {
    id: String,
    local_subnet: String,
    remote_subnet: String,
    // P2 Protocol - ESP praktis universal (AH tidak enkripsi, jarang
    // dipakai nyata - pfSense/FortiGate juga default ESP) - dibuat FIXED
    // (bukan dropdown) sebagai keputusan scope yang disengaja, bukan
    // kelupaan.
    p2_encryption: String, // "aes128" | "aes256" | "aes128gcm16" | "aes256gcm16"
    p2_integrity: String,  // "sha256" | "sha384" | "sha512" (diabaikan kalau p2_encryption AEAD/gcm)
    #[serde(default)]
    p2_dh_group: String, // PFS group, opsional - string kosong = tanpa PFS
    // Enable/Disable P2 - permintaan bro (pfSense punya ini juga untuk P2,
    // bukan cuma P1). BEDA dari Terminate/Disconnect (yang cuma putus
    // sesi aktif sesaat, config tetap ada, otomatis reconnect): Disable
    // benar-benar KELUARKAN child ini dari swanctl.conf (tidak ikut
    // ter-generate di generate_swanctl_conf sampai di-enable lagi) -
    // sama prinsip persis dengan enabled di level tunnel (P1).
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpsecTunnel {
    id: String,
    name: String,
    #[serde(default = "default_true")]
    enabled: bool,
    peer_address: String, // IP or FQDN of remote peer
    psk: String,
    p1_encryption: String, // "aes128" | "aes256" | "aes128gcm16" | "aes256gcm16"
    p1_integrity: String,  // "sha256" | "sha384" | "sha512"
    p1_dh_group: String,   // "modp2048" (14) | "modp3072" (15) | "ecp256" (19) | "ecp384" (20)
    #[serde(default)]
    phase2: Vec<IpsecPhase2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IpsecConfig {
    #[serde(default)]
    tunnels: Vec<IpsecTunnel>,
}

fn load_ipsec_config() -> IpsecConfig {
    fs::read_to_string(IPSEC_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_ipsec_config(cfg: &IpsecConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(IPSEC_CONFIG_FILE, json).map_err(|e| e.to_string())
}

fn swanctl_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// AEAD (GCM) cipher sudah bawa autentikasi sendiri - klausa integrity
/// terpisah TIDAK ditambahkan untuk kombinasi itu (redundant/invalid di
/// syntax swanctl), berbeda dari cipher klasik (AES biasa) yang WAJIB
/// klausa integrity terpisah.
fn build_ike_proposal(encryption: &str, integrity: &str, dh_group: &str) -> String {
    if encryption.ends_with("gcm16") {
        format!("{encryption}-{dh_group}")
    } else {
        format!("{encryption}-{integrity}-{dh_group}")
    }
}

/// Sama prinsip AEAD seperti di atas, plus PFS (dh_group) OPSIONAL untuk
/// child SA - kalau admin tidak pilih PFS group, klausa itu diomit sama
/// sekali (bukan dipaksa ada).
fn build_esp_proposal(encryption: &str, integrity: &str, dh_group: &str) -> String {
    let base = if encryption.ends_with("gcm16") {
        encryption.to_string()
    } else {
        format!("{encryption}-{integrity}")
    };
    if dh_group.trim().is_empty() {
        base
    } else {
        format!("{base}-{dh_group}")
    }
}

/// Generate isi swanctl.conf - satu section per tunnel enabled, BANYAK
/// children per tunnel (satu per Phase 2) - IKEv2 saja (version = 2).
/// start_action = trap berarti tunnel dibentuk ON-DEMAND begitu ada
/// traffic match salah satu local_ts/remote_ts child-nya, pola yang sama
/// seperti pfSense/FortiGate site-to-site standar.
fn generate_swanctl_conf(cfg: &IpsecConfig) -> String {
    let mut connections = String::new();
    let mut secrets = String::new();
    for t in &cfg.tunnels {
        if !t.enabled || t.phase2.is_empty() {
            // Tunnel tanpa Phase 2 sama sekali tidak ada gunanya di-load
            // (tidak ada traffic selector, tidak akan pernah match apa
            // pun) - dilewati daripada menulis connection kosong yang
            // membingungkan saat troubleshooting nanti.
            continue;
        }
        let key = &t.id;
        let mut children = String::new();
        for p2 in &t.phase2 {
            if !p2.enabled {
                // Disabled - dikeluarkan sepenuhnya dari children block,
                // bukan cuma dilewati sesaat (beda dari Terminate yang
                // cuma putus sesi aktif tapi config tetap ter-load).
                continue;
            }
            let esp_proposal = build_esp_proposal(&p2.p2_encryption, &p2.p2_integrity, &p2.p2_dh_group);
            children.push_str(&format!(
                "            {p2key} {{\n                local_ts = {local_ts}\n                remote_ts = {remote_ts}\n                start_action = trap\n                esp_proposals = {esp_proposal}\n            }}\n",
                p2key = p2.id,
                local_ts = p2.local_subnet,
                remote_ts = p2.remote_subnet,
                esp_proposal = esp_proposal,
            ));
        }
        let ike_proposal = build_ike_proposal(&t.p1_encryption, &t.p1_integrity, &t.p1_dh_group);
        connections.push_str(&format!(
            "    {key} {{\n        version = 2\n        local_addrs = %any\n        remote_addrs = {peer}\n        local {{\n            auth = psk\n        }}\n        remote {{\n            auth = psk\n        }}\n        proposals = {ike_proposal}\n        children {{\n{children}        }}\n    }}\n",
            key = key,
            peer = t.peer_address,
            ike_proposal = ike_proposal,
            children = children,
        ));
        secrets.push_str(&format!(
            "    ike-{key} {{\n        id = {peer}\n        secret = \"{psk}\"\n    }}\n",
            key = key,
            peer = t.peer_address,
            psk = swanctl_escape(&t.psk),
        ));
    }
    format!(
        "# NTPSense InetGateway Tier 2 - swanctl.conf\n# AUTO-GENERATED by ntpsense-configd - do not edit manually.\n\nconnections {{\n{connections}}}\n\nsecrets {{\n{secrets}}}\n"
    )
}

const IPSEC_FIREWALL_RULE_ID_IKE: &str = "ipsec_auto_punch_ike";
const IPSEC_FIREWALL_RULE_ID_NATT: &str = "ipsec_auto_punch_natt";

fn sync_ipsec_firewall_rule(cfg: &IpsecConfig) -> Result<(), String> {
    let (_, wan1_if, _) = parse_pf_conf_zones();
    let Some(wan1_if) = wan1_if else {
        return Ok(());
    };

    let any_enabled = cfg.tunnels.iter().any(|t| t.enabled);

    let mut data = load_custom_rules();
    data.rules.retain(|r| r.id != IPSEC_FIREWALL_RULE_ID_IKE && r.id != IPSEC_FIREWALL_RULE_ID_NATT);

    if any_enabled {
        data.rules.push(CustomRule {
            id: IPSEC_FIREWALL_RULE_ID_IKE.to_string(),
            interface: wan1_if.clone(),
            action: "pass".to_string(),
            direction: "in".to_string(),
            protocol: "udp".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: Some(500),
            description: "Auto: IPsec IKE (managed automatically, do not edit)".to_string(),
            nat_redirect_ip: None,
            nat_redirect_port: None,
            limiter_name: None,
            gateway_group_name: None,
            zone_group: None,
            enabled: true,
            floating: false,
        });
        data.rules.push(CustomRule {
            id: IPSEC_FIREWALL_RULE_ID_NATT.to_string(),
            interface: wan1_if.clone(),
            action: "pass".to_string(),
            direction: "in".to_string(),
            protocol: "udp".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: Some(4500),
            description: "Auto: IPsec NAT-T (managed automatically, do not edit)".to_string(),
            nat_redirect_ip: None,
            nat_redirect_port: None,
            limiter_name: None,
            gateway_group_name: None,
            zone_group: None,
            enabled: true,
            floating: false,
        });
    }

    save_custom_rules(&data)?;
    regenerate_pf_conf_for_interface(&wan1_if, &effective_rules_for_interface(&wan1_if))
}

const IPSEC_PF_START_MARKER: &str = "# NTPSENSE_CUSTOM_RULES_enc0_START";
const IPSEC_PF_END_MARKER: &str = "# NTPSENSE_CUSTOM_RULES_enc0_END";

fn ensure_ipsec_pf_marker() -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    if content.contains(IPSEC_PF_START_MARKER) {
        return Ok(());
    }
    let anchor = "\nblock log all\n";
    let Some(idx) = content.find(anchor) else {
        return Err("Could not find 'block log all' anchor in /etc/pf.conf to insert IPsec marker".to_string());
    };
    let insert_at = idx + anchor.len();
    let new_content = format!("{}\n{IPSEC_PF_START_MARKER}\n{IPSEC_PF_END_MARKER}\n\n{}", &content[..insert_at], &content[insert_at..]);

    let tmp_path = "/tmp/pf.conf.ipsec_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed - /etc/pf.conf NOT changed. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

/// Tulis drop-in logging kita SENDIRI (file terpisah dari
/// charon-logging.conf bawaan package, yang isinya template kosong
/// ter-comment semua - dikonfirmasi dari file nyata di test VM, bukan
/// tebakan) - memanfaatkan pola 'include strongswan.d/*.conf' yang
/// sudah aktif. File ini kita miliki penuh, aman ditulis ulang setiap
/// apply (bukan config bersama seperti pf.conf yang perlu pola
/// ensure-marker-exists-only).
fn ensure_ipsec_logging_conf() -> Result<(), String> {
    let content = "charon {\n    filelog {\n        ntpsense_charon {\n            path = /var/log/charon.log\n            default = 1\n            append = yes\n            flush_line = yes\n        }\n    }\n}\n";
    fs::write(IPSEC_LOGGING_DROPIN, content).map_err(|e| format!("Failed to write {IPSEC_LOGGING_DROPIN}: {e}"))
}

fn apply_ipsec_conf() -> Result<(), String> {
    let cfg = load_ipsec_config();
    let conf_text = generate_swanctl_conf(&cfg);
    fs::write(SWANCTL_CONF_PATH, &conf_text).map_err(|e| format!("Failed to write {SWANCTL_CONF_PATH}: {e}"))?;

    ensure_ipsec_logging_conf()?;

    let _ = Command::new("kldload").arg("if_enc").status();
    let _ = Command::new("sysrc").arg("if_enc_load=YES").status();
    let _ = Command::new("ifconfig").arg(IPSEC_INTERFACE).arg("up").status();

    ensure_ipsec_pf_marker()?;
    sync_ipsec_firewall_rule(&cfg)?;

    let _ = Command::new("sysrc").arg("strongswan_enable=YES").status();
    let _ = Command::new("service").arg("strongswan").arg("onestart").status();
    // Restart (bukan cuma --load-all) supaya drop-in logging baru
    // (di-tulis di atas) benar-benar dibaca ulang oleh proses charon -
    // swanctl --load-all cuma reload connections/secrets, TIDAK reload
    // pengaturan logging strongswan.conf/strongswan.d.
    let _ = Command::new("service").arg("strongswan").arg("restart").status();

    let reload_status = Command::new("/usr/local/sbin/swanctl")
        .arg("--load-all")
        .status()
        .map_err(|e| format!("Failed to run swanctl --load-all: {e}"))?;
    if !reload_status.success() {
        return Err("swanctl --load-all failed - check swanctl.conf syntax (see IPsec Log tab for charon's own diagnostic output)".to_string());
    }
    Ok(())
}

fn get_ipsec_tunnel_status() -> std::collections::HashMap<String, bool> {
    let mut status = std::collections::HashMap::new();
    if let Ok(output) = Command::new("/usr/local/sbin/swanctl").arg("--list-sas").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some((name, rest)) = trimmed.split_once(':') {
                if rest.contains("ESTABLISHED") {
                    status.insert(name.trim().to_string(), true);
                }
            }
        }
    }
    status
}

fn get_ipsec_log(limit: usize) -> Vec<String> {
    match fs::read_to_string(IPSEC_LOG_FILE) {
        Ok(content) => {
            let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            let start = lines.len().saturating_sub(limit);
            lines.split_off(start)
        }
        Err(_) => Vec::new(),
    }
}

// ============================================================
// Dashboard - System Information widget (pola pfSense Status > Dashboard,
// tapi ADAPTASI: konten Netgate/pfBlockerNG DIHAPUS total - itu marketing
// khusus vendor mereka, tidak relevan untuk produk kita. Interfaces
// widget REUSE network.zones yang sudah ada (MGMT/LAN1/WAN1/OPT/VPN),
// bukan hardcode WAN/LAN seperti pfSense.
//
// SETIAP fungsi di bawah DEFENSIF - parsing command eksternal (uptime,
// top, df) rawan meleset kalau formatnya sedikit beda dari yang
// diriset di atas kertas; kegagalan parse mengembalikan None/fallback
// string, TIDAK PERNAH panic - dashboard tetap tampil (field itu saja
// yang jadi "-") walau satu command tak terduga formatnya di VM nyata.
// PERLU VERIFIKASI EMPIRIS begitu di-deploy, sama seperti disiplin
// project ini untuk asumsi command eksternal lainnya.
// ============================================================

fn get_hostname() -> String {
    Command::new("/bin/hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_freebsd_version() -> String {
    Command::new("/bin/freebsd-version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Parse output 'uptime' - contoh yang diriset:
/// "1:06PM up 42 days, 2:39, 1 user, load averages: 0.05, 0.06, 0.02"
/// Dipecah jadi dua bagian terpisah (uptime_str, load_avg) karena
/// keduanya dipakai di baris terpisah di UI (pola pfSense sendiri).
fn get_uptime_and_load() -> (String, Option<[f64; 3]>) {
    let raw = match Command::new("/usr/bin/uptime").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => return ("—".to_string(), None),
    };
    // Ambil bagian antara "up " dan ", load averages" atau ", N user(s)"
    let uptime_part = raw
        .find("up ")
        .and_then(|start| {
            let after_up = &raw[start + 3..];
            let end = after_up.find(", load averages").unwrap_or(after_up.len());
            // potong juga di ", N user" kalau ada SEBELUM load averages
            let end2 = after_up.find(" user").map(|i| {
                // mundur ke koma sebelum angka user count
                after_up[..i].rfind(',').map(|c| c).unwrap_or(end)
            }).unwrap_or(end);
            let cut = end2.min(end);
            Some(after_up[..cut].trim().to_string())
        })
        .unwrap_or_else(|| "—".to_string());

    let load = raw.find("load averages:").and_then(|idx| {
        let nums_part = &raw[idx + "load averages:".len()..];
        let nums: Vec<f64> = nums_part
            .split(',')
            .filter_map(|s| s.trim().parse::<f64>().ok())
            .collect();
        if nums.len() >= 3 {
            Some([nums[0], nums[1], nums[2]])
        } else {
            None
        }
    });

    (uptime_part, load)
}

/// Satu pemanggilan 'top -b -n 1' dipakai bersama untuk CPU, Memory, DAN
/// Swap - REFACTOR dari versi awal yang memanggil top DUA KALI terpisah
/// (satu untuk CPU, satu lagi untuk Memory) - tidak perlu, satu snapshot
/// sudah berisi ketiga baris (CPU:/Mem:/Swap:) sekaligus.
fn get_top_snapshot() -> Option<String> {
    // '-P' ditambah (permintaan user - Dashboard per-CPU load) - top
    // JUGA mencetak baris "CPU 0:"/"CPU 1:" per-core, SELAIN baris
    // agregat "CPU:" yang sudah dipakai - satu snapshot tetap cukup
    // untuk semua kebutuhan (CPU agregat, per-core, Mem, Swap
    // sekaligus), tidak perlu proses top kedua.
    let output = Command::new("/usr/bin/top").args(["-b", "-P", "-n", "1"]).output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Model CPU - dari 'sysctl -n hw.model', live tiap request dashboard
/// (nilai ini TIDAK PERNAH berubah selama uptime, tapi query-nya
/// murah, tidak perlu infrastruktur cache terpisah).
fn get_cpu_model() -> Option<String> {
    let output = Command::new("/sbin/sysctl").args(["-n", "hw.model"]).output().ok()?;
    let model = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if model.is_empty() { None } else { Some(model) }
}

/// Jumlah core/thread logical - dari 'sysctl -n hw.ncpu'. Ini ANGKA
/// LOGICAL (termasuk Hyper-Threading kalau CPU-nya punya) - untuk CPU
/// tanpa HT (mis. Celeron J1800 di test hardware nyata), angka ini
/// SAMA dengan jumlah core fisik.
fn get_cpu_core_count() -> Option<u32> {
    let output = Command::new("/sbin/sysctl").args(["-n", "hw.ncpu"]).output().ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse::<u32>().ok()
}

/// Load per-core - HANYA terisi kalau 'top' dipanggil dengan '-P'
/// (lihat get_top_snapshot()). Format terverifikasi hardware fisik
/// nyata (mini PC Celeron J1800, 2 core): "CPU 0:  1.2% user, ...
/// 96.1% idle" / "CPU 1: ...". Beda dari baris agregat "CPU:" (tanpa
/// nomor) yang dipakai parse_cpu_usage_pct() - keduanya tidak saling
/// tumpang tindih (anchor "CPU " dengan spasi vs "CPU:" tanpa spasi).
fn parse_percpu_usage(top_text: &str) -> Vec<(u32, f64)> {
    let mut result = Vec::new();
    for line in top_text.lines() {
        let line = line.trim_start();
        if !line.starts_with("CPU ") {
            continue;
        }
        let rest = &line[4..];
        let Some(colon_pos) = rest.find(':') else { continue };
        let core_str = rest[..colon_pos].trim();
        let Ok(core_num) = core_str.parse::<u32>() else { continue };
        let idle_pct = rest[colon_pos + 1..]
            .split(',')
            .find(|part| part.contains("idle"))
            .and_then(|part| part.split('%').next().map(|s| s.trim()))
            .and_then(|s| s.rsplit(' ').next())
            .and_then(|s| s.parse::<f64>().ok());
        if let Some(idle) = idle_pct {
            result.push((core_num, (100.0 - idle).max(0.0)));
        }
    }
    result
}

/// Parse nilai dengan suffix unit (mis. "83M", "1898M", "4096M") jadi bytes.
fn parse_unit_value(token: &str) -> Option<u64> {
    let token = token.trim();
    let unit = token.chars().last()?;
    // RCA (ditemukan dari test hardware fisik nyata - swap genuinely
    // aktif+sehat 8GB tapi Dashboard tampil kosong): 'top' mencetak
    // "0B" (huruf B POLOS, tanpa skala K/M/G) untuk nilai PERSIS NOL -
    // umum di banyak tool Unix untuk kasus zero-value. Sebelumnya
    // fungsi ini cuma kenal K/M/G, 'B' polos jatuh ke None, dan karena
    // caller (parse_swap_usage) butuh used+total SUKSES keduanya lewat
    // '?', satu field gagal bikin SELURUH baris Swap: tidak terbaca -
    // bukan cuma field yang nol, genuinely seluruh data hilang.
    if unit == 'B' {
        let num_part = &token[..token.len() - 1];
        return num_part.parse::<f64>().ok().map(|n| n as u64);
    }
    let multiplier: u64 = match unit {
        'K' => 1024,
        'M' => 1024 * 1024,
        'G' => 1024 * 1024 * 1024,
        _ => return None,
    };
    let num_part = &token[..token.len() - 1];
    num_part.parse::<f64>().ok().map(|n| (n * multiplier as f64) as u64)
}

/// CPU usage - parsing baris "CPU:" untuk persentase idle, usage = 100 -
/// idle. FORMAT terverifikasi di VM nyata: "CPU:  0.0% user,  0.0% nice,
/// 0.0% system,  0.3% interrupt, 99.7% idle".
fn parse_cpu_usage_pct(top_text: &str) -> Option<f64> {
    let cpu_line = top_text.lines().find(|l| l.trim_start().starts_with("CPU:"))?;
    let idle_pct = cpu_line
        .split(',')
        .find(|part| part.contains("idle"))
        .and_then(|part| part.split('%').next().map(|s| s.trim()))
        .and_then(|s| s.rsplit(' ').next())
        .and_then(|s| s.parse::<f64>().ok())?;
    Some((100.0 - idle_pct).max(0.0))
}

/// Memory usage - REVISI (RCA nyata, ditemukan dari data VM sungguhan):
/// implementasi pertama pakai hw.physmem dikurangi
/// vm.stats.vm.v_free_count*page_size - SALAH secara metodologi, bukan
/// salah parsing. FreeBSD agresif memakai RAM nganggur untuk cache disk
/// (mirip "free vs available" di Linux) - v_free_count HANYA hitung
/// halaman yang benar-benar kosong, TIDAK termasuk cache/inactive yang
/// sebenarnya bisa direklaim kapan saja. Rumus pertama itu akan SELALU
/// tampil RAM hampir penuh (>95%) walau sistem sedang santai.
///
/// Fix: parse baris "Mem:" dari 'top' langsung (top SUDAH menghitung
/// breakdown yang benar sendiri). Diverifikasi dengan DUA sample nyata
/// dari VM berbeda waktu (83M Active saat santai -> 45.7% used, 2253M
/// Active saat Suricata jalan penuh -> 81.1% used) - rumus terbukti
/// benar, angka tinggi yang sempat terlihat GENUINELY akurat (Suricata
/// sendiri makan ~2.8GB RES di VM 4GB RAM), bukan bug perhitungan.
/// Definisi used/available yang dipakai (konvensi umum tools monitoring
/// FreeBSD, didokumentasikan eksplisit supaya admin tahu persis apa yang
/// dihitung kalau meragukan angkanya):
///   Used      = Active + Wired + Laundry (genuinely tidak bisa dipakai
///               proses lain saat ini)
///   Available = Inactive + Buf + Free (bisa direklaim kapan saja kalau
///               dibutuhkan proses lain)
fn parse_memory_usage(top_text: &str) -> Option<(u64, u64)> {
    let mem_line = top_text.lines().find(|l| l.trim_start().starts_with("Mem:"))?;
    let mut categories: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for part in mem_line.trim_start_matches("Mem:").split(',') {
        let part = part.trim();
        let mut tokens = part.splitn(2, ' ');
        let value_tok = tokens.next()?;
        let label = tokens.next()?.trim().to_string();
        if let Some(bytes) = parse_unit_value(value_tok) {
            categories.insert(label, bytes);
        }
    }
    let get = |k: &str| categories.get(k).copied().unwrap_or(0);
    let used = get("Active") + get("Wired") + get("Laundry");
    let available = get("Inact") + get("Buf") + get("Free");
    let total = used + available;
    if total == 0 {
        return None;
    }
    Some((used, total))
}

/// Swap usage - parsing baris "Swap:" dari 'top', DITEMUKAN dari
/// verifikasi VM nyata (bro sempat coba 'swapinfo' terpisah, tapi 'top'
/// yang SUDAH kita panggil untuk CPU/Memory ternyata sudah punya baris
/// ini juga - tidak perlu command tambahan). Format nyata dari VM:
/// "Swap: 4096M Total, 550M Used, 3545M Free, 13% Inuse".
fn parse_swap_usage(top_text: &str) -> Option<(u64, u64)> {
    // RCA NYATA (ditemukan dari test hardware fisik - mini PC 2eth,
    // BUKAN dugaan "0B" sebelumnya yang salah): FreeBSD 'top' TIDAK
    // PERNAH melaporkan label "Used" untuk swap - formatnya "Total" +
    // "Free" saja, contoh nyata: "Swap: 8192M Total, 8192M Free".
    // Parser lama cuma cari "Total"+"Used" - karena "Used" genuinely
    // tidak pernah ada, hasilnya SELALU None apa pun isi datanya.
    let swap_line = top_text.lines().find(|l| l.trim_start().starts_with("Swap:"))?;
    let mut used: Option<u64> = None;
    let mut free: Option<u64> = None;
    let mut total: Option<u64> = None;
    for part in swap_line.trim_start_matches("Swap:").split(',') {
        let part = part.trim();
        let mut tokens = part.splitn(2, ' ');
        let value_tok = tokens.next()?;
        let label = tokens.next()?.trim();
        let bytes = parse_unit_value(value_tok);
        if label == "Total" {
            total = bytes;
        } else if label == "Used" {
            used = bytes;
        } else if label == "Free" {
            free = bytes;
        }
    }
    let total = total?;
    // Dukung KEDUA kemungkinan format: "Used" langsung kalau suatu
    // saat ada varian FreeBSD/tool lain yang melaporkannya, ATAU
    // hitung used = total - free (format yang GENUINELY dipakai
    // FreeBSD, dikonfirmasi dari test nyata).
    let used = used.or_else(|| free.map(|f| total.saturating_sub(f)))?;
    Some((used, total))
}

/// Disk usage via 'df -h' - skip baris header dan filesystem non-fisik
/// (devfs, tmpfs) yang tidak relevan ditampilkan ke admin.
struct DiskUsage {
    mount: String,
    used: String,
    size: String,
    pct: String,
}

fn get_disk_usage() -> Vec<DiskUsage> {
    let output = match Command::new("/bin/df").arg("-h").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let filesystem = cols[0];
        if filesystem.starts_with("devfs") || filesystem.starts_with("tmpfs") {
            continue;
        }
        result.push(DiskUsage {
            size: cols[1].to_string(),
            used: cols[2].to_string(),
            pct: cols[4].to_string(),
            mount: cols[5].to_string(),
        });
    }
    result
}

/// Traffic Graphs widget (Dashboard) - byte counter KUMULATIF per
/// interface (bukan rate - JS di sisi client yang hitung selisih antar
/// dua polling untuk dapat kbps, supaya server tidak perlu simpan
/// riwayat sample sendiri). Sumber: 'netstat -ibn', ambil HANYA baris
/// "<Link#N>" per interface (level link/agregat) - baris per-protokol
/// (IPv4/IPv6) di bawahnya SENGAJA dilewati, karena riset mengonfirmasi
/// baris itu cuma subset (bukan penjumlah) dari baris Link, menghitung
/// keduanya akan double-count. Kolom "Ibytes"/"Obytes" dicari dinamis
/// dari baris header (bukan index tetap) - posisi kolom netstat bisa
/// beda tergantung versi/flag, jangan diasumsikan tetap.
fn get_interface_traffic_bytes() -> std::collections::HashMap<String, (u64, u64)> {
    let mut result = std::collections::HashMap::new();
    let output = match Command::new("/usr/bin/netstat").args(["-ibn"]).output() {
        Ok(o) => o,
        Err(_) => return result,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();

    let header = match lines.next() {
        Some(h) => h,
        None => return result,
    };
    let header_cols: Vec<&str> = header.split_whitespace().collect();
    let ibytes_idx = header_cols.iter().position(|c| *c == "Ibytes");
    let obytes_idx = header_cols.iter().position(|c| *c == "Obytes");
    let (ibytes_idx, obytes_idx) = match (ibytes_idx, obytes_idx) {
        (Some(i), Some(o)) => (i, o),
        _ => return result, // format tak dikenali - kembalikan kosong, jangan tebak posisi
    };

    for line in lines {
        if !line.contains("<Link#") {
            continue; // hanya baris link-level, lewati baris per-protokol IPv4/IPv6
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() <= ibytes_idx.max(obytes_idx) {
            continue;
        }
        let iface = cols[0].to_string();
        let rx = cols[ibytes_idx].parse::<u64>().ok();
        let tx = cols[obytes_idx].parse::<u64>().ok();
        if let (Some(rx), Some(tx)) = (rx, tx) {
            result.insert(iface, (rx, tx));
        }
    }
    result
}

// ============================================================
// Link Aggregation (lagg) - Tahap 1 dari rencana "Zone Groups + LAGG +
// Multi-WAN" (disepakati dengan bro). Protokol didukung: failover,
// lacp, loadbalance, roundrobin - dikonfirmasi dari if_lagg(4) resmi
// dan FreeBSD Handbook, BUKAN ditebak. Gotcha nyata yang ditemukan dari
// riset (forum FreeBSD): member interface WAJIB di-'up' SEBELUM lagg
// interface dibuat, kalau tidak status "no carrier" muncul dan gagal
// dapat IP - urutan di bawah ini SENGAJA mengikuti urutan itu persis.
//
// Member interface HANYA boleh OPT dengan Role=Undefined DAN belum
// punya custom rule apa pun - mencegah admin tidak sengaja
// menghancurkan zona yang sudah aktif dipakai (subnet/DHCP/rule sudah
// dikonfigurasi). Setelah lagg dibuat, marker pf.conf untuk SETIAP
// member dihapus total, digantikan SATU marker baru untuk interface
// lagg itu sendiri - parse_pf_conf_zones() yang sudah ada otomatis
// mendeteksi ini sebagai OPT baru (marker-based, sama seperti perilaku
// sudah ada untuk enc0/wg0 - lihat RCA soal itu), tidak perlu
// perubahan apa pun di fungsi itu.
// ============================================================

fn get_existing_lagg_names() -> Vec<String> {
    let output = match Command::new("/sbin/ifconfig").arg("-l").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|s| s.starts_with("lagg"))
        .map(|s| s.to_string())
        .collect()
}

fn next_available_lagg_name() -> String {
    let existing = get_existing_lagg_names();
    let mut n = 0u32;
    loop {
        let candidate = format!("lagg{n}");
        if !existing.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Validasi member LAGG - HANYA interface OPT dengan Role=Undefined DAN
/// tanpa custom rule apa pun boleh jadi anggota. Ini genuinely mencegah
/// penghancuran zona yang sudah dipakai admin (bukan sekadar UI hint -
/// dicek di Rust, lapis validasi yang sama tidak bisa dilewati dari
/// request API mentah).
fn validate_single_lagg_candidate(
    m: &str,
    opt_ifaces: &[String],
    roles: &std::collections::HashMap<String, String>,
    custom_rules: &CustomRulesFile,
) -> Result<(), String> {
    if m.starts_with("lagg") {
        return Err(format!(
            "'{m}' is itself a LAGG interface - it cannot be nested inside another LAGG group."
        ));
    }
    if !opt_ifaces.contains(&m.to_string()) {
        return Err(format!(
            "Interface '{m}' is not an available OPT zone - only unused OPT interfaces can be LAGG members."
        ));
    }
    let role = roles.get(m).map(|s| s.as_str()).unwrap_or("Undefined");
    if role != "Undefined" {
        return Err(format!(
            "Interface '{m}' already has Role={role} assigned - remove its role first before using it as a LAGG member (LAGG members must be genuinely unused ports)."
        ));
    }
    if custom_rules.rules.iter().any(|r| r.interface == m) {
        return Err(format!(
            "Interface '{m}' already has custom Firewall rules configured - remove them first before using it as a LAGG member."
        ));
    }
    Ok(())
}

fn validate_lagg_members(members: &[String]) -> Result<(), String> {
    if members.len() < 2 {
        return Err("At least 2 member interfaces are required for link aggregation.".to_string());
    }
    let (_mgmt_if, _lan1_if, opt_ifaces) = parse_pf_conf_zones();
    let roles = load_roles();
    let custom_rules = load_custom_rules();

    for m in members {
        validate_single_lagg_candidate(m, &opt_ifaces, &roles, &custom_rules)?;
    }
    Ok(())
}

fn lagg_create(members: &[String], protocol: &str) -> Result<String, String> {
    let valid_protocols = ["failover", "lacp", "loadbalance", "roundrobin"];
    if !valid_protocols.contains(&protocol) {
        return Err(format!(
            "Invalid protocol '{protocol}' - must be one of: {}",
            valid_protocols.join(", ")
        ));
    }
    validate_lagg_members(members)?;

    let lagg_name = next_available_lagg_name();

    // RCA (ditemukan nyata - bro coba LAGG-kan OPT2/em3 yang sebelumnya
    // sudah diberi IP statis lewat "Save subnet", dapat error "IP '' is
    // not valid" waktu coba kosongkan lewat form yang sama - form itu
    // memang TIDAK PERNAH didesain untuk mengosongkan IP, cuma untuk set
    // IP valid): daripada admin harus cari jalan manual yang tidak ada,
    // lagg_create() sendiri yang membersihkan IP lama tiap member -
    // BAIK live (ifconfig) MAUPUN persisten (rc.conf) - sebelum member
    // dipakai untuk LAGG. Member yang genuinely tidak pernah dikonfigurasi
    // (get_interface_ip() = None) dilewati saja, tidak ada yang perlu
    // dibersihkan.
    for m in members {
        if let Some(existing_ip) = get_interface_ip(m) {
            let _ = Command::new("/sbin/ifconfig").args([m.as_str(), "inet", &existing_ip, "delete"]).status();
        }
        let _ = Command::new("sysrc").arg("-x").arg(format!("ifconfig_{m}")).status();
    }

    // Urutan WAJIB (gotcha nyata dari riset): member interface di-'up'
    // dulu, BARU lagg interface dibuat dan dikonfigurasi - kalau
    // dibalik, status "no carrier" muncul dan lagg gagal dapat traffic.
    for m in members {
        let status = Command::new("/sbin/ifconfig").args([m.as_str(), "up"]).status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            return Err(format!("Failed to bring up member interface '{m}'."));
        }
    }

    let create_status = Command::new("/sbin/ifconfig").args([lagg_name.as_str(), "create"]).status();
    if create_status.map(|s| !s.success()).unwrap_or(true) {
        return Err(format!("Failed to create '{lagg_name}' (ifconfig {lagg_name} create)."));
    }

    let mut cfg_args: Vec<String> = vec![lagg_name.clone(), "up".to_string(), "laggproto".to_string(), protocol.to_string()];
    for m in members {
        cfg_args.push("laggport".to_string());
        cfg_args.push(m.clone());
    }
    let cfg_status = Command::new("/sbin/ifconfig").args(&cfg_args).status();
    if cfg_status.map(|s| !s.success()).unwrap_or(true) {
        // Rollback - hapus lagg interface yang terlanjur dibuat supaya
        // tidak meninggalkan interface setengah-jadi kalau langkah ini gagal.
        let _ = Command::new("/sbin/ifconfig").args([lagg_name.as_str(), "destroy"]).status();
        return Err(format!("Failed to configure '{lagg_name}' with laggproto {protocol}."));
    }

    // Persist ke rc.conf - pola resmi FreeBSD Handbook:
    // cloned_interfaces="laggN" + ifconfig_laggN="up laggproto ... laggport ... laggport ..."
    let existing_cloned = Command::new("sysrc")
        .args(["-n", "cloned_interfaces"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let new_cloned = if existing_cloned.is_empty() {
        lagg_name.clone()
    } else if existing_cloned.split_whitespace().any(|s| s == lagg_name) {
        existing_cloned.clone()
    } else {
        format!("{existing_cloned} {lagg_name}")
    };
    let _ = Command::new("sysrc").arg(format!("cloned_interfaces={new_cloned}")).status();

    let laggport_str = members.iter().map(|m| format!("laggport {m}")).collect::<Vec<_>>().join(" ");
    let _ = Command::new("sysrc")
        .arg(format!("ifconfig_{lagg_name}=up laggproto {protocol} {laggport_str}"))
        .status();

    // pf.conf: hapus marker+isi SETIAP member, sisipkan SATU marker baru
    // untuk lagg_name - lihat splice_lagg_marker() untuk detail.
    splice_lagg_marker(members, &lagg_name)?;

    Ok(lagg_name)
}

/// Mengganti N blok marker (member lama) dengan 1 blok marker baru
/// (interface lagg) dalam SATU pass baca-tulis, divalidasi dengan
/// pfctl -nf SEBELUM ditulis ke /etc/pf.conf - prinsip yang sama
/// dipegang di seluruh project ini untuk setiap perubahan pf.conf.
fn splice_lagg_marker(members: &[String], lagg_name: &str) -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    let mut lines: Vec<&str> = content.lines().collect();

    // Hapus SETIAP baris marker (START dan END) milik member - blok ini
    // dipastikan kosong oleh validate_lagg_members() (tidak ada custom
    // rule), jadi aman dihapus tanpa kehilangan konfigurasi apa pun.
    // Baris marker START dijadikan titik sisip untuk marker baru (posisi
    // member PERTAMA yang ditemukan) supaya lagg muncul di lokasi yang
    // masuk akal (bekas posisi salah satu member-nya), bukan di ujung file.
    let mut insert_at: Option<usize> = None;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        let is_member_start = members.iter().any(|m| line == format!("# NTPSENSE_CUSTOM_RULES_{m}_START"));
        let is_member_end = members.iter().any(|m| line == format!("# NTPSENSE_CUSTOM_RULES_{m}_END"));
        if is_member_start {
            if insert_at.is_none() {
                insert_at = Some(i);
            }
            lines.remove(i);
            continue;
        }
        if is_member_end {
            lines.remove(i);
            continue;
        }
        i += 1;
    }

    let insert_at = insert_at.ok_or_else(|| {
        "Could not find marker blocks for the given member interfaces in /etc/pf.conf.".to_string()
    })?;

    let new_marker_start = format!("# NTPSENSE_CUSTOM_RULES_{lagg_name}_START");
    let new_marker_end = format!("# NTPSENSE_CUSTOM_RULES_{lagg_name}_END");
    lines.insert(insert_at, new_marker_end.as_str());
    lines.insert(insert_at, new_marker_start.as_str());

    let new_content = lines.join("\n") + "\n";

    // Validasi WAJIB sebelum tulis - draft ke file temp dulu.
    let tmp_path = "/tmp/pf.conf.lagg-new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft pf.conf: {e}"))?;
    let check = Command::new("pfctl").args(["-nf", tmp_path]).output();
    match check {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            return Err(format!(
                "pf.conf validation failed after LAGG marker splice, NOT applied: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
        }
        Err(e) => return Err(format!("Failed to run pfctl -nf: {e}")),
    }

    fs::write("/etc/pf.conf", &new_content).map_err(|e| format!("Failed to write /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();

    Ok(())
}

fn lagg_delete(lagg_name: &str) -> Result<(), String> {
    if !lagg_name.starts_with("lagg") {
        return Err("Not a lagg interface.".to_string());
    }
    // Cek marker punya custom rule - kalau ADA, tolak (sama disiplin
    // seperti validate_lagg_members: jangan hancurkan konfigurasi aktif
    // tanpa admin menghapusnya dulu secara eksplisit).
    let custom_rules = load_custom_rules();
    if custom_rules.rules.iter().any(|r| r.interface == lagg_name) {
        return Err(format!(
            "'{lagg_name}' still has custom Firewall rules - remove them first before deleting this LAGG group."
        ));
    }

    // Ambil daftar member SEBELUM di-destroy - dibutuhkan untuk
    // mengembalikan marker OPT individual masing-masing setelahnya
    // (RCA: dikonfirmasi dari dokumentasi resmi pfSense + forum Netgate
    // - member yang dilepas dari LAGG SEHARUSNYA otomatis bisa
    // di-assign lagi sebagai interface mandiri, bukan "hilang" tanpa
    // marker/zona apa pun - perilaku yang sama dikonfirmasi juga di
    // FortiGate: interface disembunyikan HANYA selama jadi member,
    // muncul kembali begitu dilepas).
    let (_protocol, members) = lagg_get_current_state(lagg_name);

    let _ = Command::new("/sbin/ifconfig").args([lagg_name, "destroy"]).status();

    let existing_cloned = Command::new("sysrc")
        .args(["-n", "cloned_interfaces"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let new_cloned: Vec<&str> = existing_cloned.split_whitespace().filter(|s| *s != lagg_name).collect();
    let _ = Command::new("sysrc").arg(format!("cloned_interfaces={}", new_cloned.join(" "))).status();
    let _ = Command::new("sysrc").arg("-x").arg(format!("ifconfig_{lagg_name}")).status();

    // Ganti marker lagg dengan marker INDIVIDUAL untuk setiap member -
    // member kembali terlihat sebagai OPT mandiri di Physical
    // Interfaces (parse_pf_conf_zones() otomatis mendeteksinya lagi,
    // sama seperti waktu marker individual pertama kali ada, sebelum
    // di-LAGG-kan).
    if let Ok(content) = fs::read_to_string("/etc/pf.conf") {
        let start_marker = format!("# NTPSENSE_CUSTOM_RULES_{lagg_name}_START");
        let end_marker = format!("# NTPSENSE_CUSTOM_RULES_{lagg_name}_END");
        let mut new_lines: Vec<String> = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == start_marker {
                for m in &members {
                    new_lines.push(format!("# NTPSENSE_CUSTOM_RULES_{m}_START"));
                    new_lines.push(format!("# NTPSENSE_CUSTOM_RULES_{m}_END"));
                }
                continue;
            }
            if trimmed == end_marker {
                continue;
            }
            new_lines.push(line.to_string());
        }
        let new_content = new_lines.join("\n") + "\n";
        let tmp_path = "/tmp/pf.conf.lagg-delete";
        if fs::write(tmp_path, &new_content).is_ok() {
            if let Ok(o) = Command::new("pfctl").args(["-nf", tmp_path]).output() {
                if o.status.success() {
                    let _ = fs::write("/etc/pf.conf", &new_content);
                    let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();
                }
            }
        }
    }

    // Pastikan member fisik tetap 'up' (sudah dilakukan waktu lagg
    // dibuat, tapi dipastikan lagi di sini supaya genuinely langsung
    // bisa dipakai tanpa langkah tambahan dari admin).
    for m in &members {
        let _ = Command::new("/sbin/ifconfig").args([m.as_str(), "up"]).status();
    }

    Ok(())
}

/// Baca member port + protokol SAAT INI dari sebuah lagg interface via
/// 'ifconfig <lagg>' - dipakai bersama oleh network.lagg_list DAN
/// lagg_edit() (satu sumber kebenaran, bukan parsing duplikat).
fn lagg_get_current_state(lagg_name: &str) -> (String, Vec<String>) {
    let output = Command::new("/sbin/ifconfig").arg(lagg_name).output().ok();
    let text = output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let protocol = text
        .lines()
        .find(|l| l.trim_start().starts_with("laggproto"))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("unknown")
        .to_string();
    let members: Vec<String> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("laggport:"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string())
        .collect();
    (protocol, members)
}

/// Edit grup LAGG yang sudah ada - GENUINELY live (tanpa destroy+
/// recreate), memanfaatkan dukungan asli FreeBSD lagg(4): laggproto
/// bisa diganti langsung, member ditambah via 'laggport <if>' dan
/// dilepas via '-laggport <if>' TANPA membongkar interface lagg itu
/// sendiri (dikonfirmasi dari man page resmi + riset - bukan tebakan).
/// Ini juga konsisten dengan cara Cisco EtherChannel/Linux bonding
/// menangani perubahan port/protokol - umumnya tidak wajib bongkar-
/// pasang total untuk perubahan sesederhana ini.
///
/// Member yang SUDAH jadi bagian grup ini boleh tetap dipertahankan
/// walau tidak lagi "eligible" secara independen (karena memang sudah
/// terpakai OLEH grup ini sendiri) - hanya member BARU yang divalidasi
/// lewat validate_single_lagg_candidate(), sama seperti lagg_create().
fn lagg_edit(lagg_name: &str, new_members: &[String], new_protocol: &str) -> Result<(), String> {
    let valid_protocols = ["failover", "lacp", "loadbalance", "roundrobin"];
    if !valid_protocols.contains(&new_protocol) {
        return Err(format!(
            "Invalid protocol '{new_protocol}' - must be one of: {}",
            valid_protocols.join(", ")
        ));
    }
    if new_members.len() < 2 {
        return Err("At least 2 member interfaces are required for link aggregation.".to_string());
    }
    if !lagg_name.starts_with("lagg") {
        return Err("Not a lagg interface.".to_string());
    }

    let (current_protocol, current_members) = lagg_get_current_state(lagg_name);
    if current_protocol == "unknown" && current_members.is_empty() {
        return Err(format!("Could not read current state of '{lagg_name}' - does it exist?"));
    }

    // Validasi HANYA member yang BENAR-BENAR baru (bukan sudah jadi
    // bagian grup ini sebelumnya) - member existing tidak perlu lolos
    // cek eligibility lagi (mereka memang sudah "terpakai" oleh grup
    // yang sedang diedit ini sendiri, itu wajar).
    let (_, _, opt_ifaces) = parse_pf_conf_zones();
    let roles = load_roles();
    let custom_rules = load_custom_rules();
    for m in new_members {
        if !current_members.contains(m) {
            validate_single_lagg_candidate(m, &opt_ifaces, &roles, &custom_rules)?;
        }
    }

    // Member baru yang belum pernah 'up' - bawa up dulu (gotcha yang
    // sama seperti lagg_create - member harus up SEBELUM dipakai lagg,
    // kalau tidak "no carrier").
    for m in new_members {
        if !current_members.contains(m) {
            let status = Command::new("/sbin/ifconfig").args([m.as_str(), "up"]).status();
            if status.map(|s| !s.success()).unwrap_or(true) {
                return Err(format!("Failed to bring up new member interface '{m}'."));
            }
        }
    }

    // Ganti protokol dulu (kalau beda) - laggproto bisa diganti live
    // tanpa mempengaruhi member yang sudah terpasang.
    if current_protocol != new_protocol {
        let status = Command::new("/sbin/ifconfig")
            .args([lagg_name, "laggproto", new_protocol])
            .status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            return Err(format!("Failed to change protocol to '{new_protocol}'."));
        }
    }

    // Lepas member yang TIDAK LAGI diinginkan (ada di current, tidak
    // ada di new_members) - DAN kembalikan marker OPT individual untuk
    // masing-masing, supaya langsung terlihat lagi sebagai interface
    // mandiri di Physical Interfaces (RCA sama seperti lagg_delete() -
    // dikonfirmasi dari dokumentasi resmi pfSense: member yang dilepas
    // dari LAGG SEHARUSNYA otomatis bisa di-assign lagi, bukan hilang
    // tanpa marker/zona apa pun).
    let released: Vec<String> = current_members.iter().filter(|m| !new_members.contains(m)).cloned().collect();
    for m in &released {
        let _ = Command::new("/sbin/ifconfig").args([lagg_name, "-laggport", m.as_str()]).status();
    }
    if !released.is_empty() {
        if let Ok(content) = fs::read_to_string("/etc/pf.conf") {
            let lagg_start_marker = format!("# NTPSENSE_CUSTOM_RULES_{lagg_name}_START");
            let mut new_lines: Vec<String> = Vec::new();
            for line in content.lines() {
                if line.trim() == lagg_start_marker {
                    for m in &released {
                        new_lines.push(format!("# NTPSENSE_CUSTOM_RULES_{m}_START"));
                        new_lines.push(format!("# NTPSENSE_CUSTOM_RULES_{m}_END"));
                    }
                }
                new_lines.push(line.to_string());
            }
            let new_content = new_lines.join("\n") + "\n";
            let tmp_path = "/tmp/pf.conf.lagg-edit";
            if fs::write(tmp_path, &new_content).is_ok() {
                if let Ok(o) = Command::new("pfctl").args(["-nf", tmp_path]).output() {
                    if o.status.success() {
                        let _ = fs::write("/etc/pf.conf", &new_content);
                        let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();
                    }
                }
            }
        }
        for m in &released {
            let _ = Command::new("/sbin/ifconfig").args([m.as_str(), "up"]).status();
        }
    }
    // Tambah member yang BARU diinginkan (ada di new_members, belum ada
    // di current).
    let newly_added: Vec<String> = new_members.iter().filter(|m| !current_members.contains(m)).cloned().collect();
    for m in &newly_added {
        let status = Command::new("/sbin/ifconfig").args([lagg_name, "laggport", m.as_str()]).status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            return Err(format!("Failed to add member '{m}' to '{lagg_name}'."));
        }
    }
    // Hapus marker individual member yang BARU diserap - begitu jadi
    // member, tidak lagi terlihat sebagai OPT mandiri (sama seperti
    // lagg_create() - marker individualnya dihapus, digantikan marker
    // lagg yang sudah ada, TIDAK perlu marker baru disisipkan karena
    // marker lagg_name sendiri sudah ada sejak awal).
    if !newly_added.is_empty() {
        if let Ok(content) = fs::read_to_string("/etc/pf.conf") {
            let lines: Vec<&str> = content
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !newly_added.iter().any(|m| {
                        t == format!("# NTPSENSE_CUSTOM_RULES_{m}_START") || t == format!("# NTPSENSE_CUSTOM_RULES_{m}_END")
                    })
                })
                .collect();
            let new_content = lines.join("\n") + "\n";
            let tmp_path = "/tmp/pf.conf.lagg-edit-add";
            if fs::write(tmp_path, &new_content).is_ok() {
                if let Ok(o) = Command::new("pfctl").args(["-nf", tmp_path]).output() {
                    if o.status.success() {
                        let _ = fs::write("/etc/pf.conf", &new_content);
                        let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();
                    }
                }
            }
        }
    }

    // Persist ke rc.conf - tulis ulang ifconfig_laggN dengan state BARU
    // secara utuh (bukan diff), supaya pasti konsisten dengan apa yang
    // baru saja diterapkan live di atas.
    let laggport_str = new_members.iter().map(|m| format!("laggport {m}")).collect::<Vec<_>>().join(" ");
    let _ = Command::new("sysrc")
        .arg(format!("ifconfig_{lagg_name}=up laggproto {new_protocol} {laggport_str}"))
        .status();

    Ok(())
}

// ============================================================
// VLAN Interfaces (802.1Q) - riset 4 vendor rujukan (FortiGate, pfSense,
// Palo Alto, Sangfor) + Cisco L2/L3 sebelum desain, disepakati bareng
// bro: (1) parent BOLEH interface yang sudah punya IP/zone sendiri
// (Physical atau LAGG, TIDAK BOLEH MGMT ataupun VLAN lain - no nested
// VLAN, pelajaran sama dengan "lagg0 tidak masuk akal jadi member LAGG
// baru"), dengan WARNING (bukan blok) kalau parent-nya sudah ada IP -
// mirip konsep "native VLAN" Cisco, traffic untagged tetap ke zona
// parent, traffic tagged ke VLAN baru; (2) Type baru "VLAN" sejajar
// Physical/LAGG di taxonomy yang sudah ada, jadi slot OPT zone baru -
// detect_interface_type() SUDAH forward-compatible untuk ini sejak
// awal (cek prefix 'vlan'), tidak perlu diubah.
//
// Alat: ifconfig + vlan(4) kernel module - dikonfirmasi dari ifconfig(8)
// man page resmi ("vlan vlan_tag" + "vlandev iface" harus diset
// bersamaan), BUKAN etherswitchcfg (itu untuk chip switch fisik
// tertanam di board SoC, tidak relevan untuk NIC generic Mini
// PC/rackmount yang jadi target hardware project ini).
//
// VLAN ID 0 dan 4095 reserved sesuai standar 802.1Q (dikonfirmasi
// FortiGate KB) - range valid 1-4094. Parent+VLAN ID immutable setelah
// dibuat (pola FortiGate persis) - ganti berarti hapus lalu buat ulang,
// bukan edit in-place, supaya tidak ada state ifconfig yang setengah-
// konsisten dengan rc.conf.
// ============================================================

/// Ambil wan1_if SAJA - parse_pf_conf_zones() sudah extract macro ini
/// secara internal tapi tidak mengembalikannya di tuple (3 return value
/// yang sudah ada dipakai banyak caller lain, sengaja TIDAK diubah
/// signature-nya supaya tidak perlu update semua call site yang sudah
/// ada) - helper kecil terpisah ini reuse pola extract_macro yang sama.
fn get_wan1_interface() -> Option<String> {
    let content = fs::read_to_string("/etc/pf.conf").ok()?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("wan1_if = \"") {
            return rest.strip_suffix('"').map(|s| s.to_string());
        }
    }
    None
}

fn get_existing_vlan_names() -> Vec<String> {
    let output = match Command::new("/sbin/ifconfig").arg("-l").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|s| s.starts_with("vlan"))
        .map(|s| s.to_string())
        .collect()
}

// (next_available_vlan_name() dihapus - interface sekarang dinamai
// LANGSUNG dari VLAN ID, "vlan{tag}", bukan urutan sequential vlan0/
// vlan1/vlan2 lagi. RCA nyata dari bro: penamaan sequential itu
// benar-benar membingungkan admin - VLAN ID 10 jadi interface "vlan0"
// tidak ada hubungan sama sekali secara visual, harus selalu buka
// tabel buat cocokkan mana-ke-mana. Ini juga lebih dekat konvensi
// FreeBSD community sungguhan (dikonfirmasi dari beberapa contoh
// forum resmi - interface sering dinamai "vlan100"/"vlan200" persis
// tag-nya, bukan "vlan0"/"vlan1"), jadi bukan sekadar preferensi UX
// tapi juga lebih idiomatis.

/// Baca tag + parent SAAT INI dari sebuah vlan interface via
/// 'ifconfig <vlan_name>' - format output DIKONFIRMASI dari beberapa
/// sample forum FreeBSD resmi (bukan tebakan): satu baris berisi
/// "vlan: <tag> vlanproto: 802.1q vlanpcp: <n> parent interface: <if>".
/// Parsing berbasis token whitespace, BUKAN asumsi nomor kolom tetap -
/// robust terhadap variasi versi FreeBSD yang mungkin geser urutan
/// field vlanproto/vlanpcp.
fn get_vlan_current_state(vlan_name: &str) -> Option<(u16, String)> {
    let output = Command::new("/sbin/ifconfig").arg(vlan_name).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut tag: Option<u16> = None;
    let mut parent: Option<String> = None;
    for i in 0..tokens.len() {
        if tokens[i] == "vlan:" && i + 1 < tokens.len() {
            tag = tokens[i + 1].parse::<u16>().ok();
        }
        if tokens[i] == "parent" && tokens.get(i + 1) == Some(&"interface:") && i + 2 < tokens.len() {
            parent = Some(tokens[i + 2].to_string());
        }
    }
    match (tag, parent) {
        (Some(t), Some(p)) => Some((t, p)),
        _ => None,
    }
}

/// Interface yang boleh jadi parent VLAN: LAN1/WAN1/OPT (fisik, sudah
/// ada IP atau belum - keduanya diizinkan sesuai kesepakatan) DAN
/// setiap LAGG yang ada - TIDAK PERNAH MGMT (fixed by design, sama
/// seperti larangan LAGG member) dan TIDAK PERNAH interface VLAN lain
/// (no nested VLAN).
fn get_vlan_eligible_parents() -> Vec<String> {
    let (_mgmt_if, lan1_if, opt_ifaces) = parse_pf_conf_zones();
    let wan1_if = get_wan1_interface();
    let mut parents: Vec<String> = Vec::new();
    if let Some(l) = lan1_if {
        parents.push(l);
    }
    if let Some(w) = wan1_if {
        if !parents.contains(&w) {
            parents.push(w);
        }
    }
    for o in opt_ifaces {
        // opt_ifaces dari parse_pf_conf_zones() sudah termasuk LAGG
        // (marker-based detection generik) - TAPI belum termasuk VLAN
        // yang sudah ada sendiri (kita exclude eksplisit di bawah,
        // no nested VLAN).
        if !o.starts_with("vlan") && !parents.contains(&o) {
            parents.push(o);
        }
    }
    parents
}

fn validate_vlan_tag(tag: u16) -> Result<(), String> {
    if !(1..=4094).contains(&tag) {
        return Err("VLAN tag must be between 1 and 4094 (0 and 4095 are reserved by the 802.1Q standard).".to_string());
    }
    Ok(())
}

fn validate_vlan_parent(parent: &str) -> Result<(), String> {
    let (mgmt_if, _lan1_if, _opt_ifaces) = parse_pf_conf_zones();
    if mgmt_if.as_deref() == Some(parent) {
        return Err("The MGMT interface cannot be used as a VLAN parent - it is fixed by design.".to_string());
    }
    if parent.starts_with("vlan") {
        return Err(format!("'{parent}' is itself a VLAN interface - it cannot be nested inside another VLAN."));
    }
    if !get_vlan_eligible_parents().contains(&parent.to_string()) {
        return Err(format!("'{parent}' is not a currently known LAN1/WAN1/OPT/LAGG interface."));
    }
    Ok(())
}

/// Insert marker pf.conf BARU untuk interface yang genuinely baru -
/// TIDAK menggantikan marker siapa pun (beda dari splice_lagg_marker,
/// yang memang "menyerap" marker member) karena parent VLAN TETAP
/// punya marker/zona sendiri yang utuh (parent tidak "dikonsumsi" -
/// bisa sekaligus tetap dipakai untuk traffic untagged-nya sendiri).
/// Pola sama persis dengan ensure_ipsec_pf_marker() untuk enc0.
fn ensure_pf_marker_for_interface(iface: &str) -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    let start_marker = format!("# NTPSENSE_CUSTOM_RULES_{iface}_START");
    if content.contains(&start_marker) {
        return Ok(());
    }
    let end_marker = format!("# NTPSENSE_CUSTOM_RULES_{iface}_END");
    let anchor = "\nblock log all\n";
    let Some(idx) = content.find(anchor) else {
        return Err("Could not find 'block log all' anchor in /etc/pf.conf to insert VLAN marker".to_string());
    };
    let insert_at = idx + anchor.len();
    let new_content = format!("{}\n{start_marker}\n{end_marker}\n\n{}", &content[..insert_at], &content[insert_at..]);

    let tmp_path = "/tmp/pf.conf.vlan-new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed after adding VLAN marker, NOT applied. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

fn remove_pf_marker_for_interface(iface: &str) -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    let start_marker = format!("# NTPSENSE_CUSTOM_RULES_{iface}_START");
    let end_marker = format!("# NTPSENSE_CUSTOM_RULES_{iface}_END");
    let mut lines: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in content.lines() {
        let t = line.trim();
        if t == start_marker {
            inside = true;
            continue;
        }
        if t == end_marker {
            inside = false;
            continue;
        }
        if inside {
            continue;
        }
        lines.push(line);
    }
    let new_content = lines.join("\n") + "\n";
    let tmp_path = "/tmp/pf.conf.vlan-delete";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed while removing VLAN marker, NOT applied. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

/// Return (vlan_name, parent_has_ip) - flag kedua dipakai PHP untuk
/// tampilkan pesan sukses yang mengingatkan soal native-VLAN-style
/// traffic split kalau relevan (parent sudah ada IP-nya sendiri).
fn vlan_create(parent: &str, tag: u16) -> Result<(String, bool), String> {
    validate_vlan_tag(tag)?;
    validate_vlan_parent(parent)?;

    // Enforced 2-step flow (Cisco): VLAN ID HARUS sudah didefinisikan
    // di VLAN Database (ID+Name) dulu sebelum bisa di-bind ke parent
    // mana pun - persis seperti 'switchport access vlan 10' yang akan
    // ditolak IOS kalau 'vlan 10' belum pernah dibuat di database.
    if !load_vlan_database().vlans.iter().any(|v| v.id == tag) {
        return Err(format!(
            "VLAN ID {tag} is not defined in the VLAN Database yet - add it there first (with a name) before binding it to a parent interface."
        ));
    }

    // Cegah duplikat: dengan penamaan langsung "vlan{tag}", satu VLAN
    // ID cuma bisa punya SATU interface/binding pada satu waktu -
    // dicek eksplisit di sini (bukan cuma mengandalkan ifconfig create
    // gagal sendiri) supaya pesan error-nya jelas menyebutkan parent
    // yang SEDANG dipakai, bukan sekadar "already exists" generik.
    let vlan_name = format!("vlan{tag}");
    if get_existing_vlan_names().contains(&vlan_name) {
        let current_parent = get_vlan_current_state(&vlan_name)
            .map(|(_, p)| p)
            .unwrap_or_else(|| "unknown".to_string());
        return Err(format!(
            "VLAN {tag} ('{vlan_name}') already exists, bound to parent '{current_parent}' - delete it first before recreating it on a different parent."
        ));
    }

    let parent_has_ip = get_interface_ip(parent).is_some();

    // Pastikan parent 'up' dulu - pelajaran sama dengan LAGG (walau
    // vlan(4) tidak punya isu "no carrier" yang sama persis, tetap
    // best practice supaya parent siap terima/kirim traffic tagged).
    let _ = Command::new("/sbin/ifconfig").args([parent, "up"]).status();

    let create_status = Command::new("/sbin/ifconfig").args([vlan_name.as_str(), "create"]).status();
    if create_status.map(|s| !s.success()).unwrap_or(true) {
        return Err(format!("Failed to create '{vlan_name}' (ifconfig {vlan_name} create)."));
    }

    let cfg_status = Command::new("/sbin/ifconfig")
        .args([vlan_name.as_str(), "vlan", &tag.to_string(), "vlandev", parent, "up"])
        .status();
    if cfg_status.map(|s| !s.success()).unwrap_or(true) {
        let _ = Command::new("/sbin/ifconfig").args([vlan_name.as_str(), "destroy"]).status();
        return Err(format!("Failed to configure '{vlan_name}' with vlan {tag} vlandev {parent}."));
    }

    // Persist ke rc.conf - pola sama persis dengan LAGG (satu variabel
    // ifconfig_vlanN berisi seluruh parameter, dikonfirmasi valid dari
    // beberapa contoh rc.conf resmi FreeBSD di forum).
    let existing_cloned = Command::new("sysrc")
        .args(["-n", "cloned_interfaces"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let new_cloned = if existing_cloned.is_empty() {
        vlan_name.clone()
    } else if existing_cloned.split_whitespace().any(|s| s == vlan_name) {
        existing_cloned.clone()
    } else {
        format!("{existing_cloned} {vlan_name}")
    };
    let _ = Command::new("sysrc").arg(format!("cloned_interfaces={new_cloned}")).status();
    let _ = Command::new("sysrc").arg(format!("ifconfig_{vlan_name}=vlan {tag} vlandev {parent} up")).status();

    if let Err(e) = ensure_pf_marker_for_interface(&vlan_name) {
        // Rollback interface yang terlanjur dibuat kalau marker pf.conf
        // gagal disisipkan - jangan tinggalkan VLAN yang tidak akan
        // pernah muncul sebagai zona di Web UI.
        let _ = Command::new("/sbin/ifconfig").args([vlan_name.as_str(), "destroy"]).status();
        let _ = Command::new("sysrc").arg("-x").arg(format!("ifconfig_{vlan_name}")).status();
        return Err(e);
    }

    // Salin Name dari VLAN Database jadi Alias interface secara
    // otomatis - RCA nyata dari bro: tanpa ini, tabel "VLAN Interfaces"
    // selalu tampil "(unnamed)" padahal nama sudah diketik di VLAN
    // Database sebelumnya, admin jadi harus ketik ulang manual lewat
    // Edit. Non-fatal kalau gagal ditulis (interface-nya tetap valid
    // dan sudah jadi, cuma alias-nya kosong) - tidak perlu rollback
    // seluruh proses create hanya karena file alias gagal ditulis.
    if let Some(entry) = load_vlan_database().vlans.iter().find(|v| v.id == tag) {
        let mut aliases = load_aliases();
        aliases.insert(vlan_name.clone(), entry.name.clone());
        let _ = save_aliases(&aliases);
    }

    Ok((vlan_name, parent_has_ip))
}

fn vlan_delete(vlan_name: &str) -> Result<(), String> {
    if !vlan_name.starts_with("vlan") {
        return Err("Not a VLAN interface.".to_string());
    }
    let custom_rules = load_custom_rules();
    if custom_rules.rules.iter().any(|r| r.interface == vlan_name) {
        return Err(format!(
            "'{vlan_name}' still has custom Firewall rules - remove them first before deleting this VLAN interface."
        ));
    }

    let _ = Command::new("/sbin/ifconfig").args([vlan_name, "destroy"]).status();

    let existing_cloned = Command::new("sysrc")
        .args(["-n", "cloned_interfaces"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let new_cloned: Vec<&str> = existing_cloned.split_whitespace().filter(|s| *s != vlan_name).collect();
    let _ = Command::new("sysrc").arg(format!("cloned_interfaces={}", new_cloned.join(" "))).status();
    let _ = Command::new("sysrc").arg("-x").arg(format!("ifconfig_{vlan_name}")).status();

    // Parent TIDAK PERLU dikembalikan/dipulihkan apa pun (beda dari
    // LAGG delete) - parent tidak pernah "diserap", zonanya sendiri
    // tetap utuh sepanjang waktu VLAN ini ada.
    remove_pf_marker_for_interface(vlan_name)?;

    Ok(())
}

// --- VLAN Database (ID + Name katalog, Cisco-style) - lihat komentar
// struct VlanDbEntry untuk alasan pemisahan ini dari vlan_create/delete
// di atas (yang mengurus BINDING ke parent, bukan identitas VLAN itu
// sendiri).

fn vlan_db_create(id: u16, name: &str) -> Result<(), String> {
    validate_vlan_tag(id)?;
    let name = name.trim();
    if name.is_empty() {
        return Err("VLAN name cannot be empty.".to_string());
    }
    if name.len() > 32 {
        return Err("VLAN name must be 32 characters or fewer.".to_string());
    }
    let mut db = load_vlan_database();
    if db.vlans.iter().any(|v| v.id == id) {
        return Err(format!("VLAN ID {id} already exists in the VLAN Database."));
    }
    db.vlans.push(VlanDbEntry { id, name: name.to_string() });
    db.vlans.sort_by_key(|v| v.id);
    save_vlan_database(&db)
}

/// Cegah hapus entry VLAN Database yang masih dipakai satu atau lebih
/// interface aktual (vlan(4) terikat ke parent) - sama prinsipnya
/// dengan larangan hapus Role yang masih di-assign ke user: hindari
/// keadaan "interface hidup tapi identitas VLAN-nya sudah hilang dari
/// katalog", membingungkan tanpa manfaat apa pun.
fn vlan_db_delete(id: u16) -> Result<(), String> {
    let bound: Vec<String> = get_existing_vlan_names()
        .iter()
        .filter_map(|name| get_vlan_current_state(name).map(|(tag, _)| (name.clone(), tag)))
        .filter(|(_, tag)| *tag == id)
        .map(|(name, _)| name)
        .collect();
    if !bound.is_empty() {
        return Err(format!(
            "VLAN ID {id} is still bound to interface(s): {} - delete those VLAN interfaces first.",
            bound.join(", ")
        ));
    }
    let mut db = load_vlan_database();
    let before = db.vlans.len();
    db.vlans.retain(|v| v.id != id);
    if db.vlans.len() == before {
        return Err(format!("VLAN ID {id} not found in the VLAN Database."));
    }
    save_vlan_database(&db)
}

// ============================================================
// Loopback Interfaces (lo0, lo1, lo2, ...) - fitur baru, diminta bro
// setelah diskusi soal validasi IP duplikat (dikonfirmasi dari
// keluhan nyata operator jaringan di mailing list Juniper NSP: IP
// sama di dua interface aktif dianggap bug serius, bukan hal yang
// boleh dibiarkan). lo0 SELALU ada bawaan FreeBSD (127.0.0.1) -
// diperlakukan READ-ONLY/terkunci di sini (sama seperti MGMT), tidak
// bisa dihapus atau diubah dari Web UI. lo1, lo2, dst adalah yang
// admin bisa create/delete/assign IP sendiri - satu IP per loopback
// (versi sederhana, disepakati dengan bro - bukan multi-alamat ala
// Juniper).
//
// Validasi #4 (ARP live-conflict) SENGAJA TIDAK diterapkan di sini -
// loopback secara definisi tidak terhubung ke L2 segment fisik mana
// pun, jadi ARP probe tidak akan pernah relevan/dapat balasan
// bermakna untuk interface jenis ini.
// ============================================================

fn get_loopback_names() -> Vec<String> {
    let output = match Command::new("/sbin/ifconfig").arg("-l").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|s| s.starts_with("lo") && !s.starts_with("lagg"))
        .map(|s| s.to_string())
        .collect()
}

fn next_available_loopback_name() -> String {
    let existing = get_loopback_names();
    let mut n = 1u32; // mulai dari lo1 - lo0 selalu bawaan sistem
    loop {
        let candidate = format!("lo{n}");
        if !existing.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Validasi lengkap sebelum assign IP ke loopback baru - reuse
/// fungsi yang SAMA dipakai network.set_subnet (satu sumber
/// kebenaran untuk "apa itu IP host yang valid"), plus duplicate-
/// check terhadap SEMUA interface lain di sistem (fisik, LAGG, VPN,
/// loopback lain) - bukan cuma zona fisik seperti pada set_subnet,
/// karena loopback IP genuinely bisa bentrok dengan interface
/// APA PUN, tidak terbatas pada zona jaringan biasa.
fn validate_loopback_ip(ip: &str, prefix: u8) -> Result<(), String> {
    let Some(ip_bytes) = parse_ipv4(ip) else {
        return Err(format!("IP '{ip}' is not valid"));
    };
    if prefix == 0 || prefix > 32 {
        return Err("Prefix must be between 1-32".to_string());
    }
    if is_network_or_broadcast_address(ip_bytes, prefix) {
        return Err(format!("'{ip}' is the network or broadcast address of {ip}/{prefix} - not a valid host IP"));
    }
    if is_reserved_ip(ip_bytes) {
        return Err(format!("'{ip}' is in a reserved/special IP range and cannot be assigned"));
    }

    // Duplicate exact check - terhadap SEMUA interface lain yang
    // punya IP saat ini (zona fisik/LAGG, loopback lain) - beda dari
    // set_subnet yang cuma cek zona jaringan, di sini kita cek benar-
    // benar semua supaya konsisten dengan concern nyata dari riset
    // Juniper NSP (IP sama di DUA interface APA PUN itu masalah).
    let (mgmt_if, lan1_if, opt_ifaces) = parse_pf_conf_zones();
    let mut all_ips: Vec<String> = Vec::new();
    if let Some(m) = &mgmt_if {
        if let Some(existing) = get_interface_ip(m) {
            all_ips.push(existing);
        }
    }
    if let Some(l) = &lan1_if {
        if let Some(existing) = get_interface_ip(l) {
            all_ips.push(existing);
        }
    }
    for opt in &opt_ifaces {
        if let Some(existing) = get_interface_ip(opt) {
            all_ips.push(existing);
        }
    }
    for lo in get_loopback_names() {
        if let Some(existing) = get_interface_ip(&lo) {
            all_ips.push(existing);
        }
    }
    if all_ips.contains(&ip.to_string()) {
        return Err(format!("IP '{ip}' is already assigned to another interface on this gateway"));
    }

    Ok(())
}

fn loopback_create(ip: &str, prefix: u8) -> Result<String, String> {
    validate_loopback_ip(ip, prefix)?;
    let lo_name = next_available_loopback_name();

    let create_status = Command::new("/sbin/ifconfig").args([lo_name.as_str(), "create"]).status();
    if create_status.map(|s| !s.success()).unwrap_or(true) {
        return Err(format!("Failed to create '{lo_name}' (ifconfig {lo_name} create)."));
    }
    let cidr = format!("{ip}/{prefix}");
    let apply_status = Command::new("/sbin/ifconfig").args([lo_name.as_str(), "inet", &cidr]).status();
    if apply_status.map(|s| !s.success()).unwrap_or(true) {
        let _ = Command::new("/sbin/ifconfig").args([lo_name.as_str(), "destroy"]).status();
        return Err(format!("Failed to assign IP '{cidr}' to '{lo_name}'."));
    }

    // Persist ke rc.conf - pola sama seperti LAGG (cloned_interfaces +
    // ifconfig_<if>).
    let existing_cloned = Command::new("sysrc")
        .args(["-n", "cloned_interfaces"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let new_cloned = if existing_cloned.is_empty() {
        lo_name.clone()
    } else if existing_cloned.split_whitespace().any(|s| s == lo_name) {
        existing_cloned.clone()
    } else {
        format!("{existing_cloned} {lo_name}")
    };
    let _ = Command::new("sysrc").arg(format!("cloned_interfaces={new_cloned}")).status();
    let _ = Command::new("sysrc").arg(format!("ifconfig_{lo_name}=inet {cidr}")).status();

    Ok(lo_name)
}

fn loopback_delete(lo_name: &str) -> Result<(), String> {
    if lo_name == "lo0" {
        return Err("lo0 is the system's built-in loopback interface and cannot be deleted.".to_string());
    }
    if !lo_name.starts_with("lo") {
        return Err("Not a loopback interface.".to_string());
    }

    let _ = Command::new("/sbin/ifconfig").args([lo_name, "destroy"]).status();

    let existing_cloned = Command::new("sysrc")
        .args(["-n", "cloned_interfaces"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let new_cloned: Vec<&str> = existing_cloned.split_whitespace().filter(|s| *s != lo_name).collect();
    let _ = Command::new("sysrc").arg(format!("cloned_interfaces={}", new_cloned.join(" "))).status();
    let _ = Command::new("sysrc").arg("-x").arg(format!("ifconfig_{lo_name}")).status();

    Ok(())
}

/// Reset Interface - "default interface" ala Cisco, dibatasi ke OPT
/// saja (MGMT terkunci permanen, LAN1/WAN1 terlalu berisiko kalau
/// ke-reset tidak sengaja - bisa putus internet/akses LAN). Membersihkan
/// SEMUA konfigurasi interface itu ke kondisi awal: IP/subnet (live +
/// persisten), DHCP server, Role (balik Undefined), Alias (balik
/// default), dan custom Firewall rules. TIDAK menyentuh status
/// enable/disable port - itu genuinely konsep terpisah (operasional,
/// bukan konfigurasi), tetap seperti semula.
///
/// Ditemukan perlunya fitur ini secara nyata: admin coba siapkan OPT
/// untuk jadi member LAGG, ternyata TIDAK ADA cara mengosongkan IP yang
/// sudah di-set sebelumnya lewat Web UI (network.set_subnet cuma
/// validasi IP baru yang valid, tidak pernah didesain untuk
/// mengosongkan) - reset_interface() ini solusi umum, bukan cuma
/// tempelan khusus kasus LAGG.
fn reset_interface(interface: &str) -> Result<(), String> {
    let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
    let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
    if mgmt_if.as_deref() == Some(interface) {
        return Err("MGMT cannot be reset - it is permanently locked.".to_string());
    }
    if lan1_if.as_deref() == Some(interface) || wan1_if.as_deref() == Some(interface) {
        return Err("LAN1/WAN1 cannot be reset via this action - resetting the trusted default zone or internet uplink is too disruptive to do casually.".to_string());
    }
    if !opt_ifaces.contains(&interface.to_string()) {
        return Err(format!("Interface '{interface}' is not a recognized OPT zone."));
    }

    // 1. IP/subnet - live + persisten (pola sama seperti dipakai
    // lagg_create() untuk membersihkan member sebelum digabung).
    if let Some(existing_ip) = get_interface_ip(interface) {
        let _ = Command::new("/sbin/ifconfig").args([interface, "inet", &existing_ip, "delete"]).status();
    }
    let _ = Command::new("sysrc").arg("-x").arg(format!("ifconfig_{interface}")).status();

    // 2. DHCP server - hapus config, regenerate Kea supaya subnet yang
    // sudah tidak ada lagi tidak ikut disajikan.
    let mut dhcp_configs = load_dhcp_configs();
    if dhcp_configs.remove(interface).is_some() {
        save_dhcp_configs(&dhcp_configs)?;
        regenerate_kea_config()?;
    }

    // 3. Role - balik ke Undefined (hapus entry, default sudah Undefined
    // kalau tidak ada di map - lihat network.zones roles.get(...)
    // unwrap_or("Undefined")).
    let mut roles = load_roles();
    roles.remove(interface);
    save_roles(&roles)?;

    // 4. Alias - balik ke default (hapus entry custom, network.zones
    // sudah fallback ke "OPT{n}" kalau tidak ada di map).
    let mut aliases = load_aliases();
    aliases.remove(interface);
    save_aliases(&aliases)?;

    // 5. Custom Firewall rules - hapus SEMUA rule milik interface ini
    // (baik dari daftar tersimpan MAUPUN dari pf.conf-nya).
    let mut custom_rules = load_custom_rules();
    let had_rules = custom_rules.rules.iter().any(|r| r.interface == interface);
    if had_rules {
        custom_rules.rules.retain(|r| r.interface != interface);
        save_custom_rules(&custom_rules)?;
        regenerate_pf_conf_for_interface(interface, &[])?;
    }

    // 5b. Zone Group membership - interface yang di-destroy TIDAK BOLEH
    // tertinggal sebagai anggota grup manapun.
    let mut zone_groups = load_zone_groups();
    let mut zone_groups_changed = false;
    for group in zone_groups.groups.iter_mut() {
        let before = group.member_interfaces.len();
        group.member_interfaces.retain(|m| m != interface);
        if group.member_interfaces.len() != before {
            zone_groups_changed = true;
        }
    }
    if zone_groups_changed {
        let _ = save_zone_groups(&zone_groups);
    }

    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DhcpReservation {
    interface: String,
    mac: String,
    ip: String,
    hostname: String,
}

fn load_dhcp_reservations() -> Vec<DhcpReservation> {
    fs::read_to_string(DHCP_RESERVATIONS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_dhcp_reservations(data: &[DhcpReservation]) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(DHCP_RESERVATIONS_FILE, json).map_err(|e| e.to_string())
}

fn load_dhcp_configs() -> std::collections::HashMap<String, DhcpZoneConfig> {
    fs::read_to_string(DHCP_CONFIG_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_dhcp_configs(data: &std::collections::HashMap<String, DhcpZoneConfig>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(DHCP_CONFIG_FILE, json).map_err(|e| e.to_string())
}

/// Generate ULANG /usr/local/etc/kea/kea-dhcp4.conf dari SEMUA zona
/// DHCP yang enabled=true (bukan cuma satu interface yang sedang
/// diedit - Kea mendukung banyak subnet4 dalam SATU file config,
/// masing-masing terikat 'interfaces-config.interfaces'). Validasi
/// SEMANTIK (format IP, overlap subnet, dst) SUDAH dilakukan Rust
/// sendiri SEBELUM fungsi ini dipanggil (reuse fungsi Fase B yang
/// sudah ada dan teruji) - flag '-t' resmi Kea untuk validasi syntax
/// TIDAK dipakai di sini karena TIDAK KONSISTEN ada di semua versi
/// Kea (ada di 1.8/2.0, TAPI HILANG dari dokumentasi resmi versi
/// 2.1.3 ke atas) - tidak bisa diandalkan tanpa tahu persis versi
/// yang ter-install. Sebagai gantinya, KEBERHASILAN NYATA diverifikasi
/// dari status service SETELAH restart (bukan cuma exit code restart
/// command, yang bisa saja "berhasil" walau daemon di baliknya lantas
/// crash).
/// Bangun payload hex mentah DHCP Option 43 untuk Cisco lightweight AP
/// (join WLC lewat L3 kalau beda subnet - dikonfirmasi dari dokumentasi
/// resmi Cisco: sub-option TLV Type=0xf1 (241), Length=jumlah_IP*4,
/// Value=alamat IP WLC berurutan dalam bentuk byte). Pola ini SAMA
/// persis dipakai di Windows DHCP Server maupun ISC dhcpd - satu blob
/// hex mentah, bukan didekomposisi jadi sub-option space Kea yang lebih
/// rumit - dipilih supaya konsisten dengan cara paling umum didukung
/// semua vendor DHCP server, dan lebih mudah diverifikasi manual kalau
/// ada masalah (tinggal bandingkan hex string-nya).
fn build_option43_hex(wlc_ips: &[String]) -> Result<String, String> {
    if wlc_ips.is_empty() || wlc_ips.len() > 10 {
        return Err("Provide between 1 and 10 WLC IP addresses for Option 43.".to_string());
    }
    let mut value_bytes: Vec<u8> = Vec::new();
    for ip in wlc_ips {
        let octets = parse_ipv4(ip).ok_or_else(|| format!("'{ip}' is not a valid IPv4 address."))?;
        value_bytes.extend_from_slice(&octets);
    }
    let mut tlv = vec![0xf1u8, value_bytes.len() as u8];
    tlv.extend_from_slice(&value_bytes);
    Ok(tlv.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn regenerate_kea_config() -> Result<(), String> {
    if !std::path::Path::new("/usr/local/sbin/kea-dhcp4").exists() {
        return Err("The Kea DHCP package does not appear to be installed (missing /usr/local/sbin/kea-dhcp4) - run 'pkg install kea' on the gateway first".to_string());
    }

    let configs = load_dhcp_configs();
    let mut interfaces: Vec<String> = Vec::new();
    let mut subnet4: Vec<serde_json::Value> = Vec::new();
    // RCA (ditemukan dari log Kea sungguhan): 'subnet configuration
    // failed: missing parameter id' - Kea MEWAJIBKAN setiap entry
    // subnet4 punya field 'id' unik (integer), tidak boleh diabaikan
    // seperti field opsional lain. Pakai counter sekuensial sederhana
    // (1, 2, 3, ...) - cukup untuk kebutuhan kita karena SELURUH file
    // ini digenerate ulang dari nol tiap kali (bukan diff-update
    // parsial), jadi tidak ada risiko id lama "nyangkut"/konflik
    // dengan id baru di config yang berbeda.
    let mut next_subnet_id: u32 = 1;

    for (iface, cfg) in configs.iter() {
        if !cfg.enabled {
            continue;
        }
        let Some(cidr) = get_interface_cidr(iface) else {
            continue;
        };
        // Kea (dan Squid) BUTUH alamat network murni untuk deklarasi
        // subnet, bukan IP host - lihat normalize_network_cidr().
        let Some(subnet_cidr) = normalize_network_cidr(&cidr) else {
            continue;
        };
        let gateway = get_interface_ip(iface).unwrap_or_default();

        interfaces.push(iface.clone());

        let mut option_data = vec![serde_json::json!({ "name": "routers", "data": gateway })];
        if !cfg.dns_servers.is_empty() {
            option_data.push(serde_json::json!({
                "name": "domain-name-servers",
                "data": cfg.dns_servers.join(", "),
            }));
        }
        // DHCP Option 43 (Cisco WLC discovery) - dikirim sebagai raw
        // hex blob lewat option redefinisi "vendor-encapsulated-options"
        // (code 43) jadi tipe 'binary' polos, TIDAK memakai sub-option
        // space Kea yang lebih kompleks - lihat build_option43_hex().
        if !cfg.option43_wlc_ips.is_empty() {
            let hex = build_option43_hex(&cfg.option43_wlc_ips)?;
            option_data.push(serde_json::json!({
                "name": "vendor-encapsulated-options",
                "code": 43,
                "data": hex,
            }));
        }

        let reservations_for_iface: Vec<serde_json::Value> = load_dhcp_reservations()
            .into_iter()
            .filter(|r| &r.interface == iface)
            .map(|r| serde_json::json!({
                "hw-address": r.mac,
                "ip-address": r.ip,
                "hostname": r.hostname,
            }))
            .collect();
        subnet4.push(serde_json::json!({
            "id": next_subnet_id,
            "subnet": subnet_cidr,
            "pools": [{ "pool": format!("{} - {}", cfg.range_start, cfg.range_end) }],
            "option-data": option_data,
            "valid-lifetime": cfg.lease_time,
            "reservations": reservations_for_iface,
        }));
        next_subnet_id += 1;
    }

    if interfaces.is_empty() {
        // Tidak ada zona DHCP aktif sama sekali - hentikan service kalau
        // sedang jalan, jangan biarkan Kea jalan dengan config kosong.
        let _ = Command::new("service").arg("kea").arg("stop").status();
        let _ = Command::new("sysrc").arg("kea_enable=NO").status();
        return Ok(());
    }

    let kea_config = serde_json::json!({
        "Dhcp4": {
            "interfaces-config": { "interfaces": interfaces },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": "/var/db/kea/dhcp4.leases"
            },
            "valid-lifetime": 604800,
            // Redefinisi option 43 jadi 'binary' polos (bukan sub-option
            // space Kea standar) - supaya hex TLV yang sudah kita bangun
            // sendiri di build_option43_hex() bisa dikirim APA ADANYA,
            // konsisten dengan pola paling umum di semua DHCP server
            // (Windows/ISC dhcpd). Aman didefinisikan di sini SELALU
            // (tidak bersyarat) - tidak berefek apa pun kalau tidak ada
            // zona yang benar-benar memakai Option 43.
            "option-def": [{
                "name": "vendor-encapsulated-options",
                "code": 43,
                "type": "binary",
                "array": false
            }],
            "subnet4": subnet4,
            "loggers": [{
                "name": "kea-dhcp4",
                "severity": "INFO",
                "output_options": [{ "output": "/var/log/kea/kea-dhcp4.log" }]
            }]
        }
    });

    let json_str = serde_json::to_string_pretty(&kea_config).map_err(|e| e.to_string())?;
    // RCA (ditemukan dari test user): direktori /usr/local/etc/kea bisa
    // saja belum ada - baik karena paket 'kea' belum ter-install lengkap
    // (mis. VM lama yang belum sempat pkg install kea manual sesuai
    // instruksi), atau instalasi paket tidak membuat direktori config
    // secara default. Defensif: buat direktorinya dulu SEBELUM nulis,
    // jangan asumsikan sudah ada begitu saja.
    if let Some(parent) = std::path::Path::new(KEA_DHCP4_CONF).parent() {
        let _ = fs::create_dir_all(parent);
    }
    // Kea 3.x membatasi lokasi log HANYA boleh di /var/log/kea/ (bukan
    // langsung /var/log/) - dikonfirmasi dari error nyata "invalid path
    // in `output`: invalid path specified: '/var/log', supported path
    // is '/var/log/kea'" - pastikan direktori ini ada juga.
    let _ = fs::create_dir_all("/var/log/kea");
    fs::write(KEA_DHCP4_CONF, &json_str).map_err(|e| format!("Failed to write {KEA_DHCP4_CONF}: {e}"))?;

    let _ = Command::new("sysrc").arg("kea_enable=YES").status();
    let restart_status = Command::new("service").arg("kea").arg("restart").status();
    if !matches!(restart_status, Ok(s) if s.success()) {
        let _ = Command::new("service").arg("kea").arg("start").status();
    }

    // RCA SUSULAN (ditemukan dari log user - false negative setelah fix
    // background-thread startup): status check di bawah dipanggil TANPA
    // jeda sama sekali setelah 'service kea restart' - restart_status
    // di atas cuma menandakan keactrl SUDAH SPAWN proses kea-dhcp4/kea-
    // dhcp6 (ini persis pesan "appears to be running, PID..." yang
    // muncul di log user - itu passthrough stdout dari restart itu
    // sendiri, BUKAN dari status check kita), belum tentu control-agent
    // kea-dhcp4 sudah selesai init sampai bisa menjawab query detail
    // "DHCPv4 server: active". Fix: retry dengan jeda pendek (bukan
    // sleep tetap yang boros kalau Kea sudah siap lebih cepat) - sampai
    // 5x percobaan, 500ms antar percobaan (total maksimal 2.5 detik
    // sebelum benar-benar dianggap gagal).
    let mut dhcp4_active = false;
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let status_output = Command::new("service").arg("kea").arg("status").output();
        dhcp4_active = match &status_output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("DHCPv4 server: active"),
            Err(_) => false,
        };
        if dhcp4_active {
            break;
        }
    }
    if !dhcp4_active {
        return Err("Kea DHCPv4 failed to start after applying the new configuration (checked via 'DHCPv4 server: active' in service status) - check /var/log/kea/kea-dhcp4.log for details".to_string());
    }

    Ok(())
}

/// Ambil kunci HMAC per-gateway - dibuat OTOMATIS sekali di panggilan
/// pertama kalau belum ada (bukan saat instalasi, karena instalasi shell
/// tidak punya sumber randomness kriptografis yang mudah tanpa dependency
/// tambahan) - dibaca dari /dev/urandom LANGSUNG (32 byte), BUKAN pakai
/// crate 'rand' terpisah, konsisten prinsip dependency minimal proyek
/// ini. Kunci ini TIDAK PERNAH ditampilkan ke admin/log/console - murni
/// rahasia internal mesin-ke-mesin (persis pola Tier 1 Bab 13.3.1),
/// dan file-nya SENGAJA TIDAK PERNAH masuk daftar backup_file_list() -
/// kalau ikut ter-backup, restore ke gateway lain bisa membuat backup
/// gateway itu "dikenali" seolah dari gateway asal, membatalkan seluruh
/// tujuan verifikasi keaslian sumber.
/// Scan teks JSON (mentah, string) untuk token yang MIRIP nama interface
/// FreeBSD (pola "emN"/"igbN"/"reN" dst - huruf diikuti angka) - dipakai
/// system.backup_restore untuk deteksi interface yang direferensikan di
/// backup TANPA perlu parse setiap bentuk JSON secara spesifik (file
/// yang di-scan punya struktur field yang beda-beda: kadang key HashMap,
/// kadang field "interface" di dalam array object). Manual scanner
/// SENGAJA dipakai (bukan crate 'regex' terpisah) - konsisten prinsip
/// dependency minimal, dan pola yang dicari cukup sederhana untuk
/// ditulis manual tanpa regex.
fn scan_interface_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_lowercase() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
            let letters_end = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i > letters_end && (letters_end - start) <= 4 {
                let candidate: String = chars[start..i].iter().collect();
                if !tokens.contains(&candidate) {
                    tokens.push(candidate);
                }
            }
        } else {
            i += 1;
        }
    }
    tokens
}

fn get_or_create_hmac_key() -> Result<Vec<u8>, String> {
    if let Ok(existing) = fs::read(HMAC_KEY_FILE) {
        if existing.len() == 32 {
            return Ok(existing);
        }
    }
    // /dev/urandom adalah device karakter TANPA EOF alami - 'fs::read'
    // biasa akan blocking mencoba baca sampai EOF yang tidak pernah
    // datang. WAJIB pakai Read::take(32) untuk baca TEPAT 32 byte lalu
    // berhenti, bukan asumsi fs::read "otomatis tahu kapan berhenti".
    use std::io::Read;
    let mut file = fs::File::open("/dev/urandom").map_err(|e| format!("Failed to open /dev/urandom: {e}"))?;
    let mut key = vec![0u8; 32];
    file.read_exact(&mut key).map_err(|e| format!("Failed to read 32 bytes from /dev/urandom: {e}"))?;

    if let Some(parent) = std::path::Path::new(HMAC_KEY_FILE).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(HMAC_KEY_FILE, &key).map_err(|e| format!("Failed to write {HMAC_KEY_FILE}: {e}"))?;
    let _ = fs::set_permissions(HMAC_KEY_FILE, fs::Permissions::from_mode(0o600));

    Ok(key)
}

/// Hitung HMAC-SHA256 dari sebuah file, kembalikan 16 karakter hex
/// pertama (64 bit) - pola PERSIS Tier 1 Bab 13.3.2: ditempel di nama
/// file (bukan file terpisah), 16 karakter dipilih sebagai keseimbangan
/// proporsional (bukan 64 karakter penuh yang terlalu panjang untuk
/// nama file, tapi tetap ruang kemungkinan sangat besar untuk model
/// ancaman realistis produk ini).
fn compute_file_hmac(path: &str) -> Result<String, String> {
    let key = get_or_create_hmac_key()?;
    let data = fs::read(path).map_err(|e| format!("Failed to read {path} for HMAC: {e}"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    let full_hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
    Ok(full_hex[..16].to_string())
}

fn load_aliases() -> std::collections::HashMap<String, String> {
    fs::read_to_string(ALIAS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_aliases(data: &std::collections::HashMap<String, String>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(ALIAS_FILE, json).map_err(|e| e.to_string())
}

/// Description per interface - TEMUAN bro: sebelumnya kolom
/// "Description" di tabel Network zones itu STRING HARDCODED di kode
/// PHP ("Not yet assigned a role", dst), sama sekali BUKAN data
/// tersimpan/bisa diedit. Sekarang jadi field editable sungguhan,
/// pola penyimpanan PERSIS sama dengan Alias (file JSON terpisah,
/// key=interface). MGMT/LAN1/WAN1 tetap punya default text bawaan
/// (dikembalikan PHP kalau belum pernah di-custom) - OPT/VLAN/LAGG
/// defaultnya string kosong, PHP yang isi placeholder "Not yet
/// assigned a role" kalau kosong.
fn load_descriptions() -> std::collections::HashMap<String, String> {
    fs::read_to_string(DESCRIPTION_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_descriptions(data: &std::collections::HashMap<String, String>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(DESCRIPTION_FILE, json).map_err(|e| e.to_string())
}

/// Deteksi tipe interface - HEURISTIK sederhana berdasarkan nama, BUKAN
/// query sistem yang lebih dalam (mis. 'ifconfig -v' vlan tag info) -
/// cukup untuk kondisi proyek SAAT INI karena install-gateway-v2.sh
/// SENGAJA blocklist interface 'vlan*' dari deteksi NIC fisik (lihat
/// Bagian 2) - artinya SEMUA zona yang ada sekarang DIJAMIN Physical,
/// tidak pernah VLAN, karena dukungan VLAN belum ada sama sekali di
/// proyek ini. Kolom "Type" ditambahkan sekarang supaya UI sudah siap
/// forward-compatible kalau/waktu VLAN benar-benar diimplementasi nanti
/// (deteksi via nama mengandung '.' atau prefix 'vlan' - konvensi
/// standar FreeBSD, mis. 'em0.100').
fn detect_interface_type(iface: &str) -> &'static str {
    if iface.starts_with("lagg") {
        "LAGG"
    } else if iface.contains('.') || iface.starts_with("vlan") {
        "VLAN"
    } else {
        "Physical"
    }
}

fn load_custom_rules() -> CustomRulesFile {
    fs::read_to_string(CUSTOM_RULES_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_custom_rules(data: &CustomRulesFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(CUSTOM_RULES_FILE, json).map_err(|e| e.to_string())
}

fn load_limiters() -> LimitersFile {
    fs::read_to_string(LIMITERS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_limiters(data: &LimitersFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(LIMITERS_FILE, json).map_err(|e| e.to_string())
}

/// Alokasikan sepasang pipe ID dummynet yang belum dipakai limiter
/// mana pun - PERMANEN sekali dialokasikan (disimpan di struct
/// BandwidthLimiter itu sendiri), bukan dihitung ulang tiap generate
/// config, supaya nomor pipe di /etc/dnctl.conf stabil antar restart.
fn next_limiter_pipe_ids() -> (u32, u32) {
    let existing = load_limiters();
    let max_used = existing
        .limiters
        .iter()
        .flat_map(|l| [l.download_pipe_id, l.upload_pipe_id])
        .max()
        .unwrap_or(0);
    (max_used + 1, max_used + 2)
}

/// Tulis ulang /etc/dnctl.conf dari SELURUH limiter yang ada -
/// dipanggil setiap kali limiter dibuat/diedit/dihapus, pola sama
/// dengan regenerate_kea_config()/regenerate_pf_conf_for_interface()
/// (satu sumber kebenaran, seluruh file ditulis ulang total tiap kali,
/// bukan di-patch sebagian - lebih mudah dijamin konsisten). Tipe
/// 'fq_codel' dipilih sebagai SATU-SATUNYA AQM yang diexpose ke admin
/// (bukan pilihan bebas fifo/red/dll) - fq_codel adalah AQM modern
/// anti-bufferbloat yang direkomendasikan FreeBSD sendiri, dan
/// membatasi pilihan sesuai filosofi "Simple" project ini.
fn regenerate_dnctl_conf() -> Result<(), String> {
    let limiters = load_limiters().limiters;
    let mut lines = vec!["# Auto-generated by ntpsense-configd - DO NOT EDIT MANUALLY".to_string()];
    for l in &limiters {
        lines.push(format!(
            "pipe {} config bw {}Mbit/s type fq_codel",
            l.download_pipe_id, l.download_mbps
        ));
        lines.push(format!(
            "pipe {} config bw {}Mbit/s type fq_codel",
            l.upload_pipe_id, l.upload_mbps
        ));
    }
    let content = lines.join("\n") + "\n";
    fs::write(DNCTL_CONF, content).map_err(|e| format!("Failed to write {DNCTL_CONF}: {e}"))?;

    // RCA: BEDA dari vlan(4)/lagg(4) (yang otomatis di-load kernel-nya
    // begitu 'ifconfig vlanN create' pertama kali dipanggil), modul
    // 'dummynet' TIDAK dikompilasi ke kernel GENERIC maupun di-load
    // otomatis oleh service apa pun secara default. kldload diulang di
    // SINI (bukan cuma sekali saat instalasi) karena fungsi ini bisa
    // dipanggil di gateway yang sudah lama jalan tanpa limiter sama
    // sekali sebelumnya - modulnya belum tentu ter-load dari boot
    // terakhir. "module already loaded" dari kldload itu sendiri BUKAN
    // error nyata - makanya exit code-nya diabaikan di sini.
    let _ = Command::new("kldload").arg("dummynet").status();
    let _ = Command::new("sysrc").arg("kld_list+=dummynet").status();
    let _ = Command::new("sysrc").arg("dnctl_enable=YES").status();

    // RCA KEDUA (baru ketahuan dari output SSH nyata): 'dnctl -f <file>'
    // BUKAN syntax yang valid - dnctl TIDAK PUNYA flag '-f' sama sekali
    // ("illegal option -- f"). Asumsi itu diambil dari contoh rc.conf
    // di sebuah blog post yang sebenarnya cuma menunjukkan variabel
    // dnctl_enable/dnctl_program untuk service rc.d dnctl (yang
    // membaca /etc/dnctl.conf lewat mekanismenya SENDIRI saat boot),
    // bukan argumen command-line dnctl itu sendiri. Fix: panggil dnctl
    // LANGSUNG per-pipe dengan argumen eksplisit - persis command yang
    // sama yang sudah dikonfirmasi berulang kali di seluruh dokumentasi
    // ('dnctl pipe <id> config bw <mbps>Mbit/s type fq_codel'), tidak
    // bergantung pada mekanisme load-dari-file apa pun.
    for l in &limiters {
        let apply_pipe = |pipe_id: u32, mbps: f64| -> Result<(), String> {
            let status = Command::new("dnctl")
                .args(["pipe", &pipe_id.to_string(), "config", "bw", &format!("{mbps}Mbit/s"), "type", "fq_codel"])
                .status();
            if status.map(|s| !s.success()).unwrap_or(true) {
                return Err(format!(
                    "dnctl pipe {pipe_id} config failed - is the 'dummynet' kernel module loaded? (kldstat | grep dummynet)"
                ));
            }
            Ok(())
        };
        apply_pipe(l.download_pipe_id, l.download_mbps)?;
        apply_pipe(l.upload_pipe_id, l.upload_mbps)?;
    }
    Ok(())
}

/// Generate SATU baris rule pf dari CustomRule. Pola SELALU 'in quick
/// on <if>' (konsisten rule OPT lain di sekitarnya) - 'keep state'
/// HANYA untuk action 'pass' (tidak relevan/valid untuk 'block').
/// RCA (5-way isolated pfctl test on real VM, definitive): FreeBSD's pf on
/// this system does NOT support the modern combined "pass ... rdr-to ..."
/// single-line syntax at all - EVERY variant tried (rdr-to before/after
/// keep state, with/without quick, with/without keep state) failed
/// pfctl -nf with a generic "syntax error". Only the CLASSIC two-part
/// syntax (separate `rdr` translation rule + separate `pass` filter rule)
/// validated successfully. This is a genuine platform difference, not a
/// word-order mistake - a blog citation claiming "FreeBSD 13+" supports
/// the unified syntax was wrong for this actual system, discovered only
/// by testing all plausible variants directly rather than trusting the
/// citation a second time.
///
/// Architectural consequence: `rdr` is a TRANSLATION rule and pf.conf
/// requires ALL translation rules to appear in an earlier section of the
/// file than ANY filter (block/pass) rule - not just before the specific
/// pass rule it pairs with. It can NOT live in the same per-interface
/// filter marker block used for ordinary custom rules (which sits deep in
/// the filter section). It needs its own marker
/// (NTPSENSE_NAT_PORTFWD_START/END) positioned right after the existing
/// `nat on $wan1_if ...` line, before `block all`. See
/// regenerate_nat_portfwd_block().
// ============================================================
// System Log Viewer + Firewall Log Viewer - riset dulu (pfSense,
// FortiGate, Palo Alto): pfSense sendiri TIDAK pakai pflog mentah untuk
// tampilan Firewall log mereka - sejak versi 2.2 mereka ganti ke daemon
// custom (filterlog) yang tulis CSV ke syslog, BUKAN bagian dari FreeBSD
// base. Kita tidak punya daemon custom itu - pendekatan kita pakai
// mekanisme FreeBSD base MURNI: pflogd (dari pflog_enable=YES, SUDAH
// aktif sejak awal project) otomatis tulis packet yang di-log ke
// /var/log/pflog (format pcap biner), dibaca balik pakai
// 'tcpdump -n -e -tttt -r /var/log/pflog' (dikonfirmasi dari FreeBSD
// forum/dokumentasi resmi, BUKAN tebakan).
//
// RCA nyata (ditemukan bro langsung - jam di Firewall Log menunjukkan
// "00:00:01.031221" dst, sama sekali tidak cocok jam gateway 14:02):
// versi SEBELUMNYA pakai flag '-ttt' (TIGA t) - itu artinya tcpdump
// cetak SELISIH WAKTU sejak paket sebelumnya (delta), BUKAN jam
// dinding sungguhan. '-tttt' (EMPAT t) yang benar - tanggal+jam
// absolut, zona waktu lokal sistem. Parsing di bawah TIDAK PERLU
// berubah sama sekali - kode cuma menangkap teks mentah sebelum kata
// "rule " apa adanya sebagai field waktu, jadi format apa pun yang
// dihasilkan tcpdump otomatis tertangkap benar.
//
// CATATAN JUJUR: parsing output tcpdump di bawah ini pakai regex yang
// dirancang cocok dengan format standar yang didokumentasikan, tapi
// BELUM divalidasi terhadap /var/log/pflog nyata yang berisi data -
// perlu diverifikasi begitu di-deploy (sama seperti setiap asumsi
// format lain di project ini yang akhirnya dicocokkan lewat test
// nyata). Kalau regex tidak cocok persis, baris mentah tetap
// ditampilkan (fallback), bukan hilang begitu saja.
// ============================================================

#[derive(Debug, Serialize)]
struct FirewallLogEntry {
    time: String,
    rule_number: String,
    action: String,   // "pass" | "block"
    direction: String, // "in" | "out"
    interface: String,
    protocol: String,
    source: String,
    destination: String,
    // Tidak dikirim ke client (skip_serializing) - field ini menduplikasi
    // SELURUH baris tcpdump mentah di samping field yang sudah di-parse,
    // kira-kira dobel ukuran response tanpa perlu (RCA nyata: ini yang
    // bikin response Firewall Log Viewer kepotong di tengah JSON lewat
    // fgets() 64KB PHP - lihat fix NtpsenseConfigd.php). Tetap disimpan
    // di struct untuk kemungkinan debugging internal nanti (belum benar2
    // dipakai sekarang) - #[allow(dead_code)] di sini SENGAJA, bukan
    // warning yang diabaikan tanpa alasan.
    #[allow(dead_code)]
    #[serde(skip_serializing)]
    raw: String,
}

fn get_pflog_entries(limit: usize) -> Vec<FirewallLogEntry> {
    let output = Command::new("tcpdump")
        .args(["-n", "-e", "-tttt", "-r", "/var/log/pflog"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut entries: Vec<FirewallLogEntry> = Vec::new();

    for line in text.lines() {
        // Format umum tcpdump untuk pflog (dikonfirmasi dari dokumentasi
        // OpenBSD/FreeBSD): "<time> rule <n>/<n>(<reason>): <action> <dir>
        // on <if>: <src> > <dst>: <proto detail>"
        // Contoh: "00:00:00.000000 rule 2/0(match): block in on em5: 1.2.3.4.1234 > 5.6.7.8.80: ..."
        let mut entry = FirewallLogEntry {
            time: String::new(),
            rule_number: String::new(),
            action: String::new(),
            direction: String::new(),
            interface: String::new(),
            protocol: String::new(),
            source: String::new(),
            destination: String::new(),
            raw: line.to_string(),
        };

        let parts: Vec<&str> = line.splitn(2, "rule ").collect();
        if parts.len() == 2 {
            entry.time = parts[0].trim().to_string();
            let rest = parts[1];
            if let Some(slash_idx) = rest.find('/') {
                entry.rule_number = rest[..slash_idx].to_string();
            }
            for act in ["pass", "block"] {
                if let Some(idx) = rest.find(act) {
                    entry.action = act.to_string();
                    let after_action = &rest[idx + act.len()..];
                    if after_action.trim_start().starts_with("in") {
                        entry.direction = "in".to_string();
                    } else if after_action.trim_start().starts_with("out") {
                        entry.direction = "out".to_string();
                    }
                    break;
                }
            }
            if let Some(on_idx) = rest.find(" on ") {
                let after_on = &rest[on_idx + 4..];
                if let Some(colon_idx) = after_on.find(':') {
                    entry.interface = after_on[..colon_idx].trim().to_string();
                    let traffic = after_on[colon_idx + 1..].trim();
                    if let Some(gt_idx) = traffic.find(" > ") {
                        entry.source = traffic[..gt_idx].trim().to_string();
                        let remainder = &traffic[gt_idx + 3..];
                        if let Some(colon2) = remainder.find(':') {
                            entry.destination = remainder[..colon2].trim().to_string();
                            entry.protocol = remainder[colon2 + 1..].trim().to_string();
                        } else {
                            entry.destination = remainder.trim().to_string();
                        }
                    }
                }
            }
        }
        entries.push(entry);
    }

    let start = entries.len().saturating_sub(limit);
    entries.split_off(start)
}

/// Baca file log teks biasa (bukan pflog binary) - dipakai untuk semua
/// tab System Log Viewer selain Firewall: General (/var/log/messages),
/// OS Boot (/var/log/dmesg.boot), dan log per-service yang path-nya
/// sudah dikonfirmasi dari kerja sebelumnya di project ini (Kea, Squid,
/// lighttpd).
fn tail_log_file(path: &str, limit: usize) -> Vec<String> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            let start = lines.len().saturating_sub(limit);
            lines.split_off(start)
        }
        Err(_) => Vec::new(),
    }
}

// ============================================================
// Parser log generik (roadmap - permintaan bro langsung: 9 tab System
// Logs yang tadinya tampil sebagai teks mentah <pre> diubah jadi
// tabel Timestamp/Level/Message yang mudah dibaca). Dipakai bersama
// oleh General/DHCP/OS Boot/Watchdog/Maintenance/OpenVPN/IPsec - tujuh
// sumber ini cukup mirip (baris berbasis timestamp+pesan) untuk satu
// parser generik, BEDA dari Proxy/GUI Service yang formatnya jauh
// lebih terstruktur (access log kolom tetap) dan dapat parser sendiri
// di bawah.
// ============================================================

#[derive(Debug, Serialize)]
struct ParsedLogEntry {
    timestamp: String,
    level: String, // "error" | "warning" | "info"
    message: String,
}

/// Coba beberapa pola timestamp UMUM secara berurutan - kalau tidak
/// ada yang cocok, seluruh baris jadi 'message' tanpa timestamp
/// (fallback aman, TIDAK PERNAH menghilangkan baris hanya karena
/// formatnya tidak dikenali).
fn split_timestamp_and_message(line: &str) -> (String, String) {
    // Pola 1: "YYYY-MM-DD HH:MM:SS[.frac] <pesan>" - Watchdog/OpenVPN/
    // Maintenance/Kea, format yang sudah sering kita temui di project ini.
    if line.len() > 19 {
        let prefix = &line[0..19];
        let bytes = prefix.as_bytes();
        let digit_positions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
        let sep_positions: [(usize, u8); 5] = [(4, b'-'), (7, b'-'), (10, b' '), (13, b':'), (16, b':')];
        let digits_ok = digit_positions.iter().all(|&p| bytes.get(p).map(u8::is_ascii_digit).unwrap_or(false));
        let seps_ok = sep_positions.iter().all(|&(p, c)| bytes.get(p) == Some(&c));
        if digits_ok && seps_ok {
            let rest = line[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit()).trim_start();
            return (prefix.to_string(), rest.to_string());
        }
    }
    // Pola 2: "Mon D HH:MM:SS <pesan>" - format syslog klasik
    // (/var/log/messages), tanggal tanpa tahun, hari bisa 1 atau 2 digit.
    let syslog_re_parts: Vec<&str> = line.splitn(4, ' ').collect();
    if syslog_re_parts.len() == 4 {
        let month = syslog_re_parts[0];
        let day = syslog_re_parts[1];
        let time = syslog_re_parts[2];
        let is_month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].contains(&month);
        let is_day = !day.is_empty() && day.len() <= 2 && day.chars().all(|c| c.is_ascii_digit());
        let is_time = time.len() == 8 && time.as_bytes().get(2) == Some(&b':') && time.as_bytes().get(5) == Some(&b':');
        if is_month && is_day && is_time {
            return (format!("{month} {day} {time}"), syslog_re_parts[3].to_string());
        }
    }
    // Pola 3: "Www Mmm dd hh:mm:ss yyyy : Level: pesan" - format
    // asctime()/ctime() C standar, dipakai FreeRADIUS (radiusd) sendiri
    // untuk log-nya - 24 karakter TETAP untuk bagian tanggal (hari 3
    // huruf, bulan 3 huruf, tanggal, waktu, tahun 4 digit), lalu " : "
    // sebagai pemisah sebelum "Level: pesan". RCA (ditemukan dari test
    // user nyata - kolom Timestamp System Logs > FreeRADIUS selalu
    // kosong): dua pola di atas TIDAK ADA yang cocok format ini (Pola 2
    // gagal karena token pertama "Wed" bukan nama bulan, terdeteksi
    // sebagai hari-dalam-minggu bukan bulan).
    if line.len() > 24 {
        let prefix = &line[0..24];
        let bytes = prefix.as_bytes();
        let days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let day_ok = days.iter().any(|d| prefix.starts_with(d));
        let month_ok = prefix.get(4..7).map(|m| months.contains(&m)).unwrap_or(false);
        let sep_ok = bytes.get(3) == Some(&b' ')
            && bytes.get(7) == Some(&b' ')
            && bytes.get(10) == Some(&b' ')
            && bytes.get(19) == Some(&b' ');
        let time_ok = bytes.get(13) == Some(&b':') && bytes.get(16) == Some(&b':');
        let year_ok = prefix.get(20..24).map(|y| y.chars().all(|c| c.is_ascii_digit())).unwrap_or(false);
        if day_ok && month_ok && sep_ok && time_ok && year_ok {
            // Urutan trim WAJIB: spasi dulu (sisa setelah tahun), baru
            // titik dua pemisah, baru spasi lagi (RCA nyata - urutan
            // terbalik meninggalkan ": " nempel di depan pesan, karena
            // trim_start_matches(':') dipanggil SAAT karakter pertama
            // masih spasi, jadi tidak menemukan apa pun untuk di-trim).
            let rest = line[24..].trim_start().trim_start_matches(':').trim_start().to_string();
            return (prefix.to_string(), rest);
        }
    }
    // Tidak ada pola cocok - seluruh baris jadi message, timestamp kosong.
    (String::new(), line.to_string())
}

/// Deteksi level dari kata kunci di pesan (case-insensitive) - bukan
/// parsing field level formal (kebanyakan sumber di sini tidak
/// menyertakan level eksplisit terstruktur), cukup untuk pewarnaan
/// baris yang membantu admin cepat lihat mana yang perlu perhatian.
fn detect_log_level(message: &str) -> &'static str {
    let lower = message.to_lowercase();
    if lower.contains("error") || lower.contains("fail") || lower.contains("fatal") || lower.contains("critical") || lower.contains("denied") {
        "error"
    } else if lower.contains("warn") {
        "warning"
    } else {
        "info"
    }
}

fn parse_syslog_style_lines(lines: &[String]) -> Vec<ParsedLogEntry> {
    lines
        .iter()
        .map(|line| {
            let (timestamp, message) = split_timestamp_and_message(line);
            let level = detect_log_level(&message).to_string();
            ParsedLogEntry { timestamp, level, message }
        })
        .collect()
}

/// Format unix timestamp (detik) jadi "YYYY-MM-DD HH:MM:SS" pakai zona
/// waktu LOKAL sistem - reuse binari 'date' base FreeBSD (tidak perlu
/// tambah crate chrono cuma untuk satu konversi ini, konsisten dengan
/// pola project ini menghindari dependency baru kalau base system
/// tool sudah cukup).
fn format_unix_timestamp(epoch_secs: i64) -> String {
    Command::new("date")
        .args(["-r", &epoch_secs.to_string(), "+%Y-%m-%d %H:%M:%S"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| epoch_secs.to_string())
}

// ------------------------------------------------------------
// lighttpd access.log (Combined Log Format standar Apache/lighttpd) -
// pola: IP - - [tanggal:jam +zona] "METHOD URL PROTO" status size
// ------------------------------------------------------------
#[derive(Debug, Serialize)]
struct LighttpdLogEntry {
    timestamp: String,
    client_ip: String,
    method: String,
    url: String,
    status: String,
    size: String,
}

fn parse_lighttpd_access_line(line: &str) -> Option<LighttpdLogEntry> {
    let client_ip = line.split_whitespace().next()?.to_string();
    let ts_start = line.find('[')?;
    let ts_end = line[ts_start..].find(']')? + ts_start;
    let timestamp = line[ts_start + 1..ts_end].to_string();
    let req_start = line[ts_end..].find('"')? + ts_end;
    let req_end_rel = line[req_start + 1..].find('"')?;
    let request = &line[req_start + 1..req_start + 1 + req_end_rel];
    let req_parts: Vec<&str> = request.split_whitespace().collect();
    let method = req_parts.first().unwrap_or(&"").to_string();
    let url = req_parts.get(1).unwrap_or(&"").to_string();
    let after_request = line[req_start + 1 + req_end_rel + 1..].trim_start();
    let tail_parts: Vec<&str> = after_request.split_whitespace().collect();
    let status = tail_parts.first().unwrap_or(&"").to_string();
    let size = tail_parts.get(1).unwrap_or(&"").to_string();
    Some(LighttpdLogEntry { timestamp, client_ip, method, url, status, size })
}

fn generate_rdr_line(rule: &CustomRule) -> Option<String> {
    let redirect_ip = rule.nat_redirect_ip.as_ref()?;
    let mut line = format!("rdr on {} proto {} from any to ({})", rule.interface, rule.protocol, rule.interface);
    if let Some(port) = rule.port {
        line.push_str(&format!(" port {port}"));
    }
    line.push_str(&format!(" -> {redirect_ip}"));
    if let Some(redirect_port) = rule.nat_redirect_port {
        line.push_str(&format!(" port {redirect_port}"));
    }
    Some(line)
}

/// RCA (ditemukan dari test interop pfSense nyata - dua sisi client
/// sungguhan tidak bisa saling ping lewat tunnel IPsec, ESP SA
/// established tapi 0 bytes/0 packets di KEDUA arah): rule custom di
/// project ini SELALU hardcode arah 'in', tidak pernah 'out' - ini
/// kebetulan tidak masalah untuk LAN1/OPT (cukup filter traffic MASUK
/// dari client fisik), tapi SALAH untuk interface tunnel VPN virtual
/// (wg0/enc0) - traffic yang mau MASUK ke tunnel untuk dienkripsi butuh
/// arah berbeda dari traffic yang BARU KELUAR dari tunnel setelah
/// didekripsi. Tanpa arah 'out' eksplisit, 'block all' default diam-diam
/// memblokir salah satu arah - persis skenario yang bikin ESP SA
/// established tapi tidak pernah ada traffic yang lewat.
///
/// Fix: interface tunnel VPN (wg0/enc0) sekarang dapat DUA baris rule
/// (in DAN out) untuk setiap custom rule admin, bukan cuma satu -
/// interface fisik (LAN1/OPT/WAN1/MGMT) TIDAK berubah sama sekali,
/// tetap satu baris 'in' seperti sebelumnya (sudah terbukti benar lewat
/// testing ekstensif, tidak perlu disentuh).
/// RCA LANJUTAN (ditemukan dari test interop pfSense nyata, PUTARAN
/// KEDUA): fix sebelumnya cuma mengkhususkan wg0/enc0 untuk dapat arah
/// 'out' juga - tapi ternyata SETIAP zona (LAN1, OPT mana pun) berpotensi
/// jadi TUJUAN traffic dari VPN (subnet lokal Phase 2 IPsec, atau
/// AllowedIPs WireGuard) - client pfSense berhasil ping ke gateway LAN1
/// (10.252.1.1, kena rule sistem MGMT-access yang punya out tersendiri)
/// TAPI GAGAL ping ke client LAN1 sungguhan (10.252.1.101), karena paket
/// forwarded dari tunnel butuh KELUAR lewat em1 - bukan traffic yang
/// "masuk" dari em1 sendiri, jadi tidak pernah cocok rule 'in' yang
/// sudah ada, dan tidak ada rule 'out' sama sekali di em1. Kesimpulan:
/// pembatasan ke tunnel-interface-saja tidak cukup luas - SEMUA
/// interface sekarang dapat KEDUA arah untuk setiap custom rule, bukan
/// cuma wg0/enc0. Ini aditif murni (tidak mengubah rule 'in' yang sudah
/// terbukti benar), tidak menghapus kapabilitas apa pun yang sudah ada.
/// Direction sekarang FIELD EKSPLISIT yang admin pilih sendiri lewat
/// Web UI (Action, Direction, Protocol, Source, Destination, Port,
/// Description) - bukan dipaksa otomatis. RCA yang melatarbelakangi
/// field ini ditambahkan: client pfSense gagal ping ke client LAN1
/// asli (traffic forwarded dari tunnel IPsec butuh KELUAR lewat em1,
/// bukan cuma masuk) - rule 'in' yang sudah ada tidak pernah cocok
/// traffic semacam itu. "both" menghasilkan DUA baris (in + out)
/// sekaligus untuk kasus yang butuh keduanya (mis. custom rule di
/// wg0/enc0 yang perlu menangani traffic masuk-untuk-dekripsi DAN
/// keluar-untuk-enkripsi).
fn generate_rule_line(rule: &CustomRule) -> Vec<String> {
    let directions: Vec<&str> = match rule.direction.as_str() {
        "out" => vec!["out"],
        "both" => vec!["in", "out"],
        _ => vec!["in"], // default aman, cocok perilaku lama sebelum field ini ada
    };

    // Kalau rule ini punya Bandwidth Limiter terpasang, cari pipe ID-nya
    // SEKALI di sini (bukan per-baris di closure bawah) - urutan tuple
    // (upload, download) SELALU sama terlepas in/out/both: pf men-track
    // state per KONEKSI, begitu paket pertama match rule ini, arah maju
    // pakai pipe pertama dan balasannya otomatis pakai pipe kedua -
    // tidak tergantung baris 'in' atau 'out' mana yang match duluan.
    let dnpipe_clause: Option<String> = rule.limiter_name.as_ref().and_then(|name| {
        load_limiters()
            .limiters
            .iter()
            .find(|l| &l.name == name)
            .map(|l| format!(" dnpipe ({}, {})", l.upload_pipe_id, l.download_pipe_id))
    });

    // Multi-WAN policy routing - dihitung SEKALI di sini (bukan per-baris
    // in/out), reuse untuk tiap direction line yang dihasilkan. HANYA
    // berlaku untuk rule 'pass' (route-to di rule 'block' tidak ada
    // artinya - traffic yang diblok tidak pernah benar-benar di-routing).
    let route_to_clause: Option<String> =
        if rule.action == "pass" { rule.gateway_group_name.as_deref().and_then(multiwan::compute_route_to_clause) } else { None };

    directions
        .into_iter()
        .map(|direction| {
            // RCA (ditemukan sebelum sempat jadi masalah nyata - saat
            // membangun Firewall Log Viewer, bukan dari laporan bug):
            // rule yang di-generate di sini TIDAK PERNAH punya keyword
            // 'log' sejak awal project. Infrastruktur pflogd (dari
            // pflog_enable=YES) sudah aktif sejak lama, tapi karena tidak
            // ada rule yang bilang "log paket ini", /var/log/pflog tidak
            // pernah benar-benar terisi data - pfctl -s info bisa
            // menunjukkan statistik, tapi Firewall Log Viewer butuh
            // paket sungguhan yang tercatat. Fix: tambah 'log' ke semua
            // custom rule (pass maupun block) - pf cuma log paket
            // PERTAMA yang membentuk state untuk rule 'keep state',
            // bukan setiap paket, jadi volume log tetap wajar.
            let mut line = if rule.floating {
                // Floating - TANPA 'on <interface>' sama sekali, berlaku
                // di semua zona lewat satu baris global, bukan diulang
                // per-interface.
                format!("{} {direction} log quick", rule.action)
            } else {
                format!("{} {direction} log quick on {}", rule.action, rule.interface)
            };
            // route-to/reply-to WAJIB di posisi ini persis (tepat setelah
            // 'quick on <if>', SEBELUM proto/from/to) - dikonfirmasi dari
            // riset: kalau ditaruh di akhir baris (mengikuti urutan baca
            // deskripsi biasa), pf akan menolak dengan syntax error yang
            // membingungkan tanpa petunjuk jelas apa yang salah.
            if let Some(clause) = &route_to_clause {
                line.push_str(clause);
            }
            if rule.protocol != "any" {
                line.push_str(&format!(" proto {}", rule.protocol));
            }
            // Grammar pf: action [direction] [quick] [on if] [proto] [from src]
            // [to dst [port p]] - 'from' WAJIB sebelum 'to'. 'any' tetap
            // ditulis eksplisit (bukan diskip seperti protocol) karena pf
            // mewajibkan klausa 'from' ada kalau mau tulis 'to' di rule yang
            // sama - default implicit-nya tanpa 'from' sama sekali sebenarnya
            // sudah berarti 'from any', tapi eksplisit lebih jelas dibaca di
            // 'pfctl -s rules' dan konsisten dengan kolom Source di Web UI.
            //
            // NAT (Port Forward), classic 2-part syntax (lihat generate_rdr_line
            // untuk penjelasan lengkap kenapa BUKAN rdr-to inline): rule filter
            // ini mencocokkan packet SETELAH translasi terjadi - destination-nya
            // jadi internal redirect IP (post-NAT), BUKAN alamat WAN1 sendiri
            // seperti implementasi combined-syntax sebelumnya yang gagal.
            let (destination, port_override) = if let Some(redirect_ip) = &rule.nat_redirect_ip {
                (redirect_ip.clone(), rule.nat_redirect_port)
            } else {
                (rule.destination.clone(), rule.port)
            };
            line.push_str(&format!(" from {} to {}", rule.source, destination));
            if let Some(port) = port_override {
                line.push_str(&format!(" port {port}"));
            }
            if let Some(clause) = &dnpipe_clause {
                line.push_str(clause);
            }
            if rule.action == "pass" {
                line.push_str(" keep state");
            }
            line
        })
        .collect()
}

/// Splice custom rule ke ANTARA marker '# NTPSENSE_CUSTOM_RULES_<if>_START'
/// dan '_END' di /etc/pf.conf (marker ini SUDAH ada di posisi yang benar
/// dari install-gateway-v2.sh Bagian 6 - lihat komentar di sana soal
/// alasan posisinya). WAJIB validasi 'pfctl -nf' SEBELUM apply - draft
/// TIDAK PERNAH ditulis ke /etc/pf.conf kalau invalid (prinsip yang
/// sama dipegang sejak Bagian 6 install-gateway-v2.sh).
// ============================================================
// Zone Groups - model ADDITIVE pfSense "Interface Groups" (BUKAN
// model "zona" FortiGate yang menggantikan identitas interface total).
// Dua aturan inti: (1) WAN1/OPT ber-role WAN TIDAK BOLEH jadi anggota
// grup (best practice pfSense: reply-to/route-to tidak dapat perlakuan
// benar lewat tab grup); (2) rule di tab grup diproses SEBELUM rule
// individual interface, tidak bisa di-override di level interface.
// ============================================================

const ZONE_GROUPS_FILE: &str = "/usr/local/etc/ntpsense/zone-groups.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ZoneGroup {
    name: String,
    member_interfaces: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ZoneGroupsFile {
    #[serde(default)]
    groups: Vec<ZoneGroup>,
}

fn load_zone_groups() -> ZoneGroupsFile {
    fs::read_to_string(ZONE_GROUPS_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_zone_groups(data: &ZoneGroupsFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(ZONE_GROUPS_FILE, json).map_err(|e| e.to_string())
}

/// Interface yang BOLEH jadi anggota Zone Group - LAN1 dan OPT yang
/// BUKAN ber-role WAN.
fn zone_group_eligible_interfaces() -> Vec<String> {
    let (lan1_if, _wan1_if, opt_ifaces) = parse_pf_conf_zones();
    let roles = load_roles();
    let mut result: Vec<String> = Vec::new();
    if let Some(l) = lan1_if {
        result.push(l);
    }
    for o in opt_ifaces {
        let is_wan = roles.get(&o).map(|r| r == "WAN").unwrap_or(false);
        if !is_wan {
            result.push(o);
        }
    }
    result
}

fn create_zone_group(name: &str, member_interfaces: &[String]) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Zone Group name cannot be empty.".to_string());
    }
    if member_interfaces.is_empty() {
        return Err("A Zone Group needs at least one member interface.".to_string());
    }
    let eligible = zone_group_eligible_interfaces();
    for m in member_interfaces {
        if !eligible.contains(m) {
            return Err(format!(
                "'{m}' is not eligible for a Zone Group - only LAN1 and OPT interfaces WITHOUT the WAN role can be grouped (matches pfSense's own best practice against mixing WANs into interface groups)."
            ));
        }
    }
    let mut data = load_zone_groups();
    if data.groups.iter().any(|g| g.name.eq_ignore_ascii_case(name)) {
        return Err(format!("A Zone Group named '{name}' already exists."));
    }
    data.groups.push(ZoneGroup { name: name.to_string(), member_interfaces: member_interfaces.to_vec() });
    save_zone_groups(&data)?;
    Ok(())
}

fn update_zone_group(name: &str, member_interfaces: &[String]) -> Result<(), String> {
    if member_interfaces.is_empty() {
        return Err("A Zone Group needs at least one member interface.".to_string());
    }
    let eligible = zone_group_eligible_interfaces();
    for m in member_interfaces {
        if !eligible.contains(m) {
            return Err(format!("'{m}' is not eligible for a Zone Group (LAN1/OPT non-WAN only)."));
        }
    }
    let mut data = load_zone_groups();
    let old_members = data.groups.iter().find(|g| g.name == name).map(|g| g.member_interfaces.clone());
    let Some(group) = data.groups.iter_mut().find(|g| g.name == name) else {
        return Err(format!("Zone Group '{name}' not found."));
    };
    group.member_interfaces = member_interfaces.to_vec();
    save_zone_groups(&data)?;
    let mut all_affected: Vec<String> = member_interfaces.to_vec();
    if let Some(old) = old_members {
        for o in old {
            if !all_affected.contains(&o) {
                all_affected.push(o);
            }
        }
    }
    for iface in &all_affected {
        let _ = regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface));
    }
    Ok(())
}

fn delete_zone_group(name: &str) -> Result<(), String> {
    let rules_using = load_custom_rules().rules.iter().any(|r| r.zone_group.as_deref() == Some(name));
    if rules_using {
        return Err(format!(
            "Cannot delete Zone Group '{name}' - it still has Firewall rules on its tab. Remove those rules first."
        ));
    }
    let mut data = load_zone_groups();
    let removed = data.groups.iter().find(|g| g.name == name).map(|g| g.member_interfaces.clone());
    let before = data.groups.len();
    data.groups.retain(|g| g.name != name);
    if data.groups.len() == before {
        return Err(format!("Zone Group '{name}' not found."));
    }
    save_zone_groups(&data)?;
    if let Some(members) = removed {
        for iface in &members {
            let _ = regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface));
        }
    }
    Ok(())
}

/// Gabungkan rule Zone Group (untuk grup mana pun yang beranggotakan
/// interface ini) DENGAN rule individual interface ini - rule grup
/// SELALU ditaruh DULUAN (semantik pfSense: diproses sebelum rule
/// individual, tidak bisa di-override di level interface).
fn effective_rules_for_interface(iface: &str) -> Vec<CustomRule> {
    let all_rules = load_custom_rules().rules;
    let groups = load_zone_groups().groups;
    let mut effective: Vec<CustomRule> = Vec::new();

    for group in &groups {
        if !group.member_interfaces.iter().any(|m| m == iface) {
            continue;
        }
        for rule in all_rules.iter().filter(|r| r.enabled && r.zone_group.as_deref() == Some(group.name.as_str())) {
            let mut materialized = rule.clone();
            materialized.interface = iface.to_string();
            effective.push(materialized);
        }
    }

    for rule in all_rules.iter().filter(|r| r.enabled && r.zone_group.is_none() && r.interface == iface) {
        effective.push(rule.clone());
    }

    effective
}

// ============================================================
// Date & Time / NTP - GAP NYATA ditemukan lewat bug 2FA bro (kode
// TOTP ditolak karena jam gateway tidak akurat): install-gateway-v2.sh
// TERNYATA tidak pernah benar-benar mengaktifkan NTP daemon sama
// sekali - "NTP" cuma muncul sebagai bagian nama produk, bukan
// instruksi konfigurasi sungguhan. ntpd BAWAAN FreeBSD base, tapi
// TIDAK otomatis aktif tanpa 'ntpd_enable=YES' eksplisit. Riset
// FortiGate/pfSense sebelum dibangun: keduanya punya halaman System >
// Date & Time standar (bukan cuma timezone) + FortiGate bahkan punya
// banner peringatan otomatis kalau jam meleset >2 menit - pola itu
// yang ditiru di sini.
// ============================================================

const NTP_CONF_PATH: &str = "/etc/ntp.conf";
const TIMEZONE_FILE: &str = "/etc/localtime";
const ZONEINFO_DIR: &str = "/usr/share/zoneinfo";

/// Pasang NTP daemon TANPA SYARAT - pola "unconditional reapply" yang
/// sama dipegang konsisten di seluruh project ini. Aman dipanggil
/// berkali-kali (idempotent) - kalau sudah aktif+terkonfigurasi,
/// cuma memastikan tetap begitu, tidak mengganggu apa pun.
fn ensure_ntp_configured() {
    // Server default - pool.ntp.org, standar industri (dipakai
    // pfSense/FreeBSD base sebagai default juga) - bukan server privat
    // vendor tertentu, supaya tetap jalan di jaringan mana pun.
    if !std::path::Path::new(NTP_CONF_PATH).exists() {
        let default_conf = "pool 0.freebsd.pool.ntp.org iburst\npool 1.freebsd.pool.ntp.org iburst\npool 2.freebsd.pool.ntp.org iburst\npool 3.freebsd.pool.ntp.org iburst\n";
        let _ = fs::write(NTP_CONF_PATH, default_conf);
    }
    let _ = Command::new("sysrc").arg("ntpd_enable=YES").status();
    // '-g' penting - izinkan lompatan besar sekali di awal (kalau jam
    // sudah jauh meleset, mis. clock VM yang baru pertama kali hidup)
    // alih-alih ntpd menolak koreksi karena dianggap "terlalu besar,
    // mungkin serangan" (perilaku default tanpa -g).
    let _ = Command::new("sysrc").arg("ntpd_sync_on_start=YES").status();
    // RCA (ditemukan bro langsung dari log VM nyata): 'service ntpd
    // status' PERNAH salah lapor "not running" padahal proses ntpd
    // ASLI masih hidup sehat (pidfile custom di /var/db/ntp/ntpd.pid,
    // beda dari lokasi default yang mungkin dicek status wrapper).
    // Akibatnya kode ini percaya begitu saja dan coba start instance
    // KEDUA - yang langsung gagal ("unable to bind... another process
    // may be running - EXITING") karena instance pertama masih pegang
    // semua socket port 123. Tidak pernah benar-benar merusak sync
    // waktu (instance asli tidak terganggu), tapi bikin noise WARNING
    // di log SETIAP restart daemon. Pola sama seperti Kea/Squid/
    // WireGuard di project ini: JANGAN percaya exit code status
    // wrapper - cek keberadaan proses ASLI dulu (pgrep) sebelum
    // memutuskan perlu start atau tidak.
    let real_process_alive = Command::new("pgrep").arg("-x").arg("ntpd").output().map(|o| o.status.success() && !o.stdout.is_empty()).unwrap_or(false);
    if !real_process_alive {
        let _ = Command::new("service").arg("ntpd").arg("start").status();
    }
}

/// Parse 'ntpq -p' - baris yang diawali '*' adalah sumber sync AKTIF
/// SAAT INI (bukan cuma kandidat) - itu satu-satunya baris yang
/// dianggap "tersinkron" untuk status ringkas di Web UI.
fn get_ntp_status() -> serde_json::Value {
    let output = Command::new("ntpq").arg("-p").output();
    let Ok(output) = output else {
        return serde_json::json!({ "running": false, "synced": false, "offset_ms": null, "peers": [] });
    };
    if !output.status.success() {
        return serde_json::json!({ "running": false, "synced": false, "offset_ms": null, "peers": [] });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut synced = false;
    let mut offset_ms: Option<f64> = None;
    let mut peers: Vec<serde_json::Value> = Vec::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('=') || line.trim().is_empty() || line.starts_with("     remote") {
            continue;
        }
        let status_char = line.chars().next().unwrap_or(' ');
        let rest = &line[1..];
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let remote = cols[0].to_string();
        let offset: f64 = cols[cols.len() - 2].parse().unwrap_or(0.0);
        if status_char == '*' {
            synced = true;
            offset_ms = Some(offset);
        }
        peers.push(serde_json::json!({ "remote": remote, "status": status_char.to_string(), "offset_ms": offset }));
    }
    serde_json::json!({ "running": true, "synced": synced, "offset_ms": offset_ms, "peers": peers })
}

// ============================================================
// DNS servers - GAP LAIN ditemukan bro langsung setelah bug 2FA/NTP:
// belum pernah ada halaman Web UI yang menampilkan/mengatur DNS
// server sama sekali sepanjang project ini (cuma implisit dari DHCP
// WAN1). Relevan LANGSUNG dengan NTP - server berbasis hostname
// (pool.ntp.org, dst) butuh DNS resolusi dulu sebelum bisa connect,
// persis kelas masalah yang baru saja kita bereskan bareng.
// ============================================================

fn get_dns_servers() -> Vec<String> {
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver").map(|rest| rest.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn set_dns_servers(servers: &[String]) -> Result<(), String> {
    for s in servers {
        if parse_ipv4(s).is_none() {
            return Err(format!("'{s}' is not a valid IPv4 DNS server address"));
        }
    }
    // Baris SELAIN 'nameserver' (mis. 'search <domain>', 'options ...')
    // DIPERTAHANKAN apa adanya - cuma baris nameserver yang diganti
    // total, pola sama dengan penanganan /etc/ntp.conf di system.update.
    let existing = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut new_lines: Vec<String> = existing.lines().filter(|l| !l.trim().starts_with("nameserver")).map(|s| s.to_string()).collect();
    for s in servers {
        new_lines.push(format!("nameserver {s}"));
    }
    fs::write("/etc/resolv.conf", new_lines.join("\n") + "\n").map_err(|e| format!("Failed to write /etc/resolv.conf: {e}"))
}

fn get_current_timezone() -> String {
    // /etc/localtime itu symlink ke /usr/share/zoneinfo/<Region>/<City>
    // di FreeBSD - baca target symlink-nya, potong prefix zoneinfo.
    match fs::read_link(TIMEZONE_FILE) {
        Ok(target) => {
            let target_str = target.to_string_lossy().to_string();
            target_str.strip_prefix(&format!("{ZONEINFO_DIR}/")).unwrap_or("UTC").to_string()
        }
        Err(_) => "UTC".to_string(),
    }
}

/// Parser koordinat ISO 6709 - format resmi dipakai zone1970.tab IANA
/// tzdata. Dua bentuk: "±DDMM±DDDMM" (tanpa detik, 11 karakter total)
/// atau "±DDMMSS±DDDMMSS" (dengan detik, 15 karakter total) - dibedakan
/// murni dari PANJANG string-nya (posisi split antara lat/lon TIDAK
/// ditandai pemisah apa pun di format aslinya, cuma bisa dihitung dari
/// tahu-persis berapa digit tiap bagian).
fn parse_iso6709(coord: &str) -> Option<(f64, f64)> {
    match coord.len() {
        11 => Some((parse_dm(&coord[0..5], 2)?, parse_dm(&coord[5..11], 3)?)),
        15 => Some((parse_dms(&coord[0..7], 2)?, parse_dms(&coord[7..15], 3)?)),
        _ => None,
    }
}

fn parse_dm(s: &str, deg_digits: usize) -> Option<f64> {
    let sign = if s.starts_with('-') { -1.0 } else { 1.0 };
    let digits = &s[1..];
    let deg: f64 = digits.get(0..deg_digits)?.parse().ok()?;
    let min: f64 = digits.get(deg_digits..)?.parse().ok()?;
    Some(sign * (deg + min / 60.0))
}

fn parse_dms(s: &str, deg_digits: usize) -> Option<f64> {
    let sign = if s.starts_with('-') { -1.0 } else { 1.0 };
    let digits = &s[1..];
    let deg: f64 = digits.get(0..deg_digits)?.parse().ok()?;
    let min: f64 = digits.get(deg_digits..deg_digits + 2)?.parse().ok()?;
    let sec: f64 = digits.get(deg_digits + 2..)?.parse().ok()?;
    Some(sign * (deg + min / 60.0 + sec / 3600.0))
}

fn set_timezone(tz: &str) -> Result<(), String> {
    // Validasi - tolak path traversal DAN tolak nama yang bukan file
    // zoneinfo sungguhan (bukan validasi kosmetik, /etc/localtime
    // adalah symlink yang dibaca banyak bagian sistem - salah satu
    // yang salah bisa bikin log timestamp seluruh sistem kacau).
    if tz.contains("..") || tz.starts_with('/') {
        return Err("Invalid timezone name".to_string());
    }
    let source = format!("{ZONEINFO_DIR}/{tz}");
    if !std::path::Path::new(&source).exists() {
        return Err(format!("'{tz}' is not a known timezone"));
    }
    let _ = fs::remove_file(TIMEZONE_FILE);
    std::os::unix::fs::symlink(&source, TIMEZONE_FILE).map_err(|e| format!("Failed to set timezone: {e}"))?;
    // adjkerntz -a menyamakan waktu kernel FreeBSD dengan RTC+timezone
    // baru - tanpa ini, /etc/localtime berubah tapi kernel time offset
    // internal masih pakai timezone lama sampai reboot.
    let _ = Command::new("adjkerntz").arg("-a").status();
    Ok(())
}

// ============================================================
// REST API (roadmap #5) - riset FortiGate/pfSense sebelum dibangun:
// FortiGate cuma pakai token-based auth (bukan username/password di
// API), token digenerate SEKALI untuk akun "API administrator"
// terpisah, DITAMPILKAN SEKALI (pola sama dengan recovery codes 2FA
// kita), dikirim lewat header Authorization (bukan URL param - FortiGate
// eksplisit menyarankan hindari URL param). pfSense punya API Key +
// JWT, dua-duanya Bearer token di header juga.
//
// MVP yang disepakati bareng bro: endpoint TUNGGAL (bukan REST
// resource-per-endpoint penuh - itu jauh lebih besar scope-nya),
// meneruskan {action, params} yang SAMA persis dipakai protokol
// internal daemon lewat Unix socket, dengan 2 tingkat izin sederhana
// (Read-only / Full) diklasifikasi dari POLA NAMA action (bukan
// registry per-action yang sangat besar) - "cukup" untuk least-
// privilege dasar tanpa membangun ulang seluruh sistem RBAC kategori
// yang sudah ada untuk Users/Roles Web UI.
// ============================================================

const API_KEYS_FILE: &str = "/usr/local/etc/ntpsense/api-keys.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKey {
    id: String,
    name: String,
    token_hash: String,
    permission: String, // "read" | "full"
    #[serde(default)]
    trusted_ip: Option<String>,
    created_at: u64,
    #[serde(default)]
    last_used_at: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ApiKeysFile {
    #[serde(default)]
    keys: Vec<ApiKey>,
}

fn load_api_keys() -> ApiKeysFile {
    fs::read_to_string(API_KEYS_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_api_keys(data: &ApiKeysFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    fs::write(API_KEYS_FILE, json).map_err(|e| e.to_string())
}

/// SHA256 biasa (bukan bcrypt/argon2) - token API sendiri SUDAH
/// high-entropy acak (256-bit dari /dev/urandom), beda dari password
/// manusia yang butuh hash lambat supaya tahan brute-force kamus.
/// Pola sama dipakai luas untuk API token (GitHub, Fortinet, dst).
fn hash_api_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 256-bit dari /dev/urandom langsung - tanpa dependency crate 'rand'
/// tambahan, CSPRNG bawaan OS yang sudah terbukti/standar di FreeBSD.
fn generate_api_token() -> Result<String, String> {
    use std::io::Read as _;
    let mut f = fs::File::open("/dev/urandom").map_err(|e| format!("failed to open /dev/urandom: {e}"))?;
    let mut bytes = [0u8; 32];
    f.read_exact(&mut bytes).map_err(|e| format!("failed to read /dev/urandom: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Klasifikasi Read vs Write dari POLA NAMA action - heuristik yang
/// disepakati sebagai MVP (bukan registry lengkap per-action). Action
/// yang TIDAK cocok pola manapun default ke Write (fail-safe konservatif
/// - lebih baik salah tolak action aman daripada salah izinkan action
/// berbahaya lewat key Read-only).
fn action_requires_write(action: &str) -> bool {
    let read_suffixes = [".list", ".status", ".get_config", ".get_status", ".get_log", ".get_alerts", ".eligible_interfaces", ".eligible_wan_interfaces", ".catalog", ".known_zones", ".hit_counts", ".sync_status", ".time_status", ".dns_status", ".list_timezones", ".settings_get"];
    let read_prefixes_exact = ["network.zones", "system.info", "system.get_dashboard_info", "multiwan.eligible_interfaces"];
    if read_prefixes_exact.contains(&action) {
        return false;
    }
    for suffix in read_suffixes {
        if action.ends_with(suffix) {
            return false;
        }
    }
    true
}

/// Verifikasi token dari header Authorization - hash yang masuk,
/// cocokkan ke daftar tersimpan, update last_used_at kalau cocok
/// (observability - kapan terakhir key ini benar-benar dipakai).
fn verify_api_token(token: &str, client_ip: &str) -> Result<ApiKey, String> {
    let hash = hash_api_token(token);
    let mut data = load_api_keys();
    let Some(key) = data.keys.iter_mut().find(|k| k.token_hash == hash) else {
        return Err("Invalid or revoked API token".to_string());
    };
    if let Some(trusted) = &key.trusted_ip {
        if trusted != client_ip {
            return Err(format!("API key '{}' is restricted to a different source IP", key.name));
        }
    }
    key.last_used_at = Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    let result = key.clone();
    let _ = save_api_keys(&data);
    Ok(result)
}

const FLOATING_PF_START_MARKER: &str = "# NTPSENSE_FLOATING_RULES_START";
const FLOATING_PF_END_MARKER: &str = "# NTPSENSE_FLOATING_RULES_END";
/// Sisipkan marker Floating Rules ke /etc/pf.conf kalau belum ada -
/// pola SAMA persis dengan sync_wireguard_pf_rule()/openvpn::
/// sync_pf_rule() (self-healing, aman dipanggil berkali-kali,
/// idempotent). Perlu dipanggil SEBELUM regenerate_floating_rules()
/// supaya VM yang sudah lama terinstall (dari sebelum fitur ini ada)
/// otomatis dapat marker-nya tanpa perlu migrasi pf.conf manual.
fn ensure_floating_pf_marker() -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    if content.contains(FLOATING_PF_START_MARKER) {
        return Ok(());
    }
    let anchor = "\nblock log all\n";
    let Some(idx) = content.find(anchor) else {
        return Err("Could not find 'block log all' anchor in /etc/pf.conf to insert Floating Rules marker".to_string());
    };
    let insert_at = idx + anchor.len();
    let new_content = format!(
        "{}\n{FLOATING_PF_START_MARKER}\n{FLOATING_PF_END_MARKER}\n\n{}",
        &content[..insert_at],
        &content[insert_at..]
    );
    let tmp_path = "/tmp/pf.conf.floating_marker_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed inserting Floating Rules marker - /etc/pf.conf NOT changed. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    Ok(())
}

/// Regenerasi isi marker Floating Rules - SATU baris per rule (bukan
/// diduplikasi per-interface seperti Zone Group), diambil dari SEMUA
/// custom rule yang floating=true dan enabled=true, urut sesuai
/// urutan tersimpan (reorder up/down berlaku sama seperti rule
/// interface biasa).
fn regenerate_floating_rules() -> Result<(), String> {
    ensure_floating_pf_marker()?;
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;

    let start_idx = content
        .find(FLOATING_PF_START_MARKER)
        .ok_or_else(|| format!("Marker '{FLOATING_PF_START_MARKER}' not found in /etc/pf.conf"))?;
    let end_idx = content
        .find(FLOATING_PF_END_MARKER)
        .ok_or_else(|| format!("Marker '{FLOATING_PF_END_MARKER}' not found in /etc/pf.conf"))?;
    let before = &content[..start_idx + FLOATING_PF_START_MARKER.len()];
    let after = &content[end_idx..];

    let floating_rules: Vec<CustomRule> = load_custom_rules().rules.into_iter().filter(|r| r.floating && r.enabled).collect();
    let mut middle = String::new();
    for rule in &floating_rules {
        for line in generate_rule_line(rule) {
            middle.push('\n');
            middle.push_str(&line);
        }
    }
    middle.push('\n');

    let new_content = format!("{before}{middle}{after}");
    let tmp_path = "/tmp/pf.conf.floating_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;
    let status = Command::new("pfctl").arg("-nf").arg(tmp_path).status().map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!("pfctl -nf validation failed on Floating Rules - /etc/pf.conf NOT changed. Draft at {tmp_path} for debugging."));
    }
    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

fn regenerate_pf_conf_for_interface(interface: &str, rules_for_iface: &[CustomRule]) -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;

    // wg0 - kasus khusus: markernya sudah ada sejak fitur WireGuard
    // dibangun (# NTPSENSE_WIREGUARD_PF_START/END, disisipkan
    // sync_wireguard_pf_rule() tepat setelah 'block all'), BUKAN pola
    // generik "NTPSENSE_CUSTOM_RULES_<if>" yang dipakai interface fisik.
    // Ketimbang ganti nama marker (yang butuh migrasi pf.conf manual di
    // setiap sistem yang sudah ter-install), fungsi ini cukup tahu untuk
    // pakai nama marker yang sudah ada - ditemukan sebagai bug nyata
    // begitu tab Firewall > wg0 dibuka untuk custom rule CRUD (sebelumnya
    // wg0 tidak pernah lewat sini sama sekali, jadi celah ini belum
    // ketahuan sampai sekarang).
    let (start_marker, end_marker) = if interface == WG_INTERFACE {
        (WG_PF_START_MARKER.to_string(), WG_PF_END_MARKER.to_string())
    } else {
        (
            format!("# NTPSENSE_CUSTOM_RULES_{interface}_START"),
            format!("# NTPSENSE_CUSTOM_RULES_{interface}_END"),
        )
    };

    let start_idx = content
        .find(&start_marker)
        .ok_or_else(|| format!("Marker '{start_marker}' not found in /etc/pf.conf - interface '{interface}' may not be a valid OPT"))?;
    let end_idx = content
        .find(&end_marker)
        .ok_or_else(|| format!("Marker '{end_marker}' not found in /etc/pf.conf"))?;

    let before = &content[..start_idx + start_marker.len()];
    let after = &content[end_idx..];

    let mut middle = String::new();
    for rule in rules_for_iface {
        for line in generate_rule_line(rule) {
            middle.push('\n');
            middle.push_str(&line);
        }
    }
    middle.push('\n');

    let mut new_content = format!("{before}{middle}{after}");

    // Splice the NAT_PORTFWD translation-section marker into the SAME
    // buffer, in the SAME validation pass - see generate_rdr_line() doc
    // comment for why rdr rules can't live in the filter marker above.
    // Doing this here (not as a separate write) means a bad rdr line and
    // a bad filter line are caught by ONE pfctl -nf call, and either BOTH
    // halves of a port-forward rule apply or NEITHER does.
    //
    // IMPORTANT: only touch this marker when regenerating WAN1 itself,
    // not any other interface - this function is called separately per
    // interface (LAN1/OPT/WAN1 each with their own rules_for_iface
    // subset). If this guard used "rdr_lines is non-empty" instead, a
    // LAN1-only regeneration (rdr_lines always empty there, since NAT
    // validation restricts redirects to WAN1) would WRONGLY WIPE WAN1's
    // real port-forward rules every time an unrelated LAN1 rule changed.
    // Always sync (even to empty) rather than only-when-non-empty, so
    // deleting the LAST port-forward rule actually clears the stale rdr
    // line instead of leaving a translation rule for a rule that no
    // longer exists.
    let (_, wan1_if, _) = parse_pf_conf_zones();
    if wan1_if.as_deref() == Some(interface) {
        let rdr_lines: Vec<String> = rules_for_iface.iter().filter_map(generate_rdr_line).collect();
        let nat_start = "# NTPSENSE_NAT_PORTFWD_START";
        let nat_end = "# NTPSENSE_NAT_PORTFWD_END";
        let nat_start_idx = new_content.find(nat_start).ok_or_else(|| {
            format!(
                "Marker '{nat_start}' not found in /etc/pf.conf - port forward needs this marker \
                 added after the 'nat on $wan1_if ...' line (see NAT feature setup notes)"
            )
        })?;
        let nat_end_idx = new_content.find(nat_end).ok_or_else(|| format!("Marker '{nat_end}' not found in /etc/pf.conf"))?;
        let nat_before = &new_content[..nat_start_idx + nat_start.len()];
        let nat_after = &new_content[nat_end_idx..];
        let mut nat_middle = String::new();
        for line in &rdr_lines {
            nat_middle.push('\n');
            nat_middle.push_str(line);
        }
        nat_middle.push('\n');
        new_content = format!("{nat_before}{nat_middle}{nat_after}");
    }

    let tmp_path = "/tmp/pf.conf.custom_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;

    let status = Command::new("pfctl")
        .arg("-nf")
        .arg(tmp_path)
        .status()
        .map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!(
            "pfctl -nf GAGAL validasi syntax - pf.conf TIDAK diubah. Draft ada di {tmp_path} untuk debug."
        ));
    }

    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

/// Update SATU macro di /etc/pf.conf (format 'nama = "nilai_lama"' jadi
/// 'nama = "nilai_baru"') - dipakai Fase B untuk update 'lan1_net' saat
/// subnet LAN1 berubah. Rule sistem yang REFERENSI macro ini (mis.
/// 'block in quick on emX to $lan1_net') OTOMATIS ikut berubah begitu
/// pf.conf di-reload - TIDAK PERLU migrasi manual (persis prinsip
/// "Zona" yang dibahas - macro pf setara konsep Zone/Address Object di
/// FortiGate/Palo Alto: ubah definisi sekali, semua rule yang mengacu
/// ke situ otomatis ikut, TANPA menulis ulang rule satu-satu).
fn update_pf_conf_macro(macro_name: &str, new_value: &str) -> Result<(), String> {
    let content = fs::read_to_string("/etc/pf.conf").map_err(|e| format!("Failed to read /etc/pf.conf: {e}"))?;
    let prefix = format!("{macro_name} = \"");

    let mut found = false;
    let new_lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&prefix) {
                found = true;
                format!("{macro_name} = \"{new_value}\"")
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        return Err(format!("Macro '{macro_name}' not found in /etc/pf.conf"));
    }

    let new_content = new_lines.join("\n") + "\n";
    let tmp_path = "/tmp/pf.conf.macro_new";
    fs::write(tmp_path, &new_content).map_err(|e| format!("Failed to write draft: {e}"))?;

    let status = Command::new("pfctl")
        .arg("-nf")
        .arg(tmp_path)
        .status()
        .map_err(|e| format!("Failed to run pfctl -nf: {e}"))?;
    if !status.success() {
        return Err(format!(
            "pfctl -nf GAGAL validasi syntax - pf.conf TIDAK diubah. Draft ada di {tmp_path} untuk debug."
        ));
    }

    fs::copy(tmp_path, "/etc/pf.conf").map_err(|e| format!("Failed to copy to /etc/pf.conf: {e}"))?;
    let _ = Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status();
    Ok(())
}

/// Scan SEMUA custom rule (lintas interface, bukan cuma interface yang
/// sedang diubah - admin bisa saja mengetik subnet LAN1 sebagai
/// destination di rule OPT) untuk literal string yang cocok subnet
/// LAMA. Pola SENGAJA "warn dulu, block sampai admin konfirmasi" (ala
/// FortiGate/Palo Alto - popup alert kalau interface/subnet masih
/// dipakai rule), BUKAN auto-migrate diam-diam - risiko auto-migrate
/// salah tafsir (subnet yang diketik BUKAN untuk merujuk zona sendiri,
/// tapi kebetulan mirip IP eksternal) lebih berbahaya daripada
/// merepotkan admin sedikit untuk konfirmasi.
fn scan_rules_for_literal_subnet(old_cidr: &str) -> Vec<CustomRule> {
    let data = load_custom_rules();
    let old_network = old_cidr.split('/').next().unwrap_or(old_cidr);
    data.rules
        .into_iter()
        .filter(|r| r.source.contains(old_network) || r.destination.contains(old_network))
        .collect()
}

fn handle_action(action: &str, params: &serde_json::Value) -> Result<serde_json::Value, (String, String)> {
    match action {
        "zone.mgmt_interface" => match fs::read_to_string(MGMT_LOCK_FILE) {
            Ok(contents) => {
                let iface = contents.trim().to_string();
                Ok(serde_json::json!({ "mgmt_interface": iface, "locked": true }))
            }
            Err(e) => Err(("INTERNAL_ERROR".to_string(), format!("Unable to read {MGMT_LOCK_FILE}: {e}"))),
        },
        "zone.reassign" => {
            let requested_if = params.get("interface").and_then(|v| v.as_str()).unwrap_or("");
            if let Ok(mgmt_if) = fs::read_to_string(MGMT_LOCK_FILE) {
                if requested_if == mgmt_if.trim() {
                    return Err((
                        "PERMISSION_DENIED".to_string(),
                        format!("Interface {requested_if} is the locked MGMT interface - cannot be reassigned"),
                    ));
                }
            }
            Err(("NOT_IMPLEMENTED".to_string(), "zone.reassign for non-MGMT interfaces is not yet implemented".to_string()))
        }
        // Query read-only gabungan seluruh zona (MGMT dari lock file,
        // LAN1/WAN1 dari macro pf.conf, OPT dari pola rule per-interface)
        // + IP live tiap interface via ifconfig - dipakai halaman Network.
        "network.zones" => {
            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let aliases = load_aliases();
            let descriptions = load_descriptions();
            let port_status = load_port_status();
            let roles = load_roles();
            let dhcp_configs = load_dhcp_configs();

            let dhcp_json = |name: &str| -> serde_json::Value {
                match dhcp_configs.get(name) {
                    Some(cfg) => serde_json::to_value(cfg).unwrap_or(serde_json::Value::Null),
                    None => serde_json::json!({ "enabled": false, "range_start": "", "range_end": "", "dns_servers": [], "lease_time": 604800, "option43_wlc_ips": [] }),
                }
            };

            let build_zone = |iface: &Option<String>, default_label: &str, fixed_role: &str, default_description: &str, supports_dhcp: bool| -> serde_json::Value {
                match iface {
                    Some(name) => serde_json::json!({
                        "interface": name,
                        "ip": get_interface_ip(name),
                        "prefix": get_interface_prefix(name),
                        "ip_mode": get_interface_config_mode(name),
                        "alias": aliases.get(name).cloned().unwrap_or_else(|| default_label.to_string()),
                        "description": descriptions.get(name).cloned().unwrap_or_else(|| default_description.to_string()),
                        "type": detect_interface_type(name),
                        "enabled": *port_status.get(name).unwrap_or(&true),
                        "link_up": get_interface_link_status(name),
                        "role": fixed_role,
                        "dhcp": if supports_dhcp { dhcp_json(name) } else { serde_json::Value::Null },
                    }),
                    None => serde_json::json!({ "interface": null, "ip": null, "prefix": null, "ip_mode": null, "alias": null, "description": null, "type": null, "enabled": null, "link_up": null, "role": null, "dhcp": null }),
                }
            };

            let opt_zones: Vec<serde_json::Value> = opt_ifaces
                .iter()
                .enumerate()
                .map(|(i, name)| serde_json::json!({
                    "interface": name,
                    "ip": get_interface_ip(name),
                    "prefix": get_interface_prefix(name),
                    "ip_mode": get_interface_config_mode(name),
                    "alias": aliases.get(name).cloned().unwrap_or_else(|| format!("OPT{}", i + 1)),
                    "description": descriptions.get(name).cloned().unwrap_or_default(),
                    "type": detect_interface_type(name),
                    "enabled": *port_status.get(name).unwrap_or(&true),
                    "link_up": get_interface_link_status(name),
                    "role": roles.get(name).cloned().unwrap_or_else(|| "Undefined".to_string()),
                    "dhcp": dhcp_json(name),
                }))
                .collect();

            Ok(serde_json::json!({
                "mgmt": build_zone(&mgmt_if, "MGMT", "MGMT", "Locked, cannot be reassigned", false),
                "lan1": build_zone(&lan1_if, "LAN1", "LAN", "Trusted, full access to MGMT + internet", true),
                "wan1": build_zone(&wan1_if, "WAN1", "WAN", "DHCP from upstream ISP", false),
                "opt": opt_zones,
            }))
        }
        "network.lagg_available_members" => {
            // Kandidat member LAGG - OPT dengan Role=Undefined DAN tanpa
            // custom rule apa pun (SAMA persis validasi yang dipakai
            // network.lagg_create - satu sumber kebenaran, Web UI cuma
            // tampilkan hasil query ini, tidak duplikasi logikanya sendiri).
            //
            // RCA (bug nyata - "lagg0" sendiri sempat muncul sebagai
            // kandidat untuk BIKIN lagg BARU, padahal dia sudah SEBUAH
            // interface lagg): begitu lagg0 dibuat, dia otomatis jadi OPT
            // baru dengan Role=Undefined (default OPT baru) - filter di
            // sini cuma cek Role/rule, tidak pernah mengecualikan
            // interface yang namanya sendiri diawali "lagg". Nesting
            // lagg-di-dalam-lagg TIDAK masuk akal secara teknis (laggport
            // FreeBSD mengharapkan NIC fisik, bukan interface lagg lain).
            let (_, _, opt_ifaces) = parse_pf_conf_zones();
            let roles = load_roles();
            let custom_rules = load_custom_rules();
            let aliases = load_aliases();
            let candidates: Vec<serde_json::Value> = opt_ifaces
                .iter()
                .filter(|name| {
                    if name.starts_with("lagg") {
                        return false;
                    }
                    let role = roles.get(*name).map(|s| s.as_str()).unwrap_or("Undefined");
                    let has_rules = custom_rules.rules.iter().any(|r| &r.interface == *name);
                    role == "Undefined" && !has_rules
                })
                .map(|name| serde_json::json!({
                    "interface": name,
                    "alias": aliases.get(name).cloned(),
                }))
                .collect();
            Ok(serde_json::json!({ "candidates": candidates }))
        }
        "network.lagg_create" => {
            let members: Vec<String> = params
                .get("members")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("failover").to_string();
            match lagg_create(&members, &protocol) {
                Ok(lagg_name) => Ok(serde_json::json!({ "lagg_interface": lagg_name })),
                Err(msg) => Err(("LAGG_CREATE_FAILED".to_string(), msg)),
            }
        }
        "network.lagg_list" => {
            let lagg_names = get_existing_lagg_names();
            let details: Vec<serde_json::Value> = lagg_names
                .iter()
                .map(|name| {
                    let (protocol, members) = lagg_get_current_state(name);
                    serde_json::json!({
                        "interface": name,
                        "protocol": protocol,
                        "members": members,
                        "ip": get_interface_ip(name),
                    })
                })
                .collect();
            Ok(serde_json::json!({ "lagg_groups": details }))
        }
        "network.lagg_edit" => {
            let lagg_name = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let members: Vec<String> = params
                .get("members")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("failover").to_string();
            match lagg_edit(&lagg_name, &members, &protocol) {
                Ok(()) => Ok(serde_json::json!({ "interface": lagg_name })),
                Err(msg) => Err(("LAGG_EDIT_FAILED".to_string(), msg)),
            }
        }
        "network.lagg_delete" => {
            let lagg_name = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match lagg_delete(&lagg_name) {
                Ok(()) => Ok(serde_json::json!({ "deleted": lagg_name })),
                Err(msg) => Err(("LAGG_DELETE_FAILED".to_string(), msg)),
            }
        }
        "network.reset_interface" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match reset_interface(&interface) {
                Ok(()) => Ok(serde_json::json!({ "reset": interface })),
                Err(msg) => Err(("RESET_FAILED".to_string(), msg)),
            }
        }
        "network.vlan_db_list" => {
            // "show vlan"-style response: setiap entry katalog (ID+Name)
            // di-cross-reference LIVE dengan interface vlan(4) yang
            // sungguhan terikat ke ID itu (via get_existing_vlan_names +
            // get_vlan_current_state) - "status" dan "interfaces" SELALU
            // dihitung fresh, tidak pernah disimpan statis di file
            // katalog (supaya tidak pernah nyasar/basi).
            let db = load_vlan_database();
            let vlan_interfaces = get_existing_vlan_names();
            let entries: Vec<serde_json::Value> = db.vlans.iter().map(|entry| {
                let bound: Vec<serde_json::Value> = vlan_interfaces
                    .iter()
                    .filter_map(|name| get_vlan_current_state(name).map(|(tag, parent)| (name.clone(), tag, parent)))
                    .filter(|(_, tag, _)| *tag == entry.id)
                    .map(|(name, _, parent)| serde_json::json!({ "interface": name, "parent": parent }))
                    .collect();
                serde_json::json!({
                    "id": entry.id,
                    "name": entry.name,
                    "status": if bound.is_empty() { "not bound" } else { "active" },
                    "interfaces": bound,
                })
            }).collect();
            Ok(serde_json::json!({ "vlans": entries }))
        }
        "network.vlan_db_create" => {
            let id = params.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match vlan_db_create(id, &name) {
                Ok(()) => Ok(serde_json::json!({ "id": id, "name": name })),
                Err(msg) => Err(("VLAN_DB_CREATE_FAILED".to_string(), msg)),
            }
        }
        "network.vlan_db_delete" => {
            let id = params.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            match vlan_db_delete(id) {
                Ok(()) => Ok(serde_json::json!({ "deleted": id })),
                Err(msg) => Err(("VLAN_DB_DELETE_FAILED".to_string(), msg)),
            }
        }
        "network.vlan_available_parents" => {
            let aliases = load_aliases();
            let parents: Vec<serde_json::Value> = get_vlan_eligible_parents()
                .iter()
                .map(|name| serde_json::json!({
                    "interface": name,
                    "alias": aliases.get(name).cloned(),
                    "type": detect_interface_type(name),
                    "has_ip": get_interface_ip(name).is_some(),
                }))
                .collect();
            Ok(serde_json::json!({ "candidates": parents }))
        }
        "network.vlan_create" => {
            let parent = params.get("parent").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let tag = params.get("tag").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            match vlan_create(&parent, tag) {
                Ok((vlan_name, parent_has_ip)) => Ok(serde_json::json!({
                    "interface": vlan_name,
                    "parent_has_ip": parent_has_ip,
                })),
                Err(msg) => Err(("VLAN_CREATE_FAILED".to_string(), msg)),
            }
        }
        "network.vlan_list" => {
            let vlan_names = get_existing_vlan_names();
            let aliases = load_aliases();
            let details: Vec<serde_json::Value> = vlan_names
                .iter()
                .map(|name| {
                    let (tag, parent) = get_vlan_current_state(name).unwrap_or((0, "unknown".to_string()));
                    serde_json::json!({
                        "interface": name,
                        "tag": tag,
                        "parent": parent,
                        "alias": aliases.get(name).cloned(),
                        "ip": get_interface_ip(name),
                        "prefix": get_interface_prefix(name),
                    })
                })
                .collect();
            Ok(serde_json::json!({ "vlans": details }))
        }
        "network.vlan_delete" => {
            let vlan_name = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match vlan_delete(&vlan_name) {
                Ok(()) => Ok(serde_json::json!({ "deleted": vlan_name })),
                Err(msg) => Err(("VLAN_DELETE_FAILED".to_string(), msg)),
            }
        }
        "network.loopback_list" => {
            let names = get_loopback_names();
            let details: Vec<serde_json::Value> = names
                .iter()
                .map(|name| serde_json::json!({
                    "interface": name,
                    "ip": get_interface_ip(name),
                    "locked": name == "lo0",
                }))
                .collect();
            Ok(serde_json::json!({ "loopbacks": details }))
        }
        "network.loopback_create" => {
            let ip = params.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let prefix = params.get("prefix").and_then(|v| v.as_u64()).unwrap_or(32) as u8;
            match loopback_create(&ip, prefix) {
                Ok(name) => Ok(serde_json::json!({ "interface": name })),
                Err(msg) => Err(("LOOPBACK_CREATE_FAILED".to_string(), msg)),
            }
        }
        "network.loopback_delete" => {
            let name = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match loopback_delete(&name) {
                Ok(()) => Ok(serde_json::json!({ "deleted": name })),
                Err(msg) => Err(("LOOPBACK_DELETE_FAILED".to_string(), msg)),
            }
        }
        // Fase A "Manage Interface" - set/ganti alias custom sebuah
        // interface. Validasi Lapis 2: interface HARUS salah satu zona
        // yang benar-benar dikenal sistem sekarang (MGMT/LAN1/WAN1/OPT),
        // MGMT TIDAK DIKECUALIKAN di sini (beda dari custom_rules) karena
        // alias murni kosmetik/label, tidak menyentuh pf.conf/keamanan -
        // memberi nama custom ke MGMT tidak berisiko seperti mengubah
        // rule-nya.
        "network.set_alias" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let alias = params.get("alias").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();

            if alias.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Alias cannot be empty".to_string()));
            }
            if alias.len() > 32 {
                return Err(("INVALID_PARAMS".to_string(), "Alias must be at most 32 characters".to_string()));
            }

            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let mut known_ifaces = opt_ifaces;
            if let Some(m) = &mgmt_if {
                known_ifaces.push(m.clone());
            }
            if let Some(l) = &lan1_if {
                known_ifaces.push(l.clone());
            }
            if let Some(w) = &wan1_if {
                known_ifaces.push(w.clone());
            }
            if !known_ifaces.contains(&interface) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not recognized (currently known interfaces: {known_ifaces:?})"),
                ));
            }

            let mut aliases = load_aliases();
            aliases.insert(interface.clone(), alias.clone());
            save_aliases(&aliases).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "interface": interface, "alias": alias }))
        }
        "network.set_description" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // Kosong DIIZINKAN (beda dari Alias yang wajib diisi) -
            // description murni catatan bebas, wajar kalau admin mau
            // hapus/kosongkan lagi.
            let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            if description.len() > 200 {
                return Err(("INVALID_PARAMS".to_string(), "Description must be at most 200 characters".to_string()));
            }

            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let mut known_ifaces = opt_ifaces;
            if let Some(m) = &mgmt_if {
                known_ifaces.push(m.clone());
            }
            if let Some(l) = &lan1_if {
                known_ifaces.push(l.clone());
            }
            if let Some(w) = &wan1_if {
                known_ifaces.push(w.clone());
            }
            if !known_ifaces.contains(&interface) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not recognized (currently known interfaces: {known_ifaces:?})"),
                ));
            }

            let mut descriptions = load_descriptions();
            if description.is_empty() {
                descriptions.remove(&interface);
            } else {
                descriptions.insert(interface.clone(), description.clone());
            }
            save_descriptions(&descriptions).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "interface": interface, "description": description }))
        }
        // Role klasifikasi (LAN/WAN/DMZ/Undefined, pola FortiGate Interface
        // Role) - HANYA berlaku untuk interface OPT. MGMT/LAN1/WAN1 SUDAH
        // punya role tetap otomatis (dikembalikan langsung di network.zones,
        // tidak pernah lewat file ROLE_FILE) - request untuk MGMT/LAN1/WAN1
        // di sini DITOLAK karena mengubahnya tidak masuk akal (role mereka
        // memang identik dengan nama zona-nya, bukan sesuatu yang "dipilih").
        "network.set_role" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let role = params.get("role").and_then(|v| v.as_str()).unwrap_or("").to_string();

            const VALID_ROLES: [&str; 4] = ["LAN", "WAN", "DMZ", "Undefined"];
            if !VALID_ROLES.contains(&role.as_str()) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("role must be one of {VALID_ROLES:?}"),
                ));
            }

            let (_, _, opt_ifaces) = parse_pf_conf_zones();
            if !opt_ifaces.contains(&interface) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not a valid OPT interface (currently detected OPT: {opt_ifaces:?}) - role can only be set for OPT interfaces, MGMT/LAN1/WAN1 already have a fixed role"),
                ));
            }

            // RCA (ditemukan SEBELUM kejadian nyata, saat menyusun skenario
            // test Role taxonomy - bukan hasil bug report user): mengubah
            // Role interface dari "WAN" ke apa pun yang lain TIDAK
            // memutus gateway Multi-WAN yang sudah ada di interface itu
            // (health monitoring baca interface/gateway_ip langsung dari
            // config gateway, TIDAK re-cek eligibility Role setiap
            // cycle - eligibility cuma dicek sekali saat CREATE gateway).
            // Dibiarkan begitu saja, ini kondisi rancu: interface tampil
            // "bukan WAN" di halaman Network, tapi diam-diam MASIH aktif
            // dipakai Multi-WAN - risiko nyata kalau Role interface itu
            // nanti di-set ulang jadi DMZ/LAN sementara gateway masih
            // hidup. Blok perubahan MENJAUH dari "WAN" kalau interface
            // itu masih jadi gateway aktif - pola sama dengan
            // delete_gateway() yang sudah lebih dulu mencegah hapus
            // gateway yang masih jadi anggota Gateway Group.
            if role != "WAN" {
                let using_gateways: Vec<String> = multiwan::list_gateways().iter().filter(|g| g.interface == interface).map(|g| g.name.clone()).collect();
                if !using_gateways.is_empty() {
                    return Err((
                        "INTERFACE_IN_USE".to_string(),
                        format!(
                            "Cannot change '{interface}' away from WAN role - it is still used by Multi-WAN gateway(s): {}. Delete or reassign those gateway(s) first.",
                            using_gateways.join(", ")
                        ),
                    ));
                }
            }

            let mut roles = load_roles();
            roles.insert(interface.clone(), role.clone());
            save_roles(&roles).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "interface": interface, "role": role }))
        }
        // Fase 1 DHCP server (Kea) - mengikuti field inti FortiOS: status
        // enable/disable, ip-range, dns-server, lease-time. HANYA valid
        // untuk LAN1/OPT (pola Fortinet: DHCP server dikonfigurasi di
        // interface ber-role LAN-type, bukan WAN/MGMT). Gateway TIDAK
        // jadi parameter di sini - SELALU dihitung live dari IP interface
        // itu sendiri saat regenerate_kea_config() dipanggil, supaya
        // tidak pernah nyasar kalau subnet berubah lewat Fase B nanti.
        "network.add_dhcp_reservation" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mac = params.get("mac").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ip = params.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let hostname = params.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if interface.is_empty() || mac.is_empty() || ip.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "interface, mac, and ip are required".to_string()));
            }
            let mut reservations = load_dhcp_reservations();
            // Cegah duplikat - kalau MAC ini sudah punya reservation,
            // UPDATE (bukan tambah entry baru) - idempotent.
            reservations.retain(|r| r.mac != mac);
            reservations.push(DhcpReservation { interface, mac, ip, hostname });
            save_dhcp_reservations(&reservations).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            regenerate_kea_config().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "success": true }))
        }
        "network.delete_dhcp_reservation" => {
            let mac = params.get("mac").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if mac.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "mac is required".to_string()));
            }
            let mut reservations = load_dhcp_reservations();
            reservations.retain(|r| r.mac != mac);
            save_dhcp_reservations(&reservations).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            regenerate_kea_config().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "success": true }))
        }
        "network.get_dhcp_leases" => {
            let reservations = load_dhcp_reservations();
            let reserved_macs: std::collections::HashSet<String> = reservations.iter().map(|r| r.mac.clone()).collect();

            // Tentukan interface pemilik tiap lease - dibutuhkan tombol
            // "Make Static" (reservation harus masuk subnet Kea yang
            // benar). Cocokkan via IP-in-CIDR (BUKAN subnet_id file
            // lease - itu bisa bergeser kalau config di-regenerate,
            // lebih rapuh dibanding cocokkan IP langsung ke CIDR
            // interface yang genuinely aktif SEKARANG).
            let dhcp_configs = load_dhcp_configs();
            let iface_subnets: Vec<(String, std::net::Ipv4Addr, u32)> = dhcp_configs.iter()
                .filter(|(_, cfg)| cfg.enabled)
                .filter_map(|(iface, _)| {
                    let cidr = get_interface_cidr(iface)?;
                    let normalized = normalize_network_cidr(&cidr)?;
                    let mut parts = normalized.split('/');
                    let net_ip: std::net::Ipv4Addr = parts.next()?.parse().ok()?;
                    let prefix: u32 = parts.next()?.parse().ok()?;
                    Some((iface.clone(), net_ip, prefix))
                })
                .collect();
            let find_iface_for_ip = |ip_str: &str| -> String {
                let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() else { return String::new(); };
                let ip_bits = u32::from(ip);
                for (iface, net_ip, prefix) in &iface_subnets {
                    let mask: u32 = if *prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                    if (ip_bits & mask) == (u32::from(*net_ip) & mask) {
                        return iface.clone();
                    }
                }
                String::new()
            };

            let mut leases: Vec<serde_json::Value> = get_dhcp_leases().into_iter().map(|l| {
                let is_static = reserved_macs.contains(&l.mac);
                let interface = find_iface_for_ip(&l.ip);
                serde_json::json!({
                    "ip": l.ip,
                    "mac": l.mac,
                    "hostname": l.hostname,
                    "lease_start": l.lease_start,
                    "lease_expire": l.lease_expire,
                    "active": l.active,
                    "is_static": is_static,
                    "interface": interface,
                })
            }).collect();

            // Tambahkan reservation yang BELUM PERNAH genuinely dipakai
            // (belum ada di file lease sama sekali) - tetap harus
            // tampil sebagai "Static" walau belum ada aktivitas DHCP
            // dari device itu, konsisten pola FortiGate/pfSense
            // (reservation kelihatan permanen di daftar, bukan cuma
            // muncul setelah lease pertama).
            let leased_macs: std::collections::HashSet<String> = leases.iter()
                .filter_map(|l| l.get("mac").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .collect();
            for r in reservations.iter().filter(|r| !leased_macs.contains(&r.mac)) {
                leases.push(serde_json::json!({
                    "ip": r.ip,
                    "mac": r.mac,
                    "hostname": r.hostname,
                    "lease_start": "-",
                    "lease_expire": "-",
                    "active": false,
                    "is_static": true,
                    "interface": r.interface,
                }));
            }

            Ok(serde_json::json!({ "leases": leases }))
        }
        "network.set_dhcp_config" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);

            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let is_lan1 = lan1_if.as_deref() == Some(interface.as_str());
            let is_opt = opt_ifaces.contains(&interface);
            if mgmt_if.as_deref() == Some(interface.as_str()) || wan1_if.as_deref() == Some(interface.as_str()) {
                return Err((
                    "PERMISSION_DENIED".to_string(),
                    "DHCP server is only available for LAN1/OPT interfaces, not MGMT/WAN1".to_string(),
                ));
            }
            if !is_lan1 && !is_opt {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not a valid LAN1/OPT interface for DHCP server"),
                ));
            }

            let mut configs = load_dhcp_configs();

            if enabled {
                let range_start = params.get("range_start").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let range_end = params.get("range_end").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let dns_servers: Vec<String> = params
                    .get("dns_servers")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                let lease_time = params.get("lease_time").and_then(|v| v.as_u64()).unwrap_or(604800) as u32;
                let option43_wlc_ips: Vec<String> = params
                    .get("option43_wlc_ips")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
                    .unwrap_or_default();

                if parse_ipv4(&range_start).is_none() {
                    return Err(("INVALID_PARAMS".to_string(), format!("range_start '{range_start}' is not a valid IP")));
                }
                if parse_ipv4(&range_end).is_none() {
                    return Err(("INVALID_PARAMS".to_string(), format!("range_end '{range_end}' is not a valid IP")));
                }
                // Validasi Option 43 di titik input, BUKAN cuma nanti
                // saat regenerate_kea_config() - supaya admin dapat
                // pesan error yang jelas segera, bukan Kea gagal start
                // diam-diam nanti setelah config sudah disimpan.
                if !option43_wlc_ips.is_empty() {
                    build_option43_hex(&option43_wlc_ips).map_err(|e| ("INVALID_PARAMS".to_string(), e))?;
                }
                let Some(cidr) = get_interface_cidr(&interface) else {
                    return Err(("INTERNAL_ERROR".to_string(), format!("Could not determine current subnet for '{interface}'")));
                };
                if !cidr_overlaps(&format!("{range_start}/32"), &cidr) || !cidr_overlaps(&format!("{range_end}/32"), &cidr) {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        format!("DHCP range {range_start} - {range_end} is not within the interface's current subnet ({cidr})"),
                    ));
                }

                configs.insert(
                    interface.clone(),
                    DhcpZoneConfig { enabled: true, range_start, range_end, dns_servers, lease_time, option43_wlc_ips },
                );
            } else if let Some(existing) = configs.get_mut(&interface) {
                existing.enabled = false;
            } else {
                // Belum pernah ada config sama sekali untuk interface ini,
                // dan admin minta disable - tidak ada apa-apa yang perlu
                // dilakukan (sudah 'disabled' secara default/implisit).
                return Ok(serde_json::json!({ "interface": interface, "enabled": false }));
            }

            save_dhcp_configs(&configs).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            regenerate_kea_config().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "interface": interface, "enabled": enabled }))
        }
        // Administrative port shutdown - pola sama dengan 'shutdown'/
        // 'no shutdown' Cisco atau enable/disable port Fortinet/Sangfor.
        // MGMT SENGAJA DIKECUALIKAN (tidak boleh di-disable) - beda dari
        // set_alias yang aman untuk MGMT, mematikan interface MGMT
        // adalah LOCKOUT TOTAL yang lebih parah dari sekadar salah rule
        // firewall (RCA #28) - fisik interface mati, bukan cuma diblok
        // pf, jadi tidak ada jalan pulih lewat Web UI sama sekali kalau
        // ini sampai ke-disable tanpa sengaja.
        "network.set_port_status" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool());
            let Some(enabled) = enabled else {
                return Err(("INVALID_PARAMS".to_string(), "Parameter 'enabled' must be a boolean true/false".to_string()));
            };

            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            if !enabled && mgmt_if.as_deref() == Some(interface.as_str()) {
                return Err((
                    "PERMISSION_DENIED".to_string(),
                    "The MGMT interface cannot be disabled from the Web UI - risk of total lockout (RCA #28)".to_string(),
                ));
            }

            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let mut known_ifaces = opt_ifaces;
            if let Some(m) = &mgmt_if {
                known_ifaces.push(m.clone());
            }
            if let Some(l) = &lan1_if {
                known_ifaces.push(l.clone());
            }
            if let Some(w) = &wan1_if {
                known_ifaces.push(w.clone());
            }
            if !known_ifaces.contains(&interface) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not recognized (currently known interfaces: {known_ifaces:?})"),
                ));
            }

            let updown = if enabled { "up" } else { "down" };
            let status = Command::new("ifconfig").arg(&interface).arg(updown).status();
            match status {
                Ok(s) if s.success() => {}
                _ => return Err(("INTERNAL_ERROR".to_string(), format!("Failed to run 'ifconfig {interface} {updown}'"))),
            }

            let mut port_status = load_port_status();
            port_status.insert(interface.clone(), enabled);
            save_port_status(&port_status).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "interface": interface, "enabled": enabled }))
        }
        // Fase B - ganti IP/subnet LAN1 atau OPT (BUKAN untuk MGMT -
        // tetap fixed by design, dan BUKAN untuk WAN1 - itu action
        // terpisah 'network.set_wan1_config' karena WAN1 punya konsep
        // gateway/default-route yang tidak relevan untuk LAN1/OPT).
        //
        // Alur "warn dulu, block sampai konfirmasi" (pola FortiGate/Palo
        // Alto - popup alert kalau interface masih dipakai rule): kalau
        // ada custom rule (LINTAS interface manapun, bukan cuma
        // interface yang diubah) yang menuliskan LITERAL subnet lama di
        // Source/Destination, request DITOLAK dengan daftar rule yang
        // terpengaruh - KECUALI 'confirm: true' eksplisit dikirim,
        // artinya admin sudah lihat peringatan dan tetap mau lanjut
        // (rule TIDAK diubah otomatis, TETAP jadi tanggung jawab admin
        // membersihkan/menyesuaikan manual setelahnya).
        //
        // Rule SISTEM (mis. 'block ... to $lan1_net') TIDAK PERLU
        // migrasi sama sekali - begitu macro lan1_net diupdate di sini,
        // rule itu OTOMATIS ikut berubah saat pf.conf reload (persis
        // prinsip Zone/Address Object FortiGate/Palo Alto yang dibahas).
        "network.set_subnet" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mode = params.get("mode").and_then(|v| v.as_str()).unwrap_or("static").to_string();

            // Mode DHCP Client - RCA (temuan nyata dari bro, dikonfirmasi
            // vendor rujukan kita semua: pfSense/FortiGate/Sangfor/Palo
            // Alto): setiap interface (bukan cuma WAN1) seharusnya bisa
            // jadi DHCP client, bukan cuma static. Kalau mode ini dipilih,
            // fitur DHCP SERVER interface itu OTOMATIS dinonaktifkan -
            // tidak masuk akal menyajikan DHCP Server untuk subnet yang
            // kita sendiri tidak tahu pasti (didapat dinamis dari DHCP
            // upstream). Pola aktivasi DHCP client REUSE persis dari
            // network.set_wan1_config (satu sumber kebenaran, bukan
            // duplikasi logika).
            if mode == "dhcp" {
                let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
                if mgmt_if.as_deref() == Some(interface.as_str()) {
                    return Err(("PERMISSION_DENIED".to_string(), "MGMT cannot be changed from here - it remains fixed by design".to_string()));
                }
                let (lan1_if, _wan1_if, opt_ifaces) = parse_pf_conf_zones();
                let is_lan1 = lan1_if.as_deref() == Some(interface.as_str());
                let is_opt = opt_ifaces.contains(&interface);
                if !is_lan1 && !is_opt {
                    return Err(("INVALID_PARAMS".to_string(), format!("Interface '{interface}' is not a valid LAN1/OPT for this action")));
                }

                // RCA (bug nyata ditemukan bro - lagg0 di-set DHCP Client,
                // rc.conf 'ifconfig_lagg0' yang TADINYA berisi
                // "laggproto failover laggport em2 laggport em3 laggport
                // em4" TERTIMPA TOTAL jadi cuma "DHCP" oleh baris di
                // bawah - begitu 'service netif restart' menerapkan
                // config yang sudah rusak itu, interface KEHILANGAN
                // konfigurasi member-nya sama sekali, dan lagg_delete()
                // yang dijalankan setelahnya membaca daftar member KOSONG
                // dari 'ifconfig lagg0' (bukan bug di lagg_delete() itu
                // sendiri - dia jadi korban config yang sudah rusak
                // duluan). Diblokir dulu di sini SENGAJA (bukan ditebak
                // syntax rc.conf gabungan lagg+DHCP yang benar tanpa
                // diverifikasi dulu - pelajaran dari insiden
                // stream_get_line sebelumnya: lebih aman blokir eksplisit
                // dengan pesan jelas daripada tebak lagi dan berisiko
                // merusak konfigurasi admin).
                if interface.starts_with("lagg") {
                    return Err((
                        "NOT_SUPPORTED".to_string(),
                        format!("DHCP Client mode is not yet supported for LAGG interfaces ('{interface}') - setting it would destroy the interface's laggproto/laggport configuration. This is a known gap, not a permanent limitation; use Static mode for LAGG interfaces for now."),
                    ));
                }

                let sysrc_status = Command::new("sysrc").arg(format!("ifconfig_{interface}=DHCP")).status();
                if !matches!(sysrc_status, Ok(s) if s.success()) {
                    return Err(("INTERNAL_ERROR".to_string(), "Failed to 'sysrc' set interface to DHCP".to_string()));
                }
                let _ = Command::new("service").arg("netif").arg("restart").arg(&interface).status();
                let _ = Command::new("dhclient").arg(&interface).status();

                let port_status = load_port_status();
                if !*port_status.get(&interface).unwrap_or(&true) {
                    let _ = Command::new("ifconfig").arg(&interface).arg("down").status();
                }

                // Nonaktifkan DHCP Server untuk interface ini - subnet-nya
                // sekarang dinamis (dari DHCP upstream), bukan sesuatu
                // yang bisa kita jadikan range DHCP Server sendiri.
                let mut dhcp_configs = load_dhcp_configs();
                if let Some(cfg) = dhcp_configs.get_mut(&interface) {
                    cfg.enabled = false;
                    save_dhcp_configs(&dhcp_configs).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                    regenerate_kea_config().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                }

                return Ok(serde_json::json!({ "interface": interface, "mode": "dhcp" }));
            }

            let ip = params.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let prefix = params.get("prefix").and_then(|v| v.as_u64()).unwrap_or(24) as u8;
            let confirm = params.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);

            if parse_ipv4(&ip).is_none() {
                return Err(("INVALID_PARAMS".to_string(), format!("IP '{ip}' is not valid")));
            }
            if prefix == 0 || prefix > 32 {
                return Err(("INVALID_PARAMS".to_string(), "Prefix must be between 1-32".to_string()));
            }
            let new_cidr = format!("{ip}/{prefix}");

            // Validasi #1: IP tidak boleh alamat network atau broadcast
            // dari subnet-nya sendiri (mis. 10.252.1.0/24 atau
            // 10.252.1.255/24 bukan IP host yang valid).
            let ip_bytes = parse_ipv4(&ip).unwrap(); // sudah divalidasi format-nya di atas
            if is_network_or_broadcast_address(ip_bytes, prefix) {
                return Err(("INVALID_PARAMS".to_string(), format!("'{ip}' is the network or broadcast address of {new_cidr} - not a valid host IP")));
            }
            // Validasi #2: IP tidak boleh masuk range reserved/special
            // (loopback/multicast/reserved) - private range TETAP boleh.
            if is_reserved_ip(ip_bytes) {
                return Err(("INVALID_PARAMS".to_string(), format!("'{ip}' is in a reserved/special IP range and cannot be assigned to an interface")));
            }

            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let is_mgmt = mgmt_if.as_deref() == Some(interface.as_str());
            // RCA nyata (ditemukan bro langsung lewat testing HA/CARP):
            // MGMT IP dulu dikunci PERMANEN atas nama anti-lockout - tapi
            // itu bikin masalah baru saat 2 node NTPSense dipasang untuk
            // HA: keduanya WAJIB IP MGMT yang SAMA (tidak bisa diedit),
            // dua device beda dengan IP identik di jaringan yang sama itu
            // konflik ARP nyata, terlepas CARP dipakai atau tidak. Fix:
            // MGMT IP sekarang BOLEH diubah - tapi tetap warn (bukan hard
            // block) karena risiko lockout tetap nyata kalau salah ketik,
            // pola sama persis dengan warning ARP-conflict/custom-rule di
            // bawah - admin modern (target pengguna produk ini) dianggap
            // mampu membuat keputusan sendiri, bukan dilarang total.
            if is_mgmt && !confirm {
                return Ok(serde_json::json!({
                    "warning": true,
                    "message": format!("Changing the MGMT IP carries a real lockout risk if the new IP is wrong or unreachable from where you're connecting - MGMT is the interface used to manage this gateway itself. Make sure you can reach '{ip}' before confirming. Resend with confirm:true to proceed."),
                    "affected_rules": [],
                }));
            }

            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let is_lan1 = lan1_if.as_deref() == Some(interface.as_str());
            let is_opt = opt_ifaces.contains(&interface);
            if !is_lan1 && !is_opt && !is_mgmt {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not a valid MGMT/LAN1/OPT for subnet changes"),
                ));
            }

            // Validasi collision - kumpulkan SEMUA subnet zona lain yang
            // sedang aktif sekarang. MGMT diambil LIVE (bukan hardcode
            // "10.252.252.0/24" lagi seperti sebelumnya) karena sekarang
            // bisa diubah - dan dikecualikan dari daftar "zona lain" kalau
            // MGMT sendiri yang sedang diedit (tidak masuk akal
            // membandingkan subnet baru MGMT dengan subnet LAMA MGMT
            // sendiri sebagai "konflik").
            let mut other_subnets: Vec<String> = Vec::new();
            if !is_mgmt {
                if let Some(m) = &mgmt_if {
                    if let Some(cidr) = get_interface_cidr(m) {
                        other_subnets.push(cidr);
                    }
                }
            }
            if let Some(w) = &wan1_if {
                if let Some(cidr) = get_interface_cidr(w) {
                    other_subnets.push(cidr);
                }
            }
            if !is_lan1 {
                if let Some(l) = &lan1_if {
                    if let Some(cidr) = get_interface_cidr(l) {
                        other_subnets.push(cidr);
                    }
                }
            }
            for opt in &opt_ifaces {
                if opt != &interface {
                    if let Some(cidr) = get_interface_cidr(opt) {
                        other_subnets.push(cidr);
                    }
                }
            }
            for existing in &other_subnets {
                if cidr_overlaps(&new_cidr, existing) {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        format!("Subnet '{new_cidr}' conflicts with another zone already using '{existing}'"),
                    ));
                }
            }

            // Validasi #3: IP host yang PERSIS SAMA dengan zona lain -
            // dicek TERPISAH dari overlap subnet di atas, karena dua
            // subnet BISA saja tidak overlap (prefix beda) tapi tetap
            // punya IP host yang persis sama (kasus jarang tapi mungkin).
            for existing in &other_subnets {
                if let Some((existing_ip, _)) = existing.split_once('/') {
                    if existing_ip == ip {
                        return Err((
                            "INVALID_PARAMS".to_string(),
                            format!("IP '{ip}' is already assigned to another zone on this gateway ({existing})"),
                        ));
                    }
                }
            }

            // Validasi #4: ARP live-probe - deteksi kalau IP ini SEDANG
            // dipakai perangkat LAIN di jaringan (bukan interface
            // gateway kita sendiri) - mekanisme sama seperti yang
            // FortiGate pakai sebelum assign IP statis (Gratuitous ARP
            // probe), dikonfirmasi dari dokumentasi Fortinet resmi.
            // Tidak dijalankan kalau confirm=true sudah dikirim
            // (admin sudah tahu dan sengaja lanjut - pola sama seperti
            // warning custom-rule di bawah).
            if !confirm {
                if let Some(conflicting_mac) = detect_live_ip_conflict(&ip, &interface) {
                    return Ok(serde_json::json!({
                        "warning": true,
                        "message": format!("IP '{ip}' appears to already be in use by another device on the network (MAC {conflicting_mac} responded to an ARP probe) - assigning it here would likely cause a conflict. Resend with confirm:true to proceed anyway if you're certain this is safe.", ),
                        "affected_rules": [],
                    }));
                }
            }

            // Cek custom rule yang literal-reference subnet LAMA sebelum apply.
            let old_cidr = get_interface_cidr(&interface);
            if let Some(old) = &old_cidr {
                let affected = scan_rules_for_literal_subnet(old);
                if !affected.is_empty() && !confirm {
                    return Ok(serde_json::json!({
                        "warning": true,
                        "message": format!("{} custom rule(s) reference the old subnet literally ({}) - these rules will NOT be updated automatically. Resend with confirm:true to proceed anyway (you remain responsible for adjusting them manually).", affected.len(), old),
                        "affected_rules": affected,
                    }));
                }
            }

            // Apply live + persist untuk boot berikutnya.
            let ifconfig_value = format!("inet {new_cidr}");
            let sysrc_status = Command::new("sysrc").arg(format!("ifconfig_{interface}={ifconfig_value}")).status();
            if !matches!(sysrc_status, Ok(s) if s.success()) {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to 'sysrc' persist interface config".to_string()));
            }
            let live_status = Command::new("ifconfig").arg(&interface).arg("inet").arg(&new_cidr).status();
            if !matches!(live_status, Ok(s) if s.success()) {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to apply the new IP live via ifconfig".to_string()));
            }

            // RCA (ditemukan dari test user - port yang sengaja di-disable
            // muncul lagi UP di flags 'ifconfig' setelah subnet-nya
            // diganti): dikonfirmasi dari forum resmi FreeBSD, meng-
            // konfigurasi ulang IP address sebuah interface via ifconfig
            // SECARA IMPLISIT membawa interface itu kembali UP, TERLEPAS
            // dari status administratively-down sebelumnya - "unconfigured
            // interfaces are brought up by default" saat di-ifconfig ulang.
            // Fix: cek status tersimpan SETELAH apply IP baru, kalau
            // interface ini memang HARUS tetap disabled, paksa 'down' lagi
            // supaya status admin yang sudah di-set sebelumnya tidak
            // ketimpa diam-diam oleh efek samping ganti subnet.
            let port_status = load_port_status();
            if !*port_status.get(&interface).unwrap_or(&true) {
                let _ = Command::new("ifconfig").arg(&interface).arg("down").status();
            }

            if is_lan1 {
                update_pf_conf_macro("lan1_net", &new_cidr).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            }
            if is_mgmt {
                update_pf_conf_macro("mgmt_net", &new_cidr).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            }

            Ok(serde_json::json!({ "interface": interface, "subnet": new_cidr }))
        }
        // Fase B - toggle WAN1 antara DHCP dan Static. TERPISAH dari
        // set_subnet karena WAN1 punya konsep gateway/default-route yang
        // tidak relevan untuk LAN1/OPT, dan tidak ada macro 'wan1_net'
        // yang perlu di-update (WAN1 tidak dipakai sebagai referensi
        // isolasi zona manapun).
        "network.set_wan1_config" => {
            let mode = params.get("mode").and_then(|v| v.as_str()).unwrap_or("");
            let (_, wan1_if, _) = parse_pf_conf_zones();
            let Some(wan1_if) = wan1_if else {
                return Err(("INTERNAL_ERROR".to_string(), "WAN1 interface not detected in pf.conf".to_string()));
            };

            if mode == "dhcp" {
                let sysrc_status = Command::new("sysrc").arg(format!("ifconfig_{wan1_if}=DHCP")).status();
                if !matches!(sysrc_status, Ok(s) if s.success()) {
                    return Err(("INTERNAL_ERROR".to_string(), "Failed to 'sysrc' set WAN1 to DHCP".to_string()));
                }
                let _ = Command::new("service").arg("netif").arg("restart").arg(&wan1_if).status();
                let _ = Command::new("dhclient").arg(&wan1_if).status();

                let port_status = load_port_status();
                if !*port_status.get(&wan1_if).unwrap_or(&true) {
                    let _ = Command::new("ifconfig").arg(&wan1_if).arg("down").status();
                }

                Ok(serde_json::json!({ "interface": wan1_if, "mode": "dhcp" }))
            } else if mode == "static" {
                let ip = params.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let prefix = params.get("prefix").and_then(|v| v.as_u64()).unwrap_or(24) as u8;
                let gateway = params.get("gateway").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let confirm = params.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);

                if parse_ipv4(&ip).is_none() {
                    return Err(("INVALID_PARAMS".to_string(), format!("IP '{ip}' is not valid")));
                }
                if parse_ipv4(&gateway).is_none() {
                    return Err(("INVALID_PARAMS".to_string(), format!("Gateway '{gateway}' is not valid")));
                }
                let new_cidr = format!("{ip}/{prefix}");

                // Validasi #1 & #2 (sama seperti network.set_subnet -
                // satu standar konsisten di SEMUA interface, bukan cuma
                // LAN1/OPT).
                let ip_bytes = parse_ipv4(&ip).unwrap();
                if is_network_or_broadcast_address(ip_bytes, prefix) {
                    return Err(("INVALID_PARAMS".to_string(), format!("'{ip}' is the network or broadcast address of {new_cidr} - not a valid host IP")));
                }
                if is_reserved_ip(ip_bytes) {
                    return Err(("INVALID_PARAMS".to_string(), format!("'{ip}' is in a reserved/special IP range and cannot be assigned to an interface")));
                }

                // Validasi #3 - WAN1 SEBELUMNYA tidak pernah dicek sama
                // sekali terhadap collision zona internal (gap terpisah,
                // ikut ditutup sekalian karena bro minta konsisten di
                // semua interface) - cek IP host exact SAMA dengan
                // MGMT/LAN1/OPT mana pun.
                let (lan1_if, _, opt_ifaces) = parse_pf_conf_zones();
                let mut other_ips: Vec<String> = vec!["10.252.252.100".to_string()]; // MGMT selalu fixed
                if let Some(l) = &lan1_if {
                    if let Some(existing_ip) = get_interface_ip(l) {
                        other_ips.push(existing_ip);
                    }
                }
                for opt in &opt_ifaces {
                    if let Some(existing_ip) = get_interface_ip(opt) {
                        other_ips.push(existing_ip);
                    }
                }
                if other_ips.contains(&ip) {
                    return Err(("INVALID_PARAMS".to_string(), format!("IP '{ip}' is already assigned to another zone on this gateway")));
                }

                // Gateway WAJIB berada di dalam subnet yang sama dengan
                // IP static-nya sendiri - kalau tidak, default route
                // akan gagal total dan WAN1 kehilangan internet.
                if !cidr_overlaps(&format!("{gateway}/32"), &new_cidr) {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        format!("Gateway '{gateway}' is not within subnet '{new_cidr}' - the default route would fail"),
                    ));
                }

                // Validasi #4 - ARP live-probe (sama seperti
                // network.set_subnet), sebelum benar-benar apply.
                if !confirm {
                    if let Some(conflicting_mac) = detect_live_ip_conflict(&ip, &wan1_if) {
                        return Ok(serde_json::json!({
                            "warning": true,
                            "message": format!("IP '{ip}' appears to already be in use by another device on the network (MAC {conflicting_mac} responded to an ARP probe) - assigning it here would likely cause a conflict. Resend with confirm:true to proceed anyway if you're certain this is safe."),
                            "affected_rules": [],
                        }));
                    }
                }

                let sysrc_status = Command::new("sysrc").arg(format!("ifconfig_{wan1_if}=inet {new_cidr}")).status();
                if !matches!(sysrc_status, Ok(s) if s.success()) {
                    return Err(("INTERNAL_ERROR".to_string(), "Failed to 'sysrc' set WAN1 static IP".to_string()));
                }
                let _ = Command::new("sysrc").arg(format!("defaultrouter={gateway}")).status();
                let _ = Command::new("ifconfig").arg(&wan1_if).arg("inet").arg(&new_cidr).status();
                let _ = Command::new("route").arg("add").arg("default").arg(&gateway).status();

                // Fix konsisten sama dengan network.set_subnet - ganti IP
                // via ifconfig bisa implisit membawa interface kembali UP
                // walau sebelumnya administratively-down.
                let port_status = load_port_status();
                if !*port_status.get(&wan1_if).unwrap_or(&true) {
                    let _ = Command::new("ifconfig").arg(&wan1_if).arg("down").status();
                }

                Ok(serde_json::json!({ "interface": wan1_if, "mode": "static", "ip": ip, "gateway": gateway }))
            } else {
                Err(("INVALID_PARAMS".to_string(), "mode must be 'dhcp' or 'static'".to_string()))
            }
        }
        // Query read-only status pf + ruleset MENTAH (pola sama seperti
        // pfSense: tampilkan /tmp/rules.debug apa adanya, BUKAN editor
        // rule interaktif - itu scope terpisah untuk sesi mendatang).
        "firewall.status" => {
            let info_output = Command::new("pfctl").arg("-s").arg("info").output();
            let rules_output = Command::new("pfctl").arg("-s").arg("rules").output();

            let info_text = match &info_output {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => String::new(),
            };
            let rules_text = match &rules_output {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => String::new(),
            };
            let enabled = info_text.contains("Status: Enabled");

            Ok(serde_json::json!({
                "enabled": enabled,
                "info": info_text,
                "rules": rules_text,
            }))
        }
        // Query read-only info sistem dasar - hostname (via 'hostname'
        // command, sumber kebenaran paling live) dan timezone (baca
        // symlink /etc/localtime, konvensi standar FreeBSD/tzsetup:
        // /etc/localtime -> /usr/share/zoneinfo/<Region>/<City>).
        "apikey.create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            if name.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "API key name cannot be empty".to_string()));
            }
            let permission = params.get("permission").and_then(|v| v.as_str()).unwrap_or("read").to_string();
            if permission != "read" && permission != "full" {
                return Err(("INVALID_PARAMS".to_string(), "permission must be 'read' or 'full'".to_string()));
            }
            let trusted_ip = params.get("trusted_ip").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
            let token = generate_api_token().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            let key = ApiKey {
                id: format!("k{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                name,
                token_hash: hash_api_token(&token),
                permission,
                trusted_ip,
                created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                last_used_at: None,
            };
            let mut data = load_api_keys();
            data.keys.push(key.clone());
            save_api_keys(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            // token PLAINTEXT cuma pernah muncul DI SINI, sekali - tidak
            // pernah tersimpan, tidak pernah bisa diambil ulang lewat
            // action apa pun (pola sama dengan recovery codes 2FA dan
            // WireGuard peer private key).
            Ok(serde_json::json!({ "id": key.id, "name": key.name, "permission": key.permission, "token": token }))
        }
        "apikey.list" => {
            let keys: Vec<serde_json::Value> = load_api_keys()
                .keys
                .iter()
                .map(|k| serde_json::json!({ "id": k.id, "name": k.name, "permission": k.permission, "trusted_ip": k.trusted_ip, "created_at": k.created_at, "last_used_at": k.last_used_at }))
                .collect();
            Ok(serde_json::json!({ "keys": keys }))
        }
        "apikey.revoke" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut data = load_api_keys();
            let before = data.keys.len();
            data.keys.retain(|k| k.id != id);
            if data.keys.len() == before {
                return Err(("NOT_FOUND".to_string(), format!("API key id '{id}' not found")));
            }
            save_api_keys(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "revoked": id }))
        }
        "openvpn.get_config" => {
            let cfg = openvpn::load_config();
            let installed = std::path::Path::new(openvpn::OPENVPN_BIN).exists();
            Ok(serde_json::json!({
                "config": cfg,
                "installed": installed,
                "pki_actually_exists": openvpn::pki_actually_exists(),
                "ca_info": openvpn::ca_info(),
            }))
        }
        "openvpn.set_config" => {
            let mut cfg = openvpn::load_config();
            if let Some(v) = params.get("enabled").and_then(|v| v.as_bool()) {
                cfg.enabled = v;
            }
            if let Some(v) = params.get("remote_access_enabled").and_then(|v| v.as_bool()) {
                cfg.remote_access_enabled = v;
            }
            if let Some(v) = params.get("site_to_site_enabled").and_then(|v| v.as_bool()) {
                cfg.site_to_site_enabled = v;
            }
            if let Some(v) = params.get("protocol").and_then(|v| v.as_str()) {
                if v != "tcp" && v != "udp" {
                    return Err(("INVALID_PARAMS".to_string(), "protocol must be 'tcp' or 'udp'".to_string()));
                }
                cfg.protocol = v.to_string();
            }
            if let Some(v) = params.get("port").and_then(|v| v.as_u64()) {
                let requested_port = v as u16;
                // RCA nyata (bukan hipotetis - bro langsung mengalami ini):
                // admin set OpenVPN ke TCP/443 (persis saran kita sendiri
                // untuk tembus firewall ketat) - TAPI port itu SUDAH
                // dipakai lighttpd untuk Web UI HTTPS. OpenVPN start
                // duluan, "menyita" port itu, lighttpd gagal bind sama
                // sekali - Web UI mati total sampai OpenVPN dimatikan
                // manual. Validasi di sini MENOLAK port yang sudah
                // dipakai layanan kritis project ini sendiri, sebelum
                // sempat tersimpan sama sekali - bukan cuma peringatan
                // di UI yang bisa diabaikan.
                const RESERVED_PORTS: &[(u16, &str)] = &[
                    (80, "Web UI (HTTP)"),
                    (443, "Web UI (HTTPS)"),
                    (22, "SSH"),
                    (500, "IPsec IKE"),
                    (4500, "IPsec NAT-T"),
                ];
                if let Some((_, used_by)) = RESERVED_PORTS.iter().find(|(p, _)| *p == requested_port) {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        format!(
                            "Port {requested_port} is already used by {used_by} on this gateway - OpenVPN cannot also bind to it. \
                             For TCP mode specifically (firewall traversal), port 943 is a common alternative that still avoids \
                             looking like a random high port, without colliding with the Web UI."
                        ),
                    ));
                }
                let wg_cfg = load_wg_config();
                if wg_cfg.enabled && requested_port == wg_cfg.listen_port {
                    return Err(("INVALID_PARAMS".to_string(), format!("Port {requested_port} is already used by WireGuard on this gateway.")));
                }
                cfg.port = requested_port;
            }
            if let Some(v) = params.get("remote_access_subnet").and_then(|v| v.as_str()) {
                cfg.remote_access_subnet = v.to_string();
            }
            if let Some(v) = params.get("radius_auth_enabled").and_then(|v| v.as_bool()) {
                cfg.radius_auth_enabled = v;
            }
            openvpn::save_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            if cfg.enabled {
                openvpn::apply_openvpn_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            } else {
                let _ = Command::new("/usr/sbin/service").args(["openvpn", "stop"]).status();
            }
            Ok(serde_json::json!({ "config": cfg }))
        }
        "openvpn.init_pki" => {
            openvpn::init_pki().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "initialized": true }))
        }
        "openvpn.reset_pki" => {
            openvpn::reset_pki().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "reset": true }))
        }
        "openvpn.client_list" => {
            Ok(serde_json::json!({ "clients": openvpn::load_state().clients }))
        }
        "openvpn.client_create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !openvpn::pki_actually_exists() {
                return Err(("INVALID_PARAMS".to_string(), "Initialize PKI first before creating clients.".to_string()));
            }
            let client = openvpn::create_client(&name).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "client": client }))
        }
        "openvpn.client_set_active" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let active = params.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
            openvpn::set_client_active(&id, active).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            // Reload supaya OpenVPN baca ulang isi client-config-dir -
            // sama seperti CRL, perubahan file CCD di disk TIDAK
            // otomatis berlaku untuk sesi yang sudah lama jalan (kalau
            // client itu SEDANG connect saat di-deactivate, mereka
            // baru benar-benar tertolak di percobaan reconnect
            // berikutnya, bukan langsung terputus - itu peran tombol
            // Disconnect terpisah).
            if openvpn::load_config().enabled {
                let _ = openvpn::apply_openvpn_conf();
            }
            Ok(serde_json::json!({ "id": id, "active": active }))
        }
        "openvpn.client_disconnect" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let common_name = format!("client-{name}");
            let response = openvpn::disconnect_client(&common_name).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "response": response }))
        }
        "openvpn.client_revoke" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            openvpn::revoke_client(&id).map_err(|e| ("NOT_FOUND".to_string(), e))?;
            // KRITIS - CRL baru di disk TIDAK OTOMATIS berlaku untuk
            // proses OpenVPN yang sudah lama jalan (RCA nyata: tanpa
            // baris ini, client yang di-revoke tetap bisa connect
            // sampai server di-restart oleh sebab lain). Restart di
            // sini, bukan cuma regenerasi CRL saja.
            if openvpn::load_config().enabled {
                let _ = openvpn::apply_openvpn_conf();
            }
            Ok(serde_json::json!({ "revoked": id }))
        }
        "openvpn.client_download_config" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let server_host = params.get("server_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if server_host.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "server_host is required (public IP/hostname clients will connect to).".to_string()));
            }
            let cfg = openvpn::load_config();
            let ovpn = openvpn::build_client_ovpn(&name, &cfg, &server_host).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "ovpn": ovpn, "filename": format!("{name}.ovpn") }))
        }
        "openvpn.site_list" => {
            Ok(serde_json::json!({ "sites": openvpn::load_state().sites }))
        }
        "openvpn.site_create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let remote_subnet = params.get("remote_subnet").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !openvpn::pki_actually_exists() {
                return Err(("INVALID_PARAMS".to_string(), "Initialize PKI first before creating sites.".to_string()));
            }
            let site = openvpn::create_site(&name, &remote_subnet).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "site": site }))
        }
        "openvpn.site_revoke" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            openvpn::revoke_site(&id).map_err(|e| ("NOT_FOUND".to_string(), e))?;
            if openvpn::load_config().enabled {
                let _ = openvpn::apply_openvpn_conf();
            }
            Ok(serde_json::json!({ "revoked": id }))
        }
        "openvpn.site_download_config" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let server_host = params.get("server_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if server_host.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "server_host is required.".to_string()));
            }
            let cfg = openvpn::load_config();
            // Reuse build_client_ovpn() - mekanisme bundling PEM SAMA
            // persis untuk site-to-site, cuma common_name-nya beda
            // prefix ('site-' bukan 'client-') - lihat implementasinya.
            let common_name_helper = format!("site-{name}");
            let ca_crt = fs::read_to_string(format!("{}/ca.crt", openvpn::OPENVPN_PKI_DIR)).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("failed to read ca.crt: {e}")))?;
            let site_crt = fs::read_to_string(format!("{}/issued/{common_name_helper}.crt", openvpn::OPENVPN_PKI_DIR)).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("failed to read site cert: {e}")))?;
            let site_key = fs::read_to_string(format!("{}/private/{common_name_helper}.key", openvpn::OPENVPN_PKI_DIR)).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("failed to read site key: {e}")))?;
            let ta_key = fs::read_to_string(format!("{}/ta.key", openvpn::OPENVPN_PKI_DIR)).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("failed to read ta.key: {e}")))?;
            let strip = |raw: &str| -> String {
                let start = raw.find("-----BEGIN").unwrap_or(0);
                raw[start..].to_string()
            };
            let ovpn = format!(
                "client\ndev tun\nproto {proto}\nremote {host} {port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3\n\n<ca>\n{ca}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n<tls-crypt>\n{ta}</tls-crypt>\n",
                proto = cfg.protocol, host = server_host, port = cfg.port,
                ca = strip(&ca_crt), cert = strip(&site_crt), key = site_key, ta = ta_key,
            );
            Ok(serde_json::json!({ "ovpn": ovpn, "filename": format!("{name}.ovpn") }))
        }
        "openvpn.status" => {
            let installed = std::path::Path::new(openvpn::OPENVPN_BIN).exists();
            if !installed {
                return Ok(serde_json::json!({ "installed": false, "running": false }));
            }
            let running = Command::new("pgrep").args(["-q", "-f", openvpn::OPENVPN_BIN]).status().map(|s| s.success()).unwrap_or(false);
            let (connected_clients, live) = match openvpn::get_connected_clients_live() {
                Ok(list) => (list, true),
                Err(_) => (openvpn::get_connected_clients(), false),
            };
            let connected_count = connected_clients.len();
            Ok(serde_json::json!({
                "installed": true,
                "running": running,
                "connected_clients": connected_clients,
                "connected_count": connected_count,
                "live": live,
            }))
        }
        // Endpoint TUNGGAL REST API - satu-satunya action yang PHP
        // api.php benar-benar panggil. Verifikasi token + cek izin
        // (Read-only vs Full) TERJADI DI SINI, satu tempat, sebelum
        // memanggil ULANG handle_action() secara rekursif untuk action
        // sesungguhnya yang diminta klien eksternal - bukan dua
        // round-trip socket terpisah (verifikasi lalu eksekusi), supaya
        // tidak ada celah antara "token valid" dan "action dijalankan".
        "api.dispatch" => {
            let token = params.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let client_ip = params.get("client_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if token.is_empty() {
                return Err(("UNAUTHORIZED".to_string(), "Missing API token".to_string()));
            }
            let key = verify_api_token(&token, &client_ip).map_err(|e| ("UNAUTHORIZED".to_string(), e))?;
            let inner_action = params.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if inner_action.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Missing 'action'".to_string()));
            }
            // apikey.* sendiri TIDAK BOLEH dipanggil lewat API eksternal
            // - manajemen API key itu sendiri cuma lewat Web UI (session
            // admin biasa), mencegah satu key yang bocor dipakai untuk
            // membuat key BARU tanpa batas (privilege escalation).
            if inner_action.starts_with("apikey.") {
                return Err(("FORBIDDEN".to_string(), "API key management is not available via the API itself".to_string()));
            }
            if key.permission == "read" && action_requires_write(&inner_action) {
                return Err(("FORBIDDEN".to_string(), format!("API key '{}' is read-only; '{inner_action}' requires full access", key.name)));
            }
            let inner_params = params.get("params").cloned().unwrap_or(serde_json::json!({}));
            handle_action(&inner_action, &inner_params)
        }
        "system.info" => {
            let hostname = Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();

            let timezone = fs::read_link("/etc/localtime")
                .ok()
                .and_then(|p| {
                    let s = p.to_string_lossy().to_string();
                    s.split("zoneinfo/").nth(1).map(|s| s.to_string())
                })
                .unwrap_or_else(|| "UTC".to_string());

            let freebsd_version = Command::new("freebsd-version")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();

            let ntp_servers: Vec<String> = fs::read_to_string("/etc/ntp.conf")
                .map(|content| {
                    content
                        .lines()
                        .filter_map(|line| {
                            let line = line.trim();
                            line.strip_prefix("server ").map(|rest| {
                                rest.split_whitespace().next().unwrap_or("").to_string()
                            })
                        })
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            Ok(serde_json::json!({
                "hostname": hostname,
                "timezone": timezone,
                "freebsd_version": freebsd_version,
                "ntp_servers": ntp_servers,
                "configd_version": VERSION,
            }))
        }
        // Update hostname dan/atau timezone - keduanya WAJIB persisten
        // (sysrc/symlink) DAN live-apply (pola sama seperti MGMT/WAN1
        // di install-gateway-v2.sh), supaya berlaku tanpa perlu reboot.
        // Validasi input SEDERHANA di sisi Rust (bukan cuma percaya PHP
        // Lapis 1) - konsisten prinsip validasi dua-lapis proyek ini.
        "system.update" => {
            let mut applied = Vec::new();

            if let Some(hostname) = params.get("hostname").and_then(|v| v.as_str()) {
                let hostname = hostname.trim();
                let valid = !hostname.is_empty()
                    && hostname.len() <= 63
                    && hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
                if !valid {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        "Invalid hostname - only letters, digits, hyphens, and dots are allowed, max 63 characters".to_string(),
                    ));
                }
                let _ = Command::new("sysrc").arg(format!("hostname={hostname}")).output();
                let _ = Command::new("hostname").arg(hostname).output();
                applied.push("hostname");
            }

            if let Some(timezone) = params.get("timezone").and_then(|v| v.as_str()) {
                let timezone = timezone.trim();
                let zoneinfo_path = format!("/usr/share/zoneinfo/{timezone}");
                if !std::path::Path::new(&zoneinfo_path).is_file() {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        format!("Timezone '{timezone}' not found at {zoneinfo_path}"),
                    ));
                }
                let _ = fs::remove_file("/etc/localtime");
                if std::os::unix::fs::symlink(&zoneinfo_path, "/etc/localtime").is_err() {
                    return Err(("INTERNAL_ERROR".to_string(), "Failed to update /etc/localtime symlink".to_string()));
                }
                // adjkerntz -a WAJIB dipanggil setelah ganti symlink - tanpa
                // ini, kernel machdep.adjkerntz masih pakai zona lama sampai
                // reboot (dikonfirmasi dari dokumentasi FreeBSD/forum resmi).
                let _ = Command::new("adjkerntz").arg("-a").output();
                applied.push("timezone");
            }

            if let Some(servers) = params.get("ntp_servers").and_then(|v| v.as_array()) {
                let server_lines: Vec<String> = servers
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                // Tulis ulang /etc/ntp.conf - baris 'server ' lama DIHAPUS
                // SEMUA, baris lain (driftfile, restrict, dst) DIPERTAHANKAN
                // apa adanya. Tulis via file sementara + rename (atomik),
                // BUKAN overwrite langsung - konsisten prinsip proyek
                // "jangan pernah tulis config setengah jadi".
                let existing = fs::read_to_string("/etc/ntp.conf").unwrap_or_default();
                let mut new_lines: Vec<String> = existing
                    .lines()
                    .filter(|line| !line.trim().starts_with("server "))
                    .map(|s| s.to_string())
                    .collect();
                for s in &server_lines {
                    new_lines.push(format!("server {s} iburst"));
                }
                let new_content = new_lines.join("\n") + "\n";

                let tmp_path = "/etc/ntp.conf.new";
                if fs::write(tmp_path, &new_content).is_err()
                    || fs::rename(tmp_path, "/etc/ntp.conf").is_err()
                {
                    return Err(("INTERNAL_ERROR".to_string(), "Failed to write /etc/ntp.conf".to_string()));
                }
                let _ = Command::new("service").arg("ntpd").arg("restart").output();
                applied.push("ntp_servers");
            }

            Ok(serde_json::json!({ "applied": applied }))
        }
        // --- TLS Certificate Management (Web UI HTTPS) - sebelumnya
        // cert self-signed HANYA di-generate SEKALI oleh install-gateway-
        // v2.sh (CN=ntpsense-gateway, RSA 2048, 3650 hari) TANPA cara
        // apa pun untuk admin melihat status expiry-nya, regenerate
        // (mis. setelah IP MGMT berubah), atau upload cert asli sendiri
        // (internal CA/purchased) dari Web UI - satu-satunya jalan
        // sebelumnya adalah console/SSH manual. Tiga action baru di sini
        // menutup gap itu.
        "system.alerts_summary" => {
            // Dipanggil di HEADER, jadi di SETIAP halaman - sengaja dibuat
            // seringan mungkin (tail terbatas, tanpa parsing tanggal
            // presisi) daripada akurat sampai ke detik, supaya tidak
            // membebani setiap page load. Tiga sumber digabung jadi satu
            // badge lonceng: Suricata (severity tinggi/sedang),
            // Certificate (expired/mendekati expired), Watchdog (service
            // yang pernah mati dan direstart otomatis). Masing-masing
            // difilter terhadap AlertsAckState - RCA nyata dari bro:
            // versi awal selalu menghitung ULANG kondisi live tanpa
            // konsep "sudah dibaca", jadi badge tidak pernah hilang
            // meski admin sudah membuka halaman tujuannya.
            let ack = load_alerts_ack();
            let mut alerts: Vec<serde_json::Value> = Vec::new();

            // 1. Suricata - severity 1 (high) atau 2 (medium) dari tail
            // terbaru, HANYA yang timestamp-nya lebih baru dari
            // security_ack_ts (string comparison, format ISO8601 eve.json
            // sudah terbukti sortable sebagai string - lihat komentar
            // AlertsAckState). 'low'/None diabaikan supaya lonceng tidak
            // penuh noise untuk hal yang tidak genting.
            if std::path::Path::new(security::EVE_JSON_LOG).is_file() {
                let output = Command::new("tail").arg("-n").arg("500").arg(security::EVE_JSON_LOG).output();
                let raw = output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                let lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
                let recent_alerts = security::parse_eve_alerts(&lines, 500);
                let new_high_medium_count = recent_alerts
                    .iter()
                    .filter(|a| matches!(a.severity, Some(1) | Some(2)) && a.timestamp > ack.security_ack_ts)
                    .count();
                if new_high_medium_count > 0 {
                    alerts.push(serde_json::json!({
                        "source": "security",
                        "severity": "warning",
                        "message": format!("{new_high_medium_count} new high/medium Suricata alert(s)"),
                        "link": "/security.php?tab=alerts",
                    }));
                }
            }

            // 2. Certificate - kondisinya kontinu (bukan diskrit seperti
            // event log), jadi "sudah dibaca" dilacak via kunci gabungan
            // (not_after + severity) - alert re-trigger otomatis kalau
            // cert diganti/diperbarui ATAU severity memburuk (mis. dari
            // "expiring_soon" jadi "expired") meski sudah pernah di-ack
            // sebelumnya, karena kunci gabungannya jadi beda.
            if std::path::Path::new(SSL_CERT_PATH).is_file() {
                let checkend = |seconds: &str| -> bool {
                    Command::new("openssl")
                        .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-checkend", seconds])
                        .status()
                        .map(|s| !s.success())
                        .unwrap_or(true)
                };
                let not_after = Command::new("openssl")
                    .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-enddate"])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                let (severity, message) = if checkend("0") {
                    ("critical", "Web UI TLS certificate has EXPIRED")
                } else if checkend("2592000") {
                    ("warning", "Web UI TLS certificate expires within 30 days")
                } else {
                    ("", "")
                };
                if !severity.is_empty() {
                    let current_key = format!("{not_after}:{severity}");
                    if current_key != ack.certificate_ack_key {
                        alerts.push(serde_json::json!({
                            "source": "certificate",
                            "severity": severity,
                            "message": message,
                            "link": "/system.php?tab=certificates",
                        }));
                    }
                }
            }

            // 3. Watchdog - hitung baris WARNING di file log SAAT INI
            // (bukan file .1 hasil rotasi) yang timestamp-nya lebih baru
            // dari watchdog_ack_ts - format "YYYY-MM-DD HH:MM:SS ..." di
            // 19 karakter pertama, juga sortable sebagai string.
            if let Ok(content) = fs::read_to_string(WATCHDOG_LOG) {
                let new_warning_count = content
                    .lines()
                    .filter(|l| l.contains("WARNING:") && is_watchdog_timestamp_line(l) && l.get(0..19).unwrap_or("") > ack.watchdog_ack_ts.as_str())
                    .count();
                if new_warning_count > 0 {
                    alerts.push(serde_json::json!({
                        "source": "watchdog",
                        "severity": "warning",
                        "message": format!("{new_warning_count} new service restart event(s) logged by the watchdog"),
                        "link": "/system-logs.php?tab=watchdog",
                    }));
                }
            }

            // 4. Multi-WAN - gateway yang sedang down. Dilacak via kunci
            // "himpunan nama gateway yang sedang down" (sorted, di-join)
            // - sama filosofinya dengan certificate: re-alert otomatis
            // kalau himpunan itu BERUBAH (ada gateway tambahan down),
            // bukan cuma dihitung ulang setiap saat.
            let multiwan_status = multiwan::get_status_summary();
            let mut down_names: Vec<String> = multiwan_status["gateways"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter(|g| !g["up"].as_bool().unwrap_or(true))
                .filter_map(|g| g["name"].as_str().map(|s| s.to_string()))
                .collect();
            down_names.sort();
            if !down_names.is_empty() {
                let current_key = down_names.join(",");
                if current_key != ack.multiwan_ack_key {
                    alerts.push(serde_json::json!({
                        "source": "multiwan",
                        "severity": "critical",
                        "message": format!("Gateway(s) down: {}", down_names.join(", ")),
                        "link": "/multiwan.php?tab=status",
                    }));
                }
            }

            // 5. Resource (disk + swap) - reuse check_resource_alert(),
            // fungsi bersama juga dipakai alerts_list dan
            // alerts_acknowledge (satu sumber kebenaran).
            if let Some((severity, message, key)) = check_resource_alert() {
                if key != ack.resource_ack_key {
                    alerts.push(serde_json::json!({
                        "source": "resource",
                        "severity": severity,
                        "message": message,
                        "link": "/system.php?tab=maintenance",
                    }));
                }
            }


            // 7. VPN - tunnel IPsec/WireGuard yang dikonfigurasi tapi mati.
            if let Some((severity, message, key)) = check_vpn_alert() {
                if key != ack.vpn_ack_key {
                    alerts.push(serde_json::json!({
                        "source": "vpn",
                        "severity": severity,
                        "message": message,
                        "link": "/vpn.php?tab=peers",
                    }));
                }
            }

            Ok(serde_json::json!({ "count": alerts.len(), "alerts": alerts }))
        }
        "system.alerts_acknowledge" => {
            // Dipanggil PHP saat admin membuka halaman tujuan sebuah
            // alert (Watchdog log, Security Alerts, Certificates) - live
            // state SAAT INI (bukan snapshot lama) yang direkam sebagai
            // "sudah dibaca", supaya event yang genuinely baru SETELAH
            // titik ini tetap ke-detect di kunjungan berikutnya.
            let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("");
            // Atribusi (halaman Alerts penuh) - siapa yang meng-ack.
            // Opsional secara sengaja (default "system") - jalur lama
            // (bell dropdown, dipanggil dari alerts-ack.php) SEKARANG
            // sudah diperbarui untuk selalu mengirim username asli,
            // tapi tetap fail-safe kalau suatu saat dipanggil tanpa itu.
            let acknowledged_by = params.get("acknowledged_by").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("system").to_string();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let mut ack = load_alerts_ack();
            match source {
                "watchdog" => {
                    if let Ok(content) = fs::read_to_string(WATCHDOG_LOG) {
                        if let Some(last) = content.lines().filter(|l| l.contains("WARNING:") && is_watchdog_timestamp_line(l)).last() {
                            ack.watchdog_ack_ts = last.get(0..19).unwrap_or("").to_string();
                        }
                    }
                    ack.watchdog_ack_by = Some(acknowledged_by);
                    ack.watchdog_ack_at = Some(now);
                }
                "security" => {
                    if std::path::Path::new(security::EVE_JSON_LOG).is_file() {
                        let output = Command::new("tail").arg("-n").arg("500").arg(security::EVE_JSON_LOG).output();
                        let raw = output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                        let lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
                        let recent_alerts = security::parse_eve_alerts(&lines, 500);
                        if let Some(latest) = recent_alerts.iter().map(|a| a.timestamp.clone()).max() {
                            ack.security_ack_ts = latest;
                        }
                    }
                    ack.security_ack_by = Some(acknowledged_by);
                    ack.security_ack_at = Some(now);
                }
                "certificate" => {
                    if std::path::Path::new(SSL_CERT_PATH).is_file() {
                        let checkend = |seconds: &str| -> bool {
                            Command::new("openssl")
                                .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-checkend", seconds])
                                .status()
                                .map(|s| !s.success())
                                .unwrap_or(true)
                        };
                        let not_after = Command::new("openssl")
                            .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-enddate"])
                            .output()
                            .ok()
                            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                            .unwrap_or_default();
                        let severity = if checkend("0") { "critical" } else if checkend("2592000") { "warning" } else { "none" };
                        ack.certificate_ack_key = format!("{not_after}:{severity}");
                    }
                    ack.certificate_ack_by = Some(acknowledged_by);
                    ack.certificate_ack_at = Some(now);
                }
                "multiwan" => {
                    let status = multiwan::get_status_summary();
                    let mut down_names: Vec<String> = status["gateways"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .filter(|g| !g["up"].as_bool().unwrap_or(true))
                        .filter_map(|g| g["name"].as_str().map(|s| s.to_string()))
                        .collect();
                    down_names.sort();
                    ack.multiwan_ack_key = down_names.join(",");
                    ack.multiwan_ack_by = Some(acknowledged_by);
                    ack.multiwan_ack_at = Some(now);
                }
                "resource" => {
                    ack.resource_ack_key = check_resource_alert().map(|(_, _, key)| key).unwrap_or_default();
                    ack.resource_ack_by = Some(acknowledged_by);
                    ack.resource_ack_at = Some(now);
                }
                "ha" => {
                    return Err(("INVALID_PARAMS".to_string(), "High Availability is a Pro feature".to_string()));
                }
                "vpn" => {
                    ack.vpn_ack_key = check_vpn_alert().map(|(_, _, key)| key).unwrap_or_default();
                    ack.vpn_ack_by = Some(acknowledged_by);
                    ack.vpn_ack_at = Some(now);
                }
                other => {
                    return Err(("INVALID_PARAMS".to_string(), format!("Unknown alert source '{other}'")));
                }
            }
            save_alerts_ack(&ack).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "acknowledged": source }))
        }
        "system.alerts_list" => {
            // Halaman Alerts penuh (roadmap - riset Palo Alto/FortiGate/
            // pfSense: kolom Timestamp/Severity/Source/Message/Suggested
            // Action/Status). Beda dari alerts_summary (yang cuma
            // menghitung per-sumber untuk lonceng) - di sini watchdog dan
            // security DIPECAH jadi baris individual (masing-masing
            // event log/alert Suricata), sementara certificate dan
            // multiwan tetap satu baris "kondisi saat ini" (bukan daftar
            // event diskrit - lihat komentar arsitektur di
            // alerts_summary). "acknowledged" per baris dihitung dari
            // watermark ack SUMBER-nya (bukan ID per-baris terpisah) -
            // pendekatan pragmatis yang disepakati: kategori dianggap
            // "dibersihkan oleh X pada waktu Y", bukan status per-baris
            // individual dengan ID unik masing-masing.
            let ack = load_alerts_ack();
            let mut rows: Vec<serde_json::Value> = Vec::new();

            // Helper - ID stabil dari hash sederhana (source+timestamp+
            // message) supaya konsisten dipanggil ulang, tanpa perlu
            // menyimpan tabel ID terpisah di manapun.
            fn stable_id(parts: &[&str]) -> String {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                for p in parts {
                    p.hash(&mut hasher);
                }
                format!("a{:x}", hasher.finish())
            }

            // 1. Watchdog - satu baris per event restart (limit 30
            // terbaru, cukup untuk halaman tanpa membebani setiap load).
            if let Ok(content) = fs::read_to_string(WATCHDOG_LOG) {
                let mut warning_lines: Vec<&str> = content.lines().filter(|l| l.contains("WARNING:") && is_watchdog_timestamp_line(l)).collect();
                warning_lines.reverse(); // terbaru dulu
                for line in warning_lines.into_iter().take(30) {
                    let ts = line.get(0..19).unwrap_or("").to_string();
                    let acknowledged = ts.as_str() <= ack.watchdog_ack_ts.as_str();
                    rows.push(serde_json::json!({
                        "id": stable_id(&["watchdog", &ts, line]),
                        "timestamp": ts,
                        "severity": "warning",
                        "source": "watchdog",
                        "message": line.get(20..).unwrap_or(line).trim(),
                        "suggested_action": "Check why the service keeps restarting - review System Logs > OS Boot / GUI Service for surrounding context.",
                        "link": "/system-logs.php?tab=watchdog",
                        "acknowledged": acknowledged,
                        "acknowledged_by": if acknowledged { ack.watchdog_ack_by.clone() } else { None },
                        "acknowledged_at": if acknowledged { ack.watchdog_ack_at } else { None },
                    }));
                }
            }

            // 2. Security (Suricata) - satu baris per alert severity
            // tinggi/sedang (limit 30 terbaru, dari tail 500 baris eve.json
            // yang sama dipakai alerts_summary - konsisten satu sumber).
            if std::path::Path::new(security::EVE_JSON_LOG).is_file() {
                let output = Command::new("tail").arg("-n").arg("500").arg(security::EVE_JSON_LOG).output();
                let raw = output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                let lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
                let recent_alerts = security::parse_eve_alerts(&lines, 500);
                for a in recent_alerts.iter().filter(|a| matches!(a.severity, Some(1) | Some(2))).take(30) {
                    let acknowledged = a.timestamp.as_str() <= ack.security_ack_ts.as_str();
                    let sev_label = if a.severity == Some(1) { "critical" } else { "warning" };
                    rows.push(serde_json::json!({
                        "id": stable_id(&["security", &a.timestamp, &a.signature.clone().unwrap_or_default()]),
                        "timestamp": a.timestamp,
                        "severity": sev_label,
                        "source": "security",
                        "message": a.signature.clone().unwrap_or_else(|| "Suricata alert".to_string()),
                        "suggested_action": "Review the full signature, source/destination IP, and category on Security > Alerts.",
                        "link": "/security.php?tab=alerts",
                        "acknowledged": acknowledged,
                        "acknowledged_by": if acknowledged { ack.security_ack_by.clone() } else { None },
                        "acknowledged_at": if acknowledged { ack.security_ack_at } else { None },
                    }));
                }
            }

            // 3. Certificate - satu baris KONDISI (bukan daftar event) -
            // cuma muncul kalau memang sedang warning/critical saat ini.
            if std::path::Path::new(SSL_CERT_PATH).is_file() {
                let checkend = |seconds: &str| -> bool {
                    Command::new("openssl")
                        .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-checkend", seconds])
                        .status()
                        .map(|s| !s.success())
                        .unwrap_or(true)
                };
                let not_after = Command::new("openssl")
                    .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-enddate"])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                let (severity, message) = if checkend("0") {
                    ("critical", "Web UI TLS certificate has EXPIRED")
                } else if checkend("2592000") {
                    ("warning", "Web UI TLS certificate expires within 30 days")
                } else {
                    ("", "")
                };
                if !severity.is_empty() {
                    let current_key = format!("{not_after}:{severity}");
                    let acknowledged = current_key == ack.certificate_ack_key;
                    rows.push(serde_json::json!({
                        "id": stable_id(&["certificate", &current_key]),
                        "timestamp": "",
                        "severity": severity,
                        "source": "certificate",
                        "message": message,
                        "suggested_action": "Renew or replace the certificate under System > Certificates.",
                        "link": "/system.php?tab=certificates",
                        "acknowledged": acknowledged,
                        "acknowledged_by": if acknowledged { ack.certificate_ack_by.clone() } else { None },
                        "acknowledged_at": if acknowledged { ack.certificate_ack_at } else { None },
                    }));
                }
            }

            // 4. Multi-WAN - satu baris KONDISI juga (himpunan gateway down saat ini).
            let multiwan_status = multiwan::get_status_summary();
            let mut down_names: Vec<String> = multiwan_status["gateways"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter(|g| !g["up"].as_bool().unwrap_or(true))
                .filter_map(|g| g["name"].as_str().map(|s| s.to_string()))
                .collect();
            down_names.sort();
            if !down_names.is_empty() {
                let current_key = down_names.join(",");
                let acknowledged = current_key == ack.multiwan_ack_key;
                rows.push(serde_json::json!({
                    "id": stable_id(&["multiwan", &current_key]),
                    "timestamp": "",
                    "severity": "critical",
                    "source": "multiwan",
                    "message": format!("Gateway(s) down: {}", down_names.join(", ")),
                    "suggested_action": "Check the WAN's physical link and ISP status on Multi-WAN > Status.",
                    "link": "/multiwan.php?tab=status",
                    "acknowledged": acknowledged,
                    "acknowledged_by": if acknowledged { ack.multiwan_ack_by.clone() } else { None },
                    "acknowledged_at": if acknowledged { ack.multiwan_ack_at } else { None },
                }));
            }

            // 5. Resource (disk + swap) - kondisi, reuse check_resource_alert().
            if let Some((severity, message, key)) = check_resource_alert() {
                let acknowledged = key == ack.resource_ack_key;
                rows.push(serde_json::json!({
                    "id": stable_id(&["resource", &key]),
                    "timestamp": "",
                    "severity": severity,
                    "source": "resource",
                    "message": message,
                    "suggested_action": "Free up disk space or increase VM RAM/swap under System > Maintenance - this project has a documented real OOM-kill incident from this exact precondition.",
                    "link": "/system.php?tab=maintenance",
                    "acknowledged": acknowledged,
                    "acknowledged_by": if acknowledged { ack.resource_ack_by.clone() } else { None },
                    "acknowledged_at": if acknowledged { ack.resource_ack_at } else { None },
                }));
            }


            // 7. VPN - kondisi, reuse check_vpn_alert().
            if let Some((severity, message, key)) = check_vpn_alert() {
                let acknowledged = key == ack.vpn_ack_key;
                rows.push(serde_json::json!({
                    "id": stable_id(&["vpn", &key]),
                    "timestamp": "",
                    "severity": severity,
                    "source": "vpn",
                    "message": message,
                    "suggested_action": "Check tunnel configuration and remote peer reachability on VPN > Peers or IPsec VPN.",
                    "link": "/vpn.php?tab=peers",
                    "acknowledged": acknowledged,
                    "acknowledged_by": if acknowledged { ack.vpn_ack_by.clone() } else { None },
                    "acknowledged_at": if acknowledged { ack.vpn_ack_at } else { None },
                }));
            }

            // Urut terbaru dulu - baris tanpa timestamp (certificate/
            // multiwan, kondisi kontinu bukan event bertitik waktu)
            // ditaruh PALING ATAS (string kosong "" < timestamp apa pun
            // secara alfabetis salah arah untuk 'descending', jadi
            // dibalik eksplisit di closure sort di bawah).
            rows.sort_by(|a, b| {
                let ta = a["timestamp"].as_str().unwrap_or("");
                let tb = b["timestamp"].as_str().unwrap_or("");
                if ta.is_empty() && tb.is_empty() {
                    std::cmp::Ordering::Equal
                } else if ta.is_empty() {
                    std::cmp::Ordering::Less
                } else if tb.is_empty() {
                    std::cmp::Ordering::Greater
                } else {
                    tb.cmp(ta)
                }
            });

            Ok(serde_json::json!({ "alerts": rows }))
        }
        "system.cert_get_status" => {
            if !std::path::Path::new(SSL_CERT_PATH).is_file() {
                return Err(("NOT_FOUND".to_string(), format!("No certificate found at {SSL_CERT_PATH}")));
            }
            let field = |flag: &str| -> Option<String> {
                let output = Command::new("openssl").args(["x509", "-in", SSL_CERT_PATH, "-noout", flag]).output().ok()?;
                if !output.status.success() {
                    return None;
                }
                String::from_utf8_lossy(&output.stdout).trim().split_once('=').map(|(_, v)| v.trim().to_string())
            };
            // openssl x509 -checkend <detik> - exit code 0 kalau MASIH
            // valid setelah <detik> dari sekarang, exit code 1 kalau
            // sudah/akan expired dalam rentang itu. Dipakai APA ADANYA
            // (boolean dari exit code), TANPA parsing tanggal manual -
            // menghindari kebutuhan crate date/time tambahan (filosofi
            // dependensi minimal daemon ini) sekaligus menghindari bug
            // parsing timezone/format tanggal OpenSSL yang berbeda-beda.
            let checkend = |seconds: &str| -> bool {
                Command::new("openssl")
                    .args(["x509", "-in", SSL_CERT_PATH, "-noout", "-checkend", seconds])
                    .status()
                    .map(|s| !s.success())
                    .unwrap_or(true)
            };
            let subject = field("-subject").unwrap_or_else(|| "unknown".to_string());
            let issuer = field("-issuer").unwrap_or_else(|| "unknown".to_string());
            Ok(serde_json::json!({
                "subject": subject,
                "issuer": issuer,
                "not_before": field("-startdate"),
                "not_after": field("-enddate"),
                "is_self_signed": subject == issuer,
                "expired": checkend("0"),
                "expiring_soon": checkend("2592000"),
            }))
        }
        "system.cert_regenerate" => {
            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let (lan1_if, _wan1_if, _opt_ifaces) = parse_pf_conf_zones();
            // SAN (Subject Alternative Name) diisi dengan IP live MGMT +
            // LAN1 kalau ada - browser modern (Chrome 58+) MENGABAIKAN
            // Common Name sama sekali untuk validasi hostname, HANYA
            // membaca SAN. Cert lama dari installer (CN saja, tanpa SAN)
            // akan selalu gagal validasi hostname di browser modern
            // meskipun trusted - perbaikan nyata, bukan kosmetik.
            let mut san_entries: Vec<String> = Vec::new();
            if let Some(m) = &mgmt_if {
                if let Some(ip) = get_interface_ip(m) {
                    san_entries.push(format!("IP:{ip}"));
                }
            }
            if let Some(l) = &lan1_if {
                if let Some(ip) = get_interface_ip(l) {
                    if !san_entries.iter().any(|s| s == &format!("IP:{ip}")) {
                        san_entries.push(format!("IP:{ip}"));
                    }
                }
            }
            san_entries.push("DNS:ntpsense-gateway".to_string());
            let san_string = san_entries.join(",");

            let _ = fs::create_dir_all(SSL_DIR);
            let _ = fs::create_dir_all(SSL_BACKUP_DIR);

            // Backup cert LAMA dulu (kalau ada) sebelum ditimpa - pola
            // sama dengan setiap config-mutating action lain di daemon
            // ini (rollback tetap mungkin lewat console/SSH kalau perlu).
            if std::path::Path::new(SSL_PEM_PATH).is_file() {
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                let _ = fs::copy(SSL_CERT_PATH, format!("{SSL_BACKUP_DIR}/webui-{ts}.crt"));
                let _ = fs::copy(SSL_KEY_PATH, format!("{SSL_BACKUP_DIR}/webui-{ts}.key"));
            }

            let tmp_key = "/tmp/ntpsense-cert-regen.key";
            let tmp_crt = "/tmp/ntpsense-cert-regen.crt";
            let gen_status = Command::new("openssl")
                .args([
                    "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:2048",
                    "-keyout", tmp_key, "-out", tmp_crt,
                    "-subj", "/CN=ntpsense-gateway",
                    "-addext", &format!("subjectAltName={san_string}"),
                ])
                .status();
            if gen_status.map(|s| !s.success()).unwrap_or(true) {
                return Err(("CERT_REGENERATE_FAILED".to_string(), "openssl req failed to generate the new certificate".to_string()));
            }
            // Validasi cert baru bisa di-parse SEBELUM menimpa file
            // production - sama disiplinnya dengan pfctl -nf/squid -k
            // parse di setiap action lain.
            let verify = Command::new("openssl").args(["x509", "-in", tmp_crt, "-noout", "-subject"]).status();
            if verify.map(|s| !s.success()).unwrap_or(true) {
                return Err(("CERT_REGENERATE_FAILED".to_string(), "Newly generated certificate failed validation - old certificate left untouched".to_string()));
            }

            if fs::copy(tmp_key, SSL_KEY_PATH).is_err() || fs::copy(tmp_crt, SSL_CERT_PATH).is_err() {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to install newly generated certificate files".to_string()));
            }
            let key_content = fs::read_to_string(SSL_KEY_PATH).unwrap_or_default();
            let crt_content = fs::read_to_string(SSL_CERT_PATH).unwrap_or_default();
            if fs::write(SSL_PEM_PATH, format!("{key_content}{crt_content}")).is_err() {
                return Err(("INTERNAL_ERROR".to_string(), format!("Failed to write combined {SSL_PEM_PATH}")));
            }
            let _ = Command::new("chmod").args(["600", SSL_KEY_PATH, SSL_PEM_PATH]).status();
            let _ = Command::new("chmod").args(["644", SSL_CERT_PATH]).status();
            let _ = fs::remove_file(tmp_key);
            let _ = fs::remove_file(tmp_crt);

            let restart_status = Command::new("service").arg("lighttpd").arg("restart").status();
            if restart_status.map(|s| !s.success()).unwrap_or(true) {
                let _ = Command::new("service").arg("lighttpd").arg("start").status();
            }
            let lighttpd_running = wait_for_lighttpd_running();

            Ok(serde_json::json!({
                "regenerated": true,
                "san": san_entries,
                "lighttpd_running": lighttpd_running,
            }))
        }
        "system.cert_upload" => {
            let cert_pem = params.get("cert_pem").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let key_pem = params.get("key_pem").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Both certificate and private key PEM content are required".to_string()));
            }

            let tmp_crt = "/tmp/ntpsense-cert-upload.crt";
            let tmp_key = "/tmp/ntpsense-cert-upload.key";
            if fs::write(tmp_crt, &cert_pem).is_err() || fs::write(tmp_key, &key_pem).is_err() {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to write uploaded certificate to a temp file".to_string()));
            }

            let verify_cert = Command::new("openssl").args(["x509", "-in", tmp_crt, "-noout", "-subject"]).status();
            if verify_cert.map(|s| !s.success()).unwrap_or(true) {
                let _ = fs::remove_file(tmp_crt);
                let _ = fs::remove_file(tmp_key);
                return Err(("INVALID_PARAMS".to_string(), "The uploaded certificate is not valid PEM/X.509 (openssl x509 -in ... failed to parse it)".to_string()));
            }
            let verify_key = Command::new("openssl").args(["pkey", "-in", tmp_key, "-noout"]).status();
            if verify_key.map(|s| !s.success()).unwrap_or(true) {
                let _ = fs::remove_file(tmp_crt);
                let _ = fs::remove_file(tmp_key);
                return Err(("INVALID_PARAMS".to_string(), "The uploaded private key is not valid PEM (openssl pkey -in ... failed to parse it)".to_string()));
            }

            // Cocokkan cert dan private key dengan BANDINGKAN public key
            // turunan masing-masing (bukan modulus RSA saja) - teknik ini
            // bekerja seragam untuk RSA, EC, maupun Ed25519, tidak
            // seperti '-noout -modulus' yang HANYA berlaku untuk RSA.
            let cert_pubkey = Command::new("openssl").args(["x509", "-in", tmp_crt, "-noout", "-pubkey"]).output();
            let key_pubkey = Command::new("openssl").args(["pkey", "-in", tmp_key, "-pubout"]).output();
            let matches = match (cert_pubkey, key_pubkey) {
                (Ok(a), Ok(b)) => a.status.success() && b.status.success() && a.stdout == b.stdout,
                _ => false,
            };
            if !matches {
                let _ = fs::remove_file(tmp_crt);
                let _ = fs::remove_file(tmp_key);
                return Err(("INVALID_PARAMS".to_string(), "The certificate and private key do not match (their public keys are different)".to_string()));
            }
            let already_expired = Command::new("openssl")
                .args(["x509", "-in", tmp_crt, "-noout", "-checkend", "0"])
                .status()
                .map(|s| !s.success())
                .unwrap_or(true);
            if already_expired {
                let _ = fs::remove_file(tmp_crt);
                let _ = fs::remove_file(tmp_key);
                return Err(("INVALID_PARAMS".to_string(), "The uploaded certificate has already expired - upload a currently-valid certificate".to_string()));
            }

            let _ = fs::create_dir_all(SSL_DIR);
            let _ = fs::create_dir_all(SSL_BACKUP_DIR);
            if std::path::Path::new(SSL_PEM_PATH).is_file() {
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                let _ = fs::copy(SSL_CERT_PATH, format!("{SSL_BACKUP_DIR}/webui-{ts}.crt"));
                let _ = fs::copy(SSL_KEY_PATH, format!("{SSL_BACKUP_DIR}/webui-{ts}.key"));
            }

            if fs::copy(tmp_crt, SSL_CERT_PATH).is_err() || fs::copy(tmp_key, SSL_KEY_PATH).is_err() {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to install the uploaded certificate files".to_string()));
            }
            if fs::write(SSL_PEM_PATH, format!("{key_pem}{cert_pem}")).is_err() {
                return Err(("INTERNAL_ERROR".to_string(), format!("Failed to write combined {SSL_PEM_PATH}")));
            }
            let _ = Command::new("chmod").args(["600", SSL_KEY_PATH, SSL_PEM_PATH]).status();
            let _ = Command::new("chmod").args(["644", SSL_CERT_PATH]).status();
            let _ = fs::remove_file(tmp_crt);
            let _ = fs::remove_file(tmp_key);

            let restart_status = Command::new("service").arg("lighttpd").arg("restart").status();
            if restart_status.map(|s| !s.success()).unwrap_or(true) {
                let _ = Command::new("service").arg("lighttpd").arg("start").status();
            }
            let lighttpd_running = wait_for_lighttpd_running();

            Ok(serde_json::json!({
                "uploaded": true,
                "lighttpd_running": lighttpd_running,
            }))
        }
        // --- Backup & Restore - arsitektur ditiru dari Tier 1 (Doc 6 Bab
        // 13, sudah teruji): HMAC-SHA256 ditempel di nama file (bukan
        // file terpisah) untuk membuktikan KEASLIAN SUMBER (bukan cuma
        // deteksi korupsi seperti checksum biasa), plus pertahanan Tar
        // Slip (list dulu via 'tar -tzf' SEBELUM ekstraksi sungguhan,
        // tolak entri path traversal/absolut atau nama asing di luar
        // daftar yang dikenal). Penyesuaian KHUSUS Tier 2 (multi-zone,
        // beda dari Tier 1 yang single-zone): validasi interface yang
        // disebut di backup terhadap interface yang BENAR-BENAR
        // terdeteksi sekarang - kalau restore ke hardware/VM berbeda
        // dengan urutan NIC berbeda, admin diberi PERINGATAN dulu (pola
        // sama dengan warning subnet-conflict Fase B), bukan diam-diam
        // salah-terap.
        "system.backup_create" => {
            let _ = fs::create_dir_all(BACKUP_DIR);
            let staging_dir = "/tmp/ntpsense-backup-staging";
            let _ = fs::remove_dir_all(staging_dir);
            fs::create_dir_all(staging_dir).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to create staging dir: {e}")))?;

            let mut included: Vec<&str> = Vec::new();
            for (src, archive_name) in backup_file_list() {
                if let Ok(data) = fs::read(src) {
                    let dest = format!("{staging_dir}/{archive_name}");
                    if fs::write(&dest, data).is_ok() {
                        included.push(archive_name);
                    }
                }
            }

            if included.is_empty() {
                let _ = fs::remove_dir_all(staging_dir);
                return Err(("INTERNAL_ERROR".to_string(), "No configuration files were found to back up".to_string()));
            }

            let tmp_archive = "/tmp/ntpsense-backup-unsigned.tar.gz";
            let mut tar_args = vec!["-czf".to_string(), tmp_archive.to_string(), "-C".to_string(), staging_dir.to_string()];
            tar_args.extend(included.iter().map(|s| s.to_string()));
            let tar_status = Command::new("tar").args(&tar_args).status();
            let _ = fs::remove_dir_all(staging_dir);
            if !matches!(tar_status, Ok(s) if s.success()) {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to create the backup archive".to_string()));
            }

            let hmac = compute_file_hmac(tmp_archive).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let final_name = format!("ntpsense-backup-{timestamp}-{hmac}.tar.gz");
            let final_path = format!("{BACKUP_DIR}/{final_name}");

            fs::copy(tmp_archive, &final_path).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to save backup: {e}")))?;
            let _ = fs::remove_file(tmp_archive);
            let _ = fs::set_permissions(&final_path, fs::Permissions::from_mode(0o640));
            let _ = Command::new("chown").arg(format!("root:{ALLOWED_GROUP}")).arg(&final_path).status();

            Ok(serde_json::json!({ "filename": final_name, "included": included }))
        }
        "system.backup_list" => {
            let mut backups: Vec<serde_json::Value> = Vec::new();
            if let Ok(entries) = fs::read_dir(BACKUP_DIR) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("gz") {
                        continue;
                    }
                    let filename = entry.file_name().to_string_lossy().to_string();
                    let metadata = entry.metadata().ok();
                    let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                    let modified = metadata
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    backups.push(serde_json::json!({ "filename": filename, "size": size, "modified": modified }));
                }
            }
            backups.sort_by(|a, b| b["modified"].as_u64().unwrap_or(0).cmp(&a["modified"].as_u64().unwrap_or(0)));
            Ok(serde_json::json!({ "backups": backups }))
        }
        "system.backup_delete" => {
            let filename = params.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if filename.contains('/') || filename.contains("..") {
                return Err(("INVALID_PARAMS".to_string(), "Invalid filename".to_string()));
            }
            let path = format!("{BACKUP_DIR}/{filename}");
            fs::remove_file(&path).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to delete backup: {e}")))?;
            Ok(serde_json::json!({ "deleted": filename }))
        }
        "system.reboot" => {
            log_maintenance_event("Reboot requested via Web UI");
            // Ditunda 2 detik lewat thread terpisah - supaya response
            // sukses sempat terkirim ke Web UI dulu sebelum koneksi
            // benar-benar terputus oleh reboot itu sendiri.
            thread::spawn(|| {
                thread::sleep(std::time::Duration::from_secs(2));
                let _ = Command::new("shutdown").args(["-r", "now"]).status();
            });
            Ok(serde_json::json!({ "rebooting": true }))
        }
        "system.restart_services" => {
            restart_all_services();
            Ok(serde_json::json!({ "restarted": true }))
        }
        "system.factory_reset" => {
            let confirm_text = params.get("confirm_text").and_then(|v| v.as_str()).unwrap_or("");
            if confirm_text != "RESET" {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    "Confirmation text must be exactly 'RESET' (case-sensitive) to proceed - this is a deliberately strict check for a destructive, hard-to-reverse action.".to_string(),
                ));
            }
            match perform_factory_reset() {
                Ok(()) => Ok(serde_json::json!({ "reset": true, "rebooting_in_seconds": 3 })),
                Err(e) => Err(("INTERNAL_ERROR".to_string(), e)),
            }
        }
        // Pindahkan file backup yang diunggah admin (PHP sudah menulisnya
        // ke lokasi sementara yang bisa ditulis www, mis. /tmp/ - PHP
        // TIDAK PERNAH menulis langsung ke BACKUP_DIR yang dimiliki root)
        // ke lokasi final. Validasi KEASLIAN sesungguhnya (HMAC + Tar
        // Slip) TETAP dilakukan nanti saat system.backup_restore
        // dipanggil - action ini SENGAJA ringan, cuma pemindahan file +
        // sanity check nama, bukan tempat verifikasi keamanan utama.
        // Whitelist paket yang boleh di-install/uninstall dari sini -
        // HARUS SINKRON dengan daftar di lib/PackageCatalog.php (PHP).
        // Install langsung dari repo RESMI FreeBSD (disepakati dengan
        // user) - repo custom ntpsense.conf TETAP disimpan untuk masa
        // depan (plugin yang BUKAN paket FreeBSD standar), TIDAK
        // dipakai di sini.
        // ASYNC (bukan lagi synchronous menunggu 'pkg install' selesai) -
        // RCA nyata (ditemukan dari test user): paket dengan dependency
        // resolution + download > 15 detik bikin PHP timeout duluan
        // padahal instalasi sebenarnya tetap berjalan normal di
        // background - model IPC daemon ini ONE-SHOT per request
        // (lihat komentar arsitektur di puncak file), jadi action yang
        // lambat TIDAK BOLEH menahan balasan. Fix: spawn 'pkg install'
        // di thread terpisah, balas SEGERA begitu thread dimulai
        // (bukan menunggu 'pkg' selesai) - progress+hasil akhir ditulis
        // ke PACKAGE_INSTALL_LOG, dipoll terpisah lewat
        // package.install_status (lihat action itu tepat di bawah ini) -
        // ini juga SEKALIGUS jadi basis untuk web console live progress
        // yang diminta user di Package Manager (Install button -> popup
        // yang nge-poll status ini, bukan menunggu request tunggal).
        "package.install" => {
            const ALLOWED_PACKAGES: [&str; 7] = ["squid", "suricata", "wireguard-tools", "openvpn", "freeradius3", "strongswan", "openldap26-client"];
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !ALLOWED_PACKAGES.contains(&name.as_str()) {
                return Err(("INVALID_PARAMS".to_string(), format!("Package '{name}' is not in the allowed catalog")));
            }
            let header = format!("=== Installing '{name}' - started {} ===\n", format_unix_timestamp(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)));
            let _ = fs::write(PACKAGE_INSTALL_LOG, &header);
            let name_for_thread = name.clone();
            // RCA (ditemukan dari test user - popup console tampil KOSONG
            // lalu tiba-tiba meledak SEMUA output sekaligus di akhir, BUKAN
            // baris-per-baris real-time seperti pfSense/apt/dnf): versi
            // sebelumnya pakai Command::output() yang MENUNGGU seluruh
            // proses 'pkg install' selesai baru capture stdout/stderr
            // sekaligus - poll PHP di tengah proses selalu baca log yang
            // masih kosong. Fix: spawn dengan stdout/stderr di-piped, baca
            // BARIS PER BARIS saat itu juga, APPEND ke log file setiap
            // baris muncul - poll berikutnya langsung lihat progress
            // genuinely bertambah.
            thread::spawn(move || {
                let child = Command::new("pkg")
                    .arg("install")
                    .arg("-y")
                    .arg(&name_for_thread)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn();
                let mut child = match child {
                    Ok(c) => c,
                    Err(e) => {
                        let mut log_content = fs::read_to_string(PACKAGE_INSTALL_LOG).unwrap_or_default();
                        log_content.push_str(&format!("\nFailed to run 'pkg install': {e}\n===NTPSENSE_INSTALL_DONE_FAIL===\n"));
                        let _ = fs::write(PACKAGE_INSTALL_LOG, &log_content);
                        return;
                    }
                };
                // stdout DAN stderr dibaca di thread TERPISAH masing-masing
                // (bukan bergantian) - kalau cuma baca satu stream sementara
                // stream lain penuh menunggu dibaca, proses child BISA
                // DEADLOCK (buffer pipe OS terbatas). Keduanya append ke
                // file log yang SAMA - urutan antar stdout/stderr tidak
                // dijamin persis sama seperti terminal asli, tapi cukup
                // memadai untuk tujuan "lihat progress live".
                let stdout_handle = child.stdout.take().map(|s| {
                    thread::spawn(move || {
                        let reader = BufReader::new(s);
                        for line in reader.lines().flatten() {
                            if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_INSTALL_LOG) {
                                let _ = writeln!(f, "{line}");
                            }
                        }
                    })
                });
                let stderr_handle = child.stderr.take().map(|s| {
                    thread::spawn(move || {
                        let reader = BufReader::new(s);
                        for line in reader.lines().flatten() {
                            if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_INSTALL_LOG) {
                                let _ = writeln!(f, "{line}");
                            }
                        }
                    })
                });
                let status = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }
                let done_line = match status {
                    Ok(s) if s.success() => "\n===NTPSENSE_INSTALL_DONE_OK===\n".to_string(),
                    Ok(s) => format!("\n===NTPSENSE_INSTALL_DONE_FAIL=== (exit: {s})\n"),
                    Err(e) => format!("\nFailed to wait for 'pkg install': {e}\n===NTPSENSE_INSTALL_DONE_FAIL===\n"),
                };
                if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_INSTALL_LOG) {
                    let _ = f.write_all(done_line.as_bytes());
                }
            });
            Ok(serde_json::json!({ "started": true, "name": name }))
        }
        // Dipoll PHP/JS berkala (mis. tiap 1 detik) selama popup console
        // Install terbuka - baca APA ADANYA isi log SAAT INI, deteksi
        // selesai/gagal dari sentinel marker yang ditulis thread di atas
        // begitu 'pkg install' benar-benar tuntas.
        "package.install_status" => {
            let content = fs::read_to_string(PACKAGE_INSTALL_LOG).unwrap_or_default();
            let finished = content.contains("===NTPSENSE_INSTALL_DONE_OK===") || content.contains("===NTPSENSE_INSTALL_DONE_FAIL===");
            let success = if content.contains("===NTPSENSE_INSTALL_DONE_OK===") {
                Some(true)
            } else if content.contains("===NTPSENSE_INSTALL_DONE_FAIL===") {
                Some(false)
            } else {
                None
            };
            Ok(serde_json::json!({ "log": content, "finished": finished, "success": success }))
        }
        // ASYNC + STREAMING - pola SAMA PERSIS dengan package.install
        // (lihat komentar lengkap di sana) - konsistensi UX: Uninstall
        // juga dapat popup console live progress, bukan cuma Install.
        "package.uninstall" => {
            const ALLOWED_PACKAGES: [&str; 7] = ["squid", "suricata", "wireguard-tools", "openvpn", "freeradius3", "strongswan", "openldap26-client"];
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !ALLOWED_PACKAGES.contains(&name.as_str()) {
                return Err(("INVALID_PARAMS".to_string(), format!("Package '{name}' is not in the allowed catalog")));
            }
            let header = format!("=== Uninstalling '{name}' - started {} ===\n", format_unix_timestamp(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)));
            let _ = fs::write(PACKAGE_UNINSTALL_LOG, &header);
            let name_for_thread = name.clone();
            thread::spawn(move || {
                // Hentikan service terkait dulu SEBELUM uninstall - biar
                // tidak ada proses zombie yang masih pegang binary/config
                // yang baru saja dihapus. Dipindah KE DALAM thread (bukan
                // synchronous sebelum spawn) supaya ikut tercatat di log
                // live yang sama, konsisten dengan filosofi "semua langkah
                // kelihatan di console", bukan langkah tersembunyi.
                if name_for_thread == "squid" {
                    if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_UNINSTALL_LOG) {
                        let _ = writeln!(f, "Stopping squid service first...");
                    }
                    let _ = Command::new("service").arg("squid").arg("stop").status();
                }
                let child = Command::new("pkg")
                    .arg("delete")
                    .arg("-y")
                    .arg(&name_for_thread)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn();
                let mut child = match child {
                    Ok(c) => c,
                    Err(e) => {
                        let mut log_content = fs::read_to_string(PACKAGE_UNINSTALL_LOG).unwrap_or_default();
                        log_content.push_str(&format!("\nFailed to run 'pkg delete': {e}\n===NTPSENSE_UNINSTALL_DONE_FAIL===\n"));
                        let _ = fs::write(PACKAGE_UNINSTALL_LOG, &log_content);
                        return;
                    }
                };
                let stdout_handle = child.stdout.take().map(|s| {
                    thread::spawn(move || {
                        let reader = BufReader::new(s);
                        for line in reader.lines().flatten() {
                            if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_UNINSTALL_LOG) {
                                let _ = writeln!(f, "{line}");
                            }
                        }
                    })
                });
                let stderr_handle = child.stderr.take().map(|s| {
                    thread::spawn(move || {
                        let reader = BufReader::new(s);
                        for line in reader.lines().flatten() {
                            if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_UNINSTALL_LOG) {
                                let _ = writeln!(f, "{line}");
                            }
                        }
                    })
                });
                let status = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }
                let done_line = match status {
                    Ok(s) if s.success() => "\n===NTPSENSE_UNINSTALL_DONE_OK===\n".to_string(),
                    Ok(s) => format!("\n===NTPSENSE_UNINSTALL_DONE_FAIL=== (exit: {s})\n"),
                    Err(e) => format!("\nFailed to wait for 'pkg delete': {e}\n===NTPSENSE_UNINSTALL_DONE_FAIL===\n"),
                };
                if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PACKAGE_UNINSTALL_LOG) {
                    let _ = f.write_all(done_line.as_bytes());
                }
            });
            Ok(serde_json::json!({ "started": true, "name": name }))
        }
        "package.uninstall_status" => {
            let content = fs::read_to_string(PACKAGE_UNINSTALL_LOG).unwrap_or_default();
            let finished = content.contains("===NTPSENSE_UNINSTALL_DONE_OK===") || content.contains("===NTPSENSE_UNINSTALL_DONE_FAIL===");
            let success = if content.contains("===NTPSENSE_UNINSTALL_DONE_OK===") {
                Some(true)
            } else if content.contains("===NTPSENSE_UNINSTALL_DONE_FAIL===") {
                Some(false)
            } else {
                None
            };
            Ok(serde_json::json!({ "log": content, "finished": finished, "success": success }))
        }
        // Query status install untuk SELURUH katalog - SENGAJA dijalankan
        // di sini (daemon privileged, root), BUKAN via exec() langsung
        // dari PHP-FPM (www, tidak privileged) seperti versi awal -
        // ditemukan dari bug nyata: PHP-FPM jalankan 'pkg info'/'pkg
        // query' sendiri dan HASILNYA SELALU KOSONG walau paket
        // sungguhan terinstall (kemungkinan besar exec() dibatasi atau
        // akses pkg database ditolak untuk user non-root) - konsisten
        // dengan prinsip arsitektur proyek ini sejak awal: SEMUA operasi
        // privileged (termasuk sekadar QUERY status pkg) lewat daemon
        // Rust, PHP TIDAK PERNAH eksekusi command sistem langsung.
        "package.list_installed" => {
            const ALLOWED_PACKAGES: [&str; 7] = ["squid", "suricata", "wireguard-tools", "openvpn", "freeradius3", "strongswan", "openldap26-client"];
            let mut installed = serde_json::Map::new();
            for name in ALLOWED_PACKAGES {
                let exists = Command::new("pkg").arg("info").arg("-e").arg(name).status();
                if !matches!(exists, Ok(s) if s.success()) {
                    continue;
                }
                let version_output = Command::new("pkg").arg("query").arg("%v").arg(name).output();
                if let Ok(o) = version_output {
                    let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if !version.is_empty() {
                        installed.insert(name.to_string(), serde_json::Value::String(version));
                    }
                }
            }
            Ok(serde_json::Value::Object(installed))
        }
        "proxy.get_config" => {
            let installed = std::path::Path::new("/usr/local/sbin/squid").exists();
            let cfg = proxy::load_proxy_config();
            // Status LIVE proses (bukan cuma "installed" atau config
            // 'enabled' tersimpan) - cek teks output 'service squid
            // status' (pola sama seperti verifikasi Kea sebelumnya,
            // BUKAN cuma percaya exit code) untuk baris "squid is
            // running as pid" secara eksplisit.
            let running = if installed {
                Command::new("service")
                    .arg("squid")
                    .arg("status")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).contains("squid is running"))
                    .unwrap_or(false)
            } else {
                false
            };
            Ok(serde_json::json!({ "installed": installed, "running": running, "config": cfg }))
        }
        "proxy.set_config" => {
            if !std::path::Path::new("/usr/local/sbin/squid").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "Squid is not installed - install it first from Package Manager".to_string()));
            }
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let port = params.get("port").and_then(|v| v.as_u64()).unwrap_or(3128) as u16;
            let cache_size_mb = params.get("cache_size_mb").and_then(|v| v.as_u64()).unwrap_or(1000) as u32;

            // Load config EXISTING dulu, cuma timpa field General - Local
            // cache (cache_mem_mb/maximum_object_size_mb) disimpan lewat
            // action TERPISAH (proxy.set_local_cache), jangan sampai
            // ke-reset ke default tiap kali admin Save tab General.
            let mut cfg = proxy::load_proxy_config();
            cfg.enabled = enabled;
            cfg.port = port;
            cfg.cache_size_mb = cache_size_mb;
            let conf_text = proxy::generate_squid_conf(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let tmp_path = "/tmp/squid.conf.new";
            fs::write(tmp_path, &conf_text).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to write draft: {e}")))?;

            let parse_status = Command::new("/usr/local/sbin/squid").arg("-k").arg("parse").arg("-f").arg(tmp_path).output();
            match &parse_status {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let err_text = String::from_utf8_lossy(&o.stderr);
                    return Err(("INTERNAL_ERROR".to_string(), format!("squid.conf failed syntax validation ('squid -k parse'): {err_text}")));
                }
                Err(e) => return Err(("INTERNAL_ERROR".to_string(), format!("Failed to run 'squid -k parse': {e}"))),
            }

            if let Some(parent) = std::path::Path::new(proxy::SQUID_CONF).parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::copy(tmp_path, proxy::SQUID_CONF).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to copy to {}: {e}", proxy::SQUID_CONF)))?;

            proxy::save_proxy_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            if enabled {
                // Inisialisasi cache directory - AMAN dipanggil berulang
                // (squid -z idempotent, cuma bikin struktur direktori
                // cache kalau belum ada, tidak menghapus cache lama).
                let _ = fs::create_dir_all("/var/squid/cache");
                let _ = Command::new("/usr/local/sbin/squid").arg("-z").arg("-f").arg(proxy::SQUID_CONF).output();
                let _ = Command::new("sysrc").arg("squid_enable=YES").status();
                let restart_status = Command::new("service").arg("squid").arg("restart").status();
                if !matches!(restart_status, Ok(s) if s.success()) {
                    let _ = Command::new("service").arg("squid").arg("start").status();
                }
                let status_check = Command::new("service").arg("squid").arg("status").status();
                if !matches!(status_check, Ok(s) if s.success()) {
                    return Err(("INTERNAL_ERROR".to_string(), "Squid failed to start after applying the new configuration - check /var/log/squid/cache.log".to_string()));
                }
            } else {
                let _ = Command::new("sysrc").arg("squid_enable=NO").status();
                let _ = Command::new("service").arg("squid").arg("stop").status();
            }

            Ok(serde_json::json!({ "config": cfg }))
        }
        "proxy.get_blocklist_config" => {
            let cfg = proxy::load_blocklist_config();
            // Waktu update terakhir PER KATEGORI - diambil dari mtime
            // file di disk (bukan field tersimpan terpisah, supaya tidak
            // ada risiko dua sumber kebenaran yang bisa tidak sinkron -
            // file itu sendiri SUDAH otentik menunjukkan kapan terakhir
            // ditulis). Dicek untuk SEMUA kategori yang PERNAH punya
            // file (bukan cuma yang sedang enabled), supaya admin masih
            // bisa lihat riwayat kalau sempat men-disable lalu enable
            // ulang kategori yang sama nanti.
            let mut last_updated = serde_json::Map::new();
            for category in proxy::VALID_CATEGORIES {
                let path = format!("{}/{category}.txt", proxy::BLOCKLIST_DIR);
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                            last_updated.insert(category.to_string(), serde_json::Value::from(duration.as_secs()));
                        }
                    }
                }
            }
            Ok(serde_json::json!({ "config": cfg, "last_updated": last_updated }))
        }
        // Simpan pilihan kategori/whitelist/blacklist-manual, generate
        // ulang squid.conf (marker WHITELIST/BLOCKLIST-MANUAL/BLOCKLIST
        // di posisi yang sudah dijaga ketat di generate_squid_conf()),
        // lalu apply live - MENGIKUTI pola sama seperti proxy.set_config
        // (validasi syntax dulu, verifikasi status SUNGGUHAN setelah
        // restart, bukan cuma percaya exit code).
        "proxy.set_blocklist_config" => {
            if !std::path::Path::new("/usr/local/sbin/squid").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "Squid is not installed - install it first from Package Manager".to_string()));
            }

            let categories: Vec<String> = params
                .get("categories")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .filter(|c| proxy::VALID_CATEGORIES.contains(&c.as_str()))
                        .collect()
                })
                .unwrap_or_default();

            // Lapis 2 validasi domain (defense in depth) - baris tidak
            // valid DIBUANG SENYAP di sini (bukan tempat lapor error,
            // PHP di Lapis 1 sudah beri kesempatan admin memperbaiki).
            let whitelist: Vec<String> = params
                .get("whitelist")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).filter(|d| proxy::is_valid_domain(d)).collect())
                .unwrap_or_default();
            let blacklist_manual: Vec<String> = params
                .get("blacklist_manual")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).filter(|d| proxy::is_valid_domain(d)).collect())
                .unwrap_or_default();

            let blocklist_cfg = proxy::BlocklistConfig { categories, whitelist, blacklist_manual };
            proxy::save_blocklist_config(&blocklist_cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let proxy_cfg = proxy::load_proxy_config();
            let conf_text = proxy::generate_squid_conf(&proxy_cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            let tmp_path = "/tmp/squid.conf.new";
            fs::write(tmp_path, &conf_text).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to write draft: {e}")))?;

            let parse_status = Command::new("/usr/local/sbin/squid").arg("-k").arg("parse").arg("-f").arg(tmp_path).output();
            match &parse_status {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let err_text = String::from_utf8_lossy(&o.stderr);
                    return Err(("INTERNAL_ERROR".to_string(), format!("squid.conf failed syntax validation ('squid -k parse'): {err_text}")));
                }
                Err(e) => return Err(("INTERNAL_ERROR".to_string(), format!("Failed to run 'squid -k parse': {e}"))),
            }

            fs::copy(tmp_path, proxy::SQUID_CONF).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to copy to {}: {e}", proxy::SQUID_CONF)))?;

            if proxy_cfg.enabled {
                let restart_status = Command::new("service").arg("squid").arg("restart").status();
                if !matches!(restart_status, Ok(s) if s.success()) {
                    let _ = Command::new("service").arg("squid").arg("start").status();
                }
                let status_check = Command::new("service").arg("squid").arg("status").status();
                if !matches!(status_check, Ok(s) if s.success()) {
                    return Err(("INTERNAL_ERROR".to_string(), "Squid failed to start after applying the new blocklist configuration - check /var/log/squid/cache.log".to_string()));
                }
            }

            Ok(serde_json::json!({ "config": blocklist_cfg }))
        }
        // Download/update file kategori dari Block List Project - SUMBER
        // URL HARDCODED (bukan parameter, pola Tier 1) - tidak ada cara
        // meminta helper fetch dari domain lain. HANYA download kategori
        // yang SEDANG AKTIF (baca dari state file, bukan "semua 8
        // kategori" - Tier 1 punya RCA soal boros bandwidth kalau
        // download semua walau tidak pernah diaktifkan admin). Download-
        // ke-temp-dulu: file kategori lama TIDAK PERNAH ditimpa kalau
        // download/validasi gagal.
        "proxy.blocklist_update" => {
            let (updated, failed) = proxy::run_blocklist_update();
            if updated.is_empty() && failed.is_empty() {
                Ok(serde_json::json!({ "updated": [], "message": "No categories are currently enabled - nothing to update" }))
            } else {
                Ok(serde_json::json!({ "updated": updated, "failed": failed }))
            }
        }
        // Threat Intelligence (IP reputation blocklist, layer pf) -
        // pola PARALEL dengan proxy.get_blocklist_config/set_blocklist_
        // config/blocklist_update di atas, tapi beroperasi di pf table
        // (semua protokol, dua arah) bukan Squid ACL (HTTP saja).
        // Status ringkas Squid - Fase 1 (uptime, ukuran cache dipakai,
        // jumlah koneksi aktif) - SENGAJA tidak memakai 'squidclient
        // mgr:info' (butuh setup cachemgr_passwd tambahan, scope lebih
        // besar) - cukup gabungkan beberapa command sistem dasar yang
        // sudah reliable (service status untuk PID, ps untuk uptime
        // proses, du untuk disk cache, sockstat untuk koneksi aktif).
        "proxy.get_status" => {
            let installed = std::path::Path::new("/usr/local/sbin/squid").exists();
            if !installed {
                return Ok(serde_json::json!({ "installed": false, "running": false }));
            }

            let status_output = Command::new("service").arg("squid").arg("status").output();
            let status_text = status_output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            let running = status_text.contains("squid is running");

            // Ekstrak PID dari teks "squid is running as pid 1234."
            let pid: Option<String> = status_text
                .split_whitespace()
                .skip_while(|w| *w != "pid")
                .nth(1)
                .map(|s| s.trim_end_matches('.').to_string());

            let uptime = pid.as_ref().and_then(|p| {
                Command::new("ps")
                    .arg("-o")
                    .arg("etime=")
                    .arg("-p")
                    .arg(p)
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .filter(|s| !s.is_empty())
            });

            let cache_disk_usage = Command::new("du")
                .arg("-sh")
                .arg("/var/squid/cache")
                .output()
                .ok()
                .and_then(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().next().map(|s| s.to_string()));

            let proxy_cfg = proxy::load_proxy_config();
            let active_connections = Command::new("sockstat")
                .arg("-4")
                .output()
                .ok()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .filter(|l| l.contains(&format!(":{}", proxy_cfg.port)))
                        .count()
                })
                .unwrap_or(0);

            Ok(serde_json::json!({
                "installed": true,
                "running": running,
                "uptime": uptime,
                "cache_disk_usage": cache_disk_usage,
                "active_connections": active_connections,
            }))
        }
        // Log viewer Fase 1 - tail N baris terakhir access.log (BUKAN
        // baca seluruh file ke memori, bisa sangat besar) - read-only,
        // tidak ada filter/search di fase ini (ditunda kalau diperlukan).
        "proxy.get_log" => {
            let lines_arg = params.get("lines").and_then(|v| v.as_u64()).unwrap_or(200).min(1000);
            let log_path = "/var/log/squid/access.log";
            if !std::path::Path::new(log_path).is_file() {
                return Ok(serde_json::json!({ "log": "", "exists": false, "parsed": [] }));
            }
            let output = Command::new("tail").arg("-n").arg(lines_arg.to_string()).arg(log_path).output();
            let log_text = output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            // Timestamp kolom (permintaan bro langsung - Log Viewer
            // sebelumnya <pre> teks mentah, tidak ada kolom Timestamp
            // sama sekali) - reuse parser YANG SAMA dipakai
            // system.get_log untuk sumber 'proxy', satu sumber
            // kebenaran, bukan implementasi kedua yang bisa beda hasil.
            let parsed: Vec<proxy::SquidLogEntry> = log_text.lines().filter_map(proxy::parse_squid_access_line).collect();
            Ok(serde_json::json!({ "log": log_text, "exists": true, "parsed": parsed }))
        }
        // Bandwidth usage Fase 1 - parse access.log Squid, agregasi per
        // ZONA (LAN1/OPT1-n, cocokkan IP client ke subnet live via
        // cidr_overlaps yang sudah ada dan teruji dari Fase B) dan per
        // CLIENT IP (top 10 terbesar). Format baris native access.log
        // Squid (default, spasi-separated): <timestamp> <elapsed_ms>
        // <client_ip> <result>/<http_status> <bytes> <method> <url> ...
        // - kolom ke-5 (index 4) adalah ukuran byte response.
        "proxy.get_bandwidth_usage" => {
            let log_path = "/var/log/squid/access.log";
            if !std::path::Path::new(log_path).is_file() {
                return Ok(serde_json::json!({ "zones": [], "clients": [], "domains": [] }));
            }
            let content = fs::read_to_string(log_path).unwrap_or_default();
            let lines: Vec<&str> = content.lines().collect();
            let raw_agg = proxy::compute_bandwidth_aggregate(&lines);
            // Live view TETAP sort+truncate (top 10 client, top 20 domain) -
            // reuse fungsi gabungan yang sama dipakai get_bandwidth_range()
            // supaya urutan/batas top-N SELALU identik antara live dan
            // historis, bukan dua logic terpisah yang bisa diam-diam beda.
            let mut zone_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            let mut client_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            let mut domain_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            let mut domain_hits: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for z in raw_agg["zones"].as_array().cloned().unwrap_or_default() {
                if let (Some(l), Some(b)) = (z["label"].as_str(), z["bytes"].as_u64()) {
                    zone_bytes.insert(l.to_string(), b);
                }
            }
            for c in raw_agg["clients"].as_array().cloned().unwrap_or_default() {
                if let (Some(ip), Some(b)) = (c["ip"].as_str(), c["bytes"].as_u64()) {
                    client_bytes.insert(ip.to_string(), b);
                }
            }
            for d in raw_agg["domains"].as_array().cloned().unwrap_or_default() {
                if let (Some(domain), Some(b)) = (d["domain"].as_str(), d["bytes"].as_u64()) {
                    domain_bytes.insert(domain.to_string(), b);
                    domain_hits.insert(domain.to_string(), d["hits"].as_u64().unwrap_or(0));
                }
            }
            Ok(proxy::finalize_bandwidth_result(zone_bytes, client_bytes, domain_bytes, domain_hits))
        }
        "proxy.get_bandwidth_range" => {
            let from = params.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let to = params.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !proxy::is_valid_date_string(&from) || !proxy::is_valid_date_string(&to) {
                return Err(("INVALID_PARAMS".to_string(), "from/to must be dates in YYYY-MM-DD format".to_string()));
            }
            Ok(proxy::get_bandwidth_range(&from, &to))
        }
        "proxy.get_log_range" => {
            let from = params.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let to = params.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if !proxy::is_valid_date_string(&from) || !proxy::is_valid_date_string(&to) {
                return Err(("INVALID_PARAMS".to_string(), "from/to must be dates in YYYY-MM-DD format".to_string()));
            }
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(1000).min(10000) as usize;
            let (lines, truncated) = proxy::get_log_range(&from, &to, limit);
            let parsed: Vec<proxy::SquidLogEntry> = lines.iter().filter_map(|l| proxy::parse_squid_access_line(l)).collect();
            Ok(serde_json::json!({ "lines": lines, "truncated": truncated, "parsed": parsed }))
        }
        "proxy.get_archive_settings" => {
            Ok(serde_json::to_value(proxy::load_archive_settings()).unwrap_or(serde_json::Value::Null))
        }
        "proxy.set_archive_settings" => {
            let retention_days = params.get("retention_days").and_then(|v| v.as_u64()).unwrap_or(30) as u32;
            let cfg = proxy::save_archive_settings(retention_days).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::to_value(cfg).unwrap_or(serde_json::Value::Null))
        }
        // --- Local cache (Fase 2 Proxy) ---
        "proxy.set_local_cache" => {
            if !std::path::Path::new("/usr/local/sbin/squid").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "Squid is not installed - install it first from Package Manager".to_string()));
            }
            let cache_mem_mb = params.get("cache_mem_mb").and_then(|v| v.as_u64()).unwrap_or(256) as u32;
            let maximum_object_size_mb = params.get("maximum_object_size_mb").and_then(|v| v.as_u64()).unwrap_or(4) as u32;

            let mut cfg = proxy::load_proxy_config();
            cfg.cache_mem_mb = cache_mem_mb;
            cfg.maximum_object_size_mb = maximum_object_size_mb;
            proxy::save_proxy_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "config": cfg }))
        }
        // --- ACL custom (Fase 2 Proxy) - CRUD mirip pola CustomRule
        // Firewall (add/delete/reorder), TAPI level kontrol akses proxy
        // bukan level paket. ---
        "proxy.acl_list" => {
            Ok(serde_json::json!({ "rules": proxy::load_acl_rules().rules }))
        }
        "proxy.acl_add" => {
            if !std::path::Path::new("/usr/local/sbin/squid").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "Squid is not installed - install it first from Package Manager".to_string()));
            }
            let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("any").to_string();
            let destination = params.get("destination").and_then(|v| v.as_str()).unwrap_or("any").to_string();
            let action_field = params.get("action_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();

            if action_field != "allow" && action_field != "deny" {
                return Err(("INVALID_PARAMS".to_string(), "action must be 'allow' or 'deny'".to_string()));
            }

            let rule = proxy::AclRule {
                id: format!("a{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                source,
                destination,
                action: action_field,
                description,
            };

            let mut data = proxy::load_acl_rules();
            data.rules.push(rule.clone());
            proxy::save_acl_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "rule": rule }))
        }
        "proxy.acl_delete" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut data = proxy::load_acl_rules();
            let before_len = data.rules.len();
            data.rules.retain(|r| r.id != id);
            if data.rules.len() == before_len {
                return Err(("NOT_FOUND".to_string(), format!("ACL rule id '{id}' not found")));
            }
            proxy::save_acl_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "deleted": id }))
        }
        "proxy.acl_reorder" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("");
            if direction != "up" && direction != "down" {
                return Err(("INVALID_PARAMS".to_string(), "direction must be 'up' or 'down'".to_string()));
            }
            let mut data = proxy::load_acl_rules();
            let Some(pos) = data.rules.iter().position(|r| r.id == id) else {
                return Err(("NOT_FOUND".to_string(), format!("ACL rule id '{id}' not found")));
            };
            let neighbor = if direction == "up" {
                if pos == 0 {
                    return Err(("INVALID_PARAMS".to_string(), "Rule is already at the top".to_string()));
                }
                pos - 1
            } else {
                if pos + 1 >= data.rules.len() {
                    return Err(("INVALID_PARAMS".to_string(), "Rule is already at the bottom".to_string()));
                }
                pos + 1
            };
            data.rules.swap(pos, neighbor);
            proxy::save_acl_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "reordered": id }))
        }
        // --- Basic Authentication (Fase 2 Proxy) ---
        "proxy.auth_get_config" => {
            Ok(serde_json::json!({ "config": proxy::load_auth_config() }))
        }
        "proxy.auth_set_enabled" => {
            if !std::path::Path::new("/usr/local/sbin/squid").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "Squid is not installed - install it first from Package Manager".to_string()));
            }
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut cfg = proxy::load_auth_config();
            if enabled && cfg.usernames.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Add at least one user before enabling authentication - otherwise every request would be denied".to_string()));
            }
            if enabled && !std::path::Path::new(proxy::BASIC_NCSA_AUTH_HELPER).is_file() {
                return Err((
                    "INTERNAL_ERROR".to_string(),
                    format!("The basic_ncsa_auth helper was not found at {} - it should have been installed together with the squid package", proxy::BASIC_NCSA_AUTH_HELPER),
                ));
            }
            cfg.enabled = enabled;
            proxy::save_auth_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "config": cfg }))
        }
        "proxy.auth_add_user" => {
            let username = params.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let password = params.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();

            if !proxy::is_valid_username(&username) {
                return Err(("INVALID_PARAMS".to_string(), "Username must be 1-64 characters, letters/digits/underscore/hyphen only".to_string()));
            }
            if password.len() < 8 {
                return Err(("INVALID_PARAMS".to_string(), "Password must be at least 8 characters".to_string()));
            }

            let hash = proxy::hash_password_apr1(&password).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            // Baca file passwd EXISTING (kalau ada), buang baris user
            // yang sama kalau sudah ada (update password), lalu tambah
            // baris baru - format NCSA standar "username:hash".
            let existing = fs::read_to_string(proxy::SQUID_PASSWD_FILE).unwrap_or_default();
            let mut lines: Vec<String> = existing
                .lines()
                .filter(|l| !l.starts_with(&format!("{username}:")))
                .map(|l| l.to_string())
                .collect();
            lines.push(format!("{username}:{hash}"));

            if let Some(parent) = std::path::Path::new(proxy::SQUID_PASSWD_FILE).parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(proxy::SQUID_PASSWD_FILE, lines.join("\n") + "\n").map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to write {}: {e}", proxy::SQUID_PASSWD_FILE)))?;

            let mut auth_cfg = proxy::load_auth_config();
            if !auth_cfg.usernames.contains(&username) {
                auth_cfg.usernames.push(username.clone());
            }
            proxy::save_auth_config(&auth_cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            // Kalau auth SEDANG enabled, apply ulang supaya user baru
            // langsung bisa dipakai tanpa perlu toggle enabled ulang.
            if auth_cfg.enabled {
                proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            }

            Ok(serde_json::json!({ "username": username }))
        }
        "proxy.auth_delete_user" => {
            let username = params.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();

            let existing = fs::read_to_string(proxy::SQUID_PASSWD_FILE).unwrap_or_default();
            let lines: Vec<String> = existing
                .lines()
                .filter(|l| !l.starts_with(&format!("{username}:")))
                .map(|l| l.to_string())
                .collect();
            let _ = fs::write(proxy::SQUID_PASSWD_FILE, lines.join("\n") + "\n");

            let mut auth_cfg = proxy::load_auth_config();
            auth_cfg.usernames.retain(|u| u != &username);
            // Kalau ini user TERAKHIR dan auth masih enabled, matikan
            // otomatis - daripada biarkan proxy jadi TIDAK BISA DIAKSES
            // SAMA SEKALI (semua request ditolak karena tidak ada satu
            // pun kredensial valid yang bisa dipakai).
            if auth_cfg.usernames.is_empty() {
                auth_cfg.enabled = false;
            }
            proxy::save_auth_config(&auth_cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            proxy::apply_squid_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            Ok(serde_json::json!({ "deleted": username }))
        }
        // --- WireGuard VPN (Fase 1) ---
        "vpn.get_config" => {
            let installed = std::path::Path::new("/usr/local/bin/wg").exists();
            let mut cfg = load_wg_config();
            cfg.server_private_key = String::new();
            Ok(serde_json::json!({ "installed": installed, "config": cfg }))
        }
        "vpn.set_config" => {
            if !std::path::Path::new("/usr/local/bin/wg").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "WireGuard is not installed - install 'wireguard-tools' first from Package Manager".to_string()));
            }
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let listen_port = params.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(51820) as u16;
            let vpn_subnet = params.get("vpn_subnet").and_then(|v| v.as_str()).unwrap_or("10.66.66.0/24").to_string();

            if parse_cidr(&vpn_subnet).is_none() {
                return Err(("INVALID_PARAMS".to_string(), format!("VPN subnet '{vpn_subnet}' is not a valid CIDR")));
            }
            // Validasi reserved range (sama semangat dengan network.set_subnet)
            // - CUMA ini yang genuinely applicable di sini: vpn_subnet
            // adalah deklarasi ALAMAT NETWORK untuk pool WireGuard
            // (gateway .1 dihitung otomatis, bukan IP host individual
            // yang di-input admin), jadi cek network/broadcast address
            // dan ARP-probe TIDAK relevan untuk field ini - overlap
            // antar-zona sudah tercover di bawah.
            if let Some((network_addr, _)) = parse_cidr(&vpn_subnet) {
                let network_bytes = [
                    (network_addr >> 24) as u8,
                    (network_addr >> 16) as u8,
                    (network_addr >> 8) as u8,
                    network_addr as u8,
                ];
                if is_reserved_ip(network_bytes) {
                    return Err(("INVALID_PARAMS".to_string(), format!("VPN subnet '{vpn_subnet}' is in a reserved/special IP range")));
                }
            }

            let mut existing_subnets: Vec<String> = vec!["10.252.252.0/24".to_string()];
            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            if let Some(l) = &lan1_if {
                if let Some(cidr) = get_interface_cidr(l).and_then(|c| normalize_network_cidr(&c)) {
                    existing_subnets.push(cidr);
                }
            }
            if let Some(w) = &wan1_if {
                if let Some(cidr) = get_interface_cidr(w).and_then(|c| normalize_network_cidr(&c)) {
                    existing_subnets.push(cidr);
                }
            }
            for opt in &opt_ifaces {
                if let Some(cidr) = get_interface_cidr(opt).and_then(|c| normalize_network_cidr(&c)) {
                    existing_subnets.push(cidr);
                }
            }
            for existing in &existing_subnets {
                if cidr_overlaps(&vpn_subnet, existing) {
                    return Err(("INVALID_PARAMS".to_string(), format!("VPN subnet '{vpn_subnet}' conflicts with an existing zone already using '{existing}'")));
                }
            }

            let mut cfg = load_wg_config();
            cfg.enabled = enabled;
            cfg.listen_port = listen_port;
            cfg.vpn_subnet = vpn_subnet;

            if cfg.server_private_key.is_empty() {
                let (private_key, public_key) = generate_wg_keypair().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                cfg.server_private_key = private_key;
                cfg.server_public_key = public_key;
            }

            save_wg_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_wireguard_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let mut response_cfg = cfg;
            response_cfg.server_private_key = String::new();
            Ok(serde_json::json!({ "config": response_cfg }))
        }
        "vpn.peer_list" => {
            let mut cfg = load_wg_config();
            cfg.server_private_key = String::new();

            // Status koneksi NYATA per peer - parse 'wg show wg0 dump'
            // (format resmi machine-readable: satu baris per peer,
            // tab-separated, kolom ke-5 = unix timestamp handshake
            // TERAKHIR, 0 kalau belum pernah handshake sama sekali).
            // "Connected" didefinisikan sebagai handshake dalam 3 menit
            // terakhir (WireGuard re-handshake tiap ~2 menit selama
            // trafik aktif - >3 menit berarti tunnel sudah idle/putus).
            let mut status_by_pubkey: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
            if let Ok(output) = Command::new("/usr/local/bin/wg").arg("show").arg(WG_INTERFACE).arg("dump").output() {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for (i, line) in text.lines().enumerate() {
                        if i == 0 {
                            continue; // baris pertama = info interface sendiri, bukan peer
                        }
                        let fields: Vec<&str> = line.split('\t').collect();
                        if fields.len() < 7 {
                            continue;
                        }
                        let pubkey = fields[0].to_string();
                        let latest_handshake: u64 = fields[4].parse().unwrap_or(0);
                        let rx_bytes: u64 = fields[5].parse().unwrap_or(0);
                        let tx_bytes: u64 = fields[6].parse().unwrap_or(0);
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                        let connected = latest_handshake > 0 && now.saturating_sub(latest_handshake) < 180;
                        status_by_pubkey.insert(
                            pubkey,
                            serde_json::json!({
                                "connected": connected,
                                "last_handshake": if latest_handshake > 0 { Some(latest_handshake) } else { None },
                                "rx_bytes": rx_bytes,
                                "tx_bytes": tx_bytes,
                            }),
                        );
                    }
                }
            }

            let peers_with_status: Vec<serde_json::Value> = cfg
                .peers
                .iter()
                .map(|p| {
                    let mut peer_json = serde_json::to_value(p).unwrap_or(serde_json::Value::Null);
                    let status = status_by_pubkey
                        .get(&p.public_key)
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({ "connected": false, "last_handshake": null, "rx_bytes": 0, "tx_bytes": 0 }));
                    if let Some(obj) = peer_json.as_object_mut() {
                        obj.insert("status".to_string(), status);
                    }
                    peer_json
                })
                .collect();

            Ok(serde_json::json!({ "peers": peers_with_status }))
        }
        "vpn.peer_add" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            if name.is_empty() || name.len() > 64 {
                return Err(("INVALID_PARAMS".to_string(), "Peer name must be 1-64 characters".to_string()));
            }

            let mut cfg = load_wg_config();
            if cfg.server_private_key.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Configure and save the VPN General settings first (server keypair not generated yet)".to_string()));
            }
            let Some(allowed_ip) = next_available_wg_ip(&cfg) else {
                return Err(("INTERNAL_ERROR".to_string(), format!("No available IP addresses left in subnet '{}'", cfg.vpn_subnet)));
            };
            let (peer_private_key, peer_public_key) = generate_wg_keypair().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let peer = WireguardPeer {
                id: format!("p{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                name: name.clone(),
                public_key: peer_public_key,
                allowed_ip: allowed_ip.clone(),
                enabled: true,
            };
            cfg.peers.push(peer.clone());
            save_wg_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_wireguard_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let (_, wan1_if, _) = parse_pf_conf_zones();
            let endpoint_ip = wan1_if.as_deref().and_then(get_interface_ip).unwrap_or_else(|| "<GATEWAY_WAN_IP>".to_string());

            let client_config = format!(
                "[Interface]\nPrivateKey = {}\nAddress = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}:{}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
                peer_private_key, allowed_ip, cfg.server_public_key, endpoint_ip, cfg.listen_port
            );

            Ok(serde_json::json!({ "peer": peer, "client_config": client_config }))
        }
        "vpn.peer_delete" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut cfg = load_wg_config();
            let before_len = cfg.peers.len();
            cfg.peers.retain(|p| p.id != id);
            if cfg.peers.len() == before_len {
                return Err(("NOT_FOUND".to_string(), format!("Peer id '{id}' not found")));
            }
            save_wg_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_wireguard_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "deleted": id }))
        }
        "vpn.peer_set_enabled" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut cfg = load_wg_config();
            let peer = cfg.peers.iter_mut().find(|p| p.id == id);
            let Some(peer) = peer else {
                return Err(("NOT_FOUND".to_string(), format!("Peer id '{id}' not found")));
            };
            peer.enabled = enabled;
            save_wg_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            // apply_wireguard_conf() regenerates wg0.conf from cfg.peers
            // (skipping disabled ones, see generate_wg_conf) and reloads
            // it - this is what makes Disable genuine rather than
            // cosmetic, same principle as every other config mutation in
            // this daemon (validate/apply, don't just flip a database flag).
            apply_wireguard_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "id": id, "enabled": enabled }))
        }
        // --- IPsec Site-to-Site VPN (strongSwan) ---
        "ipsec.get_config" => {
            let installed = std::path::Path::new("/usr/local/sbin/swanctl").exists() || std::path::Path::new("/usr/local/bin/swanctl").exists();
            let cfg = load_ipsec_config();
            Ok(serde_json::json!({ "installed": installed, "tunnels": cfg.tunnels }))
        }
        "ipsec.tunnel_add" | "ipsec.tunnel_edit" => {
            if !(std::path::Path::new("/usr/local/sbin/swanctl").exists() || std::path::Path::new("/usr/local/bin/swanctl").exists()) {
                return Err(("INTERNAL_ERROR".to_string(), "strongSwan is not installed - install 'strongswan' first from Package Manager".to_string()));
            }
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let peer_address = params.get("peer_address").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let psk = params.get("psk").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let p1_encryption = params.get("p1_encryption").and_then(|v| v.as_str()).unwrap_or("aes256").to_string();
            let p1_integrity = params.get("p1_integrity").and_then(|v| v.as_str()).unwrap_or("sha256").to_string();
            let p1_dh_group = params.get("p1_dh_group").and_then(|v| v.as_str()).unwrap_or("modp2048").to_string();
            if name.is_empty() || peer_address.is_empty() || psk.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "name, peer_address, and psk are all required".to_string()));
            }
            let mut cfg = load_ipsec_config();
            let edit_id = params.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
            if let Some(edit_id) = edit_id {
                // Edit - PRESERVE existing phase2 children, hanya field
                // P1 yang diperbarui. Tidak pakai pola delete-lalu-add
                // seperti Firewall Rules, karena itu akan menghapus
                // Phase 2 yang admin sudah susun - in-place lebih aman
                // di sini.
                let tunnel = cfg.tunnels.iter_mut().find(|t| t.id == edit_id);
                let Some(tunnel) = tunnel else {
                    return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{edit_id}' not found")));
                };
                tunnel.name = name;
                tunnel.peer_address = peer_address;
                tunnel.psk = psk;
                tunnel.p1_encryption = p1_encryption;
                tunnel.p1_integrity = p1_integrity;
                tunnel.p1_dh_group = p1_dh_group;
            } else {
                cfg.tunnels.push(IpsecTunnel {
                    id: format!("ips{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                    name,
                    enabled: true,
                    peer_address,
                    psk,
                    p1_encryption,
                    p1_integrity,
                    p1_dh_group,
                    phase2: Vec::new(),
                });
            }
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "tunnels": cfg.tunnels }))
        }
        "ipsec.tunnel_delete" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut cfg = load_ipsec_config();
            let before_len = cfg.tunnels.len();
            cfg.tunnels.retain(|t| t.id != id);
            if cfg.tunnels.len() == before_len {
                return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{id}' not found")));
            }
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "deleted": id }))
        }
        "ipsec.tunnel_set_enabled" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut cfg = load_ipsec_config();
            let tunnel = cfg.tunnels.iter_mut().find(|t| t.id == id);
            let Some(tunnel) = tunnel else {
                return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{id}' not found")));
            };
            tunnel.enabled = enabled;
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "id": id, "enabled": enabled }))
        }
        "ipsec.phase2_add" => {
            let tunnel_id = params.get("tunnel_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let local_subnet = params.get("local_subnet").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let remote_subnet = params.get("remote_subnet").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let p2_encryption = params.get("p2_encryption").and_then(|v| v.as_str()).unwrap_or("aes256").to_string();
            let p2_integrity = params.get("p2_integrity").and_then(|v| v.as_str()).unwrap_or("sha256").to_string();
            let p2_dh_group = params.get("p2_dh_group").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if local_subnet.is_empty() || remote_subnet.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "local_subnet and remote_subnet are required".to_string()));
            }
            let mut cfg = load_ipsec_config();
            let tunnel = cfg.tunnels.iter_mut().find(|t| t.id == tunnel_id);
            let Some(tunnel) = tunnel else {
                return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{tunnel_id}' not found")));
            };
            tunnel.phase2.push(IpsecPhase2 {
                id: format!("p2-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                local_subnet,
                remote_subnet,
                p2_encryption,
                p2_integrity,
                p2_dh_group,
                enabled: true,
            });
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "tunnels": cfg.tunnels }))
        }
        "ipsec.phase2_delete" => {
            let tunnel_id = params.get("tunnel_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let phase2_id = params.get("phase2_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut cfg = load_ipsec_config();
            let tunnel = cfg.tunnels.iter_mut().find(|t| t.id == tunnel_id);
            let Some(tunnel) = tunnel else {
                return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{tunnel_id}' not found")));
            };
            let before_len = tunnel.phase2.len();
            tunnel.phase2.retain(|p| p.id != phase2_id);
            if tunnel.phase2.len() == before_len {
                return Err(("NOT_FOUND".to_string(), format!("Phase 2 id '{phase2_id}' not found on tunnel '{tunnel_id}'")));
            }
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "tunnels": cfg.tunnels }))
        }
        "ipsec.phase2_edit" => {
            let tunnel_id = params.get("tunnel_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let phase2_id = params.get("phase2_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let local_subnet = params.get("local_subnet").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let remote_subnet = params.get("remote_subnet").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let p2_encryption = params.get("p2_encryption").and_then(|v| v.as_str()).unwrap_or("aes256").to_string();
            let p2_integrity = params.get("p2_integrity").and_then(|v| v.as_str()).unwrap_or("sha256").to_string();
            let p2_dh_group = params.get("p2_dh_group").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if local_subnet.is_empty() || remote_subnet.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "local_subnet and remote_subnet are required".to_string()));
            }
            let mut cfg = load_ipsec_config();
            let tunnel = cfg.tunnels.iter_mut().find(|t| t.id == tunnel_id);
            let Some(tunnel) = tunnel else {
                return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{tunnel_id}' not found")));
            };
            let p2 = tunnel.phase2.iter_mut().find(|p| p.id == phase2_id);
            let Some(p2) = p2 else {
                return Err(("NOT_FOUND".to_string(), format!("Phase 2 id '{phase2_id}' not found on tunnel '{tunnel_id}'")));
            };
            p2.local_subnet = local_subnet;
            p2.remote_subnet = remote_subnet;
            p2.p2_encryption = p2_encryption;
            p2.p2_integrity = p2_integrity;
            p2.p2_dh_group = p2_dh_group;
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "tunnels": cfg.tunnels }))
        }
        "ipsec.phase2_set_enabled" => {
            let tunnel_id = params.get("tunnel_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let phase2_id = params.get("phase2_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut cfg = load_ipsec_config();
            let tunnel = cfg.tunnels.iter_mut().find(|t| t.id == tunnel_id);
            let Some(tunnel) = tunnel else {
                return Err(("NOT_FOUND".to_string(), format!("Tunnel id '{tunnel_id}' not found")));
            };
            let p2 = tunnel.phase2.iter_mut().find(|p| p.id == phase2_id);
            let Some(p2) = p2 else {
                return Err(("NOT_FOUND".to_string(), format!("Phase 2 id '{phase2_id}' not found on tunnel '{tunnel_id}'")));
            };
            p2.enabled = enabled;
            save_ipsec_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_ipsec_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "tunnel_id": tunnel_id, "phase2_id": phase2_id, "enabled": enabled }))
        }
        "ipsec.tunnel_terminate" => {
            // Beda dari tunnel_set_enabled(false): ini cuma putus SESI
            // AKTIF sekarang (swanctl --terminate --ike <nama>) - config
            // di swanctl.conf TETAP ada, jadi bisa reconnect otomatis
            // begitu ada traffic baru yang match (start_action = trap).
            // Cocok dipakai sebagai "Disconnect" sesaat untuk
            // troubleshooting, BUKAN untuk benar-benar mematikan tunnel
            // (pakai tunnel_set_enabled untuk itu).
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if id.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "id is required".to_string()));
            }
            let status = Command::new("/usr/local/sbin/swanctl")
                .args(["--terminate", "--ike", &id])
                .status()
                .map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to run swanctl --terminate: {e}")))?;
            if !status.success() {
                return Err(("INTERNAL_ERROR".to_string(), "swanctl --terminate --ike failed - the IKE_SA may not currently be active".to_string()));
            }
            Ok(serde_json::json!({ "terminated_ike": id }))
        }
        "ipsec.phase2_terminate" => {
            let phase2_id = params.get("phase2_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if phase2_id.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "phase2_id is required".to_string()));
            }
            let status = Command::new("/usr/local/sbin/swanctl")
                .args(["--terminate", "--child", &phase2_id])
                .status()
                .map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to run swanctl --terminate: {e}")))?;
            if !status.success() {
                return Err(("INTERNAL_ERROR".to_string(), "swanctl --terminate --child failed - the CHILD_SA may not currently be active".to_string()));
            }
            Ok(serde_json::json!({ "terminated_child": phase2_id }))
        }
        "ipsec.get_status" => {
            let cfg = load_ipsec_config();
            let status_map = get_ipsec_tunnel_status();
            let tunnels_with_status: Vec<serde_json::Value> = cfg
                .tunnels
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "id": t.id,
                        "name": t.name,
                        "enabled": t.enabled,
                        "connected": status_map.get(&t.id).copied().unwrap_or(false),
                        "phase2_count": t.phase2.len(),
                    })
                })
                .collect();
            Ok(serde_json::json!({ "tunnels": tunnels_with_status }))
        }
        "ipsec.get_log" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
            let lines = get_ipsec_log(limit);
            let parsed = parse_syslog_style_lines(&lines);
            Ok(serde_json::json!({ "lines": lines, "parsed": parsed }))
        }
        "security.get_config" => {
            Ok(serde_json::to_value(security::load_security_config())
                .map_err(|e| ("INTERNAL_ERROR".to_string(), e.to_string()))?)
        }
        "security.set_config" => {
            let mut cfg = security::load_security_config();

            if let Some(zones_val) = params.get("zones").and_then(|v| v.as_array()) {
                let mut new_zones = Vec::new();
                for z in zones_val {
                    new_zones.push(security::ZoneSecurityToggle {
                        zone_alias: z.get("zone_alias").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        physical_if: z.get("physical_if").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        enabled: z.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
                    });
                }
                cfg.zones = new_zones;
            }
            if let Some(rs) = params.get("rule_sources") {
                cfg.rule_sources = security::RuleSourceConfig {
                    et_open: rs.get("et_open").and_then(|v| v.as_bool()).unwrap_or(cfg.rule_sources.et_open),
                    oisf_trafficid: rs.get("oisf_trafficid").and_then(|v| v.as_bool()).unwrap_or(cfg.rule_sources.oisf_trafficid),
                    abuse_ch_ja3: rs.get("abuse_ch_ja3").and_then(|v| v.as_bool()).unwrap_or(cfg.rule_sources.abuse_ch_ja3),
                    abuse_ch_urlhaus: rs.get("abuse_ch_urlhaus").and_then(|v| v.as_bool()).unwrap_or(cfg.rule_sources.abuse_ch_urlhaus),
                };
            }
            if let Some(auto) = params.get("auto_update_enabled").and_then(|v| v.as_bool()) {
                cfg.auto_update_enabled = auto;
            }
            // Fase 2 - Policy: daftar kategori yang di-nonaktifkan admin.
            if let Some(cats) = params.get("disabled_categories").and_then(|v| v.as_array()) {
                cfg.policy.disabled_categories = cats
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            // Fase 2 - Custom rules: textarea admin, disimpan apa adanya,
            // validasi syntax dilakukan oleh 'suricata -T' di dalam
            // pipeline suricata-update sendiri saat security.update_rules
            // dipanggil (bukan divalidasi terpisah di sini).
            if let Some(rules_text) = params.get("custom_rules_text").and_then(|v| v.as_str()) {
                cfg.custom_rules_text = rules_text.to_string();
            }
            // IPS pilot - server-side enforced WAN-only, not just a UI
            // restriction: this touches suricata.yaml's netmap: section,
            // which Suricata's own docs warn can cause full connectivity
            // loss if misconfigured on the wrong interface (e.g. MGMT).
            // Reject rather than silently correct if the request names
            // anything outside the real, currently-detected WAN-role
            // interface set. Diperluas dari WAN1-only ke banyak interface
            // (WAN1+WAN2 dst) - tapi validasi keamanan yang SAMA tetap
            // dipegang, cuma sumbernya sekarang daftar WAN eligible penuh
            // (reuse multiwan::eligible_wan_interfaces(), BUKAN hardcode
            // WAN1 doang), bukan dilonggarkan.
            if let Some(ips_val) = params.get("ips") {
                let requested_enabled = ips_val.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                let requested_ifaces: Vec<String> = ips_val
                    .get("pilot_interfaces")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                    .unwrap_or_default();
                if requested_enabled {
                    let eligible = multiwan::eligible_wan_interfaces();
                    let mut invalid: Vec<String> = Vec::new();
                    for iface in &requested_ifaces {
                        if !eligible.contains(iface) {
                            invalid.push(iface.clone());
                        }
                    }
                    if !invalid.is_empty() {
                        return Err((
                            "VALIDATION_ERROR".to_string(),
                            format!(
                                "IPS pilot is restricted to WAN-role interfaces for this phase; refusing: {} (eligible: {:?})",
                                invalid.join(", "),
                                eligible
                            ),
                        ));
                    }
                    if requested_ifaces.is_empty() {
                        return Err(("VALIDATION_ERROR".to_string(), "Select at least one WAN interface to enable IPS pilot on".to_string()));
                    }
                    cfg.ips = security::IpsPilotConfig { enabled: true, pilot_interface: String::new(), pilot_interfaces: requested_ifaces };
                } else {
                    cfg.ips = security::IpsPilotConfig { enabled: false, pilot_interface: String::new(), pilot_interfaces: requested_ifaces };
                }
            }

            security::save_security_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            security::apply_security_conf(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "status": "ok" }))
        }
        "security.update_rules" => {
            let mut cfg = security::load_security_config();
            let output = security::run_suricata_rule_update(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            // Tidak ada crate chrono di project ini - pakai pola unix-epoch
            // yang sudah dipakai di tempat lain di main.rs, bukan format
            // ISO8601. PHP tinggal date('Y-m-d H:i', $ts) untuk tampilkan.
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            cfg.last_rule_update = Some(now_unix.to_string());
            security::save_security_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "status": "ok", "output": output }))
        }
        "security.get_alerts" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(500) as usize;
            if !std::path::Path::new(security::EVE_JSON_LOG).is_file() {
                return Ok(serde_json::json!([]));
            }
            // Tail lebih banyak baris mentah daripada limit tampilan, karena
            // tidak semua baris eve.json adalah event "alert" (ada flow/dns/
            // http/dll bercampur) - sama pola over-fetch seperti proxy.get_log.
            let output = Command::new("tail").arg("-n").arg("2000").arg(security::EVE_JSON_LOG).output();
            let raw = output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            let lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
            let alerts = security::parse_eve_alerts(&lines, limit);
            Ok(serde_json::to_value(alerts).unwrap_or(serde_json::json!([])))
        }
        "security.get_status" => {
            let installed = std::path::Path::new(security::SURICATA_BIN).exists();
            if !installed {
                return Ok(serde_json::json!({ "installed": false, "running": false }));
            }
            let status_out = Command::new("/usr/sbin/service").args(["suricata", "status"]).output();
            let status_text = status_out.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            let running = status_text.contains("is running");

            let version_out = Command::new(security::SURICATA_BIN).arg("-V").output();
            let version = version_out
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();

            let rule_count = fs::read_to_string("/var/lib/suricata/rules/suricata.rules")
                .map(|s| s.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')).count())
                .unwrap_or(0);

            let cfg = security::load_security_config();
            let interfaces = security::build_suricata_interface_line(&cfg.zones);

            Ok(serde_json::json!({
                "installed": true,
                "running": running,
                "version": version,
                "rule_count": rule_count,
                "interfaces": interfaces,
            }))
        }
        "system.backup_import" => {
            let temp_path = params.get("temp_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let original_filename = params.get("original_filename").and_then(|v| v.as_str()).unwrap_or("").to_string();

            if !temp_path.starts_with("/tmp/") || temp_path.contains("..") {
                return Err(("INVALID_PARAMS".to_string(), "Invalid temp_path".to_string()));
            }
            if original_filename.contains('/') || original_filename.contains("..") || !original_filename.ends_with(".tar.gz") {
                return Err(("INVALID_PARAMS".to_string(), "Invalid original_filename".to_string()));
            }
            if !std::path::Path::new(&temp_path).is_file() {
                return Err(("NOT_FOUND".to_string(), "Uploaded temp file not found".to_string()));
            }

            let _ = fs::create_dir_all(BACKUP_DIR);
            let final_path = format!("{BACKUP_DIR}/{original_filename}");
            fs::copy(&temp_path, &final_path).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to import backup: {e}")))?;
            let _ = fs::remove_file(&temp_path);
            let _ = fs::set_permissions(&final_path, fs::Permissions::from_mode(0o640));
            let _ = Command::new("chown").arg(format!("root:{ALLOWED_GROUP}")).arg(&final_path).status();

            Ok(serde_json::json!({ "filename": original_filename }))
        }
        "system.backup_restore" => {
            let filename = params.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let confirm = params.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);

            if filename.contains('/') || filename.contains("..") {
                return Err(("INVALID_PARAMS".to_string(), "Invalid filename".to_string()));
            }
            let archive_path = format!("{BACKUP_DIR}/{filename}");
            if !std::path::Path::new(&archive_path).is_file() {
                return Err(("NOT_FOUND".to_string(), format!("Backup file '{filename}' not found")));
            }

            // 1. Verifikasi HMAC - tanda tangan dari nama file HARUS
            // cocok dengan HMAC yang dihitung ULANG dari isi file
            // sekarang. Format nama: ntpsense-backup-<ts>-<hmac16>.tar.gz
            let expected_hmac = filename
                .strip_suffix(".tar.gz")
                .and_then(|s| s.rsplit('-').next())
                .unwrap_or("");
            if expected_hmac.len() != 16 {
                return Err(("PERMISSION_DENIED".to_string(), "Backup filename is not signed (unrecognized format) - cannot verify authenticity".to_string()));
            }
            let actual_hmac = compute_file_hmac(&archive_path).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            if actual_hmac != expected_hmac {
                return Err((
                    "PERMISSION_DENIED".to_string(),
                    "HMAC signature mismatch - this backup may be from a different gateway or has been modified".to_string(),
                ));
            }

            // 2. Pertahanan Tar Slip - list dulu (tar -tzf, TIDAK menulis
            // apa pun ke disk), tolak path traversal/absolut atau nama
            // yang tidak dikenal SEBELUM ekstraksi sungguhan.
            let list_output = Command::new("tar").arg("-tzf").arg(&archive_path).output();
            let Ok(list_output) = list_output else {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to list backup archive contents".to_string()));
            };
            if !list_output.status.success() {
                return Err(("INTERNAL_ERROR".to_string(), "Backup archive appears to be corrupted".to_string()));
            }
            let known_names: Vec<&str> = backup_file_list().iter().map(|(_, name)| *name).collect();
            let entries_text = String::from_utf8_lossy(&list_output.stdout);
            for entry in entries_text.lines() {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                if entry.contains("..") || entry.starts_with('/') {
                    return Err(("PERMISSION_DENIED".to_string(), format!("Backup archive contains a suspicious entry ('{entry}') - refusing to extract (possible Tar Slip)")));
                }
                if !known_names.contains(&entry) {
                    return Err(("PERMISSION_DENIED".to_string(), format!("Backup archive contains an unrecognized entry ('{entry}') - refusing to extract")));
                }
            }

            // 3. Ekstrak ke staging dulu (BUKAN langsung ke lokasi
            // final) - supaya bisa scan interface yang direferensikan
            // SEBELUM benar-benar menimpa config yang sedang berjalan.
            let staging_dir = "/tmp/ntpsense-restore-staging";
            let _ = fs::remove_dir_all(staging_dir);
            fs::create_dir_all(staging_dir).map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to create staging dir: {e}")))?;
            let extract_status = Command::new("tar").arg("-xzf").arg(&archive_path).arg("-C").arg(staging_dir).status();
            if !matches!(extract_status, Ok(s) if s.success()) {
                let _ = fs::remove_dir_all(staging_dir);
                return Err(("INTERNAL_ERROR".to_string(), "Failed to extract backup archive".to_string()));
            }

            // 4. Scan referensi interface di file yang di-staging -
            // dibandingkan dengan interface yang BENAR-BENAR terdeteksi
            // sekarang (mgmt/lan1/wan1/opt). Beda dari Tier 1
            // (single-zone) - Tier 2 rawan restore ke hardware/VM
            // berbeda urutan NIC, jadi validasi ini WAJIB sebelum
            // benar-benar menimpa config.
            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let mut known_ifaces: Vec<String> = opt_ifaces;
            if let Some(m) = mgmt_if {
                known_ifaces.push(m);
            }
            if let Some(l) = lan1_if {
                known_ifaces.push(l);
            }
            if let Some(w) = wan1_if {
                known_ifaces.push(w);
            }

            let mut referenced_ifaces: Vec<String> = Vec::new();
            for (_, archive_name) in backup_file_list() {
                if archive_name == "pf.conf.reference" {
                    continue; // referensi saja, bukan sumber restore aktif
                }
                let staged_path = format!("{staging_dir}/{archive_name}");
                if let Ok(text) = fs::read_to_string(&staged_path) {
                    for token in scan_interface_tokens(&text) {
                        if !referenced_ifaces.contains(&token) {
                            referenced_ifaces.push(token);
                        }
                    }
                }
            }
            let unknown_ifaces: Vec<&String> = referenced_ifaces.iter().filter(|i| !known_ifaces.contains(i)).collect();

            if !unknown_ifaces.is_empty() && !confirm {
                let _ = fs::remove_dir_all(staging_dir);
                return Ok(serde_json::json!({
                    "warning": true,
                    "message": format!(
                        "This backup references interface(s) not detected on this system now: {unknown_ifaces:?}. It may have been created on different hardware. Resend with confirm:true to restore anyway (unmatched interface entries will simply have no effect)."
                    ),
                    "unknown_interfaces": unknown_ifaces,
                    "known_interfaces": known_ifaces,
                }));
            }

            // 5. Salin dari staging ke lokasi final SUNGGUHAN.
            for (dest, archive_name) in backup_file_list() {
                if archive_name == "pf.conf.reference" {
                    continue; // TIDAK PERNAH menimpa /etc/pf.conf langsung dari backup - itu SELALU digenerate oleh install-gateway-v2.sh, restore cukup pulihkan state JSON kita lalu splice ulang lewat regenerate_pf_conf_for_interface()/regenerate_kea_config() di bawah.
                }
                let staged_path = format!("{staging_dir}/{archive_name}");
                if let Ok(data) = fs::read(&staged_path) {
                    if let Some(parent) = std::path::Path::new(dest).parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(dest, data);
                }
            }
            let _ = fs::remove_dir_all(staging_dir);

            // 6. Terapkan ULANG state yang baru dipulihkan ke sistem
            // yang sedang jalan (custom rules -> pf.conf, dhcp config ->
            // Kea, port status -> ifconfig up/down) - pola sama persis
            // dengan startup reapply main(), supaya restore langsung
            // AKTIF tanpa perlu reboot manual (ini justru RCA #13 Tier
            // 1 yang SUDAH kita hindari sejak awal di sini).
            let restored_rules = load_custom_rules();
            let restored_groups = load_zone_groups();
            let mut apply_ifaces: std::collections::HashSet<String> = std::collections::HashSet::new();
            for r in &restored_rules.rules {
                if r.zone_group.is_none() {
                    apply_ifaces.insert(r.interface.clone());
                }
            }
            for group in &restored_groups.groups {
                for member in &group.member_interfaces {
                    apply_ifaces.insert(member.clone());
                }
            }
            for iface in &apply_ifaces {
                let _ = regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface));
            }
            let _ = regenerate_kea_config();
            // Reapply Squid config juga (kalau paket sungguhan terinstall
            // di sistem ini - restore ke gateway yang belum pernah
            // install Squid seharusnya tidak coba restart service yang
            // tidak ada).
            if std::path::Path::new("/usr/local/sbin/squid").exists() {
                let restored_proxy_cfg = proxy::load_proxy_config();
                if let Ok(conf_text) = proxy::generate_squid_conf(&restored_proxy_cfg) {
                    let _ = fs::write(proxy::SQUID_CONF, conf_text);
                    if restored_proxy_cfg.enabled {
                        let _ = Command::new("service").arg("squid").arg("restart").status();
                    } else {
                        let _ = Command::new("service").arg("squid").arg("stop").status();
                    }
                }
            }
            let restored_port_status = load_port_status();
            for (iface, enabled) in &restored_port_status {
                let updown = if *enabled { "up" } else { "down" };
                let _ = Command::new("ifconfig").arg(iface).arg(updown).status();
            }

            if std::path::Path::new("/usr/local/bin/wg").exists() {
                let _ = apply_wireguard_conf();
            }

            Ok(serde_json::json!({ "restored": filename, "unknown_interfaces": unknown_ifaces }))
        }
        // --- Fase 1 rule editor: HANYA untuk interface OPT ---
        "firewall.custom_rules.list" => {
            let data = load_custom_rules();
            Ok(serde_json::json!({ "rules": data.rules }))
        }
        "multiwan.eligible_interfaces" => {
            Ok(serde_json::json!({ "interfaces": multiwan::eligible_wan_interfaces() }))
        }
        "multiwan.gateway_list" => {
            Ok(serde_json::json!({ "gateways": multiwan::list_gateways() }))
        }
        "multiwan.gateway_create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let gateway_ip = params.get("gateway_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let monitor_ip = params.get("monitor_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // BARU (Agustus 2026, fitur Site Mesh VPN WAN preference) -
            // "dedicated" atau "shared", default "dedicated" kalau Web
            // UI lama belum kirim field ini (backward compat).
            let link_type = params.get("link_type").and_then(|v| v.as_str()).unwrap_or("dedicated").to_string();
            match multiwan::create_gateway(&name, &interface, &gateway_ip, &monitor_ip, &link_type) {
                Ok(()) => {
                    if let Err(e) = multiwan::regenerate_outbound_nat() {
                        eprintln!("WARNING: gateway created but outbound NAT regeneration failed: {e}");
                    }
                    Ok(serde_json::json!({ "created": name }))
                }
                Err(msg) => Err(("MULTIWAN_GATEWAY_CREATE_FAILED".to_string(), msg)),
            }
        }
        "multiwan.gateway_update" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let gateway_ip = params.get("gateway_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let monitor_ip = params.get("monitor_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let link_type = params.get("link_type").and_then(|v| v.as_str()).unwrap_or("dedicated").to_string();
            match multiwan::update_gateway(&name, &gateway_ip, &monitor_ip, enabled, &link_type) {
                Ok(()) => Ok(serde_json::json!({ "updated": name })),
                Err(msg) => Err(("MULTIWAN_GATEWAY_UPDATE_FAILED".to_string(), msg)),
            }
        }
        "multiwan.gateway_delete" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match multiwan::delete_gateway(&name) {
                Ok(()) => {
                    if let Err(e) = multiwan::regenerate_outbound_nat() {
                        eprintln!("WARNING: gateway deleted but outbound NAT regeneration failed: {e}");
                    }
                    Ok(serde_json::json!({ "deleted": name }))
                }
                Err(msg) => Err(("MULTIWAN_GATEWAY_DELETE_FAILED".to_string(), msg)),
            }
        }
        "multiwan.group_list" => {
            Ok(serde_json::json!({ "groups": multiwan::list_groups() }))
        }
        "multiwan.group_create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let members: Vec<multiwan::GatewayGroupMember> = params
                .get("members")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            let gateway_name = m.get("gateway_name")?.as_str()?.to_string();
                            let tier = m.get("tier")?.as_u64()? as u8;
                            Some(multiwan::GatewayGroupMember { gateway_name, tier })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let routing_mode = params.get("routing_mode").and_then(|v| v.as_str()).unwrap_or("static").to_string();
            let sla_max_latency_ms = params.get("sla_max_latency_ms").and_then(|v| v.as_f64());
            let sla_max_jitter_ms = params.get("sla_max_jitter_ms").and_then(|v| v.as_f64());
            let sla_max_packet_loss_pct = params.get("sla_max_packet_loss_pct").and_then(|v| v.as_f64());
            match multiwan::create_group(&name, members, &routing_mode, sla_max_latency_ms, sla_max_jitter_ms, sla_max_packet_loss_pct) {
                Ok(()) => Ok(serde_json::json!({ "created": name })),
                Err(msg) => Err(("MULTIWAN_GROUP_CREATE_FAILED".to_string(), msg)),
            }
        }
        "multiwan.group_update" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let members: Vec<multiwan::GatewayGroupMember> = params
                .get("members")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            let gateway_name = m.get("gateway_name")?.as_str()?.to_string();
                            let tier = m.get("tier")?.as_u64()? as u8;
                            Some(multiwan::GatewayGroupMember { gateway_name, tier })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let routing_mode = params.get("routing_mode").and_then(|v| v.as_str()).unwrap_or("static").to_string();
            let sla_max_latency_ms = params.get("sla_max_latency_ms").and_then(|v| v.as_f64());
            let sla_max_jitter_ms = params.get("sla_max_jitter_ms").and_then(|v| v.as_f64());
            let sla_max_packet_loss_pct = params.get("sla_max_packet_loss_pct").and_then(|v| v.as_f64());
            match multiwan::update_group(&name, members, &routing_mode, sla_max_latency_ms, sla_max_jitter_ms, sla_max_packet_loss_pct) {
                Ok(()) => {
                    // RCA (ditemukan bro langsung - routing_mode diganti
                    // ke "quality", tersimpan benar, TAPI route-to di
                    // pf.conf tetap stale/satu-gateway sampai daemon
                    // di-restart penuh): update_group() di dalam
                    // multiwan.rs cuma memanggil apply_system_default_
                    // gateway() (mekanisme TERPISAH, untuk default route
                    // sistem sendiri) - TIDAK menyentuh rule Firewall
                    // manapun yang merujuk grup ini lewat
                    // gateway_group_name sama sekali. route-to clause
                    // dihitung ULANG cuma saat pf.conf untuk interface itu
                    // di-generate ulang - kalau tidak ada yang men-trigger
                    // itu, clause lama (dihitung di titik waktu SEBELUM
                    // perubahan) tetap tertanam di pf.conf selamanya.
                    // Fix: cari semua interface yang rule Firewall-nya
                    // merujuk grup ini (via gateway_group_name), regenerasi
                    // pf.conf UNTUK SETIAP interface itu - pola PERSIS sama
                    // dengan update_zone_group() di atas untuk Zone Group.
                    let affected_ifaces: std::collections::HashSet<String> = load_custom_rules()
                        .rules
                        .iter()
                        .filter(|r| r.gateway_group_name.as_deref() == Some(name.as_str()))
                        .map(|r| r.interface.clone())
                        .collect();
                    for iface in &affected_ifaces {
                        let _ = regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface));
                    }
                    Ok(serde_json::json!({ "updated": name }))
                }
                Err(msg) => Err(("MULTIWAN_GROUP_UPDATE_FAILED".to_string(), msg)),
            }
        }
        "multiwan.group_delete" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // Kumpulkan rule Firewall mana saja yang masih pakai grup ini
            // (via gateway_group_name) - dipakai delete_group() untuk
            // proteksi "masih dipakai" yang sama pola dengan Limiter/Role.
            let rules_using_groups: Vec<(String, String)> = load_custom_rules()
                .rules
                .iter()
                .filter_map(|r| r.gateway_group_name.as_ref().map(|g| (format!("{} ({})", r.description, r.interface), g.clone())))
                .collect();
            match multiwan::delete_group(&name, &rules_using_groups) {
                Ok(()) => Ok(serde_json::json!({ "deleted": name })),
                Err(msg) => Err(("MULTIWAN_GROUP_DELETE_FAILED".to_string(), msg)),
            }
        }
        "multiwan.group_set_default" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match multiwan::set_system_default_group(&name) {
                Ok(()) => Ok(serde_json::json!({ "system_default": name })),
                Err(msg) => Err(("MULTIWAN_SET_DEFAULT_FAILED".to_string(), msg)),
            }
        }
        "multiwan.status" => {
            Ok(multiwan::get_status_summary())
        }
        "multiwan.event_log" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
            Ok(serde_json::json!({ "lines": multiwan::get_event_log(limit) }))
        }
        "multiwan.settings_get" => {
            Ok(serde_json::to_value(multiwan::load_settings()).unwrap_or(serde_json::Value::Null))
        }
        "multiwan.settings_update" => {
            let interval_secs = params.get("interval_secs").and_then(|v| v.as_u64()).unwrap_or(0);
            let fail_threshold = params.get("fail_threshold").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let recover_threshold = params.get("recover_threshold").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            match multiwan::save_settings(interval_secs, fail_threshold, recover_threshold) {
                Ok(()) => Ok(serde_json::json!({ "updated": true })),
                Err(msg) => Err(("INVALID_PARAMS".to_string(), msg)),
            }
        }
        "firewall.zone_group_list" => {
            let groups = load_zone_groups().groups;
            Ok(serde_json::json!({ "groups": groups }))
        }
        "firewall.zone_group_eligible_interfaces" => {
            Ok(serde_json::json!({ "interfaces": zone_group_eligible_interfaces() }))
        }
        "firewall.zone_group_create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let members: Vec<String> = params
                .get("member_interfaces")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|m| m.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            match create_zone_group(&name, &members) {
                Ok(()) => Ok(serde_json::json!({ "created": name })),
                Err(msg) => Err(("ZONE_GROUP_CREATE_FAILED".to_string(), msg)),
            }
        }
        "firewall.zone_group_update" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let members: Vec<String> = params
                .get("member_interfaces")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|m| m.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            match update_zone_group(&name, &members) {
                Ok(()) => Ok(serde_json::json!({ "updated": name })),
                Err(msg) => Err(("ZONE_GROUP_UPDATE_FAILED".to_string(), msg)),
            }
        }
        "firewall.zone_group_delete" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match delete_zone_group(&name) {
                Ok(()) => Ok(serde_json::json!({ "deleted": name })),
                Err(msg) => Err(("ZONE_GROUP_DELETE_FAILED".to_string(), msg)),
            }
        }
        "firewall.limiter_list" => {
            Ok(serde_json::json!({ "limiters": load_limiters().limiters }))
        }
        "firewall.limiter_create" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let download_mbps = params.get("download_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let upload_mbps = params.get("upload_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0);

            if name.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Limiter name cannot be empty".to_string()));
            }
            if download_mbps <= 0.0 || upload_mbps <= 0.0 {
                return Err(("INVALID_PARAMS".to_string(), "Download and upload bandwidth must both be greater than 0 Mbps".to_string()));
            }
            let mut data = load_limiters();
            if data.limiters.iter().any(|l| l.name.eq_ignore_ascii_case(&name)) {
                return Err(("INVALID_PARAMS".to_string(), format!("A limiter named '{name}' already exists.")));
            }
            let (download_pipe_id, upload_pipe_id) = next_limiter_pipe_ids();
            let limiter = BandwidthLimiter { name, download_mbps, upload_mbps, download_pipe_id, upload_pipe_id };
            data.limiters.push(limiter.clone());
            save_limiters(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            regenerate_dnctl_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "limiter": limiter }))
        }
        "firewall.limiter_update" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let download_mbps = params.get("download_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let upload_mbps = params.get("upload_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0);
            if download_mbps <= 0.0 || upload_mbps <= 0.0 {
                return Err(("INVALID_PARAMS".to_string(), "Download and upload bandwidth must both be greater than 0 Mbps".to_string()));
            }
            let mut data = load_limiters();
            let Some(existing) = data.limiters.iter_mut().find(|l| l.name == name) else {
                return Err(("INVALID_PARAMS".to_string(), format!("Limiter '{name}' not found.")));
            };
            // Pipe ID TIDAK berubah saat update - cuma angka bandwidth-nya
            // yang di-refresh, supaya rule pf yang sudah mereferensikan
            // nama limiter ini tidak perlu di-regenerate sama sekali
            // (cukup /etc/dnctl.conf yang di-reload).
            existing.download_mbps = download_mbps;
            existing.upload_mbps = upload_mbps;
            save_limiters(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            regenerate_dnctl_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "updated": name }))
        }
        "firewall.limiter_delete" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let in_use: Vec<String> = load_custom_rules()
                .rules
                .iter()
                .filter(|r| r.limiter_name.as_deref() == Some(name.as_str()))
                .map(|r| format!("{} ({})", r.description, r.interface))
                .collect();
            if !in_use.is_empty() {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Cannot delete this limiter - still used by rule(s): {}. Remove the limiter from those rules first.", in_use.join(", ")),
                ));
            }
            let mut data = load_limiters();
            let before = data.limiters.len();
            data.limiters.retain(|l| l.name != name);
            if data.limiters.len() == before {
                return Err(("INVALID_PARAMS".to_string(), format!("Limiter '{name}' not found.")));
            }
            save_limiters(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            regenerate_dnctl_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "deleted": name }))
        }
        "firewall.custom_rules.add" => {
            let interface = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let action_field = params.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("in").to_string();
            let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("any").to_string();
            let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("any").to_string();
            let destination = params.get("destination").and_then(|v| v.as_str()).unwrap_or("any").to_string();
            let port = params.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);
            let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let nat_redirect_ip = params.get("nat_redirect_ip").and_then(|v| v.as_str()).map(|s| s.to_string());
            let nat_redirect_port = params.get("nat_redirect_port").and_then(|v| v.as_u64()).map(|p| p as u16);
            let limiter_name = params.get("limiter_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
            if let Some(name) = &limiter_name {
                if !load_limiters().limiters.iter().any(|l| &l.name == name) {
                    return Err(("INVALID_PARAMS".to_string(), format!("Bandwidth Limiter '{name}' does not exist.")));
                }
            }
            let gateway_group_name = params.get("gateway_group_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
            if let Some(name) = &gateway_group_name {
                if !multiwan::list_groups().iter().any(|g| &g.name == name) {
                    return Err(("INVALID_PARAMS".to_string(), format!("Gateway Group '{name}' does not exist.")));
                }
            }
            let zone_group = params.get("zone_group").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
            let floating = params.get("floating").and_then(|v| v.as_bool()).unwrap_or(false);
            if floating && zone_group.is_some() {
                return Err(("INVALID_PARAMS".to_string(), "A rule cannot be both Floating and part of a Zone Group - pick one.".to_string()));
            }
            let interface = if let Some(name) = &zone_group {
                if !load_zone_groups().groups.iter().any(|g| &g.name == name) {
                    return Err(("INVALID_PARAMS".to_string(), format!("Zone Group '{name}' does not exist.")));
                }
                // 'interface' diisi nama grup untuk tampilan - keputusan
                // routing sesungguhnya lewat field zone_group, jadi
                // validasi "interface fisik yang dikenal" di bawah
                // SENGAJA dilewati untuk kasus ini (lihat pengecekan
                // 'zone_group.is_none()' di blok validasi valid_ifaces).
                name.clone()
            } else if floating {
                // Sama seperti zone_group - tidak butuh interface fisik
                // spesifik, cuma placeholder tampilan.
                "floating".to_string()
            } else {
                interface
            };

            if !["in", "out", "both"].contains(&direction.as_str()) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("direction must be 'in', 'out', or 'both' - got '{direction}'"),
                ));
            }

            // Validasi Lapis 2 (Rust) - JANGAN cuma percaya validasi PHP:
            // Fase 2 - interface BOLEH salah satu dari LAN1/WAN1/OPT yang
            // benar-benar terdeteksi di pf.conf sekarang. MGMT TETAP
            // DITOLAK SECARA EKSPLISIT di sini - bukan cuma karena tidak
            // ada marker untuknya (yang sudah otomatis membuatnya gagal
            // di tahap splice), tapi supaya pesan errornya jelas dan
            // terjadi SEBELUM sempat tersimpan ke JSON. Prinsip sama
            // dengan zone.reassign: MGMT tidak pernah bisa diutak-atik
            // dari Web UI, titik - pelajaran RCA #28 Tier 1 (insiden
            // lockout diri sendiri) dan pola anti-lockout rule pfSense
            // yang SENGAJA tidak dibuat "rule biasa" yang bisa diedit.
            let mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
            if mgmt_if.as_deref() == Some(interface.as_str()) {
                return Err((
                    "PERMISSION_DENIED".to_string(),
                    format!("Interface '{interface}' is the locked MGMT interface - cannot be given a custom rule"),
                ));
            }

            let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
            let mut valid_ifaces = opt_ifaces.clone();
            if let Some(l) = &lan1_if {
                valid_ifaces.push(l.clone());
            }
            if let Some(w) = &wan1_if {
                valid_ifaces.push(w.clone());
            }
            // wg0 sengaja TIDAK pernah masuk parse_pf_conf_zones() (Type=
            // VPN Tunnel, bukan Physical - lihat Doc 7 §1.2a/RCA-20, wg0
            // tidak boleh ikut rotasi Zone fisik). Tapi wg0 PUNYA tab
            // Firewall sendiri (sekarang unlocked untuk custom rule CRUD
            // sejak redesain default-deny simetris) - validasi ini perlu
            // tahu wg0 itu interface yang sah untuk custom rule, terpisah
            // dari daftar physical di atas, bukan berarti dia masuk Zone
            // rotation.
            valid_ifaces.push(WG_INTERFACE.to_string());
            // enc0 (IPsec) - same rationale as wg0 above: Type=VPN
            // Tunnel, not part of the physical Zone rotation, but has
            // its own Firewall tab now that IPsec Site-to-Site exists.
            valid_ifaces.push(IPSEC_INTERFACE.to_string());
            if zone_group.is_none() && !floating && !valid_ifaces.contains(&interface) {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    format!("Interface '{interface}' is not valid (currently known interfaces: {valid_ifaces:?})"),
                ));
            }
            if action_field != "pass" && action_field != "block" {
                return Err(("INVALID_PARAMS".to_string(), "action must be 'pass' or 'block'".to_string()));
            }
            if !["any", "tcp", "udp", "icmp"].contains(&protocol.as_str()) {
                return Err(("INVALID_PARAMS".to_string(), "protocol must be any/tcp/udp/icmp".to_string()));
            }
            // RCA (ditemukan dari test VM nyata): pf MENOLAK kombinasi
            // 'port' tanpa 'proto tcp/udp' eksplisit - pesan error asli
            // pfctl persis "port only applies to tcp/udp". Validasi ini
            // HARUS di Rust (Lapis 2), bukan cuma di PHP form, supaya
            // rule tidak-valid tidak pernah sampai tersimpan ke JSON dan
            // gagal splice ke pf.conf.
            if port.is_some() && (protocol == "any" || protocol == "icmp") {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    "Port hanya berlaku untuk protocol tcp/udp - pilih protocol tcp atau udp kalau mengisi port".to_string(),
                ));
            }
            // NAT (Port Forward) validasi Lapis 2 - sama prinsip dengan
            // validasi port/protocol di atas, jangan cuma percaya PHP:
            if nat_redirect_ip.is_some() {
                if Some(interface.as_str()) != wan1_if.as_deref() {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        "Port forward hanya berlaku untuk interface WAN1 - meneruskan koneksi masuk hanya masuk akal dari sisi WAN".to_string(),
                    ));
                }
                if action_field != "pass" {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        "Port forward harus action 'pass' - rule yang me-redirect traffic sekaligus men-drop tidak masuk akal".to_string(),
                    ));
                }
                if protocol != "tcp" && protocol != "udp" {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        "Port forward hanya berlaku untuk protocol tcp/udp".to_string(),
                    ));
                }
                if port.is_none() {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        "Port forward butuh port eksternal (WAN) eksplisit".to_string(),
                    ));
                }
            }

            // Deteksi duplikat - riset dulu (Doc 7): Palo Alto satu-
            // satunya vendor besar dengan redundancy analysis BAWAAN,
            // tapi itu PERINGATAN, bukan blokir keras (FortiGate/pfSense
            // malah tidak punya deteksi ini sama sekali, cuma anjuran
            // review manual berkala). Pola yang dipilih di sini:
            // "warning-before-proceed" yang SUDAH jadi konvensi project
            // ini (subnet change, restore NIC mismatch) - kalau rule
            // yang persis sama (action+direction+protocol+source+
            // destination+port) SUDAH ADA di interface yang sama, tolak
            // dulu dengan kode khusus supaya PHP bisa tampilkan
            // konfirmasi - KECUALI admin sudah eksplisit confirm=true,
            // baru benar-benar disimpan. Rule identik secara teknis
            // TIDAK merusak apa pun di pf (cuma redundan), jadi ini
            // murni bantu admin sadar, bukan mencegah kesalahan fatal.
            let confirm_duplicate = params.get("confirm").and_then(|v| v.as_bool()).unwrap_or(false);
            if !confirm_duplicate {
                let existing_rules = load_custom_rules();
                let is_duplicate = existing_rules.rules.iter().any(|r| {
                    r.interface == interface
                        && r.action == action_field
                        && r.direction == direction
                        && r.protocol == protocol
                        && r.source == source
                        && r.destination == destination
                        && r.port == port
                });
                if is_duplicate {
                    return Err((
                        "DUPLICATE_RULE".to_string(),
                        "An identical rule (same action, direction, protocol, source, destination, and port) already exists on this interface.".to_string(),
                    ));
                }
            }

            let rule = CustomRule {
                id: format!("r{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                interface: interface.clone(),
                action: action_field,
                direction,
                protocol,
                source,
                destination,
                port,
                description,
                nat_redirect_ip,
                nat_redirect_port,
                limiter_name,
                gateway_group_name,
                zone_group: zone_group.clone(),
                enabled: true,
                floating,
            };

            let mut data = load_custom_rules();
            data.rules.push(rule.clone());
            save_custom_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            if floating {
                // Floating - satu regenerasi global, BUKAN loop per-
                // interface (rule ini tidak punya "member interfaces"
                // sama sekali, cukup satu baris pf tanpa klausa 'on').
                regenerate_floating_rules().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            } else {
                let targets: Vec<String> = if let Some(name) = &zone_group {
                    load_zone_groups().groups.iter().find(|g| &g.name == name).map(|g| g.member_interfaces.clone()).unwrap_or_default()
                } else {
                    vec![interface.clone()]
                };
                for iface in &targets {
                    regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface)).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                }
            }
            Ok(serde_json::json!({ "rule": rule }))
        }
        "firewall.custom_rules.delete" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut data = load_custom_rules();
            let removed = data.rules.iter().find(|r| r.id == id).cloned();
            let Some(removed_rule) = removed else {
                return Err(("NOT_FOUND".to_string(), format!("Rule id '{id}' not found")));
            };
            data.rules.retain(|r| r.id != id);
            save_custom_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let targets: Vec<String> = if let Some(name) = &removed_rule.zone_group {
                load_zone_groups().groups.iter().find(|g| &g.name == name).map(|g| g.member_interfaces.clone()).unwrap_or_default()
            } else {
                vec![removed_rule.interface.clone()]
            };
            if removed_rule.floating {
                regenerate_floating_rules().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            } else {
                for iface in &targets {
                    regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface)).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                }
            }
            Ok(serde_json::json!({ "deleted": id }))
        }
        "firewall.custom_rules.set_enabled" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut data = load_custom_rules();
            let Some(rule) = data.rules.iter_mut().find(|r| r.id == id) else {
                return Err(("NOT_FOUND".to_string(), format!("Rule id '{id}' not found")));
            };
            rule.enabled = enabled;
            let zone_group = rule.zone_group.clone();
            let interface = rule.interface.clone();
            let is_floating = rule.floating;
            save_custom_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            if is_floating {
                regenerate_floating_rules().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            } else {
                let targets: Vec<String> = if let Some(name) = &zone_group {
                    load_zone_groups().groups.iter().find(|g| &g.name == name).map(|g| g.member_interfaces.clone()).unwrap_or_default()
                } else {
                    vec![interface]
                };
                for iface in &targets {
                    regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface)).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                }
            }
            Ok(serde_json::json!({ "id": id, "enabled": enabled }))
        }
        // Rule order MATTERS in pf (first quick-match wins) - this swaps
        // a rule's position with its immediate same-interface neighbor.
        // NOTE: CustomRulesFile stores ALL interfaces in one flat array;
        // "position" for a given interface is implicit (its relative
        // order among OTHER rules of that same interface within that
        // array), there is no explicit 'position' field. So we first
        // collect the FULL-ARRAY indices of rules matching this
        // interface (in their current relative order), find the target
        // rule's slot within that filtered list, then swap with its
        // up/down neighbor's full-array index - this way, rules
        // belonging to OTHER interfaces interleaved in the same JSON
        // array are never disturbed.
        "firewall.custom_rules.reorder" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("");
            if direction != "up" && direction != "down" {
                return Err(("INVALID_PARAMS".to_string(), "direction must be 'up' or 'down'".to_string()));
            }

            let mut data = load_custom_rules();
            let Some(target) = data.rules.iter().find(|r| r.id == id).cloned() else {
                return Err(("NOT_FOUND".to_string(), format!("Rule id '{id}' not found")));
            };

            let same_iface_indices: Vec<usize> = data
                .rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.interface == target.interface)
                .map(|(i, _)| i)
                .collect();

            let Some(slot) = same_iface_indices.iter().position(|&i| data.rules[i].id == id) else {
                return Err(("INTERNAL_ERROR".to_string(), "Failed to find rule position".to_string()));
            };

            let neighbor_slot = if direction == "up" {
                if slot == 0 {
                    return Err(("INVALID_PARAMS".to_string(), "Rule is already at the top".to_string()));
                }
                slot - 1
            } else {
                if slot + 1 >= same_iface_indices.len() {
                    return Err(("INVALID_PARAMS".to_string(), "Rule is already at the bottom".to_string()));
                }
                slot + 1
            };

            data.rules.swap(same_iface_indices[slot], same_iface_indices[neighbor_slot]);
            save_custom_rules(&data).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;

            let targets: Vec<String> = if let Some(name) = &target.zone_group {
                load_zone_groups().groups.iter().find(|g| &g.name == name).map(|g| g.member_interfaces.clone()).unwrap_or_default()
            } else {
                vec![target.interface.clone()]
            };
            if target.floating {
                regenerate_floating_rules().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            } else {
                for iface in &targets {
                    regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface)).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
                }
            }

            Ok(serde_json::json!({ "reordered": id }))
        }
        "firewall.get_log" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(500) as usize;
            let source_filter = params.get("source_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let dest_filter = params.get("dest_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let action_filter = params.get("action_filter").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let interface_filter = params.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut entries = get_pflog_entries(limit.max(2000));
            if !source_filter.is_empty() {
                entries.retain(|e| e.source.contains(&source_filter));
            }
            if !dest_filter.is_empty() {
                entries.retain(|e| e.destination.contains(&dest_filter));
            }
            if !action_filter.is_empty() {
                entries.retain(|e| e.action == action_filter);
            }
            if !interface_filter.is_empty() {
                entries.retain(|e| e.interface == interface_filter);
            }
            let start = entries.len().saturating_sub(limit);
            let entries: Vec<&FirewallLogEntry> = entries[start..].iter().collect();
            Ok(serde_json::json!({ "entries": entries }))
        }
        "system.dns_status" => {
            Ok(serde_json::json!({ "servers": get_dns_servers() }))
        }
        "system.set_dns_servers" => {
            let servers: Vec<String> = params
                .get("servers")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default();
            match set_dns_servers(&servers) {
                Ok(()) => Ok(serde_json::json!({ "servers": servers })),
                Err(msg) => Err(("INVALID_PARAMS".to_string(), msg)),
            }
        }
        "system.time_status" => {
            let ntp = get_ntp_status();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            Ok(serde_json::json!({
                "unix_time": now,
                "timezone": get_current_timezone(),
                "ntp": ntp,
            }))
        }
        "system.list_timezones" => {
            // RCA permintaan bro: mau picker peta dunia gaya installer
            // Ubuntu/Mint (klik dekat kota, bukan scroll dropdown
            // panjang). Data lintang/bujur AKURAT diambil dari
            // zone1970.tab - file RESMI bawaan tzdata IANA (sudah ada
            // di FreeBSD base, /usr/share/zoneinfo/) - bukan data
            // buatan sendiri yang bisa salah/tidak presisi.
            let raw = fs::read_to_string(format!("{ZONEINFO_DIR}/zone1970.tab"))
                .or_else(|_| fs::read_to_string(format!("{ZONEINFO_DIR}/zone.tab")))
                .unwrap_or_default();
            let mut zones: Vec<serde_json::Value> = vec![serde_json::json!({ "name": "UTC", "lat": 51.48, "lon": 0.0 })];
            for line in raw.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                let cols: Vec<&str> = line.split('\t').collect();
                if cols.len() < 3 {
                    continue;
                }
                let (Some((lat, lon)), tz_name) = (parse_iso6709(cols[1]), cols[2]) else {
                    continue;
                };
                zones.push(serde_json::json!({ "name": tz_name, "lat": lat, "lon": lon }));
            }
            zones.sort_by(|a, b| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")));
            Ok(serde_json::json!({ "timezones": zones }))
        }
        "system.set_timezone" => {
            let tz = params.get("timezone").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match set_timezone(&tz) {
                Ok(()) => Ok(serde_json::json!({ "timezone": tz })),
                Err(msg) => Err(("INVALID_PARAMS".to_string(), msg)),
            }
        }
        "system.set_manual_time" => {
            // Fallback kalau NTP tidak bisa dijangkau (jaringan
            // terisolasi, dst) - matikan ntpd dulu supaya tidak
            // langsung menimpa balik waktu yang baru diset manual
            // (pola sama dengan peringatan resmi FortiGate: "disable
            // NTP before manual time set, atau FortiGate akan
            // override balik").
            let datetime = params.get("datetime").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // FreeBSD date(1) untuk SET waktu butuh format numerik padat
            // [[[[[cc]yy]mm]dd]HH]MM[.ss] - BUKAN "YYYY-MM-DD HH:MM:SS"
            // langsung (itu format tampilan, bukan format input). Parse
            // manual dari input Web UI (datetime-local HTML) ke format
            // yang benar-benar diterima 'date'.
            let digits: String = datetime.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() != 14 {
                return Err((
                    "INVALID_PARAMS".to_string(),
                    "datetime must include full date and time (YYYY-MM-DD HH:MM:SS)".to_string(),
                ));
            }
            let freebsd_format = format!("{}{}", &digits[0..12], format!(".{}", &digits[12..14]));
            let _ = Command::new("sysrc").arg("ntpd_enable=NO").status();
            let _ = Command::new("service").arg("ntpd").arg("stop").status();
            let status = Command::new("date").arg(&freebsd_format).status();
            match status {
                Ok(s) if s.success() => Ok(serde_json::json!({ "set": true, "note": "NTP disabled - re-enable it once network/DNS is reachable again." })),
                _ => Err(("INTERNAL_ERROR".to_string(), "Failed to set system time - check the format (YYYY-MM-DD HH:MM:SS)".to_string())),
            }
        }
        "system.enable_ntp" => {
            ensure_ntp_configured();
            Ok(serde_json::json!({ "enabled": true }))
        }
        "system.get_dashboard_info" => {
            // Dashboard - System Information widget. Setiap sub-fungsi
            // defensif (lihat komentar masing-masing di atas) - kalau
            // satu gagal parse, field itu jadi null/"-" di response,
            // BUKAN membuat seluruh action gagal. Dashboard tetap
            // berguna walau satu statistik tidak terbaca.
            let hostname = get_hostname();
            let freebsd_version = get_freebsd_version();
            let (uptime_str, load_avg) = get_uptime_and_load();
            // Satu snapshot 'top' dipakai bersama CPU/Memory/Swap - lihat
            // get_top_snapshot() untuk alasan refactor ini (sebelumnya
            // top dipanggil 2x terpisah, tidak perlu).
            let top_text = get_top_snapshot();
            let cpu_pct = top_text.as_deref().and_then(parse_cpu_usage_pct);
            let mem = top_text.as_deref().and_then(parse_memory_usage);
            let swap = top_text.as_deref().and_then(parse_swap_usage);
            let disks: Vec<serde_json::Value> = get_disk_usage()
                .into_iter()
                .map(|d| serde_json::json!({
                    "mount": d.mount, "used": d.used, "size": d.size, "pct": d.pct,
                }))
                .collect();
            // Permintaan user - Dashboard tampilkan model CPU, jumlah
            // core, dan load per-core (bukan cuma agregat).
            let cpu_model = get_cpu_model();
            let cpu_cores = get_cpu_core_count();
            let cpu_per_core: Vec<serde_json::Value> = top_text
                .as_deref()
                .map(parse_percpu_usage)
                .unwrap_or_default()
                .into_iter()
                .map(|(core, pct)| serde_json::json!({ "core": core, "usage_pct": pct }))
                .collect();

            Ok(serde_json::json!({
                "hostname": hostname,
                "freebsd_version": freebsd_version,
                "uptime": uptime_str,
                "load_avg": load_avg,
                "cpu_usage_pct": cpu_pct,
                "cpu_model": cpu_model,
                "cpu_cores": cpu_cores,
                "cpu_per_core": cpu_per_core,
                "memory": mem.map(|(used, total)| serde_json::json!({
                    "used_bytes": used, "total_bytes": total,
                })),
                "swap": swap.map(|(used, total)| serde_json::json!({
                    "used_bytes": used, "total_bytes": total,
                })),
                "disks": disks,
            }))
        }
        "network.get_interface_traffic" => {
            // Traffic Graphs widget - byte counter KUMULATIF, bukan rate.
            // JS di sisi client hitung selisih antar polling untuk dapat
            // kbps sendiri (lihat get_interface_traffic_bytes() untuk
            // alasan desain ini). timestamp_ms disertakan supaya JS bisa
            // hitung elapsed time SEBENARNYA antar sample (bukan asumsi
            // persis sama dengan interval polling yang diminta - timing
            // JS/network tidak pernah presisi sempurna).
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let stats = get_interface_traffic_bytes();
            let interfaces: serde_json::Map<String, serde_json::Value> = stats
                .into_iter()
                .map(|(iface, (rx, tx))| {
                    (iface, serde_json::json!({ "rx_bytes": rx, "tx_bytes": tx }))
                })
                .collect();
            Ok(serde_json::json!({
                "timestamp_ms": now_ms,
                "interfaces": interfaces,
            }))
        }
        "system.get_log" => {
            // Satu action generik untuk semua tab System Log Viewer yang
            // cuma perlu tail file teks biasa (bukan pflog binary, yang
            // sudah punya action sendiri firewall.get_log; dan bukan
            // Security/IPsec yang sudah punya action sendiri
            // security.get_alerts/ipsec.get_log - direuse dari Web UI,
            // bukan diduplikasi di sini).
            let source = params.get("source").and_then(|v| v.as_str()).unwrap_or("general");
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(500) as usize;

            // RCA (ditemukan nyata - tab OS Boot selalu kosong): asumsi
            // awal /var/log/dmesg.boot SALAH - file itu tidak ada sama
            // sekali di sistem ini (rc.d/dmesg belum tentu aktif di
            // instalasi minimal). Fix: jalankan command 'dmesg' langsung
            // (baca ring buffer kernel real-time via syscall, TIDAK
            // butuh file apa pun) - lebih robust daripada bergantung
            // pada file yang keberadaannya tidak terjamin.
            if source == "os_boot" {
                let output = Command::new("/sbin/dmesg").output();
                let lines: Vec<String> = match output {
                    Ok(o) => {
                        let text = String::from_utf8_lossy(&o.stdout).to_string();
                        let mut all_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                        let start = all_lines.len().saturating_sub(limit);
                        all_lines.split_off(start)
                    }
                    Err(_) => Vec::new(),
                };
                let parsed = parse_syslog_style_lines(&lines);
                return Ok(serde_json::json!({ "source": source, "path": "dmesg (kernel ring buffer)", "lines": lines, "parsed": parsed }));
            }

            // Proxy dan GUI Service - format access log terstruktur,
            // parser KHUSUS (kolom sungguhan: IP/method/URL/status/size),
            // bukan parser generik timestamp+message seperti 5 sumber
            // lainnya - lihat komentar di parse_squid_access_line()/
            // parse_lighttpd_access_line().
            if source == "proxy" {
                let lines = tail_log_file("/var/log/squid/access.log", limit);
                let parsed: Vec<proxy::SquidLogEntry> = lines.iter().filter_map(|l| proxy::parse_squid_access_line(l)).collect();
                return Ok(serde_json::json!({ "source": source, "path": "/var/log/squid/access.log", "lines": lines, "parsed": parsed }));
            }
            if source == "gui_service" {
                let lines = tail_log_file("/var/log/lighttpd/access.log", limit);
                let parsed: Vec<LighttpdLogEntry> = lines.iter().filter_map(|l| parse_lighttpd_access_line(l)).collect();
                return Ok(serde_json::json!({ "source": source, "path": "/var/log/lighttpd/access.log", "lines": lines, "parsed": parsed }));
            }

            let path = match source {
                "general" => "/var/log/messages",
                "dhcp" => "/var/log/kea/kea-dhcp4.log",
                "watchdog" => WATCHDOG_LOG,
                "maintenance" => MAINTENANCE_LOG,
                "openvpn" => openvpn::OPENVPN_LOG,
                other => {
                    return Err((
                        "INVALID_PARAMS".to_string(),
                        format!("Unknown log source '{other}' - valid: general, os_boot, dhcp, proxy, gui_service, watchdog, maintenance, openvpn"),
                    ));
                }
            };
            let lines = tail_log_file(path, limit);
            let parsed = parse_syslog_style_lines(&lines);
            Ok(serde_json::json!({ "source": source, "path": path, "lines": lines, "parsed": parsed }))
        }
        "freeradius.get_config" => {
            let installed = std::path::Path::new("/usr/local/sbin/radiusd").exists();
            let cfg = load_freeradius_config();
            Ok(serde_json::json!({ "installed": installed, "config": cfg }))
        }
        "freeradius.set_config" => {
            if !std::path::Path::new("/usr/local/sbin/radiusd").exists() {
                return Err(("INTERNAL_ERROR".to_string(), "FreeRADIUS is not installed - install 'freeradius3' first from Package Manager".to_string()));
            }
            let mut cfg = load_freeradius_config();
            cfg.enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            save_freeradius_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_freeradius_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "config": cfg }))
        }
        "freeradius.client_list" => {
            Ok(serde_json::json!({ "clients": load_freeradius_config().clients }))
        }
        "freeradius.client_add" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let ip_cidr = params.get("ip_cidr").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let secret = params.get("secret").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if name.is_empty() || ip_cidr.is_empty() || secret.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "name, ip_cidr, and secret are all required".to_string()));
            }
            if secret.len() < 8 {
                return Err(("INVALID_PARAMS".to_string(), "Shared secret must be at least 8 characters.".to_string()));
            }
            if secret.contains('"') {
                return Err(("INVALID_PARAMS".to_string(), "Shared secret cannot contain a double-quote character - many RADIUS client implementations mishandle special characters in shared secrets.".to_string()));
            }
            let mut cfg = load_freeradius_config();
            if cfg.clients.iter().any(|c| c.name.eq_ignore_ascii_case(&name)) {
                return Err(("INVALID_PARAMS".to_string(), format!("A NAS/Client named '{name}' already exists.")));
            }
            let client = RadiusClient {
                id: format!("rc{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                name, ip_cidr, secret, description,
            };
            cfg.clients.push(client.clone());
            save_freeradius_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_freeradius_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "client": client }))
        }
        "freeradius.client_delete" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut cfg = load_freeradius_config();
            let before = cfg.clients.len();
            cfg.clients.retain(|c| c.id != id);
            if cfg.clients.len() == before {
                return Err(("NOT_FOUND".to_string(), format!("Client id '{id}' not found")));
            }
            save_freeradius_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_freeradius_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "deleted": id }))
        }
        "freeradius.user_list" => {
            let users: Vec<serde_json::Value> = load_freeradius_config().users.iter().map(|u| {
                serde_json::json!({ "id": u.id, "username": u.username, "description": u.description })
            }).collect();
            Ok(serde_json::json!({ "users": users }))
        }
        "freeradius.user_add" => {
            let username = params.get("username").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let password = params.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if username.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "Username cannot be empty.".to_string()));
            }
            if password.len() < 8 {
                return Err(("INVALID_PARAMS".to_string(), "Password must be at least 8 characters.".to_string()));
            }
            if password.contains('"') {
                return Err(("INVALID_PARAMS".to_string(), "Password cannot contain a double-quote character.".to_string()));
            }
            let mut cfg = load_freeradius_config();
            if cfg.users.iter().any(|u| u.username.eq_ignore_ascii_case(&username)) {
                return Err(("INVALID_PARAMS".to_string(), format!("User '{username}' already exists.")));
            }
            let user = RadiusUser {
                id: format!("ru{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)),
                username, password, description,
            };
            cfg.users.push(user.clone());
            save_freeradius_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_freeradius_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "user": { "id": user.id, "username": user.username, "description": user.description } }))
        }
        "freeradius.user_delete" => {
            let id = params.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut cfg = load_freeradius_config();
            let before = cfg.users.len();
            cfg.users.retain(|u| u.id != id);
            if cfg.users.len() == before {
                return Err(("NOT_FOUND".to_string(), format!("User id '{id}' not found")));
            }
            save_freeradius_config(&cfg).map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            apply_freeradius_conf().map_err(|e| ("INTERNAL_ERROR".to_string(), e))?;
            Ok(serde_json::json!({ "deleted": id }))
        }
        "freeradius.get_status" => {
            let installed = std::path::Path::new("/usr/local/sbin/radiusd").exists();
            if !installed {
                return Ok(serde_json::json!({ "installed": false, "running": false }));
            }
            let running = Command::new("pgrep").arg("-x").arg("radiusd").output().map(|o| o.status.success() && !o.stdout.is_empty()).unwrap_or(false);
            Ok(serde_json::json!({ "installed": true, "running": running }))
        }
        "freeradius.get_log" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
            let lines = tail_log_file(RADIUS_LOG_FILE, limit);
            let parsed = parse_syslog_style_lines(&lines);
            Ok(serde_json::json!({ "lines": lines, "parsed": parsed }))
        }
        "freeradius.get_auth_log" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(500) as usize;
            let lines = tail_log_file(RADIUS_LOG_FILE, limit.max(1000));
            let mut entries = parse_radius_auth_log(&lines);
            let start = entries.len().saturating_sub(limit);
            entries = entries.split_off(start);
            entries.reverse();
            Ok(serde_json::json!({ "entries": entries }))
        }
        "system.sync_os_password" => {
            let username = params.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let password = params.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if username.is_empty() || password.is_empty() {
                return Err(("INVALID_PARAMS".to_string(), "username and password are required".to_string()));
            }
            // Cek dulu akun OS genuinely ada - kalau user Web UI ini
            // belum pernah disinkronkan via ntpsense-sync-os-accounts.sh,
            // SKIP diam-diam (bukan error) - tidak semua user Web UI
            // otomatis punya akun OS console.
            let user_exists = Command::new("pw").args(["usershow", &username]).output()
                .map(|o| o.status.success()).unwrap_or(false);
            if !user_exists {
                return Ok(serde_json::json!({ "synced": false, "reason": "no matching OS account" }));
            }
            // Pola SAMA PERSIS dengan root recovery token di
            // installerconfig-2eth ('pw usermod root -h 0') - '-h 0'
            // artinya baca password PLAINTEXT dari stdin, pw SENDIRI
            // yang hash pakai format crypt OS yang benar - TIDAK perlu
            // library crypto tambahan sama sekali.
            let mut child = Command::new("pw")
                .args(["usermod", &username, "-h", "0"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to spawn pw: {e}")))?;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(password.as_bytes());
            }
            let output = child.wait_with_output()
                .map_err(|e| ("INTERNAL_ERROR".to_string(), format!("Failed to wait for pw: {e}")))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(("INTERNAL_ERROR".to_string(), format!("'pw usermod -h 0' failed: {stderr}")));
            }
            Ok(serde_json::json!({ "synced": true }))
        }
        _ => Err(("INVALID_ACTION".to_string(), format!("Action '{action}' is not recognized/not allowed"))),
    }
}

fn handle_connection(stream: UnixStream, allowed_gid: Option<u32>) {
    if !is_peer_authorized(&stream, allowed_gid) {
        return;
    }

    let mut reader = BufReader::new(stream.try_clone().expect("gagal clone stream"));
    let mut writer = stream;

    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }

    let response = match serde_json::from_str::<Request>(&line) {
        Ok(req) => match handle_action(&req.action, &req.params) {
            Ok(data) => Response::ok(req.request_id, data),
            Err((code, message)) => Response::error(req.request_id, &code, &message),
        },
        Err(e) => Response::error("unknown".to_string(), "INVALID_REQUEST", &format!("Invalid JSON: {e}")),
    };

    if let Ok(mut body) = serde_json::to_string(&response) {
        body.push('\n');
        let _ = writer.write_all(body.as_bytes());
    }
}

fn main() {
    // Jalur KHUSUS untuk cron (dipicu /etc/cron.d/ntpsense-blocklist
    // harian) - jalankan update blocklist LANGSUNG lalu keluar, TANPA
    // bind socket sama sekali. Cron jalan sebagai root secara native,
    // tidak perlu lewat autentikasi peer-credential socket - binary
    // yang sama dipakai baik sebagai daemon persisten (default) MAUPUN
    // sebagai perintah sekali-jalan (dengan flag ini), supaya logic
    // download tetap SATU sumber kebenaran (run_blocklist_update()),
    // tidak ada helper script terpisah yang bisa tidak sinkron.
    if std::env::args().nth(1).as_deref() == Some("--cron-blocklist-update") {
        let (updated, failed) = proxy::run_blocklist_update();
        println!("ntpsense-blocklist cron: updated={updated:?} failed={failed:?}");
        std::process::exit(if failed.is_empty() { 0 } else { 1 });
    }

    // Threat Intelligence cron - pola PERSIS sama dengan
    // --cron-blocklist-update di atas: binary yang sama dipakai
    // sebagai perintah sekali-jalan lewat cron (root langsung, tanpa
    // socket), logic download tetap SATU sumber kebenaran
    // (threat_intel::run_threat_intel_update()). Setelah fetch+parse
    // sukses (yang sudah termasuk 'pfctl -T replace' di dalam fungsi
    // itu sendiri), TIDAK perlu regenerate_threat_intel_pf() lagi di
    // sini - itu cuma untuk marker+struktur pf.conf (jarang berubah),
    // bukan isi table (yang diurus fetch function sendiri).

    // Proxy history archive - cron harian (permintaan bro: Log Viewer +
    // Bandwidth Usage historis, retensi admin-configurable maks 180
    // hari). Pola SAMA persis dengan dua cron di atas - binary yang
    // sama, root langsung tanpa socket. Dijalankan idealnya larut
    // malam (installer daftarkan 00:30, offset dari cron Threat Intel
    // 03:15/Squid Blocklist 03:00 supaya tidak semua proses berat
    // numpuk di jam yang sama).
    if std::env::args().nth(1).as_deref() == Some("--cron-proxy-archive-daily") {
        let result = proxy::run_daily_archive();
        println!("ntpsense-proxy-archive cron: {result}");
        std::process::exit(0);
    }

    // Tulis version stamp ke file SETIAP kali daemon start - cek instan
    // via 'cat /var/run/ntpsense-configd.version', tanpa perlu menebak
    // dari perilaku action (yang bisa salah tafsir kalau binary basi).
    let _ = fs::write("/var/run/ntpsense-configd.version", format!("{VERSION}\n"));

    if Path::new(SOCKET_PATH).exists() {
        let _ = fs::remove_file(SOCKET_PATH);
    }

    let listener = UnixListener::bind(SOCKET_PATH).unwrap_or_else(|e| {
        eprintln!("FATAL: gagal bind socket {SOCKET_PATH}: {e}");
        std::process::exit(1);
    });

    let _ = fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660));
    let _ = Command::new("chown").arg(format!("root:{ALLOWED_GROUP}")).arg(SOCKET_PATH).status();

    let allowed_gid = resolve_group_gid(ALLOWED_GROUP);
    if allowed_gid.is_none() {
        eprintln!("PERINGATAN: grup '{ALLOWED_GROUP}' tidak ditemukan - HANYA root yang akan diizinkan connect");
    }

    // RCA KRITIS (ditemukan dari diagnosa langsung di VM user - pfctl -s
    // rules KOSONG padahal /etc/pf.conf di disk MASIH LENGKAP BENAR):
    // startup daemon SEBELUM fix ini cuma reaktif - re-apply custom rule
    // per-interface HANYA KALAU ada custom rule tersimpan untuk interface
    // itu. Kalau kernel pf sempat ke-reset (reboot, pfctl -F manual, atau
    // sebab lain) DAN tidak ada satu pun custom rule tersimpan saat itu,
    // TIDAK ADA jalur kode yang pernah panggil 'pfctl -f /etc/pf.conf'
    // secara PENUH - rule sistem (anti-lockout MGMT, isolasi OPT, dst)
    // yang seharusnya SELALU ada, tidak pernah termuat ulang ke kernel.
    // Fix: paksa reload PENUH dan TANPA SYARAT di awal startup, SEBELUM
    // splice custom rule per-interface - supaya kernel state SELALU
    // dipaksa sinkron dengan file di disk setiap kali daemon start,
    // apa pun penyebab sebelumnya kernel state bisa jadi kosong.
    // NTP - dipasang PALING AWAL di startup reapply (sebelum pf
    // sekalipun) karena begitu banyak hal lain bergantung ke jam yang
    // akurat: sertifikat TLS, log timestamp, DAN 2FA TOTP (gap nyata
    // yang ditemukan bro - installer selama ini TIDAK PERNAH benar-
    // benar mengaktifkan ntpd meski nama produk ini "NTPSense").
    ensure_ntp_configured();
    let _ = Command::new("kldload").arg("pf").status();
    let _ = Command::new("pfctl").arg("-e").status();
    match Command::new("pfctl").arg("-f").arg("/etc/pf.conf").status() {
        Ok(s) if s.success() => println!("Startup: /etc/pf.conf reloaded penuh ke kernel"),
        _ => eprintln!("PERINGATAN: gagal reload penuh /etc/pf.conf saat startup - ruleset kernel mungkin tidak sinkron dengan file"),
    }

    // pf.conf di-generate ULANG BERSIH tiap boot oleh install-gateway-v2.sh
    // (marker custom rule selalu kosong di titik itu) - jadi custom rule
    // yang tersimpan di CUSTOM_RULES_FILE harus di-splice ULANG di sini
    // setiap kali daemon start, supaya rule admin tetap berlaku setelah
    // reboot tanpa perlu re-input manual. Kegagalan splice di titik ini
    // TIDAK menghentikan daemon (cuma warning) - socket tetap harus jalan
    // walau ada satu interface yang gagal re-apply rule-nya. Fase 2:
    // mencakup LAN1/WAN1 juga, bukan cuma OPT (MGMT tetap TIDAK PERNAH
    // disertakan - tidak ada marker untuknya sama sekali by design).
    let (lan1_if, wan1_if, opt_ifaces) = parse_pf_conf_zones();
    let mut startup_ifaces = opt_ifaces;
    if let Some(l) = lan1_if {
        startup_ifaces.push(l);
    }
    if let Some(w) = wan1_if {
        startup_ifaces.push(w);
    }
    for iface in &startup_ifaces {
        // TIDAK ADA lagi guard "skip kalau individual rule kosong" -
        // interface bisa saja tidak punya rule individual sendiri TAPI
        // masih anggota Zone Group yang punya rule di tab grupnya -
        // guard lama akan salah lewatkan kasus itu.
        if let Err(e) = regenerate_pf_conf_for_interface(iface, &effective_rules_for_interface(iface)) {
            eprintln!("PERINGATAN: gagal re-apply custom rule untuk {iface} saat startup: {e}");
        }
    }

    // Re-apply port yang SENGAJA di-disable admin - fresh boot selalu
    // membawa semua interface UP dulu (via install-gateway-v2.sh), jadi
    // status "administratively down" perlu di-reapply di sini supaya
    // konsisten dengan yang tersimpan sebelumnya. MGMT TIDAK PERNAH ikut
    // proses ini (validasi network.set_port_status sudah menolak MGMT
    // di-disable dari awal, jadi seharusnya tidak akan pernah muncul di
    // file ini sebagai false - tapi tetap di-skip eksplisit di sini
    // sebagai defense in depth kalau file pernah diedit manual).
    let port_status = load_port_status();
    let startup_mgmt_if = fs::read_to_string(MGMT_LOCK_FILE).ok().map(|s| s.trim().to_string());
    for (iface, enabled) in &port_status {
        if !enabled && startup_mgmt_if.as_deref() != Some(iface.as_str()) {
            let _ = Command::new("ifconfig").arg(iface).arg("down").status();
        }
    }

    // RCA (ditemukan dari test user - fix pf routing WireGuard TIDAK
    // ter-apply walau binary baru sudah jalan): sebelum ini,
    // apply_wireguard_conf()/regenerate_kea_config()/apply_squid_conf()
    // CUMA dipanggil dari dalam action (reaktif, perlu admin sentuh
    // halaman terkait dulu) - PERSIS pola bug yang sama dengan RCA
    // pf.conf startup sebelumnya (daemon restart TIDAK otomatis
    // mereapply apa pun yang bukan pf custom-rules/port-status). Fix:
    // reapply ketiganya SECARA TIDAK BERSYARAT di startup juga (kalau
    // paket terkait terinstall) - konsisten prinsip "startup harus
    // selalu reapply, bukan cuma reaktif" yang sudah kita tetapkan.
    // Kegagalan di titik ini TIDAK menghentikan daemon (cuma warning).
    // FIX (ditemukan dari test user - Web UI timeout 15s total pas
    // startup, "Tidak terjangkau" di semua halaman): sebelum fix ini,
    // 4 reapply service (WireGuard/Squid/Kea/Suricata) di atas dijalankan
    // SECARA BERURUTAN DAN BLOCKING sebelum listener.incoming() sempat
    // mulai menerima koneksi sama sekali - socket sudah ter-bind lebih
    // awal (baris atas), TAPI tidak ada yang accept() koneksi masuk
    // selama rantai reapply belum selesai. Squid sendiri sudah lama
    // dikenal makan 2-3 menit (re-parse blocklist besar saat startup -
    // lihat catatan lama), dan penambahan Suricata di ujung rantai
    // membuat total waktu sebelum socket mulai menjawab jadi jauh
    // melebihi timeout klien PHP (15s) - BUKAN masalah permission atau
    // Suricata secara spesifik, murni total durasi startup yang membengkak.
    // Fix: pindahkan KEEMPAT reapply lambat ini ke thread terpisah,
    // dijalankan PARALEL dengan accept loop di bawah (bukan sebelum) -
    // Web UI sekarang responsif segera setelah socket ter-bind, sementara
    // service-service itu tetap reapply di background seperti biasa.
    // Langkah pf.conf/custom-rules/port-status di ATAS TETAP synchronous
    // (cepat, cuma file+pfctl, tidak ada restart service lambat).
    thread::spawn(|| {
        if std::path::Path::new("/usr/local/bin/wg").exists() {
            if let Err(e) = apply_wireguard_conf() {
                eprintln!("PERINGATAN: gagal re-apply WireGuard saat startup: {e}");
            }
        }
        if std::path::Path::new("/usr/local/sbin/squid").exists() {
            if let Err(e) = proxy::apply_squid_conf() {
                eprintln!("PERINGATAN: gagal re-apply Squid saat startup: {e}");
            }
        }
        if std::path::Path::new("/usr/local/sbin/kea-dhcp4").exists() {
            if let Err(e) = regenerate_kea_config() {
                eprintln!("PERINGATAN: gagal re-apply Kea DHCP saat startup: {e}");
            }
        }
        if std::path::Path::new(security::SURICATA_BIN).exists() {
            if let Err(e) = security::apply_security_conf(&security::load_security_config()) {
                eprintln!("WARNING: failed to re-apply Security/Suricata at startup: {e}");
            }
        }
        if std::path::Path::new("/usr/local/sbin/swanctl").exists() || std::path::Path::new("/usr/local/bin/swanctl").exists() {
            if let Err(e) = apply_ipsec_conf() {
                eprintln!("PERINGATAN: gagal re-apply IPsec saat startup: {e}");
            }
        }
        // RCA (ditemukan nyata - fix keyword 'log' tidak muncul di rule
        // custom yang sudah tersimpan sampai daemon di-restart DAN
        // sesuatu memicu regenerasi manual): custom rules Firewall
        // TIDAK PERNAH punya startup-reapply sendiri, beda dari semua
        // service lain di atas - rule yang sudah tersimpan di pf.conf
        // sebelum sebuah perubahan kode (seperti fix 'log' ini) tetap
        // dalam bentuk LAMA sampai admin eksplisit edit/reorder rule
        // itu. Ini melanggar prinsip project sendiri ("startup reapply
        // wajib untuk semua config yang bisa basi") - fix: regenerate
        // SEMUA interface yang punya custom rule tersimpan, setiap kali
        // daemon start, sama seperti service lain.
        let all_rules = load_custom_rules().rules;
        let all_groups = load_zone_groups().groups;
        let mut interfaces_with_rules: std::collections::HashSet<String> = std::collections::HashSet::new();
        for r in &all_rules {
            if r.zone_group.is_none() {
                interfaces_with_rules.insert(r.interface.clone());
            }
        }
        // Rule grup menyimpan NAMA GRUP di 'interface' (untuk tampilan),
        // BUKAN interface fisik - resolve ke SEMUA anggota fisik grup
        // itu, sama seperti fix restore-backup (RCA yang sama persis).
        for group in &all_groups {
            for member in &group.member_interfaces {
                interfaces_with_rules.insert(member.clone());
            }
        }
        for iface in interfaces_with_rules {
            if let Err(e) = regenerate_pf_conf_for_interface(&iface, &effective_rules_for_interface(&iface)) {
                eprintln!("PERINGATAN: gagal re-apply Firewall custom rules untuk {iface} saat startup: {e}");
            }
        }
        // Floating Rules - reapply tanpa syarat, pola sama dengan semua
        // fitur lain di startup ini: marker pf.conf + isi rule-nya bisa
        // basi setelah restart daemon kalau tidak di-generate ulang di
        // sini, tidak menunggu admin buka tab Firewall > Floating dulu.
        if load_custom_rules().rules.iter().any(|r| r.floating) {
            if let Err(e) = regenerate_floating_rules() {
                eprintln!("PERINGATAN: gagal re-apply Floating Rules saat startup: {e}");
            }
        }
        // Bandwidth Limiter (QoS) - sama alasannya dengan Firewall custom
        // rules di atas: modul kernel 'dummynet' TIDAK persisten sendiri
        // tanpa kldload eksplisit tiap boot (RCA baru, ditemukan dari
        // error nyata 'dnctl -f failed' pas admin pertama kali coba
        // bikin limiter) - reapply tanpa syarat di sini memastikan pipe
        // sudah terkonfigurasi ulang begitu daemon start, tidak menunggu
        // admin buka halaman Bandwidth Limiters dulu.
        if !load_limiters().limiters.is_empty() {
            if let Err(e) = regenerate_dnctl_conf() {
                eprintln!("WARNING: failed to re-apply Bandwidth Limiters (dnctl) at startup: {e}");
            }
        }
        // Daftarkan rotasi log route-ops ke newsyslog - idempotent,
        // aman dipanggil tiap startup terlepas ada gateway atau tidak
        // (permintaan bro: jangan dibuang, simpan 90 hari lewat tool
        // rotasi bawaan FreeBSD, bukan reimplementasi sendiri).
        multiwan::ensure_route_log_rotation();
        // Multi-WAN - NAT per-uplink dan system default gateway keduanya
        // WAJIB direapply tanpa syarat di startup, pola sama dengan
        // semua service lain di atas (RCA project ini yang berulang:
        // config yang cuma di-apply reaktif akan basi begitu daemon
        // restart/reboot terjadi tanpa admin menyentuh halaman terkait).
        if !multiwan::list_gateways().is_empty() {
            if let Err(e) = multiwan::regenerate_outbound_nat() {
                eprintln!("WARNING: failed to re-apply Multi-WAN outbound NAT at startup: {e}");
            }
            // Host-route untuk Monitor IP custom (kalau ada) dipasang
            // SEBELUM cycle monitoring pertama - tanpa ini, ping ke
            // Monitor IP di luar subnet lokal gateway akan gagal
            // "Network is down" persis seperti RCA yang ditemukan bro
            // lewat test manual (lihat komentar sync_monitor_route()).
            multiwan::reapply_monitor_routes();
            // Cycle monitoring pertama dijalankan SYNCHRONOUS di sini
            // (bukan menunggu loop background) supaya status gateway
            // sudah diketahui SEBELUM system default gateway diterapkan -
            // menghindari kondisi "system default diset ke gateway yang
            // ternyata sudah mati" tepat di detik pertama daemon hidup.
            multiwan::run_monitor_cycle();
            if let Err(e) = multiwan::apply_system_default_gateway() {
                eprintln!("WARNING: failed to apply Multi-WAN system default gateway at startup: {e}");
            }
        }
        println!("Background startup reapply (WireGuard/Squid/Kea/Suricata/IPsec/Firewall/dnctl/MultiWAN) done");
    });

    // Multi-WAN health monitor - thread TERPISAH dan PERSISTEN (loop
    // selamanya, beda dari thread reapply-sekali di atas). RCA pfSense
    // #11570 sengaja dihindari sejak desain: SEMUA gateway dicek TANPA
    // SYARAT tiap cycle lewat run_monitor_cycle() sendiri, terlepas
    // status aktif/tidaknya - supaya failback selalu terdeteksi andal,
    // bukan cuma failover-nya saja yang jalan.
    thread::spawn(|| loop {
        // Interval dimuat ULANG tiap iterasi (bukan sekali di awal) -
        // perubahan setting dari Web UI langsung berlaku di sleep
        // BERIKUTNYA, tanpa perlu restart daemon.
        let interval = multiwan::load_settings().interval_secs;
        thread::sleep(std::time::Duration::from_secs(interval));
        if multiwan::list_gateways().is_empty() {
            continue;
        }
        let transitioned = multiwan::run_monitor_cycle();
        // SD-WAN quality-routing (roadmap) - RCA ditemukan bro langsung
        // (grup di-set ke "quality", kedua ISP skornya berimbang, TAPI
        // route-to tetap satu gateway sampai daemon di-restart penuh):
        // any_transition SENDIRI cuma true kalau ada gateway benar-benar
        // Up<->Down - skor kualitas yang bergeser wajar tiap cycle
        // TANPA transisi apa pun sebelumnya TIDAK PERNAH memicu
        // regenerasi pf.conf sama sekali. OR-kan dengan sinyal terpisah
        // ini supaya perubahan komposisi round-robin quality-mode JUGA
        // memicu blok reapply yang sama di bawah - kalau tidak,
        // "quality routing" cuma snapshot sekali saat Save, bukan
        // adaptasi berkelanjutan yang jadi esensi SD-WAN itu sendiri.
        let quality_shifted = multiwan::quality_selection_changed();
        if transitioned || quality_shifted {
            // Status berubah - regenerasi SEMUA yang mungkin terpengaruh:
            // (1) rule Firewall mana pun yang pakai Gateway Group (route-to
            // target-nya bisa saja berubah), (2) system default gateway
            // kalau grup yang berubah itu kebetulan system default saat ini.
            let all_rules = load_custom_rules().rules;
            let all_groups = load_zone_groups().groups;
            let mut ifaces_with_gw_group: std::collections::HashSet<String> = std::collections::HashSet::new();
            for r in all_rules.iter().filter(|r| r.gateway_group_name.is_some()) {
                match &r.zone_group {
                    // Rule Multi-WAN yang JUGA berada di tab Zone Group -
                    // resolve ke semua anggota fisik grup itu, sama
                    // dengan RCA di titik-titik lain (interface di sini
                    // isinya nama grup, bukan interface fisik).
                    Some(gname) => {
                        if let Some(g) = all_groups.iter().find(|g| &g.name == gname) {
                            for m in &g.member_interfaces {
                                ifaces_with_gw_group.insert(m.clone());
                            }
                        }
                    }
                    None => {
                        ifaces_with_gw_group.insert(r.interface.clone());
                    }
                }
            }
            for iface in ifaces_with_gw_group {
                if let Err(e) = regenerate_pf_conf_for_interface(&iface, &effective_rules_for_interface(&iface)) {
                    eprintln!("WARNING: failed to re-apply route-to for {iface} after gateway status change: {e}");
                }
            }
            if let Err(e) = multiwan::apply_system_default_gateway() {
                eprintln!("WARNING: failed to apply system default gateway after status change: {e}");
            }
        }
    });



    println!("ntpsense-configd listening on {SOCKET_PATH}");
    let _ = std::io::stdout().flush();

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let _ = stream.as_raw_fd(); // sentuh sekali supaya import AsRawFd terpakai jelas
                thread::spawn(move || handle_connection(stream, allowed_gid));
            }
            Err(e) => eprintln!("gagal accept koneksi: {e}"),
        }
    }
}
