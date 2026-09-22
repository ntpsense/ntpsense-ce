<?php
declare(strict_types=1);
require_once __DIR__ . '/NtpsenseConfigd.php';
/**
 * PackageCatalog - katalog plugin NTPSense Tier 2.
 *
 * KEPUTUSAN ARSITEKTUR (didiskusikan dengan user): repo pkg custom kita
 * sendiri (ntpsense.conf) TETAP disimpan untuk masa depan (plugin yang
 * BUKAN paket FreeBSD standar), TAPI untuk paket yang memang tersedia
 * di repo resmi FreeBSD (Squid, dst), kita install LANGSUNG dari sana -
 * tidak perlu menunggu server hosting repo custom kita online. Install
 * button sekarang BENERAN FUNGSIONAL untuk paket-paket ini (bukan lagi
 * "menunggu repo", lihat package-manager.php).
 *
 * CATATAN (entri 'pfblockerng' DIHAPUS dari katalog ini): sempat ada di
 * sini sejak sesi lama, tapi ternyata BUKAN package FreeBSD asli sama
 * sekali - pfBlockerNG adalah paket khusus pfSense sendiri, tidak
 * pernah dipublikasikan di repo `pkg` resmi FreeBSD di luar pfSense.
 * Tombol "Install" untuk entri ini akan SELALU gagal kalau diklik.
 * Fungsinya sendiri (IP reputation blocking) sudah tergantikan penuh
 * oleh fitur native Threat Intelligence (Spamhaus DROP + FireHOL,
 * lihat threat_intel.rs) - genuinely FreeBSD-native dan sudah
 * tervalidasi jalan, bukan sekadar "belum sempat" tapi memang sudah
 * ada penggantinya yang lebih tepat. Dihapus dari katalog di sini
 * SEKALIGUS dari daftar ALLOWED_PACKAGES di main.rs (sudah dilakukan
 * sesi sebelumnya) - keduanya harus tetap sinkron.
 */
final class PackageCatalog
{
    /** @return array<string, array{category:string, description:string, icon:string}> */
    public static function knownPackages(): array
    {
        return [
            'squid' => [
                'category' => 'Proxy',
                'description' => 'High-performance HTTP/HTTPS caching proxy.',
                'icon' => 'ti-server-2',
            ],
            'suricata' => [
                'category' => 'Security',
                'description' => 'Signature-based intrusion detection and prevention.',
                'icon' => 'ti-shield-search',
            ],
            'wireguard-tools' => [
                'category' => 'VPN',
                'description' => 'Modern, lightweight, and fast VPN.',
                'icon' => 'ti-lock-access',
            ],
            'tailscale' => [
                'category' => 'VPN',
                'description' => 'Client used by Site Mesh VPN - required on every gateway (HQ and branches) for the self-hosted full-mesh tunnel.',
                'icon' => 'ti-topology-star-3',
            ],
            'strongswan' => [
                'category' => 'VPN',
                'description' => 'IPsec/IKEv2 site-to-site VPN. Industry-standard, interoperable with pfSense, FortiGate, Palo Alto, and Cisco.',
                'icon' => 'ti-shield-lock',
            ],
            'freeradius3' => [
                'category' => 'Services',
                'description' => 'RADIUS authentication server for enterprise WiFi/VPN.',
                'icon' => 'ti-key',
            ],
            // Ditambahkan mendukung System > Authentication (RADIUS/LDAP
            // client - Tahap 1 roadmap, lihat ExternalAuth.php) - paket
            // ini menyediakan 'ldapwhoami'/'ldapsearch' yang dipakai
            // untuk verifikasi bind LDAP. BEDA kategori dari
            // 'freeradius3' di atas secara peran (client vs server -
            // lihat catatan arsitektur di ExternalAuth.php), tapi
            // SENGAJA tetap dikelompokkan 'Services' di sini supaya
            // admin menemukan keduanya berdekatan saat mencari
            // "kebutuhan autentikasi eksternal", bukan tersebar di
            // kategori tak berhubungan.
            'openldap26-client' => [
                'category' => 'Services',
                'description' => 'LDAP client tools (ldapsearch/ldapwhoami) - required for System > Authentication LDAP login.',
                'icon' => 'ti-key',
            ],
        ];
    }
    /**
     * Query status install lewat daemon Rust (privileged) - BUKAN lagi
     * exec() 'pkg' langsung dari PHP-FPM seperti versi awal, yang
     * terbukti SELALU kosong di produksi (kemungkinan besar exec()
     * dibatasi atau akses pkg database ditolak untuk proses non-root
     * 'www') - konsisten prinsip arsitektur proyek: semua operasi
     * privileged (termasuk sekadar query status) lewat daemon, PHP
     * tidak pernah eksekusi command sistem langsung.
     *
     * @return array<string, string> nama-paket => versi
     */
    public static function getInstalledVersions(NtpsenseConfigd $configd): array
    {
        try {
            return $configd->call('package.list_installed');
        } catch (NtpsenseConfigdException $e) {
            return [];
        }
    }
    /**
     * Nama tampilan yang lebih rapi untuk paket tertentu - ucfirst()
     * polos menghasilkan "Wireguard-tools" yang aneh dibaca, jadi ada
     * pemetaan eksplisit untuk kasus semacam ini.
     */
    public static function displayName(string $packageName): string
    {
        $overrides = [
            'wireguard-tools' => 'WireGuard',
            'freeradius3' => 'FreeRADIUS',
            'strongswan' => 'strongSwan (IPsec)',
            'openldap26-client' => 'OpenLDAP Client',
        ];
        return $overrides[$packageName] ?? ucfirst($packageName);
    }
}
