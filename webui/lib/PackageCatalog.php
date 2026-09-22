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
            'openvpn' => [
                'category' => 'VPN',
                'description' => 'Certificate-based SSL VPN - Remote Access and Site-to-Site, TCP/443-friendly.',
                'icon' => 'ti-key',
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
            'openvpn' => 'OpenVPN',
            'freeradius3' => 'FreeRADIUS',
            'strongswan' => 'strongSwan (IPsec)',
        ];
        return $overrides[$packageName] ?? ucfirst($packageName);
    }
}
