<?php
declare(strict_types=1);
/**
 * ExternalAuth - autentikasi admin Web UI via RADIUS atau LDAP eksternal
 * (Tahap 1 dari roadmap RADIUS/LDAP - Tahap 2 lanjut ke autentikasi
 * user OpenVPN).
 *
 * Riset 4 vendor sebelum dibangun (pfSense/FortiGate): pola industrinya
 * SAMA di semua vendor - appliance jadi RADIUS/LDAP CLIENT (autentikasi
 * user-nya SENDIRI ke server eksternal), BUKAN jadi RADIUS server.
 * Server RADIUS/LDAP cuma menjawab "kredensial benar atau tidak" +
 * daftar grup keanggotaan - keputusan ROLE/permission APA yang didapat
 * tetap ditentukan LOKAL lewat mapping grup->role (Roles yang sudah
 * ada di Auth.php, TIDAK diduplikasi di sini).
 *
 * SENGAJA shell out ke 'radclient' (paket freeradius3) dan 'ldapwhoami'/
 * 'ldapsearch' (paket openldap-client) - BUKAN reimplementasi protokol
 * RADIUS (RFC 2865, termasuk obfuscation password MD5+shared-secret)
 * dari nol di PHP. Tools itu sudah matang, teruji luas, dan resmi
 * dipakai vendor SENDIRI untuk testing (pfSense Diagnostics >
 * Authentication reuse mekanisme serupa) - reimplementasi sendiri
 * cuma menambah risiko bug kriptografi tanpa manfaat nyata.
 */
final class ExternalAuth
{
    private const CONFIG_FILE = '/usr/local/etc/ntpsense/webui/external-auth.json';
    private const DEFAULT_CONFIG = [
        'radius_enabled' => false,
        'radius_servers' => [], // [{name, host, port, secret, timeout}]
        'ldap_enabled' => false,
        'ldap_servers' => [],   // [{name, host, port, use_tls, user_dn_template, base_dn, group_attribute}]
        'group_role_map' => [], // [{external_group, local_role}]
    ];
    /** @return array<string, mixed> */
    public static function getConfig(): array
    {
        if (!file_exists(self::CONFIG_FILE)) {
            return self::DEFAULT_CONFIG;
        }
        $data = json_decode((string) file_get_contents(self::CONFIG_FILE), true);
        if (!is_array($data)) {
            return self::DEFAULT_CONFIG;
        }
        return array_merge(self::DEFAULT_CONFIG, $data);
    }
    /** @param array<string, mixed> $config */
    public static function setConfig(array $config): void
    {
        $dir = dirname(self::CONFIG_FILE);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        $clean = array_merge(self::DEFAULT_CONFIG, $config);
        file_put_contents(self::CONFIG_FILE, json_encode($clean, JSON_PRETTY_PRINT));
        // 0640 SENGAJA sama seperti webui-admin.json - file ini
        // menyimpan RADIUS shared secret + LDAP bind password, sama
        // sensitifnya dengan password_hash user lokal.
        chmod(self::CONFIG_FILE, 0640);
    }
    /**
     * Coba autentikasi eksternal - RADIUS dulu (kalau enabled), baru
     * LDAP (kalau enabled dan RADIUS tidak berhasil/tidak dicoba).
     * Return nama role LOKAL yang cocok (via group_role_map), atau
     * null kalau kredensial salah ATAU tidak ada satu grup pun yang
     * cocok mapping (fail CLOSED - autentikasi eksternal berhasil
     * TIDAK otomatis berarti diizinkan masuk, harus ada role yang
     * benar-benar ter-mapping).
     */
    public static function attempt(string $username, string $password): ?string
    {
        $config = self::getConfig();
        if (!empty($config['radius_enabled'])) {
            foreach ((array) $config['radius_servers'] as $server) {
                $groups = self::authenticateRadius($server, $username, $password);
                if ($groups !== null) {
                    $role = self::resolveRole($groups, (array) $config['group_role_map']);
                    if ($role !== null) {
                        return $role;
                    }
                    // Kredensial RADIUS benar TAPI tidak ada grup yang
                    // cocok mapping - jangan lanjut coba server RADIUS
                    // lain untuk username yang SAMA (ambigu/berisiko),
                    // tapi JANGAN diam-diam lanjut ke LDAP juga - kalau
                    // admin sengaja pasang RADIUS, kegagalan mapping
                    // grup adalah masalah KONFIGURASI yang harus
                    // diperbaiki, bukan ditutupi dengan fallback diam-diam.
                    return null;
                }
            }
        }
        if (!empty($config['ldap_enabled'])) {
            foreach ((array) $config['ldap_servers'] as $server) {
                $groups = self::authenticateLdap($server, $username, $password);
                if ($groups !== null) {
                    $role = self::resolveRole($groups, (array) $config['group_role_map']);
                    if ($role !== null) {
                        return $role;
                    }
                    return null;
                }
            }
        }
        return null;
    }
    /**
     * @param array<string, mixed> $server
     * @return string[]|null Daftar grup (dari atribut Class RADIUS) kalau kredensial benar, null kalau salah/server tidak bisa dihubungi.
     */
    private static function authenticateRadius(array $server, string $username, string $password): ?array
    {
        $host = (string) ($server['host'] ?? '');
        $port = (string) ($server['port'] ?? '1812');
        $secret = (string) ($server['secret'] ?? '');
        $timeout = (string) ($server['timeout'] ?? '5');
        if ($host === '' || $secret === '') {
            return null;
        }
        // radclient baca pasangan atribut dari stdin, format
        // "Attribute = value" per baris - username/password DIKIRIM
        // LEWAT STDIN (bukan argumen shell), jadi TIDAK PERNAH muncul
        // di daftar proses (ps aux) atau butuh escapeshellarg sama
        // sekali untuk isinya sendiri.
        $input = sprintf(
            "User-Name = \"%s\"\nUser-Password = \"%s\"\n",
            str_replace('"', '\\"', $username),
            str_replace('"', '\\"', $password)
        );
        $cmd = sprintf(
            '/usr/local/bin/radclient -t %s -x %s:%s auth %s 2>&1',
            escapeshellarg($timeout),
            escapeshellarg($host),
            escapeshellarg($port),
            escapeshellarg($secret)
        );
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($cmd, $descriptors, $pipes);
        if (!is_resource($process)) {
            return null;
        }
        fwrite($pipes[0], $input);
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        if (!str_contains($output, 'Access-Accept')) {
            return null;
        }
        // Atribut Class - konvensi FreeRADIUS untuk kirim balik nama
        // grup, dipisah titik-koma kalau lebih dari satu (dikonfirmasi
        // dari dokumentasi pfSense - pola yang sama kita ikuti di sini,
        // bukan format baru sendiri).
        $groups = [];
        if (preg_match('/Class\s*=\s*"?([^"\n]+)"?/', $output, $m)) {
            $groups = array_map('trim', explode(';', $m[1]));
        }
        return $groups;
    }
    /**
     * @param array<string, mixed> $server
     * @return string[]|null Daftar grup kalau kredensial benar, null kalau salah/server tidak bisa dihubungi.
     */
    private static function authenticateLdap(array $server, string $username, string $password): ?array
    {
        $host = (string) ($server['host'] ?? '');
        $port = (string) ($server['port'] ?? '389');
        $useTls = !empty($server['use_tls']);
        $userDnTemplate = (string) ($server['user_dn_template'] ?? '');
        if ($host === '' || $userDnTemplate === '') {
            return null;
        }
        $userDn = str_replace('{username}', $username, $userDnTemplate);
        $scheme = $useTls ? 'ldaps' : 'ldap';
        $uri = "{$scheme}://{$host}:{$port}";
        // Simple bind LANGSUNG sebagai user itu sendiri - ini SATU-
        // SATUNYA cara memverifikasi password LDAP yang benar tanpa
        // pernah menyimpan/melihat hash password di server LDAP
        // (server LDAP sendiri yang menolak/menerima bind).
        $cmd = sprintf(
            '/usr/local/bin/ldapwhoami -x -D %s -H %s -w %s 2>&1',
            escapeshellarg($userDn),
            escapeshellarg($uri),
            escapeshellarg($password)
        );
        exec($cmd, $outputLines, $exitCode);
        if ($exitCode !== 0) {
            return null;
        }
        // Grup keanggotaan - search TERPISAH pakai bind yang BARU SAJA
        // berhasil di atas (bukan service account terpisah - lebih
        // sederhana untuk Tahap 1, cukup untuk server yang mengizinkan
        // user cari atribut dirinya sendiri, pola umum Active Directory/
        // OpenLDAP dengan memberof overlay aktif).
        $groupAttr = (string) ($server['group_attribute'] ?? 'memberOf');
        $searchCmd = sprintf(
            '/usr/local/bin/ldapsearch -x -D %s -H %s -w %s -b %s -s base %s 2>/dev/null',
            escapeshellarg($userDn),
            escapeshellarg($uri),
            escapeshellarg($password),
            escapeshellarg($userDn),
            escapeshellarg($groupAttr)
        );
        exec($searchCmd, $searchLines);
        $groups = [];
        foreach ($searchLines as $line) {
            if (stripos($line, $groupAttr . ':') === 0) {
                // Ambil CN dari DN grup penuh (mis. "CN=VPNUsers,OU=..." -> "VPNUsers")
                $value = trim(substr($line, strlen($groupAttr) + 1));
                if (preg_match('/^CN=([^,]+)/i', $value, $m)) {
                    $groups[] = $m[1];
                } else {
                    $groups[] = $value;
                }
            }
        }
        // RCA nyata (ditemukan bro langsung - bind sukses, password
        // benar, TAPI login tetap ditolak "Incorrect username or
        // password"): server di atas TIDAK mengembalikan memberOf sama
        // sekali - OpenLDAP standar (BEDA dari Active Directory) TIDAK
        // otomatis menandai atribut memberOf di entri USER hanya karena
        // dia terdaftar sebagai 'member' di entri GRUP, KECUALI overlay
        // 'memberof' aktif di server itu. TurnKey OpenLDAP TIDAK aktifkan
        // overlay itu secara default.
        //
        // Fix: kalau pencarian di atas kosong, CARI BALIK dari sisi
        // grup - susuri seluruh tree di bawah domain root (diturunkan
        // dari DN user itu sendiri, ambil dari komponen 'dc=' pertama
        // dan seterusnya) untuk entri APAPUN yang menyebut DN user ini
        // persis di atribut 'member' ATAU 'uniqueMember' (dua nama
        // atribut keanggotaan grup paling umum - groupOfNames vs
        // groupOfUniqueNames, dua objectClass grup standar LDAP).
        if (empty($groups)) {
            $dcPos = stripos($userDn, 'dc=');
            $searchBase = $dcPos !== false ? substr($userDn, $dcPos) : $userDn;
            $filter = sprintf('(|(member=%s)(uniqueMember=%s))', $userDn, $userDn);
            $reverseCmd = sprintf(
                '/usr/local/bin/ldapsearch -x -D %s -H %s -w %s -b %s -s sub %s cn 2>/dev/null',
                escapeshellarg($userDn),
                escapeshellarg($uri),
                escapeshellarg($password),
                escapeshellarg($searchBase),
                escapeshellarg($filter)
            );
            exec($reverseCmd, $reverseLines);
            foreach ($reverseLines as $line) {
                if (stripos($line, 'cn:') === 0) {
                    $groups[] = trim(substr($line, 3));
                }
            }
        }
        return $groups;
    }
    /**
     * @param string[] $groups
     * @param array<int, array{external_group: string, local_role: string}> $mapping
     */
    private static function resolveRole(array $groups, array $mapping): ?string
    {
        foreach ($mapping as $map) {
            $externalGroup = (string) ($map['external_group'] ?? '');
            if ($externalGroup !== '' && in_array($externalGroup, $groups, true)) {
                return (string) ($map['local_role'] ?? '');
            }
        }
        return null;
    }
    /**
     * Test konektivitas - dipanggil dari halaman konfigurasi supaya
     * admin bisa verifikasi setup BENAR sebelum benar-benar
     * mengandalkannya untuk login sungguhan (pola sama seperti tombol
     * "Save & Test" pfSense).
     *
     * @return array{success: bool, message: string, groups?: string[]}
     */
    public static function testRadius(array $server, string $username, string $password): array
    {
        $groups = self::authenticateRadius($server, $username, $password);
        if ($groups === null) {
            return ['success' => false, 'message' => 'Authentication failed or server unreachable.'];
        }
        return ['success' => true, 'message' => 'Authenticated successfully.', 'groups' => $groups];
    }
    /** @return array{success: bool, message: string, groups?: string[]} */
    public static function testLdap(array $server, string $username, string $password): array
    {
        $groups = self::authenticateLdap($server, $username, $password);
        if ($groups === null) {
            return ['success' => false, 'message' => 'Authentication failed, bind DN template incorrect, or server unreachable.'];
        }
        return ['success' => true, 'message' => 'Authenticated successfully.', 'groups' => $groups];
    }
}
