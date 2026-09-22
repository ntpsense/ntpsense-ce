<?php
declare(strict_types=1);
require_once __DIR__ . '/NtpsenseConfigd.php';
require_once __DIR__ . '/AuditLog.php';
require_once __DIR__ . '/ExternalAuth.php';
require_once __DIR__ . '/license.php';
/**
 * Auth - autentikasi admin MULTI-USER dengan ROLE-BASED ACCESS CONTROL.
 * Model permission diriset dari 4 vendor rujukan project ini (FortiGate
 * Admin Profiles, pfSense User Manager Groups, Palo Alto Admin Roles,
 * Sangfor Admin Management) - keempatnya SAMA polanya: 1 role bawaan
 * tetap ("Administrator"/super_admin, akses penuh, tidak bisa diedit/
 * dihapus) + role custom sejumlah berapa pun yang admin definisikan
 * sendiri, masing-masing dengan matriks izin None/Read/Read-Write per
 * kategori fitur. "System" (Users/Certificates/Backup) SENGAJA hanya
 * bisa diakses role Administrator - TIDAK BISA diberikan ke role custom
 * manapun, persis rekomendasi FortiGate (admingrp = risiko setara
 * super_admin) dan tiket bug resmi pfSense (user dengan akses User
 * Manager bisa naikkan privilege dirinya sendiri kalau tidak dibatasi).
 *
 * Kredensial & role disimpan sebagai hash/plain JSON di file config
 * terpisah dari kode - supaya file ini sendiri bisa di-review/diaudit
 * tanpa pernah menyentuh credential asli.
 *
 * ============================================================
 * PERLUASAN Agustus 2026 - gerbang lisensi Pro untuk RBAC lanjutan
 * ============================================================
 * CE (gratis) dibatasi 1 admin (akun bawaan 'admin' saja), TANPA role
 * custom, TANPA 2FA - konsisten dengan compare.html yang sudah live
 * di ntpsense.com ("Admin accounts: 1 admin" untuk CE, "Multi-admin,
 * custom roles, 2FA" untuk Pro).
 *
 * PRINSIP PENTING (supaya konsisten dengan "Open-Core Promise" yang
 * sudah dipublikasikan): gerbang ini SENGAJA mengecek fitur yang
 * MEMANG sudah disepakati sejak awal sebagai batas CE/Pro (lihat
 * compare.html) - BUKAN menggeser garis yang sudah ada. Kalau nanti
 * ada fitur BARU yang mau digeser status CE/Pro-nya, itu HARUS lewat
 * proses yang sama (umumkan dulu, jangan mendadak) sebelum kode
 * gerbang untuk fitur itu ditambahkan di sini.
 *
 * Fail-CLOSED kalau license.php sendiri gagal terbaca/error internal
 * (anggap CE, bukan anggap Pro) - lebih aman salah arah ke "terlalu
 * ketat" daripada "terlalu longgar" untuk gerbang yang berkaitan
 * dengan pendapatan produk.
 * ============================================================
 */
final class Auth
{
    // RCA: sebelumnya file ini langsung di /usr/local/etc/ntpsense/
    // (root:wheel, dibuat install-gateway-v2.sh Bagian 3/8 untuk
    // mgmt-interface.lock + ssl/ private key) - PHP-FPM (jalan sebagai
    // user 'www') TIDAK punya izin tulis di situ ("Permission denied"),
    // dan solusi darurat 'chown -R www:www' pada seluruh direktori itu
    // TIDAK aman (ikut mengubah kepemilikan folder ssl/ berisi private
    // key TLS). Fix: pindah ke subdirektori KHUSUS ('webui/') yang
    // dibuat install-webui.sh dengan permission root:ntpsenseweb 0770 -
    // scoped hanya untuk state yang memang perlu ditulis PHP-FPM,
    // TIDAK menyentuh permission ssl/ atau file lain di /usr/local/etc/ntpsense/.
    private const CREDENTIAL_FILE = '/usr/local/etc/ntpsense/webui/webui-admin.json';
    private const LOCKOUT_FILE = '/usr/local/etc/ntpsense/webui/lockout.json';
    // Disepakati bareng bro, diriset dari FortiGate (default 3/60s) dan
    // Palo Alto (lockout dua parameter independen: USERNAME dan HOST) -
    // kita pakai kombinasi keduanya supaya penyerang tidak bisa DoS
    // akun admin asli dengan sengaja spam password salah dari IP lain,
    // DAN supaya satu IP yang coba banyak username juga tetap kena block.
    private const LOCKOUT_THRESHOLD = 5;
    private const LOCKOUT_SECONDS = 900; // 15 menit
    private const DEFAULT_USERNAME = 'admin';
    private const DEFAULT_PASSWORD = 'admin';
    // "Administrator" TIDAK PERNAH disimpan sebagai objek role di file -
    // ini nama cadangan (reserved), diperlakukan sebagai kasus khusus di
    // seluruh kode: akses penuh ke SEMUA kategori TERMASUK 'system',
    // dan TIDAK BISA di-assign sebagai nama role custom (dicegah di
    // createRole/updateRole).
    public const ADMINISTRATOR_ROLE = 'Administrator';
    // Kategori yang BISA diberikan ke role custom - SENGAJA sama persis
    // dengan key $navItems di layout_header.php supaya tidak ada drift
    // antara nama menu dan nama kategori permission. 'dashboard' TIDAK
    // masuk (selalu terbuka untuk siapa pun yang sudah login, murni
    // informasional) dan 'system' TIDAK masuk (Administrator-only,
    // keputusan disepakati bareng bro berdasarkan riset FortiGate/pfSense).
    public const ASSIGNABLE_CATEGORIES = [
        'network', 'multiwan', 'ha', 'nat', 'firewall', 'proxy', 'security',
        'vpn', 'ipsec', 'services', 'system_logs', 'package_manager',
    ];
    private const PERMISSION_LEVELS = ['none', 'read', 'write'];
    /**
     * Gerbang lisensi Pro dipakai bareng di createUser()/createRole()/
     * beginTotpSetup() - satu titik kebenaran, bukan dicek ulang
     * dengan logic beda-beda di tiap fungsi. Fail-CLOSED (anggap CE)
     * kalau terjadi exception apa pun saat baca status lisensi -
     * lihat catatan kebijakan di puncak file.
     */
    private static function requireProLicense(string $featureDescription): void
    {
        try {
            $isPro = ntpsense_get_license_status()->isFullyValid();
        } catch (\Throwable $e) {
            $isPro = false; // fail-closed
        }
        if (!$isPro) {
            throw new InvalidArgumentException(
                "{$featureDescription} requires NTPSense Pro. This installation is running Community Edition (CE) - see ntpsense.com/compare.html or upload a valid Pro license under System > License."
            );
        }
    }
    public static function ensureBootstrapped(): void
    {
        if (file_exists(self::CREDENTIAL_FILE)) {
            self::migrateIfNeeded();
            return;
        }
        $dir = dirname(self::CREDENTIAL_FILE);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        $data = [
            'users' => [
                [
                    'username' => self::DEFAULT_USERNAME,
                    'password_hash' => password_hash(self::DEFAULT_PASSWORD, PASSWORD_DEFAULT),
                    'must_change_password' => true,
                    'created_at' => time(),
                    'role' => self::ADMINISTRATOR_ROLE,
                ],
            ],
            'roles' => self::defaultStarterRoles(),
        ];
        file_put_contents(self::CREDENTIAL_FILE, json_encode($data, JSON_PRETTY_PRINT));
        chmod(self::CREDENTIAL_FILE, 0640);
    }
    /**
     * Dua role custom contoh, disepakati dengan bro sebagai starting
     * point yang bisa diedit/dihapus bebas - BUKAN role bawaan yang
     * dilindungi seperti Administrator. Dipakai baik untuk instalasi
     * baru maupun migrasi dari format lama (supaya gateway existing
     * yang upgrade tetap dapat contoh yang sama, bukan role kosong).
     *
     * CATATAN Agustus 2026: starter roles ini TETAP dibuat di
     * CREDENTIAL_FILE bahkan untuk CE (data strukturnya ada), tapi
     * createRole()/updateRole() untuk role BARU digerbang lisensi -
     * starter roles yang SUDAH ada saat instalasi awal bukan "role
     * baru yang dibuat admin", jadi tidak retroaktif dicabut dari
     * instalasi CE yang kebetulan sudah py role ini dari bootstrap.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function defaultStarterRoles(): array
    {
        return [
            [
                'name' => 'Network Operator',
                'permissions' => [
                    'network' => 'write', 'multiwan' => 'write', 'nat' => 'write', 'firewall' => 'write',
                    'proxy' => 'none', 'security' => 'none',
                    'vpn' => 'write', 'ipsec' => 'write',
                    'services' => 'read', 'system_logs' => 'read', 'package_manager' => 'none',
                ],
            ],
            [
                'name' => 'Auditor',
                'permissions' => array_fill_keys(self::ASSIGNABLE_CATEGORIES, 'read'),
            ],
        ];
    }
    /**
     * Migrasi bertahap idempoten - dipanggil setiap request, tapi cuma
     * benar-benar menulis ulang file kalau memang ada yang kurang:
     * (1) format lama tanpa key 'users' sama sekali (satu objek user
     *     flat) -> dibungkus jadi array 'users'.
     * (2) 'users' sudah ada tapi 'roles' belum ada (gateway yang sempat
     *     upgrade ke versi multi-user SEBELUM fitur role ini ada) ->
     *     tambahkan starter roles, dan setiap user existing diberi
     *     'role' => Administrator supaya TIDAK ADA yang tiba-tiba
     *     kehilangan akses akibat upgrade (sama filosofinya dengan
     *     #[serde(default)] di sisi Rust).
     * (3) user individual yang entah bagaimana tidak punya field 'role'
     *     (mis. race kondisi upgrade) -> default ke Administrator, BUKAN
     *     'none', supaya gagal AMAN ke arah tetap-bisa-akses daripada
     *     diam-diam terkunci dari gateway sendiri.
     */
    private static function migrateIfNeeded(): void
    {
        $raw = json_decode((string) file_get_contents(self::CREDENTIAL_FILE), true);
        if (!is_array($raw)) {
            return;
        }
        $changed = false;
        if (!isset($raw['users'])) {
            if (!isset($raw['username'], $raw['password_hash'])) {
                return;
            }
            $raw = [
                'users' => [
                    [
                        'username' => $raw['username'],
                        'password_hash' => $raw['password_hash'],
                        'must_change_password' => (bool) ($raw['must_change_password'] ?? false),
                        'created_at' => time(),
                        'role' => self::ADMINISTRATOR_ROLE,
                    ],
                ],
            ];
            $changed = true;
        }
        if (!isset($raw['roles']) || !is_array($raw['roles'])) {
            $raw['roles'] = self::defaultStarterRoles();
            $changed = true;
        }
        foreach ($raw['users'] as &$user) {
            if (empty($user['role'])) {
                $user['role'] = self::ADMINISTRATOR_ROLE;
                $changed = true;
            }
        }
        unset($user);
        if ($changed) {
            file_put_contents(self::CREDENTIAL_FILE, json_encode($raw, JSON_PRETTY_PRINT));
            chmod(self::CREDENTIAL_FILE, 0640);
        }
    }
    /** @return array{users: array<int, array<string, mixed>>, roles: array<int, array<string, mixed>>} */
    private static function loadAll(): array
    {
        self::ensureBootstrapped();
        $data = json_decode((string) file_get_contents(self::CREDENTIAL_FILE), true);
        return [
            'users' => is_array($data['users'] ?? null) ? $data['users'] : [],
            'roles' => is_array($data['roles'] ?? null) ? $data['roles'] : [],
        ];
    }
    /**
     * @param array<int, array<string, mixed>> $users
     * @param array<int, array<string, mixed>> $roles
     */
    private static function saveAll(array $users, array $roles): void
    {
        file_put_contents(self::CREDENTIAL_FILE, json_encode([
            'users' => array_values($users),
            'roles' => array_values($roles),
        ], JSON_PRETTY_PRINT));
        chmod(self::CREDENTIAL_FILE, 0640);
    }
    /** @return array<string, array{count:int, locked_until:int}> */
    private static function loadLockoutState(): array
    {
        if (!file_exists(self::LOCKOUT_FILE)) {
            return [];
        }
        $data = json_decode((string) file_get_contents(self::LOCKOUT_FILE), true);
        return is_array($data) ? $data : [];
    }
    /** @param array<string, array{count:int, locked_until:int}> $state */
    private static function saveLockoutState(array $state): void
    {
        $dir = dirname(self::LOCKOUT_FILE);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        file_put_contents(self::LOCKOUT_FILE, json_encode($state));
        chmod(self::LOCKOUT_FILE, 0640);
    }
    /**
     * Cek dua kunci independen (username DAN IP sumber, pola Palo Alto)
     * - kalau SALAH SATU sedang lockout, tolak. Entry yang lockout-nya
     * sudah lewat dibersihkan sekalian di sini (self-cleaning, tidak
     * perlu cron terpisah).
     */
    public static function isLockedOut(string $username, string $ip): bool
    {
        $state = self::loadLockoutState();
        $now = time();
        $changed = false;
        $locked = false;
        foreach (['user:' . $username, 'ip:' . $ip] as $key) {
            if (isset($state[$key])) {
                if ($state[$key]['locked_until'] > $now) {
                    $locked = true;
                } elseif ($state[$key]['locked_until'] > 0) {
                    unset($state[$key]);
                    $changed = true;
                }
            }
        }
        if ($changed) {
            self::saveLockoutState($state);
        }
        return $locked;
    }
    /** @return int Detik tersisa sebelum bisa mencoba lagi (0 kalau tidak sedang lockout). */
    public static function lockoutSecondsRemaining(string $username, string $ip): int
    {
        $state = self::loadLockoutState();
        $now = time();
        $remaining = 0;
        foreach (['user:' . $username, 'ip:' . $ip] as $key) {
            if (isset($state[$key]) && $state[$key]['locked_until'] > $now) {
                $remaining = max($remaining, $state[$key]['locked_until'] - $now);
            }
        }
        return $remaining;
    }
    private static function registerFailedAttempt(string $username, string $ip): void
    {
        $state = self::loadLockoutState();
        $now = time();
        foreach (['user:' . $username, 'ip:' . $ip] as $key) {
            $entry = $state[$key] ?? ['count' => 0, 'locked_until' => 0];
            $entry['count']++;
            if ($entry['count'] >= self::LOCKOUT_THRESHOLD) {
                $entry['locked_until'] = $now + self::LOCKOUT_SECONDS;
                $entry['count'] = 0; // reset hitungan, lockout baru dimulai lagi dari 0 setelah expired
            }
            $state[$key] = $entry;
        }
        self::saveLockoutState($state);
    }
    private static function clearFailedAttempts(string $username, string $ip): void
    {
        $state = self::loadLockoutState();
        unset($state['user:' . $username], $state['ip:' . $ip]);
        self::saveLockoutState($state);
    }
    /**
     * @return string 'ok' (login selesai, tidak ada 2FA), 'needs_2fa'
     * (password benar, TUNGGU verifyTwoFactor()), atau 'fail' (locked
     * out ATAU username/password salah - SENGAJA tidak dibedakan di
     * return value ini, pesan spesifik biar login.php yang urus lewat
     * isLockedOut()/lockoutSecondsRemaining() terpisah seperti sebelumnya).
     */
    public static function attempt(string $username, string $password): string
    {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '-');
        if (self::isLockedOut($username, $ip)) {
            AuditLog::logLogin($username, false, 'locked out');
            return 'fail';
        }
        $data = self::loadAll();
        foreach ($data['users'] as $user) {
            if (!hash_equals((string) $user['username'], $username)) {
                continue;
            }
            // RCA (Tahap 1 roadmap RADIUS/LDAP): user yang SEBELUMNYA
            // pernah berhasil login lewat RADIUS/LDAP punya record
            // lokal dengan auth_source='external' (auto-provisioned,
            // lihat provisionExternalUser() di bawah) - password_hash
            // mereka TIDAK PERNAH benar-benar dipakai (diisi acak saat
            // provisioning), jadi verifikasi HARUS lewat ExternalAuth
            // lagi setiap kali, BUKAN password_verify() lokal yang
            // pasti gagal. 'break' di sini (bukan 'continue') supaya
            // keluar dari loop dan jatuh ke alur eksternal di bawah,
            // TIDAK dianggap "username tidak ditemukan".
            if (($user['auth_source'] ?? 'local') !== 'local') {
                break;
            }
            if (!password_verify($password, (string) $user['password_hash'])) {
                self::registerFailedAttempt($username, $ip);
                AuditLog::logLogin($username, false, 'wrong password');
                return 'fail';
            }
            self::clearFailedAttempts($username, $ip);
            if (!empty($user['totp_enabled'])) {
                // JANGAN finalisasi session di sini - cuma tandai
                // "password sudah benar, tunggu tahap 2FA" lewat marker
                // TERPISAH dari sesi admin penuh. Kalau alur berhenti di
                // sini (browser ditutup dsb), marker ini TIDAK memberi
                // akses apa pun - cuma dibaca verifyTwoFactor().
                $_SESSION['ntpsense_2fa_pending_username'] = (string) $user['username'];
                return 'needs_2fa';
            }
            $_SESSION['ntpsense_admin'] = true;
            $_SESSION['ntpsense_username'] = (string) $user['username'];
            $_SESSION['ntpsense_must_change_password'] = (bool) ($user['must_change_password'] ?? false);
            session_regenerate_id(true);
            AuditLog::logLogin($username, true);
            return 'ok';
        }
        // Tidak ketemu record LOKAL sama sekali, ATAU ketemu tapi
        // auth_source-nya eksternal - coba RADIUS/LDAP (kalau
        // dikonfigurasi admin). ExternalAuth::attempt() SENDIRI yang
        // memutuskan RADIUS/LDAP mana yang dicoba dan mapping grup->
        // role - Auth.php di sini cuma menerima hasil akhirnya (nama
        // role LOKAL, atau null kalau gagal/tidak ada mapping cocok).
        $externalRole = ExternalAuth::attempt($username, $password);
        if ($externalRole !== null && in_array($externalRole, self::validRoleNames(), true)) {
            self::clearFailedAttempts($username, $ip);
            self::provisionExternalUser($username, $externalRole);
            // Tidak ada jalur 2FA untuk user eksternal Tahap 1 ini -
            // MFA (kalau ada) jadi tanggung jawab server RADIUS/LDAP-
            // nya sendiri (banyak organisasi sudah pasang MFA di
            // level itu, mis. Duo/RADIUS proxy) - mewajibkan 2FA
            // TOTP gateway ini JUGA untuk user eksternal cuma
            // menambah friction tanpa nilai keamanan tambahan yang
            // jelas untuk Tahap 1.
            $_SESSION['ntpsense_admin'] = true;
            $_SESSION['ntpsense_username'] = $username;
            $_SESSION['ntpsense_must_change_password'] = false;
            session_regenerate_id(true);
            AuditLog::logLogin($username, true, "external auth (role: {$externalRole})");
            return 'ok';
        }
        // Username tidak ditemukan - tetap dicatat sebagai percobaan
        // gagal ke KEDUA kunci (username yang diketik apa adanya, dan
        // IP) - supaya baik username itu diulang-ulang MAUPUN IP yang
        // sama coba banyak username acak, dua-duanya tetap bisa kena
        // lockout.
        self::registerFailedAttempt($username, $ip);
        AuditLog::logLogin($username, false, 'unknown username');
        return 'fail';
    }
    /**
     * JIT (Just-In-Time) provisioning - dipanggil SETELAH RADIUS/LDAP
     * konfirmasi kredensial benar DAN grup ter-mapping ke role lokal
     * yang valid. Kalau user ini SUDAH pernah login eksternal
     * sebelumnya, cuma role-nya yang disinkronkan ulang (grup mapping
     * bisa berubah dari waktu ke waktu di server RADIUS/LDAP) - kalau
     * belum pernah, record baru dibuat. password_hash diisi RANDOM
     * (tidak pernah dipakai untuk verifikasi - lihat catatan di
     * attempt() di atas), murni supaya struktur data user tetap
     * konsisten dengan user lokal biasa.
     */
    private static function provisionExternalUser(string $username, string $role): void
    {
        $data = self::loadAll();
        $found = false;
        foreach ($data['users'] as &$user) {
            if (hash_equals((string) $user['username'], $username)) {
                $user['role'] = $role;
                $user['auth_source'] = 'external';
                $found = true;
                break;
            }
        }
        unset($user);
        if (!$found) {
            $data['users'][] = [
                'username' => $username,
                'password_hash' => password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT),
                'must_change_password' => false,
                'created_at' => time(),
                'role' => $role,
                'auth_source' => 'external',
            ];
        }
        self::saveAll($data['users'], $data['roles']);
    }
    public static function changePassword(string $newPassword): void
    {
        $username = (string) ($_SESSION['ntpsense_username'] ?? '');
        self::changePasswordForUser($username, $newPassword);
        $_SESSION['ntpsense_must_change_password'] = false;

        // Roadmap console menu (permintaan user) - sinkronkan password
        // OS juga, supaya SATU password genuinely berlaku untuk Web UI
        // DAN login console/SSH (kalau user ini punya akun OS yang
        // sudah disinkronkan via ntpsense-sync-os-accounts.sh).
        // Best-effort - TIDAK BOLEH menggagalkan ganti password Web UI
        // kalau sync OS gagal, itu fungsi UTAMA di sini.
        try {
            $configd = new NtpsenseConfigd();
            $configd->call('system.sync_os_password', ['username' => $username, 'password' => $newPassword]);
        } catch (\Throwable $e) {
            // Diam - lihat catatan di atas.
        }
    }

    /**
     * Versi changePassword() yang TIDAK bergantung $_SESSION - aman
     * dipanggil dari konteks CLI (tidak ada session sama sekali di
     * situ), dipakai console-set-password.php untuk alur ganti
     * password dari console menu (sync 2 arah OS<->Web UI, permintaan
     * user langsung setelah ditemukan sync satu arah saja tidak
     * cukup). Return true kalau username ditemukan & berhasil diubah,
     * false kalau username tidak ada di Web UI.
     */
    public static function changePasswordForUser(string $username, string $newPassword): bool
    {
        $data = self::loadAll();
        $found = false;
        foreach ($data['users'] as &$user) {
            if (hash_equals((string) $user['username'], $username)) {
                $user['password_hash'] = password_hash($newPassword, PASSWORD_DEFAULT);
                $user['must_change_password'] = false;
                $found = true;
                break;
            }
        }
        unset($user);
        if ($found) {
            self::saveAll($data['users'], $data['roles']);
        }
        return $found;
    }
    // ============================================================
    // 2FA (TOTP, RFC 6238) - kompatibel Google Authenticator/Authy/
    // Microsoft Authenticator. Native, TANPA server RADIUS eksternal -
    // riset sebelum dibangun menemukan pfSense TIDAK punya ini bawaan
    // sama sekali (satu-satunya cara dapat 2FA di pfSense adalah
    // instal paket FreeRADIUS terpisah + PAM Google Authenticator,
    // solusi berputar-putar). Opt-in per-user (disepakati bareng bro,
    // bukan wajib global) - konsisten dengan semua vendor besar
    // (GitHub, Google Workspace, AWS IAM) yang rollout 2FA opt-in
    // dulu, wajib-per-role belakangan kalau memang perlu.
    //
    // SEJAK Agustus 2026: 2FA sendiri adalah fitur Pro (lihat
    // requireProLicense() di beginTotpSetup() di bawah) - CE tetap
    // punya SEMUA kode RFC 6238 ini (satu codebase, lihat diskusi
    // Opsi A/B soal pemisahan CE/Pro), tapi tidak bisa MENGAKTIFKAN-nya
    // tanpa license Pro valid.
    //
    // Toleransi waktu ±1 langkah (~90 detik total) - TOTP berbasis
    // waktu, dan FortiGate sendiri eksplisit memperingatkan
    // "autentikasi tetap gagal meski kode benar karena NTP belum
    // sinkron" sebagai jebakan operasional nyata yang sengaja dihindari
    // di sini dengan toleransi ini (bukan solusi sempurna, tapi
    // mengurangi false-negative dari drift kecil tanpa melemahkan
    // keamanan secara berarti - window efektif tetap cuma ±30 detik).
    // ============================================================
    private const TOTP_STEP_SECONDS = 30;
    private const TOTP_DIGITS = 6;
    private const TOTP_TOLERANCE_STEPS = 1;
    private const RECOVERY_CODE_COUNT = 10;
    private static function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $output .= $alphabet[bindec($chunk)];
        }
        return $output;
    }
    private static function base32Decode(string $encoded): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $encoded = strtoupper((string) preg_replace('/[^A-Za-z2-7]/', '', $encoded));
        $bits = '';
        foreach (str_split($encoded) as $char) {
            $pos = strpos($alphabet, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr((int) bindec($byte));
            }
        }
        return $output;
    }
    /** Satu kode TOTP untuk time-step tertentu - RFC 6238 di atas HOTP (RFC 4226), HMAC-SHA1, 6 digit. */
    private static function totpCodeAt(string $secretBase32, int $timeStep): string
    {
        $secret = self::base32Decode($secretBase32);
        // Counter 8-byte big-endian - pack('N') PHP cuma 32-bit, jadi
        // 4 byte tinggi SELALU nol (timeStep tidak akan melebihi 32-bit
        // sampai ribuan tahun ke depan di step 30 detik).
        $counterBytes = pack('N', 0) . pack('N', $timeStep);
        $hash = hash_hmac('sha1', $counterBytes, $secret, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);
        $code = $binary % (10 ** self::TOTP_DIGITS);
        return str_pad((string) $code, self::TOTP_DIGITS, '0', STR_PAD_LEFT);
    }
    private static function verifyTotpCode(string $secretBase32, string $code): bool
    {
        $code = trim($code);
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }
        $currentStep = (int) floor(time() / self::TOTP_STEP_SECONDS);
        for ($i = -self::TOTP_TOLERANCE_STEPS; $i <= self::TOTP_TOLERANCE_STEPS; $i++) {
            if (hash_equals(self::totpCodeAt($secretBase32, $currentStep + $i), $code)) {
                return true;
            }
        }
        return false;
    }
    public static function currentUserHasTotp(): bool
    {
        $username = self::currentUsername();
        foreach (self::loadAll()['users'] as $user) {
            if (hash_equals((string) $user['username'], $username)) {
                return !empty($user['totp_enabled']);
            }
        }
        return false;
    }
    /**
     * Mulai setup 2FA - generate secret BARU, disimpan SEMENTARA di
     * session (BELUM ke file kredensial) sampai admin konfirmasi satu
     * kode yang benar via confirmTotpSetup() - mencegah kondisi admin
     * salah scan QR/salah ketik secret lalu 2FA-nya aktif dengan
     * secret yang sebenarnya TIDAK PERNAH sukses diverifikasi sekali
     * pun (resep pasti untuk lockout diri sendiri).
     *
     * GERBANG LISENSI Agustus 2026: 2FA adalah fitur Pro - dicek DI
     * SINI (titik paling awal alur setup), BUKAN di confirmTotpSetup()
     * saja, supaya admin CE dapat pesan jelas SEBELUM repot scan QR
     * code segala, bukan gagal di langkah terakhir.
     *
     * @return array{secret:string, otpauth_uri:string}
     */
    public static function beginTotpSetup(): array
    {
        self::requireProLicense('Two-factor authentication (2FA)');
        $secretBytes = random_bytes(20); // 160-bit, standar TOTP berbasis SHA1
        $secret = self::base32Encode($secretBytes);
        $username = self::currentUsername();
        $issuer = 'NTPSense';
        $label = rawurlencode("{$issuer}:{$username}");
        $otpauthUri = "otpauth://totp/{$label}?secret={$secret}&issuer=" . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
        $_SESSION['ntpsense_totp_setup_secret'] = $secret;
        return ['secret' => $secret, 'otpauth_uri' => $otpauthUri];
    }
    /**
     * Konfirmasi setup - verifikasi SATU kode dari secret yang barusan
     * digenerate beginTotpSetup(), baru benar-benar disimpan ke
     * kredensial + recovery codes dibuat.
     *
     * @return string[] Recovery codes PLAINTEXT - HANYA ditampilkan sekali di sini, tidak pernah bisa dilihat lagi setelah ini.
     */
    public static function confirmTotpSetup(string $code): array
    {
        // Gerbang KEDUA di sini juga (bukan cuma di beginTotpSetup()) -
        // pertahanan berlapis kalau ada state session lama tersisa dari
        // SEBELUM license CE aktif (mis. admin sempat pakai Pro, downgrade
        // ke CE, lalu ada session setup 2FA yang belum selesai).
        self::requireProLicense('Two-factor authentication (2FA)');
        $secret = (string) ($_SESSION['ntpsense_totp_setup_secret'] ?? '');
        if ($secret === '' || !self::verifyTotpCode($secret, $code)) {
            throw new InvalidArgumentException('Incorrect code - make sure the time on your phone and this gateway are both accurate, then try the newest code shown.');
        }
        $recoveryCodes = [];
        $recoveryCodeHashes = [];
        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
            $plain = strtoupper(bin2hex(random_bytes(5))); // 10 karakter hex, sekali pakai
            $recoveryCodes[] = $plain;
            $recoveryCodeHashes[] = password_hash($plain, PASSWORD_DEFAULT);
        }
        $username = self::currentUsername();
        $data = self::loadAll();
        foreach ($data['users'] as &$user) {
            if (hash_equals((string) $user['username'], $username)) {
                $user['totp_enabled'] = true;
                $user['totp_secret'] = $secret;
                $user['totp_recovery_codes'] = $recoveryCodeHashes;
                break;
            }
        }
        unset($user);
        self::saveAll($data['users'], $data['roles']);
        unset($_SESSION['ntpsense_totp_setup_secret']);
        return $recoveryCodes;
    }
    public static function disableTotp(): void
    {
        // TIDAK digerbang lisensi - menonaktifkan 2FA (mengurangi
        // fitur, bukan menambah) harus SELALU boleh, termasuk kalau
        // license Pro sudah expired/downgrade ke CE (skenario nyata:
        // admin downgrade dari Pro ke CE, TOTP yang sudah aktif dari
        // masa Pro tidak boleh membuat admin terkunci dari akun sendiri
        // tanpa cara menonaktifkannya).
        $username = self::currentUsername();
        $data = self::loadAll();
        foreach ($data['users'] as &$user) {
            if (hash_equals((string) $user['username'], $username)) {
                $user['totp_enabled'] = false;
                unset($user['totp_secret'], $user['totp_recovery_codes']);
                break;
            }
        }
        unset($user);
        self::saveAll($data['users'], $data['roles']);
    }
    /**
     * Verifikasi tahap KEDUA login (kode TOTP ATAU recovery code) -
     * dipanggil SETELAH attempt() mengembalikan 'needs_2fa'. Session
     * BENAR-BENAR baru difinalisasi di sini (bukan di attempt()) -
     * sebelum ini berhasil, admin belum punya akses apa pun meski
     * password sudah benar.
     *
     * TIDAK digerbang lisensi - kalau user SUDAH punya totp_enabled
     * true dari masa license Pro sebelumnya (dan sekarang sudah
     * downgrade ke CE), mereka TETAP HARUS bisa login pakai 2FA yang
     * sudah aktif itu. Gerbang cuma di titik AKTIVASI BARU
     * (beginTotpSetup/confirmTotpSetup), bukan di titik VERIFIKASI
     * yang sudah aktif - beda prinsip dengan disableTotp() di atas
     * untuk alasan yang sama (jangan kunci admin dari akun sendiri).
     */
    public static function verifyTwoFactor(string $code): bool
    {
        $username = (string) ($_SESSION['ntpsense_2fa_pending_username'] ?? '');
        if ($username === '') {
            return false;
        }
        $data = self::loadAll();
        foreach ($data['users'] as &$user) {
            if (!hash_equals((string) $user['username'], $username)) {
                continue;
            }
            $secret = (string) ($user['totp_secret'] ?? '');
            $codeValid = $secret !== '' && self::verifyTotpCode($secret, $code);
            $recoveryUsed = false;
            if (!$codeValid) {
                // Coba sebagai recovery code - sekali pakai, dihapus
                // dari daftar begitu terpakai (tidak bisa dipakai ulang).
                $codes = (array) ($user['totp_recovery_codes'] ?? []);
                foreach ($codes as $idx => $hash) {
                    if (password_verify(strtoupper(trim($code)), (string) $hash)) {
                        unset($codes[$idx]);
                        $user['totp_recovery_codes'] = array_values($codes);
                        $codeValid = true;
                        $recoveryUsed = true;
                        break;
                    }
                }
            }
            if (!$codeValid) {
                AuditLog::logLogin($username, false, '2FA code incorrect');
                return false;
            }
            self::saveAll($data['users'], $data['roles']);
            $_SESSION['ntpsense_admin'] = true;
            $_SESSION['ntpsense_username'] = (string) $user['username'];
            $_SESSION['ntpsense_must_change_password'] = (bool) ($user['must_change_password'] ?? false);
            unset($_SESSION['ntpsense_2fa_pending_username']);
            session_regenerate_id(true);
            AuditLog::logLogin($username, true, $recoveryUsed ? '2FA via recovery code' : '2FA OK');
            return true;
        }
        return false;
    }
    /** @return array<int, array{username:string, must_change_password:bool, created_at:int, role:string, auth_source:string}> */
    public static function listUsers(): array
    {
        return array_map(
            static fn (array $u) => [
                'username' => (string) $u['username'],
                'must_change_password' => (bool) ($u['must_change_password'] ?? false),
                'created_at' => (int) ($u['created_at'] ?? 0),
                'role' => (string) ($u['role'] ?? self::ADMINISTRATOR_ROLE),
                'auth_source' => (string) ($u['auth_source'] ?? 'local'),
            ],
            self::loadAll()['users']
        );
    }
    /** @return array<int, array{name:string, permissions:array<string,string>}> */
    public static function listRoles(): array
    {
        return array_map(
            static fn (array $r) => ['name' => (string) $r['name'], 'permissions' => (array) ($r['permissions'] ?? [])],
            self::loadAll()['roles']
        );
    }
    /** Nama role yang valid untuk di-assign ke user: Administrator + semua role custom tersimpan. */
    public static function validRoleNames(): array
    {
        return array_merge([self::ADMINISTRATOR_ROLE], array_column(self::listRoles(), 'name'));
    }
    public static function currentUsername(): string
    {
        return (string) ($_SESSION['ntpsense_username'] ?? '');
    }
    public static function currentRole(): string
    {
        $username = self::currentUsername();
        foreach (self::loadAll()['users'] as $user) {
            if (hash_equals((string) $user['username'], $username)) {
                return (string) ($user['role'] ?? self::ADMINISTRATOR_ROLE);
            }
        }
        return self::ADMINISTRATOR_ROLE;
    }
    /**
     * Level izin user yang SEDANG LOGIN untuk satu kategori - dibaca
     * FRESH dari disk setiap panggilan (bukan dari session), supaya
     * kalau role-nya diedit admin lain di tengah sesi, pembatasan baru
     * langsung berlaku di request berikutnya, tidak menunggu re-login.
     * Return: 'none' | 'read' | 'write'.
     */
    public static function currentPermission(string $category): string
    {
        $role = self::currentRole();
        if ($role === self::ADMINISTRATOR_ROLE) {
            return 'write';
        }
        foreach (self::listRoles() as $r) {
            if ($r['name'] === $role) {
                return (string) ($r['permissions'][$category] ?? 'none');
            }
        }
        // Role user tidak ditemukan lagi (mis. dihapus admin lain) -
        // fail-CLOSED (none), bukan fail-open - beda kasusnya dari
        // migrasi user lama (yang fail-open ke Administrator) karena di
        // sini rolenya memang sudah tidak ada / sudah tidak valid.
        return 'none';
    }
    /**
     * Guard standar dipanggil di setiap halaman TEPAT SETELAH
     * requireLogin() - membatasi baik akses baca halaman (GET dengan
     * permission 'none' ditolak total) maupun submit perubahan (POST
     * ditolak kalau permission cuma 'read'). 'system' TIDAK PERNAH
     * dilewatkan lewat sini - system.php punya pemeriksaan tersendiri
     * yang mewajibkan role Administrator secara eksplisit.
     */
    public static function requireCategory(string $category): void
    {
        $level = self::currentPermission($category);
        $action = (string) ($_POST['form'] ?? ($_SERVER['REQUEST_METHOD'] === 'POST' ? '(unnamed form)' : 'view'));
        if ($level === 'none') {
            AuditLog::logAccess($category, $action, 'denied - no access');
            http_response_code(403);
            echo '<!DOCTYPE html><html><body style="font-family:sans-serif; padding:40px; text-align:center;">'
                . '<h2>Access denied</h2><p>Your account role does not have access to this page.</p>'
                . '<p><a href="/index.php">Back to Dashboard</a></p></body></html>';
            exit;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $level !== 'write') {
            AuditLog::logAccess($category, $action, 'denied - read-only');
            http_response_code(403);
            echo '<!DOCTYPE html><html><body style="font-family:sans-serif; padding:40px; text-align:center;">'
                . '<h2>Read-only access</h2><p>Your account role has read-only access to this page and cannot make changes.</p>'
                . '<p><a href="javascript:history.back()">Go back</a></p></body></html>';
            exit;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            AuditLog::logAccess($category, $action, 'allowed', AuditLog::summarizePost($_POST));
        }
    }
    /** Dipanggil di system.php - System SELALU Administrator-only, tidak lewat matriks role custom. */
    public static function requireAdministrator(): void
    {
        if (self::currentRole() !== self::ADMINISTRATOR_ROLE) {
            AuditLog::logAccess('system', (string) ($_POST['form'] ?? 'view'), 'denied - not Administrator');
            http_response_code(403);
            echo '<!DOCTYPE html><html><body style="font-family:sans-serif; padding:40px; text-align:center;">'
                . '<h2>Access denied</h2><p>Only the Administrator role can access System settings.</p>'
                . '<p><a href="/index.php">Back to Dashboard</a></p></body></html>';
            exit;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            AuditLog::logAccess('system', (string) ($_POST['form'] ?? '(unnamed form)'), 'allowed', AuditLog::summarizePost($_POST));
        }
    }
    /**
     * GERBANG LISENSI Agustus 2026: CE dibatasi 1 admin (akun bawaan
     * 'admin' dari bootstrap). Dicek DI SINI (sebelum validasi lain
     * seperti username kosong/password pendek) supaya admin CE dapat
     * pesan yang JELAS soal alasan gagal - bukan tercampur dengan
     * pesan validasi generik.
     */
    public static function createUser(string $username, string $password, string $role): void
    {
        $existingUserCount = count(self::loadAll()['users']);
        if ($existingUserCount >= 1) {
            self::requireProLicense('Multiple admin accounts');
        }
        $username = trim($username);
        if ($username === '') {
            throw new InvalidArgumentException('Username cannot be empty.');
        }
        if (strlen($password) < 8) {
            throw new InvalidArgumentException('Password must be at least 8 characters.');
        }
        if (!in_array($role, self::validRoleNames(), true)) {
            throw new InvalidArgumentException('That role does not exist.');
        }
        $data = self::loadAll();
        foreach ($data['users'] as $u) {
            if (strcasecmp((string) $u['username'], $username) === 0) {
                throw new InvalidArgumentException('That username already exists.');
            }
        }
        $data['users'][] = [
            'username' => $username,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'must_change_password' => true,
            'created_at' => time(),
            'role' => $role,
        ];
        self::saveAll($data['users'], $data['roles']);
        AuditLog::logChange('system', 'user_create', '(none)', "{$username} (role: {$role})");
    }
    public static function changeUserRole(string $username, string $newRole): void
    {
        // Proteksi KEDUA, terpisah dari "Administrator terakhir tidak
        // boleh diturunkan" di bawah - khusus akun BAWAAN 'admin' (nama
        // literal, hasil bootstrap awal), permanen terkunci ke
        // Administrator TERLEPAS dari berapa banyak akun Administrator
        // lain yang ada. Ini persis pola pfSense (akun 'admin' bawaan
        // secara eksplisit tidak bisa dihapus lewat GUI apa pun
        // kondisinya, bukan cuma soal "tersisa satu-satunya admin") -
        // disepakati bareng bro supaya tidak ada risiko admin lain
        // tidak sengaja menurunkan akun seed ini.
        if (hash_equals($username, self::DEFAULT_USERNAME) && $newRole !== self::ADMINISTRATOR_ROLE) {
            throw new InvalidArgumentException('The built-in "admin" account is permanently the Administrator role and cannot be changed.');
        }
        if (!in_array($newRole, self::validRoleNames(), true)) {
            throw new InvalidArgumentException('That role does not exist.');
        }
        $data = self::loadAll();
        $administratorCount = count(array_filter($data['users'], static fn (array $u) => ($u['role'] ?? '') === self::ADMINISTRATOR_ROLE));
        $found = false;
        $oldRole = '';
        foreach ($data['users'] as &$user) {
            if (hash_equals((string) $user['username'], $username)) {
                if ((string) $user['role'] === self::ADMINISTRATOR_ROLE && $newRole !== self::ADMINISTRATOR_ROLE && $administratorCount <= 1) {
                    throw new InvalidArgumentException('Cannot change the role of the last remaining Administrator account.');
                }
                $oldRole = (string) $user['role'];
                $user['role'] = $newRole;
                $found = true;
                break;
            }
        }
        unset($user);
        if (!$found) {
            throw new InvalidArgumentException('User not found.');
        }
        self::saveAll($data['users'], $data['roles']);
        AuditLog::logChange('system', 'user_change_role', "{$username}: {$oldRole}", "{$username}: {$newRole}");
    }
    public static function resetPassword(string $username, string $newPassword): void
    {
        if (strlen($newPassword) < 8) {
            throw new InvalidArgumentException('Password must be at least 8 characters.');
        }
        $data = self::loadAll();
        $found = false;
        foreach ($data['users'] as &$user) {
            if (hash_equals((string) $user['username'], $username)) {
                $user['password_hash'] = password_hash($newPassword, PASSWORD_DEFAULT);
                $user['must_change_password'] = true;
                $found = true;
                break;
            }
        }
        unset($user);
        if (!$found) {
            throw new InvalidArgumentException('User not found.');
        }
        self::saveAll($data['users'], $data['roles']);
        AuditLog::logChange('system', 'user_reset_password', "{$username}: (previous hash)", "{$username}: (new temp password, must change on next login)");
    }
    /**
     * Dua pengaman WAJIB (sama pentingnya dengan proteksi "tidak bisa
     * hapus lo0"/"tidak bisa reassign MGMT" di Network): (1) tidak
     * boleh hapus akun sendiri yang sedang login; (2) tidak boleh hapus
     * admin Administrator TERAKHIR yang tersisa - dicek berdasarkan
     * ROLE, bukan cuma jumlah total user (gateway bisa saja punya 1
     * Administrator + banyak Network Operator/Auditor - yang boleh
     * dihapus bebas selama bukan Administrator terakhir).
     */
    public static function deleteUser(string $username): void
    {
        $currentUser = self::currentUsername();
        if (hash_equals($currentUser, $username)) {
            throw new InvalidArgumentException('You cannot delete the account you are currently logged in as.');
        }
        $data = self::loadAll();
        $target = null;
        foreach ($data['users'] as $u) {
            if (hash_equals((string) $u['username'], $username)) {
                $target = $u;
                break;
            }
        }
        if ($target === null) {
            throw new InvalidArgumentException('User not found.');
        }
        if ((string) $target['role'] === self::ADMINISTRATOR_ROLE) {
            $administratorCount = count(array_filter($data['users'], static fn (array $u) => ($u['role'] ?? '') === self::ADMINISTRATOR_ROLE));
            if ($administratorCount <= 1) {
                throw new InvalidArgumentException('Cannot delete the last remaining Administrator account.');
            }
        }
        $remaining = array_values(array_filter(
            $data['users'],
            static fn (array $u) => !hash_equals((string) $u['username'], $username)
        ));
        self::saveAll($remaining, $data['roles']);
        AuditLog::logChange('system', 'user_delete', "{$username} (role: {$target['role']})", '(deleted)');
    }
    /**
     * GERBANG LISENSI Agustus 2026: role CUSTOM (di luar Administrator
     * bawaan) adalah fitur Pro. Starter roles ("Network Operator",
     * "Auditor") yang SUDAH ada dari bootstrap TIDAK terpengaruh -
     * gerbang ini cuma untuk role BARU yang admin buat sendiri lewat
     * fungsi ini.
     */
    public static function createRole(string $name, array $permissions): void
    {
        self::requireProLicense('Custom roles');
        $name = trim($name);
        if ($name === '') {
            throw new InvalidArgumentException('Role name cannot be empty.');
        }
        if (strcasecmp($name, self::ADMINISTRATOR_ROLE) === 0) {
            throw new InvalidArgumentException('"Administrator" is a reserved built-in role name.');
        }
        $data = self::loadAll();
        foreach ($data['roles'] as $r) {
            if (strcasecmp((string) $r['name'], $name) === 0) {
                throw new InvalidArgumentException('A role with that name already exists.');
            }
        }
        $clean = self::sanitizePermissions($permissions);
        $data['roles'][] = ['name' => $name, 'permissions' => $clean];
        self::saveAll($data['users'], $data['roles']);
        AuditLog::logChange('system', 'role_create', '(none)', "{$name}: " . json_encode($clean));
    }
    public static function updateRole(string $name, array $permissions): void
    {
        // TIDAK digerbang - MENGEDIT role yang sudah ada (termasuk 2
        // starter roles bawaan CE) harus tetap boleh walau CE, karena
        // role itu sendiri sudah ada sejak bootstrap, bukan "membuat
        // baru". Gerbang cuma di createRole() (membuat role BARU).
        $data = self::loadAll();
        $found = false;
        $oldPermissions = [];
        foreach ($data['roles'] as &$r) {
            if ($r['name'] === $name) {
                $oldPermissions = (array) $r['permissions'];
                $r['permissions'] = self::sanitizePermissions($permissions);
                $found = true;
                break;
            }
        }
        unset($r);
        if (!$found) {
            throw new InvalidArgumentException('Role not found.');
        }
        self::saveAll($data['users'], $data['roles']);
        AuditLog::logChange('system', 'role_update', "{$name}: " . json_encode($oldPermissions), "{$name}: " . json_encode(self::sanitizePermissions($permissions)));
    }
    /**
     * Cegah hapus role yang masih dipakai user manapun - kalau
     * diizinkan, user yang tersisa akan punya nama role yang tidak
     * cocok dengan role manapun (currentPermission() akan fail-closed
     * ke 'none' untuk mereka - membingungkan, bukan kesalahan tapi juga
     * bukan pengalaman yang baik, jadi dicegah dari akarnya).
     */
    public static function deleteRole(string $name): void
    {
        $data = self::loadAll();
        $inUse = array_filter($data['users'], static fn (array $u) => ($u['role'] ?? '') === $name);
        if (!empty($inUse)) {
            $usernames = implode(', ', array_map(static fn (array $u) => (string) $u['username'], $inUse));
            throw new InvalidArgumentException("Cannot delete this role - still assigned to: {$usernames}. Reassign them first.");
        }
        $remaining = array_values(array_filter($data['roles'], static fn (array $r) => $r['name'] !== $name));
        if (count($remaining) === count($data['roles'])) {
            throw new InvalidArgumentException('Role not found.');
        }
        self::saveAll($data['users'], $remaining);
        AuditLog::logChange('system', 'role_delete', $name, '(deleted)');
    }
    /** @return array<string,string> */
    private static function sanitizePermissions(array $permissions): array
    {
        $clean = [];
        foreach (self::ASSIGNABLE_CATEGORIES as $cat) {
            $value = (string) ($permissions[$cat] ?? 'none');
            $clean[$cat] = in_array($value, self::PERMISSION_LEVELS, true) ? $value : 'none';
        }
        return $clean;
    }
    public static function requireLogin(): void
    {
        if (empty($_SESSION['ntpsense_admin'])) {
            header('Location: /login.php');
            exit;
        }
        if (!empty($_SESSION['ntpsense_must_change_password'])
            && ($_SERVER['SCRIPT_NAME'] ?? '') !== '/change-password.php') {
            header('Location: /change-password.php');
            exit;
        }
    }
    public static function logout(): void
    {
        $username = self::currentUsername();
        if ($username !== '') {
            AuditLog::logLogout($username);
        }
        $_SESSION = [];
        session_destroy();
    }
}
