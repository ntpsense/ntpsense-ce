<?php
declare(strict_types=1);

/**
 * AuditLog - "Users Activity" log, TERPISAH dari System Logs (yang itu
 * level OS/service). Ini level "siapa ngapain di Web UI" - polanya
 * diriset dari pfSense ("Configuration Change: admin@IP: Firewall:
 * Rules - saved/edited a firewall rule") dan FortiGate (field cfgattr
 * berisi old->new value untuk perubahan yang datanya tersedia).
 *
 * Dipanggil dari SATU titik tunggal (Auth::requireCategory() dan
 * Auth::attempt()) supaya SEMUA 12 halaman otomatis ke-log tanpa perlu
 * disentuh satu-satu - trade-off jujur: baris otomatis ini mencatat
 * "percobaan LOLOS validasi RBAC" (result=allowed), BUKAN jaminan aksi
 * di dalam handler halaman itu benar-benar sukses secara bisnis (mis.
 * validasi IP gagal di dalamnya tetap tercatat 'allowed' di sini,
 * karena RBAC-nya sendiri memang lolos). Untuk kasus bernilai tinggi
 * yang datanya sudah tersedia di kode (ganti role, ganti subnet
 * interface), cfgattr diisi manual dengan old->new value sungguhan
 * lewat logChange().
 */
final class AuditLog
{
    // RCA (persis sama dengan webui-admin.json di Auth.php): direktori
    // /usr/local/etc/ntpsense/ SENDIRI adalah root:wheel, PHP-FPM
    // (user 'www') TIDAK bisa mkdir() folder baru langsung di bawahnya
    // - "Permission denied". File log ini HARUS ada di dalam 'webui/'
    // yang SUDAH dibuat root:ntpsenseweb 0770 (oleh Auth::ensureBootstrapped()
    // atau instalasi awal), bukan bikin folder 'logs/' baru sejajar dengannya.
    private const LOG_FILE = '/usr/local/etc/ntpsense/webui/users-activity.jsonl';
    private const ROTATE_BYTES = 5 * 1024 * 1024; // 5MB, sama dengan kesepakatan awal untuk log ini
    private const KEEP_ROTATED = 1; // simpan 1 file rotasi sebelumnya (.1)

    // Field POST yang TIDAK PERNAH ikut masuk ke log, meski cuma nama
    // field-nya dicatat (bukan isinya) - mencegah kebocoran credential/
    // key lewat log audit itu sendiri (log ini bisa dibaca role
    // Administrator manapun, harus aman dari isi sensitif).
    private const REDACTED_FIELDS = ['password', 'new_password', 'confirm_password', 'key_pem', 'cert_pem'];
    private const MAX_DETAIL_LENGTH = 300;

    private static function ensureDir(): void
    {
        $dir = dirname(self::LOG_FILE);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }
    }

    private static function rotateIfNeeded(): void
    {
        if (is_file(self::LOG_FILE) && filesize(self::LOG_FILE) > self::ROTATE_BYTES) {
            $rotated = self::LOG_FILE . '.1';
            if (self::KEEP_ROTATED >= 1) {
                @rename(self::LOG_FILE, $rotated);
            } else {
                @unlink(self::LOG_FILE);
            }
        }
    }

    /**
     * Ringkas $_POST jadi satu baris teks pendek untuk kolom cfgattr
     * otomatis - field sensitif diredaksi, nilai panjang dipotong.
     * Dipakai sebagai fallback kalau tidak ada logChange() manual yang
     * lebih presisi untuk aksi tersebut.
     */
    public static function summarizePost(array $post): string
    {
        $parts = [];
        foreach ($post as $key => $value) {
            if ($key === 'form') {
                continue;
            }
            if (in_array($key, self::REDACTED_FIELDS, true)) {
                $parts[] = "{$key}=<redacted>";
                continue;
            }
            if (is_array($value)) {
                $value = json_encode($value);
            }
            $value = (string) $value;
            if (strlen($value) > 60) {
                $value = substr($value, 0, 60) . '...';
            }
            $parts[] = "{$key}={$value}";
        }
        $summary = implode(', ', $parts);
        return strlen($summary) > self::MAX_DETAIL_LENGTH ? substr($summary, 0, self::MAX_DETAIL_LENGTH) . '...' : $summary;
    }

    private static function write(array $entry): void
    {
        try {
            self::ensureDir();
            self::rotateIfNeeded();
            @file_put_contents(self::LOG_FILE, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);
            @chmod(self::LOG_FILE, 0640);
        } catch (\Throwable $e) {
            // Logging TIDAK BOLEH PERNAH menggagalkan halaman yang
            // memanggilnya - AuditLog di-require dari Auth.php yang
            // dipakai SEMUA halaman, termasuk login/logout yang masih
            // perlu header() redirect setelahnya. Kalau menulis log
            // gagal (disk penuh, permission berubah, dst), diamkan saja
            // di sini; fitur utama (login, ganti role, dst) tetap harus
            // berhasil selama logikanya sendiri benar.
        }
    }

    private static function clientIp(): string
    {
        return (string) ($_SERVER['REMOTE_ADDR'] ?? '-');
    }

    /** Login berhasil/gagal - dipanggil dari Auth::attempt(). */
    public static function logLogin(string $username, bool $success, string $reason = ''): void
    {
        self::write([
            'ts' => time(),
            'username' => $username !== '' ? $username : '(unknown)',
            'ip' => self::clientIp(),
            'category' => 'auth',
            'action' => 'login',
            'result' => $success ? 'success' : 'failed',
            'cfgattr' => $reason,
        ]);
    }

    public static function logLogout(string $username): void
    {
        self::write([
            'ts' => time(),
            'username' => $username,
            'ip' => self::clientIp(),
            'category' => 'auth',
            'action' => 'logout',
            'result' => 'success',
            'cfgattr' => '',
        ]);
    }

    /**
     * EULA diterima (implisit, saat login berhasil pertama kali) -
     * dicatat terikat ke username yang SUDAH terverifikasi oleh
     * Auth::attempt(), bukan input $_POST mentah - lihat catatan di
     * login.php soal kenapa titik pencatatan ini yang dipilih (setelah
     * password terbukti benar, bukan sebelum).
     */
    public static function logEulaAcceptance(string $username, string $eulaVersion): void
    {
        self::write([
            'ts' => time(),
            'username' => $username !== '' ? $username : '(unknown)',
            'ip' => self::clientIp(),
            'category' => 'auth',
            'action' => 'eula_acceptance',
            'result' => 'success',
            'cfgattr' => "EULA version: {$eulaVersion}",
        ]);
    }

    /**
     * Dipanggil otomatis dari Auth::requireCategory()/requireAdministrator()
     * untuk SETIAP request POST yang lolos maupun ditolak RBAC - lihat
     * catatan jujur soal makna 'allowed' di komentar kelas di atas.
     */
    public static function logAccess(string $category, string $action, string $result, string $cfgattr = ''): void
    {
        self::write([
            'ts' => time(),
            'username' => Auth::currentUsername() ?: '(unknown)',
            'ip' => self::clientIp(),
            'category' => $category,
            'action' => $action,
            'result' => $result,
            'cfgattr' => $cfgattr,
        ]);
    }

    /**
     * Untuk kasus bernilai tinggi yang datanya sudah tersedia jelas di
     * kode (ganti role user, ganti subnet interface, dst) - cfgattr
     * berisi old->new value SUNGGUHAN, bukan ringkasan POST otomatis.
     */
    public static function logChange(string $category, string $action, string $oldValue, string $newValue): void
    {
        self::write([
            'ts' => time(),
            'username' => Auth::currentUsername() ?: '(unknown)',
            'ip' => self::clientIp(),
            'category' => $category,
            'action' => $action,
            'result' => 'success',
            'cfgattr' => "{$oldValue} ==> {$newValue}",
        ]);
    }

    /**
     * Baca N baris terakhir (terbaru dulu) untuk ditampilkan di tab
     * "Users Activity" - baca file MENTAH+rotated (.1) kalau file utama
     * belum cukup, supaya history tidak langsung hilang tepat setelah
     * rotasi terjadi.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function tail(int $limit = 200): array
    {
        $lines = [];
        foreach ([self::LOG_FILE, self::LOG_FILE . '.1'] as $path) {
            if (!is_file($path)) {
                continue;
            }
            $fileLines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            $lines = array_merge($lines, $fileLines);
            if (count($lines) >= $limit) {
                break;
            }
        }
        $entries = array_filter(array_map(static fn (string $l) => json_decode($l, true), $lines));
        usort($entries, static fn ($a, $b) => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));
        return array_slice($entries, 0, $limit);
    }
}
