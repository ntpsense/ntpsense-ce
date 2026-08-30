<?php
declare(strict_types=1);

/**
 * console-set-password.php - Jembatan CLI untuk ntpsense-console-menu.sh
 * (opsi 3 - Change password) - shell TIDAK BISA generate hash bcrypt
 * yang cocok dengan Auth.php sendiri, jadi delegasikan ke PHP lewat
 * script kecil ini. Password dibaca dari STDIN (BUKAN argv) supaya
 * TIDAK bocor ke process list ('ps') selagi command jalan.
 *
 * Usage: printf '%s' "$password" | php console-set-password.php <username>
 * Output: "OK" (exit 0) kalau sukses, pesan error ke STDERR (exit 1) kalau gagal.
 */
require __DIR__ . '/Auth.php';

if ($argc < 2 || trim((string) $argv[1]) === '') {
    fwrite(STDERR, "Usage: php console-set-password.php <username>  (password dibaca dari STDIN)\n");
    exit(1);
}

$username = $argv[1];
$password = trim((string) fgets(STDIN));

if (strlen($password) < 8) {
    fwrite(STDERR, "ERROR: password minimal 8 karakter.\n");
    exit(1);
}

$ok = Auth::changePasswordForUser($username, $password);

if ($ok) {
    echo "OK\n";
    exit(0);
}

fwrite(STDERR, "ERROR: username '{$username}' tidak ditemukan di Web UI (webui-admin.json).\n");
exit(1);
