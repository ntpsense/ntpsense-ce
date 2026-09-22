<?php
/**
 * lib/license.php
 *
 * Verifikasi file license trial NTP-InetGateway menggunakan
 * kriptografi asymmetric Ed25519 (PHP sodium, bawaan standar sejak
 * PHP 7.2 - TIDAK butuh dependency tambahan apa pun, lihat Doc 6
 * Bab 18 untuk riset yang mendasari keputusan ini).
 *
 * ARSITEKTUR KEAMANAN (penting dipahami sebelum mengubah file ini):
 *   - Public key di bawah ini HANYA bisa dipakai untuk VERIFIKASI,
 *     TIDAK BISA dipakai membuat license baru (sifat dasar
 *     kriptografi asymmetric/Ed25519). Walau seluruh source code
 *     ini dibongkar pihak lain, mereka TETAP TIDAK BISA membuat
 *     file license palsu yang valid - berbeda fundamental dari
 *     HMAC simetris yang dipakai verifikasi backup config (Bab 13),
 *     yang sengaja memang BISA dipakai kedua arah (generate dan
 *     verify) karena tujuannya berbeda (portabilitas antar gateway,
 *     bukan pencegahan pemalsuan oleh pihak ketiga).
 *   - Secret key TIDAK PERNAH ada di file ini atau di mana pun pada
 *     produk - hanya dipegang NTPSense sendiri, dipakai lewat
 *     generate-license-file.php yang berjalan OFFLINE di komputer
 *     NTPSense (lihat Doc 6 Bab 18).
 *
 * PENTING: payload yang diverifikasi signature-nya BUKAN representasi
 * JSON (berisiko ambigu antar encoder), melainkan field yang digabung
 * dengan delimiter '|' dalam urutan FIXED yang harus PERSIS SAMA
 * dengan generate-license-file.php. JANGAN ubah urutan/delimiter di
 * sini tanpa mengubah kedua sisi secara bersamaan.
 *
 * ============================================================
 * PERLUASAN Agustus 2026 - Grace period & model renewal 1-tahun
 * ============================================================
 * Sejak kebijakan durasi license Pro berubah dari "sekali terbit
 * lama" ke "1 tahun + renewal" (lihat catatan kebijakan di
 * generate-license-file.php), dua kondisi baru perlu dibedakan dari
 * "expired" mentah:
 *
 *   1. GRACE PERIOD - device sudah lewat tanggal `expires`, tapi
 *      masih dalam 14 hari sejak itu. Fitur Pro TETAP AKTIF selama
 *      grace period (tidak mendadak mati begitu tanggal expire
 *      lewat - pengalaman buruk untuk pelanggan bayar yang cuma
 *      telat perpanjang beberapa hari), tapi Web UI WAJIB tampilkan
 *      peringatan mendesak supaya admin sadar dan hubungi NTPSense
 *      untuk renewal.
 *   2. RENEWAL WARNING (belum expired, tapi mendekati) - device
 *      MASIH dalam masa berlaku normal, tapi tanggal expire kurang
 *      dari 30 hari lagi. Fitur Pro aktif normal, TANPA urgensi
 *      grace period, tapi Web UI tampilkan pengingat halus supaya
 *      admin punya waktu cukup mengurus renewal sebelum kepepet.
 *
 * `isFullyValid()` SENGAJA TETAP true selama grace period (constraint
 * bisnis: jangan matikan fitur Pro yang sudah dibayar cuma karena
 * telat beberapa hari) - kode PEMANGGIL (Web UI, keputusan nyalakan/
 * matikan Squid, dst) yang perlu query terpisah `isInGracePeriod`/
 * `needsRenewalWarning()` untuk tampilkan urgensi yang sesuai.
 * ============================================================
 */
declare(strict_types=1);
require_once __DIR__ . '/system_health.php';
require_once __DIR__ . '/i18n.php';
// --- GANTI nilai ini dengan PUBLIC KEY hasil
//     generate-license-keypair.php SEBELUM build ISO. Public key
//     AMAN diketahui siapa pun (lihat catatan arsitektur di atas) -
//     TIDAK PERLU dirahasiakan, TIDAK PERLU di-obfuscate.
const NTPSENSE_LICENSE_PUBLIC_KEY_B64 = 'GANTI_DENGAN_PUBLIC_KEY_BASE64_DARI_GENERATE_LICENSE_KEYPAIR_PHP';
const NTPSENSE_LICENSE_FILE_PATH = '/usr/local/etc/ntpsense/license.json';
const NTPSENSE_LICENSE_MAX_UPLOAD_BYTES = 8192; // file license SANGAT kecil, batas longgar untuk cegah upload sembarangan
// Perluasan Agustus 2026 - lihat catatan kebijakan di puncak file.
const NTPSENSE_LICENSE_GRACE_PERIOD_DAYS = 14;
const NTPSENSE_LICENSE_RENEWAL_WARNING_DAYS = 30;
/**
 * Hasil verifikasi license - dipakai konsisten di seluruh Web UI
 * supaya satu tempat saja yang menentukan "valid/tidak", bukan
 * dicek ulang dengan logic berbeda-beda di tiap halaman.
 */
final class NtpsenseLicenseStatus
{
    public function __construct(
        public readonly bool $hasLicenseFile,
        public readonly bool $signatureValid,
        public readonly bool $snPnMatches,
        public readonly bool $isExpired,
        public readonly bool $isInGracePeriod,
        public readonly ?string $customerName,
        public readonly ?string $issuedDate,
        public readonly ?string $expiresDate,
        public readonly ?int $daysRemaining,
        public readonly ?string $errorReason,
    ) {
    }
    /**
     * TETAP true selama grace period - lihat catatan kebijakan di
     * puncak file untuk alasan bisnisnya. Kode yang mengambil
     * keputusan nyalakan/matikan fitur Pro (mis. Squid, Multi-WAN
     * lanjutan, dst) cukup panggil method ini SAJA - tidak perlu tahu
     * detail grace period di titik pemanggilan manapun.
     */
    public function isFullyValid(): bool
    {
        return $this->hasLicenseFile
            && $this->signatureValid
            && $this->snPnMatches
            && !$this->isExpired;
    }
    /**
     * True kalau admin perlu diberi tahu SEGERA (grace period aktif -
     * fitur masih jalan, tapi genuinely mendesak) ATAU tanggal expire
     * sudah dekat (belum genting, tapi worth diingatkan). Web UI
     * pakai ini untuk memutuskan tampilkan banner peringatan atau
     * tidak, TANPA perlu hitung ulang logic tanggal sendiri.
     */
    public function needsRenewalWarning(): bool
    {
        if (!$this->hasLicenseFile || !$this->signatureValid || !$this->snPnMatches) {
            return false; // kondisi lain (tidak ada license, signature salah, dst) punya pesan errornya sendiri, bukan "perlu renewal"
        }
        if ($this->isInGracePeriod) {
            return true;
        }
        return $this->daysRemaining !== null
            && $this->daysRemaining >= 0
            && $this->daysRemaining <= NTPSENSE_LICENSE_RENEWAL_WARNING_DAYS;
    }
    /**
     * Pesan siap-tampil untuk banner peringatan - dipusatkan di sini
     * (bukan logic terpisah di tiap halaman) supaya nada/bahasa
     * konsisten di seluruh Web UI.
     *
     * CATATAN: sengaja TIDAK mengasumsikan t() mendukung parameter
     * interpolasi (mis. t('key', ['days' => 5])) - saya belum pernah
     * lihat isi i18n.php, dan semua pemanggilan t() yang terlihat di
     * file ini sebelumnya cuma 1 argumen (murni key statis). Angka
     * hari digabung manual lewat sprintf() di SINI, bukan diserahkan
     * ke t(), supaya tidak berisiko salah asumsi soal API yang belum
     * terverifikasi. Kalau i18n.php TERNYATA sudah mendukung
     * interpolasi, ini bisa disederhanakan nanti setelah dicek.
     */
    public function renewalWarningMessage(): ?string
    {
        if ($this->isInGracePeriod) {
            $daysLeft = NTPSENSE_LICENSE_GRACE_PERIOD_DAYS + ($this->daysRemaining ?? 0);
            return sprintf('%s (%d)', t('license.warning_grace_period'), max(0, $daysLeft));
        }
        if ($this->needsRenewalWarning()) {
            return sprintf('%s (%d)', t('license.warning_renewal_upcoming'), $this->daysRemaining ?? 0);
        }
        return null;
    }
}
/**
 * Baca dan verifikasi file license yang sedang aktif di sistem ini.
 * SELALU mengembalikan objek status (tidak pernah throw exception
 * untuk kondisi "tidak ada license" - itu kondisi NORMAL untuk
 * trial yang belum upload license sama sekali, bukan error).
 */
function ntpsense_get_license_status(): NtpsenseLicenseStatus
{
    if (!file_exists(NTPSENSE_LICENSE_FILE_PATH)) {
        return new NtpsenseLicenseStatus(
            hasLicenseFile: false,
            signatureValid: false,
            snPnMatches: false,
            isExpired: true,
            isInGracePeriod: false,
            customerName: null,
            issuedDate: null,
            expiresDate: null,
            daysRemaining: null,
            errorReason: 'no_license_file',
        );
    }
    $raw = @file_get_contents(NTPSENSE_LICENSE_FILE_PATH);
    if ($raw === false) {
        return new NtpsenseLicenseStatus(
            hasLicenseFile: true,
            signatureValid: false,
            snPnMatches: false,
            isExpired: true,
            isInGracePeriod: false,
            customerName: null,
            issuedDate: null,
            expiresDate: null,
            daysRemaining: null,
            errorReason: 'read_failed',
        );
    }
    return ntpsense_verify_license_content($raw);
}
/**
 * Verifikasi isi license MENTAH (string) - dipisah dari
 * ntpsense_get_license_status() supaya bisa dipakai juga untuk
 * memvalidasi file yang BARU DIUPLOAD sebelum disimpan permanen
 * (lihat public/system_license_upload.php).
 */
function ntpsense_verify_license_content(string $raw): NtpsenseLicenseStatus
{
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return new NtpsenseLicenseStatus(
            hasLicenseFile: true, signatureValid: false, snPnMatches: false,
            isExpired: true, isInGracePeriod: false, customerName: null, issuedDate: null,
            expiresDate: null, daysRemaining: null, errorReason: 'invalid_json',
        );
    }
    $requiredFields = ['customer-name', 'sn', 'pn', 'issued', 'expires', 'signature'];
    foreach ($requiredFields as $field) {
        if (!isset($data[$field]) || !is_string($data[$field])) {
            return new NtpsenseLicenseStatus(
                hasLicenseFile: true, signatureValid: false, snPnMatches: false,
                isExpired: true, isInGracePeriod: false, customerName: null, issuedDate: null,
                expiresDate: null, daysRemaining: null, errorReason: 'missing_field',
            );
        }
    }
    // Pengecekan ekstensi sodium WAJIB sebelum memanggil fungsi
    // sodium_* atau memakai konstanta SODIUM_* (konstanta itu
    // HANYA tersedia jika ekstensi ter-load - tidak seperti yang
    // saya asumsikan sebelumnya bahwa konstanta itu selalu tersedia
    // sebagai bagian PHP core). Nilai byte-length Ed25519 dipakai
    // sebagai literal integer (32 dan 64) karena ini nilai TETAP
    // standar Ed25519 yang tidak bergantung pada versi sodium.
    if (!extension_loaded('sodium')) {
        return new NtpsenseLicenseStatus(
            hasLicenseFile: true, signatureValid: false, snPnMatches: false,
            isExpired: true, isInGracePeriod: false, customerName: null, issuedDate: null,
            expiresDate: null, daysRemaining: null, errorReason: 'public_key_misconfigured',
        );
    }
    $publicKey = base64_decode(NTPSENSE_LICENSE_PUBLIC_KEY_B64, true);
    $signature = base64_decode($data['signature'], true);
    if ($publicKey === false || strlen($publicKey) !== 32) {
        // Public key belum diisi dengan benar di source code (32 bytes
        // = panjang standar Ed25519 public key) - ini KESALAHAN
        // KONFIGURASI BUILD, bukan kesalahan file license.
        return new NtpsenseLicenseStatus(
            hasLicenseFile: true, signatureValid: false, snPnMatches: false,
            isExpired: true, isInGracePeriod: false, customerName: null, issuedDate: null,
            expiresDate: null, daysRemaining: null, errorReason: 'public_key_misconfigured',
        );
    }
    if ($signature === false || strlen($signature) !== 64) {
        // 64 bytes = panjang standar Ed25519 detached signature.
        return new NtpsenseLicenseStatus(
            hasLicenseFile: true, signatureValid: false, snPnMatches: false,
            isExpired: true, isInGracePeriod: false, customerName: null, issuedDate: null,
            expiresDate: null, daysRemaining: null, errorReason: 'invalid_signature_format',
        );
    }
    // Susunan payload yang ditandatangani HARUS PERSIS SAMA dengan
    // generate-license-file.php - delimiter '|', urutan field fixed.
    $signingPayload = implode('|', [
        $data['customer-name'],
        $data['sn'],
        $data['pn'],
        $data['issued'],
        $data['expires'],
    ]);
    $signatureValid = sodium_crypto_sign_verify_detached($signature, $signingPayload, $publicKey);
    if (!$signatureValid) {
        return new NtpsenseLicenseStatus(
            hasLicenseFile: true, signatureValid: false, snPnMatches: false,
            isExpired: true, isInGracePeriod: false, customerName: null, issuedDate: null,
            expiresDate: null, daysRemaining: null, errorReason: 'signature_mismatch',
        );
    }
    // SN/PN dicocokkan terhadap device INI - dengan disclaimer yang
    // SAMA seperti System Health (Bab 14.7.2): nilai ini BISA SAMA
    // antar VM hasil clone dari template yang sama, sehingga
    // pencocokan ini berfungsi sebagai KORELASI KASAR, bukan kunci
    // kriptografi mutlak yang menjamin satu license = satu install.
    //
    // CATATAN Agustus 2026: perbaikan ntpsense_derive_serial_number()/
    // ntpsense_derive_part_number() (kombinasi SMBIOS UUID + MAC
    // seluruh NIC + serial disk, bukan sumber tunggal) direncanakan
    // terpisah di system_health.php - lihat pembahasan arah strategis
    // Pro. TIDAK diubah di sini karena fungsi itu didefinisikan di
    // file lain yang belum direview ulang.
    $currentSn = ntpsense_derive_serial_number();
    $currentPn = ntpsense_derive_part_number();
    $snPnMatches = ($data['sn'] === $currentSn) && ($data['pn'] === $currentPn);
    $expiresTimestamp = strtotime($data['expires'] . ' 23:59:59 UTC');
    // Perluasan Agustus 2026 - bedakan "expired keras" (lewat grace
    // period) dari "dalam grace period" (lewat expires, tapi masih
    // dalam toleransi). $isExpired sekarang berarti "lewat grace
    // period", BUKAN lagi "lewat tanggal expires mentah" seperti versi
    // sebelumnya - ini mengubah perilaku isFullyValid() secara
    // disengaja (lihat catatan kebijakan di puncak file).
    $gracePeriodEndTimestamp = $expiresTimestamp !== false
        ? $expiresTimestamp + (NTPSENSE_LICENSE_GRACE_PERIOD_DAYS * 86400)
        : false;
    $now = time();
    $isExpired = ($expiresTimestamp === false) || ($now > $gracePeriodEndTimestamp);
    $isInGracePeriod = $expiresTimestamp !== false
        && $now > $expiresTimestamp
        && $now <= $gracePeriodEndTimestamp;
    $daysRemaining = $expiresTimestamp !== false
        ? (int)ceil(($expiresTimestamp - $now) / 86400)
        : null;
    return new NtpsenseLicenseStatus(
        hasLicenseFile: true,
        signatureValid: true,
        snPnMatches: $snPnMatches,
        isExpired: $isExpired,
        isInGracePeriod: $isInGracePeriod,
        customerName: $data['customer-name'],
        issuedDate: $data['issued'],
        expiresDate: $data['expires'],
        daysRemaining: $daysRemaining,
        errorReason: !$snPnMatches ? 'sn_pn_mismatch' : null,
    );
}
/**
 * Terjemahkan errorReason teknis menjadi pesan yang bisa ditampilkan
 * ke admin - dipusatkan di sini supaya konsisten di semua halaman
 * yang menampilkan status license.
 */
function ntpsense_license_error_message(?string $errorReason): string
{
    return match ($errorReason) {
        'no_license_file' => t('license.error_no_file'),
        'read_failed' => t('license.error_read_failed'),
        'invalid_json' => t('license.error_invalid_format'),
        'missing_field' => t('license.error_invalid_format'),
        'invalid_signature_format' => t('license.error_invalid_format'),
        'signature_mismatch' => t('license.error_signature_mismatch'),
        'sn_pn_mismatch' => t('license.error_sn_pn_mismatch'),
        'public_key_misconfigured' => t('license.error_public_key_misconfigured'),
        default => t('license.error_unknown'),
    };
}
/**
 * Simpan isi file license (yang SUDAH diverifikasi signature-nya
 * oleh pemanggil - lihat catatan keamanan di puncak file ini) ke
 * lokasi permanen lewat helper privileged. Dipanggil HANYA setelah
 * ntpsense_verify_license_content() mengonfirmasi signatureValid.
 */
function ntpsense_license_save(string $content): bool
{
    $descriptorSpec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open(
        'sudo -n /usr/local/sbin/ntpsense-license-write save',
        $descriptorSpec,
        $pipes
    );
    if (!is_resource($process)) {
        return false;
    }
    fwrite($pipes[0], $content);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    return $exitCode === 0;
}
/**
 * Hitung ulang status license SAAT INI dan beritahu helper privileged
 * untuk menyalakan/mematikan Squid sesuai keputusan tersebut - PHP
 * yang MENGHITUNG (lewat ntpsense_get_license_status()), helper yang
 * MENGEKSEKUSI AKIBATNYA pada service (lihat catatan desain pada
 * helper ntpsense-license-write).
 *
 * Dipanggil dari DUA tempat: (1) segera setelah upload license baru
 * berhasil disimpan, supaya Squid langsung menyala kembali tanpa
 * menunggu siklus cron; (2) oleh cron harian (lihat install-
 * gateway.sh) untuk menangkap kasus license yang BARU SAJA expired
 * sejak terakhir dicek, TANPA ada aksi admin apa pun.
 */
function ntpsense_license_apply_expiry_decision(): bool
{
    $status = ntpsense_get_license_status();
    $decision = $status->isFullyValid() ? 'valid' : 'expired';
    $descriptorSpec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open(
        'sudo -n /usr/local/sbin/ntpsense-license-write check-expiry',
        $descriptorSpec,
        $pipes
    );
    if (!is_resource($process)) {
        return false;
    }
    fwrite($pipes[0], $decision);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    return $exitCode === 0;
}
