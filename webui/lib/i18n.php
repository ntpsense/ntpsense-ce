<?php
/**
 * lib/i18n.php
 *
 * Sistem multi-bahasa untuk Web UI, dengan filosofi yang SAMA dengan
 * install-gateway.sh: setiap teks diberi KODE (mis. 'login.username'),
 * disimpan terpisah dari logic di file locale per bahasa, dengan
 * fallback otomatis ke English kalau kode tidak ditemukan di bahasa
 * yang sedang dipilih (mis. saat menambah bahasa baru yang belum
 * lengkap diterjemahkan semua kodenya).
 *
 * CARA MENAMBAH BAHASA BARU:
 *   1. Copy lib/locales/en.php jadi lib/locales/<kode>.php (mis. ar.php
 *      untuk Arab), terjemahkan semua value-nya.
 *   2. Tambahkan <kode> ke array NTPSENSE_SUPPORTED_LOCALES di bawah.
 *   3. Tambahkan opsi di language switcher (lihat page_chrome.php).
 *   Tidak perlu mengubah logic lain di luar dua tempat itu.
 */

declare(strict_types=1);

const NTPSENSE_SUPPORTED_LOCALES = ['id', 'en'];
const NTPSENSE_DEFAULT_LOCALE = 'id';

/** @var array<string, array<string, string>> Cache locale yang sudah dimuat, supaya file tidak di-require berulang */
$GLOBALS['_ntpsense_locale_cache'] = [];

/**
 * Muat array terjemahan untuk satu locale, dengan cache in-memory
 * per request (file locale tidak besar, tapi tidak perlu require
 * ulang setiap kali t() dipanggil dalam satu request yang sama).
 *
 * @return array<string, string>
 */
function ntpsense_load_locale(string $locale): array
{
    if (isset($GLOBALS['_ntpsense_locale_cache'][$locale])) {
        return $GLOBALS['_ntpsense_locale_cache'][$locale];
    }

    $path = __DIR__ . '/locales/' . basename($locale) . '.php';

    if (!is_file($path)) {
        return [];
    }

    $strings = require $path;
    $GLOBALS['_ntpsense_locale_cache'][$locale] = $strings;

    return $strings;
}

/**
 * Set locale aktif untuk session saat ini. Memvalidasi terhadap
 * daftar locale yang didukung - locale tidak dikenal akan diabaikan
 * (tetap pakai locale sebelumnya / default).
 */
function ntpsense_set_locale(string $locale): void
{
    if (in_array($locale, NTPSENSE_SUPPORTED_LOCALES, true)) {
        $_SESSION['locale'] = $locale;
    }
}

/**
 * Ambil locale aktif untuk session saat ini, fallback ke default
 * kalau belum pernah diset.
 */
function ntpsense_get_locale(): string
{
    return $_SESSION['locale'] ?? NTPSENSE_DEFAULT_LOCALE;
}

/**
 * Terjemahkan satu kode pesan ke teks sesuai locale aktif, dengan
 * fallback ke English kalau kode tidak ditemukan di locale aktif,
 * dan fallback ke kode itu sendiri (dibungkus tanda kurung siku)
 * kalau bahkan English pun tidak punya kode tersebut - supaya
 * developer langsung sadar ada kode yang belum diterjemahkan di
 * MANA PUN, bukan diam-diam tampil kosong.
 *
 * @param string $code Kode pesan, mis. 'login.username'
 * @param array<string, string> $vars Variabel untuk interpolasi sederhana, mis. ['name' => 'admin']
 */
function t(string $code, array $vars = []): string
{
    $locale = ntpsense_get_locale();

    $strings = ntpsense_load_locale($locale);
    $text = $strings[$code] ?? null;

    if ($text === null && $locale !== 'en') {
        $fallback = ntpsense_load_locale('en');
        $text = $fallback[$code] ?? null;
    }

    if ($text === null) {
        return '[' . $code . ']';
    }

    foreach ($vars as $key => $value) {
        $text = str_replace('{' . $key . '}', $value, $text);
    }

    return $text;
}
