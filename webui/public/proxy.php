<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
require_once __DIR__ . '/../lib/license.php';
Auth::requireLogin();
Auth::requireCategory('proxy');
$configd = new NtpsenseConfigd();
$configdError = null;
$saveMessage = null;
$saveError = null;
$installed = false;
$running = false;
$proxyConfig = null;
$blocklistConfig = ['categories' => [], 'whitelist' => [], 'blacklist_manual' => []];
$blocklistLastUpdated = [];
$invalidDomainLines = [];
// GERBANG LISENSI Agustus 2026 (lihat compare.html - baris "Proxy
// report export (CSV/XLSX)": CE "Last 7 days" vs Pro "Full history").
// Dihitung sekali di atas, dipakai konsisten di bawah - satu titik
// kebenaran.
$isProLicensed = false;
try {
    $isProLicensed = ntpsense_get_license_status()->isFullyValid();
} catch (\Throwable $e) {
    $isProLicensed = false; // fail-closed - anggap CE kalau pengecekan lisensi sendiri error
}
// Batas khusus TAMPILAN Bandwidth Usage report untuk CE (LightSquid-
// style reporting) - TERPISAH dari retention_days (retensi arsip
// mentah), yang tidak dibatasi CE sama sekali. Lihat catatan Agustus
// 2026 di dekat pemakaian $archiveSettings di bawah.
const NTPSENSE_CE_BANDWIDTH_REPORT_DAYS = 7;
/**
 * Validasi format domain - Lapis 1 (PHP, pola Tier 1 Bab 7.5.2): cek
 * SEBELUM dikirim ke daemon, laporkan baris invalid SECARA SPESIFIK ke
 * admin (bukan dibuang diam-diam) - submission DIBATALKAN SELURUHNYA
 * kalau ada baris invalid, supaya admin tidak salah kira semua
 * tersimpan padahal sebagian ditolak. Lapis 2 (defense in depth) ada
 * di daemon Rust (is_valid_domain()) - TIDAK mempercayai lapis ini
 * begitu saja.
 */
function isValidDomainLine(string $domain): bool
{
    if ($domain === '' || strlen($domain) > 253) {
        return false;
    }
    foreach (explode('.', $domain) as $label) {
        if ($label === '' || strlen($label) > 63) {
            return false;
        }
        if ($label[0] === '-' || substr($label, -1) === '-') {
            return false;
        }
        if (!preg_match('/^[A-Za-z0-9-]+$/', $label)) {
            return false;
        }
    }
    return true;
}
/** @return array{valid: string[], invalid: string[]} */
function parseDomainTextarea(string $raw): array
{
    $valid = [];
    $invalid = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        if (isValidDomainLine($line)) {
            if (!in_array($line, $valid, true)) {
                $valid[] = $line;
            }
        } else {
            $invalid[] = $line;
        }
    }
    return ['valid' => $valid, 'invalid' => $invalid];
}
try {
    $status = $configd->call('proxy.get_config');
    $installed = (bool) ($status['installed'] ?? false);
    $running = (bool) ($status['running'] ?? false);
    $proxyConfig = $status['config'] ?? null;
    if ($installed) {
        $blResult = $configd->call('proxy.get_blocklist_config');
        $blocklistConfig = $blResult['config'] ?? $blocklistConfig;
        $blocklistLastUpdated = $blResult['last_updated'] ?? [];
    }
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
$activeTab = $_GET['tab'] ?? 'general';
if (!in_array($activeTab, ['general', 'blocklist', 'status', 'log', 'bandwidth', 'local_cache', 'acls', 'auth'], true)) {
    $activeTab = 'general';
}
// Retensi arsip historis (Log Viewer + Bandwidth Usage, permintaan bro) -
// SATU setting dipakai bersama kedua tab, bukan dua field terpisah yang
// bisa tidak sinkron - "berapa lama simpan log DAN bandwidth" diminta
// sebagai satu keputusan, bukan dua.
$archiveSettings = ['retention_days' => 30];
try {
    $archiveSettings = $configd->call('proxy.get_archive_settings');
} catch (NtpsenseConfigdException $e) {
    // Diam - default 30 hari dipakai kalau daemon belum pernah simpan
    // setting ini (instalasi baru).
}
// CATATAN Agustus 2026 (dikoreksi setelah diskusi dengan bro): retensi
// arsip mentah (retention_days) TIDAK dibatasi CE di sini - Log Viewer
// (log request mentah Squid, alat diagnostik teknis) tetap dapat
// retensi PENUH untuk CE, sama seperti Pro. Yang dibatasi CE HANYA
// tampilan Bandwidth Usage (laporan agregat ala LightSquid - nilai
// bisnis untuk manajemen/finance, BUKAN log teknis) - lihat
// NTPSENSE_CE_BANDWIDTH_REPORT_DAYS dan clamping-nya di bawah, terpisah
// dari retention_days ini sepenuhnya.
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_archive_settings') {
    try {
        // Retensi arsip mentah - SAMA untuk CE dan Pro (lihat catatan
        // Agustus 2026 di atas soal kenapa Log Viewer tidak dibatasi CE).
        $archiveSettings = $configd->call('proxy.set_archive_settings', [
            'retention_days' => (int) ($_POST['retention_days'] ?? 30),
        ]);
        $saveMessage = 'Archive retention setting saved.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_general') {
    try {
        $result = $configd->call('proxy.set_config', [
            'enabled' => ($_POST['enabled'] ?? '') === '1',
            'port' => (int) ($_POST['port'] ?? 3128),
            'cache_size_mb' => (int) ($_POST['cache_size_mb'] ?? 1000),
        ]);
        $proxyConfig = $result['config'] ?? $proxyConfig;
        $saveMessage = 'Proxy configuration saved successfully.';
        try {
            $refreshed = $configd->call('proxy.get_config');
            $running = (bool) ($refreshed['running'] ?? false);
        } catch (NtpsenseConfigdException $e) {
            // biarkan status lama kalau refresh gagal - bukan error fatal
        }
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_blocklist') {
    $categories = array_values(array_intersect(
        (array) ($_POST['categories'] ?? []),
        ['ads', 'malware', 'phishing', 'gambling', 'porn', 'tracking', 'social_media', 'file_transfer']
    ));
    $whitelistParsed = parseDomainTextarea((string) ($_POST['whitelist'] ?? ''));
    $blacklistParsed = parseDomainTextarea((string) ($_POST['blacklist_manual'] ?? ''));
    $invalidDomainLines = array_merge($whitelistParsed['invalid'], $blacklistParsed['invalid']);
    // Pola Tier 1: submission DIBATALKAN SELURUHNYA kalau ADA baris
    // invalid - jangan simpan sebagian dan buat admin salah kira semua
    // tersimpan.
    if (!empty($invalidDomainLines)) {
        $saveError = 'The following domain(s) are not valid and nothing was saved: ' . implode(', ', $invalidDomainLines);
        // Prefill textarea dengan input ASLI (bukan hasil parse) supaya
        // admin bisa lihat+perbaiki tanpa kehilangan yang sudah diketik.
        $blocklistConfig['categories'] = $categories;
        $blocklistConfig['_raw_whitelist'] = (string) ($_POST['whitelist'] ?? '');
        $blocklistConfig['_raw_blacklist'] = (string) ($_POST['blacklist_manual'] ?? '');
    } else {
        try {
            $result = $configd->call('proxy.set_blocklist_config', [
                'categories' => $categories,
                'whitelist' => $whitelistParsed['valid'],
                'blacklist_manual' => $blacklistParsed['valid'],
            ]);
            $blocklistConfig = $result['config'] ?? $blocklistConfig;
            $saveMessage = 'Blocklist configuration saved successfully.';
        } catch (NtpsenseConfigdException $e) {
            $saveError = $e->getMessage();
        }
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_blocklist_update') {
    try {
        // Timeout LEBIH PANJANG khusus untuk action ini - download bisa
        // ratusan ribu baris per kategori (terbukti dari test nyata:
        // ads.txt sendiri 234rb baris/6.8MB), genuinely bisa >15s tanpa
        // ada masalah apa pun, BUKAN indikasi daemon macet.
        $result = $configd->call('proxy.blocklist_update', [], 60.0);
        $updated = $result['updated'] ?? [];
        $failed = $result['failed'] ?? [];
        $saveMessage = !empty($updated) ? 'Updated: ' . implode(', ', $updated) . '.' : ($result['message'] ?? 'No categories to update.');
        if (!empty($failed)) {
            $saveError = 'Failed to update: ' . implode(', ', $failed) . ' - the previous list (if any) was kept unchanged.';
        }
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_local_cache') {
    try {
        $result = $configd->call('proxy.set_local_cache', [
            'cache_mem_mb' => (int) ($_POST['cache_mem_mb'] ?? 256),
            'maximum_object_size_mb' => (int) ($_POST['maximum_object_size_mb'] ?? 4),
        ]);
        $proxyConfig = $result['config'] ?? $proxyConfig;
        $saveMessage = 'Local cache configuration saved successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_acl_add') {
    try {
        $configd->call('proxy.acl_add', [
            'source' => (string) ($_POST['source'] ?? 'any'),
            'destination' => (string) ($_POST['destination'] ?? 'any'),
            'action_type' => (string) ($_POST['action_type'] ?? ''),
            'description' => (string) ($_POST['description'] ?? ''),
        ]);
        $saveMessage = 'ACL rule added successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_acl_delete') {
    try {
        $configd->call('proxy.acl_delete', ['id' => (string) ($_POST['id'] ?? '')]);
        $saveMessage = 'ACL rule deleted successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_acl_reorder') {
    try {
        $configd->call('proxy.acl_reorder', [
            'id' => (string) ($_POST['id'] ?? ''),
            'direction' => (string) ($_POST['direction'] ?? ''),
        ]);
        $saveMessage = 'Rule order updated.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_auth_toggle') {
    try {
        $configd->call('proxy.auth_set_enabled', ['enabled' => ($_POST['enabled'] ?? '') === '1']);
        $saveMessage = 'Authentication setting updated successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_auth_add_user') {
    try {
        $configd->call('proxy.auth_add_user', [
            'username' => (string) ($_POST['username'] ?? ''),
            'password' => (string) ($_POST['password'] ?? ''),
        ]);
        $saveMessage = 'User added successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'proxy_auth_delete_user') {
    try {
        $configd->call('proxy.auth_delete_user', ['username' => (string) ($_POST['username'] ?? '')]);
        $saveMessage = 'User deleted successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && (($_POST['form'] ?? '') === 'proxy_blocklist_update' || $activeTab === 'blocklist')) {
    try {
        $refreshed = $configd->call('proxy.get_blocklist_config');
        $blocklistLastUpdated = $refreshed['last_updated'] ?? $blocklistLastUpdated;
    } catch (NtpsenseConfigdException $e) {
        // biarkan nilai lama kalau refresh gagal - bukan error fatal
    }
}
/** Format byte jadi bentuk terbaca manusia (KB/MB/GB). */
function formatBytes(int $bytes): string
{
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    }
    if ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    }
    if ($bytes >= 1024) {
        return number_format($bytes / 1024, 1) . ' KB';
    }
    return $bytes . ' B';
}
$bandwidthData = null;
// "Make Report from ... to ..." - kalau kedua parameter tanggal ada di
// URL, panggil action rentang (arsip historis + hari ini live) alih-alih
// live-only. isReportRange dipakai berulang di bawah (rendering + label
// export) supaya satu keputusan konsisten di semua tempat.
//
// CATATAN Agustus 2026: $reportFrom/$reportTo di bawah ini SENGAJA
// TIDAK dipangkas untuk CE - dipakai bersama oleh Log Viewer (log
// mentah Squid, TIDAK dibatasi CE) DAN Bandwidth Usage (laporan
// agregat ala LightSquid, DIBATASI CE). Variabel terpisah
// $bwReportFrom/$ceBandwidthWasClamped di bawah menangani pembatasan
// KHUSUS untuk Bandwidth Usage saja - lihat diskusi dengan bro:
// "log system ok, untuk reporting look like lightsquid tidak" -
// kedua fitur ini SENGAJA dipisah statusnya, bukan berbagi satu
// gerbang seperti versi sebelumnya.
$reportFrom = $_GET['from'] ?? '';
$reportTo = $_GET['to'] ?? '';
$isReportRange = $reportFrom !== '' && $reportTo !== '';
// Versi KHUSUS Bandwidth Usage - dipangkas untuk CE, TIDAK memengaruhi
// $reportFrom asli yang dipakai Log Viewer.
$bwReportFrom = $reportFrom;
$ceBandwidthWasClamped = false;
if (!$isProLicensed && $isReportRange) {
    $ceEarliestAllowed = date('Y-m-d', strtotime('-' . NTPSENSE_CE_BANDWIDTH_REPORT_DAYS . ' days'));
    if ($bwReportFrom < $ceEarliestAllowed) {
        $bwReportFrom = $ceEarliestAllowed;
        $ceBandwidthWasClamped = true;
    }
}
if ($installed && $activeTab === 'bandwidth') {
    try {
        if ($isReportRange) {
            $bandwidthData = $configd->call('proxy.get_bandwidth_range', ['from' => $bwReportFrom, 'to' => $reportTo], 30.0);
        } else {
            $bandwidthData = $configd->call('proxy.get_bandwidth_usage', [], 30.0);
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
// Export CSV (permintaan bro langsung) - HARUS ditangani DI SINI, sebelum
// layout_header.php mengirim HTML apa pun (PHP header() gagal senyap kalau
// output sudah mulai terkirim). Mengekspor pandangan yang SEDANG AKTIF
// (zone/client/domain, dari parameter 'view' yang sama dipakai tab-nya
// sendiri) - bukan endpoint terpisah, supaya tombol export selalu
// konsisten dengan apa yang admin lihat di layar saat itu. Nama file
// menyertakan rentang tanggal kalau ini laporan historis, atau tanggal
// hari ini kalau live - supaya admin tidak bingung file mana mewakili
// rentang mana kalau export beberapa kali.
if ($installed && $activeTab === 'bandwidth' && $bandwidthData && ($_GET['export'] ?? '') === 'csv') {
    $requestedView = $_GET['view'] ?? 'zone';
    $exportView = in_array($requestedView, ['zone', 'client', 'domain'], true) ? $requestedView : 'zone';
    $dateLabel = $isReportRange ? "{$bwReportFrom}_to_{$reportTo}" : date('Y-m-d');
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="ntpsense-proxy-bandwidth-' . $exportView . '-' . $dateLabel . '.csv"');
    $out = fopen('php://output', 'w');
    if ($exportView === 'zone') {
        fputcsv($out, ['Zone', 'Bytes'], ',', '"', '\\');
        foreach ($bandwidthData['zones'] ?? [] as $z) {
            fputcsv($out, [$z['label'], $z['bytes']], ',', '"', '\\');
        }
    } elseif ($exportView === 'client') {
        fputcsv($out, ['Client IP', 'Bytes'], ',', '"', '\\');
        foreach ($bandwidthData['clients'] ?? [] as $c) {
            fputcsv($out, [$c['ip'], $c['bytes']], ',', '"', '\\');
        }
    } else {
        fputcsv($out, ['Domain', 'Bytes', 'Hits'], ',', '"', '\\');
        foreach ($bandwidthData['domains'] ?? [] as $d) {
            fputcsv($out, [$d['domain'], $d['bytes'], $d['hits']], ',', '"', '\\');
        }
    }
    fclose($out);
    exit;
}
$aclRules = [];
if ($installed && $activeTab === 'acls') {
    try {
        $aclRules = $configd->call('proxy.acl_list')['rules'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
$authConfig = ['enabled' => false, 'usernames' => []];
if ($installed && $activeTab === 'auth') {
    try {
        $authConfig = $configd->call('proxy.auth_get_config')['config'] ?? $authConfig;
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
$proxyStatus = null;
$proxyLog = null;
if ($installed && $activeTab === 'status') {
    try {
        $proxyStatus = $configd->call('proxy.get_status');
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
if ($installed && $activeTab === 'log') {
    try {
        // GERBANG LISENSI Agustus 2026: Historical Report (rentang
        // tanggal + export) untuk Log Viewer sekarang PRO-ONLY (dikoreksi
        // setelah testing bro di HQ candidate Pro - beda dari Bandwidth
        // Usage yang TETAP dapat versi 7-hari untuk CE). CE SELALU pakai
        // live-tail di sini, TIDAK PEDULI apa isi $isReportRange/parameter
        // URL from&to - bukan cuma UI yang disembunyikan, tapi logic
        // fetch-nya sendiri diabaikan untuk CE, supaya tidak bisa
        // di-bypass dengan mengetik URL manual (?tab=log&from=...&to=...).
        if ($isProLicensed && $isReportRange) {
            $proxyLog = $configd->call('proxy.get_log_range', ['from' => $reportFrom, 'to' => $reportTo, 'limit' => 5000], 30.0);
            $proxyLog['exists'] = !empty($proxyLog['lines']);
            $proxyLog['log'] = implode("\n", $proxyLog['lines'] ?? []);
        } else {
            $proxyLog = $configd->call('proxy.get_log', ['lines' => 200]);
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
// Export Log Viewer - baris log mentah Squid TIDAK naturally berbentuk
// kolom CSV (space-separated apa adanya, bukan comma) - diekspor sebagai
// file .log teks polos yang mempertahankan format ASLI Squid, supaya
// tetap bisa diproses ulang oleh tool lain yang sudah paham format itu
// (mis. diimpor ke Lightsquid/analizer lain) - bukan dipaksa jadi CSV
// palsu yang justru menyulitkan.
// GERBANG LISENSI: export Log Viewer sekarang Pro-only juga, konsisten
// dengan Historical Report di atas - CE tidak lihat tombolnya di UI,
// dan endpoint ini SENDIRI menolak kalau ada yang coba akses URL
// export secara langsung tanpa lewat UI.
if ($installed && $isProLicensed && $activeTab === 'log' && $proxyLog && ($_GET['export'] ?? '') === 'csv') {
    $dateLabel = $isReportRange ? "{$reportFrom}_to_{$reportTo}" : date('Y-m-d');
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="ntpsense-proxy-log-' . $dateLabel . '.log"');
    echo $proxyLog['log'] ?? '';
    exit;
}
$tabLabels = ['general' => 'General', 'local_cache' => 'Local cache', 'acls' => 'ACLs', 'auth' => 'Authentication', 'blocklist' => 'Blocklist', 'status' => 'Status', 'log' => 'Log viewer', 'bandwidth' => 'Bandwidth usage'];
$pageTitle = 'Proxy';
$activeNavItem = 'proxy';
// Layer 1 (app header) - konsisten dengan pola Firewall/IPsec/NAT.
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';
if (!$installed) {
    $categoryLabel = 'Proxy';
    $categoryIcon = 'ti-server-2';
    require __DIR__ . '/../templates/plugin_not_installed.php';
    require __DIR__ . '/../templates/layout_footer.php';
    exit;
}
?>
<div style="margin-bottom:16px;">
  <span style="font-size:13px; color:#374151;">Squid status:</span>
  <?php if ($running): ?>
    <span class="ntp-badge ntp-badge-success">Running</span>
  <?php else: ?>
    <span class="ntp-badge ntp-badge-warning">Stopped</span>
  <?php endif; ?>
</div>
<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch proxy status: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($saveMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($saveMessage) ?></div>
<?php endif; ?>
<?php if ($saveError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($saveError) ?></div>
<?php endif; ?>
<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=general" class="ntp-tab<?= $activeTab === 'general' ? ' active' : '' ?>">General</a>
  <a href="?tab=local_cache" class="ntp-tab<?= $activeTab === 'local_cache' ? ' active' : '' ?>">Local cache</a>
  <a href="?tab=acls" class="ntp-tab<?= $activeTab === 'acls' ? ' active' : '' ?>">ACLs</a>
  <a href="?tab=auth" class="ntp-tab<?= $activeTab === 'auth' ? ' active' : '' ?>">Authentication</a>
  <a href="?tab=status" class="ntp-tab<?= $activeTab === 'status' ? ' active' : '' ?>">Status</a>
  <a href="?tab=log" class="ntp-tab<?= $activeTab === 'log' ? ' active' : '' ?>">Log viewer</a>
  <a href="?tab=bandwidth" class="ntp-tab<?= $activeTab === 'bandwidth' ? ' active' : '' ?>">Bandwidth usage</a>
  <a href="?tab=blocklist" class="ntp-tab<?= $activeTab === 'blocklist' ? ' active' : '' ?>">Blocklist</a>
</div>
<?php if ($activeTab === 'general' && $proxyConfig): ?>
<form method="post">
  <input type="hidden" name="form" value="proxy_general">
  <div class="ntp-card">
    <div class="ntp-card-header">General</div>
    <div style="padding:14px; display:grid; grid-template-columns:160px 1fr; gap:14px 16px; align-items:start;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">Proxy server</label>
      <select name="enabled" style="max-width:200px;">
        <option value="0" <?= !$proxyConfig['enabled'] ? 'selected' : '' ?>>Disabled</option>
        <option value="1" <?= $proxyConfig['enabled'] ? 'selected' : '' ?>>Enabled</option>
      </select>
      <label style="font-size:13px; color:#374151; padding-top:8px;">Proxy port</label>
      <input type="number" name="port" value="<?= htmlspecialchars((string) $proxyConfig['port']) ?>" min="1" max="65535" style="max-width:200px;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">Cache size (MB)</label>
      <input type="number" name="cache_size_mb" value="<?= htmlspecialchars((string) $proxyConfig['cache_size_mb']) ?>" min="100" style="max-width:200px;">
    </div>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
      Clients on LAN1 and any OPT interface with a LAN or DMZ role can use this proxy. Point client browsers to this gateway's LAN IP address on the configured port.
    </p>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
</form>
<?php endif; ?>
<?php if ($activeTab === 'local_cache' && $proxyConfig): ?>
<form method="post">
  <input type="hidden" name="form" value="proxy_local_cache">
  <div class="ntp-card">
    <div class="ntp-card-header">Local cache</div>
    <div style="padding:14px; display:grid; grid-template-columns:220px 1fr; gap:14px 16px; align-items:start;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">Memory cache size (MB)</label>
      <input type="number" name="cache_mem_mb" value="<?= htmlspecialchars((string) ($proxyConfig['cache_mem_mb'] ?? 256)) ?>" min="16" style="max-width:200px;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">Maximum object size (MB)</label>
      <input type="number" name="maximum_object_size_mb" value="<?= htmlspecialchars((string) ($proxyConfig['maximum_object_size_mb'] ?? 4)) ?>" min="1" style="max-width:200px;">
    </div>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
      Memory cache holds frequently-requested objects in RAM for the fastest response. Objects larger than the maximum size are always fetched fresh rather than cached (on disk or in memory).
    </p>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
</form>
<?php endif; ?>
<?php if ($activeTab === 'acls'): ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Custom ACLs</div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      Rules are evaluated top to bottom, the first match wins, and they take priority over the whitelist/blacklist/blocklist below. Use this for finer-grained access control by source network or destination domain.
    </p>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead>
      <tr><th>Action</th><th>Source</th><th>Destination</th><th>Description</th><th>Manage</th></tr>
      </thead>
      <tbody>
      <?php if (empty($aclRules)): ?>
        <tr><td colspan="5" style="color:#6b7280;">No custom ACL rules defined.</td></tr>
      <?php endif; ?>
      <?php foreach ($aclRules as $idx => $rule): ?>
        <tr>
          <td>
            <?php if ($rule['action'] === 'allow'): ?>
              <span class="ntp-badge ntp-badge-success">allow</span>
            <?php else: ?>
              <span class="ntp-badge ntp-badge-warning">deny</span>
            <?php endif; ?>
          </td>
          <td><?= htmlspecialchars($rule['source']) ?></td>
          <td><?= htmlspecialchars($rule['destination']) ?></td>
          <td><?= htmlspecialchars($rule['description'] ?? '') ?></td>
          <td>
            <form method="post" style="margin:0; display:inline-block;">
              <input type="hidden" name="form" value="proxy_acl_reorder">
              <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
              <input type="hidden" name="direction" value="up">
              <button type="submit" title="Move up" <?= $idx === 0 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === 0 ? 'default' : 'pointer' ?>; color:<?= $idx === 0 ? '#d1d5db' : '#374151' ?>; padding:4px;">
                <i class="ti ti-arrow-up" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
            <form method="post" style="margin:0; display:inline-block;">
              <input type="hidden" name="form" value="proxy_acl_reorder">
              <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
              <input type="hidden" name="direction" value="down">
              <button type="submit" title="Move down" <?= $idx === count($aclRules) - 1 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === count($aclRules) - 1 ? 'default' : 'pointer' ?>; color:<?= $idx === count($aclRules) - 1 ? '#d1d5db' : '#374151' ?>; padding:4px;">
                <i class="ti ti-arrow-down" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
            <form method="post" style="margin:0; display:inline-block;">
              <input type="hidden" name="form" value="proxy_acl_delete">
              <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
              <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
    <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:grid; grid-template-columns:repeat(5, 1fr); gap:10px; align-items:end;">
      <input type="hidden" name="form" value="proxy_acl_add">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Action</label>
        <select name="action_type" required style="width:100%;">
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Source</label>
        <input type="text" name="source" value="any" style="width:100%;" placeholder="10.252.1.0/24 or any">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Destination</label>
        <input type="text" name="destination" value="any" style="width:100%;" placeholder="example.com or any">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Description</label>
        <input type="text" name="description" style="width:100%;">
      </div>
      <div>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add rule</button>
      </div>
    </form>
  </div>
<?php endif; ?>
<?php if ($activeTab === 'auth'): ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Basic Authentication</div>
    <form method="post" style="padding:14px; display:flex; align-items:center; gap:12px;">
      <input type="hidden" name="form" value="proxy_auth_toggle">
      <label style="font-size:13px; color:#374151;">Require authentication:</label>
      <select name="enabled" onchange="this.form.submit()" style="max-width:200px;">
        <option value="0" <?= !$authConfig['enabled'] ? 'selected' : '' ?>>Disabled</option>
        <option value="1" <?= $authConfig['enabled'] ? 'selected' : '' ?>>Enabled</option>
      </select>
      <noscript><button type="submit" style="font-size:12px; padding:6px 14px;">Apply</button></noscript>
    </form>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
      When enabled, every client must authenticate with a username/password below before the proxy allows any request. At least one user is required before this can be enabled.
    </p>
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">Users</div>
    <table class="ntp-table">
      <tr><th>Username</th><th>Manage</th></tr>
      <?php if (empty($authConfig['usernames'])): ?>
        <tr><td colspan="2" style="color:#6b7280;">No users yet.</td></tr>
      <?php endif; ?>
      <?php foreach ($authConfig['usernames'] as $username): ?>
        <tr>
          <td><?= htmlspecialchars($username) ?></td>
          <td>
            <form method="post" style="margin:0;" onsubmit="return confirm('Delete user <?= htmlspecialchars($username) ?>?');">
              <input type="hidden" name="form" value="proxy_auth_delete_user">
              <input type="hidden" name="username" value="<?= htmlspecialchars($username) ?>">
              <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
    <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:flex; align-items:end; gap:12px;">
      <input type="hidden" name="form" value="proxy_auth_add_user">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Username</label>
        <input type="text" name="username" required style="max-width:200px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Password</label>
        <input type="password" name="password" required minlength="8" style="max-width:200px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add / update user</button>
    </form>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">Password must be at least 8 characters. Submitting an existing username updates its password.</p>
  </div>
<?php endif; ?>
<?php if ($activeTab === 'blocklist'): ?>
  <?php
  $categoryLabels = [
      'ads' => 'Ads',
      'malware' => 'Malware',
      'phishing' => 'Phishing',
      'gambling' => 'Gambling',
      'porn' => 'Porn',
      'tracking' => 'Tracking',
      'social_media' => 'Social Media (Facebook, TikTok)',
      'file_transfer' => 'File Transfer (Torrent, Piracy)',
  ];
  $selectedCategories = $blocklistConfig['categories'] ?? [];
  $whitelistText = $blocklistConfig['_raw_whitelist'] ?? implode("\n", $blocklistConfig['whitelist'] ?? []);
  $blacklistText = $blocklistConfig['_raw_blacklist'] ?? implode("\n", $blocklistConfig['blacklist_manual'] ?? []);
  ?>
  <form method="post">
    <input type="hidden" name="form" value="proxy_blocklist">
    <div class="ntp-card">
      <div class="ntp-card-header">Category blocklists</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Domain lists are sourced from the Block List Project. A category takes effect only after it's saved here and then updated (see "Update blocklists now" below) at least once.
      </p>
      <div style="padding:14px; display:grid; grid-template-columns:repeat(2, 1fr); gap:10px 20px;">
        <?php foreach ($categoryLabels as $key => $label): ?>
          <label style="font-size:13px; display:flex; align-items:center; gap:8px;">
            <input type="checkbox" name="categories[]" value="<?= $key ?>" <?= in_array($key, $selectedCategories, true) ? 'checked' : '' ?>>
            <?= htmlspecialchars($label) ?>
            <?php if (isset($blocklistLastUpdated[$key])): ?>
              <span style="font-size:11px; color:#9ca3af;">(updated <?= htmlspecialchars(date('Y-m-d H:i', (int) $blocklistLastUpdated[$key])) ?>)</span>
            <?php else: ?>
              <span style="font-size:11px; color:#9ca3af;">(never updated)</span>
            <?php endif; ?>
          </label>
        <?php endforeach; ?>
      </div>
    </div>
    <div class="ntp-card">
      <div class="ntp-card-header">Whitelist (always allowed)</div>
      <div style="padding:14px;">
        <textarea name="whitelist" rows="4" style="width:100%; font-family:monospace; font-size:12px;" placeholder="example.com"><?= htmlspecialchars($whitelistText) ?></textarea>
      </div>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">One domain per line. A whitelisted domain is always allowed, even if it also appears in an active category or the manual blacklist below.</p>
    </div>
    <div class="ntp-card">
      <div class="ntp-card-header">Manual blacklist (always blocked)</div>
      <div style="padding:14px;">
        <textarea name="blacklist_manual" rows="4" style="width:100%; font-family:monospace; font-size:12px;" placeholder="example.com"><?= htmlspecialchars($blacklistText) ?></textarea>
      </div>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">One domain per line. Use this for specific domains you want blocked that aren't covered by any category above.</p>
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save blocklist configuration</button>
  </form>
  <form method="post" style="margin-top:12px;">
    <input type="hidden" name="form" value="proxy_blocklist_update">
    <button type="submit" style="background:#ffffff; color:#14213d; border:1px solid #14213d; padding:8px 18px; font-size:13px; border-radius:6px;">Update blocklists now</button>
    <span style="font-size:12px; color:#6b7280; margin-left:10px;">Downloads the latest domain lists for the categories currently enabled above.</span>
  </form>
<?php endif; ?>
<?php if ($activeTab === 'status' && $proxyStatus): ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Status</div>
    <table class="ntp-table">
      <tr>
        <th>State</th>
        <td>
          <?php if ($proxyStatus['running']): ?>
            <span class="ntp-badge ntp-badge-success">Running</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-warning">Stopped</span>
          <?php endif; ?>
        </td>
      </tr>
      <tr>
        <th>Uptime</th>
        <td><?= htmlspecialchars($proxyStatus['uptime'] ?? '—') ?></td>
      </tr>
      <tr>
        <th>Cache disk usage</th>
        <td><?= htmlspecialchars($proxyStatus['cache_disk_usage'] ?? '—') ?></td>
      </tr>
      <tr>
        <th>Active connections</th>
        <td><?= htmlspecialchars((string) ($proxyStatus['active_connections'] ?? 0)) ?></td>
      </tr>
    </table>
  </div>
<?php endif; ?>
<?php if ($activeTab === 'log'): ?>
  <?php // GERBANG LISENSI Agustus 2026: kartu Historical Report (kalender,
        // Make Report, Export) untuk Log Viewer sekarang SELURUHNYA
        // Pro-only, tidak ditampilkan sama sekali untuk CE - dikoreksi
        // dari versi sebelumnya (yang cuma batasi rentang tanggal) setelah
        // testing bro di HQ candidate Pro. CE cukup lihat tabel log
        // live + search box, tanpa UI historical apa pun. ?>
  <?php if ($isProLicensed): ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">Historical Report</div>
    <form method="get" style="padding:14px; display:flex; align-items:end; gap:10px; flex-wrap:wrap;">
      <input type="hidden" name="tab" value="log">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Make Report from</label>
        <input type="date" name="from" value="<?= htmlspecialchars($reportFrom) ?>" max="<?= date('Y-m-d') ?>" style="max-width:170px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">to</label>
        <input type="date" name="to" value="<?= htmlspecialchars($reportTo) ?>" max="<?= date('Y-m-d') ?>" style="max-width:170px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Make Report</button>
      <a href="?tab=log<?= $isReportRange ? '&from=' . htmlspecialchars($reportFrom) . '&to=' . htmlspecialchars($reportTo) : '' ?>&export=csv" style="font-size:12px; color:#14213d; border:1px solid #14213d; padding:8px 14px; border-radius:6px; text-decoration:none;">
        <i class="ti ti-download" aria-hidden="true"></i> Export
      </a>
      <?php if ($isReportRange): ?>
        <a href="?tab=log" style="font-size:12px; color:#6b7280;">Back to live view</a>
      <?php endif; ?>
    </form>
    <form method="post" style="padding:0 14px 14px; display:flex; align-items:center; gap:10px;">
      <input type="hidden" name="form" value="proxy_archive_settings">
      <label style="font-size:12px; color:#374151;">Keep history for:</label>
      <select name="retention_days" onchange="this.form.submit()" style="max-width:180px;">
        <?php foreach ([7 => '7 days', 14 => '14 days', 30 => '30 days', 60 => '60 days', 90 => '90 days', 180 => '180 days (6 months, max)'] as $val => $label): ?>
          <option value="<?= $val ?>" <?= (int) $archiveSettings['retention_days'] === $val ? 'selected' : '' ?>><?= $label ?></option>
        <?php endforeach; ?>
      </select>
      <span style="font-size:11px; color:#9ca3af;">Applies to both Log Viewer and Bandwidth Usage history.</span>
    </form>
  </div>
  <?php endif; ?>
  <div class="ntp-card">
    <div class="ntp-card-header">
      <?php if ($isProLicensed && $isReportRange): ?>
        Log viewer — <?= htmlspecialchars($reportFrom) ?> to <?= htmlspecialchars($reportTo) ?>
      <?php else: ?>
        Log viewer — access.log (last 200 lines)
      <?php endif; ?>
    </div>
    <?php if ($isProLicensed && $isReportRange && !empty($proxyLog['truncated'])): ?>
      <p style="padding:10px 14px 0; font-size:12px; color:#9a5b00;">This range has more lines than shown - displaying the most recent 5,000. Narrow the date range or use Export for the complete data.</p>
    <?php endif; ?>
    <?php $logParsedRows = $proxyLog['parsed'] ?? []; ?>
    <?php if (!empty($logParsedRows)): ?>
      <input type="text" class="ntp-table-search" data-table-target="tbl-proxy-log" placeholder="Search in results...">
      <div class="ntp-table-resizable-wrap">
      <table class="ntp-table-resizable" id="tbl-proxy-log">
        <thead>
        <tr><th style="width:160px;">Timestamp</th><th style="width:140px;">Client IP</th><th style="width:80px;">Method</th><th style="width:340px;">URL</th><th style="width:80px;">Status</th><th style="width:90px;">Size</th></tr>
        </thead>
        <tbody>
        <?php foreach ($logParsedRows as $e): ?>
          <tr>
            <td style="white-space:nowrap;"><?= htmlspecialchars($e['timestamp'] ?? '') ?></td>
            <td style="font-family:monospace;"><?= htmlspecialchars($e['client_ip'] ?? '') ?></td>
            <td><?= htmlspecialchars($e['method'] ?? '') ?></td>
            <td style="word-break:break-all;"><?= htmlspecialchars($e['url'] ?? '') ?></td>
            <td>
              <?php $st = (string) ($e['status'] ?? ''); ?>
              <?php if (str_starts_with($st, '4') || str_starts_with($st, '5')): ?>
                <span class="ntp-badge ntp-badge-warning"><?= htmlspecialchars($st) ?></span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-success"><?= htmlspecialchars($st) ?></span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($e['size'] ?? '') ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
    <?php else: ?>
      <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
        <?= ($isProLicensed && $isReportRange) ? 'No log data found for this date range - it may be outside the current retention window, or before the archive feature was enabled.' : "Log file not found yet - it's created once Squid has processed at least one request." ?>
      </p>
    <?php endif; ?>
    <div style="padding:10px 14px 14px;">
      <a href="?tab=log<?= ($isProLicensed && $isReportRange) ? '&from=' . htmlspecialchars($reportFrom) . '&to=' . htmlspecialchars($reportTo) : '' ?>" style="font-size:12px; color:#14213d;">Refresh</a>
    </div>
  </div>
<?php endif; ?>
<?php if ($activeTab === 'bandwidth' && $bandwidthData): ?>
  <?php
  $requestedView = $_GET['view'] ?? 'zone';
  $viewMode = in_array($requestedView, ['zone', 'client', 'domain'], true) ? $requestedView : 'zone';
  $zones = $bandwidthData['zones'] ?? [];
  $clients = $bandwidthData['clients'] ?? [];
  $domains = $bandwidthData['domains'] ?? [];
  $palette = ['#14213d', '#1a7f4b', '#9a5b00', '#b3261e', '#4f46e5', '#0891b2', '#c026d3', '#65a30d'];
  ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">
      Historical Report
      <?php if (!$isProLicensed): ?>
        <span class="ntp-badge ntp-badge-muted">CE: last <?= NTPSENSE_CE_BANDWIDTH_REPORT_DAYS ?> days</span>
      <?php endif; ?>
    </div>
    <?php if ($ceBandwidthWasClamped): ?>
      <p style="padding:10px 14px 0; font-size:12px; color:#92400e; background:#fffbeb; border:1px solid #fbbf24; border-radius:6px; margin:10px 14px 0; padding:8px 10px;">
        Community Edition (CE) bandwidth reporting only covers the last <?= NTPSENSE_CE_BANDWIDTH_REPORT_DAYS ?> days -
        the start date was adjusted accordingly. Raw log data itself isn't limited - see
        <a href="?tab=log&from=<?= htmlspecialchars($reportFrom) ?>&to=<?= htmlspecialchars($reportTo) ?>">Log Viewer</a>
        for the full range. <a href="https://ntpsense.com/compare.html" target="_blank" rel="noopener">NTPSense Pro</a>
        adds full-range bandwidth reporting too.
      </p>
    <?php endif; ?>
    <form method="get" style="padding:14px; display:flex; align-items:end; gap:10px; flex-wrap:wrap;">
      <input type="hidden" name="tab" value="bandwidth">
      <input type="hidden" name="view" value="<?= htmlspecialchars($viewMode) ?>">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Make Report from</label>
        <input type="date" name="from" value="<?= htmlspecialchars($bwReportFrom) ?>" <?= !$isProLicensed ? 'min="' . date('Y-m-d', strtotime('-' . NTPSENSE_CE_BANDWIDTH_REPORT_DAYS . ' days')) . '"' : '' ?> max="<?= date('Y-m-d') ?>" style="max-width:170px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">to</label>
        <input type="date" name="to" value="<?= htmlspecialchars($reportTo) ?>" max="<?= date('Y-m-d') ?>" style="max-width:170px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Make Report</button>
      <a href="?tab=bandwidth&view=<?= htmlspecialchars($viewMode) ?><?= $isReportRange ? '&from=' . htmlspecialchars($bwReportFrom) . '&to=' . htmlspecialchars($reportTo) : '' ?>&export=csv" style="font-size:12px; color:#14213d; border:1px solid #14213d; padding:8px 14px; border-radius:6px; text-decoration:none;">
        <i class="ti ti-download" aria-hidden="true"></i> Export
      </a>
      <?php if ($isReportRange): ?>
        <a href="?tab=bandwidth" style="font-size:12px; color:#6b7280;">Back to live view</a>
      <?php endif; ?>
    </form>
    <form method="post" style="padding:0 14px 14px; display:flex; align-items:center; gap:10px;">
      <input type="hidden" name="form" value="proxy_archive_settings">
      <label style="font-size:12px; color:#374151;">Keep history for:</label>
      <select name="retention_days" onchange="this.form.submit()" style="max-width:180px;">
        <?php foreach ([7 => '7 days', 14 => '14 days', 30 => '30 days', 60 => '60 days', 90 => '90 days', 180 => '180 days (6 months, max)'] as $val => $label): ?>
          <option value="<?= $val ?>" <?= (int) $archiveSettings['retention_days'] === $val ? 'selected' : '' ?>><?= $label ?></option>
        <?php endforeach; ?>
      </select>
      <span style="font-size:11px; color:#9ca3af;">Applies to both Log Viewer and Bandwidth Usage history. <?php if (!$isProLicensed): ?>Bandwidth reporting view is still capped at <?= NTPSENSE_CE_BANDWIDTH_REPORT_DAYS ?> days on CE regardless of this setting.<?php endif; ?></span>
    </form>
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">
      <?php if ($isReportRange): ?>
        Bandwidth usage — <?= htmlspecialchars($bwReportFrom) ?> to <?= htmlspecialchars($reportTo) ?>
      <?php else: ?>
        Bandwidth usage
      <?php endif; ?>
    </div>
    <form method="get" style="padding:14px; display:flex; align-items:center; gap:10px;">
      <input type="hidden" name="tab" value="bandwidth">
      <?php if ($isReportRange): ?>
        <input type="hidden" name="from" value="<?= htmlspecialchars($bwReportFrom) ?>">
        <input type="hidden" name="to" value="<?= htmlspecialchars($reportTo) ?>">
      <?php endif; ?>
      <label style="font-size:13px; color:#374151;">View:</label>
      <select name="view" onchange="this.form.submit()" style="max-width:220px;">
        <option value="zone" <?= $viewMode === 'zone' ? 'selected' : '' ?>>Total per zone</option>
        <option value="client" <?= $viewMode === 'client' ? 'selected' : '' ?>>Top 10 by client IP</option>
        <option value="domain" <?= $viewMode === 'domain' ? 'selected' : '' ?>>Top 20 domains</option>
      </select>
    </form>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
      <?= $isReportRange ? 'Combined from the archived history for this range (plus live data for today, if included).' : 'Calculated from the full access.log (all traffic recorded since the log was last rotated).' ?>
    </p>
    <?php if ($viewMode === 'zone'): ?>
      <?php if (empty($zones)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No traffic recorded yet.</p>
      <?php else: ?>
        <?php
        $total = array_sum(array_column($zones, 'bytes'));
        $gradientParts = [];
        $cursor = 0.0;
        foreach ($zones as $i => $z) {
            $pct = $total > 0 ? ($z['bytes'] / $total) * 100 : 0;
            $color = $palette[$i % count($palette)];
            $gradientParts[] = "{$color} {$cursor}% " . ($cursor + $pct) . '%';
            $cursor += $pct;
        }
        $gradient = implode(', ', $gradientParts);
        ?>
        <div style="padding:14px; display:flex; align-items:center; gap:32px; flex-wrap:wrap;">
          <div style="width:180px; height:180px; border-radius:50%; background:conic-gradient(<?= $gradient ?>); flex-shrink:0;"></div>
          <table class="ntp-table" style="max-width:400px;">
            <tr><th>Zone</th><th>Usage</th><th>Share</th></tr>
            <?php foreach ($zones as $i => $z): ?>
              <?php $pct = $total > 0 ? ($z['bytes'] / $total) * 100 : 0; ?>
              <tr>
                <td><span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:<?= $palette[$i % count($palette)] ?>; margin-right:6px;"></span><?= htmlspecialchars($z['label']) ?></td>
                <td><?= htmlspecialchars(formatBytes((int) $z['bytes'])) ?></td>
                <td><?= number_format($pct, 1) ?>%</td>
              </tr>
            <?php endforeach; ?>
          </table>
        </div>
      <?php endif; ?>
    <?php elseif ($viewMode === 'client'): ?>
      <?php if (empty($clients)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No traffic recorded yet.</p>
      <?php else: ?>
        <?php $maxBytes = max(array_column($clients, 'bytes')); ?>
        <div style="padding:14px;">
          <?php foreach ($clients as $c): ?>
            <?php $barPct = $maxBytes > 0 ? ($c['bytes'] / $maxBytes) * 100 : 0; ?>
            <div style="margin-bottom:10px;">
              <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:2px;">
                <span style="font-family:monospace;"><?= htmlspecialchars($c['ip']) ?></span>
                <span style="color:#6b7280;"><?= htmlspecialchars(formatBytes((int) $c['bytes'])) ?></span>
              </div>
              <div style="background:#e5e7eb; border-radius:4px; height:14px; overflow:hidden;">
                <div style="background:#14213d; width:<?= $barPct ?>%; height:100%;"></div>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    <?php else: ?>
      <?php if (empty($domains)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No traffic recorded yet.</p>
      <?php else: ?>
        <input type="text" class="ntp-table-search" data-table-target="tbl-top-domains" placeholder="Search in results..." style="margin:0 14px 10px; width:calc(100% - 28px);">
        <div class="ntp-table-scroll">
        <table class="ntp-table" id="tbl-top-domains">
          <thead>
          <tr><th>Domain</th><th>Bandwidth</th><th>Requests</th></tr>
          </thead>
          <tbody>
          <?php foreach ($domains as $d): ?>
            <tr>
              <td style="font-family:monospace;"><?= htmlspecialchars($d['domain']) ?></td>
              <td><?= htmlspecialchars(formatBytes((int) $d['bytes'])) ?></td>
              <td><?= number_format((int) $d['hits']) ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>
<?php endif; ?>
<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
