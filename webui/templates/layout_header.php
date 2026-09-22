<?php
declare(strict_types=1);
/**
 * Layout header - dipakai semua halaman setelah login. Sidebar navy
 * (#14213d) dan struktur kategori (Network/Firewall/Proxy/Security/VPN/
 * Services/Package manager/System) PERSIS sesuai mockup yang sudah
 * disetujui sebelumnya.
 *
 * REVISI (app shell 3-lapis): header + footer aplikasi ditambahkan,
 * keduanya diam (fixed via flex, bukan position:fixed) - hanya
 * .ntp-content yang scroll. Sidebar sekarang collapsible, state
 * disimpan di COOKIE (bukan localStorage) supaya PHP bisa baca nilainya
 * di server SEBELUM HTML dikirim - render class="collapsed" langsung di
 * initial paint, tidak ada kedipan sidebar-terbuka-lalu-collapse yang
 * akan terjadi kalau pakai localStorage (JS baru jalan setelah DOM
 * ter-render, dan hampir semua navigasi di app ini full-page-reload,
 * bukan SPA, jadi kedipan itu akan kelihatan di HAMPIR SETIAP klik menu).
 *
 * Variabel yang HARUS di-set oleh pemanggil sebelum include file ini:
 *   $pageTitle      - judul <title> dan breadcrumb terakhir
 *   $activeNavItem  - key nav yang di-highlight (lihat array $navItems)
 *
 * Variabel OPSIONAL:
 *   $breadcrumbTail - segmen tambahan setelah nama nav item, ditampilkan
 *                      di header sebagai "NavLabel > segmen1 > segmen2".
 *                      Bisa string tunggal (mis. "Rules") atau array
 *                      multi-level (mis. ['Rules', 'WAN1'] untuk
 *                      "Firewall > Rules > WAN1"). Kalau tidak di-set,
 *                      header cuma tampilkan nama nav item saja.
 */
if (!isset($pageTitle)) {
    $pageTitle = 'NTPSense';
}
if (!isset($activeNavItem)) {
    $activeNavItem = '';
}
if (!isset($breadcrumbTail)) {
    $breadcrumbTail = null;
}
// Normalisasi ke array supaya rendering di bawah cukup satu bentuk -
// string tunggal (pola lama) tetap didukung penuh, dibungkus jadi
// array satu elemen.
$breadcrumbTailSegments = match (true) {
    $breadcrumbTail === null => [],
    is_array($breadcrumbTail) => $breadcrumbTail,
    default => [$breadcrumbTail],
};
// Baca preferensi collapse dari cookie DI SERVER - lihat penjelasan di
// atas kenapa ini cookie, bukan localStorage.
$sidebarCollapsed = ($_COOKIE['ntpsense_sidebar_collapsed'] ?? '0') === '1';
$navItems = [
    'dashboard' => ['label' => 'Dashboard', 'icon' => 'ti-gauge', 'href' => '/index.php'],
    // Grup "Network" - Network/Multi-WAN/NAT/High Availability semuanya
    // soal konektivitas & redundansi dasar (permintaan bro langsung -
    // sidebar terasa penuh dengan 15 item flat, digrupkan supaya lebih
    // rapi). Key daun (network/multiwan/nat/ha) SENGAJA TIDAK berubah -
    // setiap halaman yang sudah set $activeNavItem = 'network' dst
    // TIDAK PERLU disentuh sama sekali, cuma cara render-nya di sini
    // yang berubah.
    'network_group' => [
        'label' => 'Network', 'icon' => 'ti-topology-star', 'group' => true,
        'children' => [
            'network'  => ['label' => 'Interfaces',        'icon' => 'ti-topology-star',   'href' => '/network.php'],
            'multiwan' => ['label' => 'Multi-WAN',         'icon' => 'ti-route',           'href' => '/multiwan.php'],
            'nat'      => ['label' => 'NAT',               'icon' => 'ti-arrows-exchange', 'href' => '/nat.php'],
        ],
    ],
    'firewall' => ['label' => 'Firewall', 'icon' => 'ti-firewall-flame', 'href' => '/firewall.php'],
    'proxy'    => ['label' => 'Proxy',    'icon' => 'ti-server-2',       'href' => '/proxy.php'],
    'security' => ['label' => 'Security', 'icon' => 'ti-shield-lock',    'href' => '/security.php'],
    // Grup "VPN" - saran langsung dari bro sendiri: WireGuard/IPsec/
    // OpenVPN jadi satu grup, bukan 3 baris terpisah.
    'vpn_group' => [
        'label' => 'VPN', 'icon' => 'ti-lock-access', 'group' => true,
        'children' => [
            'vpn'     => ['label' => 'WireGuard', 'icon' => 'ti-lock-access', 'href' => '/vpn.php'],
            'ipsec'   => ['label' => 'IPsec',     'icon' => 'ti-shield-lock', 'href' => '/ipsec.php'],
            'openvpn' => ['label' => 'OpenVPN',   'icon' => 'ti-key',         'href' => '/openvpn.php'],
        ],
    ],
    'services'        => ['label' => 'Services',        'icon' => 'ti-adjustments', 'href' => '/services.php'],
    'system_logs'     => ['label' => 'System Logs',     'icon' => 'ti-file-text',   'href' => '/system-logs.php'],
    'package_manager' => ['label' => 'Package manager', 'icon' => 'ti-puzzle',      'href' => '/package-manager.php'],
    'system'          => ['label' => 'System',          'icon' => 'ti-settings',    'href' => '/system.php'],
];
// RCA (keputusan DIBALIK dari sebelumnya - konfirmasi eksplisit bro):
// menu OpenVPN dulu SENGAJA disembunyikan sampai package terinstall,
// alasannya waktu itu halaman "not installed" cuma banner teks polos
// tanpa link apa pun. SEKARANG openvpn.php sudah pakai
// plugin_not_installed.php (sama seperti IPsec, ada link langsung ke
// Package Manager) - menyembunyikan menu JUSTRU membuat fitur ini
// tidak bisa ditemukan via navigasi normal sama sekali (ditemukan
// dari test nyata: admin harus tebak-tebak/ketik URL manual). Menu
// SELALU tampil sekarang, konsisten dengan IPsec.
// Label breadcrumb tetap harus bisa temukan item aktif walau sekarang
// dia mungkin bersarang di dalam 'children' grup, bukan level atas.
$activeLabel = $navItems[$activeNavItem]['label'] ?? null;
if ($activeLabel === null) {
    foreach ($navItems as $item) {
        if (!empty($item['group']) && isset($item['children'][$activeNavItem])) {
            $activeLabel = $item['children'][$activeNavItem]['label'];
            break;
        }
    }
}
$activeLabel = $activeLabel ?? $pageTitle;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?= htmlspecialchars($pageTitle) ?> - NTPSense InetGateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/assets/tabler-icons.min.css">
<link rel="stylesheet" href="/assets/app.css">
<?php $ntpAppShellCssVer = @filemtime(__DIR__ . '/../assets/app-shell.css') ?: time(); ?>
<link rel="stylesheet" href="/assets/app-shell.css?v=<?= $ntpAppShellCssVer ?>">
</head>
<body>
<div class="ntp-shell">
  <header class="ntp-appheader">
    <button type="button" id="ntpCollapseBtn" class="ntp-collapse-btn" aria-label="Toggle sidebar">
      <i class="ti ti-menu-2" aria-hidden="true"></i>
    </button>
    <a href="/index.php" class="ntp-appheader-logo">
      <img src="/assets/ntpsense-logo.png" alt="NTPSense - Simple + Fast + Secure">
    </a>
    <div class="ntp-appheader-divider"></div>
    <div class="ntp-appheader-heading">
      <?= htmlspecialchars($activeLabel) ?>
      <?php foreach ($breadcrumbTailSegments as $segment): ?>
        <span class="sep">&gt;</span>
        <span class="tail"><?= htmlspecialchars($segment) ?></span>
      <?php endforeach; ?>
    </div>
    <div class="ntp-appheader-spacer"></div>
    <?php
    // Bell alert - dipanggil di SETIAP halaman lewat header bersama ini,
    // makanya HARUS defensif total: kegagalan di sini TIDAK BOLEH
    // pernah merusak rendering halaman manapun. require_once dipanggil
    // eksplisit di sini (bukan cuma mengandalkan halaman pemanggil
    // sudah require NtpsenseConfigd.php duluan) supaya header ini benar-
    // benar mandiri/self-contained.
    require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
    $ntpAlerts = [];
    try {
        $ntpAlertsConfigd = new NtpsenseConfigd();
        $ntpAlerts = $ntpAlertsConfigd->call('system.alerts_summary', [], 5.0)['alerts'] ?? [];
    } catch (\Throwable $e) {
        // Diam saja - bell tampil kosong/normal, tidak menampilkan error
        // apa pun ke admin hanya karena daemon sedang lambat/sibuk.
    }
    ?>
    <div class="ntp-appheader-alerts">
      <button type="button" id="ntpAlertBell" class="ntp-alert-bell-btn" aria-label="Alerts" onclick="ntpToggleAlertPanel();">
        <i class="ti ti-bell" aria-hidden="true"></i>
        <?php if (!empty($ntpAlerts)): ?>
          <span class="ntp-alert-badge" id="ntpAlertBadge"><?= count($ntpAlerts) > 9 ? '9+' : count($ntpAlerts) ?></span>
        <?php endif; ?>
      </button>
      <div id="ntpAlertPanel" class="ntp-alert-panel">
        <div class="ntp-alert-panel-header">Alerts</div>
        <div id="ntpAlertPanelBody">
          <?php if (empty($ntpAlerts)): ?>
            <div class="ntp-alert-panel-empty">No active alerts - everything looks normal.</div>
          <?php else: ?>
            <?php foreach ($ntpAlerts as $a): ?>
              <a href="<?= htmlspecialchars($a['link'] ?? '#') ?>" class="ntp-alert-item ntp-alert-item-<?= htmlspecialchars($a['severity'] ?? 'warning') ?>">
                <i class="ti ti-<?= ($a['severity'] ?? '') === 'critical' ? 'alert-triangle' : 'alert-circle' ?>" aria-hidden="true"></i>
                <span><?= htmlspecialchars($a['message'] ?? '') ?></span>
              </a>
            <?php endforeach; ?>
          <?php endif; ?>
        </div>
      </div>
    </div>
    <div class="ntp-appheader-user">
      <span class="ntp-appheader-username"><?= htmlspecialchars($_SESSION['ntpsense_username'] ?? '') ?></span>
      <a href="/logout.php" class="ntp-logout-btn" title="Log out" aria-label="Log out" onclick="return confirm('Log out of NTPSense InetGateway?');">
        <i class="ti ti-logout" aria-hidden="true"></i>
      </a>
    </div>
  </header>
  <div class="ntp-body">
    <nav class="ntp-sidebar<?= $sidebarCollapsed ? ' collapsed' : '' ?>" id="ntpSidebar">
      <div class="ntp-sidebar-nav">
        <?php foreach ($navItems as $key => $item): ?>
          <?php if (!empty($item['group'])): ?>
            <?php
            $groupHasActiveChild = isset($item['children'][$activeNavItem]);
            ?>
            <button type="button"
                    class="ntp-nav-group-toggle<?= $groupHasActiveChild ? ' active open' : '' ?>"
                    aria-expanded="<?= $groupHasActiveChild ? 'true' : 'false' ?>"
                    onclick="var grp = this.nextElementSibling; var isOpen = grp.classList.toggle('open'); this.classList.toggle('open', isOpen); this.setAttribute('aria-expanded', isOpen ? 'true' : 'false');">
              <i class="ti <?= htmlspecialchars($item['icon']) ?>" aria-hidden="true"></i>
              <span><?= htmlspecialchars($item['label']) ?></span>
              <i class="ti ti-chevron-right ntp-nav-group-chevron" aria-hidden="true"></i>
            </button>
            <div class="ntp-nav-group<?= $groupHasActiveChild ? ' open' : '' ?>">
              <?php foreach ($item['children'] as $childKey => $child): ?>
                <a href="<?= htmlspecialchars($child['href']) ?>"
                   class="ntp-nav-link ntp-nav-link-sub<?= $childKey === $activeNavItem ? ' active' : '' ?>"
                   title="<?= htmlspecialchars($child['label']) ?>">
                  <i class="ti <?= htmlspecialchars($child['icon']) ?>" aria-hidden="true"></i>
                  <span><?= htmlspecialchars($child['label']) ?></span>
                </a>
              <?php endforeach; ?>
            </div>
          <?php else: ?>
            <a href="<?= htmlspecialchars($item['href']) ?>"
               class="ntp-nav-link<?= $key === $activeNavItem ? ' active' : '' ?>"
               title="<?= htmlspecialchars($item['label']) ?>">
              <i class="ti <?= htmlspecialchars($item['icon']) ?>" aria-hidden="true"></i>
              <span><?= htmlspecialchars($item['label']) ?></span>
            </a>
          <?php endif; ?>
        <?php endforeach; ?>
      </div>
    </nav>
    <main class="ntp-content">
