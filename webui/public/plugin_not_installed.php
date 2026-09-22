<?php
declare(strict_types=1);
/**
 * Template shared untuk halaman kategori yang belum ada plugin terinstall
 * (Proxy, Security, VPN, Services, IPsec VPN). Variabel yang HARUS
 * di-set sebelum include:
 *   $categoryLabel - nama kategori (mis. "Proxy")
 *   $categoryKey   - key kategori PackageCatalog (mis. "Proxy")
 *   $categoryIcon  - kelas ikon Tabler
 *
 * CATATAN: breadcrumb/judul halaman TIDAK dirender di sini lagi (dulu
 * ada <div class="ntp-breadcrumb">+<h2> duplikat) - setiap halaman
 * pemanggil sudah set $pageTitle/$breadcrumbTail dan meng-include
 * layout_header.php SEBELUM include template ini, jadi judul sudah
 * tampil di app header. Merender breadcrumb+h2 di sini lagi cuma
 * mengulang informasi yang sama persis.
 */
require_once __DIR__ . '/../lib/PackageCatalog.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
// Halaman pemanggil (mis. proxy.php) mungkin sudah punya instance
// $configd sendiri (dipakai juga untuk hal lain di halaman itu) - reuse
// kalau ada, supaya tidak buat koneksi/instance ganda tanpa perlu.
// Kalau belum ada (mis. security.php/vpn.php/services.php yang belum
// butuh $configd untuk hal lain), buat instance baru di sini.
if (!isset($configd) || !($configd instanceof NtpsenseConfigd)) {
    $configd = new NtpsenseConfigd();
}
$catalog = PackageCatalog::knownPackages();
$installedVersions = PackageCatalog::getInstalledVersions($configd);
$relevantPackages = array_filter(
    $catalog,
    fn(array $meta): bool => $meta['category'] === $categoryLabel
);
?>
<div class="ntp-card">
  <div style="padding:32px 24px; text-align:center;">
    <i class="ti <?= htmlspecialchars($categoryIcon) ?>" style="font-size:36px; color:#9ca3af;" aria-hidden="true"></i>
    <p style="font-weight:500; font-size:15px; margin:12px 0 4px;">No <?= htmlspecialchars($categoryLabel) ?> plugin installed yet</p>
    <p style="font-size:13px; color:#6b7280; margin:0 0 16px;">Install one of the packages below via Package manager to enable this page.</p>
    <a href="/package-manager.php?tab=available" style="display:inline-block; background:#14213d; color:#ffffff; text-decoration:none; padding:8px 18px; font-size:13px; border-radius:6px;">Open Package manager</a>
  </div>
</div>
<?php if (!empty($relevantPackages)): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Available <?= htmlspecialchars($categoryLabel) ?> packages</div>
  <div style="padding:12px 14px; display:flex; flex-direction:column; gap:8px;">
    <?php foreach ($relevantPackages as $name => $meta): ?>
      <div style="display:flex; align-items:center; gap:12px;">
        <i class="ti <?= htmlspecialchars($meta['icon']) ?>" style="font-size:18px; color:#14213d;" aria-hidden="true"></i>
        <span style="font-size:13px; font-weight:500;"><?= htmlspecialchars(ucfirst($name)) ?></span>
        <span style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($meta['description']) ?></span>
        <?php if (isset($installedVersions[$name])): ?>
          <span class="ntp-badge ntp-badge-success" style="margin-left:auto;">Installed</span>
        <?php endif; ?>
      </div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>
