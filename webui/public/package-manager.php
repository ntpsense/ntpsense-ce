<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/PackageCatalog.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();
Auth::requireCategory('package_manager');

$configd = new NtpsenseConfigd();

// AJAX endpoint ringan (permintaan bro - web console live progress saat
// Install) - deteksi lewat 'ajax_action', balas JSON MURNI dan exit
// SEBELUM layout_header.php di-include, tidak pernah merender halaman
// penuh untuk request ini. Pola ini dipilih daripada bikin file
// endpoint baru terpisah - konsisten dengan app yang sudah full-page-
// reload/tidak SPA, cukup satu file ini merangkap jadi tiny JSON API
// kalau parameter ini ada.
if (isset($_POST['ajax_action'])) {
    header('Content-Type: application/json');
    if ($_POST['ajax_action'] === 'install_start') {
        try {
            $name = (string) ($_POST['name'] ?? '');
            $configd->call('package.install', ['name' => $name]);
            echo json_encode(['ok' => true]);
        } catch (NtpsenseConfigdException $e) {
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    if ($_POST['ajax_action'] === 'install_status') {
        try {
            $result = $configd->call('package.install_status');
            echo json_encode(array_merge(['ok' => true], $result));
        } catch (NtpsenseConfigdException $e) {
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    if ($_POST['ajax_action'] === 'uninstall_start') {
        try {
            $name = (string) ($_POST['name'] ?? '');
            $configd->call('package.uninstall', ['name' => $name]);
            echo json_encode(['ok' => true]);
        } catch (NtpsenseConfigdException $e) {
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    if ($_POST['ajax_action'] === 'uninstall_status') {
        try {
            $result = $configd->call('package.uninstall_status');
            echo json_encode(array_merge(['ok' => true], $result));
        } catch (NtpsenseConfigdException $e) {
            echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Unknown ajax_action']);
    exit;
}

$actionMessage = null;
$actionError = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'install') {
    try {
        $name = (string) ($_POST['name'] ?? '');
        $configd->call('package.install', ['name' => $name]);
        $actionMessage = PackageCatalog::displayName($name) . ' installed successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'uninstall') {
    try {
        $name = (string) ($_POST['name'] ?? '');
        $configd->call('package.uninstall', ['name' => $name]);
        $actionMessage = PackageCatalog::displayName($name) . ' uninstalled successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

$tab = ($_GET['tab'] ?? 'installed') === 'available' ? 'available' : 'installed';
$catalog = PackageCatalog::knownPackages();
$installedVersions = PackageCatalog::getInstalledVersions($configd);

$pageTitle = 'Package manager';
$activeNavItem = 'package_manager';
// Layer 1 (app header) - konsisten dengan pola halaman lain yang sudah
// diretrofit.
$breadcrumbTail = [$tab === 'available' ? 'Available packages' : 'Installed packages'];
require __DIR__ . '/../templates/layout_header.php';
?>

<?php if ($actionMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($actionMessage) ?></div>
<?php endif; ?>
<?php if ($actionError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($actionError) ?></div>
<?php endif; ?>

<p style="font-size:12px; color:#6b7280; margin:0 0 14px;">
  Packages are installed directly from the official FreeBSD package repository.
</p>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=installed" class="ntp-tab<?= $tab === 'installed' ? ' active' : '' ?>">Installed</a>
  <a href="?tab=available" class="ntp-tab<?= $tab === 'available' ? ' active' : '' ?>">Available</a>
</div>

<?php if ($tab === 'installed'): ?>
  <div class="ntp-card">
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead>
      <tr><th>Name</th><th>Category</th><th>Version</th><th>Status</th><th></th></tr>
      </thead>
      <tbody>
      <?php if (empty($installedVersions)): ?>
        <tr><td colspan="5" style="color:#6b7280;">No packages installed yet.</td></tr>
      <?php endif; ?>
      <?php foreach ($installedVersions as $name => $version): ?>
        <?php $meta = $catalog[$name] ?? ['category' => '—', 'icon' => 'ti-puzzle']; ?>
        <tr>
          <td><i class="ti ti-check" style="color:#1a7f4b;" aria-hidden="true"></i> <?= htmlspecialchars(PackageCatalog::displayName($name)) ?></td>
          <td><?= htmlspecialchars($meta['category']) ?></td>
          <td><?= htmlspecialchars($version) ?></td>
          <td><span class="ntp-badge ntp-badge-success">Installed</span></td>
          <td>
            <form method="post" style="margin:0;" onsubmit="ntpPkgOperation(event, 'uninstall', '<?= htmlspecialchars($name, ENT_QUOTES) ?>', '<?= htmlspecialchars(PackageCatalog::displayName($name), ENT_QUOTES) ?>'); return false;">
              <input type="hidden" name="form" value="uninstall">
              <input type="hidden" name="name" value="<?= htmlspecialchars($name) ?>">
              <button type="submit" style="font-size:12px; padding:4px 10px; color:#b3261e;">Uninstall</button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
<?php else: ?>
  <div style="display:flex; flex-direction:column; gap:8px;">
    <?php foreach ($catalog as $name => $meta): ?>
      <?php if (isset($installedVersions[$name])) continue; ?>
      <div style="display:flex; align-items:center; gap:14px; padding:12px 14px; background:#ffffff; border-radius:8px;">
        <i class="ti <?= htmlspecialchars($meta['icon']) ?>" style="font-size:22px; color:#14213d;" aria-hidden="true"></i>
        <div style="flex:1;">
          <p style="font-weight:500; font-size:14px; margin:0;"><?= htmlspecialchars(PackageCatalog::displayName($name)) ?></p>
          <p style="font-size:12px; color:#6b7280; margin:2px 0 0;"><?= htmlspecialchars($meta['description']) ?></p>
        </div>
        <span class="ntp-badge ntp-badge-muted"><?= htmlspecialchars($meta['category']) ?></span>
        <form method="post" style="margin:0;" onsubmit="ntpPkgOperation(event, 'install', '<?= htmlspecialchars($name, ENT_QUOTES) ?>', '<?= htmlspecialchars(PackageCatalog::displayName($name), ENT_QUOTES) ?>'); return false;">
          <input type="hidden" name="form" value="install">
          <input type="hidden" name="name" value="<?= htmlspecialchars($name) ?>">
          <button type="submit" style="font-size:12px; padding:6px 16px; background:#14213d; color:#ffffff; border:none; border-radius:6px;">Install</button>
        </form>
      </div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>

<div id="ntpInstallModal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:1000; align-items:center; justify-content:center;">
  <div style="background:#ffffff; border-radius:10px; width:600px; max-width:90vw; max-height:80vh; display:flex; flex-direction:column; overflow:hidden;">
    <div style="padding:14px 18px; border-bottom:1px solid #e5e7eb; display:flex; justify-content:space-between; align-items:center;">
      <strong id="ntpInstallModalTitle" style="font-size:14px;">Installing...</strong>
      <span id="ntpInstallModalSpinner" style="font-size:12px; color:#6b7280;">Working...</span>
    </div>
    <pre id="ntpInstallModalConsole" style="flex:1; overflow-y:auto; margin:0; padding:14px 18px; font-family:monospace; font-size:11px; background:#0f172a; color:#d1fae5; white-space:pre-wrap; min-height:200px;"></pre>
    <div style="padding:12px 18px; border-top:1px solid #e5e7eb; text-align:right;">
      <button type="button" id="ntpInstallModalCloseBtn" onclick="ntpInstallModalClose();" disabled style="font-size:12px; padding:6px 16px; background:#14213d; color:#ffffff; border:none; border-radius:6px; opacity:0.5; cursor:not-allowed;">Close &amp; Refresh</button>
    </div>
  </div>
</div>
<script>
let ntpPkgPollTimer = null;
function ntpPkgOperation(evt, op, name, displayName) {
  evt.preventDefault();
  if (op === 'uninstall' && !confirm('Uninstall ' + displayName + '? Its configuration page will show as not installed afterward.')) {
    return;
  }
  var verb = op === 'install' ? 'Installing' : 'Uninstalling';
  document.getElementById('ntpInstallModalTitle').textContent = verb + ' ' + displayName;
  document.getElementById('ntpInstallModalSpinner').textContent = 'Working...';
  document.getElementById('ntpInstallModalConsole').textContent = '';
  var closeBtn = document.getElementById('ntpInstallModalCloseBtn');
  closeBtn.disabled = true;
  closeBtn.style.opacity = '0.5';
  closeBtn.style.cursor = 'not-allowed';
  document.getElementById('ntpInstallModal').style.display = 'flex';
  fetch(window.location.pathname, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'ajax_action=' + op + '_start&name=' + encodeURIComponent(name)
  }).then(function (r) { return r.json(); }).then(function (data) {
    if (!data.ok) {
      document.getElementById('ntpInstallModalConsole').textContent = 'Failed: ' + (data.error || 'unknown error');
      document.getElementById('ntpInstallModalSpinner').textContent = 'Failed';
      ntpInstallModalEnableClose();
      return;
    }
    ntpPkgPollTimer = setInterval(function () { ntpPkgPollStatus(op); }, 1000);
    ntpPkgPollStatus(op);
  }).catch(function (err) {
    document.getElementById('ntpInstallModalConsole').textContent = 'Failed to start: ' + err;
    document.getElementById('ntpInstallModalSpinner').textContent = 'Failed';
    ntpInstallModalEnableClose();
  });
}
function ntpPkgPollStatus(op) {
  fetch(window.location.pathname, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'ajax_action=' + op + '_status'
  }).then(function (r) { return r.json(); }).then(function (data) {
    if (!data.ok) {
      return;
    }
    var consoleEl = document.getElementById('ntpInstallModalConsole');
    consoleEl.textContent = data.log || '';
    consoleEl.scrollTop = consoleEl.scrollHeight;
    if (data.finished) {
      clearInterval(ntpPkgPollTimer);
      document.getElementById('ntpInstallModalSpinner').textContent = data.success ? 'Done' : 'Failed';
      ntpInstallModalEnableClose();
    }
  });
}
function ntpInstallModalEnableClose() {
  var btn = document.getElementById('ntpInstallModalCloseBtn');
  btn.disabled = false;
  btn.style.opacity = '1';
  btn.style.cursor = 'pointer';
}
function ntpInstallModalClose() {
  if (ntpPkgPollTimer) { clearInterval(ntpPkgPollTimer); }
  document.getElementById('ntpInstallModal').style.display = 'none';
  window.location.reload();
}
</script>
<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
