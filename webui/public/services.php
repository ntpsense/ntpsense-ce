<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
Auth::requireLogin();
Auth::requireCategory('services');

$configd = new NtpsenseConfigd();
$actionMessage = null;
$actionError = null;

$validTabs = ['general', 'clients', 'users', 'log'];
$activeTab = $_GET['tab'] ?? 'general';
if (!in_array($activeTab, $validTabs, true)) {
    $activeTab = 'general';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_config') {
    try {
        $configd->call('freeradius.set_config', ['enabled' => isset($_POST['enabled'])]);
        $actionMessage = 'Settings saved and applied.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_add') {
    try {
        $configd->call('freeradius.client_add', [
            'name' => (string) ($_POST['name'] ?? ''),
            'ip_cidr' => (string) ($_POST['ip_cidr'] ?? ''),
            'secret' => (string) ($_POST['secret'] ?? ''),
            'description' => (string) ($_POST['description'] ?? ''),
        ]);
        $actionMessage = 'NAS/Client added.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_delete') {
    try {
        $configd->call('freeradius.client_delete', ['id' => (string) ($_POST['id'] ?? '')]);
        $actionMessage = 'NAS/Client deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'user_add') {
    try {
        $configd->call('freeradius.user_add', [
            'username' => (string) ($_POST['username'] ?? ''),
            'password' => (string) ($_POST['password'] ?? ''),
            'description' => (string) ($_POST['description'] ?? ''),
        ]);
        $actionMessage = 'User added.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'user_delete') {
    try {
        $configd->call('freeradius.user_delete', ['id' => (string) ($_POST['id'] ?? '')]);
        $actionMessage = 'User deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

// Cek status install SEBELUM apa pun lain - kalau belum ter-install,
// tampilkan template plugin_not_installed.php yang sudah ada (pola
// SAMA persis dipakai proxy.php/security.php/vpn.php - satu sumber
// kebenaran untuk tampilan "belum ter-install", bukan duplikasi UI).
$installed = false;
$freeradiusConfigError = null;
try {
    $freeradiusStatus = $configd->call('freeradius.get_status');
    $installed = $freeradiusStatus['installed'] ?? false;
} catch (NtpsenseConfigdException $e) {
    $freeradiusConfigError = $e->getMessage();
}

$tabLabels = ['general' => 'General', 'clients' => 'NAS / Clients', 'users' => 'Users', 'log' => 'Log'];
$pageTitle = 'Services';
$activeNavItem = 'services';
$breadcrumbTail = $installed ? [$tabLabels[$activeTab]] : null;
require __DIR__ . '/../templates/layout_header.php';

if (!$installed) {
    $categoryLabel = 'Services';
    $categoryIcon = 'ti-adjustments';
    require __DIR__ . '/../templates/plugin_not_installed.php';
    require __DIR__ . '/../templates/layout_footer.php';
    exit;
}

$cfg = ['enabled' => false, 'clients' => [], 'users' => []];
try {
    $result = $configd->call('freeradius.get_config');
    $cfg = $result['config'] ?? $cfg;
} catch (NtpsenseConfigdException $e) {
    if ($freeradiusConfigError === null) {
        $freeradiusConfigError = $e->getMessage();
    }
}
$clients = [];
$users = [];
$authEntries = [];
$rawLogLines = [];
try {
    if ($activeTab === 'clients') {
        $clients = $configd->call('freeradius.client_list')['clients'] ?? [];
    } elseif ($activeTab === 'users') {
        $users = $configd->call('freeradius.user_list')['users'] ?? [];
    } elseif ($activeTab === 'log') {
        $authEntries = $configd->call('freeradius.get_auth_log', ['limit' => 200])['entries'] ?? [];
        $rawLogLines = $configd->call('freeradius.get_log', ['limit' => 200])['lines'] ?? [];
    }
} catch (NtpsenseConfigdException $e) {
    if ($freeradiusConfigError === null) {
        $freeradiusConfigError = $e->getMessage();
    }
}
?>
<?php if ($freeradiusConfigError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch data from ntpsense-configd: <?= htmlspecialchars($freeradiusConfigError) ?></div>
<?php endif; ?>
<?php if ($actionMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($actionMessage) ?></div>
<?php endif; ?>
<?php if ($actionError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($actionError) ?></div>
<?php endif; ?>
<p style="font-size:12px; color:#6b7280; margin-top:0;">
  FreeRADIUS authentication server - riset 4 komponen standar industri dari pfSense FreeRADIUS package
  (Interfaces, NAS/Clients, Users, Settings). MVP ini menggabungkan jadi General/NAS-Clients/Users - server
  selalu listen di semua interface, port default 1812 (auth) / 1813 (accounting), sesuai standar RFC 2865/2866.
  Cocok untuk otentikasi terpusat WiFi enterprise (802.1X) dan VPN (OpenVPN/lainnya).
</p>
<div class="ntp-tabbar" style="margin-bottom:14px;">
  <?php foreach ($tabLabels as $key => $label): ?>
    <a href="?tab=<?= $key ?>" class="ntp-tab<?= $activeTab === $key ? ' active' : '' ?>"><?= htmlspecialchars($label) ?></a>
  <?php endforeach; ?>
</div>
<?php if ($activeTab === 'general'): ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Server Settings</div>
    <form method="post" style="padding:14px; display:flex; flex-direction:column; gap:14px;">
      <input type="hidden" name="form" value="set_config">
      <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
        <input type="checkbox" name="enabled" value="1" <?= $cfg['enabled'] ? 'checked' : '' ?>>
        Enable FreeRADIUS server
      </label>
      <p style="font-size:12px; color:#6b7280; margin:0;">
        Listening ports are fixed at the RADIUS standard defaults for this release (1812/UDP authentication,
        1813/UDP accounting) - custom port binding is not yet configurable here.
      </p>
      <div>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save &amp; Apply</button>
      </div>
    </form>
  </div>
<?php elseif ($activeTab === 'clients'): ?>
  <p style="font-size:12px; color:#6b7280; margin-top:0;">
    NAS/Clients - each device that will send authentication requests to this server (WiFi access points, VPN
    concentrators, switches for 802.1X) needs an entry here with a shared secret. This matches pfSense's own
    "NAS/Clients" tab.
  </p>
  <?php if (!empty($clients)): ?>
    <div class="ntp-table-scroll" style="margin-bottom:20px;">
    <table class="ntp-table">
      <thead><tr><th>Name</th><th>IP / CIDR</th><th>Description</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($clients as $c): ?>
        <tr>
          <td><?= htmlspecialchars($c['name']) ?></td>
          <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($c['ip_cidr']) ?></td>
          <td style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($c['description'] ?? '') ?></td>
          <td>
            <form method="post" style="margin:0;" onsubmit="return confirm('Delete NAS/Client &quot;<?= htmlspecialchars($c['name']) ?>&quot;? Devices using this secret will stop being able to authenticate.');">
              <input type="hidden" name="form" value="client_delete">
              <input type="hidden" name="id" value="<?= htmlspecialchars($c['id']) ?>">
              <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;" title="Delete"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php endif; ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Add NAS / Client</div>
    <form method="post" style="padding:14px; display:flex; gap:10px; align-items:end; flex-wrap:wrap;">
      <input type="hidden" name="form" value="client_add">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
        <input type="text" name="name" placeholder="office-ap-1" required style="width:160px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">IP / CIDR</label>
        <input type="text" name="ip_cidr" placeholder="10.252.1.50" required style="width:160px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Shared Secret</label>
        <input type="text" name="secret" placeholder="min. 8 characters" required minlength="8" style="width:180px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Description</label>
        <input type="text" name="description" placeholder="optional" style="width:180px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add</button>
    </form>
  </div>
<?php elseif ($activeTab === 'users'): ?>
  <p style="font-size:12px; color:#6b7280; margin-top:0;">
    RADIUS users - username/password checked against incoming authentication requests (PAP, the most common
    mode for WiFi/VPN client compatibility). Passwords are stored in a form FreeRADIUS itself needs to be able
    to read for this comparison - keep this list to accounts genuinely meant for RADIUS-authenticated services,
    not shared with the Web UI admin accounts.
  </p>
  <?php if (!empty($users)): ?>
    <div class="ntp-table-scroll" style="margin-bottom:20px;">
    <table class="ntp-table">
      <thead><tr><th>Username</th><th>Description</th><th></th></tr></thead>
      <tbody>
      <?php foreach ($users as $u): ?>
        <tr>
          <td><?= htmlspecialchars($u['username']) ?></td>
          <td style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($u['description'] ?? '') ?></td>
          <td>
            <form method="post" style="margin:0;" onsubmit="return confirm('Delete user &quot;<?= htmlspecialchars($u['username']) ?>&quot;?');">
              <input type="hidden" name="form" value="user_delete">
              <input type="hidden" name="id" value="<?= htmlspecialchars($u['id']) ?>">
              <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;" title="Delete"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php endif; ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Add User</div>
    <form method="post" style="padding:14px; display:flex; gap:10px; align-items:end; flex-wrap:wrap;">
      <input type="hidden" name="form" value="user_add">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Username</label>
        <input type="text" name="username" placeholder="jdoe" required style="width:180px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Password</label>
        <input type="text" name="password" placeholder="min. 8 characters" required minlength="8" style="width:180px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Description</label>
        <input type="text" name="description" placeholder="optional" style="width:200px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add</button>
    </form>
  </div>
<?php elseif ($activeTab === 'log'): ?>
  <p style="font-size:12px; color:#6b7280; margin-top:0;">
    Authentication events (who authenticated, successfully or not) - failed attempts are logged in full for
    security review; <strong>successful passwords are never written to this log</strong>, only the username
    and result, consistent with this gateway's password-handling practice elsewhere.
  </p>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">Authentication Events</div>
    <?php if (empty($authEntries)): ?>
      <p style="padding:12px 14px; font-size:12px; color:#6b7280;">No authentication events recorded yet.</p>
    <?php else: ?>
      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead><tr><th>Timestamp</th><th>Username</th><th>Result</th></tr></thead>
        <tbody>
        <?php foreach ($authEntries as $e): ?>
          <tr>
            <td style="font-size:12px;"><?= htmlspecialchars($e['timestamp']) ?></td>
            <td><?= htmlspecialchars($e['username']) ?></td>
            <td>
              <?= $e['result'] === 'accept'
                ? '<span class="ntp-badge ntp-badge-success">Accept</span>'
                : '<span class="ntp-badge ntp-badge-danger">Reject</span>' ?>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
    <?php endif; ?>
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">Raw Service Log</div>
    <?php if (empty($rawLogLines)): ?>
      <p style="padding:12px 14px; font-size:12px; color:#6b7280;">Log is empty.</p>
    <?php else: ?>
      <pre style="margin:0; padding:12px 14px; font-family:monospace; font-size:11px; max-height:320px; overflow-y:auto; background:#f9fafb;"><?= htmlspecialchars(implode("\n", $rawLogLines)) ?></pre>
    <?php endif; ?>
  </div>
<?php endif; ?>
<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
