<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();
Auth::requireCategory('vpn');

$configd = new NtpsenseConfigd();
$configdError = null;
$saveMessage = null;
$saveError = null;
$installed = false;
$wgConfig = null;
$peers = [];
$newPeerClientConfig = null;
$newPeerName = null;

try {
    $status = $configd->call('vpn.get_config');
    $installed = (bool) ($status['installed'] ?? false);
    $wgConfig = $status['config'] ?? null;
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}

$activeTab = $_GET['tab'] ?? 'general';
if (!in_array($activeTab, ['general', 'peers'], true)) {
    $activeTab = 'general';
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vpn_general') {
    try {
        $result = $configd->call('vpn.set_config', [
            'enabled' => ($_POST['enabled'] ?? '') === '1',
            'listen_port' => (int) ($_POST['listen_port'] ?? 51820),
            'vpn_subnet' => (string) ($_POST['vpn_subnet'] ?? '10.66.66.0/24'),
        ], 30.0);
        $wgConfig = $result['config'] ?? $wgConfig;
        $saveMessage = 'VPN configuration saved successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $activeTab === 'peers') {
    try {
        $peers = $configd->call('vpn.peer_list')['peers'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vpn_peer_add') {
    try {
        $result = $configd->call('vpn.peer_add', ['name' => (string) ($_POST['name'] ?? '')], 30.0);
        $newPeerClientConfig = $result['client_config'] ?? null;
        $newPeerName = $result['peer']['name'] ?? null;
        $saveMessage = 'Peer added successfully - copy or download the config below now, it will not be shown again.';
        $peers = $configd->call('vpn.peer_list')['peers'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vpn_peer_delete') {
    try {
        $configd->call('vpn.peer_delete', ['id' => (string) ($_POST['id'] ?? '')]);
        $saveMessage = 'Peer deleted successfully.';
        $peers = $configd->call('vpn.peer_list')['peers'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}
if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vpn_peer_set_enabled') {
    try {
        $enabling = ($_POST['enabled'] ?? '') === '1';
        $configd->call('vpn.peer_set_enabled', [
            'id' => (string) ($_POST['id'] ?? ''),
            'enabled' => $enabling,
        ]);
        $saveMessage = $enabling
            ? 'Peer enabled - it can handshake and pass traffic again.'
            : 'Peer disabled - the server will reject handshakes from this key until re-enabled.';
        $peers = $configd->call('vpn.peer_list')['peers'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

$pageTitle = 'VPN';
$activeNavItem = 'vpn';
// Layer 1 (app header) - konsisten dengan pola Firewall/IPsec/NAT/Proxy/
// Security.
$breadcrumbTail = [$activeTab === 'peers' ? 'Peers' : 'General'];
require __DIR__ . '/../templates/layout_header.php';

if (!$installed) {
    $categoryLabel = 'VPN';
    $categoryIcon = 'ti-lock-access';
    require __DIR__ . '/../templates/plugin_not_installed.php';
    require __DIR__ . '/../templates/layout_footer.php';
    exit;
}
?>

<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch VPN status: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($saveMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($saveMessage) ?></div>
<?php endif; ?>
<?php if ($saveError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($saveError) ?></div>
<?php endif; ?>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=general" class="ntp-tab<?= $activeTab === 'general' ? ' active' : '' ?>">General</a>
  <a href="?tab=peers" class="ntp-tab<?= $activeTab === 'peers' ? ' active' : '' ?>">Peers</a>
</div>

<?php if ($activeTab === 'general' && $wgConfig): ?>
<form method="post">
  <input type="hidden" name="form" value="vpn_general">
  <div class="ntp-card">
    <div class="ntp-card-header">General</div>
    <div style="padding:14px; display:grid; grid-template-columns:220px 1fr; gap:14px 16px; align-items:start;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">WireGuard server</label>
      <select name="enabled" style="max-width:200px;">
        <option value="0" <?= !$wgConfig['enabled'] ? 'selected' : '' ?>>Disabled</option>
        <option value="1" <?= $wgConfig['enabled'] ? 'selected' : '' ?>>Enabled</option>
      </select>

      <label style="font-size:13px; color:#374151; padding-top:8px;">Listen port (UDP)</label>
      <input type="number" name="listen_port" value="<?= htmlspecialchars((string) $wgConfig['listen_port']) ?>" min="1" max="65535" style="max-width:200px;">

      <label style="font-size:13px; color:#374151; padding-top:8px;">VPN subnet</label>
      <input type="text" name="vpn_subnet" value="<?= htmlspecialchars($wgConfig['vpn_subnet']) ?>" style="max-width:200px;" placeholder="10.66.66.0/24">

      <?php if (!empty($wgConfig['server_public_key'])): ?>
        <label style="font-size:13px; color:#374151; padding-top:8px;">Server public key</label>
        <input type="text" value="<?= htmlspecialchars($wgConfig['server_public_key']) ?>" readonly style="font-family:monospace; font-size:12px; background:#f9fafb;">
      <?php endif; ?>
    </div>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
      A firewall rule allowing this port on WAN1 is added/removed automatically as this is enabled/disabled — no manual Firewall configuration needed. Changing the port or subnet does not affect the server's identity; existing peers keep working.
    </p>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
</form>
<?php endif; ?>

<?php if ($activeTab === 'peers'): ?>
  <?php if ($newPeerClientConfig): ?>
    <?php $safeFilename = preg_replace('/[^a-zA-Z0-9_-]/', '_', (string) $newPeerName) . '.conf'; ?>
    <div class="ntp-card">
      <div class="ntp-card-header" style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
        <span>Client config for "<?= htmlspecialchars((string) $newPeerName) ?>" — copy this now, it will not be shown again</span>
        <button type="button" id="wg-download-btn" style="background:#14213d; color:#ffffff; border:none; padding:6px 14px; font-size:12px; border-radius:6px; cursor:pointer; white-space:nowrap;">Download Client Config</button>
      </div>
      <pre id="wg-client-config-text" style="margin:0; padding:12px 14px; font-size:12px; white-space:pre-wrap; font-family:monospace; background:#f9fafb;"><?= htmlspecialchars($newPeerClientConfig) ?></pre>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">Paste this into the WireGuard app on the client device (or save it as a .conf file and import it).</p>
    </div>
    <script>
      (function () {
        var btn = document.getElementById('wg-download-btn');
        if (!btn) { return; }
        btn.addEventListener('click', function () {
          var text = document.getElementById('wg-client-config-text').textContent;
          var blob = new Blob([text], { type: 'text/plain' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = <?= json_encode($safeFilename) ?>;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          // Sembunyikan tombol setelah download - config ini tidak akan
          // pernah ditampilkan lagi (private key tidak pernah disimpan
          // server-side), jadi tombol download tidak relevan lagi setelah
          // dipakai sekali.
          btn.remove();
        });
      })();
    </script>
  <?php endif; ?>

  <div class="ntp-card">
    <div class="ntp-card-header">Peers</div>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead>
      <tr><th>Name</th><th>VPN IP</th><th>Status</th><th>Manage</th></tr>
      </thead>
      <tbody>
      <?php if (empty($peers)): ?>
        <tr><td colspan="4" style="color:#6b7280;">No peers yet.</td></tr>
      <?php endif; ?>
      <?php foreach ($peers as $peer): ?>
        <?php
        $status = $peer['status'] ?? ['connected' => false, 'last_handshake' => null, 'rx_bytes' => 0, 'tx_bytes' => 0];
        $lastHandshake = $status['last_handshake'] ?? null;
        $peerEnabled = $peer['enabled'] ?? true;
        ?>
        <tr<?= $peerEnabled ? '' : ' style="opacity:.6;"' ?>>
          <td><?= htmlspecialchars($peer['name']) ?></td>
          <td><?= htmlspecialchars($peer['allowed_ip']) ?></td>
          <td>
            <?php if (!$peerEnabled): ?>
              <span class="ntp-badge ntp-badge-muted">Disabled</span>
            <?php elseif ($status['connected']): ?>
              <span class="ntp-badge ntp-badge-success">Connected</span>
            <?php elseif ($lastHandshake !== null): ?>
              <span class="ntp-badge ntp-badge-warning">Disconnected</span>
            <?php else: ?>
              <span class="ntp-badge ntp-badge-muted">Never connected</span>
            <?php endif; ?>
            <?php if ($lastHandshake !== null): ?>
              <div style="font-size:11px; color:#9ca3af; margin-top:2px;">Last handshake: <?= htmlspecialchars(date('Y-m-d H:i:s', (int) $lastHandshake)) ?></div>
            <?php endif; ?>
          </td>
          <td style="white-space:nowrap;">
            <form method="post" style="margin:0; display:inline-block;">
              <input type="hidden" name="form" value="vpn_peer_set_enabled">
              <input type="hidden" name="id" value="<?= htmlspecialchars($peer['id']) ?>">
              <?php if ($peerEnabled): ?>
                <input type="hidden" name="enabled" value="0">
                <button type="submit" title="Disable — the server will reject this peer's key until re-enabled" style="background:none; border:none; cursor:pointer; color:#9a5b00; padding:4px;">
                  <i class="ti ti-plug-connected-x" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              <?php else: ?>
                <input type="hidden" name="enabled" value="1">
                <button type="submit" title="Enable" style="background:none; border:none; cursor:pointer; color:#1a7f4b; padding:4px;">
                  <i class="ti ti-plug-connected" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              <?php endif; ?>
            </form>
            <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete peer <?= htmlspecialchars($peer['name']) ?>? The client device will lose VPN access immediately and permanently (unlike Disable, this cannot be undone — the client will need a brand new config).');">
              <input type="hidden" name="form" value="vpn_peer_delete">
              <input type="hidden" name="id" value="<?= htmlspecialchars($peer['id']) ?>">
              <button type="submit" title="Delete permanently" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
    <p style="padding:0 14px 14px; font-size:11px; color:#9ca3af;">
      Disable blocks a peer's key at the server (reversible — re-enable any time without generating a new client
      config). WireGuard has no live "disconnect" — it's connectionless, so a peer with a still-valid key and
      endpoint would simply re-handshake within seconds; Disable is the only way to genuinely block one without
      deleting it.
    </p>

    <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:flex; align-items:end; gap:12px;">
      <input type="hidden" name="form" value="vpn_peer_add">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Peer name</label>
        <input type="text" name="name" required placeholder="Bro's laptop" style="max-width:240px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add peer</button>
    </form>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">A new keypair is generated automatically for each peer. Save the VPN General settings first if this is the first peer.</p>
  </div>
<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
