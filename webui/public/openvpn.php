<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
Auth::requireLogin();
Auth::requireCategory('vpn');
$configd = new NtpsenseConfigd();
$configdError = null;
$actionMessage = null;
$actionError = null;
$downloadedOvpn = null;
$downloadedFilename = null;
$validTabs = ['general', 'clients', 'sites', 'connected'];
$activeTab = $_GET['tab'] ?? 'general';
if (!in_array($activeTab, $validTabs, true)) {
    $activeTab = 'general';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_config') {
    try {
        $configd->call('openvpn.set_config', [
            'enabled' => isset($_POST['enabled']),
            'remote_access_enabled' => isset($_POST['remote_access_enabled']),
            'site_to_site_enabled' => isset($_POST['site_to_site_enabled']),
            'protocol' => (string) ($_POST['protocol'] ?? 'udp'),
            'port' => (int) ($_POST['port'] ?? 1194),
            'remote_access_subnet' => (string) ($_POST['remote_access_subnet'] ?? '10.9.0.0/24'),
            'radius_auth_enabled' => isset($_POST['radius_auth_enabled']),
        ]);
        $actionMessage = 'Settings saved and applied.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'init_pki') {
    try {
        $configd->call('openvpn.init_pki', [], 60.0); // DH param generation genuinely takes a while
        $actionMessage = 'PKI initialized - CA, server certificate, DH parameters, and tls-crypt key all generated.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'reset_pki') {
    try {
        $configd->call('openvpn.reset_pki');
        $actionMessage = 'PKI deleted and reset - every existing client and site certificate is now invalid. Initialize PKI again to start fresh.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_set_active') {
    try {
        $newActive = ($_POST['active'] ?? '') === '1';
        $configd->call('openvpn.client_set_active', ['id' => (string) ($_POST['id'] ?? ''), 'active' => $newActive]);
        $actionMessage = $newActive ? 'Client activated - it can connect again.' : 'Client deactivated - new connection attempts will be rejected (already-connected sessions stay up until they reconnect or you use Disconnect).';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_disconnect') {
    try {
        $configd->call('openvpn.client_disconnect', ['name' => (string) ($_POST['name'] ?? '')]);
        $actionMessage = 'Disconnect signal sent - the client\'s current session (if any) has been dropped.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_create') {
    try {
        $configd->call('openvpn.client_create', ['name' => (string) ($_POST['name'] ?? '')]);
        $actionMessage = 'Client created.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_revoke') {
    try {
        $configd->call('openvpn.client_revoke', ['id' => (string) ($_POST['id'] ?? '')]);
        $actionMessage = 'Client revoked - it can no longer connect.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'client_download') {
    try {
        $result = $configd->call('openvpn.client_download_config', [
            'name' => (string) ($_POST['name'] ?? ''),
            'server_host' => (string) ($_POST['server_host'] ?? ''),
        ]);
        $downloadedOvpn = $result['ovpn'] ?? null;
        $downloadedFilename = $result['filename'] ?? 'client.ovpn';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'site_create') {
    try {
        $configd->call('openvpn.site_create', [
            'name' => (string) ($_POST['name'] ?? ''),
            'remote_subnet' => (string) ($_POST['remote_subnet'] ?? ''),
        ]);
        $actionMessage = 'Site created.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'site_revoke') {
    try {
        $configd->call('openvpn.site_revoke', ['id' => (string) ($_POST['id'] ?? '')]);
        $actionMessage = 'Site revoked.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'site_download') {
    try {
        $result = $configd->call('openvpn.site_download_config', [
            'name' => (string) ($_POST['name'] ?? ''),
            'server_host' => (string) ($_POST['server_host'] ?? ''),
        ]);
        $downloadedOvpn = $result['ovpn'] ?? null;
        $downloadedFilename = $result['filename'] ?? 'site.ovpn';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
$cfg = ['enabled' => false, 'remote_access_enabled' => false, 'site_to_site_enabled' => false, 'protocol' => 'udp', 'port' => 1194, 'remote_access_subnet' => '10.9.0.0/24', 'pki_initialized' => false, 'radius_auth_enabled' => false];
$installed = false;
$pkiActuallyExists = false;
$caInfo = null;
try {
    $result = $configd->call('openvpn.get_config');
    $cfg = $result['config'] ?? $cfg;
    $installed = $result['installed'] ?? false;
    $pkiActuallyExists = $result['pki_actually_exists'] ?? false;
    $caInfo = $result['ca_info'] ?? null;
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
$clients = [];
$sites = [];
$statusData = ['installed' => false, 'running' => false, 'connected_clients' => []];
try {
    if ($activeTab === 'clients') {
        $clients = $configd->call('openvpn.client_list')['clients'] ?? [];
    } elseif ($activeTab === 'sites') {
        $sites = $configd->call('openvpn.site_list')['sites'] ?? [];
    } elseif ($activeTab === 'connected') {
        $statusData = $configd->call('openvpn.status');
    }
} catch (NtpsenseConfigdException $e) {
    if ($configdError === null) {
        $configdError = $e->getMessage();
    }
}
$tabLabels = ['general' => 'General', 'clients' => 'Remote Access Clients', 'sites' => 'Site-to-Site', 'connected' => 'Connected Users'];
$pageTitle = 'OpenVPN';
$activeNavItem = 'openvpn';
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';

if (!$installed) {
    $categoryLabel = 'OpenVPN';
    $categoryIcon = 'ti-lock-access';
    require __DIR__ . '/../templates/plugin_not_installed.php';
    require __DIR__ . '/../templates/layout_footer.php';
    exit;
}
?>
<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch data from ntpsense-configd: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($actionMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($actionMessage) ?></div>
<?php endif; ?>
<?php if ($actionError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($actionError) ?></div>
<?php endif; ?>
<?php if ($downloadedOvpn): ?>
  <div style="background:#fff8e6; border:1px solid #f5d78e; border-radius:8px; padding:12px 14px; margin-bottom:16px;">
    <p style="font-size:13px; font-weight:600; color:#9a5b00; margin:0 0 6px;">📄 <?= htmlspecialchars($downloadedFilename) ?> ready - copy the content below or use the download link</p>
    <p style="margin:0 0 8px;">
      <a href="data:application/x-openvpn-profile;charset=utf-8,<?= rawurlencode($downloadedOvpn) ?>" download="<?= htmlspecialchars($downloadedFilename) ?>" style="background:#14213d; color:#fff; text-decoration:none; padding:6px 14px; border-radius:6px; font-size:12px; display:inline-block;">Download <?= htmlspecialchars($downloadedFilename) ?></a>
    </p>
    <textarea readonly rows="8" style="width:100%; font-family:monospace; font-size:11px; background:#ffffff; border:1px solid #f5d78e; border-radius:6px; padding:8px;" onclick="this.select();"><?= htmlspecialchars($downloadedOvpn) ?></textarea>
  </div>
<?php endif; ?>
<p style="font-size:12px; color:#6b7280; margin-top:0;">
  Certificate-based OpenVPN, researched against pfSense/OPNsense (the only one of our four reference vendors
  that actually ships OpenVPN itself - FortiGate/Palo Alto/Sangfor each use their own proprietary SSL-VPN
  instead). Kept alongside WireGuard specifically for TCP/443 compatibility - it can blend in as ordinary
  HTTPS traffic through strict firewalls that block WireGuard's UDP-only protocol.
</p>
<div class="ntp-tabbar" style="margin-bottom:14px;">
  <?php foreach ($tabLabels as $key => $label): ?>
    <a href="?tab=<?= $key ?>" class="ntp-tab<?= $activeTab === $key ? ' active' : '' ?>"><?= htmlspecialchars($label) ?></a>
  <?php endforeach; ?>
</div>
<?php if ($activeTab === 'general'): ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">1. PKI (Certificate Authority)</div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      One-time setup - generates a self-signed CA, server certificate, Diffie-Hellman parameters, and a
      tls-crypt key (modern replacement for the older tls-auth mode, obscures control-channel traffic from
      passive detection). This must run before any client or site can be created. Takes up to a minute (DH
      generation is genuinely slow) - only ever needed once. Not tied to hostname/IP - if your gateway's public
      IP or domain changes later, you only need to re-download client <code>.ovpn</code> files, not regenerate
      the CA itself.
    </p>
    <?php if ($cfg['pki_initialized'] && !$pkiActuallyExists): ?>
      <p style="margin:10px 14px 0; font-size:12px; color:#7a1f1a; background:#fff0f0; border:1px solid #f2b8b5; border-radius:6px; padding:8px 10px;">
        ⚠️ Saved config says PKI is initialized, but the certificate files are missing on disk (deleted outside
        the Web UI?). Click <strong>Initialize PKI</strong> below to generate a fresh one.
      </p>
    <?php endif; ?>
    <?php if ($pkiActuallyExists): ?>
      <div style="padding:0 14px 14px;">
        <p style="font-size:12px; color:#1a7f4b; margin:0 0 8px;">✓ PKI initialized and verified on disk.</p>
        <?php if ($caInfo): ?>
          <table class="ntp-table" style="max-width:520px;">
            <tr><th>CA valid from</th><td style="font-size:12px;"><?= htmlspecialchars($caInfo['not_before'] ?? '—') ?></td></tr>
            <tr><th>CA valid until</th><td style="font-size:12px;"><?= htmlspecialchars($caInfo['not_after'] ?? '—') ?></td></tr>
            <tr><th>CA fingerprint (SHA256)</th><td style="font-size:11px; font-family:monospace; word-break:break-all;"><?= htmlspecialchars($caInfo['fingerprint'] ?? '—') ?></td></tr>
          </table>
        <?php endif; ?>
        <form method="post" style="margin-top:12px;" onsubmit="return confirm('Delete the entire PKI? Every existing client and site certificate becomes permanently invalid immediately - they will all need to be recreated with a fresh CA. This cannot be undone. Continue?');">
          <input type="hidden" name="form" value="reset_pki">
          <button type="submit" style="background:#fff0f0; color:#b3261e; border:1px solid #f2b8b5; padding:6px 14px; font-size:12px; border-radius:6px;">Delete &amp; Reset PKI</button>
        </form>
      </div>
    <?php else: ?>
      <form method="post" style="padding:0 14px 14px;">
        <input type="hidden" name="form" value="init_pki">
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Initialize PKI</button>
      </form>
    <?php endif; ?>
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">2. Server Settings</div>
    <form method="post" style="padding:14px; display:flex; flex-direction:column; gap:14px;" onsubmit="var p=parseInt(this.port.value,10); var reserved={80:'Web UI (HTTP)',443:'Web UI (HTTPS)',22:'SSH',500:'IPsec IKE',4500:'IPsec NAT-T'}; if (reserved[p]) { alert('Port ' + p + ' is already used by ' + reserved[p] + ' on this gateway - pick a different port (943 is a safe TCP-mode alternative).'); return false; }">
      <input type="hidden" name="form" value="set_config">
      <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
        <input type="checkbox" name="enabled" value="1" <?= $cfg['enabled'] ? 'checked' : '' ?>>
        Enable OpenVPN server
      </label>
      <div style="display:flex; gap:24px;">
        <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
          <input type="checkbox" name="remote_access_enabled" value="1" <?= $cfg['remote_access_enabled'] ? 'checked' : '' ?>>
          Remote Access mode (road-warrior clients)
        </label>
        <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
          <input type="checkbox" name="site_to_site_enabled" value="1" <?= $cfg['site_to_site_enabled'] ? 'checked' : '' ?>>
          Site-to-Site mode
        </label>
      </div>
      <div style="display:flex; gap:16px; flex-wrap:wrap;">
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Protocol</label>
          <select name="protocol">
            <option value="udp" <?= $cfg['protocol'] === 'udp' ? 'selected' : '' ?>>UDP (default, faster)</option>
            <option value="tcp" <?= $cfg['protocol'] === 'tcp' ? 'selected' : '' ?>>TCP (blends in as HTTPS, better firewall traversal)</option>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Port</label>
          <input type="number" name="port" value="<?= htmlspecialchars((string) $cfg['port']) ?>" min="1" max="65535" style="width:100px;">
          <p style="font-size:11px; color:#b3261e; margin:2px 0 0; max-width:220px;">
            ⚠️ Do NOT use 443, 80, 22, 500, or 4500 - all already used by this gateway's own Web UI/SSH/IPsec.
            For TCP mode specifically, <strong>943</strong> is a safe common alternative that still avoids
            looking like a random port, without the collision.
          </p>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Remote Access subnet</label>
          <input type="text" name="remote_access_subnet" value="<?= htmlspecialchars($cfg['remote_access_subnet']) ?>" style="width:160px;">
        </div>
      </div>
      <div style="margin-top:14px; padding:12px; background:#f0f6ff; border:1px solid #cfe0fb; border-radius:8px;">
        <label style="display:flex; align-items:center; gap:8px; font-size:13px; font-weight:500;">
          <input type="checkbox" name="radius_auth_enabled" value="1" <?= !empty($cfg['radius_auth_enabled']) ? 'checked' : '' ?>>
          Require RADIUS authentication in addition to certificate (Remote Access only)
        </label>
        <p style="font-size:12px; color:#6b7280; margin:6px 0 0;">
          Genuine two-factor: certificate (already required above) + a username/password checked against the
          RADIUS server(s) configured on <a href="/system.php?tab=authentication">System &gt; Authentication</a> -
          the same server list used for admin Web UI login (researched against pfSense: no separate RADIUS config
          for OpenVPN). Site-to-Site connections are unaffected - this only applies to Remote Access clients,
          which get an <code>auth-user-pass</code> prompt added to their downloaded <code>.ovpn</code> automatically.
        </p>
      </div>
      <div style="margin-top:14px;">
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save &amp; Apply</button>
      </div>
    </form>
  </div>
<?php elseif ($activeTab === 'clients'): ?>
  <p style="font-size:12px; color:#6b7280; margin-top:0;">
    Road-warrior clients - one certificate per user, matching pfSense's own "Local User Access" model. Each
    client gets a single bundled <code>.ovpn</code> file (CA + certificate + key + tls-crypt key all inline)
    ready to import into any OpenVPN app.
  </p>
  <?php if (!empty($clients)): ?>
    <div class="ntp-table-scroll" style="margin-bottom:20px;">
    <table class="ntp-table">
      <thead><tr><th>Name</th><th>Status</th><th>Created</th><th>Manage</th></tr></thead>
      <tbody>
      <?php foreach ($clients as $c): ?>
        <?php $isRevoked = !empty($c['revoked']); $isActive = ($c['active'] ?? true) && !$isRevoked; ?>
        <tr<?= (!$isActive) ? ' style="opacity:0.5;"' : '' ?>>
          <td><?= htmlspecialchars($c['name']) ?></td>
          <td>
            <?php if ($isRevoked): ?>
              <span class="ntp-badge ntp-badge-danger">Revoked</span>
            <?php elseif (!($c['active'] ?? true)): ?>
              <span class="ntp-badge ntp-badge-muted">Deactivated</span>
            <?php else: ?>
              <span class="ntp-badge ntp-badge-success">Active</span>
            <?php endif; ?>
          </td>
          <td style="font-size:11px; color:#6b7280;"><?= htmlspecialchars(date('Y-m-d H:i', (int) $c['created_at'])) ?></td>
          <td>
            <?php if (!$isRevoked): ?>
              <form method="post" style="display:inline-flex; gap:4px; align-items:center; margin-right:8px;">
                <input type="hidden" name="form" value="client_download">
                <input type="hidden" name="name" value="<?= htmlspecialchars($c['name']) ?>">
                <input type="text" name="server_host" placeholder="vpn.example.com or public IP" required style="font-size:11px; width:170px;">
                <button type="submit" style="background:#14213d; color:#fff; border:none; padding:4px 10px; font-size:11px; border-radius:6px;">Get .ovpn</button>
              </form>
              <form method="post" style="display:inline; margin-right:6px;">
                <input type="hidden" name="form" value="client_set_active">
                <input type="hidden" name="id" value="<?= htmlspecialchars($c['id']) ?>">
                <input type="hidden" name="active" value="<?= $isActive ? '0' : '1' ?>">
                <button type="submit" title="<?= $isActive ? 'Deactivate (reversible - blocks new connections without touching the certificate)' : 'Activate' ?>" style="background:none; border:none; cursor:pointer; color:<?= $isActive ? '#374151' : '#1a7f4b' ?>; padding:4px;">
                  <i class="ti ti-<?= $isActive ? 'player-pause' : 'player-play' ?>" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <form method="post" style="display:inline; margin-right:6px;" onsubmit="return confirm('Disconnect &quot;<?= htmlspecialchars($c['name']) ?>&quot;\'s current session, if any is active right now? They can reconnect immediately unless also deactivated or revoked.');">
                <input type="hidden" name="form" value="client_disconnect">
                <input type="hidden" name="name" value="<?= htmlspecialchars($c['name']) ?>">
                <button type="submit" title="Disconnect current session" style="background:none; border:none; cursor:pointer; color:#9a5b00; padding:4px;">
                  <i class="ti ti-plug-connected-x" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <form method="post" style="display:inline;" onsubmit="return confirm('Revoke client &quot;<?= htmlspecialchars($c['name']) ?>&quot;? This is PERMANENT - unlike Deactivate, the certificate itself is invalidated and cannot be restored.');">
                <input type="hidden" name="form" value="client_revoke">
                <input type="hidden" name="id" value="<?= htmlspecialchars($c['id']) ?>">
                <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;" title="Revoke (permanent)"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
              </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php endif; ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Create Client</div>
    <form method="post" style="padding:14px; display:flex; gap:10px; align-items:end;">
      <input type="hidden" name="form" value="client_create">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
        <input type="text" name="name" placeholder="johndoe-laptop" required style="width:220px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create</button>
    </form>
  </div>
<?php elseif ($activeTab === 'sites'): ?>
  <p style="font-size:12px; color:#6b7280; margin-top:0;">
    Site-to-Site peers - one certificate per remote node, an alternative to IPsec for connecting branch
    offices. <code>remote_subnet</code> is informational here (routing between sites is configured the same
    way as any other custom route once the tunnel is up) - it is not enforced automatically.
  </p>
  <?php if (!empty($sites)): ?>
    <div class="ntp-table-scroll" style="margin-bottom:20px;">
    <table class="ntp-table">
      <thead><tr><th>Name</th><th>Remote Subnet</th><th>Status</th><th>Created</th><th>Manage</th></tr></thead>
      <tbody>
      <?php foreach ($sites as $s): ?>
        <tr<?= !empty($s['revoked']) ? ' style="opacity:0.5;"' : '' ?>>
          <td><?= htmlspecialchars($s['name']) ?></td>
          <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($s['remote_subnet']) ?></td>
          <td><?= empty($s['revoked']) ? '<span class="ntp-badge ntp-badge-success">Active</span>' : '<span class="ntp-badge ntp-badge-danger">Revoked</span>' ?></td>
          <td style="font-size:11px; color:#6b7280;"><?= htmlspecialchars(date('Y-m-d H:i', (int) $s['created_at'])) ?></td>
          <td>
            <?php if (empty($s['revoked'])): ?>
              <form method="post" style="display:inline-flex; gap:4px; align-items:center; margin-right:8px;">
                <input type="hidden" name="form" value="site_download">
                <input type="hidden" name="name" value="<?= htmlspecialchars($s['name']) ?>">
                <input type="text" name="server_host" placeholder="vpn.example.com or public IP" required style="font-size:11px; width:170px;">
                <button type="submit" style="background:#14213d; color:#fff; border:none; padding:4px 10px; font-size:11px; border-radius:6px;">Get .ovpn</button>
              </form>
              <form method="post" style="display:inline;" onsubmit="return confirm('Revoke site &quot;<?= htmlspecialchars($s['name']) ?>&quot;?');">
                <input type="hidden" name="form" value="site_revoke">
                <input type="hidden" name="id" value="<?= htmlspecialchars($s['id']) ?>">
                <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;" title="Revoke"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
              </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php endif; ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Create Site</div>
    <form method="post" style="padding:14px; display:flex; gap:10px; align-items:end;">
      <input type="hidden" name="form" value="site_create">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
        <input type="text" name="name" placeholder="Branch-Office-2" required style="width:200px;">
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Remote subnet</label>
        <input type="text" name="remote_subnet" placeholder="192.168.50.0/24" style="width:160px;">
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create</button>
    </form>
  </div>
<?php elseif ($activeTab === 'connected'): ?>
  <?php $connected = $statusData['connected_clients'] ?? []; $connectedCount = $statusData['connected_count'] ?? count($connected); $isLive = !empty($statusData['live']); ?>
  <div style="display:flex; gap:14px; margin-bottom:16px; flex-wrap:wrap;">
    <div class="ntp-card" style="flex:1; min-width:180px; padding:16px; text-align:center;">
      <div style="font-size:32px; font-weight:700; color:#14213d;"><?= (int) $connectedCount ?></div>
      <div style="font-size:12px; color:#6b7280; margin-top:2px;">user(s) connected right now</div>
    </div>
    <div class="ntp-card" style="flex:2; min-width:220px; padding:16px;">
      <table class="ntp-table" style="border:none;">
        <tr><th>Installed</th><td><?= !empty($statusData['installed']) ? '<span class="ntp-badge ntp-badge-success">Yes</span>' : '<span class="ntp-badge ntp-badge-warning">No</span>' ?></td></tr>
        <tr><th>Running</th><td><?= !empty($statusData['running']) ? '<span class="ntp-badge ntp-badge-success">Running</span>' : '<span class="ntp-badge ntp-badge-warning">Stopped</span>' ?></td></tr>
        <tr><th>Data source</th><td style="font-size:11px; color:#6b7280;"><?= $isLive ? 'Live (management interface)' : 'Fallback (status log file - management interface unreachable)' ?></td></tr>
      </table>
    </div>
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">Connected Users</div>
    <?php if (empty($connected)): ?>
      <p style="padding:12px 14px; font-size:12px; color:#6b7280;">No one is connected right now.</p>
    <?php else: ?>
      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead><tr><th>Common Name</th><th>Real Address</th><th>Virtual Address</th><th>Connected Since</th><th>Manage</th></tr></thead>
        <tbody>
        <?php foreach ($connected as $c): ?>
          <?php $cn = (string) ($c['common_name'] ?? ''); $displayName = str_starts_with($cn, 'client-') ? substr($cn, 7) : $cn; ?>
          <tr>
            <td><?= htmlspecialchars($displayName) ?></td>
            <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($c['real_address'] ?? '') ?></td>
            <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($c['virtual_address'] ?? '') ?></td>
            <td style="font-size:12px;"><?= htmlspecialchars($c['connected_since'] ?? '') ?></td>
            <td>
              <form method="post" style="margin:0; display:inline;" onsubmit="return confirm('Disconnect &quot;<?= htmlspecialchars($displayName) ?>&quot;\'s current session?');">
                <input type="hidden" name="form" value="client_disconnect">
                <input type="hidden" name="name" value="<?= htmlspecialchars($displayName) ?>">
                <button type="submit" title="Disconnect" style="background:none; border:none; cursor:pointer; color:#9a5b00; padding:4px;"><i class="ti ti-plug-connected-x" style="font-size:16px;" aria-hidden="true"></i></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
    <?php endif; ?>
  </div>
<?php endif; ?>
<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
