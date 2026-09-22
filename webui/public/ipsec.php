<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();
Auth::requireCategory('ipsec');

$configd = new NtpsenseConfigd();
$configdError = null;
$saveMessage = null;
$saveError = null;
$tunnels = [];
$installed = false;

// Pilihan dropdown P1/P2 - dibatasi ke kombinasi modern yang aman
// (bukan daftar lengkap semua algoritma yang didukung strongSwan) -
// keputusan scope yang disengaja, sama prinsip dengan Policy tab
// Security (kurasi daripada daftar penuh yang membingungkan admin).
const ENCRYPTION_OPTIONS = [
    'aes128' => 'AES (128 bits)',
    'aes256' => 'AES (256 bits)',
    'aes128gcm16' => 'AES-GCM (128 bits)',
    'aes256gcm16' => 'AES-GCM (256 bits)',
];
const INTEGRITY_OPTIONS = [
    'sha256' => 'SHA256',
    'sha384' => 'SHA384',
    'sha512' => 'SHA512',
];
const DH_GROUP_OPTIONS = [
    'modp2048' => '14 (2048-bit)',
    'modp3072' => '15 (3072-bit)',
    'ecp256' => '19 (256-bit ECP)',
    'ecp384' => '20 (384-bit ECP)',
];
const PFS_GROUP_OPTIONS = [
    '' => 'None (no PFS)',
    'modp2048' => '14 (2048-bit)',
    'modp3072' => '15 (3072-bit)',
    'ecp256' => '19 (256-bit ECP)',
    'ecp384' => '20 (384-bit ECP)',
];

function renderSelect(string $name, array $options, string $selected): void
{
    echo "<select name=\"{$name}\" style=\"width:100%;\">";
    foreach ($options as $value => $label) {
        $sel = ($value === $selected) ? ' selected' : '';
        echo '<option value="' . htmlspecialchars($value) . '"' . $sel . '>' . htmlspecialchars($label) . '</option>';
    }
    echo '</select>';
}

try {
    $status = $configd->call('ipsec.get_config');
    $installed = (bool) ($status['installed'] ?? false);
    $tunnels = $status['tunnels'] ?? [];
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}

$activeTab = $_GET['tab'] ?? 'tunnels';
if (!in_array($activeTab, ['tunnels', 'status', 'log'], true)) {
    $activeTab = 'tunnels';
}
$editingId = $_GET['edit'] ?? '';
$editingTunnel = null;
foreach ($tunnels as $t) {
    if (($t['id'] ?? '') === $editingId) {
        $editingTunnel = $t;
        break;
    }
}
$phase2ForId = $_GET['phase2_for'] ?? '';
$editPhase2Id = $_GET['edit_phase2'] ?? '';
$editPhase2Tunnel = null;
$editPhase2Entry = null;
foreach ($tunnels as $t) {
    foreach (($t['phase2'] ?? []) as $p2) {
        if (($p2['id'] ?? '') === $editPhase2Id) {
            $editPhase2Tunnel = $t;
            $editPhase2Entry = $p2;
            break 2;
        }
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_POST['form'] ?? '', ['ipsec_tunnel_add', 'ipsec_tunnel_edit'], true)) {
    try {
        $isEdit = ($_POST['form'] === 'ipsec_tunnel_edit');
        $params = [
            'name' => (string) ($_POST['name'] ?? ''),
            'peer_address' => (string) ($_POST['peer_address'] ?? ''),
            'psk' => (string) ($_POST['psk'] ?? ''),
            'p1_encryption' => (string) ($_POST['p1_encryption'] ?? 'aes256'),
            'p1_integrity' => (string) ($_POST['p1_integrity'] ?? 'sha256'),
            'p1_dh_group' => (string) ($_POST['p1_dh_group'] ?? 'modp2048'),
        ];
        if ($isEdit) {
            $params['id'] = (string) ($_POST['id'] ?? '');
        }
        $result = $configd->call($isEdit ? 'ipsec.tunnel_edit' : 'ipsec.tunnel_add', $params, 30.0);
        $saveMessage = $isEdit
            ? 'Tunnel updated.'
            : 'Phase 1 added. Now add at least one Phase 2 (subnet pair) below before this tunnel can pass any traffic. Configure the same peer address, PSK, and mirrored subnets on the remote side.';
        $tunnels = $result['tunnels'] ?? $tunnels;
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ipsec_tunnel_delete') {
    try {
        $configd->call('ipsec.tunnel_delete', ['id' => (string) ($_POST['id'] ?? '')], 30.0);
        $saveMessage = 'Tunnel deleted.';
        $tunnels = $configd->call('ipsec.get_config')['tunnels'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ipsec_tunnel_set_enabled') {
    try {
        $enabling = ($_POST['enabled'] ?? '') === '1';
        $configd->call('ipsec.tunnel_set_enabled', [
            'id' => (string) ($_POST['id'] ?? ''),
            'enabled' => $enabling,
        ], 30.0);
        $saveMessage = $enabling ? 'Tunnel enabled.' : 'Tunnel disabled.';
        $tunnels = $configd->call('ipsec.get_config')['tunnels'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_POST['form'] ?? '', ['ipsec_phase2_add', 'ipsec_phase2_edit'], true)) {
    try {
        $isP2Edit = ($_POST['form'] === 'ipsec_phase2_edit');
        $p2Params = [
            'tunnel_id' => (string) ($_POST['tunnel_id'] ?? ''),
            'local_subnet' => (string) ($_POST['local_subnet'] ?? ''),
            'remote_subnet' => (string) ($_POST['remote_subnet'] ?? ''),
            'p2_encryption' => (string) ($_POST['p2_encryption'] ?? 'aes256'),
            'p2_integrity' => (string) ($_POST['p2_integrity'] ?? 'sha256'),
            'p2_dh_group' => (string) ($_POST['p2_dh_group'] ?? ''),
        ];
        if ($isP2Edit) {
            $p2Params['phase2_id'] = (string) ($_POST['phase2_id'] ?? '');
        }
        $result = $configd->call($isP2Edit ? 'ipsec.phase2_edit' : 'ipsec.phase2_add', $p2Params, 30.0);
        $saveMessage = $isP2Edit ? 'Phase 2 updated.' : 'Phase 2 added.';
        $tunnels = $result['tunnels'] ?? $tunnels;
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ipsec_tunnel_terminate') {
    try {
        $configd->call('ipsec.tunnel_terminate', ['id' => (string) ($_POST['id'] ?? '')], 30.0);
        $saveMessage = 'Phase 1 disconnected - it will reconnect automatically the next time matching traffic is sent.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ipsec_phase2_terminate') {
    try {
        $configd->call('ipsec.phase2_terminate', ['phase2_id' => (string) ($_POST['phase2_id'] ?? '')], 30.0);
        $saveMessage = 'Phase 2 disconnected - it will reconnect automatically the next time matching traffic is sent.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ipsec_phase2_set_enabled') {
    try {
        $enablingP2 = ($_POST['enabled'] ?? '') === '1';
        $result = $configd->call('ipsec.phase2_set_enabled', [
            'tunnel_id' => (string) ($_POST['tunnel_id'] ?? ''),
            'phase2_id' => (string) ($_POST['phase2_id'] ?? ''),
            'enabled' => $enablingP2,
        ], 30.0);
        $saveMessage = $enablingP2 ? 'Phase 2 enabled.' : 'Phase 2 disabled.';
        $tunnels = $configd->call('ipsec.get_config')['tunnels'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ipsec_phase2_delete') {
    try {
        $result = $configd->call('ipsec.phase2_delete', [
            'tunnel_id' => (string) ($_POST['tunnel_id'] ?? ''),
            'phase2_id' => (string) ($_POST['phase2_id'] ?? ''),
        ], 30.0);
        $saveMessage = 'Phase 2 removed.';
        $tunnels = $result['tunnels'] ?? $tunnels;
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

$statusTunnels = [];
if ($activeTab === 'status') {
    try {
        $statusTunnels = $configd->call('ipsec.get_status')['tunnels'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

$logLines = [];
if ($activeTab === 'log') {
    try {
        $logLines = $configd->call('ipsec.get_log', ['limit' => 300])['lines'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

$pageTitle = 'IPsec VPN';
$activeNavItem = 'ipsec';
$breadcrumbTail = [ucfirst($activeTab)];
require __DIR__ . '/../templates/layout_header.php';

if (!$installed) {
    $categoryLabel = 'IPsec VPN';
    $categoryIcon = 'ti-lock-access';
    require __DIR__ . '/../templates/plugin_not_installed.php';
    require __DIR__ . '/../templates/layout_footer.php';
    exit;
}
?>

<?php if ($configdError): ?>
  <div class="ntp-alert-error">Unable to fetch IPsec status: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($saveMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($saveMessage) ?></div>
<?php endif; ?>
<?php if ($saveError): ?>
  <div class="ntp-alert-error">Failed: <?= htmlspecialchars($saveError) ?></div>
<?php endif; ?>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=tunnels" class="ntp-tab<?= $activeTab === 'tunnels' ? ' active' : '' ?>">Tunnels</a>
  <a href="?tab=status" class="ntp-tab<?= $activeTab === 'status' ? ' active' : '' ?>">Status</a>
  <a href="?tab=log" class="ntp-tab<?= $activeTab === 'log' ? ' active' : '' ?>">IPsec Log</a>
</div>

<?php if ($activeTab === 'tunnels'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Phase 1 (IKE) — Site-to-Site Tunnels</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    IKEv2 only (the modern default recommended by pfSense, FortiGate, and Palo Alto alike). Each Phase 1
    connects to one peer; add one or more Phase 2 entries below a tunnel to define which subnet pairs actually
    pass traffic through it — a tunnel with no Phase 2 will negotiate but carry nothing. Firewall access for
    decrypted tunnel traffic is controlled separately from <a href="/firewall.php?zone=enc0">Firewall &gt; enc0</a>.
  </p>
  <table class="ntp-table">
    <tr><th>Name</th><th>Peer address</th><th>P1 Encryption</th><th>P1 Integrity</th><th>P1 DH Group</th><th>Status</th><th>Manage</th></tr>
    <?php if (empty($tunnels)): ?>
      <tr><td colspan="7" style="color:#6b7280;">No tunnels configured.</td></tr>
    <?php endif; ?>
    <?php foreach ($tunnels as $t): ?>
      <?php $enabled = $t['enabled'] ?? true; ?>
      <tr<?= $enabled ? '' : ' style="opacity:.6;"' ?>>
        <td><?= htmlspecialchars($t['name'] ?? '') ?></td>
        <td><?= htmlspecialchars($t['peer_address'] ?? '') ?></td>
        <td><?= htmlspecialchars(ENCRYPTION_OPTIONS[$t['p1_encryption'] ?? ''] ?? ($t['p1_encryption'] ?? '')) ?></td>
        <td><?= htmlspecialchars(INTEGRITY_OPTIONS[$t['p1_integrity'] ?? ''] ?? ($t['p1_integrity'] ?? '')) ?></td>
        <td><?= htmlspecialchars(DH_GROUP_OPTIONS[$t['p1_dh_group'] ?? ''] ?? ($t['p1_dh_group'] ?? '')) ?></td>
        <td>
          <?php if ($enabled): ?>
            <span class="ntp-badge ntp-badge-success">Enabled</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-muted">Disabled</span>
          <?php endif; ?>
        </td>
        <td style="white-space:nowrap;">
          <a href="?tab=tunnels&edit=<?= urlencode($t['id']) ?>" title="Edit Phase 1" style="color:#374151; padding:4px; display:inline-block; text-decoration:none;">
            <i class="ti ti-pencil" style="font-size:16px;" aria-hidden="true"></i>
          </a>
          <form method="post" style="margin:0; display:inline-block;">
            <input type="hidden" name="form" value="ipsec_tunnel_set_enabled">
            <input type="hidden" name="id" value="<?= htmlspecialchars($t['id']) ?>">
            <?php if ($enabled): ?>
              <input type="hidden" name="enabled" value="0">
              <button type="submit" title="Disable" style="background:none; border:none; cursor:pointer; color:#9a5b00; padding:4px;">
                <i class="ti ti-plug-connected-x" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            <?php else: ?>
              <input type="hidden" name="enabled" value="1">
              <button type="submit" title="Enable" style="background:none; border:none; cursor:pointer; color:#1a7f4b; padding:4px;">
                <i class="ti ti-plug-connected" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            <?php endif; ?>
          </form>
          <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Disconnect this Phase 1 now? It will reconnect automatically on the next matching traffic (start_action = trap) - this does not disable or delete the tunnel.');">
            <input type="hidden" name="form" value="ipsec_tunnel_terminate">
            <input type="hidden" name="id" value="<?= htmlspecialchars($t['id']) ?>">
            <button type="submit" title="Disconnect (temporary - will reconnect on new traffic)" style="background:none; border:none; cursor:pointer; color:#6b7280; padding:4px;">
              <i class="ti ti-plug-x" style="font-size:16px;" aria-hidden="true"></i>
            </button>
          </form>
          <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete tunnel <?= htmlspecialchars($t['name'] ?? '') ?> and ALL its Phase 2 entries? The remote peer will need to be reconfigured too.');">
            <input type="hidden" name="form" value="ipsec_tunnel_delete">
            <input type="hidden" name="id" value="<?= htmlspecialchars($t['id']) ?>">
            <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
              <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
            </button>
          </form>
        </td>
      </tr>
      <tr>
        <td colspan="7" style="background:#f9fafb; padding:10px 14px 14px 30px;">
          <strong style="font-size:12px; color:#374151;">Phase 2 (<?= count($t['phase2'] ?? []) ?>)</strong>
          <table class="ntp-table" style="margin-top:6px;">
            <tr><th>Local subnet</th><th>Remote subnet</th><th>Encryption</th><th>Auth (integrity)</th><th>PFS</th><th>Status</th><th>Manage</th></tr>
            <?php if (empty($t['phase2'])): ?>
              <tr><td colspan="7" style="color:#9ca3af;">No Phase 2 yet — this tunnel won't pass any traffic until one is added.</td></tr>
            <?php endif; ?>
            <?php foreach (($t['phase2'] ?? []) as $p2): ?>
              <?php $p2Enabled = $p2['enabled'] ?? true; ?>
              <tr<?= $p2Enabled ? '' : ' style="opacity:.6;"' ?>>
                <td><?= htmlspecialchars($p2['local_subnet'] ?? '') ?></td>
                <td><?= htmlspecialchars($p2['remote_subnet'] ?? '') ?></td>
                <td><?= htmlspecialchars(ENCRYPTION_OPTIONS[$p2['p2_encryption'] ?? ''] ?? ($p2['p2_encryption'] ?? '')) ?></td>
                <td><?= htmlspecialchars(INTEGRITY_OPTIONS[$p2['p2_integrity'] ?? ''] ?? ($p2['p2_integrity'] ?? '')) ?></td>
                <td><?= htmlspecialchars(PFS_GROUP_OPTIONS[$p2['p2_dh_group'] ?? ''] ?? ($p2['p2_dh_group'] ?: 'None')) ?></td>
                <td>
                  <?php if ($p2Enabled): ?>
                    <span class="ntp-badge ntp-badge-success">Enabled</span>
                  <?php else: ?>
                    <span class="ntp-badge ntp-badge-muted">Disabled</span>
                  <?php endif; ?>
                </td>
                <td style="white-space:nowrap;">
                  <a href="?tab=tunnels&edit_phase2=<?= urlencode($p2['id']) ?>" title="Edit Phase 2" style="color:#374151; padding:4px; display:inline-block; text-decoration:none;">
                    <i class="ti ti-pencil" style="font-size:14px;" aria-hidden="true"></i>
                  </a>
                  <form method="post" style="margin:0; display:inline-block;">
                    <input type="hidden" name="form" value="ipsec_phase2_set_enabled">
                    <input type="hidden" name="tunnel_id" value="<?= htmlspecialchars($t['id']) ?>">
                    <input type="hidden" name="phase2_id" value="<?= htmlspecialchars($p2['id']) ?>">
                    <?php if ($p2Enabled): ?>
                      <input type="hidden" name="enabled" value="0">
                      <button type="submit" title="Disable" style="background:none; border:none; cursor:pointer; color:#9a5b00; padding:4px;">
                        <i class="ti ti-plug-connected-x" style="font-size:14px;" aria-hidden="true"></i>
                      </button>
                    <?php else: ?>
                      <input type="hidden" name="enabled" value="1">
                      <button type="submit" title="Enable" style="background:none; border:none; cursor:pointer; color:#1a7f4b; padding:4px;">
                        <i class="ti ti-plug-connected" style="font-size:14px;" aria-hidden="true"></i>
                      </button>
                    <?php endif; ?>
                  </form>
                  <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Disconnect this Phase 2 now? It will reconnect automatically on the next matching traffic - this does not disable or delete it.');">
                    <input type="hidden" name="form" value="ipsec_phase2_terminate">
                    <input type="hidden" name="phase2_id" value="<?= htmlspecialchars($p2['id']) ?>">
                    <button type="submit" title="Disconnect (temporary - will reconnect on new traffic)" style="background:none; border:none; cursor:pointer; color:#6b7280; padding:4px;">
                      <i class="ti ti-plug-x" style="font-size:14px;" aria-hidden="true"></i>
                    </button>
                  </form>
                  <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Remove this Phase 2 entry?');">
                    <input type="hidden" name="form" value="ipsec_phase2_delete">
                    <input type="hidden" name="tunnel_id" value="<?= htmlspecialchars($t['id']) ?>">
                    <input type="hidden" name="phase2_id" value="<?= htmlspecialchars($p2['id']) ?>">
                    <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                      <i class="ti ti-trash" style="font-size:14px;" aria-hidden="true"></i>
                    </button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
          </table>
          <?php $isEditingThisP2 = $editPhase2Tunnel && $editPhase2Tunnel['id'] === $t['id']; ?>
          <?php if ($phase2ForId === $t['id'] || $isEditingThisP2): ?>
            <form method="post" style="margin-top:8px; display:grid; grid-template-columns:repeat(3, 1fr); gap:10px;">
              <input type="hidden" name="form" value="<?= $isEditingThisP2 ? 'ipsec_phase2_edit' : 'ipsec_phase2_add' ?>">
              <input type="hidden" name="tunnel_id" value="<?= htmlspecialchars($t['id']) ?>">
              <?php if ($isEditingThisP2): ?>
                <input type="hidden" name="phase2_id" value="<?= htmlspecialchars($editPhase2Entry['id']) ?>">
              <?php endif; ?>
              <div>
                <label style="display:block; font-size:11px; color:#374151; margin-bottom:2px;">Local subnet (this gateway's side)</label>
                <input type="text" name="local_subnet" required placeholder="10.252.1.0/24" style="width:100%;" value="<?= htmlspecialchars($editPhase2Entry['local_subnet'] ?? '') ?>">
              </div>
              <div>
                <label style="display:block; font-size:11px; color:#374151; margin-bottom:2px;">Remote subnet (peer's side)</label>
                <input type="text" name="remote_subnet" required placeholder="192.168.50.0/24" style="width:100%;" value="<?= htmlspecialchars($editPhase2Entry['remote_subnet'] ?? '') ?>">
              </div>
              <div></div>
              <div>
                <label style="display:block; font-size:11px; color:#374151; margin-bottom:2px;">P2 Encryption</label>
                <?php renderSelect('p2_encryption', ENCRYPTION_OPTIONS, $editPhase2Entry['p2_encryption'] ?? 'aes256'); ?>
              </div>
              <div>
                <label style="display:block; font-size:11px; color:#374151; margin-bottom:2px;">P2 Auth (integrity)</label>
                <?php renderSelect('p2_integrity', INTEGRITY_OPTIONS, $editPhase2Entry['p2_integrity'] ?? 'sha256'); ?>
              </div>
              <div>
                <label style="display:block; font-size:11px; color:#374151; margin-bottom:2px;">PFS Group</label>
                <?php renderSelect('p2_dh_group', PFS_GROUP_OPTIONS, $editPhase2Entry['p2_dh_group'] ?? ''); ?>
              </div>
              <div style="grid-column: 1 / -1;">
                <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 14px; font-size:12px; border-radius:6px;"><?= $isEditingThisP2 ? 'Update Phase 2' : 'Save Phase 2' ?></button>
                <a href="?tab=tunnels" style="font-size:12px; color:#6b7280; margin-left:10px;">cancel</a>
              </div>
            </form>
          <?php else: ?>
            <a href="?tab=tunnels&phase2_for=<?= urlencode($t['id']) ?>" style="display:inline-block; margin-top:8px; font-size:12px; background:#ffffff; border:1px solid #d1d5db; padding:5px 12px; border-radius:6px; text-decoration:none; color:#14213d;">+ Add P2</a>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
  </table>

  <?php if ($editingTunnel): ?>
    <div style="padding:10px 14px 0; font-size:12px; color:#14213d; font-weight:500;">
      Editing "<?= htmlspecialchars($editingTunnel['name'] ?? '') ?>" — <a href="?tab=tunnels" style="color:#6b7280;">cancel</a>
    </div>
  <?php endif; ?>
  <form method="post" style="padding:14px; display:grid; grid-template-columns:repeat(3, 1fr); gap:12px;">
    <input type="hidden" name="form" value="<?= $editingTunnel ? 'ipsec_tunnel_edit' : 'ipsec_tunnel_add' ?>">
    <?php if ($editingTunnel): ?>
      <input type="hidden" name="id" value="<?= htmlspecialchars($editingTunnel['id']) ?>">
    <?php endif; ?>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Tunnel name</label>
      <input type="text" name="name" required placeholder="Branch-Office-2" style="width:100%;" value="<?= htmlspecialchars($editingTunnel['name'] ?? '') ?>">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Peer address (IP or FQDN)</label>
      <input type="text" name="peer_address" required placeholder="203.0.113.10" style="width:100%;" value="<?= htmlspecialchars($editingTunnel['peer_address'] ?? '') ?>">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Pre-shared key</label>
      <input type="text" name="psk" required style="width:100%; font-family:monospace;" value="<?= htmlspecialchars($editingTunnel['psk'] ?? '') ?>">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">P1 Protocol (Encryption)</label>
      <?php renderSelect('p1_encryption', ENCRYPTION_OPTIONS, $editingTunnel['p1_encryption'] ?? 'aes256'); ?>
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">P1 Transform (Integrity)</label>
      <?php renderSelect('p1_integrity', INTEGRITY_OPTIONS, $editingTunnel['p1_integrity'] ?? 'sha256'); ?>
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">P1 DH Group</label>
      <?php renderSelect('p1_dh_group', DH_GROUP_OPTIONS, $editingTunnel['p1_dh_group'] ?? 'modp2048'); ?>
    </div>
    <div style="grid-column: 1 / -1;">
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;"><?= $editingTunnel ? 'Update Phase 1' : 'Add Phase 1' ?></button>
    </div>
  </form>
</div>

<?php elseif ($activeTab === 'status'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Tunnel Status</div>
  <table class="ntp-table">
    <tr><th>Name</th><th>Enabled</th><th>Phase 2 count</th><th>Connection</th></tr>
    <?php if (empty($statusTunnels)): ?>
      <tr><td colspan="4" style="color:#6b7280;">No tunnels configured.</td></tr>
    <?php endif; ?>
    <?php foreach ($statusTunnels as $t): ?>
      <tr>
        <td><?= htmlspecialchars($t['name'] ?? '') ?></td>
        <td><?= !empty($t['enabled']) ? 'Yes' : 'No' ?></td>
        <td><?= (int) ($t['phase2_count'] ?? 0) ?></td>
        <td>
          <?php if (!empty($t['connected'])): ?>
            <span class="ntp-badge ntp-badge-success">Established</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-muted">Not established</span>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
  </table>
  <p style="padding:12px 14px; font-size:11px; color:#9ca3af;">
    Tunnels use start_action = trap by default — they only come up when matching traffic is actually sent.
    "Not established" on an enabled tunnel with a Phase 2 but no recent traffic is expected, not necessarily
    a fault. Check <a href="?tab=log">IPsec Log</a> for the underlying negotiation details.
  </p>
</div>

<?php elseif ($activeTab === 'log'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">IPsec Log (charon)</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Most recent strongSwan/charon log lines — use this to troubleshoot a tunnel that won't come up (mismatched
    PSK, mismatched subnets/proposals, or the peer not responding are the most common causes).
  </p>
  <pre style="margin:0; padding:12px 14px; font-size:11px; white-space:pre-wrap; font-family:monospace; background:#f9fafb; max-height:600px; overflow-y:auto;"><?php
    if (empty($logLines)) {
        echo "No log entries yet.";
    } else {
        echo htmlspecialchars(implode("\n", $logLines));
    }
  ?></pre>
</div>
<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
