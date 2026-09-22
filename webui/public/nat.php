<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();
Auth::requireCategory('nat');

$configd = new NtpsenseConfigd();
$configdError = null;
$saveMessage = null;
$saveError = null;

// Robust boolean reader for values that round-tripped through JSON/NDJSON
// (same pattern already applied on security.php after a real mismatch
// there - applied here proactively rather than waiting for a repeat).
function natBool($val, bool $default): bool
{
    if ($val === null) return $default;
    if (is_bool($val)) return $val;
    if (is_int($val) || is_float($val)) return $val != 0;
    if (is_string($val)) return in_array(strtolower(trim($val)), ['1', 'true', 'yes', 'on'], true);
    return $default;
}

$activeTab = $_GET['tab'] ?? 'outbound';
if (!in_array($activeTab, ['outbound', 'portforward'], true)) {
    $activeTab = 'outbound';
}

// WAN1's physical interface + current status - reused from the same
// "network.zones" source of truth every other page uses (Security,
// Firewall, DHCP), not a separate/duplicated lookup.
$wan1Zone = null;
$allWanZones = [];
try {
    $zonesRaw = $configd->call('network.zones');
    $wan1Zone = $zonesRaw['wan1'] ?? null;

    // RCA: sebelumnya tab ini HARDCODE cuma WAN1 - ditulis dari zaman
    // sebelum Multi-WAN ada sama sekali ("only becomes relevant once
    // multiple WAN interfaces exist" - literalnya sudah tertulis di
    // teks lama, tapi tidak pernah diupdate begitu Multi-WAN benar-benar
    // dibangun). Sekarang ambil SEMUA interface eligible Multi-WAN
    // (WAN1 + OPT/LAGG/VLAN dengan Role=WAN) - backend
    // (multiwan::regenerate_outbound_nat()) SUDAH menulis baris NAT
    // untuk semuanya sejak gateway pertama dibuat, cuma tampilan di
    // halaman ini yang ketinggalan.
    $eligibleWanIfaces = $configd->call('multiwan.eligible_interfaces')['interfaces'] ?? [];
    $zoneByInterface = [];
    if (!empty($zonesRaw['wan1']['interface'])) {
        $zoneByInterface[$zonesRaw['wan1']['interface']] = $zonesRaw['wan1'];
    }
    foreach (($zonesRaw['opt'] ?? []) as $opt) {
        if (!empty($opt['interface'])) {
            $zoneByInterface[$opt['interface']] = $opt;
        }
    }
    foreach ($eligibleWanIfaces as $iface) {
        $allWanZones[] = $zoneByInterface[$iface] ?? ['interface' => $iface, 'alias' => $iface, 'ip' => null];
    }
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
$wan1If = $wan1Zone['interface'] ?? null;

// Add / Edit / Copy all funnel through the SAME backend primitives
// (add + delete) - there is no "update" action in the daemon by design
// (Doc 7 §1.3: "two primitives are enough"), matching exactly how the
// Firewall Rules page already does Edit (delete-old-then-add-new). A
// 'replace_id' field, when present, means "delete this id first, then
// add" - i.e. Edit. Copy is just Add with values borrowed from an
// existing rule (a fresh id is generated automatically by the backend).
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'nat_portforward_add') {
    if (!$wan1If) {
        $saveError = 'WAN1 interface not detected - configure it on the Network page first.';
    } else {
        try {
            $replaceId = (string) ($_POST['replace_id'] ?? '');
            if ($replaceId !== '') {
                $configd->call('firewall.custom_rules.delete', ['id' => $replaceId]);
            }
            $configd->call('firewall.custom_rules.add', [
                'interface' => $wan1If,
                'action' => 'pass',
                'protocol' => (string) ($_POST['protocol'] ?? 'tcp'),
                'source' => 'any',
                'destination' => 'any',
                'port' => (int) ($_POST['external_port'] ?? 0),
                'description' => (string) ($_POST['description'] ?? ''),
                'nat_redirect_ip' => (string) ($_POST['internal_ip'] ?? ''),
                'nat_redirect_port' => (int) ($_POST['internal_port'] ?? 0),
            ]);
            $saveMessage = $replaceId !== '' ? 'Port forward rule updated.' : 'Port forward rule added.';
        } catch (NtpsenseConfigdException $e) {
            $saveError = $e->getMessage();
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'nat_portforward_delete') {
    try {
        $configd->call('firewall.custom_rules.delete', ['id' => (string) ($_POST['id'] ?? '')]);
        $saveMessage = 'Port forward rule deleted.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'nat_portforward_copy') {
    try {
        $configd->call('firewall.custom_rules.add', [
            'interface' => (string) ($_POST['interface'] ?? $wan1If),
            'action' => 'pass',
            'protocol' => (string) ($_POST['protocol'] ?? 'tcp'),
            'source' => 'any',
            'destination' => 'any',
            'port' => (int) ($_POST['external_port'] ?? 0),
            'description' => trim((string) ($_POST['description'] ?? '') . ' (copy)'),
            'nat_redirect_ip' => (string) ($_POST['internal_ip'] ?? ''),
            'nat_redirect_port' => (int) ($_POST['internal_port'] ?? 0),
        ]);
        $saveMessage = 'Port forward rule copied - remember to change the external port before it takes effect (two rules on the same port will conflict).';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'nat_portforward_reorder') {
    try {
        $configd->call('firewall.custom_rules.reorder', [
            'id' => (string) ($_POST['id'] ?? ''),
            'direction' => (string) ($_POST['direction'] ?? ''),
        ]);
        $saveMessage = 'Rule order updated.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

// Port Forward tab: firewall.custom_rules.list returns EVERY custom rule
// across every interface (same action Firewall page uses) - filtered
// here to just the ones that carry a nat_redirect_ip, i.e. the ones this
// page itself created. Plain WAN1 pass/block rules (and the WireGuard
// auto-punch rule) are deliberately left out - those stay owned by the
// Firewall page, this page only owns what it created.
$portForwardRules = [];
$editingRule = null;
if ($activeTab === 'portforward') {
    try {
        $allRules = $configd->call('firewall.custom_rules.list')['rules'] ?? [];
        foreach ($allRules as $r) {
            if (!empty($r['nat_redirect_ip'])) {
                $portForwardRules[] = $r;
                if (($_GET['edit'] ?? '') === $r['id']) {
                    $editingRule = $r;
                }
            }
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

$tabLabels = ['outbound' => 'Outbound', 'portforward' => 'Port Forward'];
$pageTitle = 'NAT';
$activeNavItem = 'nat';
// Layer 1 (app header) - konsisten dengan pola Firewall/IPsec.
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';
?>

<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch NAT status: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($saveMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($saveMessage) ?></div>
<?php endif; ?>
<?php if ($saveError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($saveError) ?></div>
<?php endif; ?>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=outbound" class="ntp-tab<?= $activeTab === 'outbound' ? ' active' : '' ?>">Outbound</a>
  <a href="?tab=portforward" class="ntp-tab<?= $activeTab === 'portforward' ? ' active' : '' ?>">Port Forward</a>
</div>

<?php if ($activeTab === 'outbound'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Outbound NAT (Source NAT)</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Translates internal (LAN/OPT) addresses to the exiting WAN's own public IP for outbound traffic - one
    <code>nat on &lt;interface&gt; ... -&gt; (&lt;interface&gt;)</code> rule per WAN below, generated automatically
    (per-uplink NAT is mandatory once more than one WAN exists - a client routed out via WAN2 but translated to
    WAN1's IP causes asymmetric routing that's nearly impossible to debug). Note this does not control
    <em>which</em> WAN traffic leaves through - that's a routing decision, see
    <a href="/multiwan.php">Multi-WAN</a> and <a href="/firewall.php">Firewall</a> rules for policy routing.
  </p>
  <?php if (empty($allWanZones)): ?>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No WAN interface detected.</p>
  <?php else: ?>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead><tr><th>Alias</th><th>Interface</th><th>Translates to</th></tr></thead>
      <tbody>
      <?php foreach ($allWanZones as $wz): ?>
        <tr>
          <td><?= htmlspecialchars($wz['alias'] ?? $wz['interface']) ?></td>
          <td><?= htmlspecialchars($wz['interface']) ?></td>
          <td><?= htmlspecialchars($wz['ip'] ?? '(DHCP - resolved live)') ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php endif; ?>
</div>
<p style="font-size:11px; color:#9ca3af; margin-top:10px;">
  Manual/Hybrid outbound modes (multiple public IPs, address pools) are not yet implemented.
</p>

<?php elseif ($activeTab === 'portforward'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Port Forward (Destination NAT)</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Redirects inbound connections on a WAN1 port to an internal host — e.g. exposing a web server or game
    server behind this gateway. Generates a combined pf nat+filter rule (<code>rdr-to</code>), reusing the
    same validated infrastructure as Firewall &gt; Rules. Exposing management/admin interfaces (like this
    gateway's own Web UI) to the internet is a real risk — always pair a port forward like that with a
    Firewall &gt; Rules restriction to a specific known source IP, never "any".
  </p>
  <div class="ntp-table-scroll">
  <table class="ntp-table">
    <thead>
    <tr><th>External port</th><th>Protocol</th><th>Forwards to</th><th>Description</th><th>Manage</th></tr>
    </thead>
    <tbody>
    <?php if (empty($portForwardRules)): ?>
      <tr><td colspan="5" style="color:#6b7280;">No port forward rules configured.</td></tr>
    <?php endif; ?>
    <?php foreach ($portForwardRules as $idx => $r): ?>
      <tr>
        <td><?= htmlspecialchars((string) ($r['port'] ?? '')) ?></td>
        <td><?= htmlspecialchars(strtoupper($r['protocol'] ?? '')) ?></td>
        <td><?= htmlspecialchars(($r['nat_redirect_ip'] ?? '') . ':' . (string) ($r['nat_redirect_port'] ?? '')) ?></td>
        <td><?= htmlspecialchars($r['description'] ?? '') ?></td>
        <td style="white-space:nowrap;">
          <form method="post" style="margin:0; display:inline-block;">
            <input type="hidden" name="form" value="nat_portforward_reorder">
            <input type="hidden" name="id" value="<?= htmlspecialchars($r['id']) ?>">
            <input type="hidden" name="direction" value="up">
            <button type="submit" title="Move up" <?= $idx === 0 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === 0 ? 'default' : 'pointer' ?>; color:<?= $idx === 0 ? '#d1d5db' : '#374151' ?>; padding:4px;">
              <i class="ti ti-arrow-up" style="font-size:16px;" aria-hidden="true"></i>
            </button>
          </form>
          <form method="post" style="margin:0; display:inline-block;">
            <input type="hidden" name="form" value="nat_portforward_reorder">
            <input type="hidden" name="id" value="<?= htmlspecialchars($r['id']) ?>">
            <input type="hidden" name="direction" value="down">
            <button type="submit" title="Move down" <?= $idx === count($portForwardRules) - 1 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === count($portForwardRules) - 1 ? 'default' : 'pointer' ?>; color:<?= $idx === count($portForwardRules) - 1 ? '#d1d5db' : '#374151' ?>; padding:4px;">
              <i class="ti ti-arrow-down" style="font-size:16px;" aria-hidden="true"></i>
            </button>
          </form>
          <a href="?tab=portforward&edit=<?= urlencode($r['id']) ?>" title="Edit" style="color:#374151; padding:4px; display:inline-block; text-decoration:none;">
            <i class="ti ti-pencil" style="font-size:16px;" aria-hidden="true"></i>
          </a>
          <form method="post" style="margin:0; display:inline-block;">
            <input type="hidden" name="form" value="nat_portforward_copy">
            <input type="hidden" name="interface" value="<?= htmlspecialchars($r['interface'] ?? $wan1If) ?>">
            <input type="hidden" name="protocol" value="<?= htmlspecialchars($r['protocol'] ?? 'tcp') ?>">
            <input type="hidden" name="external_port" value="<?= htmlspecialchars((string) ($r['port'] ?? '')) ?>">
            <input type="hidden" name="internal_ip" value="<?= htmlspecialchars($r['nat_redirect_ip'] ?? '') ?>">
            <input type="hidden" name="internal_port" value="<?= htmlspecialchars((string) ($r['nat_redirect_port'] ?? '')) ?>">
            <input type="hidden" name="description" value="<?= htmlspecialchars($r['description'] ?? '') ?>">
            <button type="submit" title="Copy" style="background:none; border:none; cursor:pointer; color:#374151; padding:4px;">
              <i class="ti ti-copy" style="font-size:16px;" aria-hidden="true"></i>
            </button>
          </form>
          <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete this port forward rule?');">
            <input type="hidden" name="form" value="nat_portforward_delete">
            <input type="hidden" name="id" value="<?= htmlspecialchars($r['id']) ?>">
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

  <?php if ($editingRule): ?>
    <div style="padding:8px 14px 0; font-size:12px; color:#14213d; font-weight:500;">
      Editing rule "<?= htmlspecialchars($editingRule['description'] ?: $editingRule['id']) ?>" —
      <a href="?tab=portforward" style="color:#6b7280;">cancel</a>
    </div>
  <?php endif; ?>
  <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:grid; grid-template-columns:repeat(5, 1fr); gap:10px; align-items:end;">
    <input type="hidden" name="form" value="nat_portforward_add">
    <?php if ($editingRule): ?>
      <input type="hidden" name="replace_id" value="<?= htmlspecialchars($editingRule['id']) ?>">
    <?php endif; ?>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">External port (WAN1)</label>
      <input type="number" name="external_port" min="1" max="65535" required style="width:100%;"
             value="<?= htmlspecialchars((string) ($editingRule['port'] ?? '')) ?>">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Protocol</label>
      <select name="protocol" style="width:100%;">
        <option value="tcp" <?= ($editingRule['protocol'] ?? 'tcp') === 'tcp' ? 'selected' : '' ?>>TCP</option>
        <option value="udp" <?= ($editingRule['protocol'] ?? '') === 'udp' ? 'selected' : '' ?>>UDP</option>
      </select>
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Internal IP</label>
      <input type="text" name="internal_ip" placeholder="10.252.1.50" required style="width:100%;"
             value="<?= htmlspecialchars($editingRule['nat_redirect_ip'] ?? '') ?>">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Internal port</label>
      <input type="number" name="internal_port" min="1" max="65535" required style="width:100%;"
             value="<?= htmlspecialchars((string) ($editingRule['nat_redirect_port'] ?? '')) ?>">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Description</label>
      <input type="text" name="description" style="width:100%;"
             value="<?= htmlspecialchars($editingRule['description'] ?? '') ?>">
    </div>
    <div style="grid-column: 1 / -1;">
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">
        <?= $editingRule ? 'Update port forward' : 'Add port forward' ?>
      </button>
    </div>
  </form>
</div>
<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
