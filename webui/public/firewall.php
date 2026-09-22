<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();

$configd = new NtpsenseConfigd();
$status = null;
$customRules = [];
$zones = null;
$configdError = null;
$actionMessage = null;
$actionError = null;
$duplicateWarning = null; // ['params' => array-untuk-resubmit] kalau DUPLICATE_RULE terdeteksi
$limiters = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'limiter_create') {
    try {
        $configd->call('firewall.limiter_create', [
            'name' => (string) ($_POST['name'] ?? ''),
            'download_mbps' => (float) ($_POST['download_mbps'] ?? 0),
            'upload_mbps' => (float) ($_POST['upload_mbps'] ?? 0),
        ]);
        $actionMessage = 'Bandwidth limiter created.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'limiter_update') {
    try {
        $configd->call('firewall.limiter_update', [
            'name' => (string) ($_POST['name'] ?? ''),
            'download_mbps' => (float) ($_POST['download_mbps'] ?? 0),
            'upload_mbps' => (float) ($_POST['upload_mbps'] ?? 0),
        ]);
        $actionMessage = 'Bandwidth limiter updated.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'limiter_delete') {
    try {
        $configd->call('firewall.limiter_delete', ['name' => (string) ($_POST['name'] ?? '')]);
        $actionMessage = 'Bandwidth limiter deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'zone_group_create') {
    try {
        $configd->call('firewall.zone_group_create', [
            'name' => (string) ($_POST['name'] ?? ''),
            'member_interfaces' => $_POST['member_interfaces'] ?? [],
        ]);
        $actionMessage = 'Zone Group created.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'zone_group_update') {
    try {
        $configd->call('firewall.zone_group_update', [
            'name' => (string) ($_POST['name'] ?? ''),
            'member_interfaces' => $_POST['member_interfaces'] ?? [],
        ]);
        $actionMessage = 'Zone Group membership updated.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'zone_group_delete') {
    try {
        $configd->call('firewall.zone_group_delete', ['name' => (string) ($_POST['name'] ?? '')]);
        $actionMessage = 'Zone Group deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'add_rule') {
    try {
        // Edit mode: 'Edit' is implemented as delete-old-then-add-new (we
        // have no separate 'update' action in ntpsense-configd, and don't
        // need one - this keeps the backend simple with only add/delete
        // as the two primitives). 'Copy' uses the exact same form but
        // WITHOUT editing_id set, so the original rule is left untouched
        // and this just becomes a fresh add.
        $editingId = (string) ($_POST['editing_id'] ?? '');
        if ($editingId !== '') {
            $configd->call('firewall.custom_rules.delete', ['id' => $editingId]);
        }
        $addRuleParams = [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'action' => (string) ($_POST['action_type'] ?? ''),
            'direction' => (string) ($_POST['direction'] ?? 'in'),
            'protocol' => (string) ($_POST['protocol'] ?? 'any'),
            'source' => (string) ($_POST['source'] ?? 'any'),
            'destination' => (string) ($_POST['destination'] ?? 'any'),
            'port' => isset($_POST['port']) && $_POST['port'] !== '' ? (int) $_POST['port'] : null,
            'description' => (string) ($_POST['description'] ?? ''),
            'limiter_name' => (string) ($_POST['limiter_name'] ?? ''),
            'gateway_group_name' => (string) ($_POST['gateway_group_name'] ?? ''),
            'zone_group' => (string) ($_POST['zone_group'] ?? ''),
            'app_control_group' => (string) ($_POST['app_control_group'] ?? ''),
        ];
        // Floating Rule (roadmap item) - berlaku di SEMUA zona sekaligus,
        // bukan diwariskan per-member seperti Zone Group. Dikirim
        // sebagai boolean terpisah, BUKAN lewat field 'interface'/
        // 'zone_group' - daemon yang menentukan bagaimana ini
        // di-generate ke pf.conf (satu baris global tanpa klausa 'on').
        if (($_POST['floating'] ?? '') === '1') {
            $addRuleParams['floating'] = true;
        }
        if (($_POST['confirm'] ?? '') === '1') {
            $addRuleParams['confirm'] = true;
        }
        $configd->call('firewall.custom_rules.add', $addRuleParams);
        $actionMessage = $editingId !== '' ? 'Rule updated successfully.' : 'Rule added successfully.';
    } catch (NtpsenseConfigdException $e) {
        if (str_contains($e->getMessage(), '[DUPLICATE_RULE]')) {
            // Server confirmed an identical rule already exists on this
            // interface - store the submitted values so the page can
            // pop a native confirm() dialog and, if accepted, resubmit
            // the exact same form with confirm=1 added (see the inline
            // <script> near the bottom of this page).
            $duplicateWarning = [
                'params' => $_POST,
            ];
        } else {
            $actionError = $e->getMessage();
        }
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'add_capwap_rule') {
    // "Simple+Fast+Secure" - permintaan bro langsung: admin cuma perlu
    // isi SATU field (IP/subnet tujuan WLC), bukan bikin 2 rule manual
    // satu-satu (port 5246 kontrol + 5247 data, protocol UDP, sesuai
    // dokumentasi resmi Cisco untuk CAPWAP). Cukup SATU rule per port,
    // arah 'in' pada interface sisi AP - 'keep state' pada rule pass
    // sudah otomatis mengizinkan balasan dari WLC tanpa perlu rule
    // terpisah di sisi WLC (perilaku stateful firewall standar).
    $iface = (string) ($_POST['interface'] ?? '');
    $wlcDestination = trim((string) ($_POST['wlc_destination'] ?? ''));
    if ($wlcDestination === '') {
        $actionError = 'WLC destination IP or subnet is required.';
    } else {
        try {
            $configd->call('firewall.custom_rules.add', [
                'interface' => $iface,
                'action' => 'pass',
                'direction' => 'in',
                'protocol' => 'udp',
                'source' => 'any',
                'destination' => $wlcDestination,
                'port' => 5246,
                'description' => 'CAPWAP control (AP join/discovery to WLC)',
            ]);
            $configd->call('firewall.custom_rules.add', [
                'interface' => $iface,
                'action' => 'pass',
                'direction' => 'in',
                'protocol' => 'udp',
                'source' => 'any',
                'destination' => $wlcDestination,
                'port' => 5247,
                'description' => 'CAPWAP data (AP client traffic to WLC)',
            ]);
            $actionMessage = 'CAPWAP rules added (UDP 5246 + 5247 to ' . htmlspecialchars($wlcDestination) . ').';
        } catch (NtpsenseConfigdException $e) {
            $actionError = $e->getMessage();
        }
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'delete_rule') {
    try {
        $configd->call('firewall.custom_rules.delete', ['id' => (string) ($_POST['id'] ?? '')]);
        $actionMessage = 'Rule deleted successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'reorder_rule') {
    try {
        $configd->call('firewall.custom_rules.reorder', [
            'id' => (string) ($_POST['id'] ?? ''),
            'direction' => (string) ($_POST['direction'] ?? ''),
        ]);
        $actionMessage = 'Rule order updated.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'toggle_rule_enabled') {
    try {
        $newEnabled = ($_POST['enabled'] ?? '') === '1';
        $configd->call('firewall.custom_rules.set_enabled', [
            'id' => (string) ($_POST['id'] ?? ''),
            'enabled' => $newEnabled,
        ]);
        $actionMessage = $newEnabled ? 'Rule enabled.' : 'Rule disabled - it stays visible but no longer applies.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

try {
    $status = $configd->call('firewall.status');
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
try {
    $zones = $configd->call('network.zones');
} catch (NtpsenseConfigdException $e) {
    // used to build tabs - if this fails, tabs cannot be displayed
}
try {
    $customRules = $configd->call('firewall.custom_rules.list')['rules'] ?? [];
} catch (NtpsenseConfigdException $e) {
    // leave empty
}
try {
    $limiters = $configd->call('firewall.limiter_list')['limiters'] ?? [];
} catch (NtpsenseConfigdException $e) {
    // leave empty
}
$zoneGroups = [];
$zoneGroupEligible = [];
try {
    $zoneGroups = $configd->call('firewall.zone_group_list')['groups'] ?? [];
    $zoneGroupEligible = $configd->call('firewall.zone_group_eligible_interfaces')['interfaces'] ?? [];
} catch (NtpsenseConfigdException $e) {
    // leave empty
}
$appControlGroupsList = [];
try {
    $appControlGroupsList = $configd->call('appcontrol.group_list')['groups'] ?? [];
} catch (NtpsenseConfigdException $e) {
    // leave empty - App Control tab itself will surface the real error if something's wrong
}
$gatewayGroups = [];
try {
    $gatewayGroups = $configd->call('multiwan.group_list')['groups'] ?? [];
} catch (NtpsenseConfigdException $e) {
    // leave empty - Multi-WAN not configured is a normal state, not an error worth surfacing here
}

// wg0 HANYA muncul sebagai tab kalau plugin WireGuard sungguhan
// terinstall - reuse action yang sama dipakai halaman VPN, supaya
// tidak ada dua sumber kebenaran soal status install.
$wireguardInstalled = false;
try {
    $wireguardInstalled = (bool) ($configd->call('vpn.get_config')['installed'] ?? false);
} catch (NtpsenseConfigdException $e) {
    // biarkan false - tab wg0 cuma tidak muncul, bukan error fatal
}

// enc0 HANYA muncul sebagai tab kalau strongSwan sungguhan terinstall -
// pola identik wg0 di atas, satu sumber kebenaran yang sama (reuse
// action ipsec.get_config, bukan cek terpisah).
$ipsecInstalled = false;
try {
    $ipsecInstalled = (bool) ($configd->call('ipsec.get_config')['installed'] ?? false);
} catch (NtpsenseConfigdException $e) {
    // biarkan false - tab enc0 cuma tidak muncul, bukan error fatal
}

// tailscale0 (Site Mesh VPN) HANYA muncul sebagai tab kalau Tailscale
// sungguhan terinstall - pola identik wg0/enc0 di atas, satu sumber
// kebenaran yang sama (reuse action mesh.get_status, bukan cek
// terpisah). Muncul di gateway MANA PUN yang aktif jadi node mesh
// (HQ maupun Branch) - interface ini genuinely ada di kedua role.
$tailscaleInstalled = false;
try {
    $tailscaleInstalled = (bool) ($configd->call('mesh.get_status')['installed'] ?? false);
} catch (NtpsenseConfigdException $e) {
    // biarkan false - tab tailscale0 cuma tidak muncul, bukan error fatal
}

// ------------------------------------------------------------
// Edit / Copy prefill - both reuse the SAME add-rule form, just with
// different hidden state: Edit sets 'editing_id' (so submit deletes
// the original first), Copy does not (submit just adds a new rule
// with the same values, original stays untouched). Detected via GET
// query param so the prefill survives a page reload naturally.
// ------------------------------------------------------------
$prefillRule = null;
$isEditing = false;
if (isset($_GET['edit']) || isset($_GET['copy'])) {
    $lookupId = (string) ($_GET['edit'] ?? $_GET['copy'] ?? '');
    foreach ($customRules as $r) {
        if ($r['id'] === $lookupId) {
            $prefillRule = $r;
            $isEditing = isset($_GET['edit']);
            break;
        }
    }
}

// ------------------------------------------------------------
// Tabs are built DYNAMICALLY from network.zones - the NUMBER of OPT
// tabs follows however many OPT NICs are actually detected on the
// system (not a fixed number).
// ------------------------------------------------------------
$tabs = [];
if ($zones) {
    if (!empty($zones['mgmt']['interface'])) {
        $tabs['mgmt'] = ['label' => $zones['mgmt']['alias'] ?? 'MGMT', 'interface' => $zones['mgmt']['interface'], 'locked' => true];
    }
    if (!empty($zones['lan1']['interface'])) {
        $tabs['lan1'] = ['label' => $zones['lan1']['alias'] ?? 'LAN1', 'interface' => $zones['lan1']['interface'], 'locked' => false];
    }
    if (!empty($zones['wan1']['interface'])) {
        $tabs['wan1'] = ['label' => $zones['wan1']['alias'] ?? 'WAN1', 'interface' => $zones['wan1']['interface'], 'locked' => false];
    }
    foreach (($zones['opt'] ?? []) as $i => $opt) {
        $zoneLabel = 'OPT' . ($i + 1);
        $optAlias = $opt['alias'] ?? '';
        $label = ($optAlias !== '' && $optAlias !== $zoneLabel) ? "{$zoneLabel} - {$optAlias}" : $zoneLabel;
        $tabs['opt' . ($i + 1)] = ['label' => $label, 'interface' => $opt['interface'], 'locked' => false];
    }
    foreach ($zoneGroups as $group) {
        $tabs['zg_' . $group['name']] = [
            'label' => $group['name'],
            'interface' => $group['name'],
            'locked' => false,
            'is_zone_group' => true,
        ];
    }
    if ($wireguardInstalled) {
        $tabs['wg0'] = ['label' => 'wg0 (VPN)', 'interface' => 'wg0', 'locked' => false];
    }
    if ($ipsecInstalled) {
        $tabs['enc0'] = ['label' => 'enc0 (IPsec)', 'interface' => 'enc0', 'locked' => false];
    }
    if ($tailscaleInstalled) {
        $tabs['tailscale0'] = ['label' => 'tailscale0 (Mesh)', 'interface' => 'tailscale0', 'locked' => false];
    }
}

$activeTabKey = $_GET['zone'] ?? array_key_first($tabs) ?? 'mgmt';
if (!in_array($activeTabKey, ['activerules', 'limiters', 'zonegroups', 'floating'], true) && !isset($tabs[$activeTabKey])) {
    $activeTabKey = array_key_first($tabs) ?? 'mgmt';
}
$activeTab = $tabs[$activeTabKey] ?? null;
$activeInterface = $activeTab['interface'] ?? null;

// Floating Rules (roadmap item - "kemenangan cepat" setelah OpenVPN
// selesai) - berlaku di SEMUA zona sekaligus lewat satu baris pf
// global (tanpa klausa 'on <interface>'), TERPISAH dari Zone Group
// (yang materialize per-member-interface). Difilter langsung dari
// $customRules yang sudah di-load di atas.
$floatingRules = array_values(array_filter($customRules, fn($r) => !empty($r['floating'])));

function fixedRulesBefore(string $zoneKey, string $iface, ?string $mgmtIface): array
{
    $implicitDeny = ['desc' => 'Implicit Deny (global baseline - blocks anything not explicitly allowed above)', 'rule' => 'block drop all'];
    $zoneSpecific = match ($zoneKey) {
        'mgmt' => [
            ['desc' => 'Anti-Lockout Rule (allow access to MGMT from anywhere)', 'rule' => "pass in quick on {$iface} to ({$iface}) keep state"],
        ],
        default => [],
    };
    return [$implicitDeny, ...$zoneSpecific];
}

function fixedRuleAfter(string $zoneKey, string $iface): ?array
{
    return match (true) {
        $zoneKey === 'mgmt' => ['desc' => 'Allow MGMT outbound', 'rule' => "pass out quick on {$iface} keep state"],
        $zoneKey === 'wan1' => ['desc' => 'Default allow WAN1 outbound', 'rule' => "pass out quick on {$iface} keep state"],
        default => null,
    };
}

function parsePfRuleLine(string $line): ?array
{
    $line = trim($line);
    if ($line === '' || !preg_match('/^(pass|block)\b/', $line)) {
        return null;
    }
    $tokens = preg_split('/\s+/', $line);
    $i = 0;
    $get = fn(int $idx) => $tokens[$idx] ?? null;

    $result = [
        'action' => $get($i) ?? '', 'direction' => '', 'interface' => '*',
        'protocol' => 'any', 'source' => 'any', 'destination' => 'any',
        'port' => null, 'quick' => false, 'raw' => $line,
    ];
    $i++;
    if ($get($i) === 'drop') {
        $i++;
    }
    if (in_array($get($i), ['in', 'out'], true)) {
        $result['direction'] = $get($i);
        $i++;
    }
    if ($get($i) === 'quick') {
        $result['quick'] = true;
        $i++;
    }
    if ($get($i) === 'on') {
        $i++;
        $result['interface'] = $get($i) ?? '*';
        $i++;
    }
    if ($get($i) === 'all') {
        $i++;
    } else {
        if (in_array($get($i), ['inet', 'inet6'], true)) {
            $i++;
        }
        if ($get($i) === 'proto') {
            $i++;
            $result['protocol'] = $get($i) ?? 'any';
            $i++;
        }
        if ($get($i) === 'from') {
            $i++;
            $result['source'] = $get($i) ?? 'any';
            $i++;
        }
        if ($get($i) === 'to') {
            $i++;
            $result['destination'] = $get($i) ?? 'any';
            $i++;
        }
        if ($get($i) === 'port') {
            $i++;
            if ($get($i) === '=') {
                $i++;
            }
            $result['port'] = $get($i);
            $i++;
        }
    }
    return $result;
}

$pageTitle = 'Firewall';
$activeNavItem = 'firewall';
$breadcrumbTail = ['Rules'];
if ($activeTabKey === 'activerules') {
    $breadcrumbTail[] = 'Active Rule';
} elseif ($activeTabKey === 'floating') {
    $breadcrumbTail[] = 'Floating';
} elseif ($activeTab) {
    $breadcrumbTail[] = $activeTab['label'];
}
require __DIR__ . '/../templates/layout_header.php';
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

    <?php if ($status): ?>
      <div class="ntp-status-line">
        <span style="color:#6b7280;">pf Status</span>
        <?php if ($status['enabled']): ?>
          <span class="ntp-badge ntp-badge-success">Enabled</span>
        <?php else: ?>
          <span class="ntp-badge ntp-badge-warning">Disabled</span>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <?php if (!empty($tabs)): ?>
      <div class="ntp-tabbar">
        <a href="?zone=activerules" class="ntp-tab<?= $activeTabKey === 'activerules' ? ' active' : '' ?>">
          Active Rule
        </a>
        <a href="?zone=limiters" class="ntp-tab<?= $activeTabKey === 'limiters' ? ' active' : '' ?>">
          Bandwidth Limiters
        </a>
        <a href="?zone=zonegroups" class="ntp-tab<?= $activeTabKey === 'zonegroups' ? ' active' : '' ?>">
          Zone Groups
        </a>
        <a href="?zone=floating" class="ntp-tab<?= $activeTabKey === 'floating' ? ' active' : '' ?>">
          <i class="ti ti-world" style="font-size:11px; vertical-align:1px;" aria-hidden="true"></i>
          Floating
        </a>
        <?php foreach ($tabs as $key => $tab): ?>
          <a href="?zone=<?= htmlspecialchars($key) ?>" class="ntp-tab<?= $key === $activeTabKey ? ' active' : '' ?>">
            <?= htmlspecialchars($tab['label']) ?>
            <?php if ($tab['locked']): ?><i class="ti ti-lock" style="font-size:11px; vertical-align:1px;" aria-hidden="true"></i><?php endif; ?>
            <?php if (!empty($tab['is_zone_group'])): ?><i class="ti ti-topology-star-3" style="font-size:11px; vertical-align:1px;" aria-hidden="true"></i><?php endif; ?>
          </a>
        <?php endforeach; ?>
      </div>

    <?php if ($activeTabKey === 'activerules'): ?>
      <p style="font-size:12px; color:#6b7280; margin-top:0;">
        pf evaluates rules top to bottom - by default the <strong>last matching rule wins</strong>. A rule marked <strong>Quick</strong> stops evaluation immediately when matched (first-match, for that rule only). This is why <code>block drop all</code> at the top does not actually block everything below it - every rule after it uses Quick and can override it.
      </p>
      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead>
        <tr>
          <th>Action</th>
          <th>Quick</th>
          <th>Direction</th>
          <th>Interface</th>
          <th>Protocol</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Port</th>
        </tr>
        </thead>
        <tbody>
        <?php
        $rawLines = explode("\n", (string) ($status['rules'] ?? ''));
        $parsedAny = false;
        foreach ($rawLines as $rawLine):
            $parsed = parsePfRuleLine($rawLine);
            if ($parsed === null) {
                continue;
            }
            $parsedAny = true;
        ?>
          <tr>
            <td>
              <?php if ($parsed['action'] === 'pass'): ?>
                <span class="ntp-badge ntp-badge-success">pass</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">block</span>
              <?php endif; ?>
            </td>
            <td>
              <?php if ($parsed['quick']): ?>
                <span class="ntp-badge ntp-badge-success">Yes</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-muted">No</span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($parsed['direction'] ?: '—') ?></td>
            <td><?= htmlspecialchars($parsed['interface']) ?></td>
            <td><?= htmlspecialchars($parsed['protocol']) ?></td>
            <td><?= htmlspecialchars($parsed['source']) ?></td>
            <td><?= htmlspecialchars($parsed['destination']) ?></td>
            <td><?= htmlspecialchars($parsed['port'] ?? '—') ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$parsedAny): ?>
          <tr><td colspan="8" style="color:#6b7280;">No filter rules currently active.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
      </div>

    <?php elseif ($activeTabKey === 'limiters'): ?>

      <p style="font-size:12px; color:#6b7280; margin-top:0;">
        Named bandwidth caps (download + upload, separate) that can be attached to any Firewall rule below via
        the "Bandwidth Limit" dropdown - one limiter can be reused across multiple rules. Uses FreeBSD's native
        <code>pf</code> + <code>dummynet</code> integration (<code>dnpipe</code>) with the <code>fq_codel</code>
        queue discipline (modern bufferbloat-resistant AQM) - not ALTQ, which doesn't work reliably on modern
        NIC drivers.
      </p>

      <?php if (empty($limiters)): ?>
        <p style="font-size:12px; color:#6b7280;">No bandwidth limiters defined yet.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Name</th><th>Download</th><th>Upload</th><th>Manage</th></tr>
          </thead>
          <tbody>
          <?php foreach ($limiters as $l): ?>
            <tr>
              <td><?= htmlspecialchars($l['name']) ?></td>
              <td><?= htmlspecialchars((string) $l['download_mbps']) ?> Mbps</td>
              <td><?= htmlspecialchars((string) $l['upload_mbps']) ?> Mbps</td>
              <td>
                <details style="display:inline-block;">
                  <summary style="cursor:pointer; display:inline-block; color:#374151; font-size:12px;">Edit</summary>
                  <form method="post" style="margin:8px 0 0; display:flex; gap:8px; align-items:end;">
                    <input type="hidden" name="form" value="limiter_update">
                    <input type="hidden" name="name" value="<?= htmlspecialchars($l['name']) ?>">
                    <div>
                      <label style="display:block; font-size:11px; color:#374151;">Download (Mbps)</label>
                      <input type="number" name="download_mbps" value="<?= htmlspecialchars((string) $l['download_mbps']) ?>" step="0.1" min="0.1" required style="width:110px; font-size:12px;">
                    </div>
                    <div>
                      <label style="display:block; font-size:11px; color:#374151;">Upload (Mbps)</label>
                      <input type="number" name="upload_mbps" value="<?= htmlspecialchars((string) $l['upload_mbps']) ?>" step="0.1" min="0.1" required style="width:110px; font-size:12px;">
                    </div>
                    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 12px; font-size:12px; border-radius:6px;">Save</button>
                  </form>
                </details>
                <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete limiter &quot;<?= htmlspecialchars($l['name']) ?>&quot;? Rules using it must be updated first.');">
                  <input type="hidden" name="form" value="limiter_delete">
                  <input type="hidden" name="name" value="<?= htmlspecialchars($l['name']) ?>">
                  <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px; margin-left:6px;">
                    <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
                  </button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>

      <div style="margin-top:16px; padding-top:14px; border-top:1px solid #e5e7eb;">
        <p style="font-size:13px; font-weight:500; margin:0 0 10px;">Add limiter</p>
        <form method="post" style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
          <input type="hidden" name="form" value="limiter_create">
          <div>
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
            <input type="text" name="name" placeholder="Guest-WiFi-Limit" required style="width:200px;">
          </div>
          <div>
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Download (Mbps)</label>
            <input type="number" name="download_mbps" step="0.1" min="0.1" placeholder="10" required style="width:110px;">
          </div>
          <div>
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Upload (Mbps)</label>
            <input type="number" name="upload_mbps" step="0.1" min="0.1" placeholder="2" required style="width:110px;">
          </div>
          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add limiter</button>
        </form>
      </div>

    <?php elseif ($activeTabKey === 'zonegroups'): ?>

      <p style="font-size:12px; color:#6b7280; margin-top:0;">
        Combine LAN1/OPT zones (WAN excluded - matches pfSense's own best practice against mixing WANs into
        interface groups) so the same Firewall rules apply to all of them at once. Rules added on a group's own
        tab are checked <strong>before</strong> that zone's individual rules and cannot be overridden there -
        each zone still keeps its own tab and its own rules underneath.
      </p>

      <?php
      $ifaceLabels = [];
      if (!empty($zones['lan1']['interface'])) {
          $ifaceLabels[$zones['lan1']['interface']] = $zones['lan1']['alias'] ?? 'LAN1';
      }
      foreach (($zones['opt'] ?? []) as $i => $opt) {
          if (!empty($opt['interface'])) {
              $ifaceLabels[$opt['interface']] = ($opt['alias'] ?? '') !== '' ? $opt['alias'] : 'OPT' . ($i + 1);
          }
      }
      ?>

      <?php if (empty($zoneGroups)): ?>
        <p style="font-size:12px; color:#6b7280;">No Zone Groups defined yet.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Name</th><th>Members</th><th>Manage</th></tr>
          </thead>
          <tbody>
          <?php foreach ($zoneGroups as $g): ?>
            <tr>
              <td><?= htmlspecialchars($g['name']) ?></td>
              <td>
                <?= htmlspecialchars(implode(', ', array_map(fn($i) => $ifaceLabels[$i] ?? $i, $g['member_interfaces']))) ?>
              </td>
              <td>
                <details style="display:inline-block;">
                  <summary style="cursor:pointer; display:inline-block; color:#374151; font-size:12px;">Edit members</summary>
                  <form method="post" style="margin:8px 0 0;">
                    <input type="hidden" name="form" value="zone_group_update">
                    <input type="hidden" name="name" value="<?= htmlspecialchars($g['name']) ?>">
                    <?php foreach ($zoneGroupEligible as $iface): ?>
                      <label style="display:inline-flex; align-items:center; gap:4px; margin-right:12px; font-size:12px;">
                        <input type="checkbox" name="member_interfaces[]" value="<?= htmlspecialchars($iface) ?>" <?= in_array($iface, $g['member_interfaces'], true) ? 'checked' : '' ?>>
                        <?= htmlspecialchars($ifaceLabels[$iface] ?? $iface) ?>
                      </label>
                    <?php endforeach; ?>
                    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 12px; font-size:12px; border-radius:6px; margin-top:8px;">Save</button>
                  </form>
                </details>
                <a href="?zone=zg_<?= urlencode($g['name']) ?>" style="font-size:12px; color:#374151; margin-left:8px;">View rules</a>
                <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete Zone Group &quot;<?= htmlspecialchars($g['name']) ?>&quot;? Rules on its tab must be removed first.');">
                  <input type="hidden" name="form" value="zone_group_delete">
                  <input type="hidden" name="name" value="<?= htmlspecialchars($g['name']) ?>">
                  <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px; margin-left:6px;">
                    <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
                  </button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>

      <div style="margin-top:16px; padding-top:14px; border-top:1px solid #e5e7eb;">
        <p style="font-size:13px; font-weight:500; margin:0 0 10px;">Create Zone Group</p>
        <?php if (empty($zoneGroupEligible)): ?>
          <p style="font-size:12px; color:#6b7280;">No eligible LAN1/OPT (non-WAN) interfaces available to group yet.</p>
        <?php else: ?>
          <form method="post" style="display:flex; gap:16px; align-items:flex-end; flex-wrap:wrap;">
            <input type="hidden" name="form" value="zone_group_create">
            <div>
              <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
              <input type="text" name="name" placeholder="Trusted_LAN" required style="width:180px;">
            </div>
            <div>
              <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Members</label>
              <div>
                <?php foreach ($zoneGroupEligible as $iface): ?>
                  <label style="display:inline-flex; align-items:center; gap:4px; margin-right:12px; font-size:12px;">
                    <input type="checkbox" name="member_interfaces[]" value="<?= htmlspecialchars($iface) ?>">
                    <?= htmlspecialchars($ifaceLabels[$iface] ?? $iface) ?>
                  </label>
                <?php endforeach; ?>
              </div>
            </div>
            <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create group</button>
          </form>
        <?php endif; ?>
      </div>

    <?php elseif ($activeTabKey === 'floating'): ?>

      <p style="font-size:12px; color:#6b7280; margin-top:0;">
        Applies to <strong>every zone at once</strong> (WAN included) - a single global pf rule with no
        interface restriction at all, rather than being duplicated per zone like a Zone Group. Useful for
        things like blocking one IP everywhere without adding the same rule to every tab.
      </p>

      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead>
        <tr>
          <th>Action</th>
          <th>Direction</th>
          <th>Protocol</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Port</th>
          <th>Description</th>
          <th>Manage Rules</th>
        </tr>
        </thead>
        <tbody>
        <?php if (empty($floatingRules)): ?>
          <tr><td colspan="8" style="color:#6b7280;">No Floating Rules defined yet.</td></tr>
        <?php endif; ?>
        <?php foreach ($floatingRules as $idx => $rule): ?>
          <?php $ruleIsEnabled = ($rule['enabled'] ?? true); ?>
          <tr<?= $ruleIsEnabled ? '' : ' style="opacity:0.5;"' ?>>
            <td>
              <?php if ($rule['action'] === 'pass'): ?>
                <span class="ntp-badge ntp-badge-success">pass</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">block</span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($rule['direction'] ?? 'in') ?></td>
            <td><?= htmlspecialchars($rule['protocol']) ?></td>
            <td><?= htmlspecialchars($rule['source'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($rule['destination']) ?></td>
            <td><?= htmlspecialchars((string) ($rule['port'] ?? '—')) ?></td>
            <td><?= htmlspecialchars($rule['description'] ?? '') ?></td>
            <td>
              <form method="post" style="margin:0; display:inline-block;">
                <input type="hidden" name="form" value="reorder_rule">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <input type="hidden" name="direction" value="up">
                <button type="submit" title="Move up" <?= $idx === 0 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === 0 ? 'default' : 'pointer' ?>; color:<?= $idx === 0 ? '#d1d5db' : '#374151' ?>; padding:4px;">
                  <i class="ti ti-arrow-up" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <form method="post" style="margin:0; display:inline-block;">
                <input type="hidden" name="form" value="reorder_rule">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <input type="hidden" name="direction" value="down">
                <button type="submit" title="Move down" <?= $idx === count($floatingRules) - 1 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === count($floatingRules) - 1 ? 'default' : 'pointer' ?>; color:<?= $idx === count($floatingRules) - 1 ? '#d1d5db' : '#374151' ?>; padding:4px;">
                  <i class="ti ti-arrow-down" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <form method="post" style="margin:0; display:inline-block;">
                <input type="hidden" name="form" value="toggle_rule_enabled">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <input type="hidden" name="enabled" value="<?= $ruleIsEnabled ? '0' : '1' ?>">
                <button type="submit" title="<?= $ruleIsEnabled ? 'Disable rule (keeps it visible, stops applying it)' : 'Enable rule' ?>" style="background:none; border:none; cursor:pointer; color:<?= $ruleIsEnabled ? '#374151' : '#1a7f4b' ?>; padding:4px;">
                  <i class="ti ti-<?= $ruleIsEnabled ? 'eye' : 'eye-off' ?>" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <a href="?zone=floating&edit=<?= htmlspecialchars($rule['id']) ?>" title="Edit rule" style="color:#374151; padding:4px; display:inline-block;">
                <i class="ti ti-edit" style="font-size:16px;" aria-hidden="true"></i>
              </a>
              <a href="?zone=floating&copy=<?= htmlspecialchars($rule['id']) ?>" title="Copy rule" style="color:#374151; padding:4px; display:inline-block;">
                <i class="ti ti-copy" style="font-size:16px;" aria-hidden="true"></i>
              </a>
              <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete this Floating Rule?\n\n<?= htmlspecialchars(addslashes($rule['action'] . ' ' . ($rule['direction'] ?? 'in') . ' ' . $rule['protocol'] . ' from ' . ($rule['source'] ?? 'any') . ' to ' . $rule['destination'])) ?>\n\nThis cannot be undone.');">
                <input type="hidden" name="form" value="delete_rule">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <button type="submit" title="Delete rule" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                  <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>

    <?php elseif ($activeTab): ?>
      <?php if ($activeTab['locked']): ?>
          <p style="font-size:12px; color:#6b7280; margin-top:0;">
            The MGMT zone is permanently locked - the anti-lockout rule cannot be edited or deleted from the Web UI (see RCA #28). This is not a temporary limitation, but a deliberate security design decision.
          </p>
      <?php else: ?>
        <p style="font-size:12px; color:#6b7280; margin-top:0;">
          <?php if (!empty($activeTab['is_zone_group'])): ?>
            Zone Group <strong><?= htmlspecialchars($activeInterface ?? '') ?></strong> - rules here apply to every member zone and are checked before that zone's own individual rules.
          <?php else: ?>
            Interface <strong><?= htmlspecialchars($activeInterface ?? '') ?></strong>. Rules marked <i class="ti ti-lock" aria-hidden="true"></i> are system rules (fixed, cannot be deleted) - custom rules can be freely added/removed below them.
          <?php endif; ?>
        </p>
      <?php endif; ?>

      <?php
      $inheritedGroupNames = [];
      if (empty($activeTab['is_zone_group']) && !empty($activeInterface)) {
          foreach ($zoneGroups as $g) {
              if (in_array($activeInterface, $g['member_interfaces'] ?? [], true)) {
                  $inheritedGroupNames[] = $g['name'];
              }
          }
      }
      $inheritedGroupRules = !empty($inheritedGroupNames)
          ? array_values(array_filter($customRules, fn($r) => in_array($r['zone_group'] ?? null, $inheritedGroupNames, true)))
          : [];
      ?>
      <?php if (!empty($inheritedGroupNames)): ?>
        <div style="background:#fff8e6; border:1px solid #f5d78e; border-radius:8px; padding:10px 12px; margin-bottom:12px; font-size:12px; color:#9a5b00;">
          ⚠️ This zone is also a member of Zone Group
          <?php foreach ($inheritedGroupNames as $i => $gn): ?>
            <a href="?zone=zg_<?= urlencode($gn) ?>" style="color:#9a5b00; text-decoration:underline; font-weight:600;"><?= htmlspecialchars($gn) ?></a><?= $i < count($inheritedGroupNames) - 1 ? ', ' : '' ?>
          <?php endforeach; ?>
          - <?= count($inheritedGroupRules) ?> rule(s) from that group apply here too and are checked
          <strong>before</strong> the rules below (shown for reference, manage them on the group's own tab):
        </div>
        <div class="ntp-table-scroll" style="margin-bottom:14px;">
        <table class="ntp-table">
          <tbody>
          <?php foreach ($inheritedGroupRules as $gr): ?>
            <tr style="background:#fffbf0;">
              <td style="width:80px;">
                <?= ($gr['action'] ?? '') === 'pass' ? '<span class="ntp-badge ntp-badge-success">pass</span>' : '<span class="ntp-badge ntp-badge-warning">block</span>' ?>
              </td>
              <td style="width:60px; font-size:12px;"><?= htmlspecialchars($gr['direction'] ?? 'in') ?></td>
              <td style="width:60px; font-size:12px;"><?= htmlspecialchars($gr['protocol'] ?? 'any') ?></td>
              <td style="font-size:12px;"><?= htmlspecialchars($gr['source'] ?? 'any') ?> → <?= htmlspecialchars($gr['destination'] ?? 'any') ?></td>
              <td style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($gr['description'] ?? '') ?></td>
              <td style="font-size:11px; color:#9a5b00; text-align:right;">from <?= htmlspecialchars($gr['zone_group'] ?? '') ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>

      <?php if (!empty($floatingRules)): ?>
        <div style="background:#eef4ff; border:1px solid #c7dbfb; border-radius:8px; padding:10px 12px; margin-bottom:12px; font-size:12px; color:#1e3a6e;">
          🌐 <?= count(array_filter($floatingRules, fn($r) => $r['enabled'] ?? true)) ?> active
          <a href="?zone=floating" style="color:#1e3a6e; text-decoration:underline; font-weight:600;">Floating Rule(s)</a>
          also apply here (and to every other zone) - manage them on the Floating tab.
        </div>
      <?php endif; ?>

      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead>
        <tr>
          <th>Action</th>
          <th>Direction</th>
          <th>Protocol</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Port</th>
          <th>Description</th>
          <th>Limit</th>
          <th>Route</th>
          <th>Applications</th>
          <th>Manage Rules</th>
        </tr>
        </thead>
        <tbody>
        <?php
        $mgmtIface = $tabs['mgmt']['interface'] ?? null;
        $before = fixedRulesBefore($activeTabKey, (string) $activeInterface, $mgmtIface);
        foreach ($before as $fr):
            $p = parsePfRuleLine($fr['rule']);
        ?>
          <tr style="background:#fafafa;">
            <td>
              <i class="ti ti-lock" style="font-size:12px; margin-right:4px; color:#9ca3af;" aria-hidden="true"></i>
              <?php if (($p['action'] ?? '') === 'pass'): ?>
                <span class="ntp-badge ntp-badge-success">pass</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">block</span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($p['direction'] ?? 'in') ?></td>
            <td><?= htmlspecialchars($p['protocol'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($p['source'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($p['destination'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($p['port'] ?? '—') ?></td>
            <td style="color:#6b7280; font-size:12px;"><?= htmlspecialchars($fr['desc']) ?></td>
            <td></td>
            <td></td>
          </tr>
        <?php endforeach; ?>

        <?php
        $rulesForTab = array_values(array_filter($customRules, fn($r) => $r['interface'] === $activeInterface && empty($r['floating'])));
        if (empty($rulesForTab) && empty($before) && !$activeTab['locked']):
        ?>
          <tr><td colspan="11" style="color:#6b7280;">No rules defined for this interface.</td></tr>
        <?php endif; ?>
        <?php foreach ($rulesForTab as $idx => $rule): ?>
          <?php $ruleIsEnabled = ($rule['enabled'] ?? true); ?>
          <tr<?= $ruleIsEnabled ? '' : ' style="opacity:0.5;"' ?>>
            <td>
              <?php if ($rule['action'] === 'pass'): ?>
                <span class="ntp-badge ntp-badge-success">pass</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">block</span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($rule['direction'] ?? 'in') ?></td>
            <td><?= htmlspecialchars($rule['protocol']) ?></td>
            <td><?= htmlspecialchars($rule['source'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($rule['destination']) ?></td>
            <td><?= htmlspecialchars((string) ($rule['port'] ?? '—')) ?></td>
            <td><?= htmlspecialchars($rule['description'] ?? '') ?></td>
            <td>
              <?php if (!empty($rule['limiter_name'])): ?>
                <span class="ntp-badge ntp-badge-muted"><i class="ti ti-gauge" style="font-size:11px; vertical-align:-1px;" aria-hidden="true"></i> <?= htmlspecialchars($rule['limiter_name']) ?></span>
              <?php else: ?>
                <span style="color:#9ca3af;">—</span>
              <?php endif; ?>
            </td>
            <td>
              <?php if (!empty($rule['gateway_group_name'])): ?>
                <span class="ntp-badge ntp-badge-muted"><i class="ti ti-route" style="font-size:11px; vertical-align:-1px;" aria-hidden="true"></i> <?= htmlspecialchars($rule['gateway_group_name']) ?></span>
              <?php else: ?>
                <span style="color:#9ca3af;">—</span>
              <?php endif; ?>
            </td>
            <td>
              <?php if (!empty($rule['app_control_group'])): ?>
                <a href="/security.php?tab=app_control" class="ntp-badge ntp-badge-muted" style="text-decoration:none;" title="Managed on Security &gt; Application Control">
                  <i class="ti ti-apps" style="font-size:11px; vertical-align:-1px;" aria-hidden="true"></i> <?= htmlspecialchars($rule['app_control_group']) ?>
                </a>
              <?php else: ?>
                <span style="color:#9ca3af;">—</span>
              <?php endif; ?>
            </td>
            <td>
              <form method="post" style="margin:0; display:inline-block;">
                <input type="hidden" name="form" value="reorder_rule">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <input type="hidden" name="direction" value="up">
                <button type="submit" title="Move up" <?= $idx === 0 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === 0 ? 'default' : 'pointer' ?>; color:<?= $idx === 0 ? '#d1d5db' : '#374151' ?>; padding:4px;">
                  <i class="ti ti-arrow-up" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <form method="post" style="margin:0; display:inline-block;">
                <input type="hidden" name="form" value="reorder_rule">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <input type="hidden" name="direction" value="down">
                <button type="submit" title="Move down" <?= $idx === count($rulesForTab) - 1 ? 'disabled' : '' ?> style="background:none; border:none; cursor:<?= $idx === count($rulesForTab) - 1 ? 'default' : 'pointer' ?>; color:<?= $idx === count($rulesForTab) - 1 ? '#d1d5db' : '#374151' ?>; padding:4px;">
                  <i class="ti ti-arrow-down" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <form method="post" style="margin:0; display:inline-block;">
                <input type="hidden" name="form" value="toggle_rule_enabled">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <input type="hidden" name="enabled" value="<?= $ruleIsEnabled ? '0' : '1' ?>">
                <button type="submit" title="<?= $ruleIsEnabled ? 'Disable rule (keeps it visible, stops applying it)' : 'Enable rule' ?>" style="background:none; border:none; cursor:pointer; color:<?= $ruleIsEnabled ? '#374151' : '#1a7f4b' ?>; padding:4px;">
                  <i class="ti ti-<?= $ruleIsEnabled ? 'eye' : 'eye-off' ?>" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
              <a href="?zone=<?= htmlspecialchars($activeTabKey) ?>&edit=<?= htmlspecialchars($rule['id']) ?>" title="Edit rule" style="color:#374151; padding:4px; display:inline-block;">
                <i class="ti ti-edit" style="font-size:16px;" aria-hidden="true"></i>
              </a>
              <a href="?zone=<?= htmlspecialchars($activeTabKey) ?>&copy=<?= htmlspecialchars($rule['id']) ?>" title="Copy rule" style="color:#374151; padding:4px; display:inline-block;">
                <i class="ti ti-copy" style="font-size:16px;" aria-hidden="true"></i>
              </a>
              <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete this rule?\n\n<?= htmlspecialchars(addslashes($rule['action'] . ' ' . ($rule['direction'] ?? 'in') . ' ' . $rule['protocol'] . ' from ' . ($rule['source'] ?? 'any') . ' to ' . $rule['destination'])) ?>\n\nThis cannot be undone.');">
                <input type="hidden" name="form" value="delete_rule">
                <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                <button type="submit" title="Delete rule" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                  <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
                </button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>

        <?php $after = fixedRuleAfter($activeTabKey, (string) $activeInterface); ?>
        <?php if ($after): $p = parsePfRuleLine($after['rule']); ?>
          <tr style="background:#fafafa;">
            <td>
              <i class="ti ti-lock" style="font-size:12px; margin-right:4px; color:#9ca3af;" aria-hidden="true"></i>
              <?php if (($p['action'] ?? '') === 'pass'): ?>
                <span class="ntp-badge ntp-badge-success">pass</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">block</span>
              <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($p['direction'] ?? 'in') ?></td>
            <td><?= htmlspecialchars($p['protocol'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($p['source'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($p['destination'] ?? 'any') ?></td>
            <td><?= htmlspecialchars($p['port'] ?? '—') ?></td>
            <td style="color:#6b7280; font-size:12px;"><?= htmlspecialchars($after['desc']) ?></td>
            <td></td>
          </tr>
        <?php endif; ?>
        </tbody>
      </table>
      </div>
    <?php endif; ?>

  <?php endif; ?>

  <?php
  $showAddRuleForm = ($activeTabKey === 'floating') || (!empty($tabs) && $activeTabKey !== 'activerules' && $activeTab && !$activeTab['locked']);
  ?>
  <?php if ($showAddRuleForm): ?>

    <?php if ($activeTabKey !== 'floating' && empty($activeTab['is_zone_group'])): ?>
    <div style="margin-top:16px; padding:14px; background:#f0f6ff; border:1px solid #cfe0fb; border-radius:8px;">
      <p style="font-size:13px; font-weight:500; color:#1b1f24; margin:0 0 4px;">
        <i class="ti ti-wifi" style="font-size:14px; vertical-align:-2px;" aria-hidden="true"></i>
        Quick Add: CAPWAP (Cisco WLC)
      </p>
      <p style="font-size:12px; color:#6b7280; margin:0 0 10px;">
        For lightweight APs on this zone to reach a Wireless LAN Controller on a different zone/subnet. Adds two
        rules in one step (UDP 5246 control + UDP 5247 data), direction "in" on this interface - the WLC's reply
        is handled automatically by the firewall's connection state, no separate rule needed on the WLC's own zone.
      </p>
      <form method="post" style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
        <input type="hidden" name="form" value="add_capwap_rule">
        <input type="hidden" name="interface" value="<?= htmlspecialchars((string) $activeInterface) ?>">
        <div style="flex:1; min-width:220px;">
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">WLC IP or subnet</label>
          <input type="text" name="wlc_destination" placeholder="192.168.200.20 or 192.168.200.0/24" required style="width:100%;">
        </div>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add CAPWAP rules</button>
      </form>
    </div>
    <?php endif; ?>

    <?php
    $pfAction = $prefillRule['action'] ?? 'pass';
    $pfProtocol = $prefillRule['protocol'] ?? 'any';
    $pfSource = $prefillRule['source'] ?? 'any';
    $pfDestination = $prefillRule['destination'] ?? 'any';
    $pfPort = $prefillRule['port'] ?? null;
    $pfDirection = $prefillRule['direction'] ?? 'in';
    $pfDescription = $prefillRule['description'] ?? '';
    $portEnabled = in_array($pfProtocol, ['tcp', 'udp'], true);
    ?>
    <div style="margin-top:16px; padding-top:14px; border-top:1px solid #e5e7eb;">
      <?php if ($prefillRule): ?>
        <div style="padding:8px 0; font-size:12px; color:#1e40af;">
          <?= $isEditing ? 'Editing rule' : 'Copying rule' ?> - adjust the fields below then submit.
        </div>
      <?php endif; ?>
      <form method="post" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:10px; align-items:end;">
        <input type="hidden" name="form" value="add_rule">
        <?php if ($activeTabKey === 'floating'): ?>
          <input type="hidden" name="floating" value="1">
        <?php elseif (!empty($activeTab['is_zone_group'])): ?>
          <input type="hidden" name="zone_group" value="<?= htmlspecialchars((string) $activeInterface) ?>">
        <?php else: ?>
          <input type="hidden" name="interface" value="<?= htmlspecialchars((string) $activeInterface) ?>">
        <?php endif; ?>
        <?php if ($isEditing && $prefillRule): ?>
          <input type="hidden" name="editing_id" value="<?= htmlspecialchars($prefillRule['id']) ?>">
        <?php endif; ?>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Action</label>
          <select name="action_type" required style="width:100%;">
            <option value="pass" <?= $pfAction === 'pass' ? 'selected' : '' ?>>pass</option>
            <option value="block" <?= $pfAction === 'block' ? 'selected' : '' ?>>block</option>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Direction</label>
          <select name="direction" required style="width:100%;">
            <option value="in" <?= $pfDirection === 'in' ? 'selected' : '' ?>>in</option>
            <option value="out" <?= $pfDirection === 'out' ? 'selected' : '' ?>>out</option>
            <option value="both" <?= $pfDirection === 'both' ? 'selected' : '' ?>>both</option>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Protocol</label>
          <select name="protocol" id="protocol-select" style="width:100%;" onchange="document.getElementById('port-input').disabled = (this.value !== 'tcp' && this.value !== 'udp'); if (document.getElementById('port-input').disabled) { document.getElementById('port-input').value = ''; }">
            <option value="any" <?= $pfProtocol === 'any' ? 'selected' : '' ?>>any</option>
            <option value="tcp" <?= $pfProtocol === 'tcp' ? 'selected' : '' ?>>tcp</option>
            <option value="udp" <?= $pfProtocol === 'udp' ? 'selected' : '' ?>>udp</option>
            <option value="icmp" <?= $pfProtocol === 'icmp' ? 'selected' : '' ?>>icmp</option>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Source</label>
          <input type="text" name="source" value="<?= htmlspecialchars($pfSource) ?>" style="width:100%;">
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Destination</label>
          <input type="text" name="destination" value="<?= htmlspecialchars($pfDestination) ?>" style="width:100%;">
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Port</label>
          <input type="number" name="port" id="port-input" min="1" max="65535" value="<?= htmlspecialchars((string) ($pfPort ?? '')) ?>" <?= $portEnabled ? '' : 'disabled' ?> style="width:100%;" title="Port can only be set when protocol is tcp/udp">
        </div>
        <?php if ($activeTabKey !== 'floating'): ?>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Bandwidth Limit</label>
          <select name="limiter_name" style="width:100%;">
            <option value="">None</option>
            <?php foreach ($limiters as $l): ?>
              <option value="<?= htmlspecialchars($l['name']) ?>" <?= ($prefillRule['limiter_name'] ?? '') === $l['name'] ? 'selected' : '' ?>>
                <?= htmlspecialchars($l['name']) ?> (<?= htmlspecialchars((string) $l['download_mbps']) ?>/<?= htmlspecialchars((string) $l['upload_mbps']) ?> Mbps)
              </option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Gateway Group <span style="color:#9ca3af; font-weight:normal;">(Multi-WAN)</span></label>
          <select name="gateway_group_name" style="width:100%;">
            <option value="">None (default routing)</option>
            <?php foreach ($gatewayGroups as $gg): ?>
              <option value="<?= htmlspecialchars($gg['name']) ?>" <?= ($prefillRule['gateway_group_name'] ?? '') === $gg['name'] ? 'selected' : '' ?>>
                <?= htmlspecialchars($gg['name']) ?>
              </option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">
            Application Control Group <span style="color:#9ca3af; font-weight:normal;">(optional)</span>
            <span title="Attaches an existing App Control Group (defined on Security > Application Control) to this rule for reference - enforcement stays global on WAN1/WAN2, not scoped to just this zone." style="display:inline-flex; align-items:center; justify-content:center; width:14px; height:14px; border-radius:50%; background:#e5e7eb; color:#6b7280; font-size:10px; cursor:help; vertical-align:1px;">?</span>
          </label>
          <select name="app_control_group" style="width:100%;">
            <option value="">None</option>
            <?php foreach ($appControlGroupsList as $acg): ?>
              <option value="<?= htmlspecialchars($acg['name']) ?>" <?= ($prefillRule['app_control_group'] ?? '') === $acg['name'] ? 'selected' : '' ?>>
                <?= htmlspecialchars($acg['name']) ?> (<?= htmlspecialchars($acg['action'] ?? 'block') ?>)
              </option>
            <?php endforeach; ?>
          </select>
        </div>
        <?php endif; ?>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Description</label>
          <input type="text" name="description" value="<?= htmlspecialchars($pfDescription) ?>" style="width:100%;">
        </div>
        <div style="grid-column:1 / -1;">
          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">
            <?= $isEditing ? 'Save changes' : 'Add rule to ' . htmlspecialchars($activeTabKey === 'floating' ? 'Floating' : ($activeTab['label'] ?? '')) ?>
          </button>
          <?php if ($prefillRule): ?>
            <a href="?zone=<?= htmlspecialchars($activeTabKey) ?>" style="margin-left:10px; font-size:13px; color:#6b7280;">Cancel</a>
          <?php endif; ?>
        </div>
      </form>
    </div>
  <?php endif; ?>

<?php if ($duplicateWarning): ?>
<form method="post" id="duplicateResubmitForm" style="display:none;">
  <?php foreach ($duplicateWarning['params'] as $key => $value): ?>
    <input type="hidden" name="<?= htmlspecialchars($key) ?>" value="<?= htmlspecialchars((string) $value) ?>">
  <?php endforeach; ?>
  <input type="hidden" name="confirm" value="1">
</form>
<script>
  window.addEventListener('load', function () {
    var proceed = window.confirm(
      "An identical rule (same action, direction, protocol, source, destination, and port) " +
      "already exists on this interface.\n\nAdd it anyway?"
    );
    if (proceed) {
      document.getElementById('duplicateResubmitForm').submit();
    }
  });
</script>
<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
