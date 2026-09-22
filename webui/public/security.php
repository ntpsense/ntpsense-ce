<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();
Auth::requireCategory('security');

$configd = new NtpsenseConfigd();
$configdError = null;
$saveMessage = null;
$saveError = null;
$installed = false;
$running = false;
$securityConfig = null;
$updateDiagnostic = null;

// Robust boolean reader for values that round-tripped through JSON/NDJSON.
// Diagnostic fix: the Abuse.ch source checkboxes were confirmed correctly
// PERSISTED (verified via the daemon's own list-enabled-sources output
// after "Update rules now"), yet still rendered unchecked right after
// save/reload - i.e. the underlying value was right but a plain truthy
// check on it wasn't. A raw `?? default` check assumes the decoded value
// is already a native PHP bool; if the client ever hands back "1"/"0",
// 1/0, or "true"/"false" as strings instead (a real possibility across an
// NDJSON round-trip depending on how the response gets decoded upstream),
// a naive truthy check can silently disagree with the real value. This
// makes every checkbox in this page immune to that class of mismatch
// regardless of which representation actually comes back.
function rsBool($val, bool $default): bool
{
    if ($val === null) {
        return $default;
    }
    if (is_bool($val)) {
        return $val;
    }
    if (is_int($val) || is_float($val)) {
        return $val != 0;
    }
    if (is_string($val)) {
        return in_array(strtolower(trim($val)), ['1', 'true', 'yes', 'on'], true);
    }
    return $default;
}

try {
    $status = $configd->call('security.get_status');
    $installed = (bool) ($status['installed'] ?? false);
    $running = (bool) ($status['running'] ?? false);
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}

if ($installed) {
    try {
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

$activeTab = $_GET['tab'] ?? 'general';
if (!in_array($activeTab, ['general', 'sources', 'policy', 'custom_rules', 'alerts', 'status'], true)) {
    $activeTab = 'general';
}

// Zones come from the same Network-page interface-roles source of truth
// used by Firewall/DHCP: action "network.zones", nested {mgmt,lan1,wan1,opt:[...]}
// - flattened here so the General tab can loop over it uniformly.
$allZones = [];
if ($installed) {
    try {
        $zonesRaw = $configd->call('network.zones');
        foreach (['mgmt', 'lan1', 'wan1'] as $key) {
            $z = $zonesRaw[$key] ?? null;
            if ($z && !empty($z['interface'])) {
                $allZones[] = $z;
            }
        }
        foreach ($zonesRaw['opt'] ?? [] as $z) {
            if (!empty($z['interface'])) {
                $allZones[] = $z;
            }
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'security_ips') {
    try {
        $pilotInterfaces = array_values(array_filter((array) ($_POST['pilot_interfaces'] ?? [])));
        $configd->call('security.set_config', [
            'ips' => [
                'enabled' => isset($_POST['ips_enabled']),
                'pilot_interfaces' => $pilotInterfaces,
            ],
        ]);
        $saveMessage = isset($_POST['ips_enabled'])
            ? 'IPS pilot enabled on ' . count($pilotInterfaces) . ' interface(s). Suricata switched to netmap inline mode — verify connectivity before relying on remote access.'
            : 'IPS pilot disabled. Suricata reverted to IDS/PCAP mode.';
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'security_general') {
    $zones = [];
    foreach ($_POST['zone_alias'] ?? [] as $i => $alias) {
        $zones[] = [
            'zone_alias'  => (string) $alias,
            'physical_if' => (string) ($_POST['zone_if'][$i] ?? ''),
            'enabled'     => ($_POST['zone_enabled'][$i] ?? '0') === '1',
        ];
    }
    try {
        $configd->call('security.set_config', ['zones' => $zones]);
        $saveMessage = 'Security configuration saved and applied.';
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'security_sources') {
    try {
        $configd->call('security.set_config', [
            'rule_sources' => [
                'et_open' => isset($_POST['et_open']),
                'oisf_trafficid' => isset($_POST['oisf_trafficid']),
                'abuse_ch_ja3' => isset($_POST['abuse_ch_ja3']),
                'abuse_ch_urlhaus' => isset($_POST['abuse_ch_urlhaus']),
            ],
            'auto_update_enabled' => isset($_POST['auto_update_enabled']),
        ]);
        $saveMessage = 'Rule sources saved.';
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'security_update_rules') {
    try {
        // Timeout bumped from 60s: with 4 rule sources now enabled by
        // default vs. 2 when 60s was set, a real run confirmed to take
        // close to 3 minutes end-to-end. 300s gives headroom above that
        // observed real-world duration rather than another guess.
        $updateResult = $configd->call('security.update_rules', [], 300.0);
        $saveMessage = 'Rules updated successfully. Check the Status tab for the active rule count.';
        $updateDiagnostic = $updateResult['output'] ?? null;
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'security_policy') {
    // Same indexed-checkbox + hidden-default pattern as the RCA-17 fix on
    // the General tab - an unchecked checkbox is never submitted by the
    // browser at all, so a bare array name would silently shift indices
    // whenever fewer than all categories are checked.
    $disabledCategories = [];
    foreach ($_POST['category_key'] ?? [] as $i => $key) {
        if (($_POST['category_disabled'][$i] ?? '0') === '1') {
            $disabledCategories[] = (string) $key;
        }
    }
    try {
        $configd->call('security.set_config', ['disabled_categories' => $disabledCategories]);
        $saveMessage = 'Policy saved. Click "Update rules now" on the Rule sources tab to apply this to the active ruleset.';
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($installed && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'security_custom_rules') {
    try {
        $configd->call('security.set_config', ['custom_rules_text' => (string) ($_POST['custom_rules_text'] ?? '')]);
        $saveMessage = 'Custom rules saved. Click "Update rules now" on the Rule sources tab so the rules get validated (suricata -T) and loaded.';
        $securityConfig = $configd->call('security.get_config');
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}



$alertsData = [];
if ($installed && $activeTab === 'alerts') {
    try {
        $alertsData = $configd->call('security.get_alerts', ['limit' => 50]);
        try {
            $configd->call('system.alerts_acknowledge', ['source' => 'security']);
        } catch (NtpsenseConfigdException $e) {
            // Diam - kegagalan acknowledge tidak boleh mengganggu tampilan alert itu sendiri.
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

$statusData = null;
if ($installed && $activeTab === 'status') {
    try {
        $statusData = $configd->call('security.get_status');
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

function severityBadgeClass($sev): string
{
    if ($sev === null) return 'ntp-badge';
    if ((int) $sev === 1) return 'ntp-badge ntp-badge-danger';
    if ((int) $sev === 2) return 'ntp-badge ntp-badge-warning';
    return 'ntp-badge';
}
function severityLabel($sev): string
{
    if ($sev === null) return 'n/a';
    if ((int) $sev === 1) return 'High';
    if ((int) $sev === 2) return 'Medium';
    return 'Low';
}

$tabLabels = ['general' => 'General', 'sources' => 'Rule sources', 'policy' => 'Policy', 'custom_rules' => 'Custom rules', 'alerts' => 'Alerts', 'status' => 'Status'];
$pageTitle = 'Security';
$activeNavItem = 'security';
// Layer 1 (app header) - konsisten dengan pola Firewall/IPsec/NAT/Proxy.
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';

if (!$installed) {
    $categoryLabel = 'Security';
    $categoryIcon = 'ti-eye-search';
    require __DIR__ . '/../templates/plugin_not_installed.php';
    require __DIR__ . '/../templates/layout_footer.php';
    exit;
}
?>

<div style="margin-bottom:16px;">
  <span style="font-size:13px; color:#374151;">Suricata status:</span>
  <?php if ($running): ?>
    <span class="ntp-badge ntp-badge-success">Running</span>
  <?php else: ?>
    <span class="ntp-badge ntp-badge-warning">Stopped</span>
  <?php endif; ?>
</div>

<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch security status: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($saveMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($saveMessage) ?></div>
<?php endif; ?>
<?php if ($saveError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($saveError) ?></div>
<?php endif; ?>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=general" class="ntp-tab<?= $activeTab === 'general' ? ' active' : '' ?>">General</a>
  <a href="?tab=sources" class="ntp-tab<?= $activeTab === 'sources' ? ' active' : '' ?>">Rule sources</a>
  <a href="?tab=policy" class="ntp-tab<?= $activeTab === 'policy' ? ' active' : '' ?>">Policy</a>
  <a href="?tab=custom_rules" class="ntp-tab<?= $activeTab === 'custom_rules' ? ' active' : '' ?>">Custom rules</a>
  <a href="?tab=alerts" class="ntp-tab<?= $activeTab === 'alerts' ? ' active' : '' ?>">Alerts</a>
  <a href="?tab=status" class="ntp-tab<?= $activeTab === 'status' ? ' active' : '' ?>">Status</a>
</div>

<?php if ($activeTab === 'general'): ?>
<?php
$wan1Zone = null;
foreach ($allZones as $z) {
    if (($z['alias'] ?? '') === 'WAN1') { $wan1Zone = $z; break; }
}
// Kandidat interface pilot - reuse SUMBER YANG SAMA dipakai form
// Multi-WAN sendiri (bukan menebak field 'role' di sini) - konsisten,
// sudah teruji, mencakup WAN1 + WAN2 + WAN lain mana pun yang ada.
$wanCandidates = [];
try {
    $eligibleIfs = $configd->call('multiwan.eligible_interfaces')['interfaces'] ?? [];
    foreach ($eligibleIfs as $ifName) {
        $label = $ifName;
        foreach ($allZones as $z) {
            if (($z['interface'] ?? '') === $ifName) {
                $label = ($z['alias'] ?? '') !== '' ? $z['alias'] : $ifName;
                break;
            }
        }
        $wanCandidates[] = ['interface' => $ifName, 'label' => $label];
    }
} catch (NtpsenseConfigdException $e) {
    // Fallback minimal - WAN1 saja, kalau Multi-WAN belum dikonfigurasi sama sekali.
    if ($wan1Zone) {
        $wanCandidates[] = ['interface' => $wan1Zone['interface'], 'label' => 'WAN1'];
    }
}
$ipsEnabled = rsBool($securityConfig['ips']['enabled'] ?? null, false);
$ipsPilotIfs = $securityConfig['ips']['pilot_interfaces'] ?? [];
?>
<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Engine mode</div>
  <div style="padding:14px; display:flex; flex-direction:column; gap:12px;">
    <div style="border:1px solid #14213d; background:#eef1f8; border-radius:8px; padding:12px;">
      <strong style="font-size:13px;">IDS — detect and log</strong>
      <div style="font-size:12px; color:#6b7280;">Active on the zones enabled below (PCAP capture, no blocking)</div>
    </div>
    <div style="border:1px solid <?= $ipsEnabled ? '#b3261e' : '#e5e7eb' ?>; border-radius:8px; padding:12px;">
      <strong style="font-size:13px;">IPS — detect and block (pilot)</strong>
      <div style="font-size:12px; color:#6b7280; margin-top:2px;">
        Netmap inline mode, WAN interfaces only for this pilot phase (never MGMT/LAN). Not divert/ipfw —
        confirmed incompatible with a pf-based firewall (a real OPNsense bug report shows pf always processes
        traffic before ipfw gets a chance to divert it, so blocking silently never happens). While active, IDS
        PCAP mode is paused (single capture mode at a time).
      </div>
      <div style="font-size:11px; color:#b3261e; margin-top:8px; font-weight:500;">
        ⚠ Misconfiguration of this mode can cause connectivity loss (Suricata's own documented warning). WAN
        interfaces were chosen specifically because they are not MGMT — console/MGMT access stays available if
        something goes wrong.
      </div>
      <p style="font-size:11px; color:#9a5b00; background:#fff8e6; border:1px solid #f5d78e; border-radius:6px; padding:6px 8px; margin-top:8px;">
        💾 Each interface you enable here needs its own dedicated netmap buffer allocation (~1GB+ headroom
        recommended per interface, on top of what Suricata/Squid/Kea/WireGuard already use) - a real OOM crash
        was confirmed on a 2GB test VM with just one interface enabled. Enabling two interfaces roughly doubles
        that requirement - the gateway will refuse to enable this if it detects insufficient RAM.
      </p>
      <?php if (!empty($wanCandidates)): ?>
        <form method="post" style="margin-top:10px;">
          <input type="hidden" name="form" value="security_ips">
          <?php foreach ($wanCandidates as $wc): ?>
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; margin-bottom:6px;">
              <input type="checkbox" name="pilot_interfaces[]" value="<?= htmlspecialchars($wc['interface']) ?>" <?= in_array($wc['interface'], $ipsPilotIfs, true) ? 'checked' : '' ?>>
              <?= htmlspecialchars($wc['label']) ?> (<?= htmlspecialchars($wc['interface']) ?>)
            </label>
          <?php endforeach; ?>
          <label style="display:flex; align-items:center; gap:8px; font-size:12px; margin:10px 0 8px; padding-top:8px; border-top:1px solid #e5e7eb;">
            <input type="checkbox" name="ips_enabled" value="1" <?= $ipsEnabled ? 'checked' : '' ?>>
            Enable IPS pilot on the checked interface(s) above
          </label>
          <button type="submit" style="background:#b3261e; color:#ffffff; border:none; padding:6px 14px; font-size:12px; border-radius:6px;">Apply</button>
        </form>
      <?php else: ?>
        <p style="font-size:11px; color:#9ca3af; margin-top:8px;">No WAN interface detected — configure one on the Network or Multi-WAN page first.</p>

      <?php endif; ?>
    </div>
  </div>
</div>

<form method="post">
  <input type="hidden" name="form" value="security_general">
  <div class="ntp-card">
    <div class="ntp-card-header">Inspect per zone</div>
    <table class="ntp-table">
      <tr><th>Zone</th><th>Interface</th><th>Enabled</th></tr>
      <?php
      $enabledMap = [];
      foreach ($securityConfig['zones'] ?? [] as $z) {
          $enabledMap[$z['physical_if']] = $z['enabled'];
      }
      ?>
      <?php foreach ($allZones as $i => $z): ?>
        <?php $if = $z['interface']; $alias = $z['alias']; $isEnabled = rsBool($enabledMap[$if] ?? null, false); ?>
        <tr>
          <td><?= htmlspecialchars($alias) ?></td>
          <td style="color:#6b7280;"><?= htmlspecialchars($if) ?></td>
          <td>
            <input type="hidden" name="zone_alias[<?= $i ?>]" value="<?= htmlspecialchars($alias) ?>">
            <input type="hidden" name="zone_if[<?= $i ?>]" value="<?= htmlspecialchars($if) ?>">
            <input type="hidden" name="zone_enabled[<?= $i ?>]" value="0">
            <input type="checkbox" name="zone_enabled[<?= $i ?>]" value="1" <?= $isEnabled ? 'checked' : '' ?>>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px; margin-top:12px;">Save and apply</button>
</form>

<?php elseif ($activeTab === 'sources'): ?>
<form method="post">
  <input type="hidden" name="form" value="security_sources">
  <div class="ntp-card">
    <div class="ntp-card-header">Rule sources</div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      Free, no-registration sources, confirmed to exist in the official OISF index (<code>suricata-update list-sources</code>). Managed via <code>suricata-update</code> (bundled with the Suricata package).
    </p>
    <div style="padding:14px;">
      <label style="display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:10px;">
        <input type="checkbox" name="et_open" <?= rsBool($securityConfig['rule_sources']['et_open'] ?? null, true) ? 'checked' : '' ?>>
        Emerging Threats Open (ET Open)
      </label>
      <label style="display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:10px;">
        <input type="checkbox" name="oisf_trafficid" <?= rsBool($securityConfig['rule_sources']['oisf_trafficid'] ?? null, true) ? 'checked' : '' ?>>
        OISF Traffic ID (official, complements ET Open)
      </label>
      <label style="display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:10px;">
        <input type="checkbox" name="abuse_ch_ja3" <?= rsBool($securityConfig['rule_sources']['abuse_ch_ja3'] ?? null, false) ? 'checked' : '' ?>>
        Abuse.ch SSL/JA3 Fingerprint (Phase 2 — malware detection via TLS fingerprint)
      </label>
      <label style="display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:10px;">
        <input type="checkbox" name="abuse_ch_urlhaus" <?= rsBool($securityConfig['rule_sources']['abuse_ch_urlhaus'] ?? null, false) ? 'checked' : '' ?>>
        Abuse.ch URLhaus (Phase 2 — malicious URL list)
      </label>
      <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
        <input type="checkbox" name="auto_update_enabled" <?= rsBool($securityConfig['auto_update_enabled'] ?? null, true) ? 'checked' : '' ?>>
        Automatic daily rule update (cron)
      </label>
    </div>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px; margin-top:12px;">Save</button>
</form>

<form method="post" style="margin-top:16px; display:flex; align-items:center; gap:12px;">
  <input type="hidden" name="form" value="security_update_rules">
  <button type="submit" style="background:#ffffff; color:#14213d; border:1px solid #14213d; padding:8px 18px; font-size:13px; border-radius:6px;">Update rules now</button>
  <span style="font-size:12px; color:#6b7280;">
    Last updated:
    <?= !empty($securityConfig['last_rule_update']) ? htmlspecialchars(date('Y-m-d H:i', (int) $securityConfig['last_rule_update'])) : 'never' ?>
  </span>
</form>
<p style="font-size:11px; color:#9ca3af; margin:6px 0 0;">Can take a few minutes with multiple sources enabled — please wait for the page to respond rather than clicking again.</p>

<?php if ($updateDiagnostic): ?>
  <details class="ntp-card" style="margin-top:12px; padding:12px 14px;">
    <summary style="cursor:pointer; font-size:13px; color:#374151;">View update details (which sources are active, rule count per file)</summary>
    <pre style="margin:10px 0 0; font-size:11px; white-space:pre-wrap; font-family:monospace; max-height:400px; overflow-y:auto;"><?= htmlspecialchars($updateDiagnostic) ?></pre>
  </details>
<?php endif; ?>

<?php elseif ($activeTab === 'policy'): ?>
<?php
// Curated set of the 8 most relevant ET Open categories for a non-IPS
// decision (noise reduction, not security-critical) - the backend
// mechanism itself is generic (group:<filename>); this list is just the
// UI preset.
$policyCategories = [
    'emerging-chat.rules' => 'Chat / messaging apps',
    'emerging-p2p.rules' => 'Peer-to-peer / torrent',
    'emerging-games.rules' => 'Online games',
    'emerging-adware_pup.rules' => 'Adware / PUP',
    'emerging-policy.rules' => 'Policy / informational (tends to be noisy)',
    'emerging-inappropriate.rules' => 'Inappropriate content',
    'emerging-info.rules' => 'Informational (low severity, often just noise)',
    'emerging-mobile_malware.rules' => 'Mobile malware (relevant if mobile devices are on the network)',
];
$disabledSet = array_flip($securityConfig['policy']['disabled_categories'] ?? []);
?>
<form method="post">
  <input type="hidden" name="form" value="security_policy">
  <div class="ntp-card">
    <div class="ntp-card-header">Policy — disable rule categories</div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      Based on real alert data from the Alerts tab, disable categories proven to be noisy or irrelevant for this
      network. Uses suricata-update's own official mechanism (<code>disable.conf</code>, <code>group:&lt;file&gt;</code>) —
      takes effect after clicking "Update rules now" on the Rule sources tab, not immediately on save here.
    </p>
    <table class="ntp-table">
      <tr><th>Category</th><th>Disable</th></tr>
      <?php foreach (array_values($policyCategories) as $i => $label): $key = array_keys($policyCategories)[$i]; $isDisabled = isset($disabledSet[$key]); ?>
        <tr>
          <td><?= htmlspecialchars($label) ?> <span style="color:#9ca3af; font-size:11px;">(<?= htmlspecialchars($key) ?>)</span></td>
          <td>
            <input type="hidden" name="category_key[<?= $i ?>]" value="<?= htmlspecialchars($key) ?>">
            <input type="hidden" name="category_disabled[<?= $i ?>]" value="0">
            <input type="checkbox" name="category_disabled[<?= $i ?>]" value="1" <?= $isDisabled ? 'checked' : '' ?>>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px; margin-top:12px;">Save Policy</button>
</form>

<?php elseif ($activeTab === 'custom_rules'): ?>
<form method="post">
  <input type="hidden" name="form" value="security_custom_rules">
  <div class="ntp-card">
    <div class="ntp-card-header">Custom rules — admin-authored Suricata signatures</div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      One rule per line, standard Suricata syntax. These rules are merged in by <code>suricata-update</code> itself
      (<code>--local</code>) and automatically validated via <code>suricata -T</code> when "Update rules now" runs —
      if there's a syntax error, the update fails and Suricata's own error message is shown in the diagnostic panel
      on the Rule sources tab; the previous ruleset stays in place (no downtime).
    </p>
    <div style="padding:14px;">
      <textarea name="custom_rules_text" rows="10" style="width:100%; font-family:monospace; font-size:12px;"
        placeholder="alert icmp any any -> $HOME_NET any (msg:&quot;Custom ICMP test rule&quot;; sid:9000001; rev:1;)"><?= htmlspecialchars($securityConfig['custom_rules_text'] ?? '') ?></textarea>
    </div>
  </div>
  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px; margin-top:12px;">Save Custom rules</button>
</form>

<?php elseif ($activeTab === 'alerts'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">50 most recent alerts</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">From <code>eve.json</code>. IDS-only mode: no traffic is being blocked.</p>
  <?php if (empty($alertsData)): ?>
    <p style="padding:12px 14px; font-size:12px; color:#6b7280;">No alerts recorded yet.</p>
  <?php else: ?>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead>
      <tr><th>Time</th><th>Severity</th><th>Signature</th><th>Src</th><th>Dst</th><th>Proto</th><th>Iface</th></tr>
      </thead>
      <tbody>
      <?php foreach ($alertsData as $a): ?>
        <tr>
          <td style="color:#6b7280; font-size:12px;"><?= htmlspecialchars($a['timestamp'] ?? '') ?></td>
          <td><span class="<?= severityBadgeClass($a['severity'] ?? null) ?>"><?= severityLabel($a['severity'] ?? null) ?></span></td>
          <td><?= htmlspecialchars($a['signature'] ?? '') ?></td>
          <td style="font-size:12px;"><?= htmlspecialchars($a['src_ip'] ?? '') ?></td>
          <td style="font-size:12px;"><?= htmlspecialchars($a['dest_ip'] ?? '') ?></td>
          <td style="font-size:12px;"><?= htmlspecialchars($a['proto'] ?? '') ?></td>
          <td style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($a['in_iface'] ?? '') ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php endif; ?>
</div>

<?php elseif ($activeTab === 'status'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Status</div>
  <table class="ntp-table">
    <tr><th>State</th><td><?= ($statusData['running'] ?? false) ? '<span class="ntp-badge ntp-badge-success">Running</span>' : '<span class="ntp-badge ntp-badge-warning">Stopped</span>' ?></td></tr>
    <tr><th>Engine version</th><td><?= htmlspecialchars($statusData['version'] ?? '—') ?></td></tr>
    <tr><th>Active rule count</th><td><?= htmlspecialchars((string) ($statusData['rule_count'] ?? '—')) ?></td></tr>
    <tr><th>Monitored interfaces</th><td><?= htmlspecialchars($statusData['interfaces'] ?? '—') ?></td></tr>
  </table>
</div>

<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
