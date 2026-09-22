<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
Auth::requireLogin();
Auth::requireCategory('system_logs');
$configd = new NtpsenseConfigd();
$configdError = null;
$validTabs = ['general', 'firewall', 'dhcp', 'proxy', 'security', 'vpn', 'openvpn', 'freeradius', 'os_boot', 'gui_service', 'watchdog', 'maintenance', 'users_activity', 'alerts'];
$activeTab = $_GET['tab'] ?? 'general';
if (!in_array($activeTab, $validTabs, true)) {
    $activeTab = 'general';
}
$tabLabels = [
    'general' => 'General', 'firewall' => 'Firewall', 'dhcp' => 'DHCP',
    'proxy' => 'Proxy', 'security' => 'Security', 'vpn' => 'IPsec VPN', 'openvpn' => 'OpenVPN', 'freeradius' => 'FreeRADIUS',
    'os_boot' => 'OS Boot', 'gui_service' => 'GUI Service', 'watchdog' => 'Watchdog', 'maintenance' => 'Maintenance', 'users_activity' => 'Users Activity',
    'alerts' => 'Alerts',
];
// Firewall tab - filter form (dibatasi ke field yang benar-benar
// didukung backend saat ini - source IP, dest IP, action - bukan daftar
// lengkap ala pfSense yang belum semuanya di-wire, supaya tidak janji
// fitur yang belum jalan).
$fwSourceIp = trim((string) ($_GET['source_ip'] ?? ''));
$fwDestIp = trim((string) ($_GET['dest_ip'] ?? ''));
$fwAction = (string) ($_GET['action_filter'] ?? '');
$fwInterface = trim((string) ($_GET['interface'] ?? ''));
$firewallEntries = [];
$logLines = [];
$logParsed = [];
$logPath = null;
$vpnLogLines = [];
$vpnLogParsed = [];
$vpnIpsecTunnels = [];
$securityAlerts = [];
$userActivityEntries = [];
$userActivityFilter = trim((string) ($_GET['username_filter'] ?? ''));
$alertsList = [];
$alertsMessage = null;
$alertsError = null;
if ($activeTab === 'users_activity') {
    $userActivityEntries = AuditLog::tail(500);
    if ($userActivityFilter !== '') {
        $userActivityEntries = array_values(array_filter(
            $userActivityEntries,
            static fn (array $e) => stripos((string) ($e['username'] ?? ''), $userActivityFilter) !== false
        ));
    }
}
// Alerts tab - halaman penuh (roadmap, riset Palo Alto/FortiGate/
// pfSense: Timestamp/Severity/Source/Message/Suggested Action/Status).
// Tombol "Acknowledge" per baris eksplisit mengakui granularitasnya
// per-SUMBER (bukan per-baris-individual) - disepakati sebagai
// pendekatan pragmatis, jadi labelnya jujur "Acknowledge all Watchdog"
// dst, bukan berpura-pura presisi per-baris yang sebenarnya tidak ada.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'alert_acknowledge_source') {
    try {
        $configd->call('system.alerts_acknowledge', [
            'source' => (string) ($_POST['source'] ?? ''),
            'acknowledged_by' => (string) ($_SESSION['ntpsense_username'] ?? 'unknown'),
        ]);
        $alertsMessage = 'Acknowledged.';
    } catch (NtpsenseConfigdException $e) {
        $alertsError = $e->getMessage();
    }
}
try {
    if ($activeTab === 'firewall') {
        $params = ['limit' => 500];
        if ($fwSourceIp !== '') $params['source_ip'] = $fwSourceIp;
        if ($fwDestIp !== '') $params['dest_ip'] = $fwDestIp;
        if (in_array($fwAction, ['pass', 'block'], true)) $params['action_filter'] = $fwAction;
        if ($fwInterface !== '') $params['interface'] = $fwInterface;
        $result = $configd->call('firewall.get_log', $params, 20.0);
        $firewallEntries = $result['entries'] ?? [];
    } elseif (in_array($activeTab, ['general', 'dhcp', 'proxy', 'gui_service', 'os_boot', 'watchdog', 'maintenance', 'openvpn'], true)) {
        $result = $configd->call('system.get_log', ['source' => $activeTab, 'limit' => 500], 20.0);
        $logLines = $result['lines'] ?? [];
        $logParsed = $result['parsed'] ?? [];
        $logPath = $result['path'] ?? null;
    } elseif ($activeTab === 'freeradius') {
        // Reuse action freeradius.get_log yang sudah ada (fitur
        // Services > FreeRADIUS > Log) - bentuk data {lines, parsed}
        // PERSIS SAMA dengan tab generik di atas, jadi otomatis jatuh
        // ke UI fallback generik di bawah, tidak perlu markup baru.
        $result = $configd->call('freeradius.get_log', ['limit' => 500], 20.0);
        $logLines = $result['lines'] ?? [];
        $logParsed = $result['parsed'] ?? [];
        $logPath = '/var/log/radius.log';
        if ($activeTab === 'watchdog') {
            // Alert "sudah dibaca" - begitu admin membuka tab ini, badge
            // lonceng untuk sumber watchdog dianggap terlihat, cuma
            // muncul lagi kalau ada event WARNING baru setelah titik ini.
            try {
                $configd->call('system.alerts_acknowledge', [
                    'source' => 'watchdog',
                    'acknowledged_by' => (string) ($_SESSION['ntpsense_username'] ?? 'unknown'),
                ]);
            } catch (NtpsenseConfigdException $e) {
                // Diam - kegagalan acknowledge tidak boleh mengganggu
                // tampilan log itu sendiri.
            }
        }
    } elseif ($activeTab === 'security') {
        // Reuse action yang sudah ada - satu sumber kebenaran, bukan
        // duplikasi parsing eve.json di sini.
        $securityAlerts = $configd->call('security.get_alerts', ['limit' => 500]);
    } elseif ($activeTab === 'vpn') {
        // Reuse ipsec.get_log yang sudah ada. WireGuard tidak punya file
        // log terpisah sendiri (belum ada filelog drop-in untuk itu,
        // beda dari IPsec/charon) - ditampilkan best-effort lewat grep
        // /var/log/messages, ditandai jelas di UI kalau kosong.
        $vpnResult = $configd->call('ipsec.get_log', ['limit' => 300]);
        $vpnLogLines = $vpnResult['lines'] ?? [];
        $vpnLogParsed = $vpnResult['parsed'] ?? [];
    } elseif ($activeTab === 'alerts') {
        $alertsList = $configd->call('system.alerts_list')['alerts'] ?? [];
    }
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
$pageTitle = 'System Logs';
$activeNavItem = 'system_logs';
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';
?>
<?php if ($configdError): ?>
  <div class="ntp-alert-error">Unable to fetch log: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<div class="ntp-tabbar" style="margin-bottom:14px;">
  <?php foreach ($tabLabels as $key => $label): ?>
    <a href="?tab=<?= $key ?>" class="ntp-tab<?= $activeTab === $key ? ' active' : '' ?>"><?= htmlspecialchars($label) ?></a>
  <?php endforeach; ?>
</div>
<?php if ($activeTab === 'firewall'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Firewall Log</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Read from /var/log/pflog (pflogd, FreeBSD base) via tcpdump - every custom Firewall/NAT/VPN rule now
    includes the <code>log</code> keyword automatically. Only the packet that establishes a new state is
    logged for "keep state" rules, not every packet, so volume stays reasonable.
  </p>
  <form method="get" style="padding:14px; border-bottom:1px solid #e5e7eb; display:grid; grid-template-columns:repeat(5, 1fr); gap:10px; align-items:end;">
    <input type="hidden" name="tab" value="firewall">
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Source IP</label>
      <input type="text" name="source_ip" value="<?= htmlspecialchars($fwSourceIp) ?>" placeholder="10.252.1.50" style="width:100%;">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Destination IP</label>
      <input type="text" name="dest_ip" value="<?= htmlspecialchars($fwDestIp) ?>" placeholder="8.8.8.8" style="width:100%;">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Interface</label>
      <input type="text" name="interface" value="<?= htmlspecialchars($fwInterface) ?>" placeholder="em5" style="width:100%;">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Action</label>
      <select name="action_filter" style="width:100%;">
        <option value="" <?= $fwAction === '' ? 'selected' : '' ?>>All</option>
        <option value="pass" <?= $fwAction === 'pass' ? 'selected' : '' ?>>Pass</option>
        <option value="block" <?= $fwAction === 'block' ? 'selected' : '' ?>>Block</option>
      </select>
    </div>
    <div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Apply Filter</button>
    </div>
  </form>
  <input type="text" class="ntp-table-search" data-table-target="tbl-firewall" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-firewall">
    <thead>
    <tr><th style="width:170px;">Time</th><th style="width:80px;">Action</th><th style="width:90px;">Direction</th><th style="width:90px;">Interface</th><th style="width:70px;">Rule #</th><th style="width:180px;">Source</th><th style="width:180px;">Destination</th><th style="width:220px;">Protocol</th></tr>
    </thead>
    <tbody>
    <?php if (empty($firewallEntries)): ?>
      <tr><td colspan="8" style="color:#6b7280;">No log entries. If this stays empty after real traffic passes through, /var/log/pflog may not have data yet - confirm with <code>pfctl -s info</code> that pflogd is running.</td></tr>
    <?php endif; ?>
    <?php foreach ($firewallEntries as $e): ?>
      <tr>
        <td><?= htmlspecialchars($e['time'] ?? '') ?></td>
        <td>
          <?php if (($e['action'] ?? '') === 'block'): ?>
            <span class="ntp-badge ntp-badge-warning">block</span>
          <?php elseif (($e['action'] ?? '') === 'pass'): ?>
            <span class="ntp-badge ntp-badge-success">pass</span>
          <?php else: ?>
            <?= htmlspecialchars($e['action'] ?? '—') ?>
          <?php endif; ?>
        </td>
        <td><?= htmlspecialchars($e['direction'] ?? '—') ?></td>
        <td><?= htmlspecialchars($e['interface'] ?? '—') ?></td>
        <td><?= htmlspecialchars($e['rule_number'] ?? '—') ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars($e['source'] ?? '—') ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars($e['destination'] ?? '—') ?></td>
        <td style="color:#6b7280;"><?= htmlspecialchars($e['protocol'] ?? '—') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php elseif ($activeTab === 'security'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Security (Suricata) Alerts</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Same data as <a href="/security.php?tab=alerts">Security &gt; Alerts</a> - shown here too for a single
    consolidated log view across the whole system.
  </p>
  <input type="text" class="ntp-table-search" data-table-target="tbl-security" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-security">
    <thead>
    <tr><th style="width:170px;">Time</th><th style="width:90px;">Severity</th><th style="width:260px;">Signature</th><th style="width:150px;">Src</th><th style="width:150px;">Dst</th><th style="width:80px;">Proto</th><th style="width:90px;">Iface</th></tr>
    </thead>
    <tbody>
    <?php if (empty($securityAlerts)): ?>
      <tr><td colspan="7" style="color:#6b7280;">No alerts.</td></tr>
    <?php endif; ?>
    <?php foreach ($securityAlerts as $a): ?>
      <tr>
        <td><?= htmlspecialchars($a['timestamp'] ?? '') ?></td>
        <td><?= htmlspecialchars((string) ($a['severity'] ?? '')) ?></td>
        <td><?= htmlspecialchars($a['signature'] ?? '') ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars($a['src_ip'] ?? '') ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars($a['dest_ip'] ?? '') ?></td>
        <td><?= htmlspecialchars($a['proto'] ?? '') ?></td>
        <td><?= htmlspecialchars($a['in_iface'] ?? '') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php elseif ($activeTab === 'vpn'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">VPN — IPsec (charon)</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Same data as <a href="/ipsec.php?tab=log">IPsec VPN &gt; IPsec Log</a>.
  </p>
  <input type="text" class="ntp-table-search" data-table-target="tbl-vpn" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-vpn">
    <thead>
    <tr><th style="width:150px;">Timestamp</th><th style="width:80px;">Level</th><th style="width:500px;">Message</th></tr>
    </thead>
    <tbody>
    <?php if (empty($vpnLogParsed)): ?>
      <tr><td colspan="3" style="color:#6b7280;">No log entries yet.</td></tr>
    <?php endif; ?>
    <?php foreach ($vpnLogParsed as $e): ?>
      <tr>
        <td style="white-space:nowrap;"><?= htmlspecialchars($e['timestamp'] ?? '') ?></td>
        <td>
          <?php $lvl = $e['level'] ?? 'info'; ?>
          <?php if ($lvl === 'error'): ?>
            <span class="ntp-badge ntp-badge-danger">error</span>
          <?php elseif ($lvl === 'warning'): ?>
            <span class="ntp-badge ntp-badge-warning">warning</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-muted">info</span>
          <?php endif; ?>
        </td>
        <td><?= htmlspecialchars($e['message'] ?? '') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<div class="ntp-card" style="margin-top:16px;">
  <div class="ntp-card-header">VPN — WireGuard</div>
  <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
    WireGuard does not currently write to a dedicated log file (unlike IPsec/charon) - check
    <a href="/vpn.php?tab=peers">VPN &gt; Peers</a> for live connection/handshake status instead of a log.
  </p>
</div>
<?php elseif ($activeTab === 'users_activity'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Users Activity</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Who did what, from where, and when - login/logout, every change submitted (with old→new value where that
    information is directly available), and every access attempt blocked by role permissions. Kept separate from
    the OS/service logs above since this tracks Web UI users specifically, not the underlying FreeBSD system.
  </p>
  <form method="get" style="padding:14px; border-bottom:1px solid #e5e7eb; display:flex; gap:10px; align-items:end;">
    <input type="hidden" name="tab" value="users_activity">
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Username contains</label>
      <input type="text" name="username_filter" value="<?= htmlspecialchars($userActivityFilter) ?>" placeholder="admin" style="width:200px;">
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Filter</button>
  </form>
  <input type="text" class="ntp-table-search" data-table-target="tbl-users-activity" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-users-activity">
    <thead>
    <tr><th style="width:150px;">Time</th><th style="width:110px;">Username</th><th style="width:130px;">IP</th><th style="width:110px;">Category</th><th style="width:150px;">Action</th><th style="width:100px;">Result</th><th style="width:300px;">Details (old ==&gt; new)</th></tr>
    </thead>
    <tbody>
    <?php if (empty($userActivityEntries)): ?>
      <tr><td colspan="7" style="color:#6b7280;">No activity recorded yet.</td></tr>
    <?php endif; ?>
    <?php foreach ($userActivityEntries as $e): ?>
      <tr>
        <td><?= htmlspecialchars(date('Y-m-d H:i:s', (int) ($e['ts'] ?? 0))) ?></td>
        <td><?= htmlspecialchars((string) ($e['username'] ?? '')) ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars((string) ($e['ip'] ?? '')) ?></td>
        <td><?= htmlspecialchars((string) ($e['category'] ?? '')) ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars((string) ($e['action'] ?? '')) ?></td>
        <td>
          <?php $result = (string) ($e['result'] ?? ''); ?>
          <?php if (str_starts_with($result, 'denied') || $result === 'failed'): ?>
            <span class="ntp-badge ntp-badge-danger"><?= htmlspecialchars($result) ?></span>
          <?php elseif (in_array($result, ['success', 'allowed'], true)): ?>
            <span class="ntp-badge ntp-badge-success"><?= htmlspecialchars($result) ?></span>
          <?php else: ?>
            <?= htmlspecialchars($result) ?>
          <?php endif; ?>
        </td>
        <td style="color:#374151;"><?= htmlspecialchars((string) ($e['cfgattr'] ?? '')) ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php elseif ($activeTab === 'alerts'): ?>
<div class="ntp-card">
  <div class="ntp-card-header">Alerts</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Consolidated view across Suricata, Watchdog, Certificates, Multi-WAN, Resource usage (disk/swap), High
    Availability, and VPN tunnels - researched against Palo
    Alto/FortiGate/pfSense before building (explicit per-item Acknowledge, severity-coded rows, a suggested
    next step per alert type). "Acknowledge" clears the whole category shown here (e.g. every Watchdog
    restart event) - not one individual row at a time, since that's the same granularity the bell icon and
    each destination tab already use consistently across this product.
  </p>
  <?php if ($alertsMessage): ?>
    <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin:0 14px 12px; font-size:13px;"><?= htmlspecialchars($alertsMessage) ?></div>
  <?php endif; ?>
  <?php if ($alertsError): ?>
    <div class="ntp-alert-error" style="margin:0 14px 12px;">Failed: <?= htmlspecialchars($alertsError) ?></div>
  <?php endif; ?>
  <input type="text" class="ntp-table-search" data-table-target="tbl-alerts" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-alerts">
    <thead>
    <tr><th style="width:150px;">Timestamp</th><th style="width:90px;">Severity</th><th style="width:100px;">Source</th><th style="width:260px;">Message</th><th style="width:280px;">Suggested Action</th><th style="width:140px;">Status</th><th style="width:90px;">Manage</th></tr>
    </thead>
    <tbody>
    <?php if (empty($alertsList)): ?>
      <tr><td colspan="7" style="color:#6b7280;">No active alerts - everything looks normal.</td></tr>
    <?php endif; ?>
    <?php foreach ($alertsList as $a): ?>
      <?php $sev = (string) ($a['severity'] ?? ''); ?>
      <tr<?= !empty($a['acknowledged']) ? ' style="opacity:0.55;"' : '' ?>>
        <td style="font-size:12px; white-space:nowrap;"><?= htmlspecialchars((string) ($a['timestamp'] ?? '')) ?: '<span style="color:#9ca3af;">(current state)</span>' ?></td>
        <td>
          <?php if ($sev === 'critical'): ?>
            <span class="ntp-badge ntp-badge-danger">critical</span>
          <?php elseif ($sev === 'warning'): ?>
            <span class="ntp-badge ntp-badge-warning">warning</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-muted"><?= htmlspecialchars($sev) ?></span>
          <?php endif; ?>
        </td>
        <td style="text-transform:capitalize;"><?= htmlspecialchars((string) ($a['source'] ?? '')) ?></td>
        <td><?= htmlspecialchars((string) ($a['message'] ?? '')) ?></td>
        <td style="color:#6b7280;"><?= htmlspecialchars((string) ($a['suggested_action'] ?? '')) ?></td>
        <td>
          <?php if (!empty($a['acknowledged'])): ?>
            <span class="ntp-badge ntp-badge-success">Acknowledged</span>
            <?php if (!empty($a['acknowledged_by'])): ?>
              <br><span style="color:#9ca3af;">by <?= htmlspecialchars((string) $a['acknowledged_by']) ?><?= !empty($a['acknowledged_at']) ? ' - ' . htmlspecialchars(date('Y-m-d H:i', (int) $a['acknowledged_at'])) : '' ?></span>
            <?php endif; ?>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-warning">New</span>
          <?php endif; ?>
        </td>
        <td>
          <a href="<?= htmlspecialchars((string) ($a['link'] ?? '#')) ?>" style="color:#14213d; text-decoration:underline;">View</a>
          <?php if (empty($a['acknowledged'])): ?>
            <form method="post" style="display:inline; margin:0 0 0 8px;">
              <input type="hidden" name="form" value="alert_acknowledge_source">
              <input type="hidden" name="source" value="<?= htmlspecialchars((string) ($a['source'] ?? '')) ?>">
              <button type="submit" style="background:none; border:none; cursor:pointer; color:#1a7f4b; text-decoration:underline; padding:0; font-size:inherit;">Acknowledge</button>
            </form>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php elseif (in_array($activeTab, ['proxy', 'gui_service'], true)): ?>
<div class="ntp-card">
  <div class="ntp-card-header"><?= htmlspecialchars($tabLabels[$activeTab]) ?> Log<?= $logPath ? ' <span style="font-weight:400; font-size:11px; color:#9ca3af;">(' . htmlspecialchars($logPath) . ')</span>' : '' ?></div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    <?= $activeTab === 'proxy' ? 'Squid access log - who requested what, through the proxy.' : 'lighttpd access log - every request served by the Web UI itself.' ?>
  </p>
  <input type="text" class="ntp-table-search" data-table-target="tbl-<?= htmlspecialchars($activeTab) ?>" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-<?= htmlspecialchars($activeTab) ?>">
    <thead>
    <tr><th style="width:160px;">Timestamp</th><th style="width:140px;">Client IP</th><th style="width:80px;">Method</th><th style="width:340px;">URL</th><th style="width:80px;">Status</th><th style="width:90px;">Size</th></tr>
    </thead>
    <tbody>
    <?php if (empty($logParsed)): ?>
      <tr><td colspan="6" style="color:#6b7280;">No log entries yet.</td></tr>
    <?php endif; ?>
    <?php foreach ($logParsed as $e): ?>
      <tr>
        <td style="white-space:nowrap;"><?= htmlspecialchars($e['timestamp'] ?? '') ?></td>
        <td style="font-family:monospace;"><?= htmlspecialchars($e['client_ip'] ?? '') ?></td>
        <td><?= htmlspecialchars($e['method'] ?? '') ?></td>
        <td style="word-break:break-all;"><?= htmlspecialchars($e['url'] ?? '') ?></td>
        <td>
          <?php $st = (string) ($e['status'] ?? ''); ?>
          <?php if (str_starts_with($st, '4') || str_starts_with($st, '5')): ?>
            <span class="ntp-badge ntp-badge-warning"><?= htmlspecialchars($st) ?></span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-success"><?= htmlspecialchars($st) ?></span>
          <?php endif; ?>
        </td>
        <td><?= htmlspecialchars($e['size'] ?? '') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php else: ?>
<div class="ntp-card">
  <div class="ntp-card-header"><?= htmlspecialchars($tabLabels[$activeTab]) ?> Log<?= $logPath ? ' <span style="font-weight:400; font-size:11px; color:#9ca3af;">(' . htmlspecialchars($logPath) . ')</span>' : '' ?></div>
  <input type="text" class="ntp-table-search" data-table-target="tbl-<?= htmlspecialchars($activeTab) ?>" placeholder="Search in results...">
  <div class="ntp-table-resizable-wrap">
  <table class="ntp-table-resizable" id="tbl-<?= htmlspecialchars($activeTab) ?>">
    <thead>
    <tr><th style="width:150px;">Timestamp</th><th style="width:80px;">Level</th><th style="width:600px;">Message</th></tr>
    </thead>
    <tbody>
    <?php if (empty($logParsed)): ?>
      <tr><td colspan="3" style="color:#6b7280;">No log entries yet.</td></tr>
    <?php endif; ?>
    <?php foreach ($logParsed as $e): ?>
      <tr>
        <td style="white-space:nowrap;"><?= htmlspecialchars($e['timestamp'] ?? '') ?: '<span style="color:#9ca3af;">—</span>' ?></td>
        <td>
          <?php $lvl = $e['level'] ?? 'info'; ?>
          <?php if ($lvl === 'error'): ?>
            <span class="ntp-badge ntp-badge-danger">error</span>
          <?php elseif ($lvl === 'warning'): ?>
            <span class="ntp-badge ntp-badge-warning">warning</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-muted">info</span>
          <?php endif; ?>
        </td>
        <td><?= htmlspecialchars($e['message'] ?? '') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>
<?php endif; ?>
<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
