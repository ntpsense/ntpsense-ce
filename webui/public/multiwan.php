<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
require_once __DIR__ . '/../lib/license.php';
Auth::requireLogin();
Auth::requireCategory('multiwan');
$configd = new NtpsenseConfigd();
$configdError = null;
$actionMessage = null;
$actionError = null;
// GERBANG LISENSI Agustus 2026 (lihat compare.html - baris "Multi-WAN
// failover": CE "Basic (2 WAN)" vs Pro "Unlimited"; baris "Dedicated/
// shared WAN-aware preference": CE "-" vs Pro "v"). Dihitung SEKALI di
// atas, dipakai konsisten di seluruh handler POST dan rendering di
// bawah - satu titik kebenaran, bukan dicek ulang tiap tempat dengan
// logic berbeda-beda.
$isProLicensed = false;
try {
    $isProLicensed = ntpsense_get_license_status()->isFullyValid();
} catch (\Throwable $e) {
    $isProLicensed = false; // fail-closed - anggap CE kalau pengecekan lisensi sendiri error
}
const NTPSENSE_CE_MAX_GATEWAYS = 2;
// ------------------------------------------------------------
// POST handlers - Gateway CRUD
// ------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'gateway_create') {
    try {
        // Batas jumlah gateway untuk CE - dicek SEBELUM kirim RPC ke
        // daemon, sama pola dengan gerbang Site Mesh VPN sebelumnya
        // (murni di layer PHP, tidak perlu ubah multiwan.rs).
        if (!$isProLicensed) {
            $currentCount = count($configd->call('multiwan.gateway_list')['gateways'] ?? []);
            if ($currentCount >= NTPSENSE_CE_MAX_GATEWAYS) {
                throw new NtpsenseConfigdException(
                    'Community Edition (CE) is limited to ' . NTPSENSE_CE_MAX_GATEWAYS . ' gateways. '
                    . 'This installation already has ' . $currentCount . '. '
                    . 'Upgrade to NTPSense Pro for unlimited gateways - see ntpsense.com/compare.html or '
                    . 'upload a valid Pro license under System > License.'
                );
            }
        }
        // Link Type (dedicated/shared) adalah fitur Pro - untuk CE,
        // ABAIKAN apa pun yang terkirim dari form (walau form sendiri
        // sudah sembunyikan dropdown-nya untuk CE, JANGAN percaya cuma
        // itu - form bisa saja dimanipulasi manual) dan PAKSA selalu
        // 'dedicated' (nilai default/aman, sama seperti sebelum
        // link_type ada sama sekali).
        $linkType = $isProLicensed ? (string) ($_POST['link_type'] ?? 'dedicated') : 'dedicated';
        $configd->call('multiwan.gateway_create', [
            'name' => (string) ($_POST['name'] ?? ''),
            'interface' => (string) ($_POST['interface'] ?? ''),
            'gateway_ip' => (string) ($_POST['gateway_ip'] ?? ''),
            'monitor_ip' => (string) ($_POST['monitor_ip'] ?? ''),
            'link_type' => $linkType,
        ]);
        $actionMessage = 'Gateway created.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'gateway_update') {
    try {
        // Sama seperti gateway_create - paksa 'dedicated' untuk CE,
        // jangan percaya nilai form mentah.
        $linkType = $isProLicensed ? (string) ($_POST['link_type'] ?? 'dedicated') : 'dedicated';
        $configd->call('multiwan.gateway_update', [
            'name' => (string) ($_POST['name'] ?? ''),
            'gateway_ip' => (string) ($_POST['gateway_ip'] ?? ''),
            'monitor_ip' => (string) ($_POST['monitor_ip'] ?? ''),
            'enabled' => isset($_POST['enabled']),
            'link_type' => $linkType,
        ]);
        $actionMessage = 'Gateway updated.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'gateway_delete') {
    try {
        $configd->call('multiwan.gateway_delete', ['name' => (string) ($_POST['name'] ?? '')]);
        $actionMessage = 'Gateway deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
// ------------------------------------------------------------
// POST handlers - Gateway Group CRUD
// ------------------------------------------------------------
function buildMembersFromPost(): array
{
    $members = [];
    $names = $_POST['member_gateway'] ?? [];
    $tiers = $_POST['member_tier'] ?? [];
    foreach ($names as $i => $name) {
        $name = trim((string) $name);
        if ($name === '') {
            continue;
        }
        $members[] = ['gateway_name' => $name, 'tier' => (int) ($tiers[$i] ?? 1)];
    }
    return $members;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_create') {
    try {
        $configd->call('multiwan.group_create', [
            'name' => (string) ($_POST['name'] ?? ''),
            'members' => buildMembersFromPost(),
        ]);
        $actionMessage = 'Gateway group created.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_update') {
    try {
        $configd->call('multiwan.group_update', [
            'name' => (string) ($_POST['name'] ?? ''),
            'members' => buildMembersFromPost(),
            // Preservasi (BUKAN direset diam-diam) - form Edit kirim
            // nilai existing group lewat hidden field, supaya edit
            // members/tier saja tidak sengaja menghapus setting
            // routing_mode/SLA yang mungkin sudah admin set sebelumnya
            // (fitur quality-routing belum ada UI editing-nya sendiri
            // di form ini, tapi setidaknya tidak boleh hilang diam-diam).
            'routing_mode' => (string) ($_POST['routing_mode'] ?? 'static'),
            'sla_max_latency_ms' => ($_POST['sla_max_latency_ms'] ?? '') !== '' ? (float) $_POST['sla_max_latency_ms'] : null,
            'sla_max_jitter_ms' => ($_POST['sla_max_jitter_ms'] ?? '') !== '' ? (float) $_POST['sla_max_jitter_ms'] : null,
            'sla_max_packet_loss_pct' => ($_POST['sla_max_packet_loss_pct'] ?? '') !== '' ? (float) $_POST['sla_max_packet_loss_pct'] : null,
        ]);
        $actionMessage = 'Gateway group updated.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_delete') {
    try {
        $configd->call('multiwan.group_delete', ['name' => (string) ($_POST['name'] ?? '')]);
        $actionMessage = 'Gateway group deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_set_default') {
    try {
        $name = (string) ($_POST['name'] ?? '');
        $configd->call('multiwan.group_set_default', ['name' => $name]);
        $actionMessage = $name === '' ? 'System Default Gateway cleared.' : "System Default Gateway set to '{$name}'.";
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_clear_default') {
    try {
        $configd->call('multiwan.group_set_default', ['name' => '']);
        $actionMessage = 'System Default Gateway cleared.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'settings_update') {
    try {
        $configd->call('multiwan.settings_update', [
            'interval_secs' => (int) ($_POST['interval_secs'] ?? 0),
            'fail_threshold' => (int) ($_POST['fail_threshold'] ?? 0),
            'recover_threshold' => (int) ($_POST['recover_threshold'] ?? 0),
        ]);
        $actionMessage = 'Health-check settings updated - takes effect on the next monitoring cycle, no restart needed.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
// ------------------------------------------------------------
// Data fetch (scoped per tab, matching the pattern used everywhere else)
// ------------------------------------------------------------
$requestedTab = $_GET['tab'] ?? 'gateways';
$activeTab = in_array($requestedTab, ['gateways', 'groups', 'status', 'events', 'settings'], true) ? $requestedTab : 'gateways';
$gateways = [];
$eligibleInterfaces = [];
$groups = [];
$statusData = ['gateways' => [], 'groups' => []];
$eventLines = [];
$healthCheckSettings = ['interval_secs' => 5, 'fail_threshold' => 3, 'recover_threshold' => 3];
try {
    // Gateways dan eligible interfaces dibutuhkan hampir di semua tab
    // (dropdown member grup butuh daftar gateway juga) - diambil selalu,
    // bukan cuma saat tab='gateways'.
    $gateways = $configd->call('multiwan.gateway_list')['gateways'] ?? [];
    $eligibleInterfaces = $configd->call('multiwan.eligible_interfaces')['interfaces'] ?? [];
    $groups = $configd->call('multiwan.group_list')['groups'] ?? [];
    // statusData JUGA diambil selalu (bukan cuma tab='status') - dibutuhkan
    // untuk banner peringatan susunan tier System Default Gateway
    // (system_default_ordering_warning) yang harus terlihat di tab
    // MANA PUN, bukan cuma saat admin kebetulan buka tab Status.
    $statusData = $configd->call('multiwan.status');
    if ($activeTab === 'settings') {
        $healthCheckSettings = $configd->call('multiwan.settings_get');
    }
    if ($activeTab === 'status') {
        try {
            $configd->call('system.alerts_acknowledge', ['source' => 'multiwan']);
        } catch (NtpsenseConfigdException $e) {
            // Diam - kegagalan acknowledge tidak boleh mengganggu tampilan status itu sendiri.
        }
    }
    if ($activeTab === 'events') {
        $eventLines = $configd->call('multiwan.event_log', ['limit' => 300])['lines'] ?? [];
    }
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
$pageTitle = 'Multi-WAN';
$activeNavItem = 'multiwan';
$tabLabels = ['gateways' => 'Gateways', 'groups' => 'Gateway Groups', 'status' => 'Status', 'events' => 'Event Log', 'settings' => 'Settings'];
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';
?>
<?php if ($configdError): ?>
  <div class="ntp-alert-error">Unable to fetch Multi-WAN data: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($actionMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($actionMessage) ?></div>
<?php endif; ?>
<?php if ($actionError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($actionError) ?></div>
<?php endif; ?>
<?php // Peringatan susunan tier (dedicated vs shared) adalah fitur Pro -
      // untuk CE, banner ini TIDAK PERNAH ditampilkan sama sekali, tidak
      // peduli apa isi statusData['system_default_ordering_warning'] dari
      // daemon (yang mungkin tetap menghitungnya terlepas status lisensi -
      // ini murni gerbang tampilan, bukan bukti daemon sendiri sudah
      // di-gate, cukup untuk CE karena fitur Link Type sendiri sudah
      // dipaksa 'dedicated' di semua gateway CE, jadi peringatan ini
      // secara alami tidak akan pernah relevan buat mereka). ?>
<?php if ($isProLicensed && !empty($statusData['system_default_ordering_warning'])): ?>
  <div style="background:#fffbeb; color:#92400e; border:1px solid #fbbf24; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;">
    <i class="ti ti-alert-triangle" style="margin-right:6px;" aria-hidden="true"></i><strong>Tier ordering warning:</strong>
    <?= htmlspecialchars($statusData['system_default_ordering_warning']) ?>
  </div>
<?php endif; ?>
<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=gateways" class="ntp-tab<?= $activeTab === 'gateways' ? ' active' : '' ?>">Gateways</a>
  <a href="?tab=groups" class="ntp-tab<?= $activeTab === 'groups' ? ' active' : '' ?>">Gateway Groups</a>
  <a href="?tab=status" class="ntp-tab<?= $activeTab === 'status' ? ' active' : '' ?>">Status</a>
  <a href="?tab=events" class="ntp-tab<?= $activeTab === 'events' ? ' active' : '' ?>">Event Log</a>
  <a href="?tab=settings" class="ntp-tab<?= $activeTab === 'settings' ? ' active' : '' ?>">Settings</a>
</div>
<?php if ($activeTab === 'gateways'): ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">
      Gateways
      <?php if (!$isProLicensed): ?>
        <span class="ntp-badge ntp-badge-muted">CE: <?= count($gateways) ?>/<?= NTPSENSE_CE_MAX_GATEWAYS ?> used</span>
      <?php endif; ?>
    </div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      A Gateway is one uplink: an eligible interface (WAN1, or any OPT/LAGG/VLAN interface with its <strong>Role</strong>
      set to WAN on the <a href="/network.php">Network</a> page) paired with its next-hop IP. Health is checked every
      5 seconds via a ping bound to that interface specifically - 3 consecutive
      failures marks it Down, 3 consecutive successes marks it back Up.
    </p>
    <?php if (empty($gateways)): ?>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No gateways defined yet.</p>
    <?php else: ?>
      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead>
        <tr><th>Name</th><th>Interface</th><th>Gateway IP</th><th>Monitor IP</th><?php if ($isProLicensed): ?><th>Link Type</th><?php endif; ?><th>Enabled</th><th>Manage</th></tr>
        </thead>
        <tbody>
        <?php foreach ($gateways as $g): ?>
          <tr>
            <td><?= htmlspecialchars($g['name']) ?></td>
            <td><?= htmlspecialchars($g['interface']) ?></td>
            <td><?= htmlspecialchars($g['gateway_ip']) ?></td>
            <td><?= htmlspecialchars($g['monitor_ip'] !== '' ? $g['monitor_ip'] : '(same as gateway IP)') ?></td>
            <?php if ($isProLicensed): ?>
            <td>
              <?php if (($g['link_type'] ?? 'dedicated') === 'shared'): ?>
                <span class="ntp-badge ntp-badge-muted">Shared/NAT</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-success">Dedicated</span>
              <?php endif; ?>
            </td>
            <?php endif; ?>
            <td>
              <?php if ($g['enabled']): ?>
                <span class="ntp-badge ntp-badge-success">Enabled</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-muted">Disabled</span>
              <?php endif; ?>
            </td>
            <td>
              <details style="display:inline-block;">
                <summary style="cursor:pointer; display:inline-block; color:#374151; font-size:12px;">Edit</summary>
                <form method="post" style="margin:8px 0 0; display:flex; gap:8px; align-items:end; flex-wrap:wrap;">
                  <input type="hidden" name="form" value="gateway_update">
                  <input type="hidden" name="name" value="<?= htmlspecialchars($g['name']) ?>">
                  <div>
                    <label style="display:block; font-size:11px; color:#374151;">Gateway IP</label>
                    <input type="text" name="gateway_ip" value="<?= htmlspecialchars($g['gateway_ip']) ?>" required style="width:140px; font-size:12px;">
                  </div>
                  <div>
                    <label style="display:block; font-size:11px; color:#374151;">Monitor IP</label>
                    <input type="text" name="monitor_ip" value="<?= htmlspecialchars($g['monitor_ip']) ?>" placeholder="optional" style="width:140px; font-size:12px;">
                  </div>
                  <?php if ($isProLicensed): ?>
                  <div>
                    <label style="display:block; font-size:11px; color:#374151;">Link Type</label>
                    <select name="link_type" style="width:120px; font-size:12px;">
                      <option value="dedicated" <?= ($g['link_type'] ?? 'dedicated') === 'dedicated' ? 'selected' : '' ?>>Dedicated</option>
                      <option value="shared" <?= ($g['link_type'] ?? 'dedicated') === 'shared' ? 'selected' : '' ?>>Shared/NAT</option>
                    </select>
                  </div>
                  <?php endif; ?>
                  <label style="font-size:12px; display:flex; align-items:center; gap:4px;">
                    <input type="checkbox" name="enabled" <?= $g['enabled'] ? 'checked' : '' ?>> Enabled
                  </label>
                  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 12px; font-size:12px; border-radius:6px;">Save</button>
                </form>
              </details>
              <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete gateway &quot;<?= htmlspecialchars($g['name']) ?>&quot;?');">
                <input type="hidden" name="form" value="gateway_delete">
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
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">Add gateway</div>
    <?php if (!$isProLicensed && count($gateways) >= NTPSENSE_CE_MAX_GATEWAYS): ?>
      <div style="padding:14px;">
        <p style="font-size:12px; color:#92400e; background:#fffbeb; border:1px solid #fbbf24; border-radius:6px; padding:10px 14px; margin:0;">
          Community Edition (CE) is limited to <?= NTPSENSE_CE_MAX_GATEWAYS ?> gateways. Upgrade to
          <strong>NTPSense Pro</strong> for unlimited gateways - see
          <a href="https://ntpsense.com/compare.html" target="_blank" rel="noopener">ntpsense.com/compare.html</a>
          or upload a valid Pro license under System &gt; License.
        </p>
      </div>
    <?php elseif (empty($eligibleInterfaces)): ?>
      <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
        No eligible interface found. Go to <a href="/network.php">Network</a> and set an OPT/LAGG/VLAN interface's
        Role to <strong>WAN</strong> first (or use WAN1, which is always eligible).
      </p>
    <?php else: ?>
      <form method="post" style="padding:14px; display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
        <input type="hidden" name="form" value="gateway_create">
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
          <input type="text" name="name" placeholder="ISP1" required style="width:140px;">
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Interface</label>
          <select name="interface" style="width:140px;">
            <?php foreach ($eligibleInterfaces as $iface): ?>
              <option value="<?= htmlspecialchars($iface) ?>"><?= htmlspecialchars($iface) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Gateway IP (next-hop)</label>
          <input type="text" name="gateway_ip" placeholder="203.0.113.1" required style="width:160px;">
        </div>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Monitor IP <span style="color:#9ca3af; font-weight:normal;">(optional)</span></label>
          <input type="text" name="monitor_ip" placeholder="8.8.8.8" style="width:140px;">
        </div>
        <?php if ($isProLicensed): ?>
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Link Type</label>
          <select name="link_type" style="width:130px;">
            <option value="dedicated">Dedicated</option>
            <option value="shared">Shared/NAT</option>
          </select>
        </div>
        <?php endif; ?>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add gateway</button>
      </form>
      <p style="padding:0 14px 14px; font-size:11px; color:#9ca3af;">
        Monitor IP is useful when the ISP's next-hop router doesn't reply to ICMP (common) - point it at a reliable
        public IP instead (e.g. 8.8.8.8) without changing the actual next-hop used for routing.
        <?php if ($isProLicensed): ?>
        <strong>Link Type</strong> marks whether this uplink is a dedicated line (own public IP) or a shared/NAT
        link (e.g. wireless backup) - used to warn you if a shared link ends up with higher priority than a
        dedicated one in the System Default Gateway group, since that also controls which WAN Site Mesh VPN, NTP
        sync, DNS, and update checks use.
        <?php else: ?>
        <a href="https://ntpsense.com/compare.html" target="_blank" rel="noopener">NTPSense Pro</a> adds
        dedicated/shared link-type awareness with an automatic warning if a shared link ends up prioritized over
        a dedicated one.
        <?php endif; ?>
      </p>
    <?php endif; ?>
  </div>
<?php elseif ($activeTab === 'groups'): ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">About Gateway Groups</div>
    <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
      Members in the same <strong>Tier</strong> are load-balanced (round-robin, sticky per session) across each
      other automatically once more than one is Up; a lower tier number always takes priority over a higher one
      (failover). One gateway can only ever be alone in its tier to get pure failover behavior for that tier -
      put two or more in the same tier to load-balance between them. One group can be set as the
      <strong>System Default Gateway</strong> - this controls where NTPSense's own traffic (updates, DNS, NTP
      sync) goes, and only ever behaves as failover regardless of tier composition (self-originated traffic is
      never load-balanced, matching how every reference NGFW vendor treats it).
    </p>
  </div>
  <?php if (empty($groups)): ?>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No gateway groups defined yet.</p>
  <?php else: ?>
    <?php foreach ($groups as $grp): ?>
    <div class="ntp-card" style="margin-bottom:16px;">
      <div class="ntp-card-header">
        <?= htmlspecialchars($grp['name']) ?>
        <?php if ($grp['is_system_default']): ?>
          <span class="ntp-badge ntp-badge-success" style="margin-left:8px;">System Default Gateway</span>
        <?php endif; ?>
      </div>
      <div style="padding:12px 14px 0;">
        <table class="ntp-table" style="margin-bottom:10px;">
          <thead><tr><th>Gateway</th><th>Tier</th></tr></thead>
          <tbody>
          <?php foreach ($grp['members'] as $m): ?>
            <tr><td><?= htmlspecialchars($m['gateway_name']) ?></td><td><?= (int) $m['tier'] ?></td></tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <div style="padding:0 14px 14px;">
        <details>
          <summary style="cursor:pointer; color:#374151; font-size:12px;">Edit members</summary>
          <?php $rowsId = 'edit-member-rows-' . preg_replace('/[^a-zA-Z0-9_]/', '-', $grp['name']); ?>
          <form method="post" style="margin:10px 0 0;">
            <input type="hidden" name="form" value="group_update">
            <input type="hidden" name="name" value="<?= htmlspecialchars($grp['name']) ?>">
            <input type="hidden" name="routing_mode" value="<?= htmlspecialchars($grp['routing_mode'] ?? 'static') ?>">
            <input type="hidden" name="sla_max_latency_ms" value="<?= htmlspecialchars((string) ($grp['sla_max_latency_ms'] ?? '')) ?>">
            <input type="hidden" name="sla_max_jitter_ms" value="<?= htmlspecialchars((string) ($grp['sla_max_jitter_ms'] ?? '')) ?>">
            <input type="hidden" name="sla_max_packet_loss_pct" value="<?= htmlspecialchars((string) ($grp['sla_max_packet_loss_pct'] ?? '')) ?>">
            <div id="<?= htmlspecialchars($rowsId) ?>">
              <?php foreach ($grp['members'] as $m): ?>
                <div class="member-row" style="display:flex; gap:8px; margin-bottom:6px;">
                  <select name="member_gateway[]" style="width:180px;">
                    <option value="">- select gateway -</option>
                    <?php foreach ($gateways as $g): ?>
                      <option value="<?= htmlspecialchars($g['name']) ?>" <?= $g['name'] === $m['gateway_name'] ? 'selected' : '' ?>><?= htmlspecialchars($g['name']) ?></option>
                    <?php endforeach; ?>
                  </select>
                  <input type="number" name="member_tier[]" placeholder="Tier" min="1" max="10" value="<?= (int) $m['tier'] ?>" style="width:80px;">
                </div>
              <?php endforeach; ?>
            </div>
            <button type="button" onclick="var rows=document.getElementById('<?= htmlspecialchars($rowsId) ?>'); var row=rows.querySelector('.member-row').cloneNode(true); row.querySelectorAll('select,input').forEach(function(el){ if(el.tagName==='SELECT'){el.value='';} else {el.value='1';} }); rows.appendChild(row);" style="background:none; border:1px dashed #d1d5db; padding:5px 10px; font-size:11px; border-radius:6px; cursor:pointer; margin:0 0 10px;">+ Add another member</button>
            <div>
              <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 14px; font-size:12px; border-radius:6px;">Save members</button>
            </div>
          </form>
        </details>
      </div>
      <div style="padding:0 14px 14px; display:flex; gap:10px; flex-wrap:wrap;">
        <?php if ($grp['is_system_default']): ?>
          <form method="post" style="margin:0;">
            <input type="hidden" name="form" value="group_clear_default">
            <button type="submit" style="background:none; border:1px solid #d1d5db; padding:6px 12px; font-size:12px; border-radius:6px; cursor:pointer;">Unset as System Default</button>
          </form>
        <?php else: ?>
          <form method="post" style="margin:0;" onsubmit="return confirm('Set &quot;<?= htmlspecialchars($grp['name']) ?>&quot; as the System Default Gateway? This controls where NTPSense\'s own traffic exits.');">
            <input type="hidden" name="form" value="group_set_default">
            <input type="hidden" name="name" value="<?= htmlspecialchars($grp['name']) ?>">
            <button type="submit" style="background:none; border:1px solid #d1d5db; padding:6px 12px; font-size:12px; border-radius:6px; cursor:pointer;">Set as System Default</button>
          </form>
        <?php endif; ?>
        <form method="post" style="margin:0;" onsubmit="return confirm('Delete group &quot;<?= htmlspecialchars($grp['name']) ?>&quot;?');">
          <input type="hidden" name="form" value="group_delete">
          <input type="hidden" name="name" value="<?= htmlspecialchars($grp['name']) ?>">
          <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; font-size:12px; padding:0;">Delete this group</button>
        </form>
      </div>
    </div>
    <?php endforeach; ?>
  <?php endif; ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Add group</div>
    <?php if (empty($gateways)): ?>
      <p style="padding:12px 14px; font-size:12px; color:#6b7280;">Add at least one gateway on the Gateways tab first.</p>
    <?php else: ?>
      <form method="post" style="padding:14px;">
        <input type="hidden" name="form" value="group_create">
        <div style="margin-bottom:12px;">
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Group name</label>
          <input type="text" name="name" placeholder="WAN_Failover" required style="width:220px;">
        </div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:6px;">Members</label>
        <div id="member-rows">
          <div class="member-row" style="display:flex; gap:8px; margin-bottom:6px;">
            <select name="member_gateway[]" style="width:180px;">
              <option value="">- select gateway -</option>
              <?php foreach ($gateways as $g): ?>
                <option value="<?= htmlspecialchars($g['name']) ?>"><?= htmlspecialchars($g['name']) ?></option>
              <?php endforeach; ?>
            </select>
            <input type="number" name="member_tier[]" placeholder="Tier" min="1" max="10" value="1" style="width:80px;">
          </div>
        </div>
        <button type="button" onclick="var row=document.querySelector('.member-row').cloneNode(true); row.querySelectorAll('select,input').forEach(function(el){ if(el.tagName==='SELECT'){el.value='';} else {el.value='1';} }); document.getElementById('member-rows').appendChild(row);" style="background:none; border:1px dashed #d1d5db; padding:6px 12px; font-size:12px; border-radius:6px; cursor:pointer; margin-bottom:12px;">+ Add another member</button>
        <p style="font-size:11px; color:#9ca3af; margin:0 0 12px;">
          Same tier number on two or more members = load-balanced between them. Different tier numbers = failover
          priority order (lowest tier first).
        </p>
        <div>
          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create group</button>
        </div>
      </form>
    <?php endif; ?>
  </div>
<?php elseif ($activeTab === 'status'): ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">Gateways</div>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead><tr><th>Name</th><th>Interface</th><?php if ($isProLicensed): ?><th>Link Type</th><?php endif; ?><th>Status</th><th>Last checked</th></tr></thead>
      <tbody>
      <?php if (empty($statusData['gateways'])): ?>
        <tr><td colspan="<?= $isProLicensed ? 5 : 4 ?>" style="color:#6b7280;">No gateways defined.</td></tr>
      <?php endif; ?>
      <?php foreach (($statusData['gateways'] ?? []) as $s): ?>
        <tr>
          <td><?= htmlspecialchars($s['name']) ?></td>
          <td><?= htmlspecialchars($s['interface']) ?></td>
          <?php if ($isProLicensed): ?>
          <td>
            <?php if (($s['link_type'] ?? 'dedicated') === 'shared'): ?>
              <span class="ntp-badge ntp-badge-muted">Shared/NAT</span>
            <?php else: ?>
              <span class="ntp-badge ntp-badge-success">Dedicated</span>
            <?php endif; ?>
          </td>
          <?php endif; ?>
          <td>
            <?php if (!$s['enabled']): ?>
              <span class="ntp-badge ntp-badge-muted">Disabled</span>
            <?php elseif ($s['up']): ?>
              <span class="ntp-badge ntp-badge-success">Up</span>
            <?php else: ?>
              <span class="ntp-badge ntp-badge-danger">Down</span>
            <?php endif; ?>
          </td>
          <td style="font-size:12px; color:#6b7280;"><?= $s['last_checked_ts'] ? htmlspecialchars(date('Y-m-d H:i:s', (int) $s['last_checked_ts'])) : 'never' ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
  <div class="ntp-card">
    <div class="ntp-card-header">Gateway Groups</div>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead><tr><th>Group</th><th>Mode right now</th><th>Active gateway(s)</th><th>System Default</th></tr></thead>
      <tbody>
      <?php if (empty($statusData['groups'])): ?>
        <tr><td colspan="4" style="color:#6b7280;">No groups defined.</td></tr>
      <?php endif; ?>
      <?php foreach (($statusData['groups'] ?? []) as $s): ?>
        <tr>
          <td><?= htmlspecialchars($s['name']) ?></td>
          <td>
            <?php if ($s['mode'] === 'load_balance'): ?>
              <span class="ntp-badge ntp-badge-success">Load balancing</span>
            <?php else: ?>
              <span class="ntp-badge ntp-badge-muted">Failover</span>
            <?php endif; ?>
          </td>
          <td><?= empty($s['active_gateways']) ? '<span style="color:#b3261e;">none reachable</span>' : htmlspecialchars(implode(', ', $s['active_gateways'])) ?></td>
          <td><?= $s['is_system_default'] ? '✓' : '—' ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
<?php elseif ($activeTab === 'events'): ?>
  <div class="ntp-card">
    <div class="ntp-card-header">Multi-WAN Event Log <span style="font-weight:normal; color:#9ca3af; font-size:12px;">(/var/log/ntpsense-multiwan.log)</span></div>
    <div style="padding:14px; font-family:monospace; font-size:12px; max-height:60vh; overflow-y:auto; white-space:pre-wrap;"><?php
      if (empty($eventLines)) {
          echo '<span style="color:#6b7280; font-family:inherit;">No events logged yet.</span>';
      } else {
          echo implode('<br>', array_map('htmlspecialchars', array_reverse($eventLines)));
      }
    ?></div>
  </div>
<?php elseif ($activeTab === 'settings'): ?>
  <div class="ntp-card" style="margin-bottom:16px;">
    <div class="ntp-card-header">Health-Check Tuning</div>
    <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
      Controls how the background monitor decides a gateway is Down (or recovered) - applies to every gateway,
      not per-gateway. Takes effect on the next monitoring cycle automatically, no daemon restart needed.
    </p>
    <form method="post" style="padding:14px; display:flex; gap:16px; align-items:flex-end; flex-wrap:wrap;">
      <input type="hidden" name="form" value="settings_update">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Check interval (seconds)</label>
        <input type="number" name="interval_secs" value="<?= htmlspecialchars((string) $healthCheckSettings['interval_secs']) ?>" min="1" max="60" required style="width:100px;">
        <p style="font-size:11px; color:#9ca3af; margin:4px 0 0;">How often each gateway is pinged</p>
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Fail threshold</label>
        <input type="number" name="fail_threshold" value="<?= htmlspecialchars((string) $healthCheckSettings['fail_threshold']) ?>" min="1" max="10" required style="width:100px;">
        <p style="font-size:11px; color:#9ca3af; margin:4px 0 0;">Consecutive failed pings before marking Down</p>
      </div>
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Recover threshold</label>
        <input type="number" name="recover_threshold" value="<?= htmlspecialchars((string) $healthCheckSettings['recover_threshold']) ?>" min="1" max="10" required style="width:100px;">
        <p style="font-size:11px; color:#9ca3af; margin:4px 0 0;">Consecutive successful pings before marking Up again</p>
      </div>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
    </form>
    <p style="padding:0 14px 14px; font-size:12px; color:#374151;">
      With the current settings, worst-case detection time is roughly
      <strong><?= (int) $healthCheckSettings['interval_secs'] * (int) $healthCheckSettings['fail_threshold'] ?>-<?= (int) ($healthCheckSettings['interval_secs'] * $healthCheckSettings['fail_threshold'] * 1.8) ?> seconds</strong>
      (interval × threshold, plus real-world overhead from the ping calls themselves and cycle-timing jitter - this
      product's own testing measured actual detection closer to the higher end of that range, not the clean
      mathematical minimum).
    </p>
  </div>
  <style>
    .ntp-card > summary.ntp-card-header::-webkit-details-marker { display: none; }
    .ntp-card > summary.ntp-card-header .ti-chevron-down { transition: transform 0.15s ease; }
    details[open] > summary.ntp-card-header .ti-chevron-down { transform: rotate(180deg); }
  </style>
  <details class="ntp-card">
    <summary class="ntp-card-header" style="cursor:pointer; list-style:none; display:flex; align-items:center; gap:6px;">
      <i class="ti ti-info-circle" style="font-size:14px;" aria-hidden="true"></i>
      Best Practice &amp; Trade-off Notes
      <i class="ti ti-chevron-down" style="font-size:14px; margin-left:auto;" aria-hidden="true"></i>
    </summary>
    <div style="padding:14px; font-size:12px; color:#374151; line-height:1.7;">
      <p>
        This is the same fundamental trade-off as Cisco IP SLA or FortiGate/pfSense dead-gateway-detection
        tuning: <strong>faster detection always costs sensitivity</strong>. There is no setting that is both
        fast and immune to false positives - picking numbers here means picking which failure mode you'd rather
        have.
      </p>
      <table class="ntp-table" style="margin:10px 0;">
        <thead><tr><th>Profile</th><th>Interval / Fail / Recover</th><th>Detection time</th><th>Best for</th><th>Risk</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Conservative</strong></td>
            <td>10s / 5 / 5</td>
            <td>~50-90s</td>
            <td>Flaky/high-latency links (satellite, congested DSL) where occasional packet loss is normal</td>
            <td>Slow to react to a real outage</td>
          </tr>
          <tr>
            <td><strong>Balanced (default)</strong></td>
            <td>5s / 3 / 3</td>
            <td>~15-30s</td>
            <td>Typical SOHO/branch office with two reasonably stable ISPs - this is what was tested end-to-end on this product</td>
            <td>—</td>
          </tr>
          <tr>
            <td><strong>Aggressive</strong></td>
            <td>2s / 2 / 3</td>
            <td>~4-8s</td>
            <td>Latency-sensitive traffic (VoIP, trading, video conferencing) where every second of outage is felt directly</td>
            <td>A single momentary blip (Wi-Fi backhaul hiccup, brief ISP jitter) can trigger an unnecessary failover</td>
          </tr>
        </tbody>
      </table>
      <p>
        <strong>Why Recover threshold matters just as much as Fail threshold:</strong> a gateway that's actually
        unstable (flapping up and down) causes <em>more</em> disruption if it's allowed to rejoin the routing
        pool too eagerly - every flap forces another pf state flush and rule reload, briefly interrupting active
        connections again. Keeping Recover ≥ Fail is a reasonable default; don't set Recover to 1 just to "speed
        up" recovery unless the link is genuinely known to be stable.
      </p>
      <p>
        <strong>Why not go faster than a couple of seconds?</strong> Below roughly 1-2 second intervals, the
        overhead of spawning a new <code>ping</code> process per gateway per cycle starts to matter, and normal
        internet links routinely lose 1-2% of ICMP packets under completely healthy conditions - an interval
        that tight increases the odds an unlucky single dropped ping (not a real outage) starts counting toward
        the fail threshold.
      </p>
      <p style="margin-bottom:0;">
        There is no per-gateway override in this version - if one ISP is known to be flakier than the other,
        the whole-system setting has to accommodate the worse of the two. Consider this a deliberate simplicity
        trade-off; a future revision could split this per-gateway if a real need for it comes up.
      </p>
    </div>
  </details>
<?php endif; ?>
<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
