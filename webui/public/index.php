<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
Auth::requireLogin();

$configd = new NtpsenseConfigd();
$configdError = null;
$dashInfo = null;
$zones = null;
$vpnStatus = null;
$ipsecStatus = null;

try {
    $dashInfo = $configd->call('system.get_dashboard_info');
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
try {
    $zones = $configd->call('network.zones');
} catch (NtpsenseConfigdException $e) {
    // Interfaces widget menangani $zones null secara terpisah di bawah -
    // tidak menimpa $configdError supaya pesan error System Information
    // (kalau ada) tidak tertutup oleh ini.
}
try {
    $vpnStatus = $configd->call('vpn.get_config');
} catch (NtpsenseConfigdException $e) {
    // Non-fatal - baris wg0 di Interfaces cuma tidak muncul.
}
try {
    $ipsecStatus = $configd->call('ipsec.get_config');
} catch (NtpsenseConfigdException $e) {
    // Non-fatal - baris enc0 di Interfaces cuma tidak muncul.
}

/**
 * Format bytes jadi string human-readable (mis. "1.9G", "83M") - pola
 * yang sama seperti tampilan 'df -h'/'top' sendiri, supaya konsisten
 * dengan angka mentah yang sudah familiar buat admin FreeBSD.
 */
function formatBytes(int $bytes): string
{
    $units = ['B', 'K', 'M', 'G', 'T'];
    $i = 0;
    $val = (float) $bytes;
    while ($val >= 1024 && $i < count($units) - 1) {
        $val /= 1024;
        $i++;
    }
    return round($val, 1) . $units[$i];
}

$pageTitle = 'Dashboard';
$activeNavItem = 'dashboard';
require __DIR__ . '/../templates/layout_header.php';
?>

<?php if ($configdError): ?>
  <div class="ntp-alert-error" id="dash-global-error">
    Unable to fetch data from ntpsense-configd: <?= htmlspecialchars($configdError) ?>
  </div>
<?php endif; ?>

<div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:start;">

  <div class="ntp-card">
    <div class="ntp-card-header" style="display:flex; align-items:center; justify-content:space-between;">
      <span>System Information</span>
      <button type="button" class="ntp-dash-refresh-btn" title="Refresh now" style="background:none; border:none; cursor:pointer; color:#6b7280; padding:2px;">
        <i class="ti ti-refresh" style="font-size:15px;" aria-hidden="true"></i>
      </button>
    </div>
    <?php if ($dashInfo): ?>
      <table class="ntp-table">
        <tr><td style="width:160px; color:#6b7280;">Hostname</td><td id="dash-hostname"><?= htmlspecialchars($dashInfo['hostname']) ?></td></tr>
        <tr><td style="color:#6b7280;">Version</td><td id="dash-version">FreeBSD <?= htmlspecialchars($dashInfo['freebsd_version']) ?></td></tr>
        <tr><td style="color:#6b7280;">Uptime</td><td id="dash-uptime"><?= htmlspecialchars($dashInfo['uptime']) ?></td></tr>
        <tr>
          <td style="color:#6b7280;">Load average</td>
          <td id="dash-loadavg">
            <?php if ($dashInfo['load_avg']): ?>
              <?= implode(', ', array_map(fn($n) => number_format((float) $n, 2), $dashInfo['load_avg'])) ?>
              <span style="color:#9ca3af; font-size:11px;">(1, 5, 15 min)</span>
            <?php else: ?>
              <span style="color:#9ca3af;">—</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td style="color:#6b7280;">CPU</td>
          <td id="dash-cpu-model">
            <?php if (!empty($dashInfo['cpu_model'])): ?>
              <?= htmlspecialchars($dashInfo['cpu_model']) ?>
              <?php if (!empty($dashInfo['cpu_cores'])): ?>
                <span style="color:#9ca3af; font-size:11px;">(<?= (int) $dashInfo['cpu_cores'] ?> core<?= (int) $dashInfo['cpu_cores'] > 1 ? 's' : '' ?>)</span>
              <?php endif; ?>
            <?php else: ?>
              <span style="color:#9ca3af;">—</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td style="color:#6b7280; vertical-align:top; padding-top:10px;">Per-core load</td>
          <td id="dash-cpu-percore">
            <?php if (!empty($dashInfo['cpu_per_core'])): ?>
              <div style="display:flex; flex-wrap:wrap; gap:8px;">
                <?php foreach ($dashInfo['cpu_per_core'] as $core): ?>
                  <div style="display:flex; align-items:center; gap:6px; font-size:11px;">
                    <span style="color:#6b7280; width:38px;">Core <?= (int) $core['core'] ?></span>
                    <div style="background:#e5e7eb; border-radius:4px; height:8px; width:60px; overflow:hidden;">
                      <div style="background:#c74b00; height:100%; width:<?= min(100, (float) $core['usage_pct']) ?>%;"></div>
                    </div>
                    <span style="width:32px;"><?= number_format((float) $core['usage_pct'], 0) ?>%</span>
                  </div>
                <?php endforeach; ?>
              </div>
            <?php else: ?>
              <span style="color:#9ca3af;">—</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td style="color:#6b7280;">Memory usage</td>
          <td id="dash-mem">
            <?php if ($dashInfo['memory']): ?>
              <?php
              $memUsed = (int) $dashInfo['memory']['used_bytes'];
              $memTotal = (int) $dashInfo['memory']['total_bytes'];
              $memPct = $memTotal > 0 ? ($memUsed / $memTotal * 100) : 0;
              ?>
              <div style="background:#e5e7eb; border-radius:4px; height:8px; width:180px; display:inline-block; vertical-align:middle; overflow:hidden;">
                <div id="dash-mem-bar" style="background:#c74b00; height:100%; width:<?= min(100, $memPct) ?>%;"></div>
              </div>
              <span id="dash-mem-text" style="margin-left:8px;"><?= number_format($memPct, 1) ?>% (<?= formatBytes($memUsed) ?> of <?= formatBytes($memTotal) ?>)</span>
            <?php else: ?>
              <span style="color:#9ca3af;">—</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td style="color:#6b7280;">Swap usage</td>
          <td id="dash-swap">
            <?php if ($dashInfo['swap']): ?>
              <?php
              $swapUsed = (int) $dashInfo['swap']['used_bytes'];
              $swapTotal = (int) $dashInfo['swap']['total_bytes'];
              $swapPct = $swapTotal > 0 ? ($swapUsed / $swapTotal * 100) : 0;
              ?>
              <div style="background:#e5e7eb; border-radius:4px; height:8px; width:180px; display:inline-block; vertical-align:middle; overflow:hidden;">
                <div id="dash-swap-bar" style="background:#c74b00; height:100%; width:<?= min(100, $swapPct) ?>%;"></div>
              </div>
              <span id="dash-swap-text" style="margin-left:8px;"><?= number_format($swapPct, 1) ?>% (<?= formatBytes($swapUsed) ?> of <?= formatBytes($swapTotal) ?>)</span>
            <?php else: ?>
              <span style="color:#9ca3af;">—</span>
            <?php endif; ?>
          </td>
        </tr>
      </table>
      <p style="padding:0 14px 12px; font-size:11px; color:#9ca3af;">
        Memory usage counts Active + Wired + Laundry as used (per FreeBSD's own <code>top</code> breakdown) — Inactive/Buffer/Free pages are reclaimable on demand and not counted as "used", unlike a simpler free-memory-only calculation would suggest.
      </p>
    <?php else: ?>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">Unable to fetch system information right now.</p>
    <?php endif; ?>
  </div>

  <div class="ntp-card">
    <div class="ntp-card-header" style="display:flex; align-items:center; justify-content:space-between;">
      <span>Disks</span>
      <button type="button" class="ntp-dash-refresh-btn" title="Refresh now" style="background:none; border:none; cursor:pointer; color:#6b7280; padding:2px;">
        <i class="ti ti-refresh" style="font-size:15px;" aria-hidden="true"></i>
      </button>
    </div>
    <?php if ($dashInfo && !empty($dashInfo['disks'])): ?>
      <table class="ntp-table">
        <tr><th>Mount</th><th>Used</th><th>Size</th><th>Usage</th></tr>
        <tbody id="dash-disks-tbody">
        <?php foreach ($dashInfo['disks'] as $disk): ?>
          <?php $pctNum = (float) rtrim($disk['pct'], '%'); ?>
          <tr>
            <td><?= htmlspecialchars($disk['mount']) ?></td>
            <td><?= htmlspecialchars($disk['used']) ?></td>
            <td><?= htmlspecialchars($disk['size']) ?></td>
            <td>
              <div style="background:#e5e7eb; border-radius:4px; height:8px; width:100px; display:inline-block; vertical-align:middle; overflow:hidden;">
                <div style="background:<?= $pctNum > 85 ? '#b3261e' : '#c74b00' ?>; height:100%; width:<?= min(100, $pctNum) ?>%;"></div>
              </div>
              <span style="margin-left:8px; font-size:12px;"><?= htmlspecialchars($disk['pct']) ?></span>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php else: ?>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;" id="dash-disks-empty">Unable to fetch disk information right now.</p>
    <?php endif; ?>
  </div>

  <div class="ntp-card" style="grid-column:1 / -1;">
    <div class="ntp-card-header" style="display:flex; align-items:center; justify-content:space-between;">
      <span>Interfaces</span>
      <button type="button" class="ntp-dash-refresh-btn" title="Refresh now" style="background:none; border:none; cursor:pointer; color:#6b7280; padding:2px;">
        <i class="ti ti-refresh" style="font-size:15px;" aria-hidden="true"></i>
      </button>
    </div>
    <?php if ($zones): ?>
      <table class="ntp-table">
        <tr><th>Zone</th><th>Interface</th><th>Type</th><th>IP</th><th>Status</th></tr>
        <tbody id="dash-interfaces-tbody">
        <?php
        $interfaceRows = [
            ['label' => 'MGMT', 'data' => $zones['mgmt'] ?? null],
            ['label' => 'LAN1', 'data' => $zones['lan1'] ?? null],
            ['label' => 'WAN1', 'data' => $zones['wan1'] ?? null],
        ];
        foreach (($zones['opt'] ?? []) as $i => $opt) {
            $interfaceRows[] = ['label' => 'OPT' . ($i + 1), 'data' => $opt];
        }
        ?>
        <?php foreach ($interfaceRows as $row): ?>
          <?php $d = $row['data']; ?>
          <tr>
            <td><?= htmlspecialchars($row['label']) ?></td>
            <td><?= htmlspecialchars($d['interface'] ?? '—') ?></td>
            <td>Physical</td>
            <td><?= htmlspecialchars($d['ip'] ?? '—') ?></td>
            <td>
              <?php if (empty($d['enabled'])): ?>
                <span class="ntp-badge ntp-badge-warning">Disabled</span>
              <?php elseif (($d['link_up'] ?? null) === false): ?>
                <span class="ntp-badge ntp-badge-warning">Down</span>
              <?php elseif (!empty($d['ip'])): ?>
                <span class="ntp-badge ntp-badge-success">Active</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-muted">Unknown</span>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        <?php if ($vpnStatus && !empty($vpnStatus['installed'])): ?>
          <tr>
            <td>VPN</td>
            <td>wg0</td>
            <td>VPN Tunnel (WireGuard)</td>
            <td><?= htmlspecialchars($vpnStatus['config']['vpn_subnet'] ?? '—') ?></td>
            <td>
              <?php if (!empty($vpnStatus['config']['enabled'])): ?>
                <span class="ntp-badge ntp-badge-success">Enabled</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">Disabled</span>
              <?php endif; ?>
            </td>
          </tr>
        <?php endif; ?>
        <?php if ($ipsecStatus && !empty($ipsecStatus['installed'])): ?>
          <?php
          $ipsecTunnels = $ipsecStatus['tunnels'] ?? [];
          $anyEnabled = false;
          foreach ($ipsecTunnels as $t) {
              if (!empty($t['enabled'])) {
                  $anyEnabled = true;
                  break;
              }
          }
          ?>
          <tr>
            <td>VPN</td>
            <td>enc0</td>
            <td>VPN Tunnel (IPsec)</td>
            <td><?= count($ipsecTunnels) ?> tunnel(s)</td>
            <td>
              <?php if (empty($ipsecTunnels)): ?>
                <span class="ntp-badge ntp-badge-muted">No tunnels</span>
              <?php elseif ($anyEnabled): ?>
                <span class="ntp-badge ntp-badge-success">Enabled</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">Disabled</span>
              <?php endif; ?>
            </td>
          </tr>
        <?php endif; ?>
        </tbody>
      </table>
      <p style="padding:12px 14px 0; font-size:11px; color:#9ca3af;">
        For per-interface configuration, see <a href="/network.php">Network</a>. For VPN tunnel details, see <a href="/vpn.php">VPN</a> and <a href="/ipsec.php">IPsec VPN</a>.
      </p>
    <?php else: ?>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;" id="dash-interfaces-empty">Unable to fetch interface data right now.</p>
    <?php endif; ?>
  </div>

  <div class="ntp-card" style="grid-column:1 / -1;">
    <div class="ntp-card-header">
      <span>Traffic Graphs</span>
    </div>
    <?php
    // Peta nama interface netstat (mis. "em1") -> label ramah (mis.
    // "LAN1") - dipakai checkbox pemilih DAN judul tiap grafik. Sumber
    // SAMA dengan widget Interfaces di atas ($zones/$vpnStatus/
    // $ipsecStatus), bukan daftar terpisah - satu sumber kebenaran.
    // Default tercentang: WAN1 + LAN1 (diminta eksplisit) - sisanya
    // admin pilih sendiri.
    $trafficIfaceMap = [];
    $defaultChecked = [];
    if ($zones) {
        if (!empty($zones['wan1']['interface'])) {
            $trafficIfaceMap[$zones['wan1']['interface']] = 'WAN1';
            $defaultChecked[] = $zones['wan1']['interface'];
        }
        if (!empty($zones['lan1']['interface'])) {
            $trafficIfaceMap[$zones['lan1']['interface']] = 'LAN1';
            $defaultChecked[] = $zones['lan1']['interface'];
        }
        if (!empty($zones['mgmt']['interface'])) {
            $trafficIfaceMap[$zones['mgmt']['interface']] = 'MGMT';
        }
        foreach (($zones['opt'] ?? []) as $i => $opt) {
            if (!empty($opt['interface'])) {
                $trafficIfaceMap[$opt['interface']] = 'OPT' . ($i + 1);
            }
        }
    }
    if ($vpnStatus && !empty($vpnStatus['installed'])) {
        $trafficIfaceMap['wg0'] = 'wg0 (VPN)';
    }
    if ($ipsecStatus && !empty($ipsecStatus['installed'])) {
        $trafficIfaceMap['enc0'] = 'enc0 (IPsec)';
    }
    ?>
    <?php if (!empty($trafficIfaceMap)): ?>
      <div style="padding:12px 14px; border-bottom:1px solid #e5e7eb; display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
        <span style="font-size:12px; color:#6b7280;">Show:</span>
        <?php foreach ($trafficIfaceMap as $ifaceName => $label): ?>
          <label style="font-size:13px; display:flex; align-items:center; gap:5px; cursor:pointer;">
            <input type="checkbox" class="ntp-traffic-checkbox" value="<?= htmlspecialchars($ifaceName) ?>" data-label="<?= htmlspecialchars($label) ?>" <?= in_array($ifaceName, $defaultChecked, true) ? 'checked' : '' ?>>
            <?= htmlspecialchars($label) ?>
          </label>
        <?php endforeach; ?>
        <span style="margin-left:auto; display:flex; align-items:center; gap:6px;">
          <span style="display:inline-block; width:10px; height:10px; background:#2563eb; border-radius:2px;"></span>
          <span style="font-size:11px; color:#6b7280;">In</span>
          <span style="display:inline-block; width:10px; height:10px; background:#c74b00; border-radius:2px; margin-left:8px;"></span>
          <span style="font-size:11px; color:#6b7280;">Out</span>
        </span>
      </div>
      <div id="dash-traffic-graphs" style="padding:14px;"></div>
    <?php else: ?>
      <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No interfaces available to graph right now.</p>
    <?php endif; ?>
  </div>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
(function () {
    'use strict';

    var REFRESH_INTERVAL_MS = 10000; // 10 detik

    function escapeHtml(s) {
        var d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    function formatBytesJs(bytes) {
        var units = ['B', 'K', 'M', 'G', 'T'];
        var i = 0;
        var val = bytes;
        while (val >= 1024 && i < units.length - 1) {
            val /= 1024;
            i++;
        }
        return Math.round(val * 10) / 10 + units[i];
    }

    function badge(cls, text) {
        return '<span class="ntp-badge ntp-badge-' + cls + '">' + escapeHtml(text) + '</span>';
    }

    function renderSystemInfo(dashInfo) {
        if (!dashInfo) {
            return;
        }
        var setText = function (id, text) {
            var el = document.getElementById(id);
            if (el) {
                el.textContent = text;
            }
        };
        setText('dash-hostname', dashInfo.hostname);
        setText('dash-version', 'FreeBSD ' + dashInfo.freebsd_version);
        setText('dash-uptime', dashInfo.uptime);

        var loadEl = document.getElementById('dash-loadavg');
        if (loadEl) {
            if (dashInfo.load_avg) {
                loadEl.innerHTML = dashInfo.load_avg.map(function (n) { return n.toFixed(2); }).join(', ') +
                    ' <span style="color:#9ca3af; font-size:11px;">(1, 5, 15 min)</span>';
            } else {
                loadEl.innerHTML = '<span style="color:#9ca3af;">—</span>';
            }
        }

        var cpuModelEl = document.getElementById('dash-cpu-model');
        if (cpuModelEl) {
            if (dashInfo.cpu_model) {
                var coresText = dashInfo.cpu_cores
                    ? ' <span style="color:#9ca3af; font-size:11px;">(' + dashInfo.cpu_cores + ' core' + (dashInfo.cpu_cores > 1 ? 's' : '') + ')</span>'
                    : '';
                cpuModelEl.innerHTML = escapeHtml(dashInfo.cpu_model) + coresText;
            } else {
                cpuModelEl.innerHTML = '<span style="color:#9ca3af;">—</span>';
            }
        }

        var percoreEl = document.getElementById('dash-cpu-percore');
        if (percoreEl) {
            if (dashInfo.cpu_per_core && dashInfo.cpu_per_core.length > 0) {
                var percoreHtml = '<div style="display:flex; flex-wrap:wrap; gap:8px;">';
                dashInfo.cpu_per_core.forEach(function (core) {
                    var corePct = Math.min(100, core.usage_pct);
                    percoreHtml += '<div style="display:flex; align-items:center; gap:6px; font-size:11px;">' +
                        '<span style="color:#6b7280; width:38px;">Core ' + core.core + '</span>' +
                        '<div style="background:#e5e7eb; border-radius:4px; height:8px; width:60px; overflow:hidden;">' +
                        '<div style="background:#c74b00; height:100%; width:' + corePct + '%;"></div>' +
                        '</div>' +
                        '<span style="width:32px;">' + Math.round(core.usage_pct) + '%</span>' +
                        '</div>';
                });
                percoreHtml += '</div>';
                percoreEl.innerHTML = percoreHtml;
            } else {
                percoreEl.innerHTML = '<span style="color:#9ca3af;">—</span>';
            }
        }

        if (dashInfo.memory) {
            var used = dashInfo.memory.used_bytes;
            var total = dashInfo.memory.total_bytes;
            var pct = total > 0 ? (used / total * 100) : 0;
            var memBar = document.getElementById('dash-mem-bar');
            var memText = document.getElementById('dash-mem-text');
            if (memBar) {
                memBar.style.width = Math.min(100, pct) + '%';
            }
            if (memText) {
                memText.textContent = pct.toFixed(1) + '% (' + formatBytesJs(used) + ' of ' + formatBytesJs(total) + ')';
            }
        }

        if (dashInfo.swap) {
            var swapUsed = dashInfo.swap.used_bytes;
            var swapTotal = dashInfo.swap.total_bytes;
            var swapPct = swapTotal > 0 ? (swapUsed / swapTotal * 100) : 0;
            var swapBar = document.getElementById('dash-swap-bar');
            var swapText = document.getElementById('dash-swap-text');
            if (swapBar) {
                swapBar.style.width = Math.min(100, swapPct) + '%';
            }
            if (swapText) {
                swapText.textContent = swapPct.toFixed(1) + '% (' + formatBytesJs(swapUsed) + ' of ' + formatBytesJs(swapTotal) + ')';
            }
        }
    }

    function renderDisks(dashInfo) {
        var tbody = document.getElementById('dash-disks-tbody');
        if (!tbody || !dashInfo || !dashInfo.disks) {
            return;
        }
        var html = '';
        dashInfo.disks.forEach(function (disk) {
            var pctNum = parseFloat(disk.pct) || 0;
            var barColor = pctNum > 85 ? '#b3261e' : '#c74b00';
            html += '<tr>' +
                '<td>' + escapeHtml(disk.mount) + '</td>' +
                '<td>' + escapeHtml(disk.used) + '</td>' +
                '<td>' + escapeHtml(disk.size) + '</td>' +
                '<td>' +
                '<div style="background:#e5e7eb; border-radius:4px; height:8px; width:100px; display:inline-block; vertical-align:middle; overflow:hidden;">' +
                '<div style="background:' + barColor + '; height:100%; width:' + Math.min(100, pctNum) + '%;"></div>' +
                '</div>' +
                '<span style="margin-left:8px; font-size:12px;">' + escapeHtml(disk.pct) + '</span>' +
                '</td></tr>';
        });
        tbody.innerHTML = html;
    }

    function interfaceStatusBadge(d) {
        if (!d || !d.enabled) {
            return badge('warning', 'Disabled');
        }
        if (d.link_up === false) {
            return badge('warning', 'Down');
        }
        if (d.ip) {
            return badge('success', 'Active');
        }
        return badge('muted', 'Unknown');
    }

    function renderInterfaces(zones, vpnStatus, ipsecStatus) {
        var tbody = document.getElementById('dash-interfaces-tbody');
        if (!tbody || !zones) {
            return;
        }
        var rows = [
            { label: 'MGMT', data: zones.mgmt },
            { label: 'LAN1', data: zones.lan1 },
            { label: 'WAN1', data: zones.wan1 },
        ];
        (zones.opt || []).forEach(function (opt, i) {
            rows.push({ label: 'OPT' + (i + 1), data: opt });
        });

        var html = '';
        rows.forEach(function (row) {
            var d = row.data || {};
            html += '<tr>' +
                '<td>' + escapeHtml(row.label) + '</td>' +
                '<td>' + escapeHtml(d.interface || '—') + '</td>' +
                '<td>Physical</td>' +
                '<td>' + escapeHtml(d.ip || '—') + '</td>' +
                '<td>' + interfaceStatusBadge(d) + '</td>' +
                '</tr>';
        });

        if (vpnStatus && vpnStatus.installed) {
            var wgEnabled = vpnStatus.config && vpnStatus.config.enabled;
            html += '<tr>' +
                '<td>VPN</td><td>wg0</td><td>VPN Tunnel (WireGuard)</td>' +
                '<td>' + escapeHtml((vpnStatus.config && vpnStatus.config.vpn_subnet) || '—') + '</td>' +
                '<td>' + (wgEnabled ? badge('success', 'Enabled') : badge('warning', 'Disabled')) + '</td>' +
                '</tr>';
        }

        if (ipsecStatus && ipsecStatus.installed) {
            var tunnels = ipsecStatus.tunnels || [];
            var anyEnabled = tunnels.some(function (t) { return t.enabled; });
            var statusHtml;
            if (tunnels.length === 0) {
                statusHtml = badge('muted', 'No tunnels');
            } else if (anyEnabled) {
                statusHtml = badge('success', 'Enabled');
            } else {
                statusHtml = badge('warning', 'Disabled');
            }
            html += '<tr>' +
                '<td>VPN</td><td>enc0</td><td>VPN Tunnel (IPsec)</td>' +
                '<td>' + tunnels.length + ' tunnel(s)</td>' +
                '<td>' + statusHtml + '</td>' +
                '</tr>';
        }

        tbody.innerHTML = html;
    }

    function refreshDashboard() {
        fetch('/dashboard-data.php', { credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                renderSystemInfo(data.dashInfo);
                renderDisks(data.dashInfo);
                renderInterfaces(data.zones, data.vpnStatus, data.ipsecStatus);
            })
            .catch(function () {
                // Diam-diam gagal - biarkan data terakhir yang berhasil tetap
                // tampil, jangan ganggu admin dengan error popup untuk
                // kegagalan polling latar belakang yang genuinely non-fatal.
            });
    }

    document.querySelectorAll('.ntp-dash-refresh-btn').forEach(function (btn) {
        btn.addEventListener('click', refreshDashboard);
    });

    setInterval(refreshDashboard, REFRESH_INTERVAL_MS);
})();

(function () {
    'use strict';

    // Grafik traffic - polling terpisah dari refreshDashboard() di atas
    // (interval lebih cepat, 3 detik, supaya grafik terasa "live" -
    // widget System Info/Disks/Interfaces cukup 10 detik, traffic
    // network berubah jauh lebih cepat dari itu). Rate (kbps) DIHITUNG
    // DI SINI dari selisih counter kumulatif dua polling berurutan -
    // server cuma kirim counter mentah + timestamp-nya sendiri, bukan
    // rate yang sudah dihitung, supaya elapsed time yang dipakai akurat
    // (bukan asumsi persis sama dengan interval polling yang diminta).
    var POLL_INTERVAL_MS = 3000;
    var MAX_POINTS = 60; // ~3 menit riwayat pada interval 3 detik

    var charts = {};   // nama interface -> instance Chart.js
    var history = {};  // nama interface -> {labels:[], inData:[], outData:[]}
    var lastSample = null;

    function twoDigits(n) {
        return n < 10 ? '0' + n : String(n);
    }

    function formatTimeLabel(date) {
        return twoDigits(date.getHours()) + ':' + twoDigits(date.getMinutes()) + ':' + twoDigits(date.getSeconds());
    }

    function getCheckedInterfaces() {
        var boxes = document.querySelectorAll('.ntp-traffic-checkbox:checked');
        var result = [];
        boxes.forEach(function (b) {
            result.push({ name: b.value, label: b.dataset.label });
        });
        return result;
    }

    function ensureChart(ifaceName, ifaceLabel) {
        if (charts[ifaceName]) {
            return;
        }
        var container = document.getElementById('dash-traffic-graphs');
        if (!container) {
            return;
        }
        var wrapper = document.createElement('div');
        wrapper.id = 'traffic-wrapper-' + ifaceName;
        wrapper.style.marginBottom = '18px';
        wrapper.innerHTML = '<div style="font-size:12px; color:#374151; font-weight:500; margin-bottom:4px;">' +
            ifaceLabel + ' <span style="color:#9ca3af; font-weight:400;">(' + ifaceName + ')</span></div>' +
            '<canvas style="width:100%; max-height:140px;"></canvas>';
        container.appendChild(wrapper);

        if (!history[ifaceName]) {
            history[ifaceName] = { labels: [], inData: [], outData: [] };
        }

        var ctx = wrapper.querySelector('canvas').getContext('2d');
        charts[ifaceName] = new Chart(ctx, {
            type: 'line',
            data: {
                labels: history[ifaceName].labels,
                datasets: [
                    {
                        label: 'In',
                        data: history[ifaceName].inData,
                        borderColor: '#2563eb',
                        backgroundColor: 'rgba(37,99,235,0.08)',
                        borderWidth: 1.5,
                        pointRadius: 0,
                        tension: 0.2,
                        fill: true,
                    },
                    {
                        label: 'Out',
                        data: history[ifaceName].outData,
                        borderColor: '#c74b00',
                        backgroundColor: 'rgba(199,75,0,0.08)',
                        borderWidth: 1.5,
                        pointRadius: 0,
                        tension: 0.2,
                        fill: true,
                    },
                ],
            },
            options: {
                animation: false,
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: { ticks: { maxTicksLimit: 6, font: { size: 10 } }, grid: { display: false } },
                    y: {
                        beginAtZero: true,
                        ticks: { font: { size: 10 }, callback: function (v) { return v + ' kbps'; } },
                    },
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            title: function (items) {
                                // Label sumbu-x sudah HH:MM:SS, tapi tooltip title
                                // sekalian sertakan tanggal penuh - ambil dari
                                // history array yang tersimpan (bukan cuma label
                                // pendek), sesuai permintaan tanggal+jam+menit+detik.
                                var idx = items[0].dataIndex;
                                var full = history[ifaceName].fullTimestamps && history[ifaceName].fullTimestamps[idx];
                                return full || items[0].label;
                            },
                            label: function (item) {
                                return item.dataset.label + ': ' + item.formattedValue + ' kbps';
                            },
                        },
                    },
                },
            },
        });

        // Isi chart baru dengan riwayat yang SUDAH ada (kalau admin
        // baru centang interface ini di tengah sesi, riwayat sebelum
        // dicentang tetap tidak ada - itu wajar, grafik mulai dari
        // titik dicentang, bukan dipalsukan mundur).
        charts[ifaceName].update();
    }

    function destroyChart(ifaceName) {
        if (charts[ifaceName]) {
            charts[ifaceName].destroy();
            delete charts[ifaceName];
        }
        var wrapper = document.getElementById('traffic-wrapper-' + ifaceName);
        if (wrapper) {
            wrapper.remove();
        }
    }

    function syncChartsToSelection() {
        var checked = getCheckedInterfaces();
        var checkedNames = checked.map(function (c) { return c.name; });

        Object.keys(charts).forEach(function (name) {
            if (checkedNames.indexOf(name) === -1) {
                destroyChart(name);
            }
        });
        checked.forEach(function (c) {
            ensureChart(c.name, c.label);
        });
    }

    function pushDataPoint(ifaceName, date, inKbps, outKbps) {
        if (!history[ifaceName]) {
            history[ifaceName] = { labels: [], inData: [], outData: [], fullTimestamps: [] };
        }
        var h = history[ifaceName];
        if (!h.fullTimestamps) {
            h.fullTimestamps = [];
        }
        h.labels.push(formatTimeLabel(date));
        h.inData.push(Math.round(inKbps * 10) / 10);
        h.outData.push(Math.round(outKbps * 10) / 10);
        h.fullTimestamps.push(
            date.getFullYear() + '-' + twoDigits(date.getMonth() + 1) + '-' + twoDigits(date.getDate()) +
            ' ' + formatTimeLabel(date)
        );
        if (h.labels.length > MAX_POINTS) {
            h.labels.shift();
            h.inData.shift();
            h.outData.shift();
            h.fullTimestamps.shift();
        }
        if (charts[ifaceName]) {
            charts[ifaceName].update('none');
        }
    }

    function pollTraffic() {
        fetch('/traffic-data.php', { credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data || !data.interfaces) {
                    return;
                }
                var now = new Date(data.timestamp_ms);
                if (lastSample) {
                    var elapsedSec = (data.timestamp_ms - lastSample.timestamp_ms) / 1000;
                    if (elapsedSec > 0) {
                        Object.keys(data.interfaces).forEach(function (ifaceName) {
                            var cur = data.interfaces[ifaceName];
                            var prev = lastSample.interfaces[ifaceName];
                            if (!prev) {
                                return;
                            }
                            var rxDelta = cur.rx_bytes - prev.rx_bytes;
                            var txDelta = cur.tx_bytes - prev.tx_bytes;
                            // Counter bisa wrap/reset (mis. interface di-restart) -
                            // delta negatif berarti itu terjadi, lewati satu sample
                            // ini daripada tampilkan angka negatif yang tidak masuk akal.
                            if (rxDelta < 0 || txDelta < 0) {
                                return;
                            }
                            var inKbps = (rxDelta * 8 / 1000) / elapsedSec;
                            var outKbps = (txDelta * 8 / 1000) / elapsedSec;
                            pushDataPoint(ifaceName, now, inKbps, outKbps);
                        });
                    }
                }
                lastSample = data;
            })
            .catch(function () {
                // Diam-diam gagal, sama seperti refreshDashboard() - satu
                // polling gagal bukan alasan mengganggu admin dengan error.
            });
    }

    document.querySelectorAll('.ntp-traffic-checkbox').forEach(function (box) {
        box.addEventListener('change', syncChartsToSelection);
    });

    if (typeof Chart !== 'undefined') {
        syncChartsToSelection();
        pollTraffic();
        setInterval(pollTraffic, POLL_INTERVAL_MS);
    }
})();
</script>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
