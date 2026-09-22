<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';

Auth::requireLogin();
Auth::requireCategory('network');

$configd = new NtpsenseConfigd();
$zones = null;
$configdError = null;
$actionMessage = null;
$actionError = null;
$subnetWarning = null;

// Flash message dari session (diisi sesaat sebelum redirect - lihat
// pola Post-Redirect-Get di handler lagg_edit di bawah) - tampil SEKALI
// lewat blok render $actionMessage yang sudah ada, lalu langsung
// dihapus dari session supaya tidak muncul lagi kalau halaman
// di-refresh setelahnya.
if (!empty($_SESSION['ntp_flash_message'])) {
    $actionMessage = $_SESSION['ntp_flash_message'];
    unset($_SESSION['ntp_flash_message']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_alias') {
    try {
        $configd->call('network.set_alias', [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'alias' => (string) ($_POST['alias'] ?? ''),
        ]);
        $actionMessage = 'Alias updated successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'toggle_port') {
    try {
        $configd->call('network.set_port_status', [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'enabled' => ($_POST['enabled'] ?? '') === '1',
        ]);
        $actionMessage = 'Port status updated successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
// Fase B - ganti subnet LAN1/OPT. Respons "warning" (custom rule
// menuliskan literal subnet lama) BUKAN exception - itu balasan 'ok'
// biasa dari ntpsense-configd, cuma isinya minta konfirmasi. Ditangani
// terpisah dari $actionError supaya bisa ditampilkan sebagai panel
// peringatan sendiri (pola FortiGate: block+tampilkan rule terdampak,
// bukan auto-lanjut).
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_subnet') {
    try {
        $result = $configd->call('network.set_subnet', [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'ip' => (string) ($_POST['ip'] ?? ''),
            'prefix' => (int) ($_POST['prefix'] ?? 24),
            'confirm' => ($_POST['confirm'] ?? '') === '1',
        ]);
        if (!empty($result['warning'])) {
            $subnetWarning = $result;
            $subnetWarning['interface'] = (string) ($_POST['interface'] ?? '');
            $subnetWarning['ip'] = (string) ($_POST['ip'] ?? '');
            $subnetWarning['prefix'] = (string) ($_POST['prefix'] ?? '24');
        } else {
            $actionMessage = 'Subnet updated successfully.';
        }
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_wan1_config') {
    try {
        $params = ['mode' => (string) ($_POST['mode'] ?? '')];
        if ($params['mode'] === 'static') {
            $params['ip'] = (string) ($_POST['ip'] ?? '');
            $params['prefix'] = (int) ($_POST['prefix'] ?? 24);
            $params['gateway'] = (string) ($_POST['gateway'] ?? '');
        }
        $configd->call('network.set_wan1_config', $params);
        $actionMessage = 'WAN1 configuration updated successfully.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_role') {
    try {
        $configd->call('network.set_role', [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'role' => (string) ($_POST['role'] ?? ''),
        ]);
        $actionMessage = 'Role updated successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_dhcp_config') {
    try {
        $enabled = ($_POST['dhcp_enabled'] ?? '') === '1';
        $params = [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'enabled' => $enabled,
        ];
        if ($enabled) {
            $params['range_start'] = (string) ($_POST['range_start'] ?? '');
            $params['range_end'] = (string) ($_POST['range_end'] ?? '');
            $params['dns_servers'] = array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['dns_servers'] ?? '')))));
            $params['lease_time'] = (int) ($_POST['lease_time'] ?? 604800);
            $params['option43_wlc_ips'] = array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['option43_wlc_ips'] ?? '')))));
        }
        $configd->call('network.set_dhcp_config', $params);
        $actionMessage = 'DHCP server configuration updated successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'update_interface') {
    // Satu form, satu tombol Save untuk SEMUA properti interface sekaligus
    // (alias, role, mode/subnet, DHCP server) - sebelumnya 4 tombol
    // terpisah, digabung atas masukan bro. Backend TETAP 4 action
    // terpisah yang sudah teruji (tidak diubah) - PHP yang memanggil
    // berurutan dalam satu handler ini, bukan bikin action baru di Rust.
    //
    // Urutan PENTING: cek peringatan subnet DULU (rule yang literal-
    // reference subnet lama) - kalau ada dan belum dikonfirmasi, SEMUA
    // ditahan (alias/role/DHCP server TIDAK ikut ter-apply juga),
    // supaya tidak ada kondisi "sebagian tersimpan, sebagian menunggu
    // konfirmasi" yang membingungkan. Admin cukup submit form yang SAMA
    // sekali lagi (tombol "Proceed anyway" sudah bawa confirm=1 +
    // seluruh field lain lewat hidden input) untuk terapkan semuanya.
    $iface = (string) ($_POST['interface'] ?? '');
    $mode = $_POST['mode'] ?? null; // null kalau MGMT (field tidak dikirim sama sekali)
    $confirm = ($_POST['confirm'] ?? '') === '1';

    try {
        $subnetBlocked = false;

        if ($mode === 'static') {
            $result = $configd->call('network.set_subnet', [
                'interface' => $iface,
                'ip' => (string) ($_POST['ip'] ?? ''),
                'prefix' => (int) ($_POST['prefix'] ?? 24),
                'mode' => 'static',
                'confirm' => $confirm,
            ]);
            if (!empty($result['warning'])) {
                $subnetWarning = $result;
                $subnetWarning['interface'] = $iface;
                $subnetWarning['ip'] = (string) ($_POST['ip'] ?? '');
                $subnetWarning['prefix'] = (string) ($_POST['prefix'] ?? '24');
                $subnetWarning['pending'] = $_POST; // simpan SELURUH input lain supaya "Proceed anyway" bisa kirim ulang semuanya
                $subnetBlocked = true;
            }
        } elseif ($mode === 'dhcp') {
            $configd->call('network.set_subnet', ['interface' => $iface, 'mode' => 'dhcp']);
        } elseif ($iface === ($zones['wan1']['interface'] ?? null)) {
            $wan1Params = ['mode' => (string) ($_POST['wan1_mode'] ?? 'dhcp')];
            if ($wan1Params['mode'] === 'static') {
                $wan1Params['ip'] = (string) ($_POST['ip'] ?? '');
                $wan1Params['prefix'] = (int) ($_POST['prefix'] ?? 24);
                $wan1Params['gateway'] = (string) ($_POST['gateway'] ?? '');
                $wan1Params['confirm'] = $confirm;
            }
            $result = $configd->call('network.set_wan1_config', $wan1Params);
            if (!empty($result['warning'])) {
                $subnetWarning = $result;
                $subnetWarning['interface'] = $iface;
                $subnetWarning['pending'] = $_POST;
                $subnetBlocked = true;
            }
        }

        if (!$subnetBlocked) {
            if (isset($_POST['alias'])) {
                $configd->call('network.set_alias', [
                    'interface' => $iface,
                    'alias' => (string) $_POST['alias'],
                ]);
            }
            if (isset($_POST['description'])) {
                $configd->call('network.set_description', [
                    'interface' => $iface,
                    'description' => (string) $_POST['description'],
                ]);
            }
            if (isset($_POST['role'])) {
                $configd->call('network.set_role', [
                    'interface' => $iface,
                    'role' => (string) $_POST['role'],
                ]);
            }
            if ($mode === 'static') {
                $dhcpEnabled = ($_POST['dhcp_enabled'] ?? '') === '1';
                $dhcpParams = ['interface' => $iface, 'enabled' => $dhcpEnabled];
                if ($dhcpEnabled) {
                    $dhcpParams['range_start'] = (string) ($_POST['range_start'] ?? '');
                    $dhcpParams['range_end'] = (string) ($_POST['range_end'] ?? '');
                    $dhcpParams['dns_servers'] = array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['dns_servers'] ?? '')))));
                    $dhcpParams['lease_time'] = (int) ($_POST['lease_time'] ?? 604800);
                    $dhcpParams['option43_wlc_ips'] = array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['option43_wlc_ips'] ?? '')))));
                }
                $configd->call('network.set_dhcp_config', $dhcpParams);
            }
            $actionMessage = 'Interface updated successfully.';
            // Pola PRG (sama seperti lagg_edit) - form ini submit balik ke
            // URL yang sama persis termasuk '?manage=<iface>'. Tanpa
            // redirect, card Manage Interface tetap terbuka setelah sukses
            // DAN field prefix/ip yang ditampilkan tetap dari snapshot
            // $zones yang diambil SEBELUM update ini diterapkan - baru
            // akurat kalau halaman benar-benar di-load ulang dari awal.
            // Redirect ke '?iftab=physical' (tanpa 'manage=') sekaligus
            // menutup card dan memastikan data yang tampil di tabel below
            // maupun kalau card dibuka lagi sudah live, bukan stale.
            $_SESSION['ntp_flash_message'] = 'Interface updated successfully.';
            header('Location: ?iftab=physical');
            exit;
        }
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'lagg_create') {
    try {
        $members = array_values(array_filter((array) ($_POST['members'] ?? [])));
        $result = $configd->call('network.lagg_create', [
            'members' => $members,
            'protocol' => (string) ($_POST['protocol'] ?? 'failover'),
        ], 30.0);
        $actionMessage = 'Link aggregation "' . ($result['lagg_interface'] ?? '') . '" created successfully. It now appears as a new OPT zone below - assign it a subnet/role from Physical Interfaces like any other OPT.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'lagg_delete') {
    try {
        $configd->call('network.lagg_delete', ['interface' => (string) ($_POST['interface'] ?? '')], 30.0);
        $actionMessage = 'Link aggregation group deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'lagg_edit') {
    try {
        $members = array_values(array_filter((array) ($_POST['members'] ?? [])));
        $configd->call('network.lagg_edit', [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'members' => $members,
            'protocol' => (string) ($_POST['protocol'] ?? 'failover'),
        ], 30.0);
        // Pola Post-Redirect-Get (PRG) - RCA nyata: form ini tidak
        // punya 'action' eksplisit, jadi submit balik ke URL yang SAMA
        // PERSIS termasuk '?edit_lagg=laggN' - kalau halaman cuma
        // di-render ulang biasa (bukan redirect), $editingLagg tetap
        // terisi dari query string lama, card Edit tetap terbuka walau
        // sudah sukses. Redirect ke URL bersih (tanpa edit_lagg) juga
        // sekaligus mencegah masalah klasik "submit ulang form?" kalau
        // admin refresh halaman setelah ini. Pesan sukses disimpan
        // sebentar di session (flash message) supaya tetap tampil SEKALI
        // di halaman hasil redirect, lalu otomatis hilang.
        $_SESSION['ntp_flash_message'] = 'Link aggregation group updated successfully.';
        header('Location: ?iftab=lagg');
        exit;
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'loopback_create') {
    try {
        $result = $configd->call('network.loopback_create', [
            'ip' => (string) ($_POST['ip'] ?? ''),
            'prefix' => (int) ($_POST['prefix'] ?? 32),
        ]);
        $actionMessage = 'Loopback interface "' . ($result['interface'] ?? '') . '" created successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'loopback_delete') {
    try {
        $configd->call('network.loopback_delete', ['interface' => (string) ($_POST['interface'] ?? '')]);
        $actionMessage = 'Loopback interface deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vlan_db_create') {
    try {
        $configd->call('network.vlan_db_create', [
            'id' => (int) ($_POST['id'] ?? 0),
            'name' => (string) ($_POST['name'] ?? ''),
        ]);
        $actionMessage = 'VLAN ' . (int) ($_POST['id'] ?? 0) . ' added to the VLAN Database.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vlan_db_delete') {
    try {
        $configd->call('network.vlan_db_delete', ['id' => (int) ($_POST['id'] ?? 0)]);
        $actionMessage = 'VLAN removed from the VLAN Database.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vlan_create') {
    try {
        $result = $configd->call('network.vlan_create', [
            'parent' => (string) ($_POST['parent'] ?? ''),
            'tag' => (int) ($_POST['tag'] ?? 0),
        ]);
        $actionMessage = 'VLAN interface "' . ($result['interface'] ?? '') . '" created successfully.';
        if (!empty($result['parent_has_ip'])) {
            $actionMessage .= ' Note: the parent interface already has its own IP - untagged traffic will continue '
                . 'reaching the parent\'s zone directly (like Cisco\'s "native VLAN"), only traffic tagged with this '
                . 'VLAN ID reaches the new interface. Make sure your switch\'s trunk configuration matches what you intend.';
        }
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'vlan_delete') {
    try {
        $configd->call('network.vlan_delete', ['interface' => (string) ($_POST['interface'] ?? '')]);
        $actionMessage = 'VLAN interface deleted.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'reset_interface') {
    try {
        $configd->call('network.reset_interface', ['interface' => (string) ($_POST['interface'] ?? '')], 30.0);
        $actionMessage = 'Interface reset to default successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}

try {
    $zones = $configd->call('network.zones');
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}

// VPN Tunnel Interfaces (WireGuard + IPsec) - Type=VPN Tunnel
// interfaces are deliberately NOT part of the $zones physical Zone
// rotation above (see RCA-20, Doc 7 §1.2a: a tunnel interface must
// never compete for a WAN1/LAN1/OPT slot). Both fetches are non-fatal/
// best-effort - if a plugin isn't installed, that tab just shows a
// "not configured" state rather than blocking the whole page.
$vpnStatus = null;
try {
    $vpnStatus = $configd->call('vpn.get_config');
} catch (NtpsenseConfigdException $e) {
    // Intentionally silent.
}

$ipsecStatus = null;
try {
    $ipsecStatus = $configd->call('ipsec.get_config');
} catch (NtpsenseConfigdException $e) {
    // Intentionally silent.
}

// Tab aktif - "physical" default. Query param 'iftab' sengaja beda
// dari 'manage' (dipakai untuk edit interface fisik) supaya keduanya
// bisa hidup berdampingan di URL tanpa bentrok.
//
// RCA (bug nyata - Link Aggregation selalu tampil "Fewer than 2
// eligible ports" apa pun kondisi interface-nya): definisi ini
// SEBELUMNYA ada di bawah blok fetch LAGG yang membutuhkannya (line
// 203 vs line 170 di deploy yang ketahuan bermasalah) - PHP TIDAK
// mengeksekusi kode secara "lihat ke depan" seperti deklarasi function/
// const, jadi di titik fetch LAGG dieksekusi, $activeIfTab genuinely
// belum ada nilainya sama sekali (undefined variable, dianggap null) -
// kondisi "$activeIfTab === 'lagg'" SELALU false akibatnya, TIDAK
// PEDULI tab mana yang sebenarnya sedang aktif. Dipindah ke sini
// (sebelum dipakai) memperbaikinya.
$activeIfTab = $_GET['iftab'] ?? 'physical';
if (!in_array($activeIfTab, ['physical', 'wireguard', 'ipsec', 'lagg', 'loopback', 'vlan_database', 'vlan', 'leases'], true)) {
    $activeIfTab = 'physical';
}

// LAGG data cuma diambil kalau tab-nya sedang aktif - tidak perlu
// dibebankan ke setiap load halaman Network, konsisten dengan pola
// $statusTunnels/$logLines di ipsec.php yang juga per-tab. lagg_list
// SEKARANG juga diambil di tab 'physical' (bukan cuma 'lagg') - dibutuhkan
// untuk render child-row abu-abu member LAGG di tabel Network zones,
// sesuai pola nyata FortiGate/Sangfor (member interface tetap terlihat
// sebagai baris info di bawah interface gabungannya, bukan cuma di tab
// Link Aggregation).
$laggGroups = [];
$laggCandidates = [];
if ($activeIfTab === 'lagg' || $activeIfTab === 'physical') {
    try {
        $laggGroups = $configd->call('network.lagg_list')['lagg_groups'] ?? [];
        if ($activeIfTab === 'lagg') {
            $laggCandidates = $configd->call('network.lagg_available_members')['candidates'] ?? [];
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

// Loopback data cuma diambil kalau tab-nya sedang aktif - pola sama
// seperti $laggGroups di atas, tidak perlu membebani setiap load
// halaman Network.
$loopbacks = [];
if ($activeIfTab === 'loopback') {
    try {
        $loopbacks = $configd->call('network.loopback_list')['loopbacks'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
// DHCP leases cuma diambil kalau tab-nya sedang aktif - pola sama
// seperti $loopbacks/$laggGroups di atas. Data dari file lease Kea
// nyata (/var/db/kea/dhcp4.leases) - lihat network.get_dhcp_leases
// di daemon Rust untuk detail parsing.
$dhcpLeases = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'dhcp_make_static') {
    try {
        $configd->call('network.add_dhcp_reservation', [
            'interface' => (string) ($_POST['interface'] ?? ''),
            'mac' => (string) ($_POST['mac'] ?? ''),
            'ip' => (string) ($_POST['ip'] ?? ''),
            'hostname' => (string) ($_POST['hostname'] ?? ''),
        ]);
        $actionMessage = 'Lease converted to a static reservation successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'dhcp_remove_reservation') {
    try {
        $configd->call('network.delete_dhcp_reservation', ['mac' => (string) ($_POST['mac'] ?? '')]);
        $actionMessage = 'Static reservation removed successfully.';
    } catch (NtpsenseConfigdException $e) {
        $actionError = $e->getMessage();
    }
}
if ($activeIfTab === 'leases') {
    try {
        $dhcpLeases = $configd->call('network.get_dhcp_leases')['leases'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

// VLAN data cuma diambil kalau tab-nya sedang aktif - pola sama
// seperti $laggGroups/$loopbacks di atas.
$vlanDbEntries = [];
if ($activeIfTab === 'vlan_database' || $activeIfTab === 'vlan') {
    try {
        $vlanDbEntries = $configd->call('network.vlan_db_list')['vlans'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}
$vlans = [];
$vlanParents = [];
if ($activeIfTab === 'vlan' || $activeIfTab === 'physical') {
    try {
        $vlans = $configd->call('network.vlan_list')['vlans'] ?? [];
        if ($activeIfTab === 'vlan') {
            $vlanParents = $configd->call('network.vlan_available_parents')['candidates'] ?? [];
        }
    } catch (NtpsenseConfigdException $e) {
        $configdError = $e->getMessage();
    }
}

// Edit grup LAGG - deteksi via ?edit_lagg=laggN, cari grup yang cocok
// dari $laggGroups yang sudah diambil di atas (satu sumber data, bukan
// fetch terpisah lagi).
$editLaggName = $_GET['edit_lagg'] ?? '';
$editingLagg = null;
foreach ($laggGroups as $g) {
    if (($g['interface'] ?? '') === $editLaggName) {
        $editingLagg = $g;
        break;
    }
}

$managingInterface = $_GET['manage'] ?? null;
$managingZone = null;
$managingZoneKey = null;
if ($managingInterface && $zones) {
    $allZones = [
        ['key' => 'mgmt', 'label' => 'MGMT', 'data' => $zones['mgmt']],
        ['key' => 'lan1', 'label' => 'LAN1', 'data' => $zones['lan1']],
        ['key' => 'wan1', 'label' => 'WAN1', 'data' => $zones['wan1']],
    ];
    foreach (($zones['opt'] ?? []) as $i => $opt) {
        $allZones[] = ['key' => 'opt', 'label' => 'OPT' . ($i + 1), 'data' => $opt];
    }
    foreach ($allZones as $z) {
        if (($z['data']['interface'] ?? null) === $managingInterface) {
            $managingZone = $z;
            $managingZoneKey = $z['key'];
            break;
        }
    }
}

/** @param array<int, array<string, mixed>> $vlans */
function findVlanChildrenFor(?string $parentIface, array $vlans): array
{
    if ($parentIface === null || $parentIface === '') {
        return [];
    }
    return array_values(array_filter($vlans, static fn (array $v) => ($v['parent'] ?? '') === $parentIface));
}

function renderZoneRow(string $zoneLabel, ?array $zone, string $description, bool $isMgmt, bool $isOpt, array $laggMembers = [], array $vlanChildren = []): void
{
    $iface = $zone['interface'] ?? null;
    $enabled = $zone['enabled'] ?? true;
    $linkUp = $zone['link_up'] ?? null;
    ?>
    <tr>
      <td><?= htmlspecialchars($zoneLabel) ?></td>
      <td><?= htmlspecialchars($zone['alias'] ?? $zoneLabel) ?></td>
      <td><?= htmlspecialchars($iface ?? '—') ?></td>
      <td><?= htmlspecialchars($zone['role'] ?? '—') ?></td>
      <td><?= htmlspecialchars($zone['type'] ?? '—') ?></td>
      <td><?= htmlspecialchars(($zone['ip'] ?? null) ? $zone['ip'] . (isset($zone['prefix']) && $zone['prefix'] !== null ? '/' . $zone['prefix'] : '') : '—') ?></td>
      <td>
        <?php
        // Status precedence: Disabled (admin down) > Down (cable
        // unplugged, link_up===false) > Active (has IP) > Unknown
        // (fallback - link status undetectable and no IP yet).
        if (!$enabled): ?>
          <span class="ntp-badge ntp-badge-warning">Disabled</span>
        <?php elseif ($linkUp === false): ?>
          <span class="ntp-badge ntp-badge-warning">Down</span>
        <?php elseif ($zone['ip']): ?>
          <span class="ntp-badge ntp-badge-success">Active</span>
        <?php else: ?>
          <span class="ntp-badge ntp-badge-muted">Unknown</span>
        <?php endif; ?>
      </td>
      <td style="color:#6b7280; font-size:12px;"><?= htmlspecialchars(($zone['description'] ?? '') !== '' ? $zone['description'] : $description) ?></td>
      <td>
        <?php if ($iface): ?>
          <a href="?iftab=physical&manage=<?= htmlspecialchars($iface) ?>" title="Manage interface" style="color:#374151; padding:4px; display:inline-block;">
            <i class="ti ti-edit" style="font-size:16px;" aria-hidden="true"></i>
          </a>
          <?php if (!$isMgmt): ?>
            <form method="post" style="margin:0; display:inline-block;">
              <input type="hidden" name="form" value="toggle_port">
              <input type="hidden" name="interface" value="<?= htmlspecialchars($iface) ?>">
              <input type="hidden" name="enabled" value="<?= $enabled ? '0' : '1' ?>">
              <button type="submit" title="<?= $enabled ? 'Disable port' : 'Enable port' ?>" style="background:none; border:none; cursor:pointer; color:<?= $enabled ? '#b3261e' : '#1a7f4b' ?>; padding:4px;">
                <i class="ti ti-power" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
          <?php endif; ?>
          <?php if ($isOpt): ?>
            <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Reset interface <?= htmlspecialchars($iface) ?> to default? This clears its IP/subnet, DHCP server config, Role, Alias, AND all custom Firewall rules for this interface - like Cisco\'s &quot;default interface&quot; command. Port enable/disable state is not affected. This cannot be undone.');">
              <input type="hidden" name="form" value="reset_interface">
              <input type="hidden" name="interface" value="<?= htmlspecialchars($iface) ?>">
              <button type="submit" title="Reset interface to default (clears IP, DHCP, Role, Alias, custom rules)" style="background:none; border:none; cursor:pointer; color:#9a5b00; padding:4px;">
                <i class="ti ti-refresh" style="font-size:16px;" aria-hidden="true"></i>
              </button>
            </form>
          <?php endif; ?>
        <?php endif; ?>
      </td>
    </tr>
    <?php
    // Child row abu-abu untuk tiap member LAGG - dikonfirmasi ini pola
    // nyata FortiGate/Sangfor (member interface tetap terlihat sebagai
    // baris info di bawah interface gabungannya, TIDAK bisa diedit dari
    // sini - edit member/protokol HANYA lewat tab Link Aggregation).
    // Tidak ada icon Manage sama sekali di baris ini - benar-benar
    // read-only.
    foreach ($laggMembers as $member): ?>
      <tr style="color:#9ca3af; background:#fafafa;">
        <td></td>
        <td style="padding-left:24px;">↳ member</td>
        <td><?= htmlspecialchars($member) ?></td>
        <td colspan="5" style="font-size:12px;">Part of <?= htmlspecialchars($iface ?? '') ?> - configure via <a href="?iftab=lagg" style="color:#9ca3af;">Link Aggregation</a></td>
        <td></td>
      </tr>
    <?php endforeach;
    // Child row abu-abu untuk tiap VLAN yang terikat ke interface ini
    // sebagai parent - pola PERSIS sama dengan child row member LAGG
    // di atas (informational murni, tidak ada icon Manage, edit HANYA
    // lewat tab VLAN Interfaces) - permintaan bro supaya admin langsung
    // lihat dari Physical Interfaces tab kalau sebuah port sedang jadi
    // trunk carrier untuk VLAN apa saja, tanpa harus buka tab lain dulu.
    foreach ($vlanChildren as $vlanChild): ?>
      <tr style="color:#9ca3af; background:#fafafa;">
        <td></td>
        <td style="padding-left:24px;">↳ vlan <?= htmlspecialchars((string) $vlanChild['tag']) ?></td>
        <td><?= htmlspecialchars($vlanChild['interface']) ?></td>
        <td colspan="5" style="font-size:12px;">
          <?= htmlspecialchars($vlanChild['alias'] ?? '(unnamed)') ?> - tagged on <?= htmlspecialchars($iface ?? '') ?>,
          configure via <a href="?iftab=vlan" style="color:#9ca3af;">VLAN Interfaces</a>
        </td>
        <td></td>
      </tr>
    <?php endforeach;
}

$tabLabels = ['physical' => 'Physical', 'wireguard' => 'WireGuard VPN', 'ipsec' => 'IPsec', 'lagg' => 'Link Aggregation', 'loopback' => 'Loopback', 'vlan_database' => 'VLAN Database', 'vlan' => 'VLAN Interfaces', 'leases' => 'DHCP Leases'];
$pageTitle = 'Network';
$activeNavItem = 'network';
$breadcrumbTail = ['Interfaces', $tabLabels[$activeIfTab]];
require __DIR__ . '/../templates/layout_header.php';
?>

<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">
    Unable to fetch zone data from ntpsense-configd: <?= htmlspecialchars($configdError) ?>
  </div>
<?php endif; ?>
<?php if ($actionMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($actionMessage) ?></div>
<?php endif; ?>
<?php if ($actionError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed: <?= htmlspecialchars($actionError) ?></div>
<?php endif; ?>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?iftab=physical" class="ntp-tab<?= $activeIfTab === 'physical' ? ' active' : '' ?>">Physical Interfaces</a>
  <a href="?iftab=leases" class="ntp-tab<?= $activeIfTab === 'leases' ? ' active' : '' ?>">DHCP Leases</a>
  <a href="?iftab=wireguard" class="ntp-tab<?= $activeIfTab === 'wireguard' ? ' active' : '' ?>">WireGuard VPN Interfaces</a>
  <a href="?iftab=ipsec" class="ntp-tab<?= $activeIfTab === 'ipsec' ? ' active' : '' ?>">IPsec Interfaces</a>
  <a href="?iftab=lagg" class="ntp-tab<?= $activeIfTab === 'lagg' ? ' active' : '' ?>">Link Aggregation</a>
  <a href="?iftab=loopback" class="ntp-tab<?= $activeIfTab === 'loopback' ? ' active' : '' ?>">Loopback Interfaces</a>
  <a href="?iftab=vlan_database" class="ntp-tab<?= $activeIfTab === 'vlan_database' ? ' active' : '' ?>">VLAN Database</a>
  <a href="?iftab=vlan" class="ntp-tab<?= $activeIfTab === 'vlan' ? ' active' : '' ?>">VLAN Interfaces</a>
</div>

<?php if (!$configdError): ?>

  <?php if ($activeIfTab === 'physical'): ?>

    <?php if ($managingZone): ?>
      <div class="ntp-card" style="margin-bottom:16px;">
        <div class="ntp-card-header">Manage interface — <?= htmlspecialchars($managingZone['label']) ?> (<?= htmlspecialchars($managingInterface) ?>)</div>

        <?php if ($subnetWarning && $subnetWarning['interface'] === $managingInterface): ?>
          <div style="margin:14px; background:#fff4e0; border-radius:8px; padding:14px;">
            <p style="font-size:13px; color:#9a5b00; margin:0 0 10px; font-weight:500;">
              <?= htmlspecialchars($subnetWarning['message']) ?>
            </p>
            <?php if (!empty($subnetWarning['affected_rules'])): ?>
            <div class="ntp-table-scroll">
            <table class="ntp-table" style="background:#ffffff;">
              <thead>
              <tr><th>Interface</th><th>Action</th><th>Source</th><th>Destination</th><th>Description</th></tr>
              </thead>
              <tbody>
              <?php foreach ($subnetWarning['affected_rules'] as $r): ?>
                <tr>
                  <td><?= htmlspecialchars($r['interface']) ?></td>
                  <td><?= htmlspecialchars($r['action']) ?></td>
                  <td><?= htmlspecialchars($r['source'] ?? 'any') ?></td>
                  <td><?= htmlspecialchars($r['destination']) ?></td>
                  <td><?= htmlspecialchars($r['description'] ?? '') ?></td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
            </div>
            <?php endif; ?>
            <form method="post" style="margin-top:10px;">
              <?php foreach ($subnetWarning['pending'] as $key => $value): ?>
                <?php if ($key === 'confirm') continue; // ditimpa eksplisit di bawah ?>
                <input type="hidden" name="<?= htmlspecialchars($key) ?>" value="<?= htmlspecialchars((string) $value) ?>">
              <?php endforeach; ?>
              <input type="hidden" name="confirm" value="1">
              <button type="submit" style="background:#9a5b00; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Proceed anyway (apply all changes)</button>
              <span style="font-size:12px; color:#6b7280; margin-left:10px;">These rules will NOT be updated automatically — you'll need to adjust them manually afterward.</span>
            </form>
          </div>
        <?php else: ?>

        <?php
        $ipMode = $managingZone['data']['ip_mode'] ?? 'static';
        $dhcpCfg = $managingZone['data']['dhcp'] ?? ['enabled' => false, 'range_start' => '', 'range_end' => '', 'dns_servers' => [], 'lease_time' => 604800];
        $dhcpEnabled = $dhcpCfg['enabled'] ?? false;
        ?>
        <form method="post" style="padding:14px;">
          <input type="hidden" name="form" value="update_interface">
          <input type="hidden" name="interface" value="<?= htmlspecialchars($managingInterface) ?>">

          <div style="margin-bottom:18px;">
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Alias</label>
            <input type="text" name="alias" value="<?= htmlspecialchars($managingZone['data']['alias'] ?? '') ?>" maxlength="32" style="max-width:280px;">
          </div>

          <div style="margin-bottom:18px;">
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Description</label>
            <input type="text" name="description" value="<?= htmlspecialchars($managingZone['data']['description'] ?? '') ?>" maxlength="200" placeholder="e.g. AP native VLAN trunk, Cisco WLC management" style="max-width:480px; width:100%;">
            <p style="font-size:11px; color:#9ca3af; margin:4px 0 0;">Free-form note shown in the Network zones table. Leave empty to show the default placeholder text.</p>
          </div>

          <?php if ($managingZoneKey === 'opt'): ?>
            <div style="margin-bottom:6px;">
              <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Role</label>
              <select name="role" style="max-width:280px;">
                <?php foreach (['Undefined', 'LAN', 'WAN', 'DMZ'] as $r): ?>
                  <option value="<?= $r ?>" <?= ($managingZone['data']['role'] ?? 'Undefined') === $r ? 'selected' : '' ?>><?= $r ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <p style="font-size:11px; color:#9ca3af; margin:0 0 18px;">
              Role is a classification label only (matching FortiGate's Interface Role concept) — it does not currently change firewall behavior automatically.
            </p>
          <?php else: ?>
            <p style="font-size:11px; color:#9ca3af; margin:0 0 18px;">
              Role for MGMT/LAN1/WAN1 is fixed to match the zone itself and cannot be changed.
            </p>
          <?php endif; ?>

          <?php if ($managingZoneKey === 'lan1' || $managingZoneKey === 'opt'): ?>
            <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:14px 16px; margin-bottom:6px;">
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Mode</label>
                <select name="mode" id="subnet-mode-select" onchange="ntpToggleSubnetMode(this.value);">
                  <option value="static" <?= $ipMode === 'static' ? 'selected' : '' ?>>Static</option>
                  <option value="dhcp" <?= $ipMode === 'dhcp' ? 'selected' : '' ?>>DHCP Client</option>
                </select>
              </div>
            </div>
            <div id="subnet-static-fields" style="display:<?= $ipMode === 'static' ? 'grid' : 'none' ?>; grid-template-columns:repeat(2, 1fr); gap:14px 16px; max-width:400px; margin-bottom:6px;">
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">IP address</label>
                <input type="text" name="ip" value="<?= htmlspecialchars($managingZone['data']['ip'] ?? '') ?>" placeholder="10.252.1.1" style="width:100%;">
              </div>
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Prefix length</label>
                <input type="number" name="prefix" value="<?= htmlspecialchars((string) ($managingZone['data']['prefix'] ?? 24)) ?>" min="1" max="32" style="width:100%;">
              </div>
            </div>
            <p style="font-size:11px; color:#9ca3af; margin:0 0 18px;">
              Changing the subnet takes effect immediately. System rules referencing this zone (via pf macros) update automatically — custom rules with a literal subnet reference do not, and will be flagged separately if found.
              In DHCP Client mode, this interface's own IP comes from an upstream DHCP server, so the DHCP Server section below is disabled — serving DHCP for a subnet we don't control doesn't make sense.
            </p>

            <div style="<?= $ipMode === 'dhcp' ? 'opacity:.5;' : '' ?>" id="dhcp-server-section">
              <p style="font-size:12px; color:#374151; font-weight:500; margin:0 0 8px;">DHCP Server</p>
              <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:14px 16px; max-width:600px; margin-bottom:6px;">
                <div>
                  <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Status</label>
                  <select name="dhcp_enabled" id="dhcp-enabled-select" onchange="document.getElementById('dhcp-fields').style.display = (this.value === '1') ? 'grid' : 'none';" <?= $ipMode === 'dhcp' ? 'disabled' : '' ?>>
                    <option value="0" <?= !$dhcpEnabled ? 'selected' : '' ?>>Disabled</option>
                    <option value="1" <?= $dhcpEnabled ? 'selected' : '' ?>>Enabled</option>
                  </select>
                </div>
              </div>
              <div id="dhcp-fields" style="display:<?= ($dhcpEnabled && $ipMode !== 'dhcp') ? 'grid' : 'none'; ?>; grid-template-columns:repeat(4, 1fr); gap:14px 16px; max-width:800px; margin-bottom:6px;">
                <div>
                  <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Range start</label>
                  <input type="text" name="range_start" value="<?= htmlspecialchars($dhcpCfg['range_start'] ?? '') ?>" placeholder="10.252.1.100" style="width:100%;" <?= $ipMode === 'dhcp' ? 'disabled' : '' ?>>
                </div>
                <div>
                  <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Range end</label>
                  <input type="text" name="range_end" value="<?= htmlspecialchars($dhcpCfg['range_end'] ?? '') ?>" placeholder="10.252.1.200" style="width:100%;" <?= $ipMode === 'dhcp' ? 'disabled' : '' ?>>
                </div>
                <div>
                  <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">DNS servers (comma-separated)</label>
                  <input type="text" name="dns_servers" value="<?= htmlspecialchars(implode(', ', $dhcpCfg['dns_servers'] ?? [])) ?>" placeholder="8.8.8.8, 8.8.4.4" style="width:100%;" <?= $ipMode === 'dhcp' ? 'disabled' : '' ?>>
                </div>
                <div>
                  <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Lease time (seconds)</label>
                  <input type="number" name="lease_time" value="<?= htmlspecialchars((string) ($dhcpCfg['lease_time'] ?? 604800)) ?>" min="60" style="width:100%;" <?= $ipMode === 'dhcp' ? 'disabled' : '' ?>>
                </div>
                <div style="grid-column: 1 / -1;">
                  <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">
                    Option 43 - Cisco WLC IP(s) for AP discovery <span style="color:#9ca3af; font-weight:normal;">(optional, comma-separated)</span>
                  </label>
                  <input type="text" name="option43_wlc_ips" value="<?= htmlspecialchars(implode(', ', $dhcpCfg['option43_wlc_ips'] ?? [])) ?>" placeholder="192.168.200.10" style="width:100%;" <?= $ipMode === 'dhcp' ? 'disabled' : '' ?>>
                  <p style="font-size:11px; color:#9ca3af; margin:4px 0 0;">
                    For Cisco lightweight APs on this subnet to discover a WLC on a <strong>different</strong> subnet
                    (Layer 3 CAPWAP) - not needed if the WLC is directly reachable without DHCP-based discovery.
                  </p>
                </div>
              </div>
              <p style="font-size:11px; color:#9ca3af; margin:0 0 18px;">Gateway is always the interface's own IP address, same as FortiGate's default. The range must fall within the interface's current subnet.</p>
            </div>

          <?php elseif ($managingZoneKey === 'wan1'): ?>
            <?php $wan1Mode = $managingZone['data']['ip_mode'] ?? 'dhcp'; ?>
            <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:14px 16px; margin-bottom:6px;">
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Mode</label>
                <select name="wan1_mode" id="wan1-mode" onchange="document.getElementById('wan1-static-fields').style.display = (this.value === 'static') ? 'grid' : 'none';">
                  <option value="dhcp" <?= $wan1Mode === 'dhcp' ? 'selected' : '' ?>>DHCP</option>
                  <option value="static" <?= $wan1Mode === 'static' ? 'selected' : '' ?>>Static</option>
                </select>
              </div>
            </div>
            <div id="wan1-static-fields" style="display:<?= $wan1Mode === 'static' ? 'grid' : 'none' ?>; grid-template-columns:repeat(3, 1fr); gap:14px 16px; max-width:600px; margin-bottom:6px;">
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">IP address</label>
                <input type="text" name="ip" value="<?= htmlspecialchars($managingZone['data']['ip'] ?? '') ?>" placeholder="203.0.113.10" style="width:100%;">
              </div>
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Prefix length</label>
                <input type="number" name="prefix" value="<?= htmlspecialchars((string) ($managingZone['data']['prefix'] ?? 24)) ?>" min="1" max="32" style="width:100%;">
              </div>
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Gateway</label>
                <input type="text" name="gateway" placeholder="203.0.113.1" style="width:100%;">
              </div>
            </div>
            <p style="font-size:11px; color:#9ca3af; margin:0 0 18px;">
              Switching to Static requires a valid gateway within the chosen subnet. This change takes effect immediately and may briefly interrupt internet connectivity.
            </p>
          <?php elseif ($managingZoneKey === 'mgmt'): ?>
            <input type="hidden" name="mode" value="static">
            <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:14px 16px; max-width:400px; margin-bottom:6px;">
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">IP address</label>
                <input type="text" name="ip" value="<?= htmlspecialchars($managingZone['data']['ip'] ?? '') ?>" placeholder="10.252.252.100" style="width:100%;">
              </div>
              <div>
                <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Prefix length</label>
                <input type="number" name="prefix" value="<?= htmlspecialchars((string) ($managingZone['data']['prefix'] ?? 24)) ?>" min="1" max="32" style="width:100%;">
              </div>
            </div>
            <p style="font-size:11px; color:#9a5b00; background:#fff8e6; border:1px solid #f5d78e; border-radius:6px; padding:8px 10px; margin:0 0 18px;">
              ⚠️ MGMT is the interface used to manage this gateway itself — changing its IP carries a real lockout
              risk if you get it wrong. Make sure you can reach the new address from where you're connecting before
              confirming. (MGMT stays Static-only — DHCP Client mode is not offered here, since an admin interface
              whose address can change on its own via lease renewal is a worse lockout risk, not a smaller one.)
            </p>
          <?php endif; ?>

          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
        </form>

        <?php endif; ?>

        <div style="padding:0 14px 14px;">
          <a href="?iftab=physical" style="font-size:13px; color:#6b7280;">Back to Physical Interfaces</a>
        </div>
      </div>
      <script>
        function ntpToggleSubnetMode(mode) {
          var staticFields = document.getElementById('subnet-static-fields');
          if (staticFields) {
            staticFields.style.display = (mode === 'static') ? 'grid' : 'none';
          }
          var dhcpSection = document.getElementById('dhcp-server-section');
          if (!dhcpSection) { return; }
          var isDhcpClient = (mode === 'dhcp');
          dhcpSection.style.opacity = isDhcpClient ? '.5' : '1';
          dhcpSection.querySelectorAll('select, input').forEach(function (el) {
            el.disabled = isDhcpClient;
          });
          if (isDhcpClient) {
            var dhcpFields = document.getElementById('dhcp-fields');
            if (dhcpFields) { dhcpFields.style.display = 'none'; }
          } else {
            var dhcpEnabledSelect = document.getElementById('dhcp-enabled-select');
            var dhcpFields = document.getElementById('dhcp-fields');
            if (dhcpEnabledSelect && dhcpFields) {
              dhcpFields.style.display = (dhcpEnabledSelect.value === '1') ? 'grid' : 'none';
            }
          }
        }
      </script>
    <?php endif; ?>

    <div class="ntp-card">
      <div class="ntp-card-header">Network zones</div>
      <div class="ntp-table-scroll">
      <table class="ntp-table">
        <thead>
        <tr>
          <th>Zone</th>
          <th>Alias</th>
          <th>Interface</th>
          <th>Role</th>
          <th>Type</th>
          <th>IP</th>
          <th>Status</th>
          <th>Description</th>
          <th>Manage Interface</th>
        </tr>
        </thead>
        <tbody>
        <?php renderZoneRow('MGMT', $zones['mgmt'], 'Locked, cannot be reassigned', true, false); ?>
        <?php renderZoneRow('LAN1', $zones['lan1'], 'Trusted, full access to MGMT + internet', false, false, [], findVlanChildrenFor($zones['lan1']['interface'] ?? null, $vlans)); ?>
        <?php renderZoneRow('WAN1', $zones['wan1'], 'DHCP from upstream ISP', false, false, [], findVlanChildrenFor($zones['wan1']['interface'] ?? null, $vlans)); ?>
        <?php if (empty($zones['opt'])): ?>
          <tr><td colspan="9" style="color:#6b7280;">No OPT NICs detected on this system.</td></tr>
        <?php endif; ?>
        <?php foreach ($zones['opt'] as $i => $opt): ?>
          <?php
          // Kalau interface OPT ini adalah sebuah lagg (nama diawali
          // "lagg"), cari member-nya dari $laggGroups (sudah diambil di
          // atas) untuk dirender sebagai child row abu-abu - kalau
          // bukan lagg, array kosong (tidak ada child row sama sekali,
          // perilaku normal seperti sebelumnya).
          $optLaggMembers = [];
          foreach ($laggGroups as $g) {
              if (($g['interface'] ?? '') === ($opt['interface'] ?? '')) {
                  $optLaggMembers = $g['members'] ?? [];
                  break;
              }
          }
          $optVlanChildren = findVlanChildrenFor($opt['interface'] ?? null, $vlans);
          renderZoneRow('OPT' . ($i + 1), $opt, 'Not yet assigned a role', false, true, $optLaggMembers, $optVlanChildren);
          ?>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>
    </div>

  <?php elseif ($activeIfTab === 'wireguard'): ?>

    <div class="ntp-card">
      <div class="ntp-card-header">WireGuard VPN Interfaces</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Virtual tunnel interface (Type: VPN Tunnel) shown here for visibility, matching how FortiGate and
        Palo Alto surface tunnel interfaces (Network &gt; Interfaces &gt; Tunnel) — kept deliberately separate
        from Physical Interfaces, since a tunnel interface must never compete for a WAN1/LAN1/OPT slot (see
        Doc 7 §1.2a / RCA-20). This is read-only; full configuration (peers, listen port, subnet) lives on
        the <a href="/vpn.php">VPN</a> page, and firewall access is managed from
        <a href="/firewall.php?zone=wg0">Firewall &gt; wg0</a>.
      </p>
      <?php if ($vpnStatus && !empty($vpnStatus['installed'])): ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Interface</th><th>Type</th><th>Subnet</th><th>Status</th><th>Description</th></tr>
          </thead>
          <tbody>
          <tr>
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
            <td>WireGuard VPN — see <a href="/vpn.php?tab=peers">VPN &gt; Peers</a> for live connection status</td>
          </tr>
          </tbody>
        </table>
        </div>
        <p style="padding:12px 14px 0; font-size:11px; color:#9ca3af;">
          "Enabled" reflects the admin-configured state, not a live per-second service check (vpn.get_config
          doesn't expose one) — for real-time peer connection status (handshake timestamps, connected/disconnected),
          see <a href="/vpn.php?tab=peers">VPN &gt; Peers</a>.
        </p>
      <?php elseif ($vpnStatus): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
          No VPN tunnel interfaces configured yet. Install and enable WireGuard from the <a href="/vpn.php">VPN</a> page to add one.
        </p>
      <?php else: ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
          Unable to fetch WireGuard VPN status right now.
        </p>
      <?php endif; ?>
    </div>

  <?php elseif ($activeIfTab === 'ipsec'): ?>

    <div class="ntp-card">
      <div class="ntp-card-header">IPsec Interfaces</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Virtual tunnel interface (Type: VPN Tunnel) shown here for visibility, same pattern as the WireGuard
        tab. This is read-only; full configuration (Phase 1/Phase 2 tunnels, PSK, subnets) lives on the
        <a href="/ipsec.php">IPsec VPN</a> page, and firewall access is managed from
        <a href="/firewall.php?zone=enc0">Firewall &gt; enc0</a>.
      </p>
      <?php if ($ipsecStatus && !empty($ipsecStatus['installed'])): ?>
        <?php
        $ipsecTunnels = $ipsecStatus['tunnels'] ?? [];
        $anyEnabled = false;
        $allLocalSubnets = [];
        foreach ($ipsecTunnels as $t) {
            if (!empty($t['enabled'])) {
                $anyEnabled = true;
            }
            foreach (($t['phase2'] ?? []) as $p2) {
                if (!empty($p2['local_subnet'])) {
                    $allLocalSubnets[$p2['local_subnet']] = true;
                }
            }
        }
        $allLocalSubnets = array_keys($allLocalSubnets);
        ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Interface</th><th>Type</th><th>Tunnels (Phase 1)</th><th>Local Subnets</th><th>Status</th><th>Description</th></tr>
          </thead>
          <tbody>
          <tr>
            <td>enc0</td>
            <td>VPN Tunnel (IPsec)</td>
            <td><?= count($ipsecTunnels) ?></td>
            <td style="font-size:12px;">
              <?php if (empty($allLocalSubnets)): ?>
                <span style="color:#9ca3af;">—</span>
              <?php else: ?>
                <?= htmlspecialchars(implode(', ', $allLocalSubnets)) ?>
              <?php endif; ?>
            </td>
            <td>
              <?php if (empty($ipsecTunnels)): ?>
                <span class="ntp-badge ntp-badge-muted">No tunnels</span>
              <?php elseif ($anyEnabled): ?>
                <span class="ntp-badge ntp-badge-success">Enabled</span>
              <?php else: ?>
                <span class="ntp-badge ntp-badge-warning">Disabled</span>
              <?php endif; ?>
            </td>
            <td>IPsec Site-to-Site VPN — see <a href="/ipsec.php?tab=status">IPsec VPN &gt; Status</a> for live connection status</td>
          </tr>
          </tbody>
        </table>
        </div>
        <p style="padding:12px 14px 0; font-size:11px; color:#9ca3af;">
          enc0 is policy-based (not route-based like wg0) — it has no single IP/subnet of its own. Each tunnel's
          Phase 2 defines its own local↔remote subnet pair, which can be completely different per tunnel; "Local
          Subnets" above lists every one currently configured across all tunnels. "Enabled" means at least one
          Phase 1 tunnel is admin-enabled, not a live per-second service check — for real-time tunnel connection
          status, see <a href="/ipsec.php?tab=status">IPsec VPN &gt; Status</a>.
        </p>

      <?php elseif ($ipsecStatus): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
          IPsec is not configured yet. Install strongSwan from <a href="/package-manager.php">Package Manager</a>
          and add a Site-to-Site tunnel from the <a href="/ipsec.php">IPsec VPN</a> page to add one.
        </p>
      <?php else: ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">
          Unable to fetch IPsec status right now.
        </p>
      <?php endif; ?>
    </div>

  <?php elseif ($activeIfTab === 'lagg'): ?>

    <div class="ntp-card" style="margin-bottom:16px;">
      <div class="ntp-card-header">Existing Link Aggregation Groups</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Combines 2+ physical ports into one logical interface (<code>laggN</code>) for bandwidth aggregation
        and/or failover — matches FreeBSD's native <code>lagg(4)</code> driver. Once created, the resulting
        interface appears as a new OPT zone on the <a href="?iftab=physical">Physical Interfaces</a> tab, where
        you assign it a subnet/role/DHCP like any other OPT.
      </p>
      <?php if (empty($laggGroups)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No link aggregation groups configured yet.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Interface</th><th>Protocol</th><th>Member ports</th><th>IP</th><th>Manage</th></tr>
          </thead>
          <tbody>
          <?php foreach ($laggGroups as $g): ?>
            <tr>
              <td><?= htmlspecialchars($g['interface']) ?></td>
              <td><?= htmlspecialchars($g['protocol']) ?></td>
              <td><?= htmlspecialchars(implode(', ', $g['members'] ?? [])) ?></td>
              <td><?= htmlspecialchars($g['ip'] ?? '—') ?></td>
              <td>
                <a href="?iftab=lagg&edit_lagg=<?= urlencode($g['interface']) ?>" title="Edit (change protocol or member ports)" style="color:#374151; padding:4px; display:inline-block;">
                  <i class="ti ti-pencil" style="font-size:16px;" aria-hidden="true"></i>
                </a>
                <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete link aggregation group <?= htmlspecialchars($g['interface']) ?>? Member ports will need to be reassigned individually afterward if you want to use them again.');">
                  <input type="hidden" name="form" value="lagg_delete">
                  <input type="hidden" name="interface" value="<?= htmlspecialchars($g['interface']) ?>">
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
      <?php endif; ?>
    </div>

    <div class="ntp-card">
      <div class="ntp-card-header"><?= $editingLagg ? 'Edit "' . htmlspecialchars($editingLagg['interface']) . '"' : 'Create Link Aggregation Group' ?></div>
      <?php
      // Mode edit: gabungkan kandidat yang genuinely tersedia DENGAN
      // member interface GRUP INI SENDIRI (yang tidak lagi muncul di
      // $laggCandidates karena sudah "terpakai" oleh grup ini) - supaya
      // admin bisa lihat & pertahankan/lepas member yang sudah ada,
      // bukan cuma tambah yang baru.
      $formCandidates = $laggCandidates;
      $currentMembers = $editingLagg['members'] ?? [];
      if ($editingLagg) {
          $existingInterfaceNames = array_column($formCandidates, 'interface');
          foreach ($currentMembers as $m) {
              if (!in_array($m, $existingInterfaceNames, true)) {
                  $formCandidates[] = ['interface' => $m, 'alias' => null];
              }
          }
      }
      ?>
      <?php if (!$editingLagg && count($formCandidates) < 2): ?>
        <p style="padding:12px 14px 14px; font-size:12px; color:#6b7280;">
          Fewer than 2 eligible ports available. Only OPT interfaces with Role=Undefined and no custom Firewall
          rules can be used as LAGG members — free up at least 2 such ports first (via
          <a href="?iftab=physical">Physical Interfaces</a>) before creating a group.
        </p>
      <?php else: ?>
        <form method="post" style="padding:14px;">
          <input type="hidden" name="form" value="<?= $editingLagg ? 'lagg_edit' : 'lagg_create' ?>">
          <?php if ($editingLagg): ?>
            <input type="hidden" name="interface" value="<?= htmlspecialchars($editingLagg['interface']) ?>">
          <?php endif; ?>
          <p style="font-size:12px; color:#374151; margin:0 0 8px; font-weight:500;">Member ports (select 2 or more)</p>
          <div style="display:flex; flex-direction:column; gap:6px; margin-bottom:14px;">
            <?php foreach ($formCandidates as $c): ?>
              <label style="font-size:13px; display:flex; align-items:center; gap:8px;">
                <input type="checkbox" name="members[]" value="<?= htmlspecialchars($c['interface']) ?>" <?= in_array($c['interface'], $currentMembers, true) ? 'checked' : '' ?>>
                <?= htmlspecialchars($c['interface']) ?>
                <?php if (!empty($c['alias'])): ?>
                  <span style="color:#9ca3af;">(<?= htmlspecialchars($c['alias']) ?>)</span>
                <?php endif; ?>
              </label>
            <?php endforeach; ?>
          </div>

          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Protocol</label>
          <select name="protocol" style="width:100%; margin-bottom:6px;">
            <?php $curProto = $editingLagg['protocol'] ?? 'failover'; ?>
            <option value="failover" <?= $curProto === 'failover' ? 'selected' : '' ?>>Failover — redundancy only, no switch config needed</option>
            <option value="lacp" <?= $curProto === 'lacp' ? 'selected' : '' ?>>LACP (802.3ad) — bandwidth + failover, switch must support LACP</option>
            <option value="loadbalance" <?= $curProto === 'loadbalance' ? 'selected' : '' ?>>Load balance — static hash, no switch cooperation needed</option>
            <option value="roundrobin" <?= $curProto === 'roundrobin' ? 'selected' : '' ?>>Round robin — max throughput, can reorder packets</option>
          </select>
          <p style="font-size:11px; color:#9ca3af; margin:0 0 14px;">
            "Failover" works with any switch (even unmanaged) but only uses one port at a time. "LACP" gives real
            combined bandwidth but needs the connected switch port(s) configured for LACP too — mismatched
            configuration on the switch side is the most common reason LACP doesn't come up.
            <?php if ($editingLagg): ?>
              Changes here apply live (add/remove member ports, change protocol) without destroying and
              recreating <?= htmlspecialchars($editingLagg['interface']) ?> - matches FreeBSD's native <code>lagg(4)</code> behavior.
            <?php endif; ?>
          </p>

          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">
            <?= $editingLagg ? 'Update Link Aggregation Group' : 'Create Link Aggregation Group' ?>
          </button>
          <?php if ($editingLagg): ?>
            <a href="?iftab=lagg" style="margin-left:10px; font-size:13px; color:#6b7280;">Cancel</a>
          <?php endif; ?>
        </form>
      <?php endif; ?>
    </div>

  <?php elseif ($activeIfTab === 'leases'): ?>

    <div class="ntp-card">
      <div class="ntp-card-header" style="display:flex; align-items:center; justify-content:space-between;">
        <span>DHCP Leases</span>
        <input type="text" id="leases-search" placeholder="Search leases..." style="font-size:12px; padding:5px 10px; border:1px solid #d1d5db; border-radius:6px; width:220px;">
      </div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Devices currently holding an IP address from an active DHCP server on this gateway. Data is read live
        from the Kea DHCP lease database — refresh this page to see updates.
      </p>
      <?php if (empty($dhcpLeases)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No active leases found. Enable a DHCP server on an interface (Physical Interfaces tab) and connect a client to see leases here.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table" id="leases-table">
          <thead>
          <tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Lease Start</th><th>Lease Expires</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
          <?php foreach ($dhcpLeases as $lease): ?>
            <tr>
              <td><?= htmlspecialchars($lease['ip']) ?></td>
              <td><code><?= htmlspecialchars($lease['mac']) ?></code></td>
              <td><?= htmlspecialchars($lease['hostname']) ?></td>
              <td><?= htmlspecialchars($lease['lease_start']) ?></td>
              <td><?= htmlspecialchars($lease['lease_expire']) ?></td>
              <td>
                <?php if (!empty($lease['is_static'])): ?>
                  <span class="ntp-badge ntp-badge-info">Static</span>
                <?php elseif (!empty($lease['active'])): ?>
                  <span class="ntp-badge ntp-badge-success">Active</span>
                <?php else: ?>
                  <span class="ntp-badge ntp-badge-muted">Expired</span>
                <?php endif; ?>
              </td>
              <td>
                <?php if (empty($lease['is_static'])): ?>
                  <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Make <?= htmlspecialchars($lease['ip']) ?> a permanent static reservation for this device?');">
                    <input type="hidden" name="form" value="dhcp_make_static">
                    <input type="hidden" name="interface" value="<?= htmlspecialchars($lease['interface'] ?? '') ?>">
                    <input type="hidden" name="mac" value="<?= htmlspecialchars($lease['mac']) ?>">
                    <input type="hidden" name="ip" value="<?= htmlspecialchars($lease['ip']) ?>">
                    <input type="hidden" name="hostname" value="<?= htmlspecialchars($lease['hostname']) ?>">
                    <button type="submit" title="Make Static" style="background:none; border:none; cursor:pointer; color:#14213d; padding:4px; font-size:11px;">
                      <i class="ti ti-pin" style="font-size:14px;" aria-hidden="true"></i> Make Static
                    </button>
                  </form>
                <?php else: ?>
                  <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Remove static reservation for <?= htmlspecialchars($lease['ip']) ?>? This device will get a new dynamic IP next time.');">
                    <input type="hidden" name="form" value="dhcp_remove_reservation">
                    <input type="hidden" name="mac" value="<?= htmlspecialchars($lease['mac']) ?>">
                    <button type="submit" title="Remove Reservation" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                      <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
                    </button>
                  </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>
    </div>
    <script>
    (function () {
        var searchBox = document.getElementById('leases-search');
        var table = document.getElementById('leases-table');
        if (!searchBox || !table) { return; }
        searchBox.addEventListener('input', function () {
            var q = searchBox.value.toLowerCase();
            table.querySelectorAll('tbody tr').forEach(function (row) {
                row.style.display = row.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
            });
        });
    })();
    </script>

  <?php elseif ($activeIfTab === 'loopback'): ?>

    <div class="ntp-card" style="margin-bottom:16px;">
      <div class="ntp-card-header">Existing Loopback Interfaces</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Virtual interfaces (<code>loN</code>) that are never down and not tied to any physical port — commonly used
        for router-ID style addressing, service endpoints, or loopback-based health checks (matches Juniper/Cisco
        loopback conventions). <code>lo0</code> is FreeBSD's built-in loopback (127.0.0.1) and is locked/read-only;
        additional loopbacks (<code>lo1</code>, <code>lo2</code>, ...) can be created and removed below. Each
        loopback holds a single IP address.
      </p>
      <?php if (empty($loopbacks)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No loopback interfaces found.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Interface</th><th>IP</th><th>Status</th><th>Manage</th></tr>
          </thead>
          <tbody>
          <?php foreach ($loopbacks as $lo): ?>
            <tr<?= !empty($lo['locked']) ? ' style="color:#9ca3af;"' : '' ?>>
              <td><?= htmlspecialchars($lo['interface']) ?></td>
              <td><?= htmlspecialchars($lo['ip'] ?? '—') ?></td>
              <td>
                <?php if (!empty($lo['locked'])): ?>
                  <span class="ntp-badge ntp-badge-muted">System (locked)</span>
                <?php elseif ($lo['ip']): ?>
                  <span class="ntp-badge ntp-badge-success">Active</span>
                <?php else: ?>
                  <span class="ntp-badge ntp-badge-muted">Unknown</span>
                <?php endif; ?>
              </td>
              <td>
                <?php if (empty($lo['locked'])): ?>
                  <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete loopback interface <?= htmlspecialchars($lo['interface']) ?>?');">
                    <input type="hidden" name="form" value="loopback_delete">
                    <input type="hidden" name="interface" value="<?= htmlspecialchars($lo['interface']) ?>">
                    <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;">
                      <i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i>
                    </button>
                  </form>
                <?php else: ?>
                  <span style="font-size:11px;">—</span>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>
    </div>

    <div class="ntp-card">
      <div class="ntp-card-header">Create Loopback Interface</div>
      <form method="post" style="padding:14px;">
        <input type="hidden" name="form" value="loopback_create">
        <div style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
          <div style="flex:1; min-width:160px;">
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">IP Address</label>
            <input type="text" name="ip" placeholder="e.g. 10.255.0.1" required style="width:100%;">
          </div>
          <div style="width:110px;">
            <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Prefix</label>
            <select name="prefix" style="width:100%;">
              <?php for ($p = 32; $p >= 1; $p--): ?>
                <option value="<?= $p ?>" <?= $p === 32 ? 'selected' : '' ?>>/<?= $p ?></option>
              <?php endfor; ?>
            </select>
          </div>
        </div>
        <p style="font-size:11px; color:#9ca3af; margin:10px 0 14px;">
          The next available name (<code>lo1</code>, <code>lo2</code>, ...) is assigned automatically. A single
          host IP per loopback — this does not need to match any physical subnet, but it must not collide with
          an IP already in use on any other interface (physical, LAGG, or loopback) on this gateway.
        </p>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">
          Create Loopback Interface
        </button>
      </form>
    </div>

  <?php elseif ($activeIfTab === 'vlan_database'): ?>

    <div class="ntp-card" style="margin-bottom:16px;">
      <div class="ntp-card-header">VLAN Database</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        Pure VLAN identity - ID and Name only, same as Cisco's <code>vlan 10</code> + <code>name dosen</code>.
        No parent or IP is involved here yet; a VLAN can exist in this database with no interface using it at
        all (Status shows "not bound"), exactly like an unused VLAN on a Cisco switch. Once defined here, use
        the <a href="?iftab=vlan">VLAN Interfaces</a> tab to bind it to a parent (Physical/LAGG) and give it an
        IP - equivalent to Cisco's <code>interface vlan10</code> + <code>ip address ...</code>.
      </p>
      <?php if (empty($vlanDbEntries)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No VLANs defined yet.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>VLAN</th><th>Name</th><th>Status</th><th>Interface(s)</th><th>Manage</th></tr>
          </thead>
          <tbody>
          <?php foreach ($vlanDbEntries as $entry): ?>
            <tr>
              <td><?= htmlspecialchars((string) $entry['id']) ?></td>
              <td><?= htmlspecialchars($entry['name']) ?></td>
              <td>
                <?php if (($entry['status'] ?? '') === 'active'): ?>
                  <span class="ntp-badge ntp-badge-success">active</span>
                <?php else: ?>
                  <span class="ntp-badge ntp-badge-muted">not bound</span>
                <?php endif; ?>
              </td>
              <td style="font-size:12px;">
                <?php if (empty($entry['interfaces'])): ?>
                  <span style="color:#9ca3af;">—</span>
                <?php else: ?>
                  <?php foreach ($entry['interfaces'] as $i => $bound): ?><?= $i > 0 ? ', ' : '' ?><?= htmlspecialchars($bound['interface']) ?> (<?= htmlspecialchars($bound['parent']) ?>)<?php endforeach; ?>
                <?php endif; ?>
              </td>
              <td>
                <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Remove VLAN <?= htmlspecialchars((string) $entry['id']) ?> (<?= htmlspecialchars($entry['name']) ?>) from the VLAN Database?');">
                  <input type="hidden" name="form" value="vlan_db_delete">
                  <input type="hidden" name="id" value="<?= htmlspecialchars((string) $entry['id']) ?>">
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
      <?php endif; ?>
    </div>

    <div class="ntp-card">
      <div class="ntp-card-header">Add VLAN</div>
      <form method="post" style="padding:14px; display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
        <input type="hidden" name="form" value="vlan_db_create">
        <div style="width:140px;">
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">VLAN ID</label>
          <input type="number" name="id" min="1" max="4094" placeholder="e.g. 10" required style="width:100%;">
        </div>
        <div style="flex:1; min-width:200px;">
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
          <input type="text" name="name" maxlength="32" placeholder="e.g. dosen" required style="width:100%;">
        </div>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add VLAN</button>
      </form>
      <p style="padding:0 14px 14px; font-size:11px; color:#9ca3af;">
        Valid VLAN ID range is 1-4094 (0 and 4095 are reserved by the 802.1Q standard).
      </p>
    </div>

  <?php elseif ($activeIfTab === 'vlan'): ?>

    <div class="ntp-card" style="margin-bottom:16px;">
      <div class="ntp-card-header">Existing VLAN Interfaces</div>
      <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
        802.1Q tagged sub-interfaces terminated on this gateway (router-on-a-stick style) - matches how
        FortiGate/pfSense/Palo Alto all handle VLAN termination. The parent carries traffic for one or more VLANs
        tagged with the ID selected below; parent and VLAN ID cannot be changed after creation (matching
        FortiGate) - delete and recreate instead if you need to change either.
      </p>
      <p style="padding:0 14px 12px; font-size:12px; color:#6b7280;">
        This is the "binding" step (Cisco's SVI): pick a VLAN already defined on the <a href="?iftab=vlan_database">VLAN
        Database</a> tab and a parent interface to terminate it on. Parent and VLAN ID cannot be changed after
        creation - delete and recreate instead. Click the
        <i class="ti ti-pencil" style="font-size:13px; vertical-align:-2px;" aria-hidden="true"></i> <strong>Edit</strong>
        icon below to assign a subnet, Role, and DHCP server (equivalent to Cisco's <code>interface vlan10</code>
        + <code>ip address ...</code>).
      </p>
      <?php if (empty($vlans)): ?>
        <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">No VLAN interfaces found.</p>
      <?php else: ?>
        <div class="ntp-table-scroll">
        <table class="ntp-table">
          <thead>
          <tr><th>Interface</th><th>Name</th><th>VLAN ID</th><th>Parent</th><th>IP</th><th>Manage</th></tr>
          </thead>
          <tbody>
          <?php foreach ($vlans as $v): ?>
            <tr>
              <td><?= htmlspecialchars($v['interface']) ?></td>
              <td><?= htmlspecialchars($v['alias'] ?? '') ?: '<span style="color:#9ca3af;">(unnamed)</span>' ?></td>
              <td><?= htmlspecialchars((string) $v['tag']) ?></td>
              <td><?= htmlspecialchars($v['parent']) ?></td>
              <td><?= htmlspecialchars(($v['ip'] ?? null) ? $v['ip'] . (isset($v['prefix']) && $v['prefix'] !== null ? '/' . $v['prefix'] : '') : '—') ?></td>
              <td>
                <a href="?iftab=physical&manage=<?= urlencode($v['interface']) ?>" title="Edit - assign Name, subnet, Role, DHCP" style="color:#374151; padding:4px; display:inline-block;">
                  <i class="ti ti-pencil" style="font-size:16px;" aria-hidden="true"></i>
                </a>
                <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete VLAN interface <?= htmlspecialchars($v['interface']) ?> (tag <?= htmlspecialchars((string) $v['tag']) ?>)?');">
                  <input type="hidden" name="form" value="vlan_delete">
                  <input type="hidden" name="interface" value="<?= htmlspecialchars($v['interface']) ?>">
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
      <?php endif; ?>
    </div>

    <div class="ntp-card">
      <div class="ntp-card-header">Create VLAN Interface</div>
      <?php if (empty($vlanParents)): ?>
        <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
          No eligible parent interface found. LAN1, WAN1, OPT, and LAGG interfaces can all be used as a VLAN
          parent (MGMT and existing VLAN interfaces cannot).
        </p>
      <?php elseif (empty($vlanDbEntries)): ?>
        <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
          No VLANs defined yet. Add one on the <a href="?iftab=vlan_database">VLAN Database</a> tab first
          (ID + Name) before it can be bound to a parent interface here - same as Cisco requiring
          <code>vlan 10</code> to exist before <code>switchport access vlan 10</code> will work.
        </p>
      <?php else: ?>
        <form method="post" style="padding:14px;">
          <input type="hidden" name="form" value="vlan_create">
          <div style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
            <div style="width:220px;">
              <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">VLAN</label>
              <select name="tag" style="width:100%;">
                <?php foreach ($vlanDbEntries as $entry): ?>
                  <option value="<?= htmlspecialchars((string) $entry['id']) ?>"><?= htmlspecialchars((string) $entry['id']) ?> - <?= htmlspecialchars($entry['name']) ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div style="flex:1; min-width:220px;">
              <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Parent interface</label>
              <select name="parent" id="vlan-parent-select" style="width:100%;" onchange="var w=document.getElementById('vlan-parent-ip-warning'); var opt=this.options[this.selectedIndex]; w.style.display = (opt.dataset.hasIp === '1') ? 'block' : 'none';">
                <?php foreach ($vlanParents as $p): ?>
                  <option value="<?= htmlspecialchars($p['interface']) ?>" data-has-ip="<?= !empty($p['has_ip']) ? '1' : '0' ?>">
                    <?= htmlspecialchars($p['interface']) ?><?= !empty($p['alias']) ? ' (' . htmlspecialchars($p['alias']) . ')' : '' ?><?= !empty($p['has_ip']) ? ' - has IP' : ' - recommended, no IP' ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>
          </div>
          <p id="vlan-parent-ip-warning" style="display:none; font-size:11px; color:#9a5b00; background:#fff8e6; border:1px solid #f5d78e; border-radius:6px; padding:8px 10px; margin:10px 0 0;">
            ⚠️ This parent already has its own IP. Untagged traffic on this port will continue to reach its
            existing zone directly - only traffic tagged with this VLAN ID reaches the new interface. This
            mirrors Cisco's "native VLAN" behavior; make sure your switch's trunk configuration matches what
            you intend. For a cleaner, dedicated trunk with no mixed untagged traffic, pick an OPT interface
            with no IP assigned instead.
          </p>
          <p style="font-size:11px; color:#9ca3af; margin:10px 0 14px;">
            The interface is named directly after the VLAN ID (e.g. VLAN 10 becomes <code>vlan10</code>) -
            no confusing separate numbering to keep track of. After creation this VLAN appears as a new OPT
            zone below on the Physical Interfaces tab, where you can assign it a subnet, Role, and DHCP server
            just like any other zone.
          </p>
          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">
            Create VLAN Interface
          </button>
        </form>
      <?php endif; ?>
    </div>

  <?php endif; ?>
<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
