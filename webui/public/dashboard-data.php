<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
Auth::requireLogin();

// Endpoint ringan KHUSUS untuk auto-refresh Dashboard (dipoll JS setiap
// beberapa detik) - reuse 4 action yang SAMA dipakai index.php, cuma
// hasilnya digabung jadi satu JSON polos, bukan HTML penuh. Tetap lewat
// Auth::requireLogin() - endpoint ini TIDAK boleh diakses tanpa sesi
// login yang valid, sama seperti setiap halaman lain di Web UI.
header('Content-Type: application/json');

$configd = new NtpsenseConfigd();

$result = [
    'dashInfo' => null,
    'zones' => null,
    'vpnStatus' => null,
    'ipsecStatus' => null,
    'error' => null,
];

try {
    $result['dashInfo'] = $configd->call('system.get_dashboard_info');
} catch (NtpsenseConfigdException $e) {
    $result['error'] = $e->getMessage();
}
try {
    $result['zones'] = $configd->call('network.zones');
} catch (NtpsenseConfigdException $e) {
    // Non-fatal - widget Interfaces di JS menangani null secara terpisah.
}
try {
    $result['vpnStatus'] = $configd->call('vpn.get_config');
} catch (NtpsenseConfigdException $e) {
    // Non-fatal.
}
try {
    $result['ipsecStatus'] = $configd->call('ipsec.get_config');
} catch (NtpsenseConfigdException $e) {
    // Non-fatal.
}

echo json_encode($result);
