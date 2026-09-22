<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
Auth::requireLogin();

// Endpoint ringan KHUSUS untuk widget Traffic Graphs (dipoll JS setiap
// beberapa detik) - JS yang hitung selisih (rate kbps) antar dua
// polling sendiri, server cuma kirim counter kumulatif mentah + waktu
// server saat ini (supaya JS bisa hitung elapsed time SEBENARNYA,
// bukan asumsi persis sama dengan interval polling).
header('Content-Type: application/json');

$configd = new NtpsenseConfigd();

try {
    $result = $configd->call('network.get_interface_traffic');
    echo json_encode($result);
} catch (NtpsenseConfigdException $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
