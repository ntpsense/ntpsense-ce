<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
require_once __DIR__ . '/../lib/NtpsenseConfigd.php';
// ExternalAuth.php SUDAH ter-include lewat Auth.php sendiri (require_once
// di dalamnya) - baris require terpisah di sini yang SEBELUMNYA ada
// menyebabkan file itu ke-load DUA KALI (pakai 'require' biasa, bukan
// 'require_once'), bikin PHP fatal "Cannot redeclare class". Cukup
// pakai method statis ExternalAuth::... langsung di bawah, class-nya
// sudah pasti tersedia tanpa require eksplisit lagi di sini.

Auth::requireLogin();
Auth::requireAdministrator();

$configd = new NtpsenseConfigd();

if (isset($_GET['download'])) {
    $filename = basename((string) $_GET['download']);
    $path = '/usr/local/etc/ntpsense/backups/' . $filename;
    if (str_contains($filename, '..') || !preg_match('/^ntpsense-backup-\d+-[0-9a-f]{16}\.tar\.gz$/', $filename) || !is_file($path)) {
        http_response_code(404);
        echo 'Backup file not found.';
        exit;
    }
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

$info = null;
$configdError = null;
$saveMessage = null;
$saveError = null;
$backups = [];
$backupError = null;
$backupMessage = null;
$restoreWarning = null;
$certStatus = null;
$certError = null;
$certMessage = null;
$userError = null;
$userMessage = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'user_create') {
    try {
        Auth::createUser((string) ($_POST['username'] ?? ''), (string) ($_POST['password'] ?? ''), (string) ($_POST['role'] ?? Auth::ADMINISTRATOR_ROLE));
        $userMessage = 'Admin account created. It must change its password on first login.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'user_change_role') {
    try {
        Auth::changeUserRole((string) ($_POST['username'] ?? ''), (string) ($_POST['role'] ?? ''));
        $userMessage = 'Role updated.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'role_create') {
    try {
        $permissions = [];
        foreach (Auth::ASSIGNABLE_CATEGORIES as $cat) {
            $permissions[$cat] = (string) ($_POST['perm_' . $cat] ?? 'none');
        }
        Auth::createRole((string) ($_POST['role_name'] ?? ''), $permissions);
        $userMessage = 'Role created.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'role_update') {
    try {
        $permissions = [];
        foreach (Auth::ASSIGNABLE_CATEGORIES as $cat) {
            $permissions[$cat] = (string) ($_POST['perm_' . $cat] ?? 'none');
        }
        Auth::updateRole((string) ($_POST['role_name'] ?? ''), $permissions);
        $userMessage = 'Role updated.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'role_delete') {
    try {
        Auth::deleteRole((string) ($_POST['role_name'] ?? ''));
        $userMessage = 'Role deleted.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'user_delete') {
    try {
        Auth::deleteUser((string) ($_POST['username'] ?? ''));
        $userMessage = 'Admin account deleted.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'user_reset_password') {
    try {
        Auth::resetPassword((string) ($_POST['username'] ?? ''), (string) ($_POST['new_password'] ?? ''));
        $userMessage = 'Password reset. That account must set a new password on its next login.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
    }
}

$totpSetup = null;
$totpRecoveryCodes = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'totp_setup_begin') {
    $totpSetup = Auth::beginTotpSetup();
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'totp_setup_confirm') {
    try {
        $totpRecoveryCodes = Auth::confirmTotpSetup((string) ($_POST['code'] ?? ''));
        $userMessage = 'Two-factor authentication enabled. Save your recovery codes below now - they will not be shown again.';
    } catch (InvalidArgumentException $e) {
        $userError = $e->getMessage();
        $pendingSecret = (string) ($_SESSION['ntpsense_totp_setup_secret'] ?? '');
        if ($pendingSecret !== '') {
            $issuer = 'NTPSense';
            $label = rawurlencode("{$issuer}:" . Auth::currentUsername());
            $totpSetup = [
                'secret' => $pendingSecret,
                'otpauth_uri' => "otpauth://totp/{$label}?secret={$pendingSecret}&issuer=" . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30',
            ];
        }
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'totp_setup_cancel') {
    unset($_SESSION['ntpsense_totp_setup_secret']);
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'totp_disable') {
    Auth::disableTotp();
    $userMessage = 'Two-factor authentication disabled for your account.';
}

$dtMessage = null;
$dtError = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_timezone') {
    try {
        $configd->call('system.set_timezone', ['timezone' => (string) ($_POST['timezone'] ?? '')]);
        $dtMessage = 'Timezone updated.';
    } catch (NtpsenseConfigdException $e) {
        $dtError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_manual_time') {
    try {
        $configd->call('system.set_manual_time', ['datetime' => (string) ($_POST['datetime'] ?? '')]);
        $dtMessage = 'System time set manually. NTP has been disabled - re-enable it once this gateway can reach the internet again.';
    } catch (NtpsenseConfigdException $e) {
        $dtError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'enable_ntp') {
    try {
        $configd->call('system.enable_ntp');
        $dtMessage = 'NTP re-enabled.';
    } catch (NtpsenseConfigdException $e) {
        $dtError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'cert_regenerate') {
    try {
        $result = $configd->call('system.cert_regenerate', [], 20.0);
        $certMessage = 'New self-signed certificate generated and applied (SAN: ' . implode(', ', $result['san'] ?? []) . '). '
            . 'Browsers will still show a security warning since this is self-signed - that\'s expected, same as before.';
        if (empty($result['lighttpd_running'])) {
            $certMessage .= ' Warning: lighttpd did not report as running right after the restart - reload this page in a few seconds to confirm the Web UI came back up.';
        }
    } catch (NtpsenseConfigdException $e) {
        $certError = $e->getMessage();
    }
}

$maintenanceMessage = null;
$maintenanceError = null;
$maintenanceCountdown = null;
$maintenanceRedirectTo = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'system_reboot') {
    try {
        $configd->call('system.reboot');
        $maintenanceMessage = 'Rebooting now - this page (and the whole gateway) will be unreachable for a minute or two. Reconnect once it comes back up.';
        $maintenanceCountdown = 60;
        $maintenanceRedirectTo = '/index.php';
    } catch (NtpsenseConfigdException $e) {
        $maintenanceError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'system_restart_services') {
    try {
        $configd->call('system.restart_services', [], 30.0);
        $maintenanceMessage = 'All services restarted (no OS reboot) - the gateway itself never went down, only the individual services (web UI, proxy, DHCP, IDS, VPN, firewall reload).';
        $maintenanceCountdown = 15;
        $maintenanceRedirectTo = '/index.php';
    } catch (NtpsenseConfigdException $e) {
        $maintenanceError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'system_factory_reset') {
    try {
        $confirmText = (string) ($_POST['confirm_text'] ?? '');
        $configd->call('system.factory_reset', ['confirm_text' => $confirmText], 30.0);
        $maintenanceMessage = 'Factory reset complete - rebooting now. The gateway will come back up with a fresh installation state; reconnect in a minute or two and log in with admin/admin.';
        $maintenanceCountdown = 60;
        $maintenanceRedirectTo = '/login.php';
    } catch (NtpsenseConfigdException $e) {
        $maintenanceError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'cert_upload') {
    $certFile = $_FILES['cert_file'] ?? null;
    $keyFile = $_FILES['key_file'] ?? null;
    if (empty($certFile['tmp_name']) || !is_uploaded_file($certFile['tmp_name']) || empty($keyFile['tmp_name']) || !is_uploaded_file($keyFile['tmp_name'])) {
        $certError = 'Both a certificate file and a private key file are required.';
    } else {
        $certPem = (string) file_get_contents($certFile['tmp_name']);
        $keyPem = (string) file_get_contents($keyFile['tmp_name']);
        try {
            $result = $configd->call('system.cert_upload', ['cert_pem' => $certPem, 'key_pem' => $keyPem], 20.0);
            $certMessage = 'Certificate uploaded and applied successfully.';
            if (empty($result['lighttpd_running'])) {
                $certMessage .= ' Warning: lighttpd did not report as running right after the restart - reload this page in a few seconds to confirm the Web UI came back up.';
            }
        } catch (NtpsenseConfigdException $e) {
            $certError = $e->getMessage();
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'system_settings') {
    try {
        $params = [
            'hostname' => trim((string) ($_POST['hostname'] ?? '')),
            'ntp_servers' => array_values(array_filter(array_map('trim', explode("\n", (string) ($_POST['ntp_servers'] ?? ''))))),
        ];
        $result = $configd->call('system.update', $params);
        $saveMessage = 'Saved: ' . implode(', ', $result['applied'] ?? []);
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'set_dns_servers') {
    try {
        $dnsServers = array_values(array_filter(array_map('trim', explode("\n", (string) ($_POST['dns_servers'] ?? '')))));
        $configd->call('system.set_dns_servers', ['servers' => $dnsServers]);
        $saveMessage = 'DNS servers updated.';
    } catch (NtpsenseConfigdException $e) {
        $saveError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'backup_create') {
    try {
        $result = $configd->call('system.backup_create');
        $backupMessage = 'Backup created: ' . ($result['filename'] ?? '');
    } catch (NtpsenseConfigdException $e) {
        $backupError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'backup_delete') {
    try {
        $configd->call('system.backup_delete', ['filename' => (string) ($_POST['filename'] ?? '')]);
        $backupMessage = 'Backup deleted.';
    } catch (NtpsenseConfigdException $e) {
        $backupError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'backup_restore') {
    try {
        $result = $configd->call('system.backup_restore', [
            'filename' => (string) ($_POST['filename'] ?? ''),
            'confirm' => ($_POST['confirm'] ?? '') === '1',
        ]);
        if (!empty($result['warning'])) {
            $restoreWarning = $result;
            $restoreWarning['filename'] = (string) ($_POST['filename'] ?? '');
        } else {
            $backupMessage = 'Configuration restored from ' . ($result['restored'] ?? '') . '.';
        }
    } catch (NtpsenseConfigdException $e) {
        $backupError = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'backup_upload') {
    if (!empty($_FILES['backup_file']['tmp_name']) && is_uploaded_file($_FILES['backup_file']['tmp_name'])) {
        $originalName = basename((string) $_FILES['backup_file']['name']);
        $tempDest = '/tmp/ntpsense-upload-' . bin2hex(random_bytes(8)) . '.tar.gz';
        if (!preg_match('/^ntpsense-backup-\d+-[0-9a-f]{16}\.tar\.gz$/', $originalName)) {
            $backupError = 'File name does not match the expected signed backup format - it will be rejected on restore anyway, refusing upload.';
        } elseif (!move_uploaded_file($_FILES['backup_file']['tmp_name'], $tempDest)) {
            $backupError = 'Failed to receive the uploaded file.';
        } else {
            try {
                $configd->call('system.backup_import', ['temp_path' => $tempDest, 'original_filename' => $originalName]);
                $backupMessage = 'Backup uploaded successfully. You can now restore it from the list below.';
            } catch (NtpsenseConfigdException $e) {
                $backupError = $e->getMessage();
            }
        }
    } else {
        $backupError = 'No file was uploaded.';
    }
}

$authMessage = null;
$authError = null;
$authTestResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'auth_toggle') {
    $cfg = ExternalAuth::getConfig();
    $cfg['radius_enabled'] = isset($_POST['radius_enabled']);
    $cfg['ldap_enabled'] = isset($_POST['ldap_enabled']);
    ExternalAuth::setConfig($cfg);
    $authMessage = 'Settings saved.';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'radius_server_add') {
    $cfg = ExternalAuth::getConfig();
    $cfg['radius_servers'][] = [
        'name' => (string) ($_POST['name'] ?? ''),
        'host' => (string) ($_POST['host'] ?? ''),
        'port' => (string) ($_POST['port'] ?? '1812'),
        'secret' => (string) ($_POST['secret'] ?? ''),
        'timeout' => (string) ($_POST['timeout'] ?? '5'),
    ];
    ExternalAuth::setConfig($cfg);
    $authMessage = 'RADIUS server added.';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'radius_server_delete') {
    $cfg = ExternalAuth::getConfig();
    $idx = (int) ($_POST['index'] ?? -1);
    if (isset($cfg['radius_servers'][$idx])) {
        array_splice($cfg['radius_servers'], $idx, 1);
        ExternalAuth::setConfig($cfg);
        $authMessage = 'RADIUS server removed.';
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ldap_server_add') {
    $cfg = ExternalAuth::getConfig();
    $cfg['ldap_servers'][] = [
        'name' => (string) ($_POST['name'] ?? ''),
        'host' => (string) ($_POST['host'] ?? ''),
        'port' => (string) ($_POST['port'] ?? '389'),
        'use_tls' => isset($_POST['use_tls']),
        'user_dn_template' => (string) ($_POST['user_dn_template'] ?? ''),
        'group_attribute' => (string) ($_POST['group_attribute'] ?? 'memberOf'),
    ];
    ExternalAuth::setConfig($cfg);
    $authMessage = 'LDAP server added.';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'ldap_server_delete') {
    $cfg = ExternalAuth::getConfig();
    $idx = (int) ($_POST['index'] ?? -1);
    if (isset($cfg['ldap_servers'][$idx])) {
        array_splice($cfg['ldap_servers'], $idx, 1);
        ExternalAuth::setConfig($cfg);
        $authMessage = 'LDAP server removed.';
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_map_add') {
    $cfg = ExternalAuth::getConfig();
    $cfg['group_role_map'][] = [
        'external_group' => (string) ($_POST['external_group'] ?? ''),
        'local_role' => (string) ($_POST['local_role'] ?? ''),
    ];
    ExternalAuth::setConfig($cfg);
    $authMessage = 'Group mapping added.';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'group_map_delete') {
    $cfg = ExternalAuth::getConfig();
    $idx = (int) ($_POST['index'] ?? -1);
    if (isset($cfg['group_role_map'][$idx])) {
        array_splice($cfg['group_role_map'], $idx, 1);
        ExternalAuth::setConfig($cfg);
        $authMessage = 'Group mapping removed.';
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'auth_test_radius') {
    $cfg = ExternalAuth::getConfig();
    $idx = (int) ($_POST['index'] ?? -1);
    if (isset($cfg['radius_servers'][$idx])) {
        $authTestResult = ExternalAuth::testRadius($cfg['radius_servers'][$idx], (string) ($_POST['test_username'] ?? ''), (string) ($_POST['test_password'] ?? ''));
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'auth_test_ldap') {
    $cfg = ExternalAuth::getConfig();
    $idx = (int) ($_POST['index'] ?? -1);
    if (isset($cfg['ldap_servers'][$idx])) {
        $authTestResult = ExternalAuth::testLdap($cfg['ldap_servers'][$idx], (string) ($_POST['test_username'] ?? ''), (string) ($_POST['test_password'] ?? ''));
    }
}

try {
    $info = $configd->call('system.info');
} catch (NtpsenseConfigdException $e) {
    $configdError = $e->getMessage();
}
$dnsServers = [];
try {
    $dnsServers = $configd->call('system.dns_status')['servers'] ?? [];
} catch (NtpsenseConfigdException $e) {
}
try {
    $backups = $configd->call('system.backup_list')['backups'] ?? [];
} catch (NtpsenseConfigdException $e) {
}

$requestedTab = $_GET['tab'] ?? 'general';
$activeTab = in_array($requestedTab, ['backup', 'certificates', 'users', 'roles', 'maintenance', 'datetime', 'apikeys', 'authentication'], true) ? $requestedTab : 'general';

if ($activeTab === 'certificates') {
    try {
        $certStatus = $configd->call('system.cert_get_status');
        try {
            $configd->call('system.alerts_acknowledge', ['source' => 'certificate']);
        } catch (NtpsenseConfigdException $e) {
        }
    } catch (NtpsenseConfigdException $e) {
        if ($certError === null) {
            $certError = $e->getMessage();
        }
    }
}

$timeStatus = null;
$timezoneList = [];
if ($activeTab === 'datetime') {
    try {
        $timeStatus = $configd->call('system.time_status');
        $timezoneList = $configd->call('system.list_timezones')['timezones'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        if ($dtError === null) {
            $dtError = $e->getMessage();
        }
    }
}

$apiKeyError = null;
$apiKeyMessage = null;
$newApiKeyToken = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'apikey_create') {
    try {
        $created = $configd->call('apikey.create', [
            'name' => (string) ($_POST['name'] ?? ''),
            'permission' => (($_POST['permission'] ?? '') === 'full') ? 'full' : 'read',
            'trusted_ip' => (string) ($_POST['trusted_ip'] ?? ''),
        ]);
        $newApiKeyToken = $created['token'] ?? null;
        $apiKeyMessage = 'API key "' . htmlspecialchars($created['name'] ?? '') . '" created. Copy the token now - it will never be shown again.';
    } catch (NtpsenseConfigdException $e) {
        $apiKeyError = $e->getMessage();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form'] ?? '') === 'apikey_revoke') {
    try {
        $configd->call('apikey.revoke', ['id' => (string) ($_POST['id'] ?? '')]);
        $apiKeyMessage = 'API key revoked - it can no longer be used.';
    } catch (NtpsenseConfigdException $e) {
        $apiKeyError = $e->getMessage();
    }
}
$apiKeysList = [];
if ($activeTab === 'apikeys') {
    try {
        $apiKeysList = $configd->call('apikey.list')['keys'] ?? [];
    } catch (NtpsenseConfigdException $e) {
        if ($apiKeyError === null) {
            $apiKeyError = $e->getMessage();
        }
    }
}

$authConfig = ExternalAuth::getConfig();

$tabLabels = ['general' => 'General Setup', 'backup' => 'Backup & Restore', 'certificates' => 'Certificates', 'users' => 'Users', 'roles' => 'Roles', 'authentication' => 'Authentication', 'maintenance' => 'Maintenance', 'datetime' => 'Date & Time', 'apikeys' => 'API Keys'];
$pageTitle = 'System';
$activeNavItem = 'system';
$breadcrumbTail = [$tabLabels[$activeTab]];
require __DIR__ . '/../templates/layout_header.php';
?>

<?php if ($configdError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Unable to fetch system info: <?= htmlspecialchars($configdError) ?></div>
<?php endif; ?>
<?php if ($saveMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:10px 14px; margin-bottom:10px; font-size:13px;"><?= htmlspecialchars($saveMessage) ?></div>
<?php endif; ?>
<?php if ($saveError): ?>
  <div class="ntp-alert-error" style="margin-bottom:10px;">Failed to save: <?= htmlspecialchars($saveError) ?></div>
<?php endif; ?>

<div class="ntp-tabbar" style="margin-bottom:14px;">
  <a href="?tab=general" class="ntp-tab<?= $activeTab === 'general' ? ' active' : '' ?>">General Setup</a>
  <a href="?tab=backup" class="ntp-tab<?= $activeTab === 'backup' ? ' active' : '' ?>">Backup &amp; Restore</a>
  <a href="?tab=certificates" class="ntp-tab<?= $activeTab === 'certificates' ? ' active' : '' ?>">Certificates</a>
  <a href="?tab=users" class="ntp-tab<?= $activeTab === 'users' ? ' active' : '' ?>">Users</a>
  <a href="?tab=roles" class="ntp-tab<?= $activeTab === 'roles' ? ' active' : '' ?>">Roles</a>
  <a href="?tab=authentication" class="ntp-tab<?= $activeTab === 'authentication' ? ' active' : '' ?>">Authentication</a>
  <a href="?tab=maintenance" class="ntp-tab<?= $activeTab === 'maintenance' ? ' active' : '' ?>">Maintenance</a>
  <a href="?tab=datetime" class="ntp-tab<?= $activeTab === 'datetime' ? ' active' : '' ?>">Date &amp; Time</a>
  <a href="?tab=apikeys" class="ntp-tab<?= $activeTab === 'apikeys' ? ' active' : '' ?>">API Keys</a>
</div>

<?php if ($activeTab === 'general'): ?>

<?php if ($info): ?>
<form method="post">
  <input type="hidden" name="form" value="system_settings">
  <div class="ntp-card">
    <div class="ntp-card-header">System</div>
    <div style="padding:14px; display:grid; grid-template-columns:160px 1fr; gap:14px 16px; align-items:start;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">Hostname</label>
      <input type="text" name="hostname" value="<?= htmlspecialchars($info['hostname']) ?>" style="max-width:280px;">

      <label style="font-size:13px; color:#374151; padding-top:8px;">FreeBSD version</label>
      <span style="font-size:13px; color:#6b7280; padding-top:8px;"><?= htmlspecialchars($info['freebsd_version']) ?> (read-only)</span>
    </div>
  </div>

  <div class="ntp-card">
    <div class="ntp-card-header">Localization</div>
    <div style="padding:14px; display:grid; grid-template-columns:160px 1fr; gap:14px 16px; align-items:start;">
      <label style="font-size:13px; color:#374151; padding-top:8px;">Timezone</label>
      <span style="font-size:13px; color:#6b7280; padding-top:8px;">
        Currently <strong><?= htmlspecialchars($info['timezone']) ?></strong> - manage this from the
        <a href="?tab=datetime">Date &amp; Time</a> tab now, which also shows live NTP sync status.
      </span>

      <label style="font-size:13px; color:#374151; padding-top:8px;">NTP servers</label>
      <textarea name="ntp_servers" rows="3" style="max-width:280px; font-family:monospace; font-size:12px;"><?= htmlspecialchars(implode("\n", $info['ntp_servers'])) ?></textarea>
    </div>
    <p style="padding:0 14px 14px; font-size:12px; color:#6b7280;">One NTP server per line.</p>
  </div>

  <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
</form>

<div class="ntp-card" style="margin-top:16px;">
  <div class="ntp-card-header">DNS Servers</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Used by this gateway itself to resolve hostnames - NTP servers, package updates, blocklist downloads, and
    anything else the gateway needs to look up by name (not the same as DHCP-assigned DNS handed out to LAN
    clients). Related directly to NTP: hostname-based NTP servers (like <code>pool.ntp.org</code>) need working
    DNS before they can be reached at all.
  </p>
  <form method="post" style="padding:14px;">
    <input type="hidden" name="form" value="set_dns_servers">
    <textarea name="dns_servers" rows="3" style="max-width:280px; font-family:monospace; font-size:12px;"><?= htmlspecialchars(implode("\n", $dnsServers)) ?></textarea>
    <p style="font-size:12px; color:#6b7280; margin:6px 0 10px;">
      One IP address per line. If WAN1 uses DHCP, the ISP may overwrite this on the next lease renewal - this
      is a manual override, not a permanent guarantee.
    </p>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save DNS servers</button>
  </form>
</div>

<?php endif; ?>

<?php elseif ($activeTab === 'backup'): ?>

<div class="ntp-card">
  <div class="ntp-card-header">Backup &amp; Restore</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Backups are signed with an HMAC unique to this gateway (visible in the filename) so a restore always verifies the file genuinely came from this device before applying anything.
  </p>
</div>

<?php if ($backupMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($backupMessage) ?></div>
<?php endif; ?>
<?php if ($backupError): ?>
  <div class="ntp-alert-error">Failed: <?= htmlspecialchars($backupError) ?></div>
<?php endif; ?>

<?php if ($restoreWarning): ?>
  <div style="margin-bottom:16px; background:#fff4e0; border-radius:8px; padding:14px;">
    <p style="font-size:13px; color:#9a5b00; margin:0 0 10px; font-weight:500;">
      <?= htmlspecialchars($restoreWarning['message']) ?>
    </p>
    <form method="post" style="margin:0;">
      <input type="hidden" name="form" value="backup_restore">
      <input type="hidden" name="filename" value="<?= htmlspecialchars($restoreWarning['filename']) ?>">
      <input type="hidden" name="confirm" value="1">
      <button type="submit" style="background:#9a5b00; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Restore anyway</button>
      <span style="font-size:12px; color:#6b7280; margin-left:10px;">Entries for interfaces not present on this system will simply have no effect.</span>
    </form>
  </div>
<?php endif; ?>

<div class="ntp-card">
  <div class="ntp-card-header">Existing backups</div>
  <div class="ntp-table-scroll">
  <table class="ntp-table">
    <thead>
    <tr>
      <th>Filename</th>
      <th>Size</th>
      <th>Created</th>
      <th>Actions</th>
    </tr>
    </thead>
    <tbody>
    <?php if (empty($backups)): ?>
      <tr><td colspan="4" style="color:#6b7280;">No backups yet.</td></tr>
    <?php endif; ?>
    <?php foreach ($backups as $b): ?>
      <tr>
        <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($b['filename']) ?></td>
        <td><?= htmlspecialchars(number_format(($b['size'] ?? 0) / 1024, 1)) ?> KB</td>
        <td><?= htmlspecialchars(date('Y-m-d H:i', (int) ($b['modified'] ?? 0))) ?></td>
        <td>
          <a href="?download=<?= urlencode($b['filename']) ?>" title="Download" style="color:#374151; padding:4px; display:inline-block;">
            <i class="ti ti-download" style="font-size:16px;" aria-hidden="true"></i>
          </a>
          <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Restore this backup? Current configuration will be overwritten.');">
            <input type="hidden" name="form" value="backup_restore">
            <input type="hidden" name="filename" value="<?= htmlspecialchars($b['filename']) ?>">
            <button type="submit" title="Restore" style="background:none; border:none; cursor:pointer; color:#1a7f4b; padding:4px;">
              <i class="ti ti-history" style="font-size:16px;" aria-hidden="true"></i>
            </button>
          </form>
          <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete this backup?');">
            <input type="hidden" name="form" value="backup_delete">
            <input type="hidden" name="filename" value="<?= htmlspecialchars($b['filename']) ?>">
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

  <form method="post" style="padding:14px; border-top:1px solid #e5e7eb;">
    <input type="hidden" name="form" value="backup_create">
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create backup now</button>
  </form>

  <form method="post" enctype="multipart/form-data" style="padding:14px; border-top:1px solid #e5e7eb; display:flex; gap:12px; align-items:end;">
    <input type="hidden" name="form" value="backup_upload">
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Upload a backup file</label>
      <input type="file" name="backup_file" accept=".gz" required>
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Upload</button>
  </form>
</div>

<?php elseif ($activeTab === 'certificates'): ?>

<?php if ($certMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($certMessage) ?></div>
<?php endif; ?>
<?php if ($certError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($certError) ?></div>
<?php endif; ?>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Current certificate (Web UI HTTPS)</div>
  <?php if (!$certStatus): ?>
    <p style="padding:12px 14px; font-size:12px; color:#6b7280;">Certificate status is unavailable.</p>
  <?php else: ?>
    <table class="ntp-table">
      <tr><th>Subject</th><td><?= htmlspecialchars($certStatus['subject'] ?? '—') ?></td></tr>
      <tr><th>Issuer</th><td><?= htmlspecialchars($certStatus['issuer'] ?? '—') ?></td></tr>
      <tr><th>Type</th>
        <td>
          <?php if (!empty($certStatus['is_self_signed'])): ?>
            <span class="ntp-badge ntp-badge-muted">Self-signed</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-success">CA-issued</span>
          <?php endif; ?>
        </td>
      </tr>
      <tr><th>Valid from</th><td><?= htmlspecialchars($certStatus['not_before'] ?? '—') ?></td></tr>
      <tr><th>Valid until</th><td><?= htmlspecialchars($certStatus['not_after'] ?? '—') ?></td></tr>
      <tr><th>Status</th>
        <td>
          <?php if (!empty($certStatus['expired'])): ?>
            <span class="ntp-badge ntp-badge-danger">Expired</span>
          <?php elseif (!empty($certStatus['expiring_soon'])): ?>
            <span class="ntp-badge ntp-badge-warning">Expiring within 30 days</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-success">Valid</span>
          <?php endif; ?>
        </td>
      </tr>
    </table>
  <?php endif; ?>
</div>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Regenerate self-signed certificate</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Generates a new self-signed certificate (RSA 2048, 10 years) with the gateway's current MGMT and LAN1 IP
    addresses included as Subject Alternative Names - fixes the hostname-mismatch warning modern browsers show
    for the original installer-generated certificate, which had no SAN at all. Browsers will still show an
    "untrusted certificate" warning since it's self-signed - that part is expected and cannot be avoided without
    uploading a certificate from a real CA below.
  </p>
  <form method="post" style="padding:14px;" onsubmit="return confirm('Regenerate the self-signed certificate now? lighttpd will restart, briefly interrupting the Web UI (usually a few seconds).');">
    <input type="hidden" name="form" value="cert_regenerate">
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Regenerate now</button>
  </form>
</div>

<div class="ntp-card">
  <div class="ntp-card-header">Upload your own certificate</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    For a certificate issued by your own internal CA, a purchased certificate, or Let's Encrypt (if this gateway
    has a public domain name pointed at it). Both files must be PEM format. The certificate and private key are
    verified to actually match each other before anything is applied - a mismatched pair is rejected outright.
  </p>
  <form method="post" enctype="multipart/form-data" style="padding:14px; display:flex; gap:12px; align-items:end; flex-wrap:wrap;" onsubmit="return confirm('Apply this certificate? lighttpd will restart, briefly interrupting the Web UI (usually a few seconds).');">
    <input type="hidden" name="form" value="cert_upload">
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Certificate file (.crt / .pem)</label>
      <input type="file" name="cert_file" accept=".crt,.pem,.cer" required>
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Private key file (.key / .pem)</label>
      <input type="file" name="key_file" accept=".key,.pem" required>
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Upload &amp; apply</button>
  </form>
</div>

<?php elseif ($activeTab === 'users'): ?>

<?php if ($userMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($userMessage) ?></div>
<?php endif; ?>
<?php if ($userError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($userError) ?></div>
<?php endif; ?>

<?php $currentUsername = Auth::currentUsername(); $allUsers = Auth::listUsers(); $validRoles = Auth::validRoleNames(); ?>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Admin accounts</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Every account has a role that determines what it can access - see the <a href="?tab=roles">Roles</a> tab to
    define or edit roles. The last remaining Administrator account can't have its role changed or be deleted, and
    you can't delete the account you're currently logged in as. Accounts tagged <strong>External</strong> were
    auto-created on first successful RADIUS/LDAP login (see <a href="?tab=authentication">Authentication</a>) -
    their password is never checked locally, always re-verified against the external server on every login.
  </p>
  <div class="ntp-table-scroll">
  <table class="ntp-table">
    <thead>
    <tr><th>Username</th><th>Source</th><th>Role</th><th>Password status</th><th>Created</th><th>Actions</th></tr>
    </thead>
    <tbody>
    <?php foreach ($allUsers as $u): ?>
      <tr>
        <td>
          <?= htmlspecialchars($u['username']) ?>
          <?php if ($u['username'] === $currentUsername): ?>
            <span class="ntp-badge ntp-badge-muted">You</span>
          <?php endif; ?>
        </td>
        <td>
          <?php if (($u['auth_source'] ?? 'local') === 'external'): ?>
            <span class="ntp-badge ntp-badge-muted" title="Auto-provisioned from RADIUS/LDAP - role synced on every login">External</span>
          <?php else: ?>
            <span style="color:#9ca3af; font-size:12px;">Local</span>
          <?php endif; ?>
        </td>
        <td>
          <?php
            $isBuiltinAdmin = $u['username'] === 'admin';
            $isAdminRow = $u['role'] === Auth::ADMINISTRATOR_ROLE;
            $selectId = 'role-select-' . md5($u['username']);
          ?>
          <?php if ($isBuiltinAdmin): ?>
            <span class="ntp-badge ntp-badge-muted" title="The built-in admin account is permanently the Administrator role and cannot be changed.">
              <i class="ti ti-lock" style="font-size:12px; vertical-align:-1px;" aria-hidden="true"></i> Administrator
            </span>
          <?php elseif (($u['auth_source'] ?? 'local') === 'external'): ?>
            <span style="font-size:12px; color:#6b7280;" title="Role is synced automatically from the RADIUS/LDAP group mapping on every login - edit the mapping on the Authentication tab instead."><?= htmlspecialchars($u['role']) ?></span>
          <?php else: ?>
            <form method="post" style="margin:0; display:flex; gap:6px; align-items:center;">
              <input type="hidden" name="form" value="user_change_role">
              <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
              <select name="role" id="<?= $selectId ?>" style="font-size:12px;" <?= $isAdminRow ? 'disabled' : '' ?>
                onchange="if(confirm('Change role for &quot;<?= htmlspecialchars($u['username'], ENT_QUOTES) ?>&quot; to '+this.value+'?')){this.form.submit();}else{this.value='<?= htmlspecialchars($u['role'], ENT_QUOTES) ?>';}">
                <?php foreach ($validRoles as $r): ?>
                  <option value="<?= htmlspecialchars($r) ?>" <?= $r === $u['role'] ? 'selected' : '' ?>><?= htmlspecialchars($r) ?></option>
                <?php endforeach; ?>
              </select>
            </form>
            <?php if ($isAdminRow): ?>
              <button type="button" title="Unlock to change role" onclick="var s=document.getElementById('<?= $selectId ?>'); s.disabled=false; s.focus(); this.style.display='none';" style="background:none; border:none; cursor:pointer; color:#9ca3af; padding:2px; vertical-align:middle;">
                <i class="ti ti-lock" style="font-size:14px;" aria-hidden="true"></i>
              </button>
            <?php endif; ?>
          <?php endif; ?>
        </td>
        <td>

          <?php if (($u['auth_source'] ?? 'local') === 'external'): ?>
            <span style="color:#9ca3af; font-size:12px;">N/A</span>
          <?php elseif ($u['must_change_password']): ?>
            <span class="ntp-badge ntp-badge-warning">Must set new password</span>
          <?php else: ?>
            <span class="ntp-badge ntp-badge-success">Set</span>
          <?php endif; ?>
        </td>
        <td><?= $u['created_at'] ? htmlspecialchars(date('Y-m-d H:i', $u['created_at'])) : '—' ?></td>
        <td>
          <?php if (($u['auth_source'] ?? 'local') !== 'external'): ?>
          <details style="display:inline-block;">
            <summary style="cursor:pointer; display:inline-block; color:#374151; font-size:12px;">Reset password</summary>
            <form method="post" style="margin:8px 0 0; display:flex; gap:8px; align-items:end;">
              <input type="hidden" name="form" value="user_reset_password">
              <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
              <input type="password" name="new_password" placeholder="New temporary password" minlength="8" required style="font-size:12px;">
              <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 12px; font-size:12px; border-radius:6px;">Reset</button>
            </form>
          </details>
          <?php endif; ?>
          <?php if ($u['username'] !== $currentUsername && count($allUsers) > 1): ?>
            <form method="post" style="margin:0; display:inline-block;" onsubmit="return confirm('Delete admin account &quot;<?= htmlspecialchars($u['username']) ?>&quot;?');">
              <input type="hidden" name="form" value="user_delete">
              <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
              <button type="submit" title="Delete" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px; margin-left:6px;">
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
</div>

<div class="ntp-card">
  <div class="ntp-card-header">Add admin account</div>
  <form method="post" style="padding:14px; display:flex; gap:12px; align-items:end; flex-wrap:wrap;">
    <input type="hidden" name="form" value="user_create">
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Username</label>
      <input type="text" name="username" required style="width:180px;">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Temporary password</label>
      <input type="password" name="password" minlength="8" required style="width:180px;">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Role</label>
      <select name="role" style="width:180px;">
        <?php foreach ($validRoles as $r): ?>
          <option value="<?= htmlspecialchars($r) ?>"><?= htmlspecialchars($r) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add account</button>
  </form>
  <p style="padding:0 14px 14px; font-size:11px; color:#9ca3af;">
    The new account must set its own password the first time it logs in.
  </p>
</div>

<div class="ntp-card">
  <div class="ntp-card-header">Two-Factor Authentication (your account)</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Adds a second step to your own login (a 6-digit code from an authenticator app like Google Authenticator,
    Authy, or Microsoft Authenticator) - native to NTPSense, no external RADIUS server needed. Opt-in per
    account, not enforced for everyone.
  </p>

  <?php if ($totpRecoveryCodes !== null): ?>
    <div style="margin:12px 14px; padding:12px; background:#fff8e6; border:1px solid #f5d78e; border-radius:8px;">
      <p style="font-size:13px; font-weight:500; color:#9a5b00; margin:0 0 8px;">
        ⚠️ Save these recovery codes now - they will not be shown again
      </p>
      <p style="font-size:12px; color:#9a5b00; margin:0 0 10px;">
        Each code works once, if you ever lose access to your authenticator app. Store them somewhere safe
        (password manager, printed copy) - not on this gateway itself.
      </p>
      <div style="font-family:monospace; font-size:14px; background:#ffffff; border-radius:6px; padding:10px; display:grid; grid-template-columns:repeat(2, 1fr); gap:6px;">
        <?php foreach ($totpRecoveryCodes as $rc): ?>
          <div><?= htmlspecialchars($rc) ?></div>
        <?php endforeach; ?>
      </div>
    </div>
  <?php elseif ($totpSetup !== null): ?>
    <div style="padding:12px 14px;">
      <p style="font-size:12px; color:#374151; margin:0 0 10px;">
        Scan this QR code with your authenticator app, or enter the key manually, then type the current
        6-digit code below to confirm.
      </p>
      <div id="ntp-totp-qr" style="margin-bottom:10px;"></div>
      <p style="font-size:12px; color:#6b7280; margin:0 0 10px;">
        Manual entry key: <code style="font-size:13px;"><?= htmlspecialchars($totpSetup['secret']) ?></code>
      </p>
      <form method="post" style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
        <input type="hidden" name="form" value="totp_setup_confirm">
        <div>
          <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Current 6-digit code</label>
          <input type="text" name="code" inputmode="numeric" maxlength="6" required autofocus style="width:120px; letter-spacing:2px; text-align:center;">
        </div>
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Confirm and enable</button>
      </form>
      <form method="post" style="margin-top:8px;">
        <input type="hidden" name="form" value="totp_setup_cancel">
        <button type="submit" style="background:none; border:none; color:#6b7280; font-size:12px; cursor:pointer; text-decoration:underline; padding:0;">Cancel setup</button>
      </form>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <script>
      new QRCode(document.getElementById('ntp-totp-qr'), {
        text: <?= json_encode($totpSetup['otpauth_uri']) ?>,
        width: 180,
        height: 180,
      });
    </script>
  <?php elseif (Auth::currentUserHasTotp()): ?>
    <div style="padding:12px 14px;">
      <span class="ntp-badge ntp-badge-success">Enabled</span>
      <form method="post" style="margin-top:10px;" onsubmit="return confirm('Disable two-factor authentication for your account? You will only need your password to log in afterward.');">
        <input type="hidden" name="form" value="totp_disable">
        <button type="submit" style="background:none; border:1px solid #d1d5db; padding:6px 14px; font-size:12px; border-radius:6px; cursor:pointer; color:#b3261e;">Disable 2FA</button>
      </form>
    </div>
  <?php else: ?>
    <div style="padding:12px 14px;">
      <span class="ntp-badge ntp-badge-muted">Not enabled</span>
      <form method="post" style="margin-top:10px;">
        <input type="hidden" name="form" value="totp_setup_begin">
        <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Enable 2FA</button>
      </form>
    </div>
  <?php endif; ?>
</div>

<?php elseif ($activeTab === 'roles'): ?>

<?php if ($userMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($userMessage) ?></div>
<?php endif; ?>
<?php if ($userError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($userError) ?></div>
<?php endif; ?>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">About roles</div>
  <p style="padding:12px 14px; font-size:12px; color:#6b7280;">
    "Administrator" always exists, always has full read-write access to everything including this System page,
    and can't be edited or deleted here - there must always be at least one Administrator account. The roles
    below are custom and fully yours to define: each category can be set to <strong>None</strong> (page not
    accessible at all), <strong>Read</strong> (can view, cannot change anything), or <strong>Write</strong> (full
    access). "System" itself is intentionally not offered as a category here - only the Administrator role can
    ever manage users, roles, certificates, and backups, matching the same restriction FortiGate and pfSense both
    apply to their own equivalent of this page.
  </p>
</div>

<?php foreach (Auth::listRoles() as $role): ?>
<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header"><?= htmlspecialchars($role['name']) ?></div>
  <form method="post" style="padding:14px;">
    <input type="hidden" name="form" value="role_update">
    <input type="hidden" name="role_name" value="<?= htmlspecialchars($role['name']) ?>">
    <table class="ntp-table" style="margin-bottom:12px;">
      <thead><tr><th>Category</th><th style="text-align:center;">None</th><th style="text-align:center;">Read</th><th style="text-align:center;">Write</th></tr></thead>
      <tbody>
      <?php foreach (Auth::ASSIGNABLE_CATEGORIES as $cat): ?>
        <tr>
          <td><?= htmlspecialchars($navItems[$cat]['label'] ?? $cat) ?></td>
          <?php foreach (['none', 'read', 'write'] as $level): ?>
            <td style="text-align:center;">
              <input type="radio" name="perm_<?= $cat ?>" value="<?= $level ?>" <?= ($role['permissions'][$cat] ?? 'none') === $level ? 'checked' : '' ?>>
            </td>
          <?php endforeach; ?>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save</button>
  </form>
  <form method="post" style="padding:0 14px 14px;" onsubmit="return confirm('Delete role &quot;<?= htmlspecialchars($role['name']) ?>&quot;? Any user still assigned this role must be reassigned first.');">
    <input type="hidden" name="form" value="role_delete">
    <input type="hidden" name="role_name" value="<?= htmlspecialchars($role['name']) ?>">
    <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; font-size:12px; padding:0;">Delete this role</button>
  </form>
</div>
<?php endforeach; ?>

<div class="ntp-card">
  <div class="ntp-card-header">Add role</div>
  <form method="post" style="padding:14px;">
    <input type="hidden" name="form" value="role_create">
    <div style="margin-bottom:12px;">
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Role name</label>
      <input type="text" name="role_name" required style="width:240px;">
    </div>
    <table class="ntp-table" style="margin-bottom:12px;">
      <thead><tr><th>Category</th><th style="text-align:center;">None</th><th style="text-align:center;">Read</th><th style="text-align:center;">Write</th></tr></thead>
      <tbody>
      <?php foreach (Auth::ASSIGNABLE_CATEGORIES as $cat): ?>
        <tr>
          <td><?= htmlspecialchars($navItems[$cat]['label'] ?? $cat) ?></td>
          <?php foreach (['none', 'read', 'write'] as $level): ?>
            <td style="text-align:center;">
              <input type="radio" name="perm_<?= $cat ?>" value="<?= $level ?>" <?= $level === 'none' ? 'checked' : '' ?>>
            </td>
          <?php endforeach; ?>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create role</button>
  </form>
</div>

<?php elseif ($activeTab === 'authentication'): ?>

<p style="font-size:12px; color:#6b7280; margin-top:0;">
  Authenticate admin Web UI logins against an external RADIUS or LDAP server instead of (or in addition to)
  local accounts - researched against pfSense/FortiGate before building: this gateway acts as a RADIUS/LDAP
  <strong>client</strong> only, never a server. The external server just confirms "credentials correct or not"
  plus group membership - which local <a href="?tab=roles">Role</a> a user gets is still decided entirely here,
  via the group mapping below. On first successful external login, a local account record is auto-created
  (visible on the <a href="?tab=users">Users</a> tab, tagged "External") - its role is re-synced from the
  mapping on every subsequent login. <strong>Stage 2</strong> (RADIUS authentication for OpenVPN users) is a
  separate, later roadmap item - this page currently covers Web UI admin login only.
</p>

<?php if ($authMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($authMessage) ?></div>
<?php endif; ?>
<?php if ($authError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($authError) ?></div>
<?php endif; ?>
<?php if ($authTestResult): ?>
  <div style="background:<?= $authTestResult['success'] ? '#e6f6ec' : '#fff0f0' ?>; color:<?= $authTestResult['success'] ? '#1a7f4b' : '#7a1f1a' ?>; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;">
    <?= $authTestResult['success'] ? '✓' : '✗' ?> <?= htmlspecialchars($authTestResult['message']) ?>
    <?php if (!empty($authTestResult['groups'])): ?>
      <br><span style="font-size:12px;">Groups returned: <?= htmlspecialchars(implode(', ', $authTestResult['groups'])) ?></span>
    <?php endif; ?>
  </div>
<?php endif; ?>

<form method="post" style="margin-bottom:16px;">
  <input type="hidden" name="form" value="auth_toggle">
  <div class="ntp-card">
    <div class="ntp-card-header">Enable</div>
    <div style="padding:14px; display:flex; gap:24px;">
      <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
        <input type="checkbox" name="radius_enabled" value="1" <?= !empty($authConfig['radius_enabled']) ? 'checked' : '' ?>>
        RADIUS
      </label>
      <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
        <input type="checkbox" name="ldap_enabled" value="1" <?= !empty($authConfig['ldap_enabled']) ? 'checked' : '' ?>>
        LDAP
      </label>
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 14px; font-size:12px; border-radius:6px;">Save</button>
    </div>
  </div>
</form>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">RADIUS Servers</div>
  <?php if (!empty($authConfig['radius_servers'])): ?>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead><tr><th>Name</th><th>Host</th><th>Port</th><th>Timeout</th><th>Test / Manage</th></tr></thead>
      <tbody>
      <?php foreach ($authConfig['radius_servers'] as $i => $s): ?>
        <tr>
          <td><?= htmlspecialchars($s['name']) ?></td>
          <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($s['host']) ?></td>
          <td><?= htmlspecialchars($s['port']) ?></td>
          <td><?= htmlspecialchars($s['timeout']) ?>s</td>
          <td>
            <details style="display:inline-block;">
              <summary style="cursor:pointer; color:#374151; font-size:12px;">Test</summary>
              <form method="post" style="margin:8px 0 0; display:flex; gap:6px; align-items:end;">
                <input type="hidden" name="form" value="auth_test_radius">
                <input type="hidden" name="index" value="<?= $i ?>">
                <input type="text" name="test_username" placeholder="username" required style="font-size:11px; width:100px;">
                <input type="password" name="test_password" placeholder="password" required style="font-size:11px; width:100px;">
                <button type="submit" style="background:#14213d; color:#fff; border:none; padding:4px 10px; font-size:11px; border-radius:6px;">Test</button>
              </form>
            </details>
            <form method="post" style="display:inline; margin-left:6px;" onsubmit="return confirm('Remove this RADIUS server?');">
              <input type="hidden" name="form" value="radius_server_delete">
              <input type="hidden" name="index" value="<?= $i ?>">
              <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php else: ?>
    <p style="padding:12px 14px; font-size:12px; color:#6b7280;">No RADIUS servers configured yet.</p>
  <?php endif; ?>
  <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:flex; gap:10px; align-items:end; flex-wrap:wrap;">
    <input type="hidden" name="form" value="radius_server_add">
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label><input type="text" name="name" placeholder="Corporate RADIUS" required style="width:160px;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Host</label><input type="text" name="host" placeholder="10.0.0.5" required style="width:140px;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Port</label><input type="number" name="port" value="1812" style="width:80px;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Shared secret</label><input type="password" name="secret" required style="width:160px;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Timeout (s)</label><input type="number" name="timeout" value="5" style="width:70px;"></div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add server</button>
  </form>
</div>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">LDAP Servers</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    User DN template uses <code>{username}</code> as a placeholder - e.g.
    <code>uid={username},ou=people,dc=example,dc=com</code> for OpenLDAP, or
    <code>{username}@example.com</code> for Active Directory (UPN-style bind).
  </p>
  <?php if (!empty($authConfig['ldap_servers'])): ?>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead><tr><th>Name</th><th>Host</th><th>TLS</th><th>User DN Template</th><th>Test / Manage</th></tr></thead>
      <tbody>
      <?php foreach ($authConfig['ldap_servers'] as $i => $s): ?>
        <tr>
          <td><?= htmlspecialchars($s['name']) ?></td>
          <td style="font-family:monospace; font-size:12px;"><?= htmlspecialchars($s['host']) ?>:<?= htmlspecialchars($s['port']) ?></td>
          <td><?= !empty($s['use_tls']) ? '<span class="ntp-badge ntp-badge-success">Yes</span>' : '<span class="ntp-badge ntp-badge-muted">No</span>' ?></td>
          <td style="font-family:monospace; font-size:11px;"><?= htmlspecialchars($s['user_dn_template']) ?></td>
          <td>
            <details style="display:inline-block;">
              <summary style="cursor:pointer; color:#374151; font-size:12px;">Test</summary>
              <form method="post" style="margin:8px 0 0; display:flex; gap:6px; align-items:end;">
                <input type="hidden" name="form" value="auth_test_ldap">
                <input type="hidden" name="index" value="<?= $i ?>">
                <input type="text" name="test_username" placeholder="username" required style="font-size:11px; width:100px;">
                <input type="password" name="test_password" placeholder="password" required style="font-size:11px; width:100px;">
                <button type="submit" style="background:#14213d; color:#fff; border:none; padding:4px 10px; font-size:11px; border-radius:6px;">Test</button>
              </form>
            </details>
            <form method="post" style="display:inline; margin-left:6px;" onsubmit="return confirm('Remove this LDAP server?');">
              <input type="hidden" name="form" value="ldap_server_delete">
              <input type="hidden" name="index" value="<?= $i ?>">
              <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php else: ?>
    <p style="padding:12px 14px; font-size:12px; color:#6b7280;">No LDAP servers configured yet.</p>
  <?php endif; ?>
  <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:flex; gap:10px; align-items:end; flex-wrap:wrap;">
    <input type="hidden" name="form" value="ldap_server_add">
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label><input type="text" name="name" placeholder="Corporate LDAP" required style="width:150px;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Host</label><input type="text" name="host" placeholder="10.0.0.10" required style="width:130px;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Port</label><input type="number" name="port" value="389" style="width:80px;"></div>
    <div><label style="display:flex; align-items:center; gap:4px; font-size:12px; color:#374151; margin-bottom:4px;"><input type="checkbox" name="use_tls" value="1"> Use TLS (ldaps)</label></div>
    <div style="flex:1; min-width:220px;"><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">User DN template</label><input type="text" name="user_dn_template" placeholder="uid={username},ou=people,dc=example,dc=com" required style="width:100%;"></div>
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Group attribute</label><input type="text" name="group_attribute" value="memberOf" style="width:110px;"></div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add server</button>
  </form>
</div>

<div class="ntp-card">
  <div class="ntp-card-header">Group → Role Mapping</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    When a RADIUS/LDAP login succeeds, its returned group(s) are checked against this list top to bottom - the
    first match decides the local Role. No match = login rejected even though the password was correct
    (fail-closed - matching credentials to an external server is not, by itself, permission to access this
    gateway).
  </p>
  <?php if (!empty($authConfig['group_role_map'])): ?>
    <div class="ntp-table-scroll">
    <table class="ntp-table">
      <thead><tr><th>External Group</th><th>Local Role</th><th>Manage</th></tr></thead>
      <tbody>
      <?php foreach ($authConfig['group_role_map'] as $i => $m): ?>
        <tr>
          <td><?= htmlspecialchars($m['external_group']) ?></td>
          <td><?= htmlspecialchars($m['local_role']) ?></td>
          <td>
            <form method="post" style="margin:0;" onsubmit="return confirm('Remove this mapping?');">
              <input type="hidden" name="form" value="group_map_delete">
              <input type="hidden" name="index" value="<?= $i ?>">
              <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;"><i class="ti ti-trash" style="font-size:16px;" aria-hidden="true"></i></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  <?php else: ?>
    <p style="padding:12px 14px; font-size:12px; color:#6b7280;">No mappings yet - external logins will be rejected until at least one exists.</p>
  <?php endif; ?>
  <form method="post" style="padding:14px; border-top:1px solid #e5e7eb; display:flex; gap:10px; align-items:end;">
    <input type="hidden" name="form" value="group_map_add">
    <div><label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">External group name</label><input type="text" name="external_group" placeholder="VPNAdmins" required style="width:200px;"></div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Local role</label>
      <select name="local_role" style="width:180px;">
        <?php foreach (Auth::validRoleNames() as $r): ?>
          <option value="<?= htmlspecialchars($r) ?>"><?= htmlspecialchars($r) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Add mapping</button>
  </form>
</div>

<?php elseif ($activeTab === 'maintenance'): ?>

<?php if ($maintenanceMessage && $maintenanceCountdown): ?>
  <div id="ntp-maintenance-overlay" style="position:fixed; inset:0; background:rgba(20,33,61,0.92); z-index:9999; display:flex; align-items:center; justify-content:center;">
    <div style="background:#ffffff; border-radius:10px; padding:32px 40px; max-width:440px; text-align:center; box-shadow:0 10px 40px rgba(0,0,0,0.3);">
      <div style="font-size:15px; color:#14213d; font-weight:600; margin-bottom:10px;">Please wait</div>
      <p style="font-size:13px; color:#374151; margin-bottom:18px;"><?= htmlspecialchars($maintenanceMessage) ?></p>
      <div style="font-size:28px; font-weight:700; color:#14213d; margin-bottom:6px;"><span id="ntp-countdown-num"><?= (int) $maintenanceCountdown ?></span>s</div>
      <p style="font-size:11px; color:#9ca3af; margin:0;">Redirecting automatically once the wait is over - if the gateway isn't back up yet, this page will just retry.</p>
    </div>
  </div>
  <script>
    (function () {
      var seconds = <?= (int) $maintenanceCountdown ?>;
      var redirectTo = <?= json_encode($maintenanceRedirectTo) ?>;
      var numEl = document.getElementById('ntp-countdown-num');
      var timer = setInterval(function () {
        seconds -= 1;
        if (seconds <= 0) {
          clearInterval(timer);
          window.location.href = redirectTo;
          return;
        }
        numEl.textContent = seconds;
      }, 1000);
    })();
  </script>
<?php elseif ($maintenanceMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($maintenanceMessage) ?></div>
<?php endif; ?>
<?php if ($maintenanceError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($maintenanceError) ?></div>
<?php endif; ?>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Reboot</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Full operating system restart - kernel reload, hardware re-detection, all of it. All configuration is
    preserved. The gateway is unreachable for a minute or two while it comes back up.
  </p>
  <form method="post" style="padding:14px;" onsubmit="return confirm('Reboot the gateway now? It will be unreachable for a minute or two.');">
    <input type="hidden" name="form" value="system_reboot">
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Reboot now</button>
  </form>
</div>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Restart All Services</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    Restarts every NTPSense-managed service (Web UI, Proxy, DHCP, IDS, VPN, and reloads the Firewall ruleset)
    <strong>without</strong> rebooting the operating system itself - no kernel reload, no hardware re-detection.
    Faster and less disruptive than a full reboot; useful when a service is acting up but the gateway itself is
    fine. (Same concept as pfSense's "reroot" or Sangfor's "Restart Service".)
  </p>
  <form method="post" style="padding:14px;" onsubmit="return confirm('Restart all services now? Active connections through the proxy/VPN may briefly drop.');">
    <input type="hidden" name="form" value="system_restart_services">
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Restart all services</button>
  </form>
</div>

<div class="ntp-card">
  <div class="ntp-card-header" style="color:#b3261e;">
    <i class="ti ti-alert-triangle" style="font-size:14px; vertical-align:-2px;" aria-hidden="true"></i>
    Reset to Factory Default
  </div>
  <p style="padding:12px 14px 0; font-size:12px; color:#374151;">
    Wipes Network, Firewall, NAT, DHCP, VLAN, LAGG, Multi-WAN, High Availability, Bandwidth Limiters, Proxy,
    IDS/IPS, WireGuard, and IPsec configuration back to a fresh-install state, then reboots automatically -
    matching how FortiGate, pfSense, Palo Alto, and Sangfor all handle this (config wipe only, the installed
    operating system and packages themselves are untouched - equivalent to Palo Alto's
    <code>private-data-reset</code>, not a full reinstall). After reboot, log in with <code>admin</code> /
    <code>admin</code> and set a new password.
  </p>
  <p style="padding:0 14px; font-size:11px; color:#9ca3af;">
    Not yet covered by this reset: the Users/Roles system beyond the single built-in admin account (still
    being verified), and audit/system logs (left intact on purpose, for accountability).
  </p>
  <div style="margin:12px 14px; padding:10px 12px; background:#fff0f0; border:1px solid #f2b8b5; border-radius:6px; font-size:12px; color:#7a1f1a;">
    ⚠️ <strong>This cannot be undone.</strong> Take a backup first from the
    <a href="?tab=backup" style="color:#7a1f1a; text-decoration:underline;">Backup &amp; Restore</a> tab if there is
    any chance you'll want this configuration back.
  </div>
  <form method="post" style="padding:0 14px 14px;" onsubmit="return confirm('This is your last confirmation from the browser - the gateway will wipe its configuration and reboot. Continue?');">
    <input type="hidden" name="form" value="system_factory_reset">
    <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">
      Type <code>RESET</code> (all caps) to enable the button below
    </label>
    <input type="text" id="factory-reset-confirm-input" oninput="document.getElementById('factory-reset-confirm-btn').disabled = (this.value !== 'RESET');" name="confirm_text" placeholder="RESET" autocomplete="off" style="width:200px; margin-bottom:10px;">
    <br>
    <button type="submit" id="factory-reset-confirm-btn" disabled style="background:#b3261e; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px; opacity:0.5;">Reset to factory default</button>
  </form>
</div>

<?php elseif ($activeTab === 'datetime'): ?>

<?php if ($dtMessage): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($dtMessage) ?></div>
<?php endif; ?>
<?php if ($dtError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($dtError) ?></div>
<?php endif; ?>

<div id="ntp-clock-mismatch-banner" style="display:none; background:#fff0f0; border:1px solid #f2b8b5; color:#7a1f1a; border-radius:8px; padding:10px 14px; margin-bottom:16px; font-size:13px;"></div>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Current Time</div>
  <div style="padding:14px; display:flex; gap:32px; align-items:center; flex-wrap:wrap;">
    <div>
      <div id="ntp-live-clock" style="font-size:28px; font-weight:700; color:#14213d; font-variant-numeric:tabular-nums;">--:--:--</div>
      <div style="font-size:12px; color:#6b7280; margin-top:2px;">Gateway time (<?= htmlspecialchars($timeStatus['timezone'] ?? 'UTC') ?>)</div>
    </div>
    <div>
      <?php $ntpInfo = $timeStatus['ntp'] ?? ['running' => false, 'synced' => false]; ?>
      <?php if (!empty($ntpInfo['synced'])): ?>
        <span class="ntp-badge ntp-badge-success">NTP synced</span>
        <span style="font-size:11px; color:#6b7280; margin-left:6px;">offset <?= htmlspecialchars((string) ($ntpInfo['offset_ms'] ?? '0')) ?> ms</span>
      <?php elseif (!empty($ntpInfo['running'])): ?>
        <span class="ntp-badge ntp-badge-muted">Syncing…</span>
        <p style="font-size:11px; color:#9ca3af; margin:4px 0 0; max-width:280px;">
          ntpd is running but hasn't confirmed a sync source yet - this is normal for the first few minutes after
          a restart. Refresh this page in a bit before assuming something's wrong.
        </p>
      <?php else: ?>
        <span class="ntp-badge ntp-badge-danger">Not running</span>
        <form method="post" style="margin-top:6px;">
          <input type="hidden" name="form" value="enable_ntp">
          <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:6px 12px; font-size:12px; border-radius:6px;">Enable NTP</button>
        </form>
      <?php endif; ?>
    </div>
  </div>
</div>

<div class="ntp-card" style="margin-bottom:16px;">
  <div class="ntp-card-header">Timezone</div>
  <p style="padding:12px 14px 0; font-size:12px; color:#6b7280;">
    This only changes how times are <em>displayed</em> (logs, dashboards) - it does not affect 2FA codes or
    scheduled rules, which are based on the underlying clock, not the timezone label.
  </p>
  <form method="post" style="padding:14px;">
    <input type="hidden" name="form" value="set_timezone">
    <?php
    $tzByRegion = [];
    foreach ($timezoneList as $tz) {
        $region = strpos($tz['name'], '/') !== false ? explode('/', $tz['name'])[0] : 'Other';
        $tzByRegion[$region][] = $tz['name'];
    }
    ksort($tzByRegion);
    $currentTz = $timeStatus['timezone'] ?? 'UTC';
    ?>
    <select name="timezone" style="width:100%; max-width:420px;">
      <?php foreach ($tzByRegion as $region => $names): ?>
        <optgroup label="<?= htmlspecialchars($region) ?>">
          <?php foreach ($names as $name): ?>
            <option value="<?= htmlspecialchars($name) ?>" <?= $name === $currentTz ? 'selected' : '' ?>><?= htmlspecialchars($name) ?></option>
          <?php endforeach; ?>
        </optgroup>
      <?php endforeach; ?>
    </select>
    <div style="margin-top:10px;">
      <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Save timezone</button>
    </div>
  </form>
</div>
</div>

<details class="ntp-card">
  <summary class="ntp-card-header" style="cursor:pointer; list-style:none;">Manual time (fallback, no internet access)</summary>
  <div style="padding:14px;">
    <p style="font-size:12px; color:#6b7280; margin:0 0 10px;">
      Only use this if the gateway genuinely cannot reach any NTP server (isolated lab network, no internet
      uplink yet). Setting time manually disables NTP - re-enable it once real connectivity is available, or the
      clock will drift and eventually break things like 2FA and TLS certificate validity.
    </p>
    <p style="font-size:12px; color:#9a5b00; background:#fff8e6; border:1px solid #f5d78e; border-radius:6px; padding:8px 10px; margin:0 0 10px;">
      Enter the time as it should read in the gateway's <strong>current timezone</strong>
      (<?= htmlspecialchars($timeStatus['timezone'] ?? 'UTC') ?>, set above) - not UTC and not your own
      computer's timezone if they're different.
    </p>
    <form method="post" style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
      <input type="hidden" name="form" value="set_manual_time">
      <div>
        <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Date and time</label>
        <input type="datetime-local" name="datetime_local" id="ntp-manual-dt" step="1" required onchange="document.getElementById('ntp-manual-datetime-hidden').value = this.value.replace('T', ' ');">
        <input type="hidden" name="datetime" id="ntp-manual-datetime-hidden">
      </div>
      <button type="submit" style="background:none; border:1px solid #d1d5db; padding:8px 18px; font-size:13px; border-radius:6px;">Set manually</button>
    </form>
  </div>
</details>

<script>
(function () {
  var serverUnixTime = <?= (int) ($timeStatus['unix_time'] ?? time()) ?>;
  var gatewayTz = <?= json_encode($timeStatus['timezone'] ?? 'UTC') ?>;
  var pageLoadMs = Date.now();
  var clockEl = document.getElementById('ntp-live-clock');
  var formatter;
  try {
    formatter = new Intl.DateTimeFormat('en-GB', { timeZone: gatewayTz, hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    formatter = new Intl.DateTimeFormat('en-GB', { timeZone: 'UTC', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    gatewayTz = 'UTC';
  }
  function tick() {
    var elapsedSec = (Date.now() - pageLoadMs) / 1000;
    var serverNow = new Date((serverUnixTime + elapsedSec) * 1000);
    clockEl.textContent = formatter.format(serverNow);
    requestAnimationFrame(function () { setTimeout(tick, 200); });
  }
  tick();

  var clientNowMs = Date.now();
  var serverNowMs = serverUnixTime * 1000;
  var diffMinutes = Math.abs(clientNowMs - serverNowMs) / 60000;
  if (diffMinutes > 2) {
    var banner = document.getElementById('ntp-clock-mismatch-banner');
    banner.style.display = 'block';
    banner.innerHTML = '⚠️ This gateway\'s clock is off by about ' + Math.round(diffMinutes) +
      ' minute(s) compared to the computer you\'re using right now. This can cause 2FA codes and TLS ' +
      'certificates to be rejected. Check the NTP status above.';
  }
})();
</script>

<?php elseif ($activeTab === 'apikeys'): ?>

<p style="font-size:12px; color:#6b7280; margin-top:0;">
  Token-based access for external tools (monitoring, automation scripts) - reuses the same actions the Web UI
  itself calls, over a separate HTTP endpoint (<code>/api.php</code>) authenticated with a bearer token instead
  of a login session. Researched against FortiGate/pfSense before building: dedicated tokens shown once,
  never a username/password, and an optional read-only permission level for integrations that only need to
  poll status.
</p>

<?php if ($apiKeyMessage && !$newApiKeyToken): ?>
  <div style="background:#e6f6ec; color:#1a7f4b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px;"><?= htmlspecialchars($apiKeyMessage) ?></div>
<?php endif; ?>
<?php if ($apiKeyError): ?>
  <div class="ntp-alert-error" style="margin-bottom:16px;">Failed: <?= htmlspecialchars($apiKeyError) ?></div>
<?php endif; ?>

<?php if ($newApiKeyToken): ?>
  <div style="background:#fff0f0; border:1px solid #f2b8b5; border-radius:8px; padding:12px 14px; margin-bottom:16px;">
    <p style="font-size:13px; font-weight:600; color:#7a1f1a; margin:0 0 6px;">🔑 Copy this token now - it will never be shown again</p>
    <code style="display:block; background:#ffffff; border:1px solid #f2b8b5; border-radius:6px; padding:8px 10px; font-size:12px; word-break:break-all; user-select:all;"><?= htmlspecialchars($newApiKeyToken) ?></code>
    <p style="font-size:11px; color:#7a1f1a; margin:8px 0 0;">
      Send it in every request as: <code>Authorization: Bearer <?= htmlspecialchars(substr($newApiKeyToken, 0, 8)) ?>...</code>
    </p>
  </div>
<?php endif; ?>

<?php if (!empty($apiKeysList)): ?>
  <div class="ntp-table-scroll" style="margin-bottom:20px;">
  <table class="ntp-table">
    <thead><tr><th>Name</th><th>Permission</th><th>Trusted IP</th><th>Created</th><th>Last Used</th><th>Manage</th></tr></thead>
    <tbody>
    <?php foreach ($apiKeysList as $k): ?>
      <tr>
        <td><?= htmlspecialchars($k['name']) ?></td>
        <td><?= $k['permission'] === 'full' ? '<span class="ntp-badge ntp-badge-warning">Full</span>' : '<span class="ntp-badge ntp-badge-success">Read-only</span>' ?></td>
        <td style="font-size:12px;"><?= htmlspecialchars($k['trusted_ip'] ?? '') ?: '<span style="color:#9ca3af;">Any</span>' ?></td>
        <td style="font-size:11px; color:#6b7280;"><?= $k['created_at'] ? htmlspecialchars(date('Y-m-d H:i', (int) $k['created_at'])) : '—' ?></td>
        <td style="font-size:11px; color:#6b7280;"><?= $k['last_used_at'] ? htmlspecialchars(date('Y-m-d H:i', (int) $k['last_used_at'])) : 'Never' ?></td>
        <td>
          <form method="post" style="margin:0;" onsubmit="return confirm('Revoke API key &quot;<?= htmlspecialchars($k['name']) ?>&quot;? Anything still using it will stop working immediately.');">
            <input type="hidden" name="form" value="apikey_revoke">
            <input type="hidden" name="id" value="<?= htmlspecialchars($k['id']) ?>">
            <button type="submit" style="background:none; border:none; cursor:pointer; color:#b3261e; padding:4px;" title="Revoke">
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

<div class="ntp-card">
  <div class="ntp-card-header">Create API Key</div>
  <form method="post" style="padding:14px; display:flex; gap:16px; align-items:flex-end; flex-wrap:wrap;">
    <input type="hidden" name="form" value="apikey_create">
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Name</label>
      <input type="text" name="name" placeholder="Zabbix monitoring" required style="width:220px;">
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Permission</label>
      <select name="permission">
        <option value="read">Read-only</option>
        <option value="full">Full (read + write)</option>
      </select>
    </div>
    <div>
      <label style="display:block; font-size:12px; color:#374151; margin-bottom:4px;">Trusted source IP <span style="color:#9ca3af; font-weight:normal;">(optional)</span></label>
      <input type="text" name="trusted_ip" placeholder="192.168.1.50" style="width:160px;">
    </div>
    <button type="submit" style="background:#14213d; color:#ffffff; border:none; padding:8px 18px; font-size:13px; border-radius:6px;">Create Key</button>
  </form>
</div>

<?php endif; ?>

<?php require __DIR__ . '/../templates/layout_footer.php'; ?>
