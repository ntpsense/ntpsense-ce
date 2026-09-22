<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';
// Versi EULA yang SEDANG BERLAKU - sinkron MANUAL dengan "Last updated"
// di eula.php setiap kali dokumen itu direvisi substantif. Dipakai
// murni sebagai tag di log penerimaan (AuditLog::logEulaAcceptance())
// - satu sumber kebenaran di sini, bukan tersebar di banyak file.
const EULA_VERSION = '2026-08-19';
$error = null;
$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '-');
// Ada di tahap 2 (2FA) kalau marker session ini terisi - dari attempt()
// yang mengembalikan 'needs_2fa' di request SEBELUMNYA, atau dari
// request INI SENDIRI kalau baru saja masuk tahap itu.
$pendingUsername = (string) ($_SESSION['ntpsense_2fa_pending_username'] ?? '');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['totp_code'])) {
        // ------------------------------------------------------------
        // Tahap 2 - verifikasi kode TOTP ATAU recovery code. Session
        // ADMIN PENUH baru benar-benar difinalisasi di dalam
        // verifyTwoFactor() sendiri (bukan di sini) - sebelum ini
        // berhasil, marker 'ntpsense_2fa_pending_username' TIDAK
        // memberi akses apa pun ke halaman lain.
        // ------------------------------------------------------------
        $code = trim((string) $_POST['totp_code']);
        // Ambil username SEBELUM verifyTwoFactor() dipanggil - fungsi
        // itu unset() marker pending-nya begitu sukses, jadi kalau
        // dibaca SESUDAH pemanggilan, sudah kosong.
        $usernameForEulaLog = (string) ($_SESSION['ntpsense_2fa_pending_username'] ?? '');
        if (Auth::verifyTwoFactor($code)) {
            // RCA (ditemukan saat menambahkan pencatatan EULA - BUKAN
            // bug lama, murni gap yang baru disadari): checkbox EULA
            // dicentang di TAHAP 1 (request sebelumnya, sebelum masuk
            // alur 2FA) dan sampai sekarang TIDAK PERNAH benar-benar
            // dicatat ke mana pun - cuma jadi syarat submit form yang
            // hilang begitu request selesai. Dicatat DI SINI (bukan di
            // tahap 1) supaya SELALU terikat ke sesi yang benar-benar
            // berhasil sepenuhnya (password + 2FA keduanya benar),
            // bukan ke sekadar "checkbox tercentang" yang bisa saja
            // menyertai percobaan login yang akhirnya gagal.
            AuditLog::logEulaAcceptance($usernameForEulaLog, EULA_VERSION);
            header('Location: /index.php');
            exit;
        }
        $error = 'Incorrect authentication code. Use the current code from your authenticator app, or one of your saved recovery codes.';
        $pendingUsername = (string) ($_SESSION['ntpsense_2fa_pending_username'] ?? '');
    } elseif (isset($_POST['cancel_2fa'])) {
        // Batal di tengah tahap 2 - kembali ke form username/password
        // biasa (mis. salah akun, atau berubah pikiran).
        unset($_SESSION['ntpsense_2fa_pending_username']);
        header('Location: /login.php');
        exit;
    } else {
        // ------------------------------------------------------------
        // Tahap 1 - username/password seperti sebelumnya.
        // ------------------------------------------------------------
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $eulaAccepted = ($_POST['eula'] ?? '') === '1';
        $captchaAnswer = trim((string) ($_POST['captcha_answer'] ?? ''));
        $expectedCaptcha = (string) ($_SESSION['captcha_answer'] ?? '');
        if (!$eulaAccepted) {
            $error = 'You must accept the End User License Agreement to log in.';
        } elseif (Auth::isLockedOut($username, $ip)) {
            $remaining = Auth::lockoutSecondsRemaining($username, $ip);
            $minutes = (int) ceil($remaining / 60);
            $error = "Too many failed login attempts. Try again in about {$minutes} minute" . ($minutes === 1 ? '' : 's') . '.';
        } elseif ($expectedCaptcha === '' || $captchaAnswer !== $expectedCaptcha) {
            $error = 'Incorrect answer to the verification question.';
        } else {
            $result = Auth::attempt($username, $password);
            if ($result === 'ok') {
                unset($_SESSION['captcha_answer']);
                // Login penuh berhasil (tanpa 2FA) - catat penerimaan
                // EULA DI SINI, terikat ke username yang sudah
                // TERVERIFIKASI benar oleh Auth::attempt(), bukan ke
                // $_POST['username'] mentah yang bisa saja typo/palsu
                // kalau dicatat lebih awal sebelum verifikasi password.
                AuditLog::logEulaAcceptance($username, EULA_VERSION);
                header('Location: /index.php');
                exit;
            } elseif ($result === 'needs_2fa') {
                unset($_SESSION['captcha_answer']);
                $pendingUsername = (string) ($_SESSION['ntpsense_2fa_pending_username'] ?? '');
                // BELUM dicatat di sini - baru dicatat di tahap 2 di
                // atas, setelah kode TOTP juga terverifikasi benar.
            } else {
                $error = 'Incorrect username or password.';
            }
        }
    }
}
// CAPTCHA matematis sederhana, di-generate SERVER-SIDE - sengaja bukan
// reCAPTCHA/hCaptcha (butuh koneksi internet ke pihak ketiga, tidak
// cocok untuk gateway yang seharusnya tetap bisa dikelola meski WAN
// mati atau di jaringan terisolasi). Jawaban disimpan di session,
// dibuat ulang setiap kali halaman ini dirender (termasuk setelah
// gagal login) supaya tidak bisa dipakai berulang oleh script otomatis.
// Tidak dipakai lagi di tahap 2 (2FA) - CAPTCHA cuma relevan buat
// mencegah brute-force password tahap 1.
$num1 = random_int(1, 9);
$num2 = random_int(1, 9);
$_SESSION['captcha_answer'] = (string) ($num1 + $num2);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login - NTPSense InetGateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/assets/app.css">
<style>
  /* Override lokal, HANYA untuk halaman login - sengaja tidak
     menyentuh app.css (dipakai banyak halaman lain, riskan kalau
     diedit tanpa melihat isi lengkapnya). */
  .ntp-login-box { max-width: 440px; width: 100%; }
  .ntp-captcha-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .ntp-captcha-row label { white-space: nowrap; margin: 0; }
  .ntp-captcha-row input { flex: 1; min-width: 0; }
  .ntp-eula-row {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    text-align: left;
    padding: 10px 4px;
  }
  .ntp-eula-row input[type="checkbox"] { flex: 0 0 auto; margin: 0; }
  .ntp-eula-row label { font-weight: normal; font-size: 13px; margin: 0; line-height: 1.4; }
  /* app.css tidak men-style state :disabled secara berbeda (tombol
     tetap terlihat biru/aktif meski atribut disabled sudah benar) -
     dipaksa di sini dengan !important supaya visualnya jelas non-aktif
     sebelum EULA dicentang. */
  #login-submit-btn:disabled {
    background: #9ca3af !important;
    color: #f3f4f6 !important;
    cursor: not-allowed !important;
    opacity: 1 !important;
  }
  .ntp-totp-code-input {
    letter-spacing: 4px;
    font-size: 20px;
    text-align: center;
  }
</style>
</head>
<body>
<div class="ntp-login-wrap">
  <div class="ntp-login-box">
    <h1>NTPSense InetGateway</h1>
    <?php if ($pendingUsername !== ''): ?>
      <p>Enter the code from your authenticator app.</p>
      <?php if ($error): ?>
        <div class="ntp-alert-error"><?= htmlspecialchars($error) ?></div>
      <?php endif; ?>
      <form method="post">
        <div class="ntp-field">
          <label for="totp_code">Authentication code</label>
          <input type="text" id="totp_code" name="totp_code" class="ntp-totp-code-input" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" maxlength="10" required autofocus>
          <p style="font-size:11px; color:#6b7280; margin:6px 0 0;">6-digit code from your app, or one of your saved recovery codes.</p>
        </div>
        <button type="submit" class="ntp-btn-primary">Verify</button>
      </form>
      <form method="post" style="margin-top:10px; text-align:center;">
        <input type="hidden" name="cancel_2fa" value="1">
        <button type="submit" style="background:none; border:none; color:#6b7280; font-size:12px; cursor:pointer; text-decoration:underline;">Back to login</button>
      </form>
    <?php else: ?>
      <p>Sign in to manage your gateway.</p>
      <?php if ($error): ?>
        <div class="ntp-alert-error"><?= htmlspecialchars($error) ?></div>
      <?php endif; ?>
      <form method="post">
        <div class="ntp-field">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" autocomplete="username" required autofocus>
        </div>
        <div class="ntp-field">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" autocomplete="current-password" required>
        </div>
        <div class="ntp-field ntp-captcha-row">
          <label for="captcha_answer">What is <?= $num1 ?> + <?= $num2 ?>?</label>
          <input type="text" id="captcha_answer" name="captcha_answer" inputmode="numeric" autocomplete="off" required>
        </div>
        <div class="ntp-eula-row">
          <input type="checkbox" id="eula" name="eula" value="1" onchange="document.getElementById('login-submit-btn').disabled = !this.checked;">
          <label for="eula">
            I have read and agree to the
            <a href="/eula.php" target="_blank" rel="noopener">End User License Agreement</a>.
          </label>
        </div>
        <button type="submit" id="login-submit-btn" class="ntp-btn-primary" disabled>Sign In</button>
      </form>
    <?php endif; ?>
  </div>
</div>
</body>
</html>
