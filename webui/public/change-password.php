<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';

if (empty($_SESSION['ntpsense_admin'])) {
    header('Location: /login.php');
    exit;
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new = (string) ($_POST['new_password'] ?? '');
    $confirm = (string) ($_POST['confirm_password'] ?? '');
    if (strlen($new) < 8) {
        $error = 'New password must be at least 8 characters.';
    } elseif ($new !== $confirm) {
        $error = 'Password confirmation does not match.';
    } else {
        Auth::changePassword($new);
        header('Location: /index.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Change Password - NTPSense InetGateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<div class="ntp-login-wrap">
  <div class="ntp-login-box">
    <h1>Change password</h1>
    <p>You must change the default password before continuing.</p>
    <?php if ($error): ?>
      <div class="ntp-alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="post">
      <div class="ntp-field">
        <label for="new_password">New password</label>
        <input type="password" id="new_password" name="new_password" required minlength="8" autofocus>
      </div>
      <div class="ntp-field">
        <label for="confirm_password">Confirm new password</label>
        <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
      </div>
      <button type="submit" class="ntp-btn-primary">Save</button>
    </form>
  </div>
</div>
</body>
</html>
