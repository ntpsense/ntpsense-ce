<?php
declare(strict_types=1);
require __DIR__ . '/../lib/Auth.php';
Auth::startSession();

Auth::logout();
header('Location: /login.php');
exit;
