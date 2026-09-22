<?php
declare(strict_types=1);
session_start();
require __DIR__ . '/../lib/Auth.php';

Auth::logout();
header('Location: /login.php');
exit;
