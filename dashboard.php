<?php
declare(strict_types=1);
session_start();
date_default_timezone_set('Asia/Manila');

/* Only logged-in users may see this page */
if (!isset($_SESSION['uid'])) {
    header('Location: login.php');
    exit;
}

$db = new PDO('sqlite:' . __DIR__ . '/data/users.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$h = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

$st = $db->prepare('SELECT email, password, created_at FROM users WHERE id = ?');
$st->execute([$_SESSION['uid']]);
$me = $st->fetch(PDO::FETCH_ASSOC);
if (!$me) { // account no longer exists
    session_destroy();
    header('Location: login.php');
    exit;
}

/* ---------- Change password ---------- */
$msg = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('Invalid request.');
    }
    $current = (string)($_POST['current'] ?? '');
    $new = (string)($_POST['new'] ?? '');

    if (!password_verify($current, $me['password'])) {
        $msg = ['error', 'Your current password is incorrect.'];
    } elseif (strlen($new) < 6) {
        $msg = ['error', 'New password must be at least 6 characters.'];
    } elseif ($new !== (string)($_POST['confirm'] ?? '')) {
        $msg = ['error', 'New passwords do not match.'];
    } else {
        $db->prepare('UPDATE users SET password = ? WHERE id = ?')
           ->execute([password_hash($new, PASSWORD_DEFAULT), $_SESSION['uid']]);
        session_regenerate_id(true);
        $msg = ['success', 'Password updated.'];
    }
}

$total = (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn();
$since = (new DateTime($me['created_at'], new DateTimeZone('UTC')))
    ->setTimezone(new DateTimeZone('Asia/Manila'))->format('M j, Y');
$name = ucfirst(explode('@', $me['email'])[0]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard · SSG</title>
  <style>
    :root { --bg:#04130b; --line:rgb(245 197 24 / 18%); --yellow:#f5c518; --yellow-light:#ffe27a; --text:#f1f5ea; --muted:#93b09c; --error:#ffb4a2; --ok:#7be39b; }
    * { box-sizing: border-box; }
    body { min-height:100vh; margin:0; color:var(--text); font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
      background:radial-gradient(circle at 0 0,#1c7a46 0,transparent 45%),radial-gradient(circle at 100% 100%,rgb(184 144 10 / 45%) 0,transparent 40%),var(--bg); }
    header { display:flex; justify-content:space-between; align-items:center; gap:12px; padding:16px 24px; border-bottom:1px solid var(--line); background:rgb(4 19 11 / 65%); backdrop-filter:blur(14px); }
    .brand { font-weight:800; letter-spacing:1.5px; } .brand span { color:var(--yellow); }
    main { max-width:960px; margin:0 auto; padding:32px 20px 60px; }
    h2 { margin:0; font-size:clamp(1.6rem,4vw,2.4rem); } h2 em { font-style:normal; color:var(--yellow); }
    .top { display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; gap:16px; margin-bottom:24px; }
    .top p { margin:6px 0 0; color:var(--muted); }
    .clock { text-align:right; } .clock b { display:block; font-size:2rem; color:var(--yellow); font-variant-numeric:tabular-nums; } .clock span { color:var(--muted); font-size:.9rem; }
    .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-bottom:24px; }
    .glass { border:1px solid var(--line); border-radius:18px; background:rgb(255 255 255 / 5%); padding:20px; }
    .stat b { display:block; font-size:1.5rem; color:var(--yellow); word-break:break-all; } .stat span { color:var(--muted); font-size:.85rem; }
    h3 { margin:0 0 14px; color:var(--yellow-light); font-size:1rem; }
    .fg { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; }
    input { width:100%; min-height:44px; padding:10px 12px; border:1.5px solid #17502f; border-radius:10px; background:rgb(4 19 11 / 70%); color:var(--text); font:inherit; }
    input:focus { border-color:var(--yellow); outline:3px solid rgb(245 197 24 / 18%); }
    button { min-height:44px; padding:0 24px; border:0; border-radius:10px; background:linear-gradient(135deg,var(--yellow-light),var(--yellow)); color:#0a2416; cursor:pointer; font:inherit; font-weight:800; letter-spacing:1px; }
    form.logout button { min-height:38px; padding:0 18px; background:none; border:1.5px solid var(--yellow); color:var(--yellow); }
    form.logout button:hover { background:var(--yellow); color:#0a2416; }
    .panel button { margin-top:14px; }
    .message { margin:0 0 14px; } .message.error { color:var(--error); } .message.success { color:var(--ok); }
  </style>
</head>
<body>
  <header>
    <div class="brand">SSG <span>PORTAL</span></div>
    <form method="post" action="login.php" class="logout">
      <input type="hidden" name="csrf" value="<?= $h($_SESSION['csrf']) ?>">
      <input type="hidden" name="action" value="logout">
      <button type="submit">LOG OUT</button>
    </form>
  </header>

  <main>
    <div class="top">
      <div>
        <h2>Hello, <em><?= $h($name) ?></em>.</h2>
        <p>Welcome to your dashboard.</p>
      </div>
      <div class="clock"><b id="clock">--:--:--</b><span id="today"></span></div>
    </div>

    <div class="stats">
      <div class="glass stat"><b><?= $total ?></b><span>Registered members</span></div>
      <div class="glass stat"><b><?= $h($since) ?></b><span>Member since</span></div>
      <div class="glass stat"><b><?= $h($me['email']) ?></b><span>Signed in as</span></div>
    </div>

    <form method="post" class="glass panel" novalidate>
      <h3>Change password</h3>
      <?php if ($msg): ?><p class="message <?= $h($msg[0]) ?>" role="status"><?= $h($msg[1]) ?></p><?php endif; ?>
      <input type="hidden" name="csrf" value="<?= $h($_SESSION['csrf']) ?>">
      <div class="fg">
        <input name="current" type="password" placeholder="Current password" autocomplete="current-password" required>
        <input name="new" type="password" placeholder="New password" autocomplete="new-password" required>
        <input name="confirm" type="password" placeholder="Confirm new password" autocomplete="new-password" required>
      </div>
      <button type="submit">UPDATE PASSWORD</button>
    </form>
  </main>

  <script>
    function tick() {
      const n = new Date();
      document.getElementById("clock").textContent = n.toLocaleTimeString("en-US", { hour12: false });
      document.getElementById("today").textContent = n.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
    }
    tick(); setInterval(tick, 1000);
  </script>
</body>
</html>
