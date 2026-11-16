<?php
declare(strict_types=1);
session_start();

/* ---------- Database (SQLite file is created automatically) ---------- */
$dir = __DIR__ . '/data';
is_dir($dir) || mkdir($dir, 0755);
is_file("$dir/.htaccess") || file_put_contents("$dir/.htaccess", "Require all denied\n"); // blocks downloads of the DB

$db = new PDO('sqlite:' . "$dir/users.sqlite");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP)');

$h = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

$mode = ($_GET['mode'] ?? '') === 'signup' ? 'signup' : 'login';
$msg = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

/* ---------- Handle form posts ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('Invalid request.');
    }

    $action = $_POST['action'] ?? '';
    $email  = strtolower(trim((string)($_POST['email'] ?? '')));
    $pass   = (string)($_POST['password'] ?? '');

    if ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: login.php');
        exit;
    }

    if ($action === 'signup') {
        $mode = 'signup';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $msg = ['error', 'Enter a valid email address.'];
        } elseif (strlen($pass) < 6) {
            $msg = ['error', 'Password must be at least 6 characters.'];
        } elseif ($pass !== (string)($_POST['confirm'] ?? '')) {
            $msg = ['error', 'Passwords do not match.'];
        } else {
            try {
                $db->prepare('INSERT INTO users (email, password) VALUES (?, ?)')
                   ->execute([$email, password_hash($pass, PASSWORD_DEFAULT)]);
                $_SESSION['flash'] = ['success', 'Account created. You can log in now.'];
                header('Location: login.php');
                exit;
            } catch (PDOException $e) {
                $msg = ['error', 'That email already has an account. Log in instead.'];
            }
        }
    }

    if ($action === 'login') {
        $st = $db->prepare('SELECT id, password FROM users WHERE email = ?');
        $st->execute([$email]);
        $user = $st->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($pass, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['uid'] = $user['id'];
            $_SESSION['email'] = $email;
            header('Location: login.php');
            exit;
        }
        usleep(300000); // slows down password guessing
        $msg = ['error', 'Email or password is incorrect.'];
    }
}

$loggedIn = isset($_SESSION['uid']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSG Login System</title>
  <style>
    :root { --bg:#04130b; --line:rgb(245 197 24 / 18%); --yellow:#f5c518; --yellow-light:#ffe27a; --text:#f1f5ea; --muted:#93b09c; --error:#ffb4a2; --ok:#7be39b; }
    * { box-sizing: border-box; }
    body { min-height:100vh; margin:0; display:grid; place-items:center; padding:24px; color:var(--text);
      font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
      background:radial-gradient(circle at 0 0,#1c7a46 0,transparent 45%),radial-gradient(circle at 100% 100%,rgb(184 144 10 / 45%) 0,transparent 40%),var(--bg); }
    .card { width:min(100%,420px); padding:32px; border:1px solid var(--line); border-radius:20px;
      background:rgb(255 255 255 / 5%); backdrop-filter:blur(16px); box-shadow:0 30px 80px rgb(0 0 0 / 50%); }
    h1 { margin:0 0 8px; font-size:1.6rem; } h1 span { color:var(--yellow); }
    .intro { margin:0 0 20px; color:var(--muted); line-height:1.5; }
    .tabs { display:flex; gap:8px; }
    .tabs a { flex:1; padding:10px; text-align:center; border:1.5px solid #17502f; border-radius:10px; color:var(--muted); font-weight:700; text-decoration:none; }
    .tabs a.on { background:var(--yellow); border-color:var(--yellow); color:#0a2416; }
    label { display:block; margin:16px 0 7px; font-weight:600; }
    input { width:100%; min-height:46px; padding:10px 12px; border:1.5px solid #17502f; border-radius:10px; background:rgb(4 19 11 / 70%); color:var(--text); font:inherit; }
    input:focus { border-color:var(--yellow); outline:3px solid rgb(245 197 24 / 18%); }
    button { width:100%; min-height:46px; margin-top:22px; border:0; border-radius:10px; background:linear-gradient(135deg,var(--yellow-light),var(--yellow)); color:#0a2416; cursor:pointer; font:inherit; font-weight:800; letter-spacing:1px; box-shadow:0 10px 26px rgb(245 197 24 / 28%); }
    button:hover { filter:brightness(1.06); }
    .message { margin:16px 0 0; line-height:1.5; } .message.error { color:var(--error); } .message.success { color:var(--ok); }
  </style>
</head>
<body>
  <main class="card">
    <h1>SSG <span>LOGIN</span> SYSTEM</h1>

    <?php if ($msg): ?>
      <p class="message <?= $h($msg[0]) ?>" role="status"><?= $h($msg[1]) ?></p>
    <?php endif; ?>

    <?php if ($loggedIn): ?>
      <p class="intro">You are signed in as <b><?= $h($_SESSION['email']) ?></b>.</p>
      <form method="post">
        <input type="hidden" name="csrf" value="<?= $h($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="logout">
        <button type="submit">LOG OUT</button>
      </form>
    <?php else: ?>
      <p class="intro">Create an account first, then log in.</p>
      <div class="tabs">
        <a href="login.php" class="<?= $mode === 'login' ? 'on' : '' ?>">Log in</a>
        <a href="login.php?mode=signup" class="<?= $mode === 'signup' ? 'on' : '' ?>">Create account</a>
      </div>
      <form method="post" novalidate>
        <input type="hidden" name="csrf" value="<?= $h($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="<?= $mode ?>">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="username" value="<?= $h((string)($_POST['email'] ?? '')) ?>" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="<?= $mode === 'login' ? 'current-password' : 'new-password' ?>" required>
        <?php if ($mode === 'signup'): ?>
          <label for="confirm">Confirm password</label>
          <input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
        <?php endif; ?>
        <button type="submit"><?= $mode === 'login' ? 'LOG IN' : 'CREATE ACCOUNT' ?></button>
      </form>
    <?php endif; ?>
  </main>
</body>
</html>
