<?php
/**
 * panel.php — Panel de control del dueño.
 * - Auto-setup en primer uso (define password).
 * - Login con bcrypt + cookie HMAC de sesión (2h).
 * - Toggle de dev mode (8h cookie _dev) que bypasea el gate.
 * - Throttling básico contra brute-force.
 */
require_once __DIR__ . '/_lib.php';

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$flash  = '';
$flash_type = 'info';

// ----- Throttle -----
$throttle_file = sys_get_temp_dir() . '/.panel_throttle_' . md5(gate_client_ip());
function throttle_get($f) {
    if (!file_exists($f)) return [0, 0];
    $d = @json_decode(@file_get_contents($f), true);
    return is_array($d) ? [$d[0] ?? 0, $d[1] ?? 0] : [0, 0];
}
function throttle_set($f, $count, $until) {
    @file_put_contents($f, json_encode([$count, $until]));
}
[$fail_count, $lock_until] = throttle_get($throttle_file);
$now = time();
$locked = $lock_until > $now;

// ----- Acciones -----
if ($method === 'POST' && !$locked) {
    // SETUP: primera vez creando password
    if ($action === 'setup' && !panel_pass_exists()) {
        $p1 = $_POST['p1'] ?? '';
        $p2 = $_POST['p2'] ?? '';
        if (strlen($p1) < 8) {
            $flash = 'La contraseña debe tener mínimo 8 caracteres.';
            $flash_type = 'error';
        } elseif ($p1 !== $p2) {
            $flash = 'Las contraseñas no coinciden.';
            $flash_type = 'error';
        } elseif (panel_pass_set($p1)) {
            panel_session_set(true);
            header('Location: /panel.php');
            exit;
        } else {
            $flash = 'Error guardando la contraseña.';
            $flash_type = 'error';
        }
    }

    // LOGIN
    if ($action === 'login' && panel_pass_exists()) {
        $p = $_POST['p'] ?? '';
        if (panel_pass_verify($p)) {
            throttle_set($throttle_file, 0, 0);
            panel_session_set(true);
            header('Location: /panel.php');
            exit;
        } else {
            $fail_count++;
            $until = $fail_count >= 5 ? $now + 900 : 0; // lock 15min tras 5 fails
            throttle_set($throttle_file, $fail_count, $until);
            sleep(1); // pequeña demora anti brute-force
            $flash = 'Contraseña incorrecta.' . ($until ? ' Bloqueado 15 minutos.' : '');
            $flash_type = 'error';
        }
    }

    // Acciones autenticadas
    if (panel_session_active()) {
        if ($action === 'dev_on') {
            gate_dev_set(true);
            $flash = 'Dev mode ACTIVADO. Puedes navegar /web/ libremente por 8h.';
            $flash_type = 'success';
        }
        if ($action === 'dev_off') {
            gate_dev_set(false);
            $flash = 'Dev mode desactivado.';
            $flash_type = 'info';
        }
        if ($action === 'logout') {
            panel_session_set(false);
            gate_dev_set(false);
            header('Location: /panel.php');
            exit;
        }
        if ($action === 'change_pass') {
            $p1 = $_POST['p1'] ?? '';
            $p2 = $_POST['p2'] ?? '';
            $cur = $_POST['cur'] ?? '';
            if (!panel_pass_verify($cur)) {
                $flash = 'Contraseña actual incorrecta.'; $flash_type = 'error';
            } elseif (strlen($p1) < 8 || $p1 !== $p2) {
                $flash = 'Contraseña nueva inválida (mín 8, deben coincidir).'; $flash_type = 'error';
            } elseif (panel_pass_set($p1)) {
                $flash = 'Contraseña actualizada.'; $flash_type = 'success';
            }
        }
    }
}

// ----- Estado -----
$logged    = panel_session_active();
$has_pass  = panel_pass_exists();
$dev_on    = gate_dev_active();
$ip        = gate_client_ip();
$country   = gate_country($ip) ?: '?';
$ua_short  = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 60);
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>Panel</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0e1a;--card:#131826;--border:#1f2937;--text:#e5e7eb;--muted:#6b7280;--accent:#10b981;--danger:#ef4444;--warning:#f59e0b;--info:#3b82f6}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;line-height:1.5}
.wrap{width:100%;max-width:480px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:28px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:22px;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:10px}
.sub{color:var(--muted);font-size:14px;margin-bottom:24px}
.flash{padding:12px 14px;border-radius:8px;font-size:14px;margin-bottom:18px;border:1px solid}
.flash.info{background:rgba(59,130,246,.1);border-color:var(--info);color:#93c5fd}
.flash.success{background:rgba(16,185,129,.1);border-color:var(--accent);color:#6ee7b7}
.flash.error{background:rgba(239,68,68,.1);border-color:var(--danger);color:#fca5a5}
.flash.warning{background:rgba(245,158,11,.1);border-color:var(--warning);color:#fcd34d}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px;font-weight:500}
input[type=password],input[type=text]{width:100%;padding:11px 14px;background:#0a0e1a;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:15px;font-family:inherit;transition:border-color .15s}
input[type=password]:focus,input[type=text]:focus{outline:none;border-color:var(--accent)}
.field{margin-bottom:14px}
button,.btn{width:100%;padding:12px 16px;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:all .15s;font-family:inherit;text-decoration:none;display:inline-block;text-align:center}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#059669}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover{background:#dc2626}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--text)}
.row{display:flex;gap:10px;margin-top:14px}
.row > *{flex:1}
.status{display:flex;align-items:center;gap:12px;padding:16px;background:#0a0e1a;border:1px solid var(--border);border-radius:10px;margin-bottom:18px}
.dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
.dot.on{background:var(--accent);box-shadow:0 0 12px var(--accent)}
.dot.off{background:var(--muted)}
.status-text{flex:1}
.status-text strong{display:block;font-size:15px;margin-bottom:2px}
.status-text small{color:var(--muted);font-size:12px}
.info-grid{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:12px;color:var(--muted);padding:14px;background:#0a0e1a;border-radius:8px;margin-bottom:18px;border:1px solid var(--border);font-family:'SF Mono',Menlo,monospace}
.info-grid b{color:var(--text);font-weight:500}
.divider{height:1px;background:var(--border);margin:20px 0}
.links{display:flex;gap:14px;justify-content:center;font-size:13px;margin-top:16px}
.links a{color:var(--muted);text-decoration:none}
.links a:hover{color:var(--text)}
details{margin-top:14px;font-size:13px}
summary{cursor:pointer;color:var(--muted);user-select:none;padding:6px 0}
summary:hover{color:var(--text)}
details[open] summary{margin-bottom:10px}
.lock-badge{display:inline-block;padding:2px 8px;border-radius:6px;background:rgba(239,68,68,.15);color:var(--danger);font-size:11px;margin-left:6px}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">

<?php if ($flash): ?>
    <div class="flash <?= htmlspecialchars($flash_type) ?>"><?= htmlspecialchars($flash) ?></div>
<?php endif; ?>

<?php if (!$has_pass): ?>
    <!-- ============ SETUP ============ -->
    <h1>🔧 Configuración inicial</h1>
    <p class="sub">Define la contraseña del panel. Mínimo 8 caracteres. No la olvides — se guarda como bcrypt.</p>
    <form method="POST" autocomplete="off">
      <input type="hidden" name="action" value="setup">
      <div class="field">
        <label>Contraseña</label>
        <input type="password" name="p1" required minlength="8" autofocus>
      </div>
      <div class="field">
        <label>Confirmar contraseña</label>
        <input type="password" name="p2" required minlength="8">
      </div>
      <button class="btn btn-primary" type="submit">Crear cuenta</button>
    </form>

<?php elseif (!$logged): ?>
    <!-- ============ LOGIN ============ -->
    <h1>🔐 Panel<?= $locked ? ' <span class="lock-badge">BLOQUEADO</span>' : '' ?></h1>
    <p class="sub"><?= $locked ? 'Demasiados intentos fallidos. Espera 15 minutos.' : 'Ingresa tu contraseña para continuar.' ?></p>
<?php if (!$locked): ?>
    <form method="POST" autocomplete="off">
      <input type="hidden" name="action" value="login">
      <div class="field">
        <label>Contraseña</label>
        <input type="password" name="p" required autofocus>
      </div>
      <button class="btn btn-primary" type="submit">Entrar</button>
    </form>
<?php endif; ?>

<?php else: ?>
    <!-- ============ DASHBOARD ============ -->
    <h1>⚡ Control Panel</h1>
    <p class="sub">Activa Dev Mode para acceder a <code>/web/</code> sin pasar por el anuncio.</p>

    <div class="status">
      <div class="dot <?= $dev_on ? 'on' : 'off' ?>"></div>
      <div class="status-text">
        <strong>Dev Mode: <?= $dev_on ? 'ACTIVO' : 'Inactivo' ?></strong>
        <small><?= $dev_on ? 'Cookie _dev emitida (8h). Bypass de gate activado.' : 'El gate está bloqueando todo acceso normal a /web/.' ?></small>
      </div>
    </div>

    <form method="POST">
      <input type="hidden" name="action" value="<?= $dev_on ? 'dev_off' : 'dev_on' ?>">
      <button class="btn <?= $dev_on ? 'btn-danger' : 'btn-primary' ?>" type="submit">
        <?= $dev_on ? '🛑 Desactivar Dev Mode' : '✅ Activar Dev Mode' ?>
      </button>
    </form>

<?php if ($dev_on): ?>
    <div class="row">
      <a class="btn btn-ghost" href="/web/index.php" target="_blank">🌐 Abrir /web/</a>
      <a class="btn btn-ghost" href="/" target="_blank">📄 Ver landing</a>
    </div>
<?php endif; ?>

    <div class="divider"></div>

    <div class="info-grid">
      <span>IP:</span><b><?= htmlspecialchars($ip) ?></b>
      <span>País:</span><b><?= htmlspecialchars($country) ?></b>
      <span>UA:</span><b><?= htmlspecialchars($ua_short) ?>…</b>
    </div>

    <details>
      <summary>Cambiar contraseña</summary>
      <form method="POST" autocomplete="off">
        <input type="hidden" name="action" value="change_pass">
        <div class="field"><label>Contraseña actual</label><input type="password" name="cur" required></div>
        <div class="field"><label>Nueva</label><input type="password" name="p1" required minlength="8"></div>
        <div class="field"><label>Confirmar nueva</label><input type="password" name="p2" required minlength="8"></div>
        <button class="btn btn-ghost" type="submit">Actualizar</button>
      </form>
    </details>

    <div class="links">
      <form method="POST" style="display:inline">
        <input type="hidden" name="action" value="logout">
        <button class="btn btn-ghost" type="submit" style="width:auto;padding:6px 14px;font-size:13px;font-weight:400">Cerrar sesión</button>
      </form>
    </div>
<?php endif; ?>

  </div>
</div>
</body>
</html>
