<?php
/**
 * v.php — Endpoint de verificación JS (fingerprint).
 * Recibe POST JSON con fingerprint del browser. Si el visitante pasa todas
 * las validaciones (server + cliente), emite la cookie HMAC `_qok` y
 * responde con la URL destino.
 */
require_once __DIR__ . '/_lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('X-Content-Type-Options: nosniff');

// Solo POST
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false]);
    exit;
}

// Re-ejecutar checks server-side (mismas reglas que /index.php)
// pero aquí permitimos sin origen Meta porque /index.php ya filtró eso,
// y este endpoint puede ser llamado en navegaciones internas.
[$score, $reasons] = gate_compute_score(['require_origin' => false]);

// Parsear fingerprint
$raw = file_get_contents('php://input');
$fp  = json_decode($raw, true);
if (!is_array($fp)) { $fp = []; }

// ---------- VALIDACIONES JS-SIDE ----------
$jss = 0;
$jr  = [];

// Automation flags
if (!empty($fp['wd']))                                   { $jss += 12; $jr[] = 'webdriver'; }
if (!empty($fp['wa']))                                   { $jss += 8;  $jr[] = 'wd_attr'; }

// Plugins: navegadores reales (móvil incluido) suelen tener >= 0; pero 0 + Chrome UA + no touch = sospechoso
if (($fp['pl'] ?? 0) === 0 && stripos($fp['ua'] ?? '', 'chrome') !== false && empty($fp['tch'])) {
    $jss += 4; $jr[] = 'no_plugins_chrome_desktop';
}

// Idioma del navegador (preferencia es-*, suave para CO con UI inglesa)
$lg  = strtolower((string)($fp['lg']  ?? ''));
$lgs = strtolower((string)($fp['lgs'] ?? ''));
if (!preg_match('/^es(\b|-)/', $lg) && stripos($lgs, 'es') === false) {
    $jss += 2; $jr[] = 'lang_not_es';
}

// Timezone: Colombia es UTC-5 => getTimezoneOffset() === 300
// Aceptamos también -300 (algunos engines), y +/-1 por edge cases.
$tz = (int)($fp['tz'] ?? 0);
if (!in_array($tz, [300, -300], true)) {
    // Permitimos también +-240 a +-360 como tolerancia regional (algunos países LATAM)
    if ($tz < 240 || $tz > 360) {
        $jss += 12; $jr[] = 'tz_not_co:' . $tz;
    } else {
        $jss += 4; $jr[] = 'tz_near_co:' . $tz;
    }
}

// Resolución mobile: ancho < 900px típico
if (($fp['sw'] ?? 0) > 1024) { $jss += 6; $jr[] = 'screen_desktop:' . ($fp['sw'] ?? 0); }
if (($fp['sw'] ?? 0) < 240)  { $jss += 4; $jr[] = 'screen_too_small'; }

// Touch points: dispositivo móvil DEBE tener touch
if (empty($fp['tch'])) { $jss += 6; $jr[] = 'no_touch'; }

// DPR: móviles modernos >= 1.5 normalmente
if (($fp['dpr'] ?? 0) < 1) { $jss += 3; $jr[] = 'low_dpr'; }

// Hardware concurrency: 0 es headless típicamente
if (($fp['hw'] ?? 0) === 0) { $jss += 5; $jr[] = 'no_hw_concurrency'; }

// chrome object: Chrome real lo expone como 'object'
if (stripos($fp['ua'] ?? '', 'chrome') !== false && ($fp['ch'] ?? '') !== 'object') {
    $jss += 5; $jr[] = 'chrome_obj_missing';
}

// Canvas: si está vacío, blocker o headless sin canvas (suave: privacy browsers)
if (empty($fp['cv'])) { $jss += 3; $jr[] = 'canvas_empty'; }

// UA reportado por JS debe coincidir con el del header (anti-spoofing trivial,
// suave porque Brave/Firefox a veces normalizan)
$ua_hdr = $_SERVER['HTTP_USER_AGENT'] ?? '';
if ($ua_hdr && !empty($fp['ua']) && $fp['ua'] !== $ua_hdr) {
    $jss += 4; $jr[] = 'ua_mismatch';
}

// ---------- DECISIÓN ----------
$total = $score + $jss;
if ($total >= 8 || $score >= 8 || $jss >= 8) {
    // No emitir cookie. Respuesta neutra.
    echo json_encode(['ok' => false]);
    exit;
}

// Emitir cookie HMAC válida (30 min)
gate_set_cookie(1800);

echo json_encode([
    'ok'   => true,
    'next' => '/web/index.php',
]);
