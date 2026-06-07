<?php
/**
 * _lib.php — Núcleo del sistema de cloaking/gate
 * Incluido por index.php, v.php y web/_gate.php
 */

if (defined('GATE_LIB_LOADED')) return;
define('GATE_LIB_LOADED', true);

// ---------------------------------------------------------------
// SECRETO HMAC (auto-genera y persiste; fallback hardcoded)
// ---------------------------------------------------------------
function gate_secret() {
    static $cached = null;
    if ($cached !== null) return $cached;
    // 1) Env var (Heroku, Vercel, etc.) — recomendado en producción
    $env = getenv('GATE_SECRET');
    if ($env && strlen(trim($env)) >= 32) { return $cached = trim($env); }
    // 2) Archivo persistido (fallback para hosting tradicional)
    $f = __DIR__ . '/.gate_secret';
    if (!file_exists($f) || filesize($f) < 32) {
        @file_put_contents($f, bin2hex(random_bytes(32)));
        @chmod($f, 0600);
    }
    $v = @file_get_contents($f);
    $cached = ($v && strlen(trim($v)) >= 32)
        ? trim($v)
        : '7a3f9e2b1c5d8a4e6f9c2b5a8d1e3f6c9b2a5d8e1f4c7b9a3e6d2f5c8b1a4e7d';
    return $cached;
}

// ---------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------
function gate_client_ip() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    foreach ($headers as $h) {
        if (!empty($_SERVER[$h])) {
            $ip = trim(explode(',', $_SERVER[$h])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return $ip;
        }
    }
    return '0.0.0.0';
}

function gate_ip_prefix($ip) {
    // /24 para tolerar NAT móvil dentro del mismo carrier
    $parts = explode('.', $ip);
    return isset($parts[0], $parts[1], $parts[2]) ? "{$parts[0]}.{$parts[1]}.{$parts[2]}" : $ip;
}

function gate_ua_fp($ua) {
    return substr(hash('sha256', $ua), 0, 16);
}

function gate_b64u_enc($s) {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}
function gate_b64u_dec($s) {
    $r = strtr($s, '-_', '+/');
    $pad = strlen($r) % 4;
    if ($pad) $r .= str_repeat('=', 4 - $pad);
    return base64_decode($r);
}

// ---------------------------------------------------------------
// HMAC TOKEN (cookie _qok)
// ---------------------------------------------------------------
function gate_make_token($ip, $ua, $ttl = 1800) {
    $payload = json_encode([
        'i' => gate_ip_prefix($ip),
        'u' => gate_ua_fp($ua),
        'e' => time() + $ttl,
        'n' => bin2hex(random_bytes(4)),
    ]);
    $p64 = gate_b64u_enc($payload);
    $sig = gate_b64u_enc(hash_hmac('sha256', $p64, gate_secret(), true));
    return $p64 . '.' . $sig;
}

function gate_verify_token($token, $ip, $ua) {
    if (!is_string($token) || strpos($token, '.') === false) return false;
    [$p64, $sig] = explode('.', $token, 2);
    $expected = gate_b64u_enc(hash_hmac('sha256', $p64, gate_secret(), true));
    if (!hash_equals($expected, $sig)) return false;
    $payload = json_decode(gate_b64u_dec($p64), true);
    if (!is_array($payload)) return false;
    if (($payload['e'] ?? 0) < time()) return false;
    if (($payload['i'] ?? '') !== gate_ip_prefix($ip)) return false;
    if (($payload['u'] ?? '') !== gate_ua_fp($ua)) return false;
    return true;
}

// ---------------------------------------------------------------
// DETECCIONES
// ---------------------------------------------------------------
function gate_is_mobile($ua) {
    return (bool) preg_match('/Mobile|Android|iPhone|iPod|webOS|BlackBerry|IEMobile|Opera Mini/i', $ua);
}

function gate_accepts_spanish($accept_lang) {
    if (empty($accept_lang)) return false;
    // Acepta es, es-CO, es-419, es-AR, es-ES, etc.
    return (bool) preg_match('/\bes(-[A-Za-z0-9]+)?\b/i', $accept_lang);
}

function gate_meta_origin($referer, $get_params) {
    // Click legítimo desde anuncio: fbclid presente
    if (!empty($get_params['fbclid'])) return true;
    if (!empty($get_params['igshid'])) return true;
    // O referer desde dominios de Meta
    if (empty($referer)) return false;
    return (bool) preg_match(
        '#^https?://(l|lm|m|www|business|web|mobile)\.(facebook|instagram)\.com/#i',
        $referer
    ) || (bool) preg_match('#^https?://(fb\.me|fb\.gg|fb\.watch|t\.co|bit\.ly)/#i', $referer);
}

// ---------------------------------------------------------------
// GEOLOCATION COLOMBIA
// Tier 1: header Cloudflare. Tier 2: ip-api.com con cache.
// Devuelve 'CO', otro código, o '' si desconocido.
// ---------------------------------------------------------------
function gate_country($ip) {
    $cf = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? '';
    if ($cf && $cf !== 'XX' && $cf !== 'T1') return strtoupper($cf);

    $cache_dir = sys_get_temp_dir();
    $cache_file = $cache_dir . '/geo_' . md5($ip);
    if (file_exists($cache_file) && (time() - filemtime($cache_file)) < 86400) {
        $v = trim((string) @file_get_contents($cache_file));
        if ($v) return $v;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 2, 'method' => 'GET']]);
    $r = @file_get_contents("http://ip-api.com/line/{$ip}?fields=countryCode", false, $ctx);
    if ($r !== false) {
        $r = trim($r);
        if (preg_match('/^[A-Z]{2}$/', $r)) {
            @file_put_contents($cache_file, $r);
            return $r;
        }
    }
    return '';
}

// ---------------------------------------------------------------
// DATACENTER / VPN / HOSTING RANGES (expandido)
// Solo prefijos comunes; bloquea AWS/GCP/Azure/OVH/Hetzner/DO/Linode/Vultr/Contabo
// ---------------------------------------------------------------
function gate_is_datacenter($ip) {
    static $ranges = [
        // AWS
        '3.','13.','15.16.','15.17.','15.18.','15.19.','15.20.','15.21.','15.22.','15.23.','15.193.','15.197.','15.200.','15.220.','15.221.','15.222.','15.230.','15.236.','15.248.','15.252.','15.253.','15.254.','15.255.','18.130.','18.144.','18.156.','18.157.','18.158.','18.159.','18.160.','18.161.','18.162.','18.163.','18.164.','18.165.','18.166.','18.167.','18.168.','18.169.','18.170.','18.171.','18.172.','18.173.','18.174.','18.175.','18.176.','18.177.','18.178.','18.179.','18.180.','18.181.','18.182.','18.183.','18.184.','18.185.','18.186.','18.188.','18.189.','18.190.','18.191.','18.192.','18.193.','18.194.','18.195.','18.196.','18.197.','18.198.','18.199.','18.200.','18.201.','18.202.','18.203.','18.204.','18.205.','18.206.','18.207.','18.208.','18.209.','18.210.','18.211.','18.212.','18.213.','18.214.','18.215.','18.216.','18.217.','18.218.','18.219.','18.220.','18.221.','18.222.','18.223.','18.224.','18.225.','18.226.','18.228.','18.229.','18.230.','18.231.','18.232.','18.233.','18.234.','18.235.','18.236.','18.237.','18.238.','18.246.','35.71.','35.72.','35.73.','35.74.','35.75.','35.76.','35.77.','35.78.','35.79.','35.80.','35.81.','35.82.','35.83.','35.84.','35.85.','35.86.','35.87.','35.88.','35.89.','35.90.','35.91.','35.92.','35.93.','35.94.','35.95.','35.152.','35.153.','35.154.','35.155.','35.156.','35.157.','35.158.','35.165.','35.166.','35.167.','35.168.','35.169.','35.170.','35.171.','35.172.','35.173.','35.174.','35.175.','35.176.','35.177.','35.178.','35.179.','35.180.','35.181.','35.182.','35.183.','52.1.','52.2.','52.3.','52.4.','52.5.','52.6.','52.7.','52.8.','52.9.','52.10.','52.11.','52.13.','52.14.','52.15.','52.16.','52.17.','52.18.','52.19.','52.20.','52.21.','52.22.','52.23.','52.24.','52.25.','52.26.','52.27.','52.28.','52.29.','52.30.','52.31.','52.32.','52.33.','52.34.','52.35.','52.36.','52.37.','52.38.','52.39.','52.40.','52.41.','52.42.','52.43.','52.44.','52.45.','52.46.','52.47.','52.48.','52.49.','52.50.','52.51.','52.52.','52.53.','52.54.','52.55.','52.56.','52.57.','52.58.','52.59.','52.60.','52.61.','52.62.','52.63.','52.64.','52.65.','52.66.','52.67.','52.68.','52.69.','52.70.','52.71.','52.72.','52.73.','52.74.','52.75.','52.76.','52.77.','52.78.','52.79.','52.80.','52.81.','52.82.','52.83.','52.84.','52.85.','52.86.','52.87.','52.88.','52.89.','52.90.','52.91.','52.92.','52.93.','52.94.','52.95.','54.64.','54.65.','54.66.','54.67.','54.68.','54.69.','54.70.','54.71.','54.72.','54.73.','54.74.','54.75.','54.76.','54.77.','54.78.','54.79.','54.80.','54.81.','54.82.','54.83.','54.84.','54.85.','54.86.','54.87.','54.88.','54.89.','54.90.','54.91.','54.92.','54.93.','54.94.','54.144.','54.145.','54.146.','54.147.','54.148.','54.149.','54.150.','54.151.','54.152.','54.153.','54.154.','54.155.','54.156.','54.157.','54.158.','54.159.','54.160.','54.161.','54.162.','54.163.','54.164.','54.165.','54.166.','54.167.','54.168.','54.169.','54.170.','54.171.','54.172.','54.173.','54.174.','54.175.','54.176.','54.177.','54.178.','54.179.','54.180.','54.181.','54.182.','54.183.','54.184.','54.185.','54.186.','54.187.','54.188.','54.189.','54.190.','54.191.','54.192.','54.193.','54.194.','54.195.','54.196.','54.197.','54.198.','54.199.','54.200.','54.201.','54.202.','54.203.','54.204.','54.205.','54.206.','54.207.','54.208.','54.209.','54.210.','54.211.','54.212.','54.213.','54.214.','54.215.','54.216.','54.217.','54.218.','54.219.','54.220.','54.221.','54.222.','54.223.','54.224.','54.225.','54.226.','54.227.','54.228.','54.229.','54.230.','54.231.','54.232.','54.233.','54.234.','54.235.','54.236.','54.237.','54.238.','54.239.','54.240.','54.241.','54.242.','54.243.','54.244.','54.245.','54.246.','54.247.','54.248.','54.249.','54.250.','54.251.','54.252.','54.253.','54.254.','54.255.',
        // Google Cloud / GCP
        '34.64.','34.65.','34.66.','34.67.','34.68.','34.69.','34.70.','34.71.','34.72.','34.73.','34.74.','34.75.','34.76.','34.77.','34.78.','34.79.','34.80.','34.81.','34.82.','34.83.','34.84.','34.85.','34.86.','34.87.','34.88.','34.89.','34.90.','34.91.','34.92.','34.93.','34.94.','34.95.','34.96.','34.97.','34.98.','34.99.','34.100.','34.101.','34.102.','34.103.','34.104.','34.105.','34.106.','34.107.','34.108.','34.109.','34.110.','34.111.','34.112.','34.113.','34.114.','34.115.','34.116.','34.117.','34.118.','34.119.','34.120.','34.121.','34.122.','34.123.','34.124.','34.125.','34.126.','34.127.','35.184.','35.185.','35.186.','35.187.','35.188.','35.189.','35.190.','35.191.','35.192.','35.193.','35.194.','35.195.','35.196.','35.197.','35.198.','35.199.','35.200.','35.201.','35.202.','35.203.','35.204.','35.205.','35.206.','35.207.','35.208.','35.209.','35.210.','35.211.','35.212.','35.213.','35.214.','35.215.','35.216.','35.217.','35.218.','35.219.','35.220.','35.221.','35.222.','35.223.','35.224.','35.225.','35.226.','35.227.','35.228.','35.229.','35.230.','35.231.','35.232.','35.233.','35.234.','35.235.','35.236.','35.237.','35.238.','35.239.','35.240.','35.241.','35.242.','35.243.','35.244.','35.245.','35.246.','35.247.',
        // Microsoft Azure
        '13.64.','13.65.','13.66.','13.67.','13.68.','13.69.','13.70.','13.71.','13.72.','13.73.','13.74.','13.75.','13.76.','13.77.','13.78.','13.79.','13.80.','13.81.','13.82.','13.83.','13.84.','13.85.','13.86.','13.87.','13.88.','13.89.','13.90.','13.91.','13.92.','13.93.','13.94.','13.95.','13.104.','13.105.','13.106.','13.107.','20.','40.','51.10.','51.11.','51.12.','51.13.','51.103.','51.104.','51.105.','51.107.','51.116.','51.120.','51.124.','51.132.','51.136.','51.137.','51.138.','51.140.','51.141.','51.142.','51.143.','51.144.','51.145.','51.103.','52.96.','52.97.','52.98.','52.99.','52.100.','52.101.','52.102.','52.103.','52.104.','52.105.','52.106.','52.107.','52.108.','52.109.','52.110.','52.111.','52.112.','52.113.','52.114.','52.115.','52.116.','52.117.','52.118.','52.119.','52.120.','52.121.','52.122.','52.123.','52.124.','52.125.','52.126.','52.127.','52.128.','52.129.','52.130.','52.131.','52.132.','52.133.','52.134.','52.135.','52.136.','52.137.','52.138.','52.139.','52.140.','52.141.','52.142.','52.143.','52.144.','52.145.','52.146.','52.147.','52.148.','52.149.','52.150.','52.151.','52.152.','52.153.','52.154.','52.155.','52.156.','52.157.','52.158.','52.159.','52.160.','52.161.','52.162.','52.163.','52.164.','52.165.','52.166.','52.167.','52.168.','52.169.','52.170.','52.171.','52.172.','52.173.','52.174.','52.175.','52.176.','52.177.','52.178.','52.179.','52.180.','52.181.','52.182.','52.183.','52.184.','52.185.','52.186.','52.187.','52.188.','52.189.','52.190.','52.191.','52.224.','52.225.','52.226.','52.227.','52.228.','52.229.','52.230.','52.231.','52.232.','52.233.','52.234.','52.235.','52.236.','52.237.','52.238.','52.239.','52.240.','52.241.','52.242.','52.243.','52.244.','52.245.','52.246.','52.247.','52.248.','52.249.','52.250.','52.251.','52.252.','52.253.','52.254.','52.255.','104.40.','104.41.','104.42.','104.43.','104.44.','104.45.','104.46.','104.47.','104.208.','104.209.','104.210.','104.211.','104.212.','104.213.','104.214.','104.215.',
        // DigitalOcean
        '104.131.','104.236.','104.248.','138.197.','138.68.','139.59.','142.93.','143.110.','143.198.','144.126.','146.190.','157.230.','157.245.','159.65.','159.89.','159.203.','159.223.','161.35.','162.243.','164.90.','164.92.','165.22.','165.227.','165.232.','167.71.','167.99.','167.172.','174.138.','178.62.','178.128.','188.166.','188.226.','198.199.','198.211.','206.81.','206.189.','207.154.',
        // Linode
        '23.92.','23.239.','45.33.','45.56.','45.79.','50.116.','66.175.','66.228.','69.164.','72.14.','74.207.','96.126.','97.107.','103.3.','139.144.','143.42.','170.187.','172.104.','172.105.','172.232.','172.233.','172.234.','173.230.','173.255.','176.58.','178.79.','192.46.','192.53.','192.81.','192.155.','198.58.','198.74.','45.79.','5.181.','51.79.','69.164.',
        // Vultr
        '45.32.','45.63.','45.76.','45.77.','45.32.','64.176.','66.42.','78.141.','95.179.','104.156.','104.207.','104.238.','107.174.','108.61.','136.244.','139.180.','140.82.','144.202.','149.28.','155.138.','158.247.','167.179.','173.199.','199.247.','207.148.','207.246.','209.222.','216.155.','216.238.',
        // Hetzner
        '49.12.','78.46.','78.47.','116.202.','135.181.','136.243.','138.201.','142.132.','144.76.','148.251.','157.90.','159.69.','162.55.','167.235.','168.119.','176.9.','178.63.','188.40.','195.201.','213.133.','213.239.','37.27.','5.9.','5.75.','65.108.','65.109.','85.10.','88.198.','88.99.','94.130.','95.216.','95.217.',
        // OVH
        '5.39.','5.135.','5.196.','15.204.','15.235.','37.59.','37.187.','46.105.','51.68.','51.75.','51.77.','51.79.','51.81.','51.83.','51.89.','51.91.','51.161.','51.195.','51.210.','51.222.','51.254.','54.36.','54.37.','54.38.','54.39.','54.144.','79.137.','87.98.','91.121.','91.134.','92.222.','94.23.','141.94.','141.95.','142.4.','142.44.','146.59.','146.190.','147.135.','149.202.','151.80.','158.69.','164.132.','167.114.','176.31.','178.32.','178.33.','188.165.','192.95.','192.99.','193.70.','198.27.','198.50.','213.32.','213.186.','213.251.','217.182.',
        // Contabo
        '5.189.','62.171.','144.91.','149.102.','161.97.','164.68.','167.86.','173.212.','176.57.','185.86.','185.187.','185.249.','193.30.','207.180.',
        // Choopa / GleSYS / Other Euro DCs
        '45.95.','45.150.','45.155.','45.156.','45.157.','45.158.','45.159.','46.4.',
        // Oracle Cloud
        '129.213.','129.146.','130.61.','132.145.','132.226.','138.2.','140.91.','141.144.','141.146.','141.147.','141.148.','143.47.','146.235.','150.230.','152.67.','152.69.','152.70.','158.101.','193.122.','193.123.',
        // Tencent / Alibaba
        '8.129.','8.140.','8.141.','8.142.','8.146.','8.155.','8.157.','39.96.','39.97.','39.98.','39.99.','39.100.','39.101.','39.102.','39.103.','39.104.','39.105.','39.106.','39.107.','39.108.','47.74.','47.75.','47.88.','47.89.','47.90.','47.91.','47.92.','47.93.','47.94.','47.95.','47.96.','47.97.','47.98.','47.99.','47.100.','47.101.','47.102.','47.103.','47.104.','47.105.','47.106.','47.107.','47.108.','47.109.','47.110.','47.111.','47.112.','47.113.','47.114.','47.115.','47.116.','47.117.','47.118.','47.119.','47.120.','47.244.','47.245.','47.246.','47.247.','47.248.','47.249.','47.250.','47.251.','47.252.','47.253.','47.254.',
        // Meta crawlers exclusive
        '31.13.','66.220.','69.63.','69.171.','74.119.','103.4.','157.240.','163.70.','163.77.','173.252.','179.60.','185.89.','204.15.','129.134.','69.171.','199.201.',
    ];
    foreach ($ranges as $p) {
        if (strncmp($ip, $p, strlen($p)) === 0) return true;
    }
    return false;
}

function gate_is_meta_range($ip) {
    static $meta = [
        '31.13.','66.220.','69.63.','69.171.','74.119.','103.4.',
        '157.240.','163.70.','163.77.','173.252.','179.60.','185.89.','204.15.','129.134.','199.201.',
    ];
    foreach ($meta as $p) {
        if (strncmp($ip, $p, strlen($p)) === 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------
// SCORING SERVER-SIDE (decide si la petición es bot/inadecuada)
// Devuelve [score, $reasons]
// Score >= 8 => bloquear
// ---------------------------------------------------------------
function gate_compute_score($ctx = []) {
    $ua          = $ctx['ua']          ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
    $accept      = $ctx['accept']      ?? ($_SERVER['HTTP_ACCEPT'] ?? '');
    $accept_lang = $ctx['accept_lang'] ?? ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
    $accept_enc  = $ctx['accept_enc']  ?? ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '');
    $referer     = $ctx['referer']     ?? ($_SERVER['HTTP_REFERER'] ?? '');
    $ip          = $ctx['ip']          ?? gate_client_ip();
    $get         = $ctx['get']         ?? $_GET;
    $require_origin = $ctx['require_origin'] ?? true;

    $score = 0;
    $reasons = [];

    // ---------- UA: crawlers conocidos ----------
    if (preg_match('/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|applebot|msnbot|twitterbot|linkedinbot|whatsapp|telegrambot|discordbot|skypeuripreview|slackbot|pinterest|redditbot/i', $ua)) { $score += 10; $reasons[] = 'ua_searchbot'; }
    // SOLO crawlers/scrapers de Meta. NO incluye FBAN/FBIOS/FBAV/FB_IAB/Instagram
    // (esos son in-app browsers de USUARIOS REALES, no crawlers).
    if (preg_match('/facebookexternalhit|facebookcatalog|meta-externalagent|meta-link-preview|igsecurity|igprivacy|meta.*crawler|facebook.*bot|fb.*preview|metainspector/i', $ua)) { $score += 15; $reasons[] = 'ua_meta_crawler'; }
    if (preg_match('/bot|crawl|spider|scraper|fetch|curl|wget|python|java\/|ruby\b|perl\/|php-curl|lwp-|libwww|httpclient|okhttp|axios\/|go-http|node-fetch|scrapy|masscan|nikto|sqlmap|nmap|zgrab|httpx/i', $ua)) { $score += 10; $reasons[] = 'ua_generic_bot'; }
    if (preg_match('/headlesschrome|headless|phantomjs|puppeteer|playwright|selenium|webdriver|electron/i', $ua)) { $score += 12; $reasons[] = 'ua_headless'; }
    if (preg_match('/semrushbot|ahrefsbot|mj12bot|dotbot|rogerbot|majestic|blexbot|petalbot|sistrix|seokicks|domainstats|backlinks/i', $ua)) { $score += 10; $reasons[] = 'ua_seo'; }
    if (preg_match('/virustotal|urlscan|phishtank|safebrowsing|netcraft|fortiguard|kaspersky|trendmicro|sophos|symantec|mcafee|avast|avira|eset|bitdefender|webroot|paloalto|cisco|talos|umbrella|opendns|barracuda|proofpoint|mimecast|abuse|spamhaus|surbl|google.*safety/i', $ua)) { $score += 20; $reasons[] = 'ua_security'; }

    // ---------- Headers básicos ----------
    if (strlen(trim($ua)) < 20) { $score += 8; $reasons[] = 'ua_short'; }
    if (empty(trim($accept_enc))) { $score += 4; $reasons[] = 'no_accept_enc'; }
    if (empty($accept) || stripos($accept, 'text/html') === false) { $score += 4; $reasons[] = 'no_accept_html'; }

    // ---------- Idioma: muy suave (CO con UI en inglés es real) ----------
    if (empty(trim($accept_lang))) { $score += 4; $reasons[] = 'no_lang'; }
    elseif (!gate_accepts_spanish($accept_lang)) { $score += 2; $reasons[] = 'lang_not_es'; }

    // ---------- Mobile: ahora PERMITIDO también desde PC (señal informativa) ----------
    if (!gate_is_mobile($ua)) { $score += 0; $reasons[] = 'not_mobile'; } // no bloquea

    // ---------- IP: Meta + datacenter ----------
    if (gate_is_meta_range($ip)) { $score += 15; $reasons[] = 'ip_meta'; }
    if (gate_is_datacenter($ip)) { $score += 12; $reasons[] = 'ip_dc'; }

    // ---------- Geolocalización: solo Colombia ----------
    $country = gate_country($ip);
    if ($country && $country !== 'CO') { $score += 20; $reasons[] = 'geo_not_co:' . $country; }

    // ---------- Origen Meta: NO requerido (usuarios pueden volver desde marcadores,
    //            historial, links compartidos por WhatsApp, etc.). Solo cuenta como
    //            señal SUAVE para detectar tráfico orgánico vs ad.
    if ($require_origin && !gate_meta_origin($referer, $get)) {
        $score += 0; $reasons[] = 'no_meta_origin'; // informativo, no bloquea
    }

    return [$score, $reasons];
}

// ---------------------------------------------------------------
// DEV MODE — controlado desde /panel.php
// La cookie _dev NO está bound a IP/UA (para que el dueño pueda
// rotar de WiFi/4G y mantener sesión). Solo HMAC del secreto.
// ---------------------------------------------------------------
const DEV_COOKIE = '_dev';
const DEV_TTL    = 28800; // 8h

function gate_dev_active() {
    if (empty($_COOKIE[DEV_COOKIE])) return false;
    $expected = hash_hmac('sha256', 'dev_active', gate_secret());
    return hash_equals($expected, (string)$_COOKIE[DEV_COOKIE]);
}

function gate_dev_set($active, $ttl = DEV_TTL) {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    if ($active) {
        $val = hash_hmac('sha256', 'dev_active', gate_secret());
        setcookie(DEV_COOKIE, $val, [
            'expires'  => time() + $ttl,
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    } else {
        setcookie(DEV_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}

// ---------------------------------------------------------------
// PANEL — sesión y credenciales
// La password se setea desde el primer login (auto-setup).
// Hash bcrypt persistido en .panel_pass (denegado por .htaccess).
// ---------------------------------------------------------------
const PANEL_COOKIE   = '_pnl';
const PANEL_TTL      = 7200; // 2h
const PANEL_PASSFILE = __DIR__ . '/.panel_pass';

function panel_pass_get() {
    // 1) Env var (recomendado en Heroku — sobrevive deploys/restarts)
    $env = getenv('PANEL_PASS_HASH');
    if ($env && strlen(trim($env)) > 20) return trim($env);
    // 2) Archivo persistido (fallback)
    if (file_exists(PANEL_PASSFILE) && filesize(PANEL_PASSFILE) > 20) {
        return trim((string)@file_get_contents(PANEL_PASSFILE));
    }
    return '';
}
function panel_pass_exists() {
    return panel_pass_get() !== '';
}
function panel_pass_set($plain) {
    if (strlen($plain) < 6) return false;
    $h = password_hash($plain, PASSWORD_BCRYPT);
    // Si está usando env var, NO sobreescribimos archivo (el env var manda)
    if (!getenv('PANEL_PASS_HASH')) {
        @file_put_contents(PANEL_PASSFILE, $h);
        @chmod(PANEL_PASSFILE, 0600);
    }
    return true;
}
function panel_pass_verify($plain) {
    $h = panel_pass_get();
    return $h && password_verify($plain, $h);
}

function panel_session_active() {
    if (empty($_COOKIE[PANEL_COOKIE])) return false;
    $expected = hash_hmac('sha256', 'panel_v1', gate_secret());
    return hash_equals($expected, (string)$_COOKIE[PANEL_COOKIE]);
}
function panel_session_set($active) {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    if ($active) {
        setcookie(PANEL_COOKIE, hash_hmac('sha256', 'panel_v1', gate_secret()), [
            'expires'  => time() + PANEL_TTL,
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    } else {
        setcookie(PANEL_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}

// ---------------------------------------------------------------
// Tiene cookie HMAC válida? (gate normal o dev mode activo)
// ---------------------------------------------------------------
function gate_has_valid_cookie() {
    if (gate_dev_active()) return true;
    if (empty($_COOKIE['_qok'])) return false;
    return gate_verify_token(
        $_COOKIE['_qok'],
        gate_client_ip(),
        $_SERVER['HTTP_USER_AGENT'] ?? ''
    );
}

function gate_set_cookie($ttl = 1800) {
    $ip = gate_client_ip();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $tok = gate_make_token($ip, $ua, $ttl);
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    setcookie('_qok', $tok, [
        'expires'  => time() + $ttl,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    return $tok;
}

function gate_kill_cookie() {
    setcookie('_qok', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}
