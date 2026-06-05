<?php
/**
 * web/_gate.php
 * Incluido al inicio de cada PHP en /web/.
 * Valida la cookie HMAC `_qok`. Si es inválida, devuelve 404 (parece que la URL no existe).
 */
require_once __DIR__ . '/../_lib.php';

if (!gate_has_valid_cookie()) {
    // Borrar cualquier cookie inválida que el cliente esté enviando
    gate_kill_cookie();
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, private');
    echo "<!doctype html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>";
    exit;
}

// Renovar TTL deslizante: cada hit en /web/ extiende la sesión otros 30 min
gate_set_cookie(1800);
