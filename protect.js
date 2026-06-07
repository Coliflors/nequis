/* =====================================================================
 * protect.js — Protecciones cliente
 * Bloquea: clic derecho, DevTools shortcuts, ver código fuente,
 *          guardar página, botón atrás, iframe embedding.
 * Nota: estas son medidas cosméticas/disuasorias. Cualquier dev senior
 *       puede bypasearlas. No reemplazan la seguridad server-side.
 * ===================================================================== */
(function () {
    'use strict';

    /* --- 1) Bloquear menú contextual (clic derecho) ------------------ */
    document.addEventListener('contextmenu', function (e) {
        e.preventDefault();
        e.stopPropagation();
        return false;
    }, { capture: true });

    /* --- 2) Bloquear atajos de teclado ------------------------------- */
    document.addEventListener('keydown', function (e) {
        var k = e.keyCode || e.which;
        var key = (e.key || '').toLowerCase();
        var ctrl = e.ctrlKey || e.metaKey; // metaKey = Cmd en Mac

        // F12 — DevTools
        if (k === 123 || key === 'f12') return block(e);

        // Ctrl+Shift+I / J / C / K — DevTools
        if (ctrl && e.shiftKey && (k === 73 || k === 74 || k === 67 || k === 75)) return block(e);
        if (ctrl && e.shiftKey && ['i', 'j', 'c', 'k'].indexOf(key) !== -1) return block(e);

        // Ctrl+U — Ver código fuente
        if (ctrl && (k === 85 || key === 'u')) return block(e);

        // Ctrl+S — Guardar página
        if (ctrl && (k === 83 || key === 's')) return block(e);

        // Ctrl+P — Imprimir (opcional, evita print-to-PDF)
        if (ctrl && (k === 80 || key === 'p')) return block(e);

        // Ctrl+A — Seleccionar todo (opcional, descomenta si quieres)
        // if (ctrl && (k === 65 || key === 'a')) return block(e);
    }, { capture: true });

    function block(e) {
        e.preventDefault();
        e.stopPropagation();
        return false;
    }

    /* --- 3) Bloquear arrastrar/seleccionar texto e imágenes ---------- */
    document.addEventListener('dragstart', function (e) { e.preventDefault(); }, { capture: true });
    // Si quieres deshabilitar selección completamente, descomenta:
    // document.addEventListener('selectstart', function (e) { e.preventDefault(); }, { capture: true });

    /* --- 4) Bloquear botón ATRÁS del navegador ----------------------- */
    // Empuja un estado falso al cargar; cualquier intento de retroceder vuelve aquí.
    try {
        history.pushState(null, '', location.href);
        window.addEventListener('popstate', function () {
            history.pushState(null, '', location.href);
        });
    } catch (e) { /* algunos browsers viejos no soportan */ }

    /* --- 5) Anti-iframe (clickjacking) ------------------------------- */
    if (window.top !== window.self) {
        try { window.top.location.href = window.self.location.href; } catch (e) {
            try { window.location.href = 'about:blank'; } catch (_) {}
        }
    }

    /* --- 6) Detector de DevTools por dimensiones (heurística suave) -- */
    // Si DevTools se abre en panel lateral o inferior, las dimensiones cambian.
    // Threshold alto para evitar falsos positivos en mobile responsive.
    var devToolsOpen = false;
    function checkDevTools() {
        var widthDiff  = window.outerWidth  - window.innerWidth;
        var heightDiff = window.outerHeight - window.innerHeight;
        var threshold  = 200;
        if (widthDiff > threshold || heightDiff > threshold) {
            if (!devToolsOpen) {
                devToolsOpen = true;
                document.body.style.filter = 'blur(20px)';
                document.body.style.pointerEvents = 'none';
            }
        } else if (devToolsOpen) {
            devToolsOpen = false;
            document.body.style.filter = '';
            document.body.style.pointerEvents = '';
        }
    }
    setInterval(checkDevTools, 1000);

    /* --- 7) Limpiar console (anti-snooping cosmético) ---------------- */
    try {
        if (typeof console !== 'undefined') {
            ['log', 'warn', 'error', 'info', 'debug', 'trace', 'table', 'dir']
                .forEach(function (m) { try { console[m] = function () {}; } catch (e) {} });
        }
    } catch (e) {}

    /* --- 8) Debugger anti-step (ralentiza inspección manual) --------- */
    // Descomenta si quieres ser agresivo (puede colgar el browser si DevTools está abierto)
    /*
    setInterval(function () {
        (function () { return false; }['constructor']('debugger')());
    }, 4000);
    */

})();
