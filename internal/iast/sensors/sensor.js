/**
 * assay IAST sensor for Node.js.
 *
 * Deploy: NODE_OPTIONS="--require /path/to/sensor.js" node app.js
 * Set ASSAY_CALLBACK_URL to the assay IAST server.
 */

const CALLBACK = process.env.ASSAY_CALLBACK_URL || 'http://host.docker.internal:7880/api/v1/sink';
const PREFIX = 'ASSAY_TAINT_';
const SUFFIX = '_TAINT_ASSAY';
const http = require('http');

function check(value, sinkType) {
    const s = String(value);
    if (!s.includes(PREFIX) || !s.includes(SUFFIX)) return;
    const m = s.match(/ASSAY_TAINT_([a-f0-9]{8})_/);
    const markerId = m ? m[1] : '';
    const stack = new Error().stack.split('\n').slice(2, 7).join(' -> ');
    const data = JSON.stringify({
        marker_id: markerId, sink_type: sinkType,
        sink_value: s.substring(0, 500), stack_trace: stack,
        timestamp: new Date().toISOString(),
    });
    try {
        const url = new URL(CALLBACK);
        const req = http.request(url, {
            method: 'POST', headers: {'Content-Type': 'application/json'}, timeout: 1000,
        });
        req.on('error', () => {});
        req.write(data);
        req.end();
    } catch (_) {}
}

// Hook require() to intercept db/command/fs modules
const Module = require('module');
const _require = Module.prototype.require;
Module.prototype.require = function(id) {
    const mod = _require.apply(this, arguments);
    if (id === 'pg' && mod.Client) {
        const orig = mod.Client.prototype.query;
        mod.Client.prototype.query = function(text) {
            if (typeof text === 'string') check(text, 'sql_query');
            else if (text && text.text) check(text.text, 'sql_query');
            return orig.apply(this, arguments);
        };
    }
    if (id === 'child_process') {
        ['exec', 'execSync'].forEach(fn => {
            if (mod[fn]) {
                const orig = mod[fn];
                mod[fn] = function(cmd) { check(String(cmd), 'sys_command'); return orig.apply(this, arguments); };
            }
        });
    }
    if (id === 'fs') {
        ['readFile', 'readFileSync', 'writeFile', 'writeFileSync'].forEach(fn => {
            if (mod[fn]) {
                const orig = mod[fn];
                mod[fn] = function(path) { check(String(path), 'file_open'); return orig.apply(this, arguments); };
            }
        });
    }
    return mod;
};
