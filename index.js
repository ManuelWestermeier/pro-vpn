// index.js (ESM). Run with Node.js (>=18) and package.json "type": "module"
import { createServer } from "http";
import http from "http";
import https from "https";
import net from "net";
import { readFile } from "fs/promises";
import { URL } from "url";

const INDEX_HTML = await readFile(new URL('./index.html', import.meta.url), 'utf8');

const origins = new Map(); // ip -> { target: "https://example.com/" }

function normalizeIp(addr) {
    if (!addr) return 'unknown';
    return addr.replace(/^::ffff:/, '');
}

function parseUrlEncodedBody(req) {
    return new Promise((resolve, reject) => {
        const bufs = [];
        req.on('data', (c) => bufs.push(c));
        req.on('end', () => {
            const raw = Buffer.concat(bufs).toString();
            const out = {};
            if (!raw) return resolve({ raw, body: out });
            for (const pair of raw.split('&')) {
                if (!pair) continue;
                const [k, v] = pair.split('=');
                out[decodeURIComponent(k || '')] = decodeURIComponent(v || '');
            }
            resolve({ raw, body: out });
        });
        req.on('error', reject);
    });
}

function ensureHttpPrefix(u) {
    try {
        new URL(u);
        return u;
    } catch {
        return 'http://' + u;
    }
}

function sendIndex(res) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(INDEX_HTML);
}

const server = createServer(async (req, res) => {
    try {
        const ip = normalizeIp(req.socket.remoteAddress);
        const registered = origins.get(ip);

        // Serve UI when client not registered, or when explicitly requesting UI endpoints
        if (req.url === '/' || req.url === '/index.html' || req.url === '/mw/vpn/api/set' && req.method !== 'POST' || !registered) {
            // If it's a POST to set, it's handled below; this branch covers GETs and unregistered clients
            if (req.method === 'POST' && req.url === '/mw/vpn/api/set') {
                // handled below; keep for clarity
            } else {
                sendIndex(res);
                return;
            }
        }

        // Handle POST /mw/vpn/api/set => register origin for this IP and redirect to pathname
        if (req.url === '/mw/vpn/api/set' && req.method === 'POST') {
            const { body } = await parseUrlEncodedBody(req);
            let rawUrl = (body.url || '').trim();
            if (!rawUrl) {
                res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end("Missing 'url' parameter");
                return;
            }
            const normalized = ensureHttpPrefix(rawUrl);
            let parsed;
            try {
                parsed = new URL(normalized);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('Invalid URL');
                return;
            }
            const href = parsed.href;
            origins.set(ip, { target: href });

            // Redirect to the pathname+search of the target (this makes the browser request that path on our proxy)
            const redirectPath = parsed.pathname + parsed.search || '/';
            res.writeHead(302, { Location: redirectPath });
            res.end();
            return;
        }

        // If client not registered, serve index (safety)
        if (!registered) {
            sendIndex(res);
            return;
        }

        // Proxy normal HTTP(S) requests to the registered target
        const destBase = new URL(registered.target);
        const proxiedUrl = new URL(req.url, destBase); // handles absolute and relative forms

        const isHttps = destBase.protocol === 'https:';
        const client = isHttps ? https : http;
        const port = proxiedUrl.port || (isHttps ? 443 : 80);

        // Build headers: override host to proxied host
        const outHeaders = { ...req.headers, host: proxiedUrl.host };
        // Remove hop-by-hop headers (optional)
        delete outHeaders['proxy-connection'];
        delete outHeaders['connection'];
        // Prepare options
        const options = {
            protocol: destBase.protocol,
            hostname: proxiedUrl.hostname,
            port: port,
            path: proxiedUrl.pathname + proxiedUrl.search,
            method: req.method,
            headers: outHeaders,
        };

        const outbound = (isHttps ? https : http).request(options, (outRes) => {
            // copy status and headers
            const headers = { ...outRes.headers };
            // strip hop-by-hop headers
            delete headers['connection'];
            delete headers['transfer-encoding'];
            res.writeHead(outRes.statusCode || 502, headers);
            outRes.pipe(res, { end: true });
        });

        outbound.on('error', (err) => {
            res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Bad gateway: ' + String(err && err.message ? err.message : err));
        });

        req.pipe(outbound, { end: true });
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(String(err && err.stack ? err.stack : err));
    }
});

// Handle CONNECT for raw TCP tunneling (HTTPS through proxy)
server.on('connect', (req, clientSocket, head) => {
    const [host, portStr] = req.url.split(':');
    const port = parseInt(portStr || '443', 10) || 443;
    const serverSocket = net.connect(port, host, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) serverSocket.write(head);
        clientSocket.pipe(serverSocket);
        serverSocket.pipe(clientSocket);
    });
    serverSocket.on('error', () => {
        clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        clientSocket.end();
    });
});

// Handle WebSocket upgrade by piping raw TCP to the destination (using client's registered target)
server.on('upgrade', (req, socket, head) => {
    try {
        const ip = normalizeIp(req.socket.remoteAddress);
        const registered = origins.get(ip);
        if (!registered) {
            socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
            socket.end();
            return;
        }
        const destBase = new URL(registered.target);
        const proxiedUrl = new URL(req.url || '/', destBase);
        const isHttps = destBase.protocol === 'https:';
        const port = proxiedUrl.port || (isHttps ? 443 : 80);
        const host = proxiedUrl.hostname;

        const serverSocket = net.connect(port, host, () => {
            const path = proxiedUrl.pathname + proxiedUrl.search;
            const lines = [];
            lines.push(`${req.method} ${path} HTTP/1.1`);
            const headers = { ...req.headers, host: proxiedUrl.host };
            for (const [k, v] of Object.entries(headers)) {
                if (Array.isArray(v)) {
                    for (const vv of v) lines.push(`${k}: ${vv}`);
                } else if (v !== undefined) {
                    lines.push(`${k}: ${v}`);
                }
            }
            lines.push('', '');
            serverSocket.write(lines.join('\r\n'));
            if (head && head.length) serverSocket.write(head);
            socket.pipe(serverSocket);
            serverSocket.pipe(socket);
        });

        serverSocket.on('error', () => socket.end());
    } catch (err) {
        try { socket.end(); } catch { }
    }
});

const PORT = 80;
server.listen(PORT, () => {
    console.log(`Proxy server listening on :${PORT}`);
});
