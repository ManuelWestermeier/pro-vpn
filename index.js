// index.js (ESM) — simple per-IP proxy with UI at /+s
// Run with Node >=18 and package.json { "type": "module" }
import { createServer } from "http";
import http from "http";
import https from "https";
import net from "net";
import tls from "tls";
import { readFile } from "fs/promises";
import { URL } from "url";

const INDEX_HTML = await readFile(new URL("./index.html", import.meta.url), "utf8");

const origins = new Map(); // ip -> "https://example.com/"

// utilities
const normalizeIp = (addr) => (addr ? addr.replace(/^::ffff:/, "") : "unknown");

const parseForm = (req) =>
    new Promise((resolve, reject) => {
        const bufs = [];
        req.on("data", (c) => bufs.push(c));
        req.on("end", () => {
            const raw = Buffer.concat(bufs).toString();
            const out = {};
            if (!raw) return resolve(out);
            for (const pair of raw.split("&")) {
                if (!pair) continue;
                const [k, v] = pair.split("=");
                out[decodeURIComponent(k || "")] = decodeURIComponent(v || "");
            }
            resolve(out);
        });
        req.on("error", reject);
    });

const ensureHttpPrefix = (u) => {
    try {
        new URL(u);
        return u;
    } catch {
        return "http://" + u;
    }
};

const HOP_BY_HOP = new Set([
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
]);

// serve change-page only here; root (/) is never served
const server = createServer(async (req, res) => {
    try {
        const ip = normalizeIp(req.socket.remoteAddress);
        const origin = origins.get(ip);

        // Route: UI page
        if (req.url === "/+s") {
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            return res.end(INDEX_HTML);
        }

        if (req.url == "/+proxy/api/get") {
            res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
            return res.end(origin || "null");
        }
        // Route: set new origin for this IP (server-side)
        if (req.url === "/+proxy/api/set" && req.method === "POST") {
            const body = await parseForm(req);
            let raw = (body.url || "").trim();
            if (!raw) {
                res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
                return res.end("Missing 'url' parameter");
            }
            raw = ensureHttpPrefix(raw);
            let parsed;
            try {
                parsed = new URL(raw);
            } catch {
                res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
                return res.end("Invalid URL");
            }

            // store simple mapping ip -> href
            origins.set(ip, parsed.href);

            // redirect client to the pathname of the provided target
            const redirectPath = (parsed.pathname || "/") + (parsed.search || "");
            res.writeHead(302, { Location: redirectPath || "/" });
            return res.end();
        }

        // If origin is missing, redirect to change-page (except the set endpoint handled above)
        if (!origin) {
            res.writeHead(302, { Location: "/+s" });
            return res.end();
        }

        // At this point origin exists -> perform HTTP proxying for normal requests.
        // Build destination using client's registered origin as base.
        const base = new URL(origin);
        // handle absolute-form (e.g., "http://host/...") and origin-relative paths
        const dest = new URL(req.url, base);

        // choose module
        const isTls = dest.protocol === "https:";
        const client = isTls ? https : http;
        const port = dest.port || (isTls ? 443 : 80);

        // prepare headers: clone but rewrite Host, Origin, Referer; drop hop-by-hop headers
        const outHeaders = {};
        for (const [k, v] of Object.entries(req.headers || {})) {
            const lk = k.toLowerCase();
            if (HOP_BY_HOP.has(lk)) continue;
            outHeaders[lk] = v;
        }
        // ensure host header equals proxied host[:port]
        outHeaders["host"] = dest.host;
        // rewrite Origin and Referer to point at the target origin (so backend sees proper origin)
        outHeaders["origin"] = base.origin;
        outHeaders["referer"] = base.origin + (dest.pathname || "/") + (dest.search || "");

        const options = {
            protocol: dest.protocol,
            hostname: dest.hostname,
            port: port,
            path: dest.pathname + dest.search,
            method: req.method,
            headers: outHeaders,
            timeout: 30_000,
        };

        const outbound = client.request(options, (outRes) => {
            // filter hop-by-hop response headers
            const resHeaders = {};
            for (const [k, v] of Object.entries(outRes.headers || {})) {
                if (HOP_BY_HOP.has(k.toLowerCase())) continue;
                resHeaders[k] = v;
            }
            res.writeHead(outRes.statusCode || 502, resHeaders);
            outRes.pipe(res, { end: true });
        });

        outbound.on("timeout", () => {
            outbound.destroy(new Error("upstream timeout"));
        });

        outbound.on("error", (err) => {
            if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
            res.end("Bad gateway: " + String(err && err.message ? err.message : err));
        });

        // pipe request body
        req.pipe(outbound, { end: true });
    } catch (err) {
        if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end(String(err && err.stack ? err.stack : err));
    }
});

// CONNECT — raw TCP tunneling (used for HTTPS by browsers in proxy mode)
server.on("connect", (req, clientSocket, head) => {
    // Allow CONNECT only if client has an origin set (so unregistered users are still redirected)
    const ip = normalizeIp(clientSocket.remoteAddress);
    if (!origins.has(ip)) {
        clientSocket.write("HTTP/1.1 302 Found\r\nLocation: /+s\r\n\r\n");
        return clientSocket.end();
    }

    // req.url is "host:port"
    const [host, portStr] = (req.url || "").split(":");
    const port = parseInt(portStr || "443", 10) || 443;

    const serverSocket = net.connect(port, host, () => {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head && head.length) serverSocket.write(head);
        clientSocket.pipe(serverSocket);
        serverSocket.pipe(clientSocket);
    });

    serverSocket.on("error", () => {
        try {
            clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        } catch { }
        clientSocket.end();
    });
});

// upgrade — WebSocket / HTTP upgrade (supports wss via TLS connect)
server.on("upgrade", (req, clientSocket, head) => {
    try {
        const ip = normalizeIp(req.socket.remoteAddress);
        const origin = origins.get(ip);
        if (!origin) {
            clientSocket.write("HTTP/1.1 302 Found\r\nLocation: /+s\r\n\r\n");
            return clientSocket.end();
        }

        const base = new URL(origin);
        const dest = new URL(req.url || "/", base);
        const isTls = dest.protocol === "https:";
        const port = dest.port || (isTls ? 443 : 80);
        const host = dest.hostname;

        // pick connect function depending on TLS
        const upstream = isTls
            ? tls.connect({ host, port, servername: host })
            : net.connect(port, host);

        upstream.on("connect", () => {
            // reconstruct request line and headers, but rewrite Host/Origin/Referer
            const path = dest.pathname + dest.search;
            const lines = [];
            lines.push(`${req.method} ${path} HTTP/1.1`);
            const headers = { ...req.headers };
            headers["host"] = dest.host;
            headers["origin"] = base.origin;
            headers["referer"] = base.origin + (dest.pathname || "/") + (dest.search || "");
            for (const [k, v] of Object.entries(headers)) {
                if (Array.isArray(v)) {
                    for (const vv of v) lines.push(`${k}: ${vv}`);
                } else if (v !== undefined) {
                    lines.push(`${k}: ${v}`);
                }
            }
            lines.push("", "");
            upstream.write(lines.join("\r\n"));
            if (head && head.length) upstream.write(head);
            // pipe
            clientSocket.pipe(upstream);
            upstream.pipe(clientSocket);
        });

        upstream.on("error", () => {
            try { clientSocket.end(); } catch { }
        });
    } catch {
        try { clientSocket.end(); } catch { }
    }
});

const PORT = 80;
server.listen(PORT, () => {
    console.log(`Proxy server listening on :${PORT}`);
});
