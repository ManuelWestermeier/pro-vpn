// index.js (ESM). Run with Node.js (>=18) and package.json "type": "module"
// Example: node index.js
import { createServer } from "http";
import https from "https";
import { readFile } from "fs/promises";
import net from "net";
import { URL } from "url";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

const INDEX_HTML = await readFile(new URL("./index.html", import.meta.url), "utf8");

const origins = new Map(); // ip -> { target: "http://example.com:8080", history: [..] }

function normalizeIp(remoteAddress) {
    if (!remoteAddress) return "unknown";
    // strip IPv6 prefix ::ffff:
    return remoteAddress.replace(/^::ffff:/, "");
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => {
            const raw = Buffer.concat(chunks).toString();
            // try urlencoded form first
            const obj = {};
            raw.split("&").forEach((pair) => {
                if (!pair) return;
                const [k, v] = pair.split("=");
                obj[decodeURIComponent(k || "")] = decodeURIComponent(v || "");
            });
            resolve({ raw, body: obj });
        });
        req.on("error", reject);
    });
}

function ensureHttpPrefix(u) {
    try {
        // If it's already a valid URL, new URL() will succeed
        new URL(u);
        return u;
    } catch {
        // add http if missing
        return "http://" + u;
    }
}

// create the HTTP server
const server = createServer(async (req, res) => {
    try {
        const ip = normalizeIp(req.socket.remoteAddress);
        const registered = origins.get(ip);

        // Route for POST/GET to set the URL
        if (req.url === "/mw/vpn/api/set" || !registered) {
            if (req.method === "POST") {
                const { body } = await parseBody(req);
                let rawUrl = body.url || body.target || "";
                rawUrl = rawUrl.trim();
                if (!rawUrl) {
                    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
                    res.end("Missing 'url' parameter.");
                    return;
                }

                const normalized = ensureHttpPrefix(rawUrl);
                let parsed;
                try {
                    parsed = new URL(normalized);
                } catch (e) {
                    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
                    res.end("Invalid URL.");
                    return;
                }

                // store
                const prev = origins.get(ip);
                const history = (prev && prev.history) || [];
                history.unshift(parsed.href);
                // keep only last 10 entries
                if (history.length > 10) history.length = 10;
                origins.set(ip, { target: parsed.href, history });

                // redirect the user to the pathname of the provided URL (as you requested)
                const redirectPath = parsed.pathname + parsed.search;
                res.writeHead(302, { Location: redirectPath || "/" });
                res.end();
                return;
            }

            // serve the HTML form when GET or other methods
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(INDEX_HTML);
            return;
        }

        // If registered and not a CONNECT (CONNECT handled in 'connect' event below),
        // forward normal HTTP requests to the registered target.
        // Build the destination URL using the registered base as origin.
        const destBase = new URL(registered.target);
        // req.url may be absolute path or full url; new URL handles both when given base
        const proxiedUrl = new URL(req.url, destBase);

        const isHttps = destBase.protocol === "https:";
        const client = isHttps ? https : import("http");

        // Prepare options for outbound request
        const options = {
            protocol: destBase.protocol,
            hostname: proxiedUrl.hostname,
            port: proxiedUrl.port || (isHttps ? 443 : 80),
            path: proxiedUrl.pathname + proxiedUrl.search,
            method: req.method,
            headers: { ...req.headers, host: proxiedUrl.host },
            // keepAlive: true  // tune as needed
        };

        // Use runtime-determined http/https module
        const outboundReq = (isHttps ? https : await import("http")).request(options, (outRes) => {
            // copy status and headers
            const headers = { ...outRes.headers };
            // remove hop-by-hop headers per RFC (optional)
            delete headers["transfer-encoding"];
            res.writeHead(outRes.statusCode, headers);
            outRes.pipe(res, { end: true });
        });

        outboundReq.on("error", (err) => {
            res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
            res.end("Bad gateway: " + String(err.message));
        });

        // pipe request body to outbound
        req.pipe(outboundReq, { end: true });
    } catch (error) {
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end(String(error && error.stack ? error.stack : error));
    }
});

// handle CONNECT (for raw TCP tunnelling, e.g. HTTPS)
server.on("connect", (req, clientSocket, head) => {
    // req.url is host:port
    const ip = normalizeIp(clientSocket.remoteAddress);
    // allow all clients to use CONNECT; you can restrict to registered ones if desired
    const [host, portStr] = req.url.split(":");
    const port = parseInt(portStr || "443", 10) || 443;

    const serverSocket = net.connect(port, host, () => {
        // respond 200 Connection Established
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        // if there was leftover data from the client (head), push it to the server socket
        if (head && head.length) serverSocket.write(head);
        // pipe bi-directionally
        clientSocket.pipe(serverSocket);
        serverSocket.pipe(clientSocket);
    });

    serverSocket.on("error", (err) => {
        clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        clientSocket.end();
    });
});

// handle websocket / http upgrade and forward to target
server.on("upgrade", (req, socket, head) => {
    try {
        const ip = normalizeIp(req.socket.remoteAddress);
        const registered = origins.get(ip);
        if (!registered) {
            // no registered target — reject
            socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
            socket.end();
            return;
        }
        const destBase = new URL(registered.target);
        const proxiedUrl = new URL(req.url || "/", destBase);

        const isHttps = destBase.protocol === "https:";
        const port = proxiedUrl.port || (isHttps ? 443 : 80);
        const host = proxiedUrl.hostname;

        // Connect raw TCP to destination (we will write the original upgrade request over it)
        const serverSocket = net.connect(port, host, () => {
            // Reconstruct the initial request line and headers and send to target
            const lines = [];
            // Build request line use original method (should be GET for websockets)
            const path = proxiedUrl.pathname + proxiedUrl.search;
            lines.push(`${req.method} ${path} HTTP/1.1`);
            // copy headers but replace host
            const headers = { ...req.headers, host: proxiedUrl.host };
            for (const [k, v] of Object.entries(headers)) {
                if (Array.isArray(v)) {
                    for (const vv of v) lines.push(`${k}: ${vv}`);
                } else if (v !== undefined) {
                    lines.push(`${k}: ${v}`);
                }
            }
            lines.push("", ""); // blank line end of headers

            serverSocket.write(lines.join("\r\n"));
            if (head && head.length) serverSocket.write(head);

            // pipe both ways
            socket.pipe(serverSocket);
            serverSocket.pipe(socket);
        });

        serverSocket.on("error", (err) => {
            socket.end();
        });
    } catch (err) {
        socket.end();
    }
});

// Small API to view history for the client (used by index.html)
server.on("request", (req, res) => {
    if (req.url === "/mw/vpn/api/history" && req.method === "GET") {
        const ip = normalizeIp(req.socket.remoteAddress);
        const registered = origins.get(ip);
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ip, entry: registered || null }, null, 2));
    }
});

// start listening
const PORT = 80;
server.listen(PORT, () => {
    console.log(`Proxy server listening on port ${PORT}`);
});
