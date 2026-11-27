// Address-pinning local HTTP proxy for runs/2026-11-27-02.md, written for this measurement as described by the
// requesting session: it listens on 127.0.0.1 with port 0, takes plain HTTP as
// absolute-form requests and https/ws as CONNECT, resolves the name itself and relays only to the resolved IP when
// every resolved address is public. Optional Basic proxy authentication (the prototype of request A3).
//
// Usage: node probe-local-proxy.mjs <port-file> <event-log> [<auth-file>]
//   port-file   written once listening: {"port", "pid", "auth"}
//   event-log   one JSON line per event: pick (name resolution), auth (result only), client_error, upstream_error.
//               The Proxy-Authorization value and the expected credentials are never written.
//   auth-file   "user:password" (the password is 32 random bytes, base64url). With it, every request and CONNECT
//               is checked before URL parsing and name resolution; a missing or wrong value gets 407 with
//               Proxy-Authenticate. The check hashes both sides with SHA-256 and compares with timingSafeEqual.
import { lookup } from "node:dns/promises";
import { createHash, timingSafeEqual } from "node:crypto";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";

const [portFile, eventLog, authFile] = process.argv.slice(2);
const event = (e) => appendFileSync(eventLog, JSON.stringify({ t: Date.now(), ...e }) + "\n");

// Not public: IANA special-purpose IPv4 blocks (this host, private, loopback, link-local, shared address space,
// documentation, benchmarking, multicast and reserved). IPv6: only global unicast 2000::/3 minus 6to4, the
// 2001::/23 special block, documentation and 3fff::/20.
const notPublicV4 = new net.BlockList();
for (const [a, p] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 3]]) notPublicV4.addSubnet(a, p, "ipv4");
const globalV6 = new net.BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");
const notPublicV6 = new net.BlockList();
for (const [a, p] of [["2002::", 16], ["2001::", 23], ["2001:db8::", 32], ["3fff::", 20]]) notPublicV6.addSubnet(a, p, "ipv6");

function isPublicAddress(ip) {
  const h = ip.replace(/^\[|\]$/g, "");
  const v = net.isIP(h);
  if (v === 4) return !notPublicV4.check(h, "ipv4");
  if (v === 6) return globalV6.check(h, "ipv6") && !notPublicV6.check(h, "ipv6");
  return false;
}

// Names that are this PC or a private network by spelling alone (no DNS): localhost, .localhost, .local,
// .internal, .home.arpa, IPv4-mapped IPv6 of a private IPv4, fc00::/7, fe80::, and private IPv4 literals.
function isPrivateName(host) {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
  if (["localhost", "::1", "::", "0.0.0.0"].includes(h)) return true;
  if ([".localhost", ".local", ".internal", ".home.arpa"].some((s) => h.endsWith(s))) return true;
  const m6 = /^::ffff:(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(h);
  if (m6) {
    if (m6[1]) return isPrivateName(m6[1]);
    const hi = parseInt(m6[2], 16), lo = parseInt(m6[3], 16);
    return isPrivateName(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  if (/^(fc|fd)[0-9a-f]{2}:/.test(h) || h.startsWith("fe80:")) return true;
  const m4 = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(h);
  if (!m4) return false;
  const a = Number(m4[1]), b = Number(m4[2]);
  return a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
    || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

async function pick(host) {
  const h = host.replace(/^\[|\]$/g, "");
  let ip = null;
  if (net.isIP(h)) ip = isPublicAddress(h) ? h : null;
  else if (!isPrivateName(h)) {
    try {
      const all = await lookup(h, { all: true, verbatim: true });
      ip = all.length > 0 && all.every((a) => isPublicAddress(a.address)) ? all[0].address : null;
    } catch {
      ip = null;
    }
  }
  event({ ev: "pick", host: h.slice(0, 80), public: Boolean(ip) });
  return ip;
}

function hostPort(authority, fallback) {
  const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority) ?? /^([^:]+)(?::(\d+))?$/.exec(authority);
  if (!m) return null;
  const port = m[2] ? Number(m[2]) : fallback;
  return port > 0 && port < 65536 ? { host: m[1], port } : null;
}

const expected = authFile ? createHash("sha256").update(readFileSync(authFile, "utf8").trim(), "utf8").digest() : null;
const REALM = 'Basic realm="local-proxy"';

/** "off" without auth-file, else ok | none | scheme | mismatch. */
function checkAuth(req) {
  if (!expected) return "off";
  const v = req.headers["proxy-authorization"];
  if (typeof v !== "string") return "none";
  const m = /^basic +([A-Za-z0-9+/=_-]*) *$/i.exec(v);
  if (!m) return "scheme";
  const got = createHash("sha256").update(Buffer.from(m[1], "base64")).digest();
  return timingSafeEqual(got, expected) ? "ok" : "mismatch";
}

const server = http.createServer((req, res) => {
  const a = checkAuth(req);
  if (a !== "off") event({ ev: "auth", kind: "http", result: a });
  if (a !== "off" && a !== "ok") {
    res.writeHead(407, { "Proxy-Authenticate": REALM, "Content-Length": "0", Connection: "close" }).end();
    return;
  }
  let target;
  try {
    target = new URL(req.url ?? "");
  } catch {
    res.writeHead(400).end();
    return;
  }
  if (target.protocol !== "http:") {
    res.writeHead(400).end();
    return;
  }
  const port = Number(target.port) || 80;
  void pick(target.hostname).then((ip) => {
    if (!ip) {
      res.writeHead(403).end();
      return;
    }
    const { "proxy-connection": _hop, "proxy-authorization": _auth, ...headers } = req.headers;
    const up = http.request({ host: ip, port, method: req.method, path: target.pathname + target.search, headers, setHost: false }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    });
    up.on("error", (e) => {
      event({ ev: "upstream_error", code: e.code ?? String(e) });
      res.destroy();
    });
    res.on("close", () => up.destroy());
    req.pipe(up);
  });
});

server.on("connect", (req, client, head) => {
  client.on("error", () => client.destroy());
  const a = checkAuth(req);
  if (a !== "off") event({ ev: "auth", kind: "connect", result: a });
  if (a !== "off" && a !== "ok") {
    client.end(`HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: ${REALM}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    return;
  }
  const hp = hostPort(req.url ?? "", 443);
  if (!hp) return client.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  void pick(hp.host).then((ip) => {
    if (!ip) return client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    const up = net.connect(hp.port, ip, () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    up.on("error", (e) => {
      event({ ev: "upstream_error", code: e.code ?? String(e) });
      client.destroy();
    });
    up.on("close", () => client.destroy());
    client.on("close", () => up.destroy());
  });
});

server.on("clientError", (e, socket) => {
  event({ ev: "client_error", code: e.code ?? String(e) });
  socket.destroy();
});

server.listen(0, "127.0.0.1", () => {
  const { port } = server.address();
  writeFileSync(portFile, JSON.stringify({ port, pid: process.pid, auth: Boolean(expected) }));
  event({ ev: "listening", port, auth: Boolean(expected) });
});
