// A private name system for a small group.
// Names like  mysite.internal  resolve only for people whose browser uses this server as its
// DNS-over-HTTPS resolver. Everything else is passed through to a normal public resolver.
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto"), net = require("net");
const UI = fs.readFileSync(path.join(__dirname, "ui.html"), "utf8");
const E = process.env;
const TLD = (E.PRIVATE_TLD || "internal").toLowerCase().replace(/^\./, "");
const SECRET = E.DOH_SECRET || "";
const UPSTREAM = E.UPSTREAM_DOH || "https://cloudflare-dns.com/dns-query";
const ADMIN = E.ADMIN_KEY || "";
const sha = t => crypto.createHash("sha256").update(String(t)).digest("hex");
const NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/;

async function redis(cmd) {
  const r = await fetch(E.UPSTASH_REDIS_REST_URL, { method: "POST", headers: { Authorization: "Bearer " + E.UPSTASH_REDIS_REST_TOKEN }, body: JSON.stringify(cmd) });
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d.result;
}
const getNs = async n => { const v = await redis(["GET", "ns:" + n]); return v ? JSON.parse(v) : null; };
const putNs = (n, o) => redis(["SET", "ns:" + n, JSON.stringify(o)]);

// ---------- tiny DNS packet helpers ----------
function parseQuery(buf) {
  if (buf.length < 17 || buf.readUInt16BE(4) !== 1) return null;
  let o = 12; const labels = [];
  for (;;) {
    const l = buf[o++];
    if (l === undefined || (l & 0xc0)) return null;
    if (l === 0) break;
    if (o + l > buf.length) return null;
    labels.push(buf.toString("latin1", o, o + l).toLowerCase()); o += l;
  }
  if (o + 4 > buf.length) return null;
  return { id: buf.readUInt16BE(0), rd: buf.readUInt16BE(2) & 0x0100, labels, type: buf.readUInt16BE(o), qEnd: o + 4 };
}
function reply(buf, q, rcode, answers) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(q.id, 0);
  head.writeUInt16BE(0x8000 | 0x0400 | q.rd | 0x0080 | rcode, 2); // answer, authoritative, RD copied, RA
  head.writeUInt16BE(1, 4); head.writeUInt16BE(answers.length, 6);
  const parts = [head, buf.subarray(12, q.qEnd)];
  for (const a of answers) {
    const h = Buffer.alloc(12);
    h.writeUInt16BE(0xc00c, 0); h.writeUInt16BE(a.type, 2); h.writeUInt16BE(1, 4); h.writeUInt32BE(60, 6); h.writeUInt16BE(a.rdata.length, 10);
    parts.push(h, a.rdata);
  }
  return Buffer.concat(parts);
}
function ipv6Buf(s) {
  let [a, b] = s.split("::");
  const A = a ? a.split(":") : [], B = b === undefined ? [] : (b ? b.split(":") : []);
  const full = b === undefined ? A : A.concat(Array(8 - A.length - B.length).fill("0"), B);
  const out = Buffer.alloc(16);
  full.forEach((h, i) => out.writeUInt16BE(parseInt(h || "0", 16), i * 2));
  return out;
}
function rdata(rec) {
  if (rec.type === "A") return Buffer.from(rec.content.split(".").map(Number));
  if (rec.type === "AAAA") return ipv6Buf(rec.content);
  const t = Buffer.from(rec.content, "utf8"), parts = [];
  for (let i = 0; i < t.length; i += 255) { const c = t.subarray(i, i + 255); parts.push(Buffer.from([c.length]), c); }
  return Buffer.concat(parts.length ? parts : [Buffer.from([0])]);
}
const QTYPE = { A: 1, TXT: 16, AAAA: 28 };

async function resolve(buf) {
  const q = parseQuery(buf);
  if (q && q.labels[q.labels.length - 1] === TLD) {
    const name = q.labels[q.labels.length - 2];
    const ns = name && await getNs(name);
    if (!ns) return reply(buf, q, 3, []); // NXDOMAIN
    const answers = ns.recs.filter(r => QTYPE[r.type] === q.type).map(r => ({ type: QTYPE[r.type], rdata: rdata(r) }));
    return reply(buf, q, 0, answers);
  }
  const r = await fetch(UPSTREAM, { method: "POST", headers: { "content-type": "application/dns-message", accept: "application/dns-message" }, body: buf });
  return Buffer.from(await r.arrayBuffer());
}

// ---------- http helpers ----------
function send(res, status, body, type, extra) {
  res.writeHead(status, Object.assign({ "content-type": type || "text/plain;charset=utf-8" }, extra || {}));
  res.end(body);
}
const json = (res, o, st) => send(res, st || 200, JSON.stringify(o), "application/json");
function readRaw(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > max) { reject(new Error("big")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
const isAdmin = u => { const k = u.searchParams.get("key") || ""; return !!(ADMIN && k && sha(k) === sha(ADMIN)); };
const dohUrl = req => SECRET ? (req.headers["x-forwarded-proto"] || "http") + "://" + req.headers.host + "/dns/" + SECRET : "";

async function auth(b) {
  const n = String(b.name || "").toLowerCase().replace(new RegExp("\\." + TLD + "$"), "");
  if (!NAME.test(n)) return null;
  const ns = await getNs(n);
  if (!ns || !b.token || ns.th !== sha(b.token)) return null;
  return { n, ns };
}

async function handle(req, res) {
  const u = new URL(req.url, "http://x"), p = u.pathname;
  const bad = (m, st) => json(res, { error: m }, st || 400);
  if (p === "/") return send(res, 200, UI.replace(/__TLD__/g, TLD), "text/html;charset=utf-8");
  if (p === "/healthz") return send(res, 200, "ok");

  // DNS-over-HTTPS endpoint, protected by a secret path only your group knows.
  if (SECRET && p === "/dns/" + SECRET) {
    let buf;
    if (req.method === "POST") buf = await readRaw(req, 4096);
    else if (req.method === "GET" && u.searchParams.get("dns")) buf = Buffer.from(u.searchParams.get("dns"), "base64url");
    else return send(res, 400, "bad request");
    const out = await resolve(buf);
    return send(res, 200, out, "application/dns-message", { "cache-control": "max-age=30" });
  }

  if (p === "/api/ns/check") {
    const n = (u.searchParams.get("name") || "").toLowerCase();
    if (!NAME.test(n)) return json(res, { available: false, reason: "invalid" });
    return json(res, { available: !(await redis(["EXISTS", "ns:" + n])), name: n + "." + TLD });
  }

  if (p === "/api/ns/claim" && req.method === "POST") {
    let b; try { b = JSON.parse((await readRaw(req, 5000)).toString()); } catch (e) { return bad("Bad request"); }
    if (!SECRET) return bad("This server isn't set up yet", 503);
    const n = String(b.name || "").toLowerCase();
    if (!NAME.test(n)) return bad("That name isn't allowed");
    const code = String(b.invite || "").trim().toUpperCase().replace(/[^A-Z0-9-]/g, "");
    const key = "invite:" + code;
    if (!code || !(await redis(["GET", key]))) return bad("That invite code isn't valid");
    if ((await redis(["DECR", key])) < 0) { await redis(["INCR", key]); return bad("That invite code is used up"); }
    const token = crypto.randomUUID() + crypto.randomUUID();
    const ok = await redis(["SET", "ns:" + n, JSON.stringify({ th: sha(token), recs: [], t: Date.now() }), "NX"]);
    if (!ok) { await redis(["INCR", key]); return bad(n + "." + TLD + " is taken", 409); }
    return json(res, { ok: true, name: n + "." + TLD, token, dohUrl: dohUrl(req) });
  }

  if (p.startsWith("/api/ns/") && req.method === "POST") {
    let b; try { b = JSON.parse((await readRaw(req, 5000)).toString()); } catch (e) { return bad("Bad request"); }
    const a = await auth(b);
    if (!a) return bad("Wrong name or key", 403);
    if (p === "/api/ns/info") return json(res, { name: a.n + "." + TLD, recs: a.ns.recs, dohUrl: dohUrl(req) });
    if (p === "/api/ns/add") {
      const type = String(b.type || "").toUpperCase(), content = String(b.content || "").trim();
      if (!QTYPE[type]) return bad("Use A, AAAA or TXT");
      if (type === "A" && !net.isIPv4(content)) return bad("That isn't a valid IPv4 address");
      if (type === "AAAA" && !net.isIPv6(content)) return bad("That isn't a valid IPv6 address");
      if (type === "TXT" && (!content || content.length > 500)) return bad("Text must be 1 to 500 characters");
      if (a.ns.recs.length >= 10) return bad("Ten records is the limit");
      a.ns.recs.push({ type, content });
      await putNs(a.n, a.ns);
      return json(res, { ok: true, recs: a.ns.recs });
    }
    if (p === "/api/ns/delete") {
      const i = parseInt(b.index, 10);
      if (!(i >= 0 && i < a.ns.recs.length)) return bad("No such record");
      a.ns.recs.splice(i, 1);
      await putNs(a.n, a.ns);
      return json(res, { ok: true, recs: a.ns.recs });
    }
  }

  if (p === "/api/admin/invite" && isAdmin(u)) {
    const code = (u.searchParams.get("code") || "").toUpperCase().replace(/[^A-Z0-9-]/g, "");
    const uses = parseInt(u.searchParams.get("uses") || "1", 10);
    if (!code || !(uses >= 0)) return bad("Need code and uses");
    await redis(["SET", "invite:" + code, String(uses)]);
    return json(res, { code, uses });
  }
  if (p === "/api/admin/names" && isAdmin(u)) return json(res, { names: (await redis(["KEYS", "ns:*"])).map(k => k.slice(3) + "." + TLD) });
  if (p === "/api/admin/delete" && isAdmin(u)) {
    const n = (u.searchParams.get("name") || "").toLowerCase();
    if (!NAME.test(n)) return bad("Invalid name");
    await redis(["DEL", "ns:" + n]);
    return json(res, { deleted: n + "." + TLD });
  }
  send(res, 404, "Not found");
}
// Optional: keep Render's free server awake by visiting itself every 10 minutes (set KEEP_AWAKE=1).
if (E.KEEP_AWAKE && E.RENDER_EXTERNAL_URL) {
  setInterval(() => fetch(E.RENDER_EXTERNAL_URL + "/healthz").catch(() => {}), 10 * 60 * 1000);
}
http.createServer((req, res) => {
  handle(req, res).catch(e => { console.error(e); if (!res.headersSent) json(res, { error: "Server error" }, 500); else res.end(); });
}).listen(E.PORT || 3000, () => console.log("Private namespace running on ." + TLD));
