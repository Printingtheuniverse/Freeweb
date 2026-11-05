const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const UI = fs.readFileSync(path.join(__dirname, "ui.html"), "utf8");
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL, REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const ADMIN = process.env.ADMIN_KEY || "";
const RESERVED = ["api", "admin", "www", "s", "static", "app", "freeweb"];
const sha = t => crypto.createHash("sha256").update(String(t)).digest("hex");
const ok = n => /^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(n) && !RESERVED.includes(n);

async function redis(cmd) {
  const r = await fetch(REDIS_URL, { method: "POST", headers: { Authorization: "Bearer " + REDIS_TOKEN }, body: JSON.stringify(cmd) });
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d.result;
}
const getSite = async n => { const v = await redis(["GET", "site:" + n]); return v ? JSON.parse(v) : null; };

function send(res, status, body, type, extra) {
  res.writeHead(status, Object.assign({ "content-type": type || "text/plain;charset=utf-8" }, extra || {}));
  res.end(body);
}
const json = (res, o, st) => send(res, st || 200, JSON.stringify(o), "application/json");
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > max) { reject(new Error("big")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const isAdmin = u => { const k = u.searchParams.get("key") || ""; return !!(ADMIN && k && sha(k) === sha(ADMIN)); };
const APP_HOST = (process.env.APP_HOST || "").toLowerCase();
let domainsHandler;

async function handle(req, res) {
  const u = new URL(req.url, "http://x"), p = u.pathname;
  const host = String(req.headers.host || "").split(":")[0].toLowerCase().replace(/^www\./, "");
  if (APP_HOST && host && host !== APP_HOST && host !== "localhost") {
    const siteName = await redis(["GET", "domain:" + host]);
    const rec = siteName && await getSite(siteName);
    if (rec) return send(res, 200, rec.html, "text/html;charset=utf-8", {
      "content-security-policy": "sandbox allow-scripts allow-forms allow-popups", "x-content-type-options": "nosniff" });
  }
  if (await domainsHandler(req, res, u, p)) return;
  if (p === "/") return send(res, 200, UI, "text/html;charset=utf-8");
  if (p === "/healthz") return send(res, 200, "ok");

  if (p === "/api/check") {
    const n = (u.searchParams.get("name") || "").toLowerCase();
    if (!ok(n)) return json(res, { available: false, reason: "invalid" });
    const rec = await getSite(n);
    if (!rec) return json(res, { available: true });
    const t = u.searchParams.get("token");
    if (t && rec.th === sha(t)) return json(res, { available: false, mine: true });
    return json(res, { available: false, reason: "taken" });
  }

  if (p === "/api/publish" && req.method === "POST") {
    let b;
    try { b = JSON.parse(await readBody(req, 300000)); } catch (e) { return json(res, { error: "Bad request or site too big" }, 400); }
    const n = String(b.name || "").toLowerCase(), html = String(b.html || "");
    if (!ok(n)) return json(res, { error: "That name isn't allowed" }, 400);
    if (html.length > 200000) return json(res, { error: "Site is too big (200 KB max)" }, 413);
    const rec = await getSite(n);
    let token = String(b.token || "");
    if (rec) { if (!token || rec.th !== sha(token)) return json(res, { error: n + " is taken" }, 409); }
    else token = crypto.randomUUID() + crypto.randomUUID();
    await redis(["SET", "site:" + n, JSON.stringify({ html, th: sha(token), t: Date.now() })]);
    const origin = (req.headers["x-forwarded-proto"] || "http") + "://" + req.headers.host;
    return json(res, { ok: true, url: origin + "/s/" + n, token });
  }

  if (p.startsWith("/api/admin/")) {
    const key = u.searchParams.get("key") || "";
    if (!ADMIN || !key || sha(key) !== sha(ADMIN)) return send(res, 404, "Not found");
    if (p === "/api/admin/list") {
      const keys = await redis(["KEYS", "site:*"]);
      return json(res, { sites: keys.map(k => k.slice(5)) });
    }
    if (p === "/api/admin/delete") {
      const n = (u.searchParams.get("name") || "").toLowerCase();
      if (!ok(n)) return json(res, { error: "Invalid name" }, 400);
      await redis(["DEL", "site:" + n]);
      return json(res, { deleted: n });
    }
  }

  if (p.startsWith("/s/")) {
    const n = p.slice(3).replace(/\/$/, "").toLowerCase();
    const rec = ok(n) && await getSite(n);
    if (!rec) return send(res, 404, "No site here yet.");
    return send(res, 200, rec.html, "text/html;charset=utf-8", {
      "content-security-policy": "sandbox allow-scripts allow-forms allow-popups",
      "x-content-type-options": "nosniff"
    });
  }
  send(res, 404, "Not found");
}

domainsHandler = require("./domains")({ redis, sha, getSite, json, send, readBody, isAdmin });

http.createServer((req, res) => {
  handle(req, res).catch(e => { console.error(e); if (!res.headersSent) json(res, { error: "Server error" }, 500); else res.end(); });
}).listen(process.env.PORT || 3000, () => console.log("FreeWeb running"));
