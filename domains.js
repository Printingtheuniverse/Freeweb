// "Choose your .com": search, promo codes, Stripe checkout, Porkbun registration.
// Every part stays switched off until its environment variables are set.
const crypto = require("crypto");

module.exports = function (ctx) {
  const { redis, sha, getSite, json, readBody, isAdmin } = ctx;
  const E = process.env;
  const PB = E.PORKBUN_BASE || "https://api.porkbun.com/api/json/v3";
  const STRIPE = E.STRIPE_BASE || "https://api.stripe.com";
  const APP_HOST = (E.APP_HOST || "").toLowerCase();
  const MAX_COST = parseInt(E.MAX_DOMAIN_COST_CENTS || "2000", 10);
  const registrarOn = () => !!(E.PORKBUN_API_KEY && E.PORKBUN_SECRET_KEY);
  const stripeOn = () => !!(E.STRIPE_SECRET_KEY && E.STRIPE_PRICE_ID && E.STRIPE_WEBHOOK_SECRET);
  const toDomain = n => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/.test(n) ? n + ".com" : null;

  async function pb(path, body, idem) {
    const h = { "content-type": "application/json" };
    if (idem) h["Idempotency-Key"] = idem;
    const r = await fetch(PB + path, { method: "POST", headers: h,
      body: JSON.stringify(Object.assign({ apikey: E.PORKBUN_API_KEY, secretapikey: E.PORKBUN_SECRET_KEY }, body || {})) });
    try { return await r.json(); } catch (e) { return { status: "ERROR", message: "Bad response from registrar" }; }
  }

  // Is it free, and what will it cost US (in cents)?
  async function quote(d) {
    const c = await pb("/domain/checkDomain/" + d);
    if (c.status !== "SUCCESS") return { error: c.message || "Couldn't check that name" };
    const r = c.response || c;
    const av = String(r.avail !== undefined ? r.avail : r.available).toLowerCase();
    if (av !== "yes" && av !== "true") return { available: false };
    const q = await pb("/domain/create/" + d, { cost: 0, agreeToTerms: "yes", dryRun: true });
    const cost = Number(q.cost);
    if (!Number.isFinite(cost) || cost <= 0) return { error: q.message || "Couldn't get a price" };
    if (cost > MAX_COST) return { available: false, reason: "premium" };
    return { available: true, cost };
  }

  async function register(d, site, idem) {
    if (await redis(["EXISTS", "domain:" + d])) return { error: d + " is already taken" };
    const q = await quote(d);
    if (q.error) return { error: q.error };
    if (!q.available) return { error: d + " isn't available" };
    const res = await pb("/domain/create/" + d, { cost: q.cost, agreeToTerms: "yes" }, idem);
    if (res.status !== "SUCCESS") return { error: res.message || res.code || "Registration failed" };
    await redis(["SET", "domain:" + d, site]);
    let dnsOk = false, renderOk = false;
    if (APP_HOST) {
      const a = await pb("/dns/create/" + d, { type: "ALIAS", name: "", content: APP_HOST, ttl: "600" });
      const w = await pb("/dns/create/" + d, { type: "CNAME", name: "www", content: APP_HOST, ttl: "600" });
      dnsOk = a.status === "SUCCESS" && w.status === "SUCCESS";
    }
    if (E.RENDER_API_KEY && E.RENDER_SERVICE_ID) {
      try {
        const rs = await Promise.all([d, "www." + d].map(name => fetch("https://api.render.com/v1/services/" + E.RENDER_SERVICE_ID + "/custom-domains", {
          method: "POST", headers: { Authorization: "Bearer " + E.RENDER_API_KEY, "content-type": "application/json" }, body: JSON.stringify({ name }) })));
        renderOk = rs.every(r => r.ok);
      } catch (e) {}
    }
    return { ok: true, domain: d, dnsOk, renderOk };
  }

  async function owns(site, token) {
    const rec = await getSite(site);
    return !!(rec && token && rec.th === sha(token));
  }

  function verifyStripe(raw, header) {
    const parts = Object.fromEntries(String(header || "").split(",").map(s => s.split("=")));
    if (!parts.t || !parts.v1 || Math.abs(Date.now() / 1000 - Number(parts.t)) > 300) return false;
    const exp = crypto.createHmac("sha256", E.STRIPE_WEBHOOK_SECRET).update(parts.t + "." + raw).digest("hex");
    const a = Buffer.from(exp), b = Buffer.from(parts.v1);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  return async function handle(req, res, u, p) {
    if (p === "/api/domain/status") return json(res, { enabled: registrarOn(), paid: stripeOn() }), true;

    if (p === "/api/domain/check") {
      if (!registrarOn()) return json(res, { enabled: false }), true;
      const d = toDomain((u.searchParams.get("name") || "").toLowerCase());
      if (!d) return json(res, { enabled: true, available: false, reason: "invalid" }), true;
      if (await redis(["EXISTS", "domain:" + d])) return json(res, { enabled: true, domain: d, available: false }), true;
      const q = await quote(d);
      if (q.error) return json(res, { enabled: true, error: "Couldn't check right now" }), true;
      return json(res, { enabled: true, domain: d, available: !!q.available, reason: q.reason }), true;
    }

    if (p === "/api/domain/claim" && req.method === "POST") {
      let b; try { b = JSON.parse(await readBody(req, 20000)); } catch (e) { return json(res, { error: "Bad request" }, 400), true; }
      if (!registrarOn()) return json(res, { error: "Domains aren't switched on yet" }, 503), true;
      const d = toDomain(String(b.name || "").toLowerCase()), site = String(b.site || "").toLowerCase();
      if (!d) return json(res, { error: "That name isn't allowed" }, 400), true;
      if (!(await owns(site, String(b.token || "")))) return json(res, { error: "Publish your site first, then claim a domain for it" }, 403), true;
      const code = String(b.promo || "").trim().toUpperCase().replace(/[^A-Z0-9-]/g, "");
      if (code) {
        const key = "promo:" + code;
        if (!(await redis(["GET", key]))) return json(res, { error: "That promo code isn't valid" }, 400), true;
        const left = await redis(["DECR", key]);
        if (left < 0) { await redis(["INCR", key]); return json(res, { error: "That promo code is used up" }, 400), true; }
        const r = await register(d, site, "promo-" + code + "-" + d);
        if (r.error) { await redis(["INCR", key]); return json(res, { error: r.error }, 400), true; }
        return json(res, r), true;
      }
      if (!stripeOn()) return json(res, { error: "Paid domains aren't switched on yet. Use a promo code." }, 503), true;
      if (await redis(["EXISTS", "domain:" + d])) return json(res, { error: d + " is already taken" }, 409), true;
      const origin = (req.headers["x-forwarded-proto"] || "http") + "://" + req.headers.host;
      const f = new URLSearchParams({ mode: "subscription", "line_items[0][price]": E.STRIPE_PRICE_ID, "line_items[0][quantity]": "1",
        success_url: origin + "/?paid=1", cancel_url: origin + "/", "metadata[domain]": d, "metadata[site]": site });
      const r = await fetch(STRIPE + "/v1/checkout/sessions", { method: "POST",
        headers: { Authorization: "Bearer " + E.STRIPE_SECRET_KEY, "content-type": "application/x-www-form-urlencoded" }, body: f });
      const s = await r.json();
      if (!r.ok || !s.url) return json(res, { error: "Couldn't start checkout" }, 502), true;
      return json(res, { checkoutUrl: s.url }), true;
    }

    if (p === "/api/stripe/webhook" && req.method === "POST") {
      const raw = await readBody(req, 200000);
      if (!stripeOn() || !verifyStripe(raw, req.headers["stripe-signature"])) return ctx.send(res, 400, "bad signature"), true;
      let ev; try { ev = JSON.parse(raw); } catch (e) { return ctx.send(res, 400, "bad json"), true; }
      if (ev.type === "checkout.session.completed") {
        const s = ev.data.object, md = s.metadata || {};
        const r = await register(md.domain, md.site, "stripe-" + s.id);
        if (r.error) await redis(["SET", "failed:" + s.id, JSON.stringify({ domain: md.domain, site: md.site, error: r.error })]);
      }
      return json(res, { received: true }), true;
    }

    if (p === "/api/admin/promo" && isAdmin(u)) {
      const code = (u.searchParams.get("code") || "").toUpperCase().replace(/[^A-Z0-9-]/g, "");
      const uses = parseInt(u.searchParams.get("uses") || "1", 10);
      if (!code || !(uses >= 0)) return json(res, { error: "Need code and uses" }, 400), true;
      await redis(["SET", "promo:" + code, String(uses)]);
      return json(res, { code, uses }), true;
    }
    if (p === "/api/admin/domains" && isAdmin(u)) {
      const keys = await redis(["KEYS", "domain:*"]), failed = await redis(["KEYS", "failed:*"]);
      return json(res, { domains: keys.map(k => k.slice(7)), failedPayments: failed.length }), true;
    }
    return false;
  };
};
