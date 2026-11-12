"use strict";
/*
  WEAR ME server
  - Stores the shop data (products, settings, orders, sewing requests, ledger) in data/db.json
  - Stores uploaded pictures and videos in uploads/
  - One admin account (email + password), password kept as a salted scrypt hash in data/admin.json
  - Customer accounts (email + password) in data/customers.json, also salted scrypt hashes
  Nothing to install: it uses only what comes with Node (version 18 or newer).
*/
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");

/* ---------- settings ---------- */
function loadEnv() {
  try {
    fs.readFileSync(path.join(__dirname, ".env"), "utf8").split(/\r?\n/).forEach((l) => {
      const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
      if (m && !l.trim().startsWith("#") && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
    });
  } catch (e) { /* no .env file, defaults apply */ }
}
loadEnv();
const PORT = Number(process.env.PORT) || 4000;
const ORIGINS = (process.env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim()).filter(Boolean);
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const SESSION_MS = (Number(process.env.SESSION_HOURS) || 12) * 3600 * 1000;
const MAX_UPLOAD = (Number(process.env.MAX_UPLOAD_MB) || 25) * 1048576;
const PUBLIC_IMAGE_MAX = 10 * 1048576;
const DATA_DIR = path.resolve(__dirname, process.env.DATA_DIR || "data");
const UPLOAD_DIR = path.resolve(__dirname, process.env.UPLOAD_DIR || "uploads");
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || "").trim();
const GOOGLE_TOKENINFO = process.env.GOOGLE_TOKENINFO_URL || "https://oauth2.googleapis.com/tokeninfo";
const ADMIN_RESET = ["1", "true", "yes"].includes(String(process.env.ADMIN_RESET || "").toLowerCase());
const PAYSTACK_SECRET = (process.env.PAYSTACK_SECRET_KEY || "").trim();
const PAYSTACK_API = (process.env.PAYSTACK_API_URL || "https://api.paystack.co").replace(/\/+$/, "");
const SITE_URL = (process.env.SITE_URL || ORIGINS.find((o) => o !== "*") || "").replace(/\/+$/, "");
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const SITE_DIR = process.env.SITE_DIR ? path.resolve(__dirname, process.env.SITE_DIR) : "";
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- tiny file database ---------- */
const DB_FILE = path.join(DATA_DIR, "db.json");
const ADMIN_FILE = path.join(DATA_DIR, "admin.json");
const CUSTOMER_FILE = path.join(DATA_DIR, "customers.json");
const SESSION_FILE = path.join(DATA_DIR, "sessions.json");
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { return fallback; }
}
const docs = readJson(DB_FILE, {}); // { "products/1": {...}, "settings/site": {...} }
let admin = readJson(ADMIN_FILE, null); // { email, salt, hash, profile, createdAt }
const customers = readJson(CUSTOMER_FILE, {}); // { "name@mail.com": {name,email,phone,salt,hash,createdAt} }
let saveTimer = null;
function writeAtomic(file, text) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
}
function saveDb() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { writeAtomic(DB_FILE, JSON.stringify(docs)); } catch (e) { console.error("Could not save data:", e.message); }
  }, 150);
}
function flush() { try { writeAtomic(DB_FILE, JSON.stringify(docs)); } catch (e) { /* ignore */ } }
process.on("SIGINT", () => { flush(); process.exit(0); });
process.on("SIGTERM", () => { flush(); process.exit(0); });

const COLLECTIONS = ["products", "settings", "orders", "styling", "ledger"];
const PUBLIC_READ = ["products", "settings"];
const DOC_PATH = /^([a-z]+)\/([A-Za-z0-9_-]{1,64})$/;
function parsePath(p) {
  const m = DOC_PATH.exec(String(p || ""));
  if (!m || !COLLECTIONS.includes(m[1])) return null;
  return { col: m[1], id: m[2], path: m[0] };
}
function colDocs(col) {
  const out = [];
  const prefix = col + "/";
  for (const k of Object.keys(docs)) if (k.startsWith(prefix)) out.push({ id: k.slice(prefix.length), data: docs[k] });
  return out;
}

/* ---------- passwords and sessions ---------- */
function hashPassword(pw, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
function checkPassword(pw, acc) {
  const h = hashPassword(pw, acc.salt).hash;
  const a = Buffer.from(h, "hex"), b = Buffer.from(acc.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const CUSTOMER_MS = 30 * 24 * 3600 * 1000;
const sessions = new Map(Object.entries(readJson(SESSION_FILE, {}))); // sha256(token) -> { role, email, exp }
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
let sessTimer = null;
function saveSessions() {
  clearTimeout(sessTimer);
  sessTimer = setTimeout(() => {
    try { writeAtomic(SESSION_FILE, JSON.stringify(Object.fromEntries(sessions))); } catch (e) { console.error("Could not save sessions:", e.message); }
  }, 300);
}
function newSession(role, email) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(sha(token), { role, email, exp: Date.now() + (role === "admin" ? SESSION_MS : CUSTOMER_MS) });
  saveSessions();
  return token;
}
function tokenOf(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : "";
}
function sessionOf(req) {
  const t = tokenOf(req);
  if (!t) return null;
  const k = sha(t), s = sessions.get(k);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(k); saveSessions(); return null; }
  return s;
}
function isAdmin(req) { const s = sessionOf(req); return !!(s && s.role === "admin" && admin && s.email === admin.email); }
function customerOf(req) { const s = sessionOf(req); return s && s.role === "customer" && customers[s.email] ? s.email : ""; }
setInterval(() => { const n = Date.now(); let ch = false; for (const [k, v] of sessions) if (v.exp < n) { sessions.delete(k); ch = true; } if (ch) saveSessions(); }, 600000).unref();

/* Emergency: forgot the admin password. Set ADMIN_RESET=1, start the server once, then REMOVE the setting. */
if (ADMIN_RESET && admin) {
  admin = null;
  try { fs.unlinkSync(ADMIN_FILE); } catch (e) { /* already gone */ }
  for (const [k, v] of [...sessions]) if (v.role === "admin") sessions.delete(k);
  saveSessions();
  console.log("ADMIN_RESET is on: the admin account was removed. Remove ADMIN_RESET from your settings, then create the account again on admin.html.");
}

/* ---------- small rate limiter ---------- */
const hits = new Map();
function clientIp(req) {
  if (TRUST_PROXY) { const f = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim(); if (f) return f; }
  return req.socket.remoteAddress || "?";
}
function limited(req, name, max, windowMs) {
  const key = name + ":" + clientIp(req), now = Date.now();
  let h = hits.get(key);
  if (!h || h.reset < now) h = { n: 0, reset: now + windowMs };
  h.n++; hits.set(key, h);
  return h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 600000).unref();

/* ---------- http helpers ---------- */
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (code, msg) => { throw new HttpError(code, msg); };
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
}
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on("data", (c) => { n += c.length; if (n > max) { reject(new HttpError(413, "That is too big.")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
async function readBodyJson(req, max = 8 * 1048576) {
  const buf = await readBody(req, max);
  try { const v = JSON.parse(buf.toString("utf8") || "{}"); return v; } catch (e) { return bad(400, "Send valid JSON."); }
}
function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && (ORIGINS.includes("*") || ORIGINS.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", ORIGINS.includes("*") ? "*" : origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-File-Name");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    res.setHeader("Access-Control-Max-Age", "600");
    return true;
  }
  return !origin;
}
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".mp4": "video/mp4", ".webm": "video/webm", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8" };
function sendFile(req, res, file, extra) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end(); }
    const type = MIME[path.extname(file).toLowerCase()] || "application/octet-stream";
    const headers = Object.assign({ "Content-Type": type, "Accept-Ranges": "bytes" }, extra || {});
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range || ""));
    if (m && (m[1] || m[2])) {
      let start = m[1] ? Number(m[1]) : st.size - Number(m[2]), end = m[1] && m[2] ? Number(m[2]) : st.size - 1;
      end = Math.min(end, st.size - 1);
      if (start > end || start < 0) { res.writeHead(416, { "Content-Range": "bytes */" + st.size }); return res.end(); }
      res.writeHead(206, Object.assign(headers, { "Content-Range": "bytes " + start + "-" + end + "/" + st.size, "Content-Length": end - start + 1 }));
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    res.writeHead(200, Object.assign(headers, { "Content-Length": st.size }));
    fs.createReadStream(file).pipe(res);
  });
}

/* ---------- rules ---------- */
const clip = (v, n) => String(v == null ? "" : v).slice(0, n);
const isObj = (b) => b && typeof b === "object" && !Array.isArray(b);
function cleanNewStyling(s) {
  s = Object.assign({}, s);
  s.status = "New"; s.paid = false;
  delete s.quote; delete s.paidAt;
  s.createdAt = new Date().toISOString();
  return s;
}
function publicAccount() { return admin ? { email: admin.email, profile: admin.profile || {} } : null; }

/* ---------- routes ---------- */
const routes = {};
const route = (method, p, fn) => { routes[method + " " + p] = fn; };


/* ---------- Paystack ---------- */
const PAYSTACK_ON = !!PAYSTACK_SECRET;
const PAYSTACK_MODE = /^sk_live_/.test(PAYSTACK_SECRET) ? "live" : "test";
async function paystack(method, p, body) {
  if (!PAYSTACK_ON) bad(503, "Card payments are not switched on yet.");
  let r;
  try {
    r = await fetch(PAYSTACK_API + p, {
      method,
      headers: { Authorization: "Bearer " + PAYSTACK_SECRET, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) { bad(502, "Could not reach Paystack. Try again in a moment."); }
  let j = null;
  try { j = await r.json(); } catch (e) { /* not json */ }
  if (!r.ok || !j || j.status === false) bad(502, (j && j.message) || "Paystack refused the request.");
  return j;
}
const kobo = (n) => Math.round(Number(n) * 100);
const orderOfRef = (ref) => {
  const id = String(ref || "").split("_")[0];
  return docs["orders/" + id] ? docs["orders/" + id] : null;
};
/* Mark an order paid after Paystack says the money arrived. Safe to run many times. */
function applyPaystackCharge(order, tx) {
  if (!order || !tx || tx.status !== "success") return false;
  if (kobo(order.total) !== Number(tx.amount) || String(tx.currency || "NGN") !== "NGN") {
    order.payNote = "Paystack amount did not match the order. Check this payment in your Paystack dashboard.";
    saveDb(); return false;
  }
  if (order.payStatus === "Paid" || order.payStatus === "Refunded") return true;
  order.payStatus = "Paid";
  order.paidAt = tx.paid_at || new Date().toISOString();
  order.payRef = tx.reference;
  order.payChannel = clip(tx.channel, 30);
  order.paystackFee = (Number(tx.fees) || 0) / 100;
  if (tx.id) order.paystackId = tx.id;
  const c = tx.authorization || {};
  if (c.last4) order.card = { brand: clip(c.card_type || c.brand || "Card", 30).trim(), last4: clip(c.last4, 4), exp: "" };
  delete order.payNote;
  saveDb();
  return true;
}
function priceOrder(body) {
  if (!Array.isArray(body.lines) || !body.lines.length || body.lines.length > 40) bad(400, "Your cart is empty.");
  const haveProducts = colDocs("products").length > 0;
  const lines = [];
  let sub = 0, items = 0;
  for (const l of body.lines) {
    const qty = Math.floor(Number(l && l.qty));
    if (!(qty >= 1 && qty <= 20)) bad(400, "A quantity in your cart is not right.");
    const pr = docs["products/" + clip(l.pid, 40)];
    let price;
    if (pr) {
      if (pr.active === false || pr.soldOut) bad(400, (pr.name || "An item") + " is no longer available. Remove it and try again.");
      price = Number(pr.price);
    } else if (!haveProducts) price = Number(l.price); // shop not set up yet: demo products only
    else bad(400, "An item in your cart is no longer sold. Remove it and try again.");
    if (!(price >= 0)) bad(400, "A price is not right.");
    lines.push({ pid: pr ? pr.id : l.pid, name: clip(pr ? pr.name : l.name, 120), cat: clip(pr ? pr.cat : l.cat, 40), size: clip(l.size, 20), qty, price });
    sub += price * qty; items += qty;
  }
  const site = docs["settings/site"] || {};
  const f = Number(site.deliveryFee) || 0, free = Number(site.freeAbove) || 0;
  const ship = body.ship === "pickup" ? "pickup" : "home";
  const fee = ship === "pickup" ? 0 : (free > 0 && sub >= free ? 0 : f);
  return { lines, items, subtotal: sub, fee, total: sub + fee, ship };
}
function newOrderId() {
  for (;;) { const id = "WM-" + String(Math.floor(100000 + Math.random() * 900000)); if (!docs["orders/" + id]) return id; }
}
async function startPaystack(order, email) {
  const ref = order.id + "_" + crypto.randomBytes(4).toString("hex");
  const j = await paystack("POST", "/transaction/initialize", {
    email, amount: kobo(order.total), currency: "NGN", reference: ref,
    callback_url: SITE_URL ? SITE_URL + "/" : undefined,
    metadata: { order: order.id, name: order.name, phone: order.phone },
  });
  order.payRef = ref;
  saveDb();
  return j.data.authorization_url;
}
const summaryOf = (o) => ({ id: o.id, name: o.name, phone: o.phone, items: o.items, total: o.total, pay: o.pay, payStatus: o.payStatus });

route("GET", "/api/health", (req, res) => send(res, 200, { ok: true }));
route("POST", "/api/checkout", async (req, res) => {
  if (limited(req, "checkout", 40, 3600000)) bad(429, "Too many orders from this connection. Try again later.");
  const b = await readBodyJson(req);
  if (!isObj(b)) bad(400, "Send an object.");
  const method = b.method === "paystack" ? "paystack" : "transfer";
  if (method === "paystack" && !PAYSTACK_ON) bad(400, "Card payments are not switched on yet. Use bank transfer.");
  const name = clip(b.name, 120).trim(), phone = clip(b.phone, 30).trim();
  const me = customerOf(req);
  const email = (me || clip(b.email, 160)).trim().toLowerCase();
  if (!name || !phone || (b.ship !== "pickup" && !clip(b.addr, 300).trim())) bad(400, "Please complete your details.");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) bad(400, "Enter a valid email address.");
  const pr = priceOrder(b);
  let proof = "";
  if (method === "transfer") {
    proof = typeof b.proof === "string" && /^data:image\/(jpeg|png|webp);base64,/.test(b.proof) && b.proof.length < 400000 ? b.proof : "";
    if (!proof) bad(400, "Upload your payment screenshot first.");
  }
  const now = new Date().toISOString();
  const order = {
    id: newOrderId(), name, phone, email, customer: me || "",
    addr: clip(b.addr, 300), city: clip(b.city, 80), state: clip(b.state, 80), note: clip(b.note, 1000),
    ship: pr.ship, pay: method, status: "New", statusAt: { New: now }, trackNote: "",
    payStatus: method === "transfer" ? "Proof sent" : "Unpaid", proof, card: null,
    lines: pr.lines, items: pr.items, subtotal: pr.subtotal, fee: pr.fee, total: pr.total, createdAt: now,
  };
  docs["orders/" + order.id] = order;
  saveDb();
  const out = { ok: true, order: summaryOf(order) };
  if (method === "paystack") {
    try { out.url = await startPaystack(order, email); }
    catch (e) { out.url = ""; out.payError = e.message || "Could not start the payment."; }
  }
  send(res, 200, out);
});
/* Customer taps "Pay now" on an order that is still unpaid. */
route("POST", "/api/paystack/pay", async (req, res) => {
  if (limited(req, "paystackpay", 60, 3600000)) bad(429, "Too many tries. Wait a little.");
  const b = await readBodyJson(req);
  const order = docs["orders/" + clip(b.orderId, 40)];
  if (!order || order.pay !== "paystack" || order.payStatus !== "Unpaid" || order.status === "Cancelled") bad(400, "This order cannot be paid online.");
  const me = customerOf(req);
  if (order.customer && order.customer !== me) bad(403, "Log in to pay for this order.");
  send(res, 200, { ok: true, url: await startPaystack(order, order.email) });
});
/* The customer comes back from Paystack. We ask Paystack directly, we never trust the web address. */
route("POST", "/api/paystack/verify", async (req, res) => {
  if (limited(req, "paystackverify", 120, 3600000)) bad(429, "Too many tries. Wait a little.");
  const b = await readBodyJson(req);
  const ref = clip(b.reference, 80);
  if (!/^[A-Za-z0-9_-]+$/.test(ref)) bad(400, "Bad reference.");
  const order = orderOfRef(ref);
  if (!order || order.pay !== "paystack") bad(404, "We could not find that order.");
  let status = "pending";
  if (order.payStatus === "Paid" || order.payStatus === "Refunded") status = "success";
  else {
    const j = await paystack("GET", "/transaction/verify/" + encodeURIComponent(ref));
    const tx = j.data || {};
    if (applyPaystackCharge(order, tx)) status = "success";
    else if (tx.status === "failed" || tx.status === "abandoned" || tx.status === "reversed") status = "failed";
  }
  send(res, 200, { ok: true, status, order: summaryOf(order) });
});
/* Paystack tells us by itself (webhook). Signed with our secret key, so we know it is really Paystack. */
route("POST", "/api/paystack/webhook", async (req, res) => {
  const raw = await readBody(req, 1048576);
  const sig = String(req.headers["x-paystack-signature"] || "");
  const want = crypto.createHmac("sha512", PAYSTACK_SECRET || "-").update(raw).digest("hex");
  const a = Buffer.from(sig), c = Buffer.from(want);
  if (!PAYSTACK_ON || a.length !== c.length || !crypto.timingSafeEqual(a, c)) bad(401, "Bad signature");
  let ev = {};
  try { ev = JSON.parse(raw.toString("utf8")); } catch (e) { bad(400, "Bad JSON"); }
  const d = ev.data || {};
  if (ev.event === "charge.success") {
    const o = orderOfRef(d.reference);
    if (o && o.pay === "paystack") applyPaystackCharge(o, d);
  } else if (ev.event === "refund.processed" || ev.event === "refund.failed") {
    const o = orderOfRef(d.transaction_reference || d.reference) || Object.values(docs).find((x) => x && x.paystackRefundId && String(x.paystackRefundId) === String(d.id));
    if (o && o.refund) {
      o.refund.paystackStatus = ev.event === "refund.processed" ? "processed" : "failed";
      if (ev.event === "refund.failed") o.refund.note = (o.refund.note || "") + " [Paystack could not complete this refund. Check the Paystack dashboard.]";
      saveDb();
    }
  }
  send(res, 200, { ok: true });
});
route("GET", "/api/admin/paystack-status", (req, res) => {
  if (!isAdmin(req)) bad(403, "Not allowed");
  send(res, 200, { configured: PAYSTACK_ON, mode: PAYSTACK_ON ? PAYSTACK_MODE : "", siteUrl: SITE_URL });
});
/* Admin approves a refund on a Paystack order: Paystack sends the money back to the customer. */
route("POST", "/api/admin/paystack-refund", async (req, res) => {
  if (!isAdmin(req)) bad(403, "Not allowed");
  const b = await readBodyJson(req);
  const order = docs["orders/" + clip(b.orderId, 40)];
  if (!order || order.pay !== "paystack" || order.payStatus !== "Paid" || !order.payRef) bad(400, "This order was not paid through Paystack.");
  const amount = Math.min(Number(order.total), Math.max(0, Number(b.amount) || 0));
  if (!amount) bad(400, "Enter a refund amount.");
  const j = await paystack("POST", "/refund", { transaction: order.payRef, amount: kobo(amount) });
  order.refund = Object.assign({}, order.refund || {}, {
    status: "Approved", amount, approvedAt: new Date().toISOString(),
    paystackStatus: clip(j.data && j.data.status, 30) || "pending",
  });
  if (j.data && j.data.id) order.paystackRefundId = j.data.id;
  order.payStatus = "Refunded";
  saveDb();
  send(res, 200, { ok: true });
});

route("GET", "/api/doc", (req, res, q) => {
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  if (!PUBLIC_READ.includes(p.col) && !isAdmin(req)) bad(403, "Not allowed");
  const data = docs[p.path];
  send(res, 200, { exists: data !== undefined, data: data === undefined ? null : data });
});
route("GET", "/api/col", (req, res, q) => {
  const name = String(q.get("name") || "");
  if (!COLLECTIONS.includes(name)) bad(400, "Unknown collection");
  let list = colDocs(name);
  const where = String(q.get("where") || "").split(",");
  if (!isAdmin(req)) {
    if (PUBLIC_READ.includes(name)) { /* anyone may read */ }
    else if (name === "orders") {
      const me = customerOf(req);
      if (!me) bad(403, "Log in to see your orders.");
      list = list.filter((d) => d.data.customer === me);
    } else bad(403, "Not allowed");
  } else if (where.length >= 3 && where[1] === "==") {
    const v = where.slice(2).join(",");
    list = list.filter((d) => String(d.data[where[0]]) === v);
  }
  send(res, 200, { docs: list });
});
route("PUT", "/api/doc", async (req, res, q) => {
  if (limited(req, "write", 600, 3600000)) bad(429, "Too many requests.");
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  const body = await readBodyJson(req);
  if (!isObj(body)) bad(400, "Send an object.");
  if (isAdmin(req)) { docs[p.path] = body; saveDb(); return send(res, 200, { ok: true }); }
  if (docs[p.path] !== undefined) bad(403, "Not allowed");
  if (p.col === "styling") { docs[p.path] = cleanNewStyling(Object.assign({}, body, { id: p.id })); saveDb(); return send(res, 200, { ok: true }); }
  bad(403, "Not allowed");
});
route("PATCH", "/api/doc", async (req, res, q) => {
  if (limited(req, "write", 600, 3600000)) bad(429, "Too many requests.");
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  const body = await readBodyJson(req);
  if (!isObj(body)) bad(400, "Send an object.");
  if (isAdmin(req)) { docs[p.path] = Object.assign({}, docs[p.path] || {}, body); saveDb(); return send(res, 200, { ok: true }); }
  const cur = docs[p.path], keys = Object.keys(body);
  if (p.col === "orders" && cur && customerOf(req) && cur.customer === customerOf(req) && !cur.refund && keys.length === 1 && keys[0] === "refund" && isObj(body.refund) && body.refund.status === "Requested" && cur.status !== "Cancelled" && cur.payStatus !== "Unpaid") {
    cur.refund = { status: "Requested", reason: clip(body.refund.reason, 80), note: clip(body.refund.note, 1000), at: new Date().toISOString() };
    saveDb();
    return send(res, 200, { ok: true });
  }
  bad(403, "Not allowed");
});
route("DELETE", "/api/doc", (req, res, q) => {
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  if (!isAdmin(req)) bad(403, "Not allowed");
  delete docs[p.path]; saveDb();
  send(res, 200, { ok: true });
});

/* admin account */
route("GET", "/api/admin/status", (req, res) => {
  const ok = isAdmin(req);
  send(res, 200, { exists: !!admin, loggedIn: ok, account: ok ? publicAccount() : null });
});
route("POST", "/api/admin/create", async (req, res) => {
  if (limited(req, "create", 10, 3600000)) bad(429, "Too many tries. Wait a little and try again.");
  const b = await readBodyJson(req, 65536);
  if (admin) bad(403, "An admin account already exists.");
  const email = clip(b.email, 200).trim().toLowerCase(), pw = String(b.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email)) bad(400, "Enter a valid email address.");
  if (pw.length < 8) bad(400, "Use at least 8 characters for the password.");
  if (ADMIN_EMAIL && email !== ADMIN_EMAIL) bad(403, "That email is not allowed to create the admin account.");
  const h = hashPassword(pw);
  admin = { email, salt: h.salt, hash: h.hash, profile: {}, createdAt: new Date().toISOString() };
  writeAtomic(ADMIN_FILE, JSON.stringify(admin));
  send(res, 200, { ok: true, token: newSession("admin", admin.email), account: publicAccount() });
});
route("POST", "/api/admin/login", async (req, res) => {
  if (limited(req, "login", 8, 900000)) bad(429, "Too many tries. Wait 15 minutes and try again.");
  const b = await readBodyJson(req, 65536);
  if (!admin) bad(400, "No admin account yet.");
  const email = clip(b.email, 200).trim().toLowerCase(), pw = String(b.password || "");
  if (email !== admin.email || !checkPassword(pw, admin)) bad(401, "That email and password do not match.");
  send(res, 200, { ok: true, token: newSession("admin", admin.email), account: publicAccount() });
});
route("POST", "/api/admin/logout", (req, res) => {
  const t = tokenOf(req); if (t) { sessions.delete(sha(t)); saveSessions(); }
  send(res, 200, { ok: true });
});
route("PUT", "/api/admin/profile", async (req, res) => {
  if (!isAdmin(req)) bad(401, "Log in first.");
  const b = await readBodyJson(req, 65536);
  admin.profile = { name: clip(b.name, 120).trim(), dob: clip(b.dob, 20), phone: clip(b.phone, 40).trim(), role: clip(b.role, 80).trim() };
  writeAtomic(ADMIN_FILE, JSON.stringify(admin));
  send(res, 200, { ok: true, account: publicAccount() });
});
route("POST", "/api/admin/password", async (req, res) => {
  if (!isAdmin(req)) bad(401, "Log in first.");
  if (limited(req, "pw", 10, 900000)) bad(429, "Too many tries. Wait a little and try again.");
  const b = await readBodyJson(req, 65536), old = String(b.old || ""), pw = String(b.password || "");
  if (!checkPassword(old, admin)) bad(400, "Your current password is not right.");
  if (pw.length < 8) bad(400, "Use at least 8 characters.");
  const h = hashPassword(pw);
  admin.salt = h.salt; admin.hash = h.hash;
  writeAtomic(ADMIN_FILE, JSON.stringify(admin));
  const keep = sha(tokenOf(req));
  for (const [k, v] of [...sessions]) if (k !== keep && v.role === "admin") sessions.delete(k);
  saveSessions();
  send(res, 200, { ok: true });
});

/* customer accounts */
function publicCustomer(c) { return { name: c.name, email: c.email, phone: c.phone || "" }; }
route("POST", "/api/customer/signup", async (req, res) => {
  if (limited(req, "csignup", 10, 3600000)) bad(429, "Too many tries. Wait a little and try again.");
  const b = await readBodyJson(req, 65536);
  const name = clip(b.name, 120).trim(), email = clip(b.email, 200).trim().toLowerCase(), phone = clip(b.phone, 40).trim(), pw = String(b.password || "");
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) bad(400, "Enter your name and a valid email address.");
  if (pw.length < 8) bad(400, "Use at least 8 characters for your password.");
  if (customers[email]) bad(409, "That email already has an account. Log in instead.");
  const h = hashPassword(pw);
  customers[email] = { name, email, phone, salt: h.salt, hash: h.hash, createdAt: new Date().toISOString() };
  writeAtomic(CUSTOMER_FILE, JSON.stringify(customers));
  send(res, 200, { ok: true, token: newSession("customer", email), account: publicCustomer(customers[email]) });
});
route("GET", "/api/config", (req, res) => send(res, 200, { googleClientId: GOOGLE_CLIENT_ID, paystack: PAYSTACK_ON }));
route("POST", "/api/customer/google", async (req, res) => {
  if (!GOOGLE_CLIENT_ID) bad(404, "Google sign-in is not set up.");
  if (limited(req, "cgoogle", 20, 900000)) bad(429, "Too many tries. Wait a little and try again.");
  const b = await readBodyJson(req, 16384);
  const cred = String(b.credential || "");
  if (cred.length < 20 || cred.length > 8000) bad(400, "Google sign-in did not work. Try again.");
  let info;
  try {
    const r = await fetch(GOOGLE_TOKENINFO + "?id_token=" + encodeURIComponent(cred));
    info = await r.json();
    if (!r.ok) info = null;
  } catch (e) { info = null; }
  const issOk = info && ["accounts.google.com", "https://accounts.google.com"].includes(info.iss);
  if (!info || info.aud !== GOOGLE_CLIENT_ID || !issOk || String(info.email_verified) !== "true" || Number(info.exp) * 1000 < Date.now() || !info.email) bad(401, "Google sign-in did not work. Try again or use your email.");
  const email = String(info.email).trim().toLowerCase();
  let c = customers[email];
  if (!c) {
    c = customers[email] = { name: clip(info.name || email.split("@")[0], 120), email, phone: "", salt: "", hash: "", google: true, createdAt: new Date().toISOString() };
  } else if (!c.google) { c.google = true; }
  writeAtomic(CUSTOMER_FILE, JSON.stringify(customers));
  send(res, 200, { ok: true, token: newSession("customer", email), account: publicCustomer(c) });
});
route("POST", "/api/customer/login", async (req, res) => {
  if (limited(req, "clogin", 10, 900000)) bad(429, "Too many tries. Wait 15 minutes and try again.");
  const b = await readBodyJson(req, 65536);
  const email = clip(b.email, 200).trim().toLowerCase(), pw = String(b.password || "");
  const c = customers[email];
  if (c && c.google && !c.hash) bad(401, "This account uses Google. Tap Continue with Google to log in.");
  if (!c || !checkPassword(pw, c)) bad(401, "That email and password do not match. Check them or sign up.");
  send(res, 200, { ok: true, token: newSession("customer", email), account: publicCustomer(c) });
});
route("GET", "/api/customer/me", (req, res) => {
  const me = customerOf(req);
  if (!me) bad(401, "Please log in.");
  send(res, 200, { account: publicCustomer(customers[me]) });
});
route("POST", "/api/customer/logout", (req, res) => {
  const s = sessionOf(req), t = tokenOf(req);
  if (s && s.role === "customer") { sessions.delete(sha(t)); saveSessions(); }
  send(res, 200, { ok: true });
});

/* uploads */
const TYPES = {
  "image/jpeg": ["jpg", (b) => b[0] === 0xff && b[1] === 0xd8],
  "image/png": ["png", (b) => b.slice(0, 4).toString("hex") === "89504e47"],
  "image/webp": ["webp", (b) => b.slice(0, 4).toString() === "RIFF" && b.slice(8, 12).toString() === "WEBP"],
  "image/gif": ["gif", (b) => b.slice(0, 3).toString() === "GIF"],
  "video/mp4": ["mp4", (b) => b.slice(4, 8).toString() === "ftyp"],
  "video/webm": ["webm", (b) => b.slice(0, 4).toString("hex") === "1a45dfa3"]
};
route("POST", "/api/upload", async (req, res) => {
  if (limited(req, "upload", 60, 3600000)) bad(429, "Too many uploads. Try again later.");
  const type = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  const t = TYPES[type];
  if (!t) bad(415, "Use a JPG, PNG, WebP, MP4 or WebM file.");
  const adm = isAdmin(req);
  const buf = await readBody(req, adm ? MAX_UPLOAD : PUBLIC_IMAGE_MAX);
  if (buf.length < 12 || !t[1](buf)) bad(415, "That file does not look like a " + type + ".");
  if (!adm && type.startsWith("video/")) bad(403, "Not allowed.");
  const id = crypto.randomBytes(12).toString("hex");
  fs.writeFileSync(path.join(UPLOAD_DIR, id + "." + t[0]), buf);
  send(res, 200, { id, url: "/blob/" + id, contentType: type });
});

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, "http://localhost");
    if (!cors(req, res)) return send(res, 403, { error: "This website is not allowed to use the server." });
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
    const fn = routes[req.method + " " + u.pathname];
    if (fn) return await fn(req, res, u.searchParams);
    if (req.method === "GET" && u.pathname.startsWith("/blob/")) {
      const id = u.pathname.slice(6).replace(/[^a-f0-9]/g, "");
      const file = id.length === 24 && fs.readdirSync(UPLOAD_DIR).find((f) => f.startsWith(id + "."));
      if (!file) { res.writeHead(404); return res.end(); }
      return sendFile(req, res, path.join(UPLOAD_DIR, file), { "Cross-Origin-Resource-Policy": "cross-origin", "Cache-Control": "public, max-age=31536000, immutable" });
    }
    if (u.pathname.startsWith("/api/")) bad(404, "Not found");
    if (SITE_DIR && (req.method === "GET" || req.method === "HEAD")) {
      let rel = decodeURIComponent(u.pathname);
      if (rel.endsWith("/")) rel += "index.html";
      const file = path.join(SITE_DIR, path.normalize(rel));
      if (file.startsWith(SITE_DIR + path.sep) || file === SITE_DIR) return sendFile(req, res, file);
    }
    res.writeHead(404, { "Content-Type": "text/plain" }); res.end("Not found");
  } catch (e) {
    if (e instanceof HttpError) { if (!res.headersSent) send(res, e.code, { error: e.message }); else res.end(); return; }
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: "Server error" }); else res.end();
  }
});
server.listen(PORT, () => {
  console.log("WEAR ME server running on port " + PORT);
  console.log(admin ? "Admin account: set up" : "Admin account: not created yet (open admin.html to create it)");
  console.log(PAYSTACK_ON ? "Paystack: on (" + PAYSTACK_MODE + " keys)" : "Paystack: off (no PAYSTACK_SECRET_KEY set)");
  if (SITE_DIR) console.log("Also serving the website from " + SITE_DIR);
});
