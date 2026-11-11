'use strict';
const express = require('express'), cors = require('cors'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), multer = require('multer'), crypto = require('crypto');
const E = process.env;
for (const k of ['DATABASE_URL', 'JWT_SECRET', 'SITE_URL']) if (!E[k]) { console.error('Missing environment variable: ' + k); process.exit(1); }

const pool = new Pool({ connectionString: E.DATABASE_URL, ssl: E.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false });
const q = (t, p) => pool.query(t, p);
const CATS = ['Premium Parfait', 'Shawarma', 'Juice', 'Greek Yogurt', 'Drinking Yogurt', 'Pastries', 'Banana Bread', 'Meat Specials', 'Extras'];
const SITE = E.SITE_URL.trim().replace(/\/$/, '');
const origins = [SITE, ...(E.EXTRA_ORIGINS || '').split(',')].map(s => s.trim().replace(/\/$/, '')).filter(Boolean);

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: (o, cb) => cb(null, !o || origins.includes(o)) }));
app.use(express.json({ limit: '1mb', verify: (req, _r, buf) => { req.raw = buf; } }));
const up = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024, files: 1 } });
const limiter = n => rateLimit({ windowMs: 15 * 60 * 1000, limit: n, standardHeaders: true, legacyHeaders: false });

const bad = (m, s = 400) => { const e = new Error(m); e.status = s; return e; };
const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(e => {
  if (!e.status) console.error(e);
  res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error. Please try again.' });
});
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query('BEGIN'); const r = await fn(c); await c.query('COMMIT'); return r; }
  catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}

/* ---------- Database ---------- */
const DEF = {
  delivery_fee: 1500,
  account: { bank: '', name: '', no: '' },
  contact: { call: '', wa: '', email: '' },
  social: { tiktok: { url: '', live: false }, instagram: { url: '', live: false } },
  discount: { pct: 20, live: false },
  banner: { live: false, slots: [] }
};
const getS = async () => { const r = await q('SELECT key,value FROM settings'); const s = { ...DEF }; r.rows.forEach(x => { s[x.key] = x.value; }); return s; };
const setS = (k, v) => q('INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2', [k, JSON.stringify(v)]);

async function init() {
  await q(`
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS files(id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT, mime TEXT NOT NULL, size INT NOT NULL, data BYTEA NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS products(id SERIAL PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, price INT NOT NULL, stock INT NOT NULL DEFAULT 0, image UUID, created_at TIMESTAMPTZ DEFAULT now());
CREATE SEQUENCE IF NOT EXISTS order_no START 1001;
CREATE TABLE IF NOT EXISTS orders(id INT PRIMARY KEY DEFAULT nextval('order_no'), user_id INT REFERENCES users(id), name TEXT, phone TEXT, email TEXT, items JSONB NOT NULL, delivery_fee INT NOT NULL DEFAULT 0, total INT NOT NULL, ship TEXT NOT NULL, address TEXT, status TEXT NOT NULL, pay_status TEXT NOT NULL DEFAULT 'Pending', method TEXT, reference TEXT UNIQUE, receipt UUID, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS bookings(id SERIAL PRIMARY KEY, name TEXT, email TEXT, phone TEXT, event TEXT, service TEXT, date TEXT, time TEXT, venue TEXT, notes TEXT, status TEXT NOT NULL DEFAULT 'New', created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value JSONB NOT NULL);`);
  for (const [k, v] of Object.entries(DEF)) await q('INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT DO NOTHING', [k, JSON.stringify(v)]);
  if (E.ADMIN_EMAIL && E.ADMIN_PASSWORD) {
    const h = await bcrypt.hash(E.ADMIN_PASSWORD, 10);
    await q(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin') ON CONFLICT(email) DO UPDATE SET password_hash=$2, role='admin'`, [E.ADMIN_EMAIL.trim().toLowerCase(), h]);
  } else console.warn('ADMIN_EMAIL / ADMIN_PASSWORD not set: no admin account created.');
}

/* ---------- Helpers ---------- */
const sign = u => jwt.sign({ id: u.id, role: u.role }, E.JWT_SECRET, { expiresIn: '30d' });
const auth = role => (req, res, next) => {
  try {
    req.u = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), E.JWT_SECRET);
    if (role && req.u.role !== role) throw new Error('role');
    next();
  } catch (_) { res.status(401).json({ error: 'Please log in' }); }
};
const emailOk = s => /^\S+@\S+\.\S+$/.test(s);
const UUID = /^[0-9a-f-]{36}$/i;
const sum = items => items.map(i => i.q + ' × ' + i.n).join(', ');
const mine = async id => (await q(`SELECT id,items,total,ship,status FROM orders WHERE user_id=$1 AND status NOT IN ('Awaiting payment','Cancelled') ORDER BY id DESC LIMIT 100`, [id]))
  .rows.map(o => ({ id: o.id, items: sum(o.items), total: o.total, ship: o.ship, st: o.status }));

const MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', heic: 'image/heic', heif: 'image/heif', gif: 'image/gif', mp4: 'video/mp4', mov: 'video/quicktime', pdf: 'application/pdf' };
const IMG = ['png', 'jpg', 'jpeg', 'webp', 'heic', 'heif', 'gif'], VID = ['mp4', 'mov'];
function checkFile(f, allow) {
  const x = (f.originalname.split('.').pop() || '').toLowerCase();
  const k = VID.includes(x) ? 'video' : IMG.includes(x) ? 'image' : x === 'pdf' ? 'pdf' : null;
  if (!k || !allow.includes(k)) throw bad('Unsupported file type');
  if (k === 'video' && f.size > 20 * 1048576) throw bad('Video must be under 20 MB');
  if (k !== 'video' && f.size > 10 * 1048576) throw bad('File must be under 10 MB');
  f.mime = MIME[x];
  return k;
}
const saveFile = async (c, f) => (await c.query('INSERT INTO files(name,mime,size,data) VALUES($1,$2,$3,$4) RETURNING id', [f.originalname.slice(0, 120), f.mime, f.size, f.buffer])).rows[0].id;
const dropFile = id => id ? q('DELETE FROM files WHERE id=$1', [id]).catch(() => {}) : null;
const stock = async (items, sign_) => { for (const i of items) await q('UPDATE products SET stock=GREATEST(stock+$1,0) WHERE id=$2', [sign_ * i.q, i.id]); };

async function placeOrder(c, userId, b, { method, status, receipt = null, reference = null }) {
  const ship = b.ship === 'delivery' ? 'Delivery' : 'Pickup';
  const name = String(b.name || '').trim().slice(0, 100), phone = String(b.phone || '').trim().slice(0, 30), address = String(b.address || '').trim().slice(0, 300);
  if (name.length < 2) throw bad('Enter your name');
  if (phone.replace(/\D/g, '').length < 7) throw bad('Enter a valid phone number');
  if (ship === 'Delivery' && !address) throw bad('Enter your delivery address');
  const s = await getS();
  const want = {};
  (Array.isArray(b.items) ? b.items : []).forEach(i => { const id = +i.id, n = Math.floor(+i.qty); if (id > 0 && n > 0 && n <= 100) want[id] = (want[id] || 0) + n; });
  const ids = Object.keys(want).map(Number);
  if (!ids.length || ids.length > 50) throw bad('Your cart is empty');
  const pr = await c.query('SELECT id,name,price,stock FROM products WHERE id=ANY($1) ORDER BY id FOR UPDATE', [ids]);
  if (pr.rowCount !== ids.length) throw bad('One of the items is no longer available');
  const lines = []; let sub = 0;
  for (const p of pr.rows) {
    const n = want[p.id];
    if (p.stock < n) throw bad(p.stock ? `Only ${p.stock} of ${p.name} left` : `${p.name} is sold out`);
    const unit = s.discount.live ? Math.round(p.price * (100 - s.discount.pct) / 100) : p.price;
    lines.push({ id: p.id, n: p.name, q: n, p: unit }); sub += unit * n;
    await c.query('UPDATE products SET stock=stock-$1 WHERE id=$2', [n, p.id]);
  }
  const fee = ship === 'Delivery' ? s.delivery_fee : 0, total = sub + fee;
  const u = (await c.query('SELECT email FROM users WHERE id=$1', [userId])).rows[0];
  const r = await c.query(`INSERT INTO orders(user_id,name,phone,email,items,delivery_fee,total,ship,address,status,pay_status,method,reference,receipt)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'Pending',$11,$12,$13) RETURNING *`,
    [userId, name, phone, u.email, JSON.stringify(lines), fee, total, ship, address, status, method, reference, receipt]);
  return r.rows[0];
}

/* ---------- Public routes ---------- */
app.get('/', (_req, res) => res.json({ ok: true, service: 'Bee Sweet API' }));
app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.get('/api/shop', wrap(async (_req, res) => {
  const [s, p] = await Promise.all([getS(), q('SELECT id,name,category,price,stock,image FROM products ORDER BY id DESC')]);
  res.set('Cache-Control', 'no-store').json({
    products: p.rows.map(r => ({ id: r.id, n: r.name, c: r.category, p: r.price, s: r.stock, img: r.image ? '/api/files/' + r.image : null })),
    deliveryFee: s.delivery_fee,
    promo: { live: !!s.discount.live, percent: s.discount.live ? s.discount.pct : 0 },
    social: { tiktok: s.social.tiktok.live ? s.social.tiktok.url : '', instagram: s.social.instagram.live ? s.social.instagram.url : '' },
    contact: s.contact, account: s.account,
    banner: s.banner.live ? s.banner.slots.map(b => ({ type: b.type, src: '/api/files/' + b.file })) : []
  });
}));

app.get('/api/files/:id', wrap(async (req, res) => {
  if (!UUID.test(req.params.id)) return res.sendStatus(404);
  const r = await q('SELECT mime,data FROM files WHERE id=$1', [req.params.id]);
  if (!r.rowCount) return res.sendStatus(404);
  const { mime, data } = r.rows[0], n = data.length;
  res.set({ 'Content-Type': mime, 'Accept-Ranges': 'bytes', 'Cache-Control': 'public, max-age=31536000, immutable' });
  const m = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
  if (m && (m[1] || m[2])) {
    const s = m[1] ? +m[1] : Math.max(0, n - +m[2]), e = m[1] && m[2] ? Math.min(+m[2], n - 1) : n - 1;
    if (s > e || s >= n) return res.status(416).set('Content-Range', 'bytes */' + n).end();
    return res.status(206).set({ 'Content-Range': `bytes ${s}-${e}/${n}`, 'Content-Length': e - s + 1 }).end(data.subarray(s, e + 1));
  }
  res.set('Content-Length', n).end(data);
}));

/* ---------- Auth ---------- */
const authLimit = limiter(30);
app.post('/api/auth/signup', authLimit, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!emailOk(email)) throw bad('Enter a valid email address');
  if (pw.length < 6) throw bad('Password must be at least 6 characters');
  if ((await q('SELECT 1 FROM users WHERE email=$1', [email])).rowCount) throw bad('An account with this email already exists. Please log in.', 409);
  const u = (await q('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,role', [email, await bcrypt.hash(pw, 10)])).rows[0];
  res.json({ token: sign(u), email, role: u.role, orders: [] });
}));
app.post('/api/auth/login', authLimit, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const u = (await q('SELECT id,role,password_hash FROM users WHERE email=$1', [email])).rows[0];
  if (!u || !(await bcrypt.compare(pw, u.password_hash))) throw bad('Incorrect email or password', 401);
  res.json({ token: sign(u), email, role: u.role, orders: u.role === 'customer' ? await mine(u.id) : [] });
}));
app.get('/api/me', auth(), wrap(async (req, res) => {
  const u = (await q('SELECT email FROM users WHERE id=$1', [req.u.id])).rows[0];
  if (!u) throw bad('Please log in', 401);
  res.json({ email: u.email, orders: await mine(req.u.id) });
}));

/* ---------- Orders and payments ---------- */
app.post('/api/orders/transfer', auth(), up.single('receipt'), wrap(async (req, res) => {
  let b; try { b = JSON.parse(req.body.data); } catch (_) { throw bad('Invalid order'); }
  if (!req.file) throw bad('Upload your payment receipt');
  checkFile(req.file, ['image', 'pdf']);
  const o = await tx(async c => {
    const fid = await saveFile(c, req.file);
    return placeOrder(c, req.u.id, b, { method: 'Bank transfer', status: 'Pending', receipt: fid });
  });
  res.json({ order: { id: o.id, items: sum(o.items), total: o.total, ship: o.ship, st: o.status } });
}));

app.post('/api/orders/paystack', auth(), wrap(async (req, res) => {
  if (!E.PAYSTACK_SECRET_KEY) throw bad('Online payment is not available right now', 503);
  const ref = 'BS' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
  const o = await tx(c => placeOrder(c, req.u.id, req.body, { method: 'Paystack', status: 'Awaiting payment', reference: ref }));
  const channels = req.body.channel === 'card' ? ['card'] : ['card', 'bank', 'bank_transfer', 'ussd'];
  try {
    const r = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: o.email, amount: o.total * 100, currency: 'NGN', reference: ref, callback_url: SITE + '/', channels, metadata: { order_id: o.id } })
    });
    const d = await r.json();
    if (!d.status) throw new Error(d.message || 'Paystack error');
    res.json({ url: d.data.authorization_url });
  } catch (e) {
    console.error('Paystack init failed:', e.message);
    await q(`UPDATE orders SET status='Cancelled' WHERE id=$1`, [o.id]); await stock(o.items, 1);
    throw bad('Could not start the payment. Please try again.', 502);
  }
}));

async function settle(ref) {
  const o = (await q('SELECT id,total,status,items FROM orders WHERE reference=$1', [ref])).rows[0];
  if (!o) return { paid: false };
  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(ref), { headers: { Authorization: 'Bearer ' + E.PAYSTACK_SECRET_KEY } });
  const d = await r.json();
  const ok = !!(d.status && d.data && d.data.status === 'success' && d.data.currency === 'NGN' && d.data.amount === o.total * 100);
  if (ok && o.status === 'Awaiting payment') await q(`UPDATE orders SET status='Pending', pay_status='Verified' WHERE id=$1`, [o.id]);
  else if (ok && o.status === 'Cancelled') { await q(`UPDATE orders SET status='Pending', pay_status='Verified' WHERE id=$1`, [o.id]); await stock(o.items, -1); }
  return { paid: ok, orderId: o.id };
}
app.get('/api/paystack/verify', auth(), wrap(async (req, res) => {
  const ref = String(req.query.reference || '');
  const o = (await q('SELECT user_id FROM orders WHERE reference=$1', [ref])).rows[0];
  if (!o || o.user_id !== req.u.id) throw bad('Order not found', 404);
  res.json(await settle(ref));
}));
app.post('/api/paystack/webhook', wrap(async (req, res) => {
  if (!E.PAYSTACK_SECRET_KEY) return res.sendStatus(200);
  const sig = crypto.createHmac('sha512', E.PAYSTACK_SECRET_KEY).update(req.raw || '').digest('hex');
  if (sig !== req.headers['x-paystack-signature']) return res.sendStatus(401);
  if (req.body.event === 'charge.success' && req.body.data && req.body.data.reference) await settle(req.body.data.reference);
  res.sendStatus(200);
}));
// Orders that were never paid online are released after 2 hours
setInterval(async () => {
  try {
    const r = await q(`UPDATE orders SET status='Cancelled' WHERE status='Awaiting payment' AND created_at < now() - interval '2 hours' RETURNING items`);
    for (const o of r.rows) await stock(o.items, 1);
  } catch (e) { console.error(e); }
}, 10 * 60 * 1000);

/* ---------- Catering bookings ---------- */
app.post('/api/bookings', limiter(20), wrap(async (req, res) => {
  const g = (k, n = 200) => String(req.body[k] || '').trim().slice(0, n);
  const b = { name: g('name', 100), email: g('email', 120).toLowerCase(), phone: g('phone', 30), event: g('event', 80), service: g('service', 80), date: g('date', 20), time: g('time', 20), venue: g('venue', 200), notes: g('notes', 1000) };
  if (!b.name) throw bad('Enter your name');
  if (!emailOk(b.email)) throw bad('Enter a valid email address');
  if (b.phone.replace(/\D/g, '').length < 7) throw bad('Enter a valid phone number');
  if (!b.event || !b.service) throw bad('Select the event type and service');
  if (!b.date || !b.venue) throw bad('Add the event date and venue');
  await q('INSERT INTO bookings(name,email,phone,event,service,date,time,venue,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)', Object.values(b));
  res.json({ ok: true });
}));

/* ---------- Admin ---------- */
const admin = auth('admin');
const fmt = d => new Date(d).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Lagos' });

app.get('/api/admin/bootstrap', admin, wrap(async (req, res) => {
  const [s, p, o, b, m, u] = await Promise.all([
    getS(),
    q('SELECT id,name,category,price,stock,image FROM products ORDER BY id DESC'),
    q(`SELECT * FROM orders WHERE status NOT IN ('Awaiting payment','Cancelled') ORDER BY id DESC LIMIT 500`),
    q('SELECT * FROM bookings ORDER BY id DESC LIMIT 500'),
    q(`SELECT to_char(created_at AT TIME ZONE 'Africa/Lagos','YYYY-MM') k, SUM(total) t FROM orders WHERE pay_status='Verified' AND created_at > now() - interval '7 months' GROUP BY 1`),
    q('SELECT email FROM users WHERE id=$1', [req.u.id])
  ]);
  const mm = {}; m.rows.forEach(r => { mm[r.k] = Number(r.t); });
  const months = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() - i);
    months.push([d.toLocaleString('en', { month: 'short', timeZone: 'UTC' }), Math.round((mm[d.toISOString().slice(0, 7)] || 0) / 100) / 10]);
  }
  res.json({
    email: u.rows[0].email,
    products: p.rows.map(r => ({ id: r.id, n: r.name, c: r.category, p: r.price, s: r.stock, img: r.image ? '/api/files/' + r.image : null })),
    orders: o.rows.map(r => ({ id: r.id, cust: r.name, phone: r.phone, items: r.items.map(i => ({ n: i.n, q: i.q, p: i.p })), ship: r.ship, addr: r.address || '', fee: r.delivery_fee, st: r.status, pay: r.pay_status, date: fmt(r.created_at), method: r.method, receipt: r.receipt ? '/api/files/' + r.receipt : null })),
    bookings: b.rows.map(r => ({ id: r.id, name: r.name, email: r.email, phone: r.phone, event: r.event, service: r.service, date: r.date, time: r.time, venue: r.venue, notes: r.notes, status: r.status })),
    months,
    settings: {
      fee: s.delivery_fee, acct: s.account, contact: s.contact, social: s.social,
      disc: { pct: s.discount.pct, live: !!s.discount.live },
      banner: { live: !!s.banner.live, slots: s.banner.slots.map(x => ({ type: x.type, file: x.file, name: x.name || '', src: '/api/files/' + x.file })) }
    }
  });
}));

app.patch('/api/admin/orders/:id/status', admin, wrap(async (req, res) => {
  if (!['Pending', 'Processing', 'Delivered'].includes(req.body.status)) throw bad('Invalid status');
  await q(`UPDATE orders SET status=$1 WHERE id=$2 AND status NOT IN ('Awaiting payment','Cancelled')`, [req.body.status, +req.params.id]);
  res.json({ ok: true });
}));
app.patch('/api/admin/orders/:id/payment', admin, wrap(async (req, res) => {
  await q(`UPDATE orders SET pay_status='Verified' WHERE id=$1`, [+req.params.id]);
  res.json({ ok: true });
}));
app.patch('/api/admin/bookings/:id', admin, wrap(async (req, res) => {
  if (!['New', 'Contacted', 'Booked', 'Declined'].includes(req.body.status)) throw bad('Invalid status');
  await q('UPDATE bookings SET status=$1 WHERE id=$2', [req.body.status, +req.params.id]);
  res.json({ ok: true });
}));

function prodFields(b) {
  const o = {};
  if (b.name !== undefined) { o.name = String(b.name).trim().slice(0, 120); if (!o.name) throw bad('Name is required'); }
  if (b.category !== undefined) { if (!CATS.includes(b.category)) throw bad('Choose a valid category'); o.category = b.category; }
  if (b.price !== undefined) { o.price = Math.round(+b.price); if (!(o.price >= 0)) throw bad('Enter a valid price'); }
  if (b.stock !== undefined) { o.stock = Math.round(+b.stock); if (!(o.stock >= 0)) throw bad('Enter a valid quantity'); }
  return o;
}
app.post('/api/admin/products', admin, up.single('image'), wrap(async (req, res) => {
  const o = prodFields(req.body);
  if (!o.name || !o.category || o.price === undefined) throw bad('Add a name, category and price');
  if (req.file) checkFile(req.file, ['image']);
  const id = await tx(async c => {
    const img = req.file ? await saveFile(c, req.file) : null;
    return (await c.query('INSERT INTO products(name,category,price,stock,image) VALUES($1,$2,$3,$4,$5) RETURNING id', [o.name, o.category, o.price, o.stock || 0, img])).rows[0].id;
  });
  res.json({ id });
}));
app.patch('/api/admin/products/:id', admin, up.single('image'), wrap(async (req, res) => {
  const id = +req.params.id, o = prodFields(req.body);
  const old = (await q('SELECT image FROM products WHERE id=$1', [id])).rows[0];
  if (!old) throw bad('Product not found', 404);
  let dropOld = null;
  if (req.file) { checkFile(req.file, ['image']); o.image = await tx(c => saveFile(c, req.file)); dropOld = old.image; }
  const keys = Object.keys(o);
  if (keys.length) await q(`UPDATE products SET ${keys.map((k, i) => k + '=$' + (i + 1)).join(',')} WHERE id=$${keys.length + 1}`, [...keys.map(k => o[k]), id]);
  await dropFile(dropOld);
  res.json({ ok: true });
}));
app.delete('/api/admin/products/:id', admin, wrap(async (req, res) => {
  const r = await q('DELETE FROM products WHERE id=$1 RETURNING image', [+req.params.id]);
  if (r.rowCount) await dropFile(r.rows[0].image);
  res.json({ ok: true });
}));

app.post('/api/admin/upload', admin, up.single('file'), wrap(async (req, res) => {
  if (!req.file) throw bad('Choose a file');
  const type = checkFile(req.file, ['image', 'video']);
  const id = await tx(c => saveFile(c, req.file));
  res.json({ id, type, url: '/api/files/' + id });
}));
app.put('/api/admin/banner', admin, wrap(async (req, res) => {
  const slots = (Array.isArray(req.body.slots) ? req.body.slots : []).slice(0, 6)
    .filter(s => s && UUID.test(String(s.file)) && ['image', 'video'].includes(s.type))
    .map(s => ({ type: s.type, file: s.file, name: String(s.name || '').slice(0, 120) }));
  await setS('banner', { live: !!req.body.live && slots.length > 0, slots });
  res.json({ ok: true });
}));
app.put('/api/admin/discount', admin, wrap(async (req, res) => {
  const pct = Math.round(+req.body.pct);
  if (!(pct >= 1 && pct <= 90)) throw bad('Enter a percentage from 1 to 90');
  await setS('discount', { pct, live: !!req.body.live });
  res.json({ ok: true });
}));
app.put('/api/admin/settings', admin, wrap(async (req, res) => {
  const b = req.body, s = await getS(), str = (v, n = 200) => String(v || '').trim().slice(0, n);
  if (b.fee !== undefined) { const f = Math.round(+b.fee); if (!(f >= 0)) throw bad('Enter a valid delivery fee'); await setS('delivery_fee', f); }
  if (b.account) await setS('account', { bank: str(b.account.bank), name: str(b.account.name), no: str(b.account.no, 40) });
  if (b.contact) {
    const c = { call: str(b.contact.call, 30), wa: str(b.contact.wa, 30), email: str(b.contact.email, 120) };
    if (c.email && !emailOk(c.email)) throw bad('Enter a valid email address');
    await setS('contact', c);
  }
  if (b.social) {
    const so = { ...s.social };
    for (const k of ['tiktok', 'instagram']) if (b.social[k]) {
      const url = str(b.social[k].url, 300), live = !!b.social[k].live;
      if (live && !/^https?:\/\/\S+$/.test(url)) throw bad('Enter a full link starting with https://');
      so[k] = { url, live };
    }
    await setS('social', so);
  }
  res.json({ ok: true });
}));

app.use((e, _req, res, _next) => {
  const msg = e.code === 'LIMIT_FILE_SIZE' ? 'File is too large (max 20 MB)' : e.status ? e.message : 'Request error';
  res.status(e.status || 400).json({ error: msg });
});

init().then(() => app.listen(E.PORT || 3000, () => console.log('Bee Sweet API running'))).catch(e => { console.error('Startup failed:', e); process.exit(1); });
