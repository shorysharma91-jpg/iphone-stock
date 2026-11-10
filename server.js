const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const PW = process.env.ADMIN_PASSWORD, DB = process.env.DATABASE_URL;
if (!PW || !DB) { console.error('Set ADMIN_PASSWORD and DATABASE_URL'); process.exit(1); }
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('s:' + PW).digest('hex');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
const pool = new Pool({ connectionString: DB, ssl: { rejectUnauthorized: false } });
pool.query('create table if not exists phones(id text primary key, data jsonb not null, created timestamptz default now())')
  .catch(e => console.error('DB init failed', e.message));

const PRIVATE = ['cost', 'imei', 'from', 'bought', 'priv'];
const TEXT = ['model', 'storage', 'color', 'cond', 'status', 'first', 'war', 'body', 'repair', 'inc', 'notes', 'imei', 'from', 'bought', 'priv'];
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const sign = exp => exp + '.' + crypto.createHmac('sha256', SECRET).update(String(exp)).digest('hex');
function authed(req) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const exp = Number(t.split('.')[0]);
  if (!exp || exp < Date.now()) return false;
  const a = Buffer.from(t), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const need = (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'Not logged in' });
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
function clean(b) {
  const o = {};
  TEXT.forEach(k => o[k] = String(b[k] == null ? '' : b[k]).slice(0, 400));
  o.cost = Math.max(0, Number(b.cost) || 0);
  o.sell = Math.max(0, Number(b.sell) || 0);
  o.bat = Math.min(100, Math.max(0, parseInt(b.bat, 10) || 0));
  return o;
}
const row = r => Object.assign({ id: r.id }, r.data);

const tries = {};
app.post('/api/login', (req, res) => {
  const ip = req.ip, now = Date.now(), t = tries[ip] || { n: 0, s: now };
  if (now - t.s > 15 * 60e3) { t.n = 0; t.s = now; }
  if (t.n >= 8) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  if (!crypto.timingSafeEqual(sha(req.body.password || ''), sha(PW))) {
    t.n++; tries[ip] = t;
    return res.status(401).json({ error: 'Wrong password' });
  }
  delete tries[ip];
  res.json({ token: sign(now + 12 * 3600e3) });
});

app.get('/api/phones', wrap(async (req, res) => {
  const r = await pool.query('select id, data from phones order by created desc');
  res.json(r.rows.map(x => { const o = row(x); PRIVATE.forEach(k => delete o[k]); return o; }));
}));
app.get('/api/admin/phones', need, wrap(async (req, res) => {
  const r = await pool.query('select id, data from phones order by created desc');
  res.json(r.rows.map(row));
}));
app.post('/api/admin/phones', need, wrap(async (req, res) => {
  const id = crypto.randomBytes(6).toString('hex');
  await pool.query('insert into phones(id, data) values($1, $2)', [id, clean(req.body)]);
  res.json({ id });
}));
app.put('/api/admin/phones/:id', need, wrap(async (req, res) => {
  await pool.query('update phones set data = $2 where id = $1', [req.params.id, clean(req.body)]);
  res.json({ ok: true });
}));
app.delete('/api/admin/phones/:id', need, wrap(async (req, res) => {
  await pool.query('delete from phones where id = $1', [req.params.id]);
  res.json({ ok: true });
}));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(process.env.PORT || 3000, () => console.log('Running'));
