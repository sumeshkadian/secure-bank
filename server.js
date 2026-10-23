// SecureBank: Express API + OTP auth + rule-based fraud engine + live alerts (SSE)
// Data is in-memory for the demo; swap the arrays for MongoDB/PostgreSQL in production.
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
app.use(express.json());
app.use(express.static('public'));

const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const id = () => crypto.randomUUID();
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const check = (pw, h) => crypto.timingSafeEqual(Buffer.from(hash(pw, h.split(':')[0])), Buffer.from(h));

const users = [], txns = [], alerts = [], otps = new Map(), clients = new Set();
const pub = ({ pw, ...u }) => u;
const newUser = (name, email, pw, role = 'user') => {
  const u = { id: id(), name, email: email.toLowerCase(), pw: hash(pw), role,
    balance: role === 'admin' ? 0 : 100000, account: String(crypto.randomInt(1e9, 1e10)), frozen: false };
  users.push(u); return u;
};
newUser('Admin', 'admin@bank.com', 'Admin@123', 'admin');

// ---------- auth middleware (JWT; ?token= is allowed for the SSE stream) ----------
const auth = role => (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').slice(7) || req.query.token;
    const u = users.find(x => x.id === jwt.verify(t, SECRET).id);
    if (!u || u.frozen || (role && u.role !== role)) return res.status(403).json({ error: 'Access denied' });
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please log in again' }); }
};

// ---------- fraud alerts ----------
const raise = (uid, txn, score, reasons) => {
  const a = { id: id(), uid, name: users.find(u => u.id === uid)?.name, txn, score, reasons, time: Date.now(), resolved: false };
  alerts.unshift(a);
  clients.forEach(r => r.write(`data: ${JSON.stringify(a)}\n\n`));
};

// ---------- fraud engine: each rule adds to a 0-100 risk score ----------
const assess = (u, to, amt) => {
  const mine = txns.filter(t => t.from === u.id && t.status !== 'BLOCKED');
  const recent = mine.filter(t => Date.now() - t.time < 60000).length;
  const avg = mine.length >= 3 ? mine.reduce((s, t) => s + t.amount, 0) / mine.length : 0;
  const hit = [
    [amt >= 50000, 40, 'High-value transfer'],
    [avg && amt > 3 * avg, 25, 'Amount is over 3x your usual transfer'],
    [recent >= 3, 30, 'Many transfers within one minute'],
    [amt >= 20000 && !mine.some(t => t.to === to.id), 20, 'Large amount to a new payee'],
    [new Date().getHours() < 5, 15, 'Transfer at an unusual hour'],
    [amt > u.balance * 0.9, 15, 'Drains over 90% of balance'],
  ].filter(r => r[0]);
  return { score: Math.min(100, hit.reduce((s, r) => s + r[1], 0)), reasons: hit.map(r => r[2]) };
};

// ---------- routes ----------
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 8)
    return res.status(400).json({ error: 'Enter a name, a valid email and a password of 8+ characters' });
  if (users.some(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
  newUser(name, email, password); res.json({ ok: true });
});

app.post('/api/login', (req, res) => {           // step 1: password -> OTP challenge
  const u = users.find(x => x.email === (req.body.email || '').toLowerCase());
  if (!u || u.frozen || !check(req.body.password || '', u.pw)) return res.status(401).json({ error: 'Invalid credentials' });
  const challenge = id(), otp = String(crypto.randomInt(100000, 1000000));
  otps.set(challenge, { uid: u.id, otp, exp: Date.now() + 300000, tries: 0 });
  console.log(`OTP for ${u.email}: ${otp}`);     // production: send via SMS/email provider
  res.json({ challenge, demoOtp: otp });         // production: remove demoOtp
});

app.post('/api/verify-otp', (req, res) => {      // step 2: OTP -> JWT
  const c = otps.get(req.body.challenge);
  if (!c || c.exp < Date.now()) return res.status(400).json({ error: 'OTP expired. Log in again.' });
  if (c.otp !== String(req.body.otp)) {
    if (++c.tries >= 3) { otps.delete(req.body.challenge); raise(c.uid, null, 60, ['3 wrong OTP attempts']); }
    return res.status(401).json({ error: 'Wrong OTP' });
  }
  otps.delete(req.body.challenge);
  const u = users.find(x => x.id === c.uid);
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: '30m' }), user: pub(u) });
});

app.get('/api/me', auth(), (req, res) => res.json(pub(req.user)));

app.post('/api/transfer', auth('user'), (req, res) => {
  const u = req.user, amount = Number(req.body.amount);
  const to = users.find(x => x.account === req.body.toAccount && x.role === 'user');
  if (!to || to.id === u.id) return res.status(400).json({ error: 'Recipient account not found' });
  if (!(amount > 0) || amount > u.balance) return res.status(400).json({ error: 'Invalid amount or insufficient funds' });
  const { score, reasons } = assess(u, to, amount);
  const status = score >= 70 ? 'BLOCKED' : score >= 40 ? 'FLAGGED' : 'SUCCESS';
  const t = { id: id(), from: u.id, to: to.id, fromName: u.name, toName: to.name, amount,
    note: req.body.note || '', status, risk: score, time: Date.now() };
  txns.unshift(t);
  if (status !== 'BLOCKED') { u.balance -= amount; to.balance += amount; }
  if (score >= 40) raise(u.id, t.id, score, reasons);
  res.json({ status, reasons, balance: u.balance });
});

app.get('/api/transactions', auth('user'), (req, res) =>
  res.json(txns.filter(t => t.from === req.user.id || t.to === req.user.id).map(({ risk, ...t }) => t)));

// ---------- admin ----------
app.get('/api/admin/overview', auth('admin'), (req, res) => res.json({
  users: users.filter(u => u.role === 'user').map(pub), txns, alerts,
  stats: { volume: txns.filter(t => t.status !== 'BLOCKED').reduce((s, t) => s + t.amount, 0),
    blocked: txns.filter(t => t.status === 'BLOCKED').length, open: alerts.filter(a => !a.resolved).length },
}));
app.post('/api/admin/users/:id/freeze', auth('admin'), (req, res) => {
  const u = users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  u.frozen = !u.frozen; res.json({ frozen: u.frozen });
});
app.post('/api/admin/alerts/:id/resolve', auth('admin'), (req, res) => {
  const a = alerts.find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Not found' });
  a.resolved = true; res.json({ ok: true });
});
app.get('/api/admin/stream', auth('admin'), (req, res) => {   // real-time alerts (Server-Sent Events)
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders(); clients.add(res); req.on('close', () => clients.delete(res));
});

app.listen(3000, () => console.log('SecureBank running at http://localhost:3000'));
