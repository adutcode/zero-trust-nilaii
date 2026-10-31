require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const http = require('http');
const db = require('../database.js');
const policy = require('./policy.js');

const app = express();
app.use(express.json());
const ACCESS_SECRET = policy.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'praktikum-refresh-secret';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'praktikum-gateway-secret';
const PORT = Number(process.env.GATEWAY_PORT || 3000);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

function tokenPair(user) {
  const access = jwt.sign({ role: user.role, nama: user.nama }, ACCESS_SECRET, { subject: String(user.id), expiresIn: '10m' });
  const refresh = jwt.sign({ role: user.role }, REFRESH_SECRET, { subject: String(user.id), expiresIn: '1d' });
  const payload = jwt.verify(refresh, REFRESH_SECRET);
  db.prepare('INSERT INTO refresh_tokens(user_id,token_hash,expires_at) VALUES(?,?,?)')
    .run(user.id, hash(refresh), payload.exp);
  return { accessToken: access, refreshToken: refresh, expiresIn: 600 };
}

app.post('/auth/login', (req, res) => {
  const { username, password, deviceId } = req.body || {};
  const user = username ? db.prepare('SELECT * FROM users WHERE username=?').get(username) : null;
  
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    audit(req, { allowed: false, reason: 'Kredensial tidak valid' });
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }
  
  if (!deviceId || !db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(user.id, deviceId)) {
    audit(req, { allowed: false, reason: 'Device tidak terdaftar untuk pengguna ini' });
    return res.status(403).json({ error: 'Device tidak terdaftar untuk pengguna ini' });
  }
  
  audit(req, { allowed: true, reason: 'Login berhasil' });
  res.json(tokenPair(user));
});

app.post('/auth/refresh', (req, res) => {
  const refreshToken = req.body?.refreshToken;
  if (!refreshToken) {
    audit(req, { allowed: false, reason: 'refreshToken wajib disertakan' });
    return res.status(400).json({ error: 'refreshToken wajib disertakan' });
  }
  
  try {
    const payload = jwt.verify(refreshToken, REFRESH_SECRET);
    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash=? AND revoked=0 AND expires_at>?')
      .get(hash(refreshToken), Math.floor(Date.now() / 1000));
      
    if (!row) {
      audit(req, { allowed: false, reason: 'Refresh token dicabut atau tidak valid' });
      return res.status(401).json({ error: 'Refresh token dicabut atau tidak valid' });
    }
    
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
    if (!user) {
      audit(req, { allowed: false, reason: 'User tidak ditemukan' });
      return res.status(401).json({ error: 'User tidak ditemukan' });
    }
    
    audit(req, { allowed: true, reason: 'Refresh token berhasil diterbitkan' });
    res.json(tokenPair(user));
  } catch (_) {
    audit(req, { allowed: false, reason: 'Refresh token tidak valid atau kedaluwarsa' });
    res.status(401).json({ error: 'Refresh token tidak valid atau kedaluwarsa' });
  }
});

app.post('/auth/logout', (req, res) => {
  const refreshToken = req.body?.refreshToken;
  if (!refreshToken) {
    audit(req, { allowed: false, reason: 'refreshToken wajib disertakan' });
    return res.status(400).json({ error: 'refreshToken wajib disertakan' });
  }
  
  db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?').run(hash(refreshToken));
  audit(req, { allowed: true, reason: 'Logout berhasil, refresh token dicabut' });
  res.json({ message: 'Logout berhasil, refresh token dicabut' });
});

app.post('/auth/service', (req, res) => {
  const { clientId, clientSecret } = req.body || {};
  const client = clientId ? db.prepare('SELECT * FROM service_clients WHERE client_id=?').get(clientId) : null;
  
  if (!client || !clientSecret || !bcrypt.compareSync(clientSecret, client.client_secret_hash)) {
    audit(req, { allowed: false, reason: 'Kredensial service tidak valid' });
    return res.status(401).json({ error: 'Kredensial service tidak valid' });
  }
  
  const token = jwt.sign({ service: clientId, role: 'service' }, ACCESS_SECRET, { expiresIn: '5m' });
  audit(req, { allowed: true, reason: 'Token service diterbitkan' });
  res.json({ serviceToken: token, expiresIn: 300 });
});

function audit(req, decision) {
  let subject = 'anonymous';
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try { subject = token ? jwt.decode(token)?.sub || jwt.decode(token)?.service || subject : subject; } catch (_) {}
  db.prepare('INSERT INTO audit_logs(waktu,subject,endpoint,device,result,reason) VALUES(?,?,?,?,?,?)')
    .run(new Date().toISOString(), subject, `${req.method} ${req.originalUrl}`, req.headers['x-device-id'] || null,
      decision.allowed ? 'allow' : 'deny', decision.reason);
}

function enforcePolicy(req, res, next) {
  const decision = policy.decide(req);
  audit(req, decision);
  if (!decision.allowed) return res.status(decision.status || 403).json({ error: decision.reason });
  next();
}

const upstream = {
  '/nilai': { target: process.env.NILAI_SERVICE_URL || 'http://127.0.0.1:3001', changeOrigin: true },
  '/kelas': { target: process.env.NILAI_SERVICE_URL || 'http://127.0.0.1:3001', changeOrigin: true },
  '/transkrip': { target: process.env.TRANSKRIP_SERVICE_URL || 'http://127.0.0.1:3002', changeOrigin: true }
};

function proxyTo(req, res, target, options = {}) {
  const url = new URL(req.originalUrl, 'http://gateway.local');
  const destination = new URL(target);
  const headers = { ...req.headers, host: destination.host, 'x-gateway-secret': GATEWAY_SECRET };
  delete headers.connection;
  const body = req.body && Object.keys(req.body).length ? Buffer.from(JSON.stringify(req.body)) : null;
  if (body) headers['content-length'] = body.length;
  const proxyRequest = http.request({
    hostname: destination.hostname,
    port: destination.port,
    method: req.method,
    path: url.pathname + url.search,
    headers
  }, proxyResponse => {
    res.status(proxyResponse.statusCode || 502);
    for (const [name, value] of Object.entries(proxyResponse.headers)) {
      if (value !== undefined) res.setHeader(name, value);
    }
    proxyResponse.pipe(res);
  });
  proxyRequest.on('error', () => res.status(502).json({ error: 'Service tidak dapat dijangkau' }));
  if (body) proxyRequest.write(body);
  proxyRequest.end();
}

for (const [prefix, options] of Object.entries(upstream)) {
  app.use((req, res, next) => {
    if (!req.path.startsWith(prefix)) return next();
    return enforcePolicy(req, res, () => proxyTo(req, res, options.target));
  });
}

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(502).json({ error: 'Service tidak dapat dijangkau' });
});

app.listen(PORT, () => console.log(`API Gateway listening on http://localhost:${PORT}`));