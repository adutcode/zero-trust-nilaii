const jwt = require('jsonwebtoken');
const db = require('../database.js');

const JWT_SECRET = process.env.JWT_SECRET || 'praktikum-zero-trust-secret';
const ACCESS_START = process.env.ACCESS_START || '07:00';
const ACCESS_END = process.env.ACCESS_END || '21:00';

function withinAccessHours(now = new Date()) {
  const minutes = now.getHours() * 60 + now.getMinutes();
  const toMinutes = value => {
    const [hour, minute] = value.split(':').map(Number);
    return hour * 60 + minute;
  };
  return minutes >= toMinutes(ACCESS_START) && minutes <= toMinutes(ACCESS_END);
}

function deny(reason, status = 403) {
  return { allowed: false, reason, status };
}

function verifyBearer(req) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return { error: deny('Access token required', 401) };
  try {
    return { claims: jwt.verify(token, JWT_SECRET) };
  } catch (error) {
    return { error: deny('Access token tidak valid atau kedaluwarsa', 401) };
  }
}

function verifyDevice(req, claims) {
  const deviceId = req.headers['x-device-id'];
  if (!deviceId) return deny('X-Device-ID wajib disertakan', 400);
  if (!db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(claims.sub, deviceId)) {
    return deny('Device tidak terdaftar untuk pengguna ini');
  }
  return { allowed: true };
}

function decide(req) {
  const bearer = verifyBearer(req);
  if (bearer.error) return bearer.error;
  const claims = bearer.claims;
  if (claims.role === 'service') {
    if (req.method === 'POST' && req.path === '/transkrip/sinkron') return { allowed: true, reason: 'Token service valid' };
    return deny('Token service tidak dapat mengakses endpoint ini');
  }

  const device = verifyDevice(req, claims);
  if (!device.allowed) return device;
  if (!['admin', 'dosen', 'mahasiswa'].includes(claims.role)) return deny('Role tidak dikenal');

  const path = req.path;
  if (req.method === 'GET' && path === '/nilai') {
    if (claims.role === 'mahasiswa') return { allowed: true, reason: 'Mahasiswa dapat melihat nilai miliknya' };
    if (claims.role === 'dosen') return { allowed: true, reason: 'Dosen dapat melihat nilai kelas yang diampunya' };
    return deny('Admin tidak memiliki akses endpoint nilai');
  }
  if (req.method === 'PUT' && /^\/nilai\/\d+$/.test(path)) {
    if (claims.role !== 'dosen') return deny('Hanya dosen yang dapat mengubah nilai');
    const gradeId = Number(path.split('/').pop());
    const grade = db.prepare(`SELECT g.finalized,c.dosen_id FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(gradeId);
    if (!grade || grade.dosen_id !== Number(claims.sub)) return deny('Nilai bukan milik kelas dosen ini');
    if (grade.finalized) return deny('Nilai sudah final');
    if (!withinAccessHours()) return deny(`Perubahan nilai hanya diizinkan ${ACCESS_START}-${ACCESS_END}`);
    return { allowed: true, reason: 'Dosen pemilik kelas, nilai belum final, dan jam akses valid' };
  }
  if (req.method === 'POST' && /^\/kelas\/\d+\/finalisasi$/.test(path)) {
    if (claims.role !== 'dosen') return deny('Hanya dosen yang dapat memfinalisasi nilai');
    const classId = Number(path.split('/')[2]);
    const kelas = db.prepare('SELECT dosen_id FROM classes WHERE id=?').get(classId);
    if (!kelas || kelas.dosen_id !== Number(claims.sub)) return deny('Kelas bukan milik dosen ini');
    if (!withinAccessHours()) return deny(`Finalisasi hanya diizinkan ${ACCESS_START}-${ACCESS_END}`);
    return { allowed: true, reason: 'Dosen pemilik kelas dan jam akses valid' };
  }
  if (req.method === 'GET' && /^\/transkrip\/[^/]+$/.test(path)) {
    const nim = decodeURIComponent(path.split('/').pop());
    if (claims.role === 'admin') return { allowed: true, reason: 'Admin dapat melihat seluruh transkrip' };
    if (claims.role === 'mahasiswa') {
      const user = db.prepare('SELECT nim FROM users WHERE id=?').get(claims.sub);
      if (user && user.nim === nim) return { allowed: true, reason: 'Mahasiswa hanya dapat melihat NIM miliknya' };
      return deny('Mahasiswa hanya dapat melihat transkrip miliknya');
    }
    return deny('Dosen tidak dapat melihat endpoint transkrip');
  }
  return deny('Endpoint atau metode tidak diizinkan');
}

module.exports = { decide, withinAccessHours, JWT_SECRET, ACCESS_START, ACCESS_END };
   console.log(`[policy] jam akses ${ACCESS_START}-${ACCESS_END}, sekarang ${new Date().toTimeString().slice(0, 5)}, dalam jam akses: ${withinAccessHours()}`);