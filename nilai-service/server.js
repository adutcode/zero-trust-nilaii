require('dotenv').config();
const express = require('express');
const db = require('../database.js');
const { verifyGatewayAndToken } = require('../shared/service-auth.js');

const app = express();
app.use(express.json());
app.use(verifyGatewayAndToken);

const withinHours = () => {
  const now = new Date();
  const minutes = now.getHours() * 60 + now.getMinutes();
  const [startH, startM] = (process.env.ACCESS_START || '07:00').split(':').map(Number);
  const [endH, endM] = (process.env.ACCESS_END || '21:00').split(':').map(Number);
  return minutes >= startH * 60 + startM && minutes <= endH * 60 + endM;
};

app.get('/nilai', (req, res) => {
  const { sub, role } = req.auth;
  let rows;
  if (role === 'mahasiswa') {
    rows = db.prepare(`SELECT g.id,g.class_id,c.kode,c.nama AS mata_kuliah,g.nilai,g.finalized
      FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.mahasiswa_id=?`).all(sub);
  } else if (role === 'dosen') {
    rows = db.prepare(`SELECT g.id,g.class_id,c.kode,c.nama AS mata_kuliah,u.nim,u.nama AS mahasiswa,g.nilai,g.finalized
      FROM grades g JOIN classes c ON c.id=g.class_id JOIN users u ON u.id=g.mahasiswa_id WHERE c.dosen_id=?`).all(sub);
  } else return res.status(403).json({ error: 'Role tidak dapat melihat nilai' });
  res.json(rows);
});

app.put('/nilai/:id', (req, res) => {
  if (req.auth.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });
  if (!withinHours()) return res.status(403).json({ error: 'Di luar jam akses perubahan nilai' });
  const grade = db.prepare(`SELECT g.finalized,c.dosen_id FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(req.params.id);
  if (!grade || grade.dosen_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Nilai bukan milik dosen ini' });
  if (grade.finalized) return res.status(409).json({ error: 'Nilai sudah final' });
  if (typeof req.body?.nilai !== 'number') return res.status(400).json({ error: 'nilai harus berupa angka' });
  db.prepare('UPDATE grades SET nilai=? WHERE id=?').run(req.body.nilai, req.params.id);
  res.json(db.prepare(`SELECT g.*,c.kode,c.nama AS mata_kuliah FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(req.params.id));
});

app.post('/kelas/:id/finalisasi', async (req, res) => {
  if (req.auth.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });
  if (!withinHours()) return res.status(403).json({ error: 'Di luar jam akses finalisasi' });
  const classId = Number(req.params.id);
  const kelas = db.prepare('SELECT * FROM classes WHERE id=?').get(classId);
  if (!kelas || kelas.dosen_id !== Number(req.auth.sub)) return res.status(403).json({ error: 'Kelas bukan milik dosen ini' });
  db.prepare('UPDATE grades SET finalized=1 WHERE class_id=? AND finalized=0').run(classId);
  try {
    const gateway = process.env.GATEWAY_URL || 'http://127.0.0.1:3000';
    const auth = await fetch(`${gateway}/auth/service`, { method: 'POST', headers: { 'content-type':'application/json' }, body: JSON.stringify({ clientId:'nilai-service', clientSecret:process.env.SERVICE_CLIENT_SECRET || 'service-secret' }) });
    const authBody = await auth.json();
    if (!auth.ok) return res.status(502).json({ error: 'Gagal memperoleh token service', detail:authBody });
    const sync = await fetch(`${gateway}/transkrip/sinkron`, { method:'POST', headers:{ 'content-type':'application/json','authorization':`Bearer ${authBody.serviceToken}`,'x-device-id':'INTERNAL-SERVICE' }, body:JSON.stringify({ classId }) });
    const result = await sync.json();
    if (!sync.ok) return res.status(502).json({ error:'Sinkron transkrip gagal', detail:result });
    res.json({ message:'Nilai berhasil difinalisasi dan disinkronkan', sync:result });
  } catch (error) {
    res.status(502).json({ error:'Sinkron transkrip tidak dapat dijangkau', detail:error.message });
  }
});

const port = Number(process.env.NILAI_PORT || 3001);
app.listen(port, () => console.log(`Service Nilai listening on http://localhost:${port}`));
