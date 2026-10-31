require('dotenv').config();
const express = require('express');
const db = require('../database.js');
const { verifyGatewayAndToken } = require('../shared/service-auth.js');

const app = express();
app.use(express.json());
app.use(verifyGatewayAndToken);

app.get('/transkrip/:nim', (req, res) => {
  const nim = req.params.nim;
  if (req.auth.role === 'mahasiswa' && req.auth.sub) {
    const own = db.prepare('SELECT nim FROM users WHERE id=?').get(req.auth.sub);
    if (!own || own.nim !== nim) return res.status(403).json({ error:'Hanya transkrip milik sendiri' });
  } else if (req.auth.role !== 'admin') {
    return res.status(403).json({ error:'Role tidak dapat melihat transkrip' });
  }
  const transcript = db.prepare('SELECT * FROM transcripts WHERE nim=?').get(nim);
  res.json({ nim, entries: transcript ? JSON.parse(transcript.entries) : [] });
});

app.post('/transkrip/sinkron', (req, res) => {
  if (req.auth.role !== 'service') return res.status(403).json({ error:'Endpoint hanya untuk token service' });
  const classId = Number(req.body?.classId);
  const kelas = db.prepare('SELECT * FROM classes WHERE id=?').get(classId);
  if (!kelas) return res.status(404).json({ error:'Kelas tidak ditemukan' });
  const students = db.prepare(`SELECT u.nim,u.nama,g.nilai,g.finalized,c.kode,c.nama AS mata_kuliah
    FROM users u JOIN grades g ON g.mahasiswa_id=u.id JOIN classes c ON c.id=g.class_id
    WHERE g.class_id=? AND g.finalized=1`).all(classId);
  const save = db.transaction(() => {
    for (const student of students) {
      const existing = db.prepare('SELECT entries FROM transcripts WHERE nim=?').get(student.nim);
      let entries = existing ? JSON.parse(existing.entries) : [];
      entries = entries.filter(entry => entry.kode !== student.kode);
      entries.push({ kode: student.kode, mata_kuliah: student.mata_kuliah, nilai: student.nilai });
      db.prepare('INSERT OR REPLACE INTO transcripts(nim,entries) VALUES (?,?)').run(student.nim, JSON.stringify(entries));
    }
  });
  save();
  res.json({ message:'Transkrip tersinkron', classId, jumlah_mahasiswa:students.length });
});

const port = Number(process.env.TRANSKRIP_PORT || 3002);
app.listen(port, () => console.log(`Service Transkrip listening on http://localhost:${port}`));
