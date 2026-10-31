require('dotenv').config();
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbFile = process.env.DB_FILE || path.join(__dirname, 'zero-trust.db');
const db = new Database(dbFile);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','dosen','mahasiswa','service')),
  nama TEXT NOT NULL,
  nim TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL UNIQUE,
  UNIQUE(user_id, device_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kode TEXT UNIQUE NOT NULL,
  nama TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS enrollments (
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(class_id, mahasiswa_id)
);
CREATE TABLE IF NOT EXISTS grades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id INTEGER NOT NULL REFERENCES classes(id),
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  nilai REAL,
  finalized INTEGER NOT NULL DEFAULT 0,
  UNIQUE(class_id, mahasiswa_id)
);
CREATE TABLE IF NOT EXISTS transcripts (
  nim TEXT PRIMARY KEY,
  entries TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  waktu TEXT NOT NULL,
  subject TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device TEXT,
  result TEXT NOT NULL,
  reason TEXT NOT NULL
);
`);

// Schema tolerates an existing database created by an earlier run.
const run = db.transaction(() => {
  const password = bcrypt.hashSync('password123', 10);
  const insertUser = db.prepare(`INSERT OR IGNORE INTO users(username,password_hash,role,nama,nim) VALUES(?,?,?,?,?)`);
  insertUser.run('admin1', password, 'admin', 'Admin Informatika', null);
  insertUser.run('dosen1', password, 'dosen', 'Dosen Arif', null);
  insertUser.run('dosen2', password, 'dosen', 'Dosen Siti', null);
  insertUser.run('mhs1', password, 'mahasiswa', 'Mahasiswa Budi', '237001001');
  insertUser.run('mhs2', password, 'mahasiswa', 'Mahasiswa Citra', '237001002');
  insertUser.run('mhs3', password, 'mahasiswa', 'Mahasiswa Dedi', '237001003');

  const users = Object.fromEntries(db.prepare('SELECT username,id FROM users').all().map(u => [u.username, u.id]));
  const insertDevice = db.prepare('INSERT OR IGNORE INTO devices(user_id,device_id) VALUES (?,?)');
  [['admin1','DEVICE-ADMIN-01'],['dosen1','DEVICE-DOSEN-01'],['dosen2','DEVICE-DOSEN-02'],['mhs1','DEVICE-MHS-01'],['mhs2','DEVICE-MHS-02'],['mhs3','DEVICE-MHS-03']]
    .forEach(([username, device]) => insertDevice.run(users[username], device));

  db.prepare('INSERT OR IGNORE INTO classes(id,kode,nama,dosen_id) VALUES (?,?,?,?)').run(1,'IF401','Keamanan Informasi',users.dosen1);
  db.prepare('INSERT OR IGNORE INTO classes(id,kode,nama,dosen_id) VALUES (?,?,?,?)').run(2,'IF402','Kriptografi',users.dosen2);
  const enroll = db.prepare('INSERT OR IGNORE INTO enrollments(class_id,mahasiswa_id) VALUES (?,?)');
  for (const m of ['mhs1','mhs2','mhs3']) {
    enroll.run(1, users[m]);
    enroll.run(2, users[m]);
  }
  const grade = db.prepare('INSERT OR IGNORE INTO grades(class_id,mahasiswa_id,nilai,finalized) VALUES (?,?,?,?)');
  grade.run(1,users.mhs1,85,0); grade.run(1,users.mhs2,78,0); grade.run(1,users.mhs3,90,0);
  grade.run(2,users.mhs1,88,0); grade.run(2,users.mhs2,82,0); grade.run(2,users.mhs3,87,0);
  db.prepare('INSERT OR REPLACE INTO service_clients(client_id,client_secret_hash) VALUES (?,?)')
    .run('nilai-service', bcrypt.hashSync(process.env.SERVICE_CLIENT_SECRET || 'service-secret', 10));
});
run();

module.exports = db;
if (require.main === module) {
  console.log(`Database seeded: ${dbFile}`);
  db.close();
}
