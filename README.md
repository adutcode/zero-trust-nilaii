# Praktikum Zero Trust — Sistem Nilai

## Arsitektur
- API Gateway + Policy Engine: `http://localhost:3000`
- Service Nilai: `http://localhost:3001`
- Service Transkrip: `http://localhost:3002`
- SQLite bersama: `zero-trust.db`

Semua request eksternal wajib melalui gateway. Service menolak request yang tidak memiliki `X-Gateway-Secret` yang benar maupun token JWT yang valid.

## Menjalankan
```powershell
Copy-Item .env.example .env
npm install
npm run db:seed
npm run start:all
```

Gunakan Node.js 18 atau lebih baru.

## Akun seed
Semua password: `password123`.

| Username | Role | Device ID | NIM |
|---|---|---|---|
| admin1 | admin | DEVICE-ADMIN-01 | - |
| dosen1 | dosen | DEVICE-DOSEN-01 | - |
| dosen2 | dosen | DEVICE-DOSEN-02 | - |
| mhs1 | mahasiswa | DEVICE-MHS-01 | 237001001 |
| mhs2 | mahasiswa | DEVICE-MHS-02 | 237001002 |
| mhs3 | mahasiswa | DEVICE-MHS-03 | 237001003 |

Terdapat dua kelas: `IF401` milik dosen1 dan `IF402` milik dosen2. Semua mahasiswa terdaftar pada kedua kelas.

Service client ID: `nilai-service`; service secret: `service-secret` (atau nilai `SERVICE_CLIENT_SECRET` pada `.env`).

## Contoh alur
Login mahasiswa:
```powershell
curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"username":"mhs1","password":"password123","deviceId":"DEVICE-MHS-01"}'
```

Ambil nilai dan transkrip (ganti `<TOKEN>` dan pakai device milik akun):
```powershell
curl http://localhost:3000/nilai -H "Authorization: Bearer <TOKEN>" -H "X-Device-ID: DEVICE-MHS-01"
curl http://localhost:3000/transkrip/237001001 -H "Authorization: Bearer <TOKEN>" -H "X-Device-ID: DEVICE-MHS-01"
```

Login dosen, ubah nilai, lalu finalisasi:
```powershell
curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"username":"dosen1","password":"password123","deviceId":"DEVICE-DOSEN-01"}'
curl -X PUT http://localhost:3000/nilai/1 -H "Authorization: Bearer <TOKEN>" -H "X-Device-ID: DEVICE-DOSEN-01" -H "Content-Type: application/json" -d '{"nilai":88}'
curl -X POST http://localhost:3000/kelas/1/finalisasi -H "Authorization: Bearer <TOKEN>" -H "X-Device-ID: DEVICE-DOSEN-01"
```

Refresh dan logout:
```powershell
curl -X POST http://localhost:3000/auth/refresh -H "Content-Type: application/json" -d '{"refreshToken":"<REFRESH>"}'
curl -X POST http://localhost:3000/auth/logout -H "Content-Type: application/json" -d '{"refreshToken":"<REFRESH>"}'
```

Jam akses dapat diubah melalui `ACCESS_START` dan `ACCESS_END` pada `.env`. Keputusan gateway tercatat pada tabel `audit_logs`.
