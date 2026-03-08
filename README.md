# Network Security Suite (NSS ENGINE)

FortiGate konfigürasyon analizi, CVE takibi ve cihaz izleme islevlerini tek panelde birlestiren Docker tabanli bir guvenlik denetim platformu.

## Ne Yapar?
- FortiGate config dosyalarini parse eder ve guvenlik bulgularini raporlar.
- Shadow rule, genis erisim, profil eksigi, IP/DHCP gibi analizleri cikarir.
- CVE verilerini birden fazla kaynaktan cekip veritabaninda saklar (offline goruntuleme).
- FortiGate API ve SNMP uzerinden cihazlari izler, metrik ve hit count toplar.
- PDF/rapor gorunumu ile bulgulari sunar.

## Mimari
- Frontend: React (`frontend`)
- Backend: Node.js + Express (`backend`)
- DB: PostgreSQL (`db`)
- Orkestrasyon: Docker Compose

Servisler:
- `nss-frontend` -> `http://localhost:3001`
- `nss-backend` -> `http://localhost:5001` (API root: `/api`)
- `nss-postgres` -> `localhost:5433`

## Ozellikler

### 1) Konfigurasyon Analizi
- Dosya yukleme (`/api/upload-config`) ve parse (`/api/parse-config`)
- Ozet, detay, interface etkilesimi, IP analizi, shadow analizi
- Guvenlik KB tabanli kural denetimi

### 2) CVE Takibi
- Kaynak bazli CVE toplama (FortiGuard, NVD, CISA KEV, ZDI, generic RSS/JSON)
- Kaynak ekle/sil/guncelle/aktif-pasif
- Senkron periyodu ayari (5-1440 dk)
- CVE aciklamasi + cozum bilgisi saklama

### 3) Cihaz Yonetimi
- API tabanli FortiGate cihaz ekleme/izleme
- SNMP template yonetimi (v2c/v3)
- SNMP canli takip (sysName, online/offline)
- Hit count gecmisi ve performans metrikleri

### 4) Ayarlar
- LDAP ayarlari
- Sertifika ayarlari
- Security KB yonetimi
- CVE DB kaynak yonetimi

## Hizli Baslangic (Docker)

```bash
cd network-security-suite
docker compose up -d --build
```

Durum kontrolu:
```bash
docker compose ps
docker logs -f nss-backend
docker logs -f nss-frontend
```

Durdurma:
```bash
docker compose down
```

## Gelistirme

Backend:
```bash
cd backend
npm install
npm run dev
```

Frontend:
```bash
cd frontend
npm install
npm start
```

## API Ozeti
Base URL: `http://localhost:5001/api`

### Saglik
- `GET /health`

### Dosya/Analiz
- `GET /uploaded-files`
- `POST /upload-config`
- `POST /parse-config`
- `GET /analysis/:fileUid`
- `GET /config-detail/:fileUid`

### CVE
- `GET /cve`
- `GET /cve/unread-count`
- `POST /cve/mark-read`
- `POST /cve/sync`
- `GET /cve/sources`
- `POST /cve/sources`
- `PUT /cve/sources/:id`
- `DELETE /cve/sources/:id`
- `GET /cve/sync-config`
- `POST /cve/sync-config`

### Ayarlar
- `GET /settings/ldap`
- `POST /settings/ldap`
- `GET /settings/certs`
- `POST /settings/certs`
- `GET /security-kb`
- `POST /security-kb`
- `DELETE /security-kb/:id`

### Cihaz/SNMP
- `GET /snmp-templates`
- `POST /snmp-templates`
- `PUT /snmp-templates/:id`
- `DELETE /snmp-templates/:id`
- `GET /devices`
- `POST /devices`
- `PUT /devices/:id`
- `DELETE /devices/:id`
- `GET /devices/snmp-track`
- `GET /devices/monitor`
- `POST /devices/:id/scan-config`
- `POST /devices/:id/fetch-hits`
- `POST /devices/:id/collect-metrics`
- `GET /devices/:id/hit-history`
- `GET /metrics/latest`

## Veritabani Notlari
- Tablolarin bir kismi `db/init.sql` ile olusur.
- Guncel tablo/kolon migrationlari backend acilisinda (`backend/app.js`) `CREATE TABLE IF NOT EXISTS` ve `ALTER TABLE IF NOT EXISTS` ile tamamlanir.

## Onemli Konfigurasyonlar
- Frontend API adresi: `docker-compose.yml` icinde `REACT_APP_API_URL`
- Backend DB bilgisi: `docker-compose.yml` -> backend environment
- CVE scheduler periyodu: `settings` tablosunda `cve_sync_config`

## Sorun Giderme

### `ERR_EMPTY_RESPONSE` / API ulasilamiyor
```bash
docker logs --tail 200 nss-backend
docker compose restart backend frontend
```

### `Cannot find module 'net-snmp'`
```bash
docker compose exec backend npm install net-snmp
docker compose restart backend
```

### Port cakismasi
- 3001, 5001, 5433 portlarini kullanan baska stack/servis olmadigini kontrol edin.

## Dizin Yapisi
```text
network-security-suite/
  backend/
    app.js
    fortigate-parser.js
    data/
  frontend/
    src/App.js
    src/App.css
  db/
    init.sql
  docker-compose.yml
```

## Lisans
Repo icindeki lisans dosyasina bakin (`LICENSE`).
