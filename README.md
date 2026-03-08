# NSS ENGINE - Network Security Suite

NSS ENGINE, FortiGate firewall konfigürasyon dosyalarını derinlemesine analiz eden, güvenlik açıklarını tespit eden ve ağ envanterini yöneten profesyonel bir denetim platformudur.

![NSS Engine Dashboard](https://img.shields.io/badge/Security-Audit-blue)
![React](https://img.shields.io/badge/Frontend-React-61dafb)
![Node.js](https://img.shields.io/badge/Backend-Node.js-339933)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791)

## 🚀 Öne Çıkan Özellikler

*   **Derin Konfigürasyon Analizi:** 158+ kriterde STIG, CIS Benchmark ve Best Practices uyumluluk denetimi.
*   **Gölge Kural (Shadow Analizi):** Üst kurallar tarafından engellenen veya geçersiz kılınan pasif kuralların tespiti.
*   **Geniş Erişim Analizi:** "ALL" veya "ANY" nesneleri içeren, saldırı yüzeyini genişleten riskli kuralların görselleştirilmesi.
*   **IP ve DHCP Envanteri:** 
    *   Kullanılan, boşta ve şüpheli IP adreslerinin takibi.
    *   DHCP havuzlarının otomatik tespiti ve VLAN bazlı eşleştirme.
    *   Range içi "gölge IP" tespiti ve tooltip uyarıları.
*   **Arayüz Etkileşim Grafiği:** Arayüzler arasındaki trafik yoğunluğunu gösteren profesyonel görselleştirme.
*   **Güvenlik Profil Tespiti:** Kurallar üzerindeki IPS, AV, Web Filter ve SSL Inspection eksikliklerinin renkli kodlanmış raporu.
*   **Cihaz Yönetimi:** FortiGate cihazlarını API üzerinden bağlama, veritabanına kayıt ve merkezi yönetim.
*   **PDF Raporlama:** Tüm analiz sonuçlarını kurumsal formatta dışa aktarma.

## 🛠 Teknik Mimari

### Frontend (nss-frontend)
- **React (v18):** Modern bileşen yapısı ve state yönetimi.
- **Lucide-React:** Profesyonel ikon seti.
- **Axios:** Backend API iletişimi.
- **CSS3:** Özel tasarlanmış dashboard ve animasyonlar.

### Backend (nss-backend)
- **Node.js & Express:** Hızlı ve ölçeklenebilir API katmanı.
- **FortiGate Parser Engine:** Konfigürasyon satırlarını nesneye dönüştüren ve güvenlik algoritmalarını koşturan özel motor.
- **PostgreSQL:** Analiz sonuçlarının ve cihaz bilgilerinin kalıcı olarak saklanması.
- **Multer:** Güvenli dosya yükleme yönetimi.

## 📦 Kurulum ve Çalıştırma

### Docker ile (Önerilen)
Proje kök dizininde aşağıdaki komutu çalıştırarak tüm sistemi (DB, Backend, Frontend) ayağa kaldırabilirsiniz:
```bash
docker-compose up -d
```

### Manuel Kurulum
1.  **Veritabanı:** PostgreSQL kurulumunu yapın ve `db/init.sql` dosyasını içe aktarın.
2.  **Backend:**
    ```bash
    cd network-security-suite/backend
    npm install
    # .env dosyasını düzenleyin
    node app.js
    ```
3.  **Frontend:**
    ```bash
    cd network-security-suite/frontend
    npm install
    npm start
    ```

## 📁 Proje Yapısı

```text
C:\nss\network-security-suite\
├── backend\
│   ├── app.js                # API Entry Point & Express Server
│   ├── fortigate-parser.js   # Analiz & Parsing Motoru (Core)
│   ├── data\                 # Güvenlik Bilgi Tabanı (KB)
│   └── scripts\              # Veri üretim betikleri
├── db\
│   ├── init.sql              # Veritabanı şeması (Policies, Devices, etc.)
│   └── Dockerfile            # DB Container ayarı
└── frontend\
    ├── src\
    │   ├── App.js            # Ana React Uygulaması (Dashboard & Raporlar)
    │   └── App.css           # Modern Görsel Temalar
    └── public\               # Statik dosyalar
```

## 🛡 Güvenlik Denetimi Kapsamı
Sistem, yüklenen konfigürasyonu aşağıdaki başlıklarda tarar:
- **Global Ayarlar:** Parola politikaları, banner ayarları, servis erişimleri.
- **Ağ Ayarları:** Güvensiz protokoller (HTTP, Telnet), SNMP güvenliği.
- **Politika Analizi:** Kural çakışmaları, loglama eksikleri, kapsam zafiyetleri.
- **Profil Analizi:** UTM servislerinin doğru yapılandırılması.

## 📝 Lisans
Bu proje özel mülkiyet altındadır ve sadece yetkili güvenlik denetimleri için geliştirilmiştir.

---
*Developed by Gemini CLI Agent for Professional Network Security Audits.*
