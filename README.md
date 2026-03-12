# Network Security Suite (NSS) 🛡️

Network Security Suite, ağ cihazlarınızın güvenlik konfigürasyonlarını analiz eden, zafiyet takibi yapan ve ağ topolojinizi otomatik olarak çıkaran kapsamlı bir açık kaynak güvenlik yönetim platformudur.

![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)

## 🚀 Temel Özellikler

### 🔍 Güvenlik Analizi & Uyumluluk
*   **FortiGate & Switch Denetimi:** Konfigürasyon dosyalarını (veya canlı API/SSH bağlantısını) parse ederek STIG, CIS ve Best Practice standartlarına göre analiz eder.
*   **Kural Tabanlı Kontrol:** Shadow rule (çakışan kurallar), aşırı geniş erişim (All/Any) ve eksik güvenlik profili (IPS, AV, WebFilter) tespiti.
*   **Özelleştirilebilir Bilgi Tabanı (KB):** Kendi güvenlik kurallarınızı tanımlayabilir ve global standartlarla karşılaştırabilirsiniz.

### 🌐 Canlı Ağ Keşfi (Discovery)
*   **Akıllı Tarama:** SNMP (v2c/v3) üzerinden ağdaki cihazları otomatik tespit eder.
*   **Derin Keşif (Deep Discovery):** LLDP, CDP ve ARP tablolarını kullanarak cihazlar arası komşuluk ilişkilerini çıkarır.
*   **Dinamik Topoloji:** Keşfedilen verilerle ağ haritanızı otomatik olarak oluşturur ve görselleştirir.

### ⚠️ Zafiyet & Risk Yönetimi
*   **Otomatik CVE Takibi:** NVD, FortiGuard, CISA KEV ve ZDI kaynaklarından anlık zafiyet akışı.
*   **SSL Sertifika Takibi:** Kritik servislerin sertifika sürelerini hem dosya hem de URL üzerinden izler, son kullanma yaklaşınca uyarı verir.
*   **Performans İzleme:** Cihazların CPU, RAM, VPN ve HA durumlarını canlı grafiklerle takip eder.

## 🛠️ Teknik Mimari

*   **Frontend:** React.js, Recharts, Lucide Icons, Axios.
*   **Backend:** Node.js, Express, net-snmp, ssh2, RSS Parser.
*   **Database:** PostgreSQL (İlişkisel veri ve JSONB log desteği).
*   **DevOps:** Docker & Docker Compose.

## 📦 Kurulum

### Gereksinimler
*   Docker ve Docker Compose

### Hızlı Başlangıç
1.  Projeyi klonlayın:
    ```bash
    git clone https://github.com/rcpdkc/network-security-suite.git
    cd network-security-suite
    ```
2.  Sistemi başlatın:
    ```bash
    docker-compose up -d --build
    ```
3.  Tarayıcınızdan erişin:
    *   **Frontend:** `http://localhost:3001`
    *   **Backend API:** `http://localhost:5001`

## 📖 Kullanım Senaryoları

1.  **Güvenlik Sertifikasyonu:** Yeni kurulan bir Firewall'un kurum standartlarına uygunluğunu saniyeler içinde denetleyin.
2.  **Envanter Çıkarma:** Bilinmeyen bir ağa bağlandığınızda SNMP taraması ve Deep Discovery ile tüm cihazları ve bağlantılarını haritalandırın.
3.  **Proaktif İzleme:** Kritik güvenlik açıklarını (CVE) dashboard üzerinden takip ederek cihazlarınızın etkilenip etkilenmediğini analiz edin.

## 🤝 Katkıda Bulunma
Katkılarınızı bekliyoruz! Lütfen bir `Pull Request` açmadan önce projenin kodlama standartlarını inceleyin.

## 📄 Lisans
Bu proje MIT Lisansı ile lisanslanmıştır.

---
Developed with ❤️ by [rcpdkc](https://github.com/rcpdkc)
