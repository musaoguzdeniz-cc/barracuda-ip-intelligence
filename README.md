# Barracuda IP Intelligence

## English

A passive IP intelligence application for Windows, written in Rust. Open the dark-themed desktop interface with `BarracudaIPIntelligence.exe` or use the `ipintel.exe` command-line tool. Python is not required to run either executable.

### Features

- IPv4/IPv6 validation, private/public/bogon classification, and reverse DNS
- RDAP, RIPEstat network/ASN, and approximate ipwho.is geolocation lookups
- Optional AbuseIPDB, VirusTotal, Shodan, and GreyNoise sources
- A weighted risk score based only on evidence returned by successful sources
- JSON and flattened CSV reports
- A responsive dark desktop interface while network requests are running

The program performs passive lookups for one IP address; it does not scan devices on a network. Geolocation is approximate and does not identify a physical device address.

### Build Windows EXEs

Install a stable Rust toolchain. Windows builds can use the MSVC or GNU target; the GNU target may also require C/MinGW tools and libraries.

```powershell
git clone https://github.com/musaoguzdeniz-cc/barracuda-ip-intelligence.git
cd barracuda-ip-intelligence
cargo test --locked
cargo build --release --locked
```

The build creates `target\release\BarracudaIPIntelligence.exe` and `target\release\ipintel.exe`. Double-click the GUI executable to open the app. The `target` directory is ignored by Git.

### Usage

```powershell
.\target\release\ipintel.exe 8.8.8.8
.\target\release\ipintel.exe 1.1.1.1 --print-json --json reports\cloudflare.json --csv reports\cloudflare.csv
.\target\release\ipintel.exe 192.168.1.1 --no-keyless
.\target\release\ipintel.exe 8.8.8.8 --providers abuseipdb,virustotal
```

In the desktop app, enter an IP address, select sources, and click **ANALİZ ET** (Analyze). The left panel shows an IP profile and expandable full JSON result; the right panel shows the risk score and source evidence. If there is no provider evidence, the app displays **KANIT YOK** (No evidence). This does not mean the IP is safe. Use **↓ JSON** and **↓ CSV** to save reports.

### API keys

Copy `.env.example` next to the executable as `.env`, then enter the keys you want to use. Environment variables take precedence over `.env` values. For an existing installation, you can replace the executable in the same folder without changing `.env`. Keys are not embedded in the EXE and are ignored by Git.

```dotenv
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
```

A selected provider without a key is reported as `not_configured`. An HTTP error from one provider does not stop the other lookups. Do not put keys in source code, commits, screenshots, or bug reports. Each service has its own quotas, license, and terms of use.

### Risk calculation

| Provider | Weight |
| --- | ---: |
| AbuseIPDB | 35% |
| VirusTotal | 35% |
| Shodan | 15% |
| GreyNoise | 15% |

The score is normalized across only the providers that returned usable data. Levels are low 0–24, medium 25–49, high 50–74, and critical 75–100. If there is no evidence, confidence is `none`.

### Data and privacy

Selected sources receive the queried public IP address through rdap.org, RIPEstat, ipwho.is, or the chosen API providers. The app adds no telemetry. Review each service's privacy policy and terms of use.

The previous Python/Tkinter source remains in the repository for reference. The main Windows build and runtime use the Rust EXEs.

---

## Türkçe

Windows için Rust ile yazılmış pasif IP istihbaratı uygulaması. Koyu Konsol arayüzü `BarracudaIPIntelligence.exe` ile, komut satırı aracı `ipintel.exe` ile açılır. Python kurulumu çalışma sırasında gerekmez.

### Özellikler

- IPv4/IPv6 doğrulama, özel/genel/bogon sınıflandırması ve ters DNS
- RDAP, RIPEstat ağ/ASN ve ipwho.is yaklaşık konum sorguları
- İsteğe bağlı AbuseIPDB, VirusTotal, Shodan ve GreyNoise kaynakları
- Yalnızca başarılı kaynak kanıtlarını kullanan ağırlıklı risk puanı
- JSON ve düzleştirilmiş CSV raporları
- Ağ istekleri sürerken yanıt veren koyu masaüstü arayüzü

Program tek IP hakkında pasif bilgi sorgular; ağdaki cihazları taramaz. Konum verisi yaklaşık değerdir, fiziksel cihaz adresi değildir.

### Windows EXE derleme

Rust stable araç zinciri gereklidir. Windows'ta MSVC veya GNU hedefi kullanılabilir. GNU hedefinde C/MinGW araçları ve bağımlılıkları da gerekebilir.

```powershell
git clone https://github.com/musaoguzdeniz-cc/barracuda-ip-intelligence.git
cd barracuda-ip-intelligence
cargo test --locked
cargo build --release --locked
```

Derleme sonunda `target\release\BarracudaIPIntelligence.exe` ve `target\release\ipintel.exe` oluşur. Uygulamayı açmak için GUI EXE dosyasına çift tıklayın. `target` klasörü Git'e eklenmez.

### Kullanım

```powershell
.\target\release\ipintel.exe 8.8.8.8
.\target\release\ipintel.exe 1.1.1.1 --print-json --json reports\cloudflare.json --csv reports\cloudflare.csv
.\target\release\ipintel.exe 192.168.1.1 --no-keyless
.\target\release\ipintel.exe 8.8.8.8 --providers abuseipdb,virustotal
```

Arayüzde IP adresini girin, kullanılacak kaynakları seçin ve **ANALİZ ET** düğmesine basın. Sol panel IP profilinin özetini ve açılabilir tam JSON sonucunu, sağ panel risk puanını ve kaynakları gösterir. Sağlayıcı kanıtı yoksa **KANIT YOK** görünür; bu sonuç IP'nin temiz olduğunu göstermez. **↓ JSON** ve **↓ CSV** raporu kaydeder.

### API anahtarları

`.env.example` dosyasını EXE'nin yanına `.env` adıyla kopyalayıp kullanacağınız anahtarları girin. Ortam değişkenleri `.env` değerlerinden önce gelir. Mevcut bir kurulumda `.env` dosyasını değiştirmeden yeni EXE'yi aynı klasöre koyabilirsiniz. Anahtarlar EXE içine gömülmez ve Git tarafından yok sayılır.

```dotenv
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
```

Anahtarı olmayan seçili sağlayıcı `not_configured` olarak raporlanır. HTTP hataları diğer kaynak sorgularını durdurmaz. Anahtarları kaynak koda, commitlere, ekran görüntülerine veya hata raporlarına eklemeyin. Servislerin kota, lisans ve kullanım koşulları ayrıdır.

### Risk hesabı

| Sağlayıcı | Ağırlık |
| --- | ---: |
| AbuseIPDB | %35 |
| VirusTotal | %35 |
| Shodan | %15 |
| GreyNoise | %15 |

Puan, yalnızca başarıyla veri döndüren sağlayıcıların ağırlıklarına göre normalize edilir. Düzeyler: düşük 0–24, orta 25–49, yüksek 50–74, kritik 75–100. Kanıt sayısı sıfırsa güven düzeyi `none` olur.

### Veri ve gizlilik

Seçili kaynaklar, sorgulanan genel IP adresini rdap.org, RIPEstat, ipwho.is veya seçilen API sağlayıcılarına gönderir. Uygulama ayrıca telemetri eklemez. İlgili servislerin gizlilik ve kullanım koşullarını inceleyin.

Önceki Python/Tkinter kodu bu depoda geriye dönük başvuru için tutulmuştur. Windows uygulamasının ana derleme ve çalışma yolu Rust EXE'dir.

## License / Lisans

[MIT](LICENSE)
