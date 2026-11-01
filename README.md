# Barracuda IP Intelligence

A clean, Windows-first Python application for **passive IP OSINT and threat intelligence**. Core analysis works without API keys; optional commercial/community providers can enrich the result when the user supplies their own keys.

> This project performs passive lookups only. Use it lawfully and only for systems or investigations you are authorized to assess. IP geolocation is approximate and must never be treated as a device's physical address.

## English

### Features

- IPv4/IPv6 validation and classification: global, private, loopback, link-local, multicast, reserved, unspecified, and bogon
- Reverse DNS/PTR lookup
- RDAP-based registration/WHOIS data through the global RDAP bootstrap service
- ASN, announced prefix, and network holder through RIPEstat
- Keyless approximate geolocation through ipwho.is
- Optional AbuseIPDB, VirusTotal, Shodan, and GreyNoise integrations
- Transparent weighted risk score with evidence count and confidence label
- JSON and flattened CSV reports
- Dependency-free CLI and Tkinter desktop GUI
- Packaging-ready project layout for a future PyInstaller `.exe`

### Requirements

- Windows 10/11 (Linux and macOS should also work for the CLI)
- Python 3.11 or newer
- Internet access for public intelligence sources

### Installation

```powershell
git clone https://github.com/barricade561/test1.git
cd test1
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

No third-party runtime packages are required.

### CLI usage

```powershell
# Standard keyless analysis
ipintel 8.8.8.8

# Full terminal JSON and saved reports
ipintel 1.1.1.1 --print-json --json reports\cloudflare.json --csv reports\cloudflare.csv

# Local classification only; no web intelligence calls
ipintel 192.168.1.1 --no-keyless

# Query only selected configured providers
ipintel 8.8.8.8 --providers abuseipdb,virustotal
```

You can also run the source tree without installing it:

```powershell
$env:PYTHONPATH = "src"
python -m ipintel.cli 8.8.8.8
```

### Desktop GUI

```powershell
ipintel-gui
```

Or:

```powershell
$env:PYTHONPATH = "src"
python -m ipintel.gui
```

The dark console-style interface keeps the analysis responsive by running it in a background thread. Enter an IP address, select keyless and optional sources, then choose **ANALİZ ET**. The complete JSON result appears in the left panel; the right panel shows risk and provider evidence. Use **↓ JSON** or **↓ CSV** to save the report. When there is no provider evidence, the risk panel shows **KANIT YOK** instead of presenting a zero score as verified clean.

### Optional API providers

Copy the example configuration and add only the keys you want to use:

```powershell
Copy-Item .env.example .env
```

```dotenv
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
```

`.env` is ignored by Git. Never commit, paste into source code, or include real keys in screenshots and bug reports. Each service has its own account, quota, license, and acceptable-use terms.

If a key is absent, that provider is reported as `not_configured` and the rest of the analysis continues. Remote errors are isolated in their own result sections.

### Risk score

The score is a normalized weighted mean of successfully queried providers:

| Provider | Weight |
|---|---:|
| AbuseIPDB | 35% |
| VirusTotal | 35% |
| Shodan | 15% |
| GreyNoise | 15% |

Only successful provider evidence participates in the calculation. A score of zero with no evidence means **unknown**, not verified clean. Levels are `low` (0–24), `medium` (25–49), `high` (50–74), and `critical` (75–100).

### Tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Tests do not require network access or API keys.

### Future Windows executable

```powershell
python -m pip install -e ".[build]"
pyinstaller --noconfirm --clean --windowed --name BarracudaIPIntelligence --paths src src\ipintel\gui.py
```

The executable will be placed under `dist\BarracudaIPIntelligence\`. Provider keys should still be supplied through a user-created `.env` file or environment variables; they should not be embedded in the executable.

### Data sources and privacy

The application sends the queried public IP address to whichever sources are enabled: rdap.org, RIPEstat, ipwho.is, and any configured optional providers. Review their current privacy policies and terms before use. No telemetry is added by this application.

---

## Türkçe

### Özellikler

- IPv4/IPv6 doğrulama ve sınıflandırma: global, özel, loopback, link-local, multicast, reserved, unspecified ve bogon
- Reverse DNS/PTR sorgusu
- Global RDAP yönlendirme servisi üzerinden RDAP tabanlı kayıt/WHOIS bilgileri
- RIPEstat üzerinden ASN, duyurulan prefix ve ağ sahibi
- ipwho.is üzerinden API anahtarı gerektirmeyen yaklaşık konum
- Opsiyonel AbuseIPDB, VirusTotal, Shodan ve GreyNoise entegrasyonları
- Kaynak sayısı ve güven etiketi içeren şeffaf, ağırlıklı risk skoru
- JSON ve düzleştirilmiş CSV raporları
- Harici çalışma zamanı bağımlılığı olmayan CLI ve Tkinter masaüstü arayüzü
- İleride PyInstaller ile `.exe` üretimine uygun proje yapısı

### Gereksinimler ve kurulum

- Windows 10/11
- Python 3.11 veya daha yeni sürüm
- Açık istihbarat kaynakları için internet bağlantısı

```powershell
git clone https://github.com/barricade561/test1.git
cd test1
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Programın çalışması için üçüncü taraf Python paketi gerekmez.

### Kullanım

```powershell
# Anahtarsız standart analiz
ipintel 8.8.8.8

# JSON ve CSV raporu
ipintel 1.1.1.1 --json reports\rapor.json --csv reports\rapor.csv

# İnternet sorgusu yapmadan yalnızca yerel sınıflandırma
ipintel 192.168.1.1 --no-keyless

# Masaüstü arayüzü
ipintel-gui
```

### API anahtarları

`.env.example` dosyasını `.env` adıyla kopyalayın ve yalnızca kullanacağınız servislerin anahtarlarını girin. `.env` Git tarafından yok sayılır. Gerçek anahtarları kaynak koda, commitlere, ekran görüntülerine veya hata raporlarına koymayın.

Anahtarı bulunmayan sağlayıcı `not_configured` olarak gösterilir; diğer sorgular çalışmaya devam eder. Servislerin kota, lisans ve kullanım koşulları birbirinden bağımsızdır.

### Risk skorunu yorumlama

Risk skoru, başarıyla yanıt veren opsiyonel tehdit istihbaratı sağlayıcılarının ağırlıklı ortalamasıdır. Hiç sağlayıcı kanıtı yokken görülen `0`, IP'nin temiz olduğunu değil, yeterli kanıt bulunmadığını ifade eder. Sonuçları her zaman kaynak verileri ve inceleme bağlamıyla birlikte değerlendirin.

### Testler

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Testler internet bağlantısı veya API anahtarı kullanmaz.

## License / Lisans

[MIT](LICENSE)


