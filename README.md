# Barracuda IP Intelligence

Windows için Rust ile yazılmış pasif IP istihbaratı uygulaması. Koyu Konsol arayüzü `BarracudaIPIntelligence.exe` ile, komut satırı aracı `ipintel.exe` ile açılır. Python kurulumu çalışma sırasında gerekmez.

## Özellikler

- IPv4/IPv6 doğrulama, özel/genel/bogon sınıflandırması ve ters DNS
- RDAP, RIPEstat ağ/ASN ve ipwho.is yaklaşık konum sorguları
- İsteğe bağlı AbuseIPDB, VirusTotal, Shodan ve GreyNoise kaynakları
- Yalnızca başarılı kaynak kanıtlarını kullanan ağırlıklı risk puanı
- JSON ve düzleştirilmiş CSV raporları
- Ağ istekleri sürerken yanıt veren koyu masaüstü arayüzü

Program tek IP hakkında pasif bilgi sorgular; ağdaki cihazları taramaz. Konum verisi yaklaşık değerdir, fiziksel cihaz adresi değildir.

## Windows EXE derleme

Rust stable araç zinciri gereklidir. Windows'ta MSVC veya GNU hedefi kullanılabilir. GNU hedefinde C/MinGW araçları ve bağımlılıkları da gerekebilir.

```powershell
git clone https://github.com/musaoguzdeniz-cc/barracuda-ip-intelligence.git
cd barracuda-ip-intelligence
cargo test --locked
cargo build --release --locked
```

Derleme sonunda `target\release\BarracudaIPIntelligence.exe` ve `target\release\ipintel.exe` oluşur. Uygulamayı açmak için GUI EXE dosyasına çift tıklayın. `target` klasörü Git'e eklenmez.

## Kullanım

```powershell
.\target\release\ipintel.exe 8.8.8.8
.\target\release\ipintel.exe 1.1.1.1 --print-json --json reports\cloudflare.json --csv reports\cloudflare.csv
.\target\release\ipintel.exe 192.168.1.1 --no-keyless
.\target\release\ipintel.exe 8.8.8.8 --providers abuseipdb,virustotal
```

Arayüzde IP adresini girin, kullanılacak kaynakları seçin ve **ANALİZ ET** düğmesine basın. Sol panel JSON sonucunu, sağ panel risk puanını ve kaynakları gösterir. Sağlayıcı kanıtı yoksa **KANIT YOK** görünür; bu sonuç IP'nin temiz olduğunu göstermez. **↓ JSON** ve **↓ CSV** raporu kaydeder.

## API anahtarları

`.env.example` dosyasını EXE'nin yanına `.env` adıyla kopyalayıp kullanacağınız anahtarları girin. Ortam değişkenleri `.env` değerlerinden önce gelir. Mevcut bir kurulumda `.env` dosyasını değiştirmeden yeni EXE'yi aynı klasöre koyabilirsiniz. Anahtarlar EXE içine gömülmez ve Git tarafından yok sayılır.

```dotenv
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
```

Anahtarı olmayan seçili sağlayıcı `not_configured` olarak raporlanır. HTTP hataları diğer kaynak sorgularını durdurmaz. Anahtarları kaynak koda, commitlere, ekran görüntülerine veya hata raporlarına eklemeyin. Servislerin kota, lisans ve kullanım koşulları ayrıdır.

## Risk hesabı

| Sağlayıcı | Ağırlık |
| --- | ---: |
| AbuseIPDB | %35 |
| VirusTotal | %35 |
| Shodan | %15 |
| GreyNoise | %15 |

Puan, yalnızca başarıyla veri döndüren sağlayıcıların ağırlıklarına göre normalize edilir. Düzeyler: düşük 0–24, orta 25–49, yüksek 50–74, kritik 75–100. Kanıt sayısı sıfırsa güven düzeyi `none` olur.

## Veri ve gizlilik

Seçili kaynaklar, sorgulanan genel IP adresini rdap.org, RIPEstat, ipwho.is veya seçilen API sağlayıcılarına gönderir. Uygulama ayrıca telemetri eklemez. İlgili servislerin gizlilik ve kullanım koşullarını inceleyin.

Önceki Python/Tkinter kodu bu depoda geriye dönük başvuru için tutulmuştur. Windows uygulamasının ana derleme ve çalışma yolu Rust EXE'dir.

## License

[MIT](LICENSE)
