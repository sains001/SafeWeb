# SafeWeb

SafeWeb adalah pemindai keamanan web dasar berbasis Python. Tool ini melakukan pemeriksaan ringan dan non-eksploitatif pada website, seperti header keamanan, TLS, cookie, form, mixed content, HTTP method, dan file sensitif umum jika opsi tambahan diaktifkan.

Gunakan hanya pada website yang Anda miliki atau punya izin tertulis untuk diuji.

## Fitur

- Cek HTTPS dan konfigurasi TLS dasar
- Cek masa berlaku sertifikat TLS
- Cek security headers umum
- Cek cookie flags: `Secure`, `HttpOnly`, dan `SameSite`
- Cek form POST tanpa indikasi token CSRF
- Cek mixed content pada halaman HTTPS
- Cek HTTP method berisiko dari response `OPTIONS`
- Cek error HTTP `4xx` dan `5xx`
- Opsional: cek path file sensitif umum
- Output teks atau JSON
- Tanpa dependency eksternal, cukup Python 3

## Batasan

SafeWeb adalah scanner dasar, bukan vulnerability scanner penuh. Tool ini tidak melakukan:

- Eksploitasi celah
- Brute force
- Login otomatis
- Crawling banyak halaman
- Fuzzing parameter
- Scan XSS/SQLi aktif
- Pengujian autentikasi atau otorisasi

Hasil scan adalah indikasi awal dan tetap perlu verifikasi manual.

## Struktur

```text
SafeWeb/
├── safe_web.py
└── README.md
```

## Cara Menjalankan

Masuk ke folder tool:

```bash
cd /home/kali/SafeWeb
```

Scan dasar:

```bash
python3 safe_web.py https://example.com
```

Jika target ditulis tanpa skema, tool akan memakai HTTPS secara otomatis:

```bash
python3 safe_web.py example.com
```

## Contoh Penggunaan

Scan dengan timeout lebih lama:

```bash
python3 safe_web.py https://example.com --timeout 15
```

Output JSON:

```bash
python3 safe_web.py https://example.com --json
```

Cek path sensitif umum:

```bash
python3 safe_web.py https://example.com --check-paths
```

Gabungan opsi:

```bash
python3 safe_web.py https://example.com --timeout 15 --check-paths --json
```

## Opsi

| Opsi | Default | Keterangan |
| --- | --- | --- |
| `target` | wajib | URL atau domain target, contoh `https://example.com` |
| `--timeout` | `10` | Timeout request dalam detik |
| `--json` | mati | Tampilkan output dalam format JSON |
| `--check-paths` | mati | Cek beberapa path file sensitif umum |

## Pemeriksaan Security Header

SafeWeb mengecek header berikut:

| Header | Fungsi |
| --- | --- |
| `Strict-Transport-Security` | Memaksa browser memakai HTTPS |
| `Content-Security-Policy` | Membatasi sumber script dan content |
| `X-Frame-Options` | Membantu mencegah clickjacking |
| `X-Content-Type-Options` | Mencegah MIME sniffing |
| `Referrer-Policy` | Mengurangi kebocoran referrer |
| `Permissions-Policy` | Membatasi akses fitur browser |

Tool juga memberi catatan jika `Content-Security-Policy` terlihat terlalu longgar, misalnya memakai wildcard atau `unsafe-inline`.

## Pemeriksaan Cookie

SafeWeb akan memberi temuan jika cookie tidak memiliki flag penting:

- `Secure`
- `HttpOnly`
- `SameSite`

Flag yang tepat bergantung pada fungsi cookie. Cookie session atau autentikasi biasanya perlu perlindungan lebih ketat.

## Pemeriksaan Path Sensitif

Opsi `--check-paths` akan mencoba mengecek path umum berikut:

```text
/.env
/.git/HEAD
/backup.zip
/backup.tar.gz
/database.sql
/phpinfo.php
/server-status
/wp-config.php.bak
```

Gunakan opsi ini hanya jika Anda punya izin, karena request tambahan akan dikirim ke server target.

## Skor

Output teks menampilkan skor keamanan dasar:

```text
Skor: 85/100 (baik)
```

Bobot temuan:

| Severity | Pengaruh skor |
| --- | --- |
| `HIGH` | -30 |
| `MEDIUM` | -12 |
| `LOW` | -4 |
| `INFO` | 0 |

Label skor:

| Skor | Label |
| --- | --- |
| `85-100` | `baik` |
| `65-84` | `perlu perbaikan` |
| `0-64` | `berisiko` |

## Contoh Output

```text
Target       : https://example.com/
Final URL    : https://example.com/
HTTP Status  : 200
Skor         : 76/100 (perlu perbaikan)

Info:
  - content_type: text/html; charset=UTF-8
  - body_sample_bytes: 12500
  - tls_version: TLSv1.3
  - certificate_expires: 2026-09-01T12:00:00Z
  - forms: 1
  - external_scripts: 3
  - options_status: 200

[MEDIUM] Header hilang: content-security-policy
  CSP membantu membatasi sumber script/content.

[LOW] Header hilang: referrer-policy
  Referrer-Policy mengurangi kebocoran URL/referrer.
```

## Output JSON

Dengan opsi `--json`, hasil berisi:

- `target`: target awal
- `final_url`: URL akhir setelah redirect
- `status`: status HTTP
- `score`: skor ringkas
- `info`: informasi pendukung
- `findings`: daftar temuan

Contoh:

```bash
python3 safe_web.py https://example.com --json
```

## Catatan

Temuan seperti form POST tanpa token CSRF perlu diverifikasi manual, karena beberapa framework memakai proteksi CSRF melalui header, cookie, atau mekanisme lain yang tidak terlihat sebagai input form biasa. Tidak adanya temuan dari tool ini juga tidak berarti aplikasi sudah aman sepenuhnya.
