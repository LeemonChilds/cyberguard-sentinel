# 🛡️ CYBERGUARD SENTINEL
**Tagline:** *DETECT. ANALYZE. PROTECT.*  
**Versi:** 1.0.0 | **Platform:** Defensive Cybersecurity Monitoring & SOC Dashboard (Python)

---

## 1. Gambaran Umum Proyek
**CYBERGUARD SENTINEL** adalah platform pemantauan keamanan siber defensif berbasis Python dengan antarmuka web interaktif (*Security Operations Center Dashboard*). Sistem ini dirancang untuk mendeteksi indikator ancaman secara nyata pada perangkat lokal maupun dalam simulasi edukatif tanpa menggunakan fitur eksploitasi berbahaya.

### Mode Operasi Ganda
- **🟢 LIVE MODE (Default Utama):** Menginspeksi antarmuka jaringan lokal, koneksi aktif, integritas file SHA-256, pemindaian port localhost terotorisasi (`127.0.0.1`), serta korelasi insiden SOC secara *real-time*.
- **🟡 DEMO MODE (Offline Exhibition Mode):** Menggunakan dataset simulasi offline (`data/sample_events.json`) yang aman dan terisolasi, dapat berjalan 100% tanpa akses internet, serta dilengkapi penanda visual eksplisit.

---

## 2. Arsitektur 6 Security Engines + 1 Live Dashboard

| Kode Modul | Nama Modul | Fungsi Teknis & Standar Keamanan |
| :--- | :--- | :--- |
| **Module 01** | **Phishing Detection Engine** | Validasi skema HTTP/HTTPS, analisis struktur domain, deteksi alamat IP mentah, simbol `@`, penyingkat URL, kata kunci rekayasa sosial, dan penilaian risiko heuristik (`SAFE`, `SUSPICIOUS`, `HIGH RISK`). |
| **Module 02** | **Network Monitoring Engine** | Pemantauan antarmuka IPv4 lokal dan koneksi soket aktif (`psutil` & `socket`) secara *point-in-time* tanpa memerlukan hak akses *packet sniffing*. |
| **Module 03** | **File Integrity Monitor** | Komputasi sidik jari kriptografi **SHA-256** (*chunked reading*) untuk mendeteksi status `UNCHANGED`, `MODIFIED`, `NEW FILE`, dan `DELETED FILE`. |
| **Module 04** | **Password Security Analyzer** | Evaluasi entropi bit, keragaman karakter, dan pola lemah dengan kebijakan ketat **Zero-Storage** (kata sandi tidak pernah disimpan ke database maupun file log). |
| **Module 05** | **Port Security Scanner** | Pemindaian port TCP defensif pada `127.0.0.1` (atau IP privat dengan otorisasi eksplisit), dibatasi maksimal 100 port per pemindaian, dan memblokir pemindaian IP publik. |
| **Module 06** | **Security Incident Analyzer** | Korelasi otomatis *SecurityEvent* lintas modul menjadi tiket *SecurityIncident*, manajemen status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`), serta playbook mitigasi. |
| **Module 07** | **Live Security Dashboard** | Antarmuka SOC bertema *Dark Navy* (Streamlit & Plotly) dengan 9 halaman navigasi, grafik interaktif, dan ekspor laporan (`.md`, `.json`, `.csv`). |

---

## 3. Struktur Direktori Proyek

```text
CYBERGUARD-SENTINEL/
├── app.py                  # Entry point utama Streamlit (Rerun-Safe)
├── config.py               # Pusat konfigurasi, konstanta, & guardrails keamanan
├── requirements.txt        # Daftar pustaka resmi Python
├── README.md               # Dokumentasi utama sistem
├── core/                   # Fondasi inti (database, logger, validators, risk & security engine)
├── modules/                # Implementasi 6 Security Engines utama
├── database/               # Single Source of Truth skema 7 entitas SQLite (models.py)
├── dashboard/              # 9 halaman antarmuka SOC & komponen UI tema Dark Navy
├── services/               # Layanan monitoring, manajemen insiden, & generator laporan
├── tests/                  # Suite pengujian otomatis Pytest (24 unit & integration tests)
├── data/                   # Dataset simulasi offline & folder sandbox pengujian
├── reports/                # Direktori penyimpanan laporan audit hasil ekspor
├── docs/                   # Panduan demonstrasi pameran & dokumentasi pendukung
└── assets/                 # Custom CSS tema Dark Navy SOC
---

## Langkah 2: Membuat Panduan Demonstrasi Pameran (`docs/EXHIBITION_DEMO_GUIDE.md`)

### File 2: `docs/EXHIBITION_DEMO_GUIDE.md`
* **Lokasi:** `CYBERGUARD-SENTINEL\docs\EXHIBITION_DEMO_GUIDE.md`
* **Fungsi:** Panduan terstruktur untuk mendemonstrasikan aplikasi kepada berbagai kelompok audiens (SD, SMP, SMA, Guru, dan Pengunjung Umum/Juri) beserta daftar periksa persiapan stan pameran.

```markdown
# 🎤 PANDUAN DEMONSTRASI PAMERAN — CYBERGUARD SENTINEL
**Tagline:** *DETECT. ANALYZE. PROTECT.*

---

## 1. Persiapan Sebelum Pameran Dimulai (Checklist Teknis)
1. Pastikan laptop terhubung ke daya listrik dan jalankan `streamlit run app.py` di PowerShell.
2. Pastikan mode operasi di sidebar berada pada **`LIVE`** (jika lokasi stan memiliki Wi-Fi/jaringan lokal) atau **`DEMO`** (jika tidak ada internet sama sekali).
3. Buka menu **`4. File Integrity`**, klik **`1. Buat / Perbarui Baseline SHA-256`** pada folder sandbox default agar siap digunakan untuk demonstrasi perubahan file.
4. Buka menu **`1. Overview`** dan klik **`⚡ Jalankan Real-Time System Sweep Sekarang`** satu kali untuk mengisi metrik dan grafik awal.

---

## 2. Skenario Demonstrasi Berdasarkan Profil Pengunjung

### A. Untuk Siswa SD (Fokus: Analogi Sehari-hari & Kebiasaan Aman)
- **Analogi:** *"Bayangkan komputer seperti rumah kita. CYBERGUARD SENTINEL adalah satpam pintar yang menjaga pintu rumah (Port Scanner), memeriksa surat mencurigakan (Phishing Detector), dan memastikan gembok kamar sangat kuat (Password Analyzer)."*
- **Demo Praktis (2 Menit):**
  1. Buka **`5. Password Analyzer`**. Masukkan kata sandi lemah seperti `admin12345` $\rightarrow$ tunjukkan status merah (`WEAK`), lalu bandingkan dengan `Kopi!Pagi#Bali94$Aman` (`VERY STRONG`).
  2. Pesan edukasi: *Jangan pernah memakai tanggal lahir atau angka urut 12345 untuk password akun game atau belajar.*

### B. Untuk Siswa SMP (Fokus: Waspada Tautan Penipuan / Phishing)
- **Analogi:** *"Penipu di internet sering mengirim link hadiah palsu atau halaman login tiruan. Modul Phishing Detector memeriksa ciri-ciri aneh pada alamat website sebelum kita klik."*
- **Demo Praktis (3 Menit):**
  1. Buka **`2. Phishing Detection`**.
  2. Uji tautan aman `https://www.kemdikbud.go.id` (`SAFE`), lalu uji tautan jebakan `http://192.168.1.55@secure-verify-bank-account.tk/login` (`HIGH RISK`).
  3. Tunjukkan bagaimana sistem menjelaskan alasan bahayanya (tanpa HTTPS, memakai alamat IP, memakai simbol `@`, dan kata kunci pancingan).

### C. Untuk Siswa SMA (Fokus: Kriptografi SHA-256 & Jaringan Lokal)
- **Konsep Teknis:** *Menjelaskan bagaimana hash kriptografi SHA-256 bekerja sebagai "sidik jari digital" file—mengubah 1 huruf saja di dalam dokumen akan mengubah seluruh rangkaian 64 karakter hash.*
- **Demo Praktis (4 Menit):**
  1. Buka **`4. File Integrity`**, klik **`Simulasikan Modifikasi File`** di expander sandbox, lalu klik **`2. Jalankan Audit Integritas Sekarang`**.
  2. Tunjukkan perubahan status menjadi **`MODIFIED`** beserta perbandingan hash lama dan hash baru.
  3. Lanjutkan ke **`6. Port Scanner`** (target `127.0.0.1`, port `8500–8510`) untuk menunjukkan cara kerja port TCP lokal yang sedang menjalankan dashboard ini (`8501`).

### D. Untuk Guru & Tenaga Pendidik (Fokus: Keamanan Data Sekolah & Nilai Pedagogis)
- **Poin Utama:**
  - Perlindungan integritas dokumen penting (nilai, soal ujian, arsip administrasi) menggunakan baseline SHA-256.
  - Kepatuhan privasi siswa: modul *Password Analyzer* menerapkan **Zero-Storage Policy** sehingga tidak pernah menyimpan kata sandi yang diuji.
  - Cocok dijadikan media praktikum mata pelajaran **Informatika** (keamanan siber, jaringan komputer, dan pemrograman Python modular).

### E. Untuk Pengunjung Umum & Juri Teknis (Fokus: Arsitektur SOC End-to-End)
- **Alur Presentasi Lengkap (5 Menit):**
  1. Tunjukkan **`1. Overview`** sebagai pusat komando SOC dengan grafik Plotly dan *Real-Time System Sweep*.
  2. Jelaskan arsitektur **6 Security Engines + 1 Live Dashboard**, *Centralized Risk Scoring Engine (0–100)* yang *explainable*, serta isolasi database SQLite (`WAL mode` & `rerun-safe`).
  3. Buka **`7. Incident Center`**, klik **`🔗 Korelasikan Security Events Otomatis`** untuk mendemonstrasikan bagaimana temuan dari berbagai modul digabungkan menjadi tiket insiden SOC lengkap dengan *playbook* mitigasi.
  4. Akhiri di **`8. Reports`** dengan mengunduh laporan audit `.md` atau `.json` secara langsung.