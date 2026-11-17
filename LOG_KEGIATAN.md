# Log Kegiatan Development NetMon

Dokumen ini melacak aktivitas dan pembaruan fungsi utama pada aplikasi NetMon.

## Juli 2026 - Fase Penyempurnaan & Stabilisasi Laporan
**Deskripsi:** Melakukan perbaikan krusial pada metode perhitungan dan render grafik laporan bulanan agar lebih akurat dan responsif.

**Kegiatan:**
1. **Real Record Bucketing (Grafik Router):** 
   - Transisi dari metode _Average-of-Average_ (harian) menjadi sampling data historis asli (_Raw Record_) dengan periode 24 Jam (interval 15 mnt), 7 Hari (interval 2 jam), dan 1 Bulan (harian).
   - Backend mem-parsing data per-bucket menggunakan `defaultdict` pada rentang ISO Date agar titik grafiknya sinkron dengan timeline waktu sebenarnya.

2. **Real Record Bucketing (Grafik Backbone / Agregat):**
   - Menambahkan struktur _chart_data_ (24hours, 7days, 1month) pada perhitungan `backbone` di file `database.py`.
   - Menggabungkan perhitungan `rx` dan `tx` khusus dari router yang memiliki `include_in_aggregate = 1`.
   - Melakukan perombakan logika _rendering_ Javascript `reports.html` untuk memuat fungsi sinkronisasi (toggle button) antara grafik router individu dan grafik backbone secara instan.

3. **Perbaikan Race Condition Render Chart:**
   - Menangani masalah _Canvas is already in use_ di Chart.js akibat asinkronisasi proses dan eksekusi `setTimeout`.
   - Menerapkan _Generation Counter_ (`reportRenderGeneration`) yang mendeteksi apakah grafik yang akan di-render masih relevan (mencegah grafik lawas menimpa *canvas* yang baru dimuat).
   - Menghapus efek `pointRadius` dan menerapkan `fill: true` saat menampilkan mode _Raw Record_ agar browser tidak mengalami penurunan performa (_lag_) akibat _rendering_ ratusan node titik.

4. **Codebase Verification (Quality Assurance):**
   - Memastikan tidak ada pola `AVG(CASE... ELSE 0)` yang salah kaprah di seluruh *aggregate query* SQL.
   - Menggunakan _Covering Index_, _Memory Mapping_ (mmap), dan tipe jurnal WAL (_Write-Ahead Logging_) di SQLite untuk mencegah *Database Lock* pada *background thread*.
   - Melaksanakan uji coba fungsional via WSL melalui skrip simulasi metrik (`verify_backbone.py`) yang berujung **LULUS (Passed)** tanpa distorsi fungsionalitas utama aplikasi.


## November 2026 - Integrasi Telegram Bot Interaktif 2-Arah & Alerting Cerdas
**Deskripsi:** Mengimplementasikan integrasi Telegram Bot interaktif 2-arah native (menggunakan library `requests`), alerting cerdas berbasis filter AI False Alarm, tombol inline interaktif, daily digest terjadwal, dan panel konfigurasi settings.

**Kegiatan:**
1. **Modul Telegram Bot Native (`telegram_bot.py`):**
   - Mengembangkan engine Telegram Bot dengan koneksi long polling asinkron di background thread tanpa dependensi eksternal tambahan.
   - Sistem otorisasi whitelist berbasis Chat ID dan User ID untuk membatasi interaksi hanya kepada admin/grup yang berhak.
   - Fitur perintah chat 2-arah: `/status`, `/alerts`, `/down`, `/devices`, `/ack`, `/ack_all`, `/poll`, `/digest`, `/myid`, dan `/help`.
2. **Notifikasi Alert & Tombol Inline Interaktif:**
   - Notifikasi real-time ke Telegram untuk insiden perangkat DOWN/CRITICAL dan pemulihan ONLINE (RECOVERY).
   - Integrasi filter AI False Warning Detector: alert yang terindikasi false alarm (WSL socket collision, host flapping, atau pingable) otomatis di-filter agar tidak membisingkan notifikasi tim.
   - Menambahkan tombol inline `[✅ Acknowledge]` dan `[🔄 Re-check]` langsung pada pesan alert Telegram dengan *live editing* status konfirmasi pesan dan sinkronisasi real-time ke Web Dashboard via Socket.IO.
3. **Daily Digest Terjadwal:**
   - Penjadwalan laporan rekap harian otomatis (default 08:00 WIB) via background scheduler yang merangkum kesehatan perangkat, uptime ratio, latensi, dan alert aktif.
4. **Panel Pengaturan Web Settings (`settings.html` & `app.py`):**
   - Menambahkan panel konfigurasi Telegram di Web Settings (Token, Chat ID, filter Down/Up, Daily Digest Time, dan toggle aktifasi).
   - Menyediakan tombol *Test Connection* untuk verifikasi token bot dan validasi pengiriman pesan langsung dari web.
   - Penyembunyian token bot (`***`) pada respons API demi keamanan.
5. **Sinkronisasi Skrip Pembaruan (`update.sh`):**
   - Memastikan file `telegram_bot.py` otomatis tercakup dalam proses sinkronisasi dan update service di server tanpa menghapus database `netmon.db`.
6. **Penyempurnaan Total Keamanan Database & Service (`update.sh` & `install.sh`):**
   - Menghilangkan bug hilangnya service dan kerusakan database saat update.
   - Menambahkan auto-checkpoint SQLite WAL dan auto-backup persisten (`netmon.db`, `netmon.db-wal`, `netmon.db-shm`) ke direktori `/var/backups/netmon/` dengan retensi 10 backup terakhir.
   - Menghentikan service secara graceful sebelum menyalin file atau memperbarui venv agar tidak terjadi konflik penulisan database.
   - Pengecualian total (`--exclude='netmon.db*' --exclude='*.db*'`) agar file database di `/opt/netmon` tidak pernah tertimpa.
   - Auto-repair service: Jika `/etc/systemd/system/netmon.service` hilang atau belum dibuat, `update.sh` otomatis membuat dan mengaktifkannya kembali.
   - Penataan permissions ketat (`chmod 664` dan kepemilikan `netmon:netmon` pada database) agar service tidak crash saat menulis data.
7. **Optimasi Analisa Anomali Traffic & Lonjakan Resource (`snmp_worker.py`, `ai_detector.py`, `templates/settings.html`):**
   - Mengembangkan engine deteksi anomali real-time di `snmp_worker.py` dengan rolling window per perangkat untuk memantau lonjakan traffic dan utilisasi resource mendadak.
   - Algoritma korelasi multivariat: Mendeteksi korelasi simultan antara lonjakan throughput (traffic spike > 2.5x baseline) dan kenaikan drastis CPU (> 85% atau lonjakan mendadak > +40%) untuk deteksi dini serangan DDoS, broadcast storm, atau loop routing aktif.
   - Deteksi anomali resource mandiri: Peringatan dini lonjakan beban CPU atau pemakaian RAM kritis (> 90% berisiko OOM crash) meskipun perangkat belum mati.
   - Mekanisme cooldown pintar (5 menit per perangkat) untuk mencegah banjir alarm berulang saat anomali masih berlangsung.
   - Notifikasi instan via Telegram Bot dengan badge khusus (`⚡ ANOMALI TRAFFIC & RESOURCE SPIKE`) lengkap dengan diagnosa korelasi traffic & CPU.
   - Penambahan pengaturan ambang batas lonjakan (kelipatan baseline, min Mbps, ambang CPU, ambang RAM) pada antarmuka Web Settings.

8. **Perbaikan Bug Polling SNMP & Stabilisasi Anti-Flapping Alert (`snmp_worker.py`):**
   - Menghilangkan bug `return None` pada penanganan exception `SnmpTimeout` saat multiget: Kini sistem otomatis melakukan fallback graceful ke individual OID get (`c.get(oid)`) satu per satu tanpa langsung membatalkan query polling. Pada individual get, kegagalan 1 OID tidak memutus OID lainnya (`continue`).
   - Peningkatan toleransi retry SNMP (`_get`): Mengubah pola polling dari single-attempt (`range(1)`) menjadi 2-attempt dengan jeda istirahat 0.5s antar percobaan.
   - Penyesuaian ambang ICMP Ping pada Linux: Menaikkan parameter timeout ping `-W` dari 1s ke 2s dan timeout eksekusi subprocess ke 5.0s untuk mengakomodasi lonjakan beban jaringan/backup di dini hari tanpa false positive down.
   - Mekanisme Consecutive Failure Threshold & Anti-Flapping:
     - Mengatasi masalah alert berulang pada perangkat tertentu (seperti `172.17.17.21`) yang dipicu oleh paket SNMP drop minor sementara koneksi ICMP ping normal.
     - Menerapkan counter kegagalan berurutan (`_consecutive_snmp_fails` dan `_consecutive_ping_fails`). Alert warning "SNMP unreachable" hanya akan dipicu jika kegagalan SNMP terjadi minimal 2 siklus berturut-turut (`fail_count >= 2`), mencegah false alarm akibat paket drop sporadis.
     - Reset instan counter ketika perangkat merespons SNMP dengan sukses.

9. **Audit Komprehensif Seluruh Bug & Remediasi Multi-Komponen (15 Bug Fixed):**
   - **BUG-01 (Groq Model):** Mengganti model `openai/gpt-oss-120b` (invalid 400 error) ke model resmi `llama-3.3-70b-versatile` pada seluruh endpoint AI (`ai_detector.py`, `app.py`, `database.py`).
   - **BUG-02 (Race Condition):** Mengeliminasi *race condition* dispatch notifikasi Telegram melalui evaluasi heuristik sinkron cepat (`evaluate_heuristics`) sebelum pesan dikirimkan.
   - **BUG-03 (Broken SNMP Ping):** Memperbaiki konstruktor dan coroutine `_snmp_ping` pada `ai_detector.py` menggunakan wrapper `puresnmp` PyWrapper dan kredensial V1/V2C yang valid.
   - **BUG-04 (False Alarm Misclassification):** Mengoreksi logika klasifikasi false alarm agar insiden pemadaman massal (switch mati / mati lampu) tidak disalahartikan sebagai kendala WSL di lingkungan Linux produksi.
   - **BUG-05 (Floorplan Upload):** Menambahkan auto-create direktori `static/img` pada `upload_floorplan` untuk mencegah error HTTP 500 saat upload denah.
   - **BUG-06 (Telegram Callback):** Menangani callback query inline button `cmd:down` pada `telegram_bot.py`.
   - **BUG-07 (Database Method):** Mengimplementasikan method `Database.get_zone(zone_id)` yang sebelumnya hilang agar label zona pada alert Telegram tidak kosong.
   - **BUG-08 (SNMP Walk Overhead):** Mengeliminasi 4x SNMP walk redundan tiap 30 detik pada router traffic polling dengan caching 1 jam serta proteksi setting manual `uplink_speed_mbps`.
   - **BUG-09 (Date Parsing):** Melakukan normalisasi string tanggal SQLite (`replace(' ', 'T')`) pada `analyze_downtime_event` agar kompatibel dengan Python 3.9/3.10.
   - **BUG-10 (Downtime Forensics Modal):** Memperbaiki deteksi "SNMP Unreachable" pada modal web menggunakan `snmp_worker._snmp_failing` alih-alih ketergantungan semu pada metrik CPU.
   - **BUG-11 (Telegram Down Column):** Mengoreksi pemanggilan nama kolom `type` pada perintah Telegram `/down`.
   - **BUG-12 (Unack Count Discrepancy):** Menyelaraskan filter `is_false_alarm=0` pada `Database.get_unack_count()`.
   - **BUG-13 (Prometheus Escaping):** Melakukan sanitasi dan escaping karakter kutip ganda pada Prometheus exporter `/metrics`.
   - **BUG-14 (Telegram Devices Key):** Menyaring key internal `_total` pada output perintah Telegram `/devices`.
   - **BUG-15 (Schema Consistency):** Menambahkan kolom `wan_in` pada skema awal tabel `devices`.

10. **Audit Komprehensif Seluruh Bug Antarmuka Pengguna (UI/UX - 10 Bug Fixed):**
    - **UI-BUG-01 (Background Polling Leak):** Menghubungkan event `'hidden.bs.modal'` Bootstrap pada `#detailModal` di `static/js/main.js` agar `closeDetailModal()` otomatis dipanggil dan mematikan `detailPollInterval` saat modal ditutup via klik di luar backdrop atau tombol Esc.
    - **UI-BUG-02 (Chart.js Canvas Collision):** Menghancurkan `latencyChartInstance` dan memanggil `Chart.getChart(canvas)?.destroy()` secara aman di `openDeviceDetail()`, `closeDetailModal()`, dan `loadLatencyChart()` untuk mengeliminasi error *"Canvas is already in use"*.
    - **UI-BUG-03 (Race Condition Polling):** Menerapkan pengecekan `activeDetailDeviceId === targetId` pada callback respons asinkron `fetchRealtimeStats()` dan `openDeviceDetail()` agar data perangkat lama tidak menimpa modal perangkat baru saat berpindah dengan cepat.
    - **UI-BUG-04 (Theme Toggle All Charts):** Mengembangkan `updateChartsTheme(isLight)` untuk mengiterasi seluruh instance aktif Chart.js melalui `Chart.instances` sehingga grafik Backbone Dashboard, Latency Ping, Router Uplinks, dan sparklines otomatis menyesuaikan warna ticks, grid, dan tooltip saat beralih Day/Night mode.
    - **UI-BUG-05 (Deteksi Dark Mode Reports):** Memperbaiki pengecekan tema pada `templates/reports.html` (`renderBackboneReportChart` dan `renderIndividualRouterChart`) agar mendeteksi `!document.body.classList.contains('light-theme')`, mengembalikan warna grid dan tick yang kontras pada tema gelap.
    - **UI-BUG-06 (Real-time Socket.IO Alert Ack):** Menambahkan handler `window.onAlertAcked` dan `window.onAllAlertsAcked` pada `templates/dashboard.html` dan `templates/logs.html` agar counter Active Alerts, warning banner, daftar insiden aktif, dan badge logs ter-update seketika saat alert di-acknowledge dari sesi lain atau via bot Telegram.
    - **UI-BUG-07 (Mobile Sidebar & Overlay):** Membuat fungsi helper terpusat `toggleMobileSidebar(forceClose)` di `main.js` serta menambahkan auto-close event listener pada item menu navigasi untuk tampilan mobile (< 768px).
    - **UI-BUG-08 (Form Validation Settings):** Menambahkan validasi sisi klien pada `saveAll()` di `templates/settings.html` untuk memastikan seluruh field angka (poll interval, retention, dsb.) bernilai valid sebelum dikirim ke backend.
    - **UI-BUG-09 (Responsive Chart Overflow):** Menambahkan aturan `min-width: 0` dan `overflow: hidden` pada container flex grafik dashboard serta menambahkan listener `resize` window untuk penyesuaian dinamis canvas.
    - **UI-BUG-10 (DOM Interface Reset):** Melakukan reset total pada container dropdown interface, tabel status port, dan live legend teks di awal pemanggilan `openDeviceDetail()` untuk mencegah sisa tampilan dari perangkat sebelumnya muncul.
