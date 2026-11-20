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

11. **Perbaikan & Peningkatan Kehandalan Telegram Bot Command & Polling:**
    - **Pencegahan Silent Failure & Logging Komprehensif:** Menambahkan logging eksplisit ke `logger.error` dan `print` terminal (`journalctl`) pada fungsi `_send_request` dan loop polling `_poll_loop`, sehingga status incoming command, kegagalan autentikasi bot token, request error, atau network timeout terpantau secara transparan di log sistem.
    - **Auto-Resolve Webhook Collision (HTTP 409):** Mengeliminasi error 409 Conflict pada `getUpdates` dengan mengeksekusi API `deleteWebhook` baik saat inisialisasi thread maupun otomatis saat polling loop mendeteksi webhook lama masih aktif dari konfigurasi bot sebelumnya.
    - **Fallback Plain-Text pada Parsing HTML:** Mencegah pesan di-drop diam-diam oleh server Telegram jika respons berformat HTML mengalami kegagalan entity parsing (`Bad Request: can't parse entities`). Bot kini otomatis men-strip tag HTML dan mengirim ulang pesan sebagai plain-text.
    - **Penanganan Interaktif Command Belum Terotorisasi:** Memperbarui `_handle_message` agar merespons *seluruh* slash command yang dikirimkan oleh akun/grup yang belum di-whitelist dengan pesan ramah berisi Chat ID, User ID, dan instruksi penambahan ke whitelist di Settings NetMon (sebelumnya hanya command tertentu yang merespons).
    - **Fleksibilitas Whitelist Username:** Memperbarui `is_authorized()` agar mendukung pencocokan numerik Chat ID, User ID, maupun `@username` Telegram (case-insensitive) yang dimasukkan di menu Settings.
    - **Penanganan Command Tidak Dikenali & Peningkatan `/poll`:** Memberikan respons feedback bantuan saat command tidak dikenali, serta memperluas perintah `/poll` agar mendukung opsi `/poll all` untuk re-check seluruh status perangkat secara asinkron di latar belakang.
    - **Live Bot Status Badge di Settings UI:** Menambahkan indikator status real-time (`🟢 Active`, `🔴 Stopped`, atau `⚪ Disabled`) di panel Telegram Bot Integration pada `templates/settings.html` melalui endpoint `/api/telegram/status`.

12. **Ekspansi Perintah Bot Telegram untuk Monitoring Traffic & Bandwidth Usage:**
    - **Perintah `/traffic` (atau `/bw`):** Snapshot throughput agregat backbone (WAN In & Out) serta ringkasan utilisasi bandwidth seluruh router dengan indikator progress bar visual (`[████░░░░]`), status link, dan peringatan saturasi (utilisasi >= 85%). Mendukung argumen IP/ID (contoh: `/traffic 192.168.1.1`) untuk menampilkan statistik traffic per-interface perangkat tersebut.
    - **Perintah `/top` (Top Bandwidth Usage):** Menampilkan 10 interface dengan konsumsi bandwidth (RX/TX/Total) tertinggi di seluruh jaringan secara real-time.
    - **Perintah `/capture <ip/id>` (Live SNMP Capture 3 Detik):** Fitur pengukuran throughput aktif secara instan dengan mengambil 2 sampel SNMP berjarak 3 detik, mendukung 64-bit High Capacity (HC) octet counters dan proteksi counter rollover.
    - **Perintah `/iface <ip/id>`:** Memeriksa status dan daftar interface perangkat tertentu secara instan.
    - **Inline Keyboard Interaktif:** Menambahkan tombol shortcut pada pesan Telegram (`🔄 Refresh Traffic`, `🔝 Top Bandwidth`, `⚡ Live Capture (3s)`, dsb.) untuk navigasi data secara seamless tanpa mengetik ulang command.
    - **Optimasi Query Database Traffic:** Menambahkan method `get_latest_device_interface_traffic()`, `get_top_bandwidth_interfaces()`, dan `get_router_traffic_summary()` pada `database.py` dengan query agregasi CTE efisien.

13. **Pengembangan Sub-Command Pemilihan Traffic Router (All Routers vs Selected Router):**
    - **Sub-Command `/traffic all` (atau `/traffic`):** Menampilkan ringkasan throughput agregat seluruh router jaringan (backbone WAN in/out) lengkap dengan tombol interaktif untuk langsung beralih ke pemilihan router spesifik.
    - **Sub-Command `/traffic select` (atau `/traffic pilih` / `/traffic list`):** Menampilkan menu pemilih interaktif berbasis inline keyboard berisi tombol daftar router yang terdaftar, memudahkan pemilihan router hanya dengan sekali sentuh/klik di Telegram.
    - **Pencarian Cerdas Router Spesifik (`/traffic <nama/ip/id>`):** Meningkatkan fleksibilitas pemanggilan traffic perangkat melalui pencocokan cerdas ID numerik, IP address, maupun nama perangkat (substring & case-insensitive, misal: `/traffic core`).
    - **Navigasi Bolak-Balik Real-Time:** Menambahkan tombol `🔀 Pilih Router Lain` dan `🌐 Semua Router (All)` di setiap tampilan rincian router, serta integrasi callback query `cmd:traffic_picker` untuk transisi antar tampilan tanpa perlu mengetik ulang command.

14. **Evaluasi & Rekalibrasi Ambang Batas Anomali Detection & Traffic Spike (Non-Agresif):**
    - **Akar Masalah (Root Cause):** Pada pembaruan sebelumnya, deteksi anomali disetel dengan ambang batas yang terlalu agresif (multiplier 2.5x, batas minimum 20 Mbps, CPU threshold 85% / lompatan 40%, baseline hanya 2 sampel, dan toleransi link cap 1.05x). Akibatnya, router mengalami banjir false alarm saat aktivitas rutin harian (seperti backup dini hari 30-50 Mbps atau lonjakan CPU sesaat saat proses SNMP walk polling), serta grafik traffic mengalami penurunan tajam (dips/zeroed out) akibat traffic bursty melebihi 105% kapasitas link.
    - **Rekalibrasi Parameter Ambang Batas (Konservatif & Stabil):**
      - `traffic_spike_multiplier`: Ditingkatkan dari `2.5x` menjadi `4.0x` (lonjakan minimal 400% dari baseline historis).
      - `traffic_spike_min_mbps`: Ditingkatkan dari `20.0 Mbps` menjadi `80.0 Mbps` (mencegah false alarm pada aktivitas normal harian seperti download atau backup berkecepatan puluhan Mbps).
      - `cpu_spike_threshold`: Ditingkatkan dari `85%` menjadi `92%` dan disyaratkan bertahan pada 2 siklus polling berurutan (sustained high load), atau lompatan ekstrem &ge; 65% dengan beban akhir &ge; 85% untuk membedakan beban komputasi nyata dari fluktuasi sesaat SNMP walk.
      - `memory_spike_threshold`: Ditingkatkan dari `90%` menjadi `95%` dengan verifikasi kondisi sustained pada minimal 2 polling berurutan.
      - **Baseline Rolling Window:** Ditingkatkan dari 2 sampel menjadi minimal 4 sampel (~1-2 menit stabilisasi) sebelum perbandingan anomali dihitung.
      - **Kriteria Alerting Ketat:** Lonjakan traffic tunggal hanya memicu notifikasi jika utilisasi interface mencapai &ge; 85% (kondisi saturasi nyata). Cooldown alert diperpanjang dari 5 menit menjadi 10 menit (600 detik) untuk mengeliminasi alert fatigue.
    - **Perlindungan Grafik & Link Cap (Anti-Dip):**
      - `anomaly_cap_multiplier` dinaikkan dari `1.05` (5%) menjadi `1.25` (25% burst headroom), dan `anomaly_cap_gbps` menjadi `10.0 Gbps`.
      - Pada `collect_interface_traffic` dan `_poll_router_traffic`, data traffic yang sedikit melampaui kapasitas fisik link kini di-cap ke batas maksimum interface alih-alih di-nolkan (`0.0`) atau di-drop (`return None`). Hanya anomali ekstrem (&gt; 2x limit, indikasi counter rollover glitch) yang di-nolkan demi menjaga kelancaran kurva grafik dashboard.
    - **Auto-Migration Database & UI Settings:**
      - Menambahkan migrasi otomatis pada `database.py` saat startup untuk memperbarui setting default database lama tanpa menimpa setting kustom pengguna.
      - Menyelaraskan seluruh form input, nilai fallback Javascript, dan teks petunjuk di `templates/settings.html`.
      - Memperbarui instruksi prompt AI detector (`ai_detector.py`) agar model LLM Groq dapat secara akurat mengidentifikasi `is_false_alarm` (0 atau 1) saat analisis insiden anomali.

15. **Fitur Visualisasi Grafik Gambar (Traffic Charts) via Bot Telegram:**
    - **Engine Visualisasi Gambar (`chart_generator.py`):** Mengembangkan modul generator grafik visual (PNG) modern berbasis `matplotlib` dengan tema gelap (Dark Theme) selaras antarmuka NetMon. Menghasilkan kurva throughput WAN IN (Neon Cyan) dan WAN OUT (Emerald Green) lengkap dengan arsiran area, grid, timeline waktu lokal, legenda statistik (Peak, Avg, Current), dan watermark NetMon.
    - **Sinkronisasi Rentang Waktu dengan NetMon:**
      - Mendukung seluruh rentang waktu resmi NetMon:
        - `1h` (1 Jam terakhir, interval ~1 menit)
        - `6h` (6 Jam terakhir, interval ~5 menit)
        - `24h` (24 Jam terakhir, interval ~15 menit — sesuai grafik harian NetMon)
        - `7d` (7 Hari terakhir, interval ~2 jam — sesuai laporan mingguan NetMon)
        - `30d` (30 Hari / 1 Bulan terakhir, interval ~6 jam — sesuai laporan bulanan NetMon)
    - **Perintah Bot `/chart` (atau `/grafik`, `/plot`):**
      - `/chart` — Mengirimkan gambar grafik Total Backbone 24 Jam terakhir secara instan.
      - `/chart <rentang>` (contoh: `/chart 1h`, `/chart 7d`, `/chart 30d`) — Grafik agregat dengan rentang waktu fleksibel.
      - `/chart <router> [rentang]` (contoh: `/chart core 7d` atau `/chart 192.168.1.1 24h`) — Visualisasi throughput router spesifik.
      - `/chart select` — Menu pemilih router interaktif khusus visualisasi grafik.
    - **Keyboard Interaktif Dinamis & In-Place Media Editing (`editMessageMedia`):**
      - Setiap gambar grafik yang dikirim ke Telegram dilengkapi tombol pintasan rentang waktu (`[1 Jam]`, `[6 Jam]`, `[24 Jam]`, `[7 Hari]`, `[30 Hari]`, `[Pilih Router]`, `[Total Backbone]`).
      - Saat pengguna menekan tombol rentang waktu, gambar grafik otomatis berganti secara *in-place* di Telegram tanpa membanjiri chat dengan pesan baru.
    - **Integrasi Seamless dengan Perintah `/traffic`:**
      - Menambahkan tombol pintasan `[📈 Grafik 24 Jam]` dan `[📊 Grafik 7 Hari]` langsung di bawah pesan respons `/traffic all` maupun rincian `/traffic <router>` sehingga pengguna dapat beralih antara mode teks dan grafik gambar hanya dengan 1 sentuhan.
    - **Optimasi Query Data Time-Series (`database.py`):** Menambahkan method `get_chart_traffic_data(device_id, time_range)` dengan bucketing SQL agregat berpresisi tinggi dan konversi waktu lokal (`'localtime'`).
    - **Sinkronisasi Dependensi (`requirements.txt` & `update.sh`):** Menambahkan `matplotlib>=3.7.0` pada `requirements.txt` yang otomatis diinstal oleh skrip update server tanpa mempengaruhi database.

16. **Perbaikan Menyeluruh Bug Lonjakan Traffic di Atas Threshold SFP & Pemulihan Hard Cap 5 Gbps:**
    - **Akar Masalah (Root Cause):** Pada pembaruan sebelumnya, setting batas anomali `anomaly_cap_gbps` tidak sengaja termigrasi naik dari `5.0 Gbps` ke `10.0 Gbps` dan `anomaly_cap_multiplier` dari `1.05` ke `1.25`. Selain itu, saat terjadi lonjakan traffic abnormal, data yang melebihi batas link malah di-cap ke batas maksimum port fisik (`min(wan_in_bps, effective_speed)`) dan tetap disimpan ke database, alih-alih di-drop (`return None`) atau di-nolkan. Akibatnya, pada router dengan modul SFP/SFP+ 10G (namun bandwidth ISP sebenarnya hanya 5–6 Gbps), glitch counter SNMP mencatat lonjakan traffic mustahil hingga 10 Gbps ke database dan merusak grafik dashboard.
    - **Pemulihan Aturan Mutlak & Hard Cap SFP / ISP:**
      - Mengembalikan `anomaly_cap_gbps` ke **`5.0 Gbps`** (plafon absolut batas total ISP untuk link 10G SFP+).
      - Mengembalikan `anomaly_cap_multiplier` ke **`1.05`** (buffer 5% di atas kapasitas link).
      - Menghubungkan batas interface dengan pengaturan `uplink_speed_mbps` per-perangkat di database: jika port fisik SFP+ berkapasitas 10G namun setting uplink router diatur 1G atau 5G, batas efektif akan mengunci pada nilai terkecil (`min(speed_bps, uplink_bps_fallback)`), sehingga traffic tidak dapat melampaui kapasitas langganan.
    - **Penolakan Sampel Anomali Ekstrem (Drop & Zero-Out):**
      - Pada `_poll_router_traffic`: Setiap sampel traffic yang melebihi `limit_bps` seketika di-drop dengan mengembalikan `None`, mencegah data anomali merusak grafik dashboard dan metrik WAN.
      - Pada `collect_interface_traffic`: Sampel per-interface yang melebihi `limit_bps` otomatis di-reset ke `0.0`.
    - **Pembersihan Otomatis Data Korup Historis (`database.py`):**
      - Menambahkan migrasi pembersihan otomatis saat startup aplikasi di `_init_db()` untuk langsung menolkan data historis anomali yang sempat tersimpan melebihi batas SFP (`MIN(uplink_speed_mbps * 1.05, 5.0 Gbps)`) pada tabel `snmp_metrics`, `devices`, dan `interface_traffic`.
      - Menyelaraskan kembali input default dan nilai fallback pada `templates/settings.html`.

17. **Perbaikan Menyeluruh Bug Opsi Perintah `/chart`, Filter Agregasi Router BGP, & Visualisasi Utilisasi Bandwidth:**
    - **Akar Masalah Bug Opsi Grafik Telegram:**
      - Pada Telegram Bot API, method `editMessageMedia` tidak dapat dipanggil pada pesan teks (menghasilkan error `Bad Request: there is no media in the message to edit`). Saat pengguna membuka chart dari menu teks (seperti `/chart select` atau `/traffic`), bot gagal memperbarui pesan secara in-place.
      - Sebaliknya, method `editMessageText` tidak dapat dipanggil pada pesan foto/media (menghasilkan error `Bad Request: there is no text in the message to edit`). Akibatnya, saat pengguna berada pada tampilan grafik foto dan menekan tombol `[🔀 Pilih Router Lain]` atau `[📋 Teks Traffic]`, tombol tidak merespons sama sekali (dead button).
      - Menekan tombol rentang waktu yang sama atau tombol Refresh memicu error `Bad Request: message is not modified` yang sebelumnya menyebabkan bot memicu fallback dan mengirimkan foto duplikat berulang-ulang ke chat.
    - **Solusi Transisi Pesan Cerdas (Text <-> Media Seamless Transition):**
      - Menambahkan method `delete_message(chat_id, message_id)` pada `TelegramBot`.
      - Memperbarui `edit_message_text()`: Jika pesan target adalah pesan media/foto, bot otomatis menghapus pesan foto lama tersebut dan mengirimkan pesan teks baru beserta inline keyboard-nya tanpa error.
      - Memperbarui `edit_message_media()`: Menangani fallback parsing HTML entities dan memastikan foto ter-update secara in-place.
      - Pada `_send_or_update_chart()`: Jika dipanggil dari pesan teks (seperti tombol pemilih router), bot otomatis membersihkan pesan teks pemilih dan mengirimkan foto grafik baru yang segar; jika terjadi kondisi `message is not modified`, bot mengabaikannya dengan aman tanpa spamming foto duplikat.
    - **Filter Ketat Agregasi Router (Agregasi ON) vs Router BGP Tunggal:**
      - **All Traffic / Total Backbone:** Seluruh perhitungan agregat WAN In, WAN Out, dan Total Throughput pada `/traffic`, `/traffic all`, `/chart`, dan `/chart all` kini secara ketat HANYA menjumlahkan router dengan `include_in_aggregate = 1`. Router cabang atau router non-backbone dengan `include_in_aggregate = 0` tidak lagi menggelembungkan throughput backbone.
      - **Total Kapasitas Uplink Backbone:** Dihitung secara dinamis dari `SUM(uplink_speed_mbps)` seluruh router agregasi aktif (`include_in_aggregate = 1`), bukan lagi nilai statis/hardcoded.
      - **Router BGP / Tunggal (Pilihan User):** Pengguna dapat memilih router BGP/Core spesifik melalui menu interaktif (`/traffic select`, `/chart select`) atau langsung via perintah (`/traffic <nama>`, `/chart <nama>`). Disediakan deteksi otomatis kata kunci peranan seperti `bgp`, `core`, `edge`, dan `gateway`.
      - Pada daftar router ditampilkan badge status yang jelas: `[Agg ON]` atau `[Agg OFF]`, serta tanda `[BGP]`.
    - **Pemisahan Jelas antara Traffic Throughput vs Bandwidth Usage:**
      - **Traffic Throughput (Laju Aliran Data):** Menampilkan laju transfer data aktual dalam satuan Mbps / Gbps (Terkini / Current, Puncak / Peak, dan Rata-rata / Average) untuk WAN IN (Download) dan WAN OUT (Upload).
      - **Bandwidth Usage (Utilisasi Kapasitas Pipa):** Menampilkan persentase pemakaian link (`%` terhadap kapasitas uplink), visualisasi progress bar (`[████░░░░]`), kapasitas total link/uplink, serta sisa ruang kapasitas bebas (*headroom*).
      - Keduanya disajikan secara terstruktur dan informatif pada gambar grafik PNG (`chart_generator.py`) maupun teks caption bot Telegram (`telegram_bot.py`).

18. **Pengkhususan Traffic Top 10 & All Router Hanya Uplink WAN, Serta Tampilan Active Ports Pada Selected Router:**
    - **Top 10 HANYA Menampilkan Uplink (`/top`):**
      - Mengubah implementasi `get_top_bandwidth_interfaces()` di `database.py`: jika sebelumnya mengambil seluruh interface mentah (termasuk bridge, vlan internal, atau port lokal), kini secara mutlak HANYA meranking dan menampilkan traffic **Uplink WAN** (`wan_in` + `wan_out`) antar router.
      - Setiap entri top 10 menampilkan ranking (1-10), nama router, IP, nama port uplink fisik (misal `sfp-sfpplus1` atau `ether1-WAN`), laju Inbound (RX), Outbound (TX), Total Throughput, persentase utilisasi bandwidth terhadap kapasitas uplink beserta progress bar, dan badge status `[Agg ON]` / `[BGP]`.
    - **All Router HANYA Menampilkan Ringkasan Uplink (`/traffic all`):**
      - Pada tampilan `/traffic` atau `/traffic all`, antarmuka difokuskan 100% pada performa kapasitas Uplink Backbone (Inbound, Outbound, Total, dan Utilisasi Uplink).
      - Rincian port individual internal dihilangkan dari tampilan Semua Router agar tidak membingungkan dan menjaga fokus pemantauan pada link uplink utama.
    - **Selected Router BARU Menampilkan Active Ports (`/traffic <router>`):**
      - Menambahkan parameter `active_only=True` pada `get_latest_device_interface_traffic()` di `database.py` yang menyaring interface sehingga HANYA port dengan traffic aktif (`rx_bps + tx_bps > 0`) yang dimunculkan.
      - Saat pengguna memilih router tertentu via `/traffic <nama>` atau picker, bot menampilkan ringkasan performa Uplink WAN di atas, kemudian menyajikan rincian **Active Ports** yang sedang mengalirkan traffic, lengkap dengan penanda `[Uplink WAN]` pada port uplink-nya. Port idle/dormant (0 bps) otomatis disembunyikan.

19. **Penyelarasan Dinamis Provider AI Aktif (Google AI Studio vs Groq Cloud) & Optimasi Perintah AI Telegram:**
    - **Resolusi Dinamis Provider AI Aktif (`ai_detector.py`):**
      - Menambahkan fungsi publik `get_active_ai_info(db)` yang mengembalikan status konfigurasi, provider aktif (`Google AI Studio` vs `Groq Cloud`), nama model riil (`gemini-flash-lite-latest` atau `llama-3.3-70b-versatile`), serta pengaturan privasi masking IP.
      - Menyelaraskan modul `database.py` (`_filter_spikes_with_ai`) agar tidak lagi hardcoded ke endpoint Groq, melainkan menggunakan `_call_llm_completion` yang secara otomatis mendukung Google AI Studio maupun Groq Cloud saat filter outlier traffic bulanan.
      - Menambahkan rincian alokasi multi-ISP kampus ke dalam telemetri snapshot (`build_noc_telemetry_context`).
    - **Pembersihan String Hardcoded & Tampilan Engine Dinamis (`telegram_bot.py`):**
      - Menghapus seluruh teks hardcoded "Groq" pada pesan callback query (`ai_alert:`, `ai_dev:`), menu `/help`, pengantar perintah `/ai`, dan Daily Digest.
      - Pesan progress dan respons AI kini secara dinamis menampilkan badge engine aktif, contoh: `Google AI Studio • gemini-flash-lite-latest` atau `Groq Cloud • llama-3.3-70b-versatile`.
      - Perintah `/help`, `/ai`, dan Daily Digest kini menampilkan kapasitas total multi-ISP kampus secara dinamis (mengacu pada total kapasitas ISP yang dikonfigurasi).
    - **Optimasi Formatting & Prompt AI Telegram:**
      - Mengoptimalkan converter Markdown-to-Telegram HTML (`_format_ai_html`) dengan memproteksi blok kode (`<pre><code>`), inline code (`<code>`), konversi heading `#` ke `<b>`, formatting bold, dan penataan daftar poin `•` tanpa menyebabkan parse error pada Telegram Bot API.
      - Memperketat `system_prompt` pada `ask_groq_noc` / `ask_ai_noc` agar jawaban AI padat, teknis, solutif (di bawah 300 kata), langsung to-the-point untuk operator NOC, dan menyertakan perintah RouterOS yang tepat.

20. **Visualisasi Persentase Utilisasi Bandwidth Total Internet Kampus Utama pada Laporan Bulanan (`reports.html` & `database.py`):**
    - **Perhitungan Agregat & Rasio Utilisasi (`database.py`):**
      - Pada `generate_and_save_monthly_report`, sistem menghitung rasio utilisasi bandwidth backbone terhadap total kapasitas ISP kampus utama (`utilization_peak_pct`, `utilization_avg_pct`, `utilization_p95_pct`, serta utilisasi in/out).
      - Menghitung pula persentase utilisasi uplink per router individu terhadap kapasitas port uplink masing-masing.
    - **Panel Highlight Utilisasi Bandwidth Kampus (`reports.html`):**
      - Menambahkan kartu highlight visual di Section 1 Laporan Bulanan yang menampilkan kapasitas total internet kampus (misal `6.0 Gbps`), persentase utilisasi puncak (Peak), persentase P95, persentase rata-rata (Avg), dan progress bar indikator kapasitas (hijau <70%, kuning 70-85%, merah >85%).
      - Tersedia fallback penghitungan dinamis di sisi browser agar laporan historis lama tetap dapat menampilkan persentase utilisasi tanpa perlu digenerate ulang.
    - **Integrasi Tabel & Tooltip Grafik:**
      - Menambahkan baris footer (`<tfoot>`) ringkasan `TOTAL BACKBONE KAMPUS` pada tabel *Detail Uplink per Router* lengkap dengan total volume, rata-rata, P95, dan persentase utilisasi puncak.
      - Menampilkan persentase utilisasi uplink per router pada kolom *Puncak (Down/Up)*.
      - Memperbarui tooltip grafik agregat backbone agar menampilkan angka laju Mbps sekaligus persentase utilisasi terhadap kapasitas total internet kampus.
      - Memastikan seluruh elemen baru tampil proporsional pada tampilan layar web, mode cetak (Print), maupun ekspor dokumen PDF.

21. **Tema Kustom Personal "Polije Signature — Kampus SIP" (`style.css`, `base.html`, `login.html`, `settings.html`):**
    - **Palet Identitas Resmi Polije (`polije.ac.id` & Branding SIP):**
      - Mengadopsi warna resmi institusi Politeknik Negeri Jember: *Academic Royal Navy* (`#0a2a5e`), *Bondi/Sky Blue* (`#028daa` / `#0ea5e9`), *Golden Rice* (`#f5b700` — 9 bulir padi), *Hijau Vokasi* (`#16a34a`), dan *Merah Jember* (`#dc2626`) baik untuk mode Light (nuansa portal kampus) maupun Dark (mode NOC shift malam).
    - **Elemen Personal Kampus:**
      - Pita gradien 4 warna SIP di puncak sidebar dan kartu login.
      - Sidebar Navy dengan pill motto `SMART • INNOVATIVE • PRO`, garis aksen emas di bawah logo Polije, dan indikator menu aktif biru-emas.
      - Sticky page header dengan garis bawah gradien Navy–Bondi–Emas ala header portal `polije.ac.id`, serta kartu KPI/panel dengan border-top aksen biru-emas.
      - Pratinjau tema langsung (*live preview*) dan kartu palet warna identitas Polije pada halaman Settings (`UI Theme`).
