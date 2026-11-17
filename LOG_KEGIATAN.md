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
