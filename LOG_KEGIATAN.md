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
