# RunbookOS — rangkuman proyek dan status terakhir

**Diperbarui: 6 November 2026.** Sumber status: kode dan Git saat ini, laporan penerimaan terdahulu, serta ledger Batch 04 di luar repository. Angka kampanye adalah hasil yang tercatat, bukan jaminan keandalan produksi.

## Tujuan besar

RunbookOS dibangun sebagai platform operasi infrastruktur terpusat yang menghubungkan insiden, pemilihan target, diagnostik terdaftar, evidence berprovenance, analisis Qwen lokal, penilaian terstruktur, usulan tindakan, policy dan persetujuan manusia, remediasi terdaftar, pemeriksaan hasil yang independen, audit, serta tampilan CLI/dashboard. Arsitekturnya mengutamakan koneksi agentless. Teks AI bersifat advisory: keputusan AI tidak memberi izin eksekusi, tidak menghasilkan shell bebas, dan sitasi evidence tidak membuktikan sebab secara semantik.

## Lingkungan dan komponen

- Repository: `/home/morphious/united/runbookos`; branch `feat/v0.7.0-evidence-aware-assessment`; HEAD committed `d68197c3ac37336e1b9bfa8d66059e5eb8ecd001`. Worktree berisi banyak perubahan serta file historis yang belum di-commit; jangan menganggap HEAD mencakup implementasi terkini.
- Homelab KVM/libvirt `qemu:///system`: `ops-01` sebagai controller; `svc-web-01`, `svc-app-01`, `db-01`, dan `net-01` sebagai node web, aplikasi, database, dan jaringan. Instalasi v0.7.0 terisolasi pada `ops-01` di `/var/lib/runbookos/acceptance-v070/`; instalasi v0.6.0 dipertahankan.
- Model kampanye adalah Qwen 3.5 9B Q5_K_M melalui llama.cpp dengan API terautentikasi dan transport controller yang dibatasi. Per 6 November, tidak ada runner Batch 04 atau server Qwen 9B kampanye yang aktif menurut pemeriksaan proses; proses llama-server lain pada port 8081 memakai model berbeda dan tidak boleh dianggap milik kampanye.
- Kode utama: `src/runbookos/` untuk registry aksi, engine, policy, AI, assessment, proposal remediasi, persistence, audit, CLI, dashboard, dan koneksi remote. Kampanye disposable berada di `scripts/campaign_batch04*.py`; ledger privat ada di `/home/morphious/.local/state/runbookos/campaign-batch04/batch04-ledger.json`.

## Pencapaian yang sudah dibuktikan

1. **M1/M2:** `StructuredAssessment` mencatat observasi, provenance, status assertion/verifikasi, klasifikasi, confidence model, ketidakpastian, dan referensi evidence. Validator deterministik menolak referensi palsu dan kombinasi status yang tidak sah.
2. **M3:** evaluator offline dan 24 kasus sintetis terpisah dari gold labels. Benchmark Qwen Minimal Semantic Reply v2 menghasilkan **21/24 assessment diterima**; akurasi klasifikasi pada 13 jawaban yang diterima dan berlabel **11/13**. Ini hasil sintetis; semantic support dan ketepatan akar sebab nyata **belum diukur**.
3. **M4/M5 dan demo:** incident, investigation, assessment, dan evidence dapat dipersist dan ditinjau melalui CLI serta dashboard terautentikasi. Demo offline memakai data sintetis. Audit SQLite dan pemeriksaan integritas tersedia.
4. **Homelab:** lima VM pernah ditemukan berjalan; diagnostik read-only nyata pada empat node pernah berhasil dengan host-key SSH yang dipin. Bukti ini tidak otomatis memvalidasi semua endpoint atau semua kegagalan layanan.
5. **Kampanye operasional terdahulu:** satu workflow awal, Batch 01 sepuluh, Batch 02 sepuluh, dan Batch 03 sepuluh workflow selesai menurut ledger/laporan masing-masing: **31 workflow historis**. Batch 01/02 memakai pemilihan tindakan operator; jangan menghitungnya sebagai keputusan remediasi AI. Batch 03 memakai proposal Qwen, tetapi terdapat banyak percobaan gagal yang tetap tersimpan.
6. **Batch 04:** tindakan yang benar-benar berbeda telah digunakan, termasuk pemulihan service, konfigurasi, worker, backend, PostgreSQL disposable, DNS, jaringan terisolasi, storage, dan quota resource. Proposal Qwen divalidasi terhadap action/target/parameter, evidence, policy, approval satu kali, dan postflight. Kasus gabungan menggunakan investigasi baru untuk fault yang tersisa.

## Progres terakhir Batch 04

Ledger terakhir mencatat **101 percobaan, 18/20 skenario `AI_DRIVEN_PASS`**: Group A **10/10**, Group B **8/10**. Skenario B04-01 sampai B04-18 lulus; B04-19 dan B04-20 gagal pada proposal Qwen dengan kategori tersanitasi `provider_timeout`. Cleanup kedua percobaan gagal tercatat PASS. Ringkasan ledger memuat **181 request Qwen terakuntansi**; ini angka ledger, bukan klaim bahwa seluruh respons valid. Jika 31 workflow historis dihitung terpisah, total yang tercatat selesai menjadi **49**, dengan kriteria AI-driven Batch 04 hanya berlaku untuk 18 kasus Batch 04. Tidak ada 20/20 atau 51 workflow yang boleh diklaim saat ini.

Pada sesi perbaikan terakhir, kegagalan pemilihan restart yang bertentangan dengan observasi DNS, jaringan, quota, atau konfigurasi ditangani dengan prasyarat yang berasal dari evidence. Katalog kandidat lengkap tetap terlihat oleh model, sementara pilihan output terstruktur menolak tindakan yang terbukti tidak cocok. Probe kesehatan fixture diberi waktu yang cukup untuk menangkap kode `worker-resource-pressure` di dalam anggaran investigasi. Validator assessment produksi tidak dilonggarkan. Regresi offline terakhir yang dijalankan setelah perubahan tersebut: **508 passed, 11 skipped**; 11 adalah tes live opt-in, bukan bukti PASS live. Group A dan delapan kasus Group B lulus secara live sesudah perbaikan; B04-19/20 belum lulus.

## Status keselamatan dan batas bukti

- Fault injection, tindakan, dan cleanup kampanye dibatasi pada fixture disposable. Gateway `net-01`, layanan utama, database operasional, dan instalasi v0.6.0 tidak menjadi target disposable.
- Eksekusi hanya boleh lewat aksi RunbookOS yang terdaftar, target tepat, policy, approval, dan audit. Kegagalan proposal tidak diubah menjadi abstention atau tindakan operator yang diklaim sebagai pilihan AI.
- Keberhasilan pemulihan layanan tidak membuktikan penjelasan sebab model benar. Referensi evidence yang valid menunjukkan integritas ID saja; adjudikasi semantik dan akurasi akar sebab produksi tetap belum mapan.
- Kualitas kampanye belum stabil pada percobaan pertama: 101 percobaan untuk 18 keberhasilan Batch 04, dengan kegagalan historis dipertahankan. Ledger menyimpan tahap, alasan tersanitasi, tindakan, execution ID, postflight, dan audit. Angka akhir harus dihitung ulang langsung dari ledger sebelum dipublikasikan.
- Status produksi **belum tervalidasi penuh**. Dua skenario Batch 04 masih gagal, dan hasil homelab terbatas pada lingkungan serta fixture yang diuji. Tidak ada dasar untuk mengklaim 100% keandalan lintas server.

## Pekerjaan yang tersisa untuk tujuan saat ini

Diagnosis konkret berikutnya adalah timeout proposal B04-19/20. Periksa metadata durasi, token, ResourceWatch, dan transport yang tersanitasi; pertahankan semua percobaan gagal. Setelah penyebabnya diperbaiki dan diuji, jalankan ulang kedua skenario dengan ID percobaan baru, lalu verifikasi proposal asli Qwen, eksekusi tindakan yang sama, postflight independen, incident closure, audit-chain, SQLite integrity, serta cleanup. Setelah itu validasi ledger lokal dan salinan controller identik, kondisi lima VM, dan resource kampanye yang dimiliki. Jangan mengubah oracle fault atau menyebut pemulihan manual sebagai AI-driven.

Untuk sasaran jangka panjang, RunbookOS perlu dibuktikan pada cakupan operasional yang lebih luas: diagnosis kausal yang diadjudikasi independen, reliabilitas percobaan pertama, backup/restore dan rollback controller, keamanan deployment, serta hasil remediasi beragam di luar fixture disposable. Bukti sintetis dan 18 pemulihan Batch 04 adalah kemajuan nyata, tetapi bukan sertifikasi produksi.

## Rujukan bukti

- `docs/qwen-minimal-assessment-m3-evaluation.md` — metrik benchmark sintetis dan batas interpretasinya.
- `docs/homelab-operational-acceptance.md`, `docs/runbookos-functional-acceptance.md`, `docs/runbookos-production-execution-result.md` — inventaris dan penerimaan homelab sebelumnya.
- `docs/operator-demo-v0.7.0.md` — demonstrasi operator offline.
- Ledger privat Batch 01–04 di `/home/morphious/.local/state/runbookos/` — sumber utama hitungan percobaan dan tindakan nyata; jangan memasukkannya ke rilis publik tanpa sanitasi.

**Status ringkas:** perangkat lunak dan kampanye berjalan pada homelab disposable; Batch 04 **18/20** berhasil, dua kasus timeout proposal belum selesai; produksi belum dinyatakan siap.
