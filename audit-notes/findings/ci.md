# ci

- B-0002: tam crate derlemesi bu ortamda yapilamiyor (rustc OOM, 1.98 GB).
- B-0010: PR #188 workflow lari tetiklendi, rapor yazildigi anda hepsi queued.

Run id leri rapor bolum 1 ve bolum 2 B-0010.

## B-0011 - Kuyruk doygunlugu (yeni)

- **Konum:** `.github/workflows/` = 33 workflow; her PR'da hepsi tetikleniyor.
- **Önem:** orta (süreç)
- **Ne yanlış:** PR #188 ve #189 için 30+30 run tetiklendi, iki dakika sonra hepsi hâlâ `queued`. Açık PR sayısı 6.
- **Neden yanlış:** 33 workflow × 6 PR = ~200 run; her PR için tam matris. Kapı tasarımı "her şeyi her PR'da çalıştır" ise kuyruk, kapıların kendisini geciktirir ve "CI kırmızı" ile "CI çalışmadı" ayırt edilemez hale gelir.
- **Neye yol açar:** İncelenen PR'ların gerçek durumu bilinmez; yazar yeşil sanır.
- **Nasıl düzeltilir:** Strix'in kendi reposunda yaptığı gibi (commit 0601550: "fold CI into one workflow with job timeouts and path-gate the binary and workflow lint"): (1) `paths:` filtresiyle yalnız dokunulan alanın kapıları, (2) ağır işler (fuzz, Miri, kani, docker) `schedule` + `workflow_dispatch`'e, (3) PR'da zorunlu tek bir "gate summary" job'u.
- **Durum:** açık. Bu turda değiştirilmedi (workflow dosyası değişikliği ayrı PR ve ayrı kanıt ister).

## Tur 2

B-0012 … B-0018 için `findings/round2.md`. Kuyruk ölçümü, superseded iptaller ve depodaki fan-out çözüm deseni orada.
