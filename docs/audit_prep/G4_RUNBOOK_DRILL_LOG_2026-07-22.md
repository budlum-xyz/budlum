# G4 — Production Runbook Drill Log (2026-07-22)

**Drill:** G4 — backup/restore + emergency halt + 4-node devnet smoke rehearsal
**Sahip:** Ayaz (operasyonel) · **Hazırlayan:** ARENA1
**Yöntem:** Sandbox'ta Docker yok → **doc-only rehearsal**. Gerçek docker drill'i CI runner'ında `docker-smoke.yml` (`devnet-multinode-smoke`) koşar. Bu log her adımı gerçek prosedür/scrip'e bağlar ve CI-side yürütmeyi doğrular; uydurma içerik yok (rule 6).
**Kural:** CI yegâne yargıç. Bu log CI'ı bypass edemez; sadece operasyonel drill'in hazır olduğunu kanıtlar.

---

## Doğrulanan altyapı (code/script düzeyinde)

| Bileşen | Kanıt | Durum |
|---|---|---|
| Backup/restore script | `ops/backup_restore_drill.sh` | ✅ mevcut |
| 4-node devnet smoke script | `scripts/devnet-multinode-smoke.sh` | ✅ mevcut |
| Docker mainnet smoke script | `scripts/docker-smoke-mainnet.sh` | ✅ mevcut |
| RPC smoke script | `scripts/task3_smoke_rpc.sh` | ✅ mevcut |
| Compose dosyası | `docker-compose.yml` | ✅ mevcut |
| Archive şablonu | `config/archive.toml` | ✅ mevcut |
| CI docker-smoke gate | `.github/workflows/docker-smoke.yml` | ✅ mevcut (2 job) |
| Emergency-halt mekanizması | `src/core/constitution.rs` `MaxEmergencyHaltEpochs` (1–10080 epoch) + `src/core/governance.rs` | ✅ mevcut |

**Sandbox:** Docker binary yok, `/var/run/docker.sock` yok → G4 burada doc-only.

---

## Drill A — Backup / Restore

**Kaynak prosedür:** `docs/operations/ARCHIVE_AND_BACKUP.md` (Task 0.37)

### A.1 Scheduled backup davranışı (kod kesinleşti)
Archive node (`role = "archive"`) fail-closed: `pruning=false` + `backups_enabled=true` + `backup_dir` set + interval/retention nonzero olmadıkça açılmaz. Backup akışı: sled flush → `*.partial` + fsync → atomik rename → SHA-256 checksum + duplicate-key/schema kontrolü → `backup_retention_count` rotasyon.

### A.2 One-shot offline backup prosedürü
```bash
sudo systemctl stop budlum-core
budlum-core --db-path /var/lib/budlum/data --backup-dir /var/lib/budlum/backups \
  --backup-retention-count 168 --backup-now
sudo systemctl start budlum-core
```
Kural: canlı sled dizini `cp`/`rsync` ile kopyalanmaz.

### A.3 Restore drill prosedürü (otomatik)
```bash
BUDLUM_BIN=target/release/budlum-core \
SOURCE_DB=/var/lib/budlum/data \
BACKUP_DIR=/var/lib/budlum/backups \
ops/backup_restore_drill.sh
```
Restore hedefi boş/olmalı (üzerine yazmaz). `--restore-backup` decode + bounded batch import + storage/migration + chain integrity check. Sıfır-olmayan exit veya integrity hatası drill'i düşürür.

### A.4 Recovery acceptance checklist (gerçek drill'de doldurulur)
- [ ] Kaynak canonical height + son finalized hash drill öncesi kaydedildi.
- [ ] Restore ayrı volume'da temiz path'e yapıldı.
- [ ] `--check-db` bozulma raporlamadı.
- [ ] Restore edilmiş DB'de read-only/archive süreç karşılaştırması: height, finalized hash, domain registry root, son global header hash.
- [ ] Restore süresi + backup boyutu kaydedildi.
- [ ] Node failure-domain dışında en az bir test edilmiş kopya.
- [ ] Restore edilen node sync + health başarılı olmadan eski DB silinmedi.

**G4 sandbox durumu:** Script + prosedür hazır. Gerçek yürütme CI runner / operator host'ta (Docker/gerçek binary). ⏳

---

## Drill B — Emergency Halt

**Kaynak prosedür:** `docs/MAINNET_LOCKDOWN_CHECKLIST.md` (Emergency procedures) + `docs/operations/PRODUCTION_RUNBOOK.md` §6.

### B.1 Halt mekanizması (kod kesinleşti)
Halt, **governance proposal** ile tetiklenir; `MaxEmergencyHaltEpochs` constitution parametresi süreyi sınırlar (**1–10080 epoch**). `src/core/constitution.rs` validation + `src/core/governance.rs` proposal akışı. Halt statik bir TOML flag'i değil — onaylanmış bir governance action.

### B.2 Halt tetik kriterleri (sadece bunlar)
- Sistemik konsensüs hatası
- Signer-integrity (imzalama) riski
- State-root bozulması
- Bridge-safety riski

### B.3 Olay müdahale prosedürü (PRODUCTION_RUNBOOK §6)
1. Etkilenen domain'in bridge'ini devre dışı bırak.
2. DB/log kanıtlarını koru.
3. Operator mutasyonlarını durdur.
4. Son finalized global header'ı tespit et.
5. **Yalnızca test edilmiş backup'tan** restore et.
6. sled anahtarlarını manuel düzenleme.

### B.4 İletişim (no silent rollback)
- Public incident record: etkilenen SHA/range, kök neden, operator acknowledgement.
- Incident hash yayınla, affected range, önerilen operator aksiyonu, sonraki checkpoint.
- Recovery önceliği: parametre disable > domain freeze > validator rotation > chain rollback (rollback en son).

### B.5 Halt drill adımları (gerçek drill'de doldurulur)
- [ ] Bir halt proposal'ı testnet/devnet'te submit + onay akışı çalıştırıldı.
- [ ] Halt aktifken blok üretiminin durduğu doğrulandı.
- [ ] `MaxEmergencyHaltEpochs` süresi dolduğunda otomatik resume doğrulandı.
- [ ] Manual resume path (governance) test edildi.

**G4 sandbox durumu:** Mekanizma kodda hazır. Canlı halt tetik testi CI/devnet'te. ⏳
**Açık not:** Halt proposal'ının tam execution path'i (blok üretimini hangi koşulda durdurur) canlı drill'de teyit edilmeli — bu log mekanizmanın varlığını kanıtlar, runtime davranışı değil.

---

## Drill C — 4-Node Devnet Smoke

**CI gate:** `.github/workflows/docker-smoke.yml` → job `devnet-multinode-smoke`
**Script:** `scripts/devnet-multinode-smoke.sh`

CI job adı: *"Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon)"*. Çalıştırdığı: 4-node compose smoke (mesh/liveness/metrics/RPC-izolasyon). Başarısızlıkta `docker compose ... logs --tail=150` + cleanup (`down -v --remove-orphans`).

Ek olarak `docker-smoke` job: image build + trivy IMAGE scan (CRITICAL/HIGH = fail) + RPC smoke (devnet) + Docker mainnet smoke.

### C.1 CI-side doğrulama (gerçek CI run'da doldurulur)
- [ ] Son `devnet-multinode-smoke` CI run'u yeşil (4-node mesh liveness).
- [ ] Son `docker-smoke` CI run'u yeşil (trivy + mainnet smoke).
- [ ] metrics scrape başarılı (operator-RPC izolasyonu korunuyor).

**G4 sandbox durumu:** CI gate mevcut ve tasarım gereği bu drill'i koşuyor. Sandbox'ta Docker olmadığından yürütme CI'a ait. ⏳

---

## Özet — ne doğrulandı, ne bekliyor

| Durum | Kapsam |
|---|---|
| ✅ **Doğrulandı** | Tüm script'ler/dosyalar mevcut; CI gate mevcut; halt mekanizması kodda; prosedürler dokümante. |
| ⏳ **Bekliyor (CI/operator)** | Gerçek backup/restore yürütmesi; canlı halt tetik/resume testi; `devnet-multinode-smoke` + `docker-smoke` CI run'larının yeşil teyidi. |

**G4 tamamlanma kriteri (doc-only rehearsal için):** Yukarıdaki ✅ satırları + bir sonraki CI run'ında `devnet-multinode-smoke` ve `docker-smoke` job'larının yeşil olması. Gerçek runtime halt/restore davranışı operator host'ta ayrı bir canlı tatbikat gerektirir (G4'ün donanım/insan boyutu — Ayaz).

---

## Sign-off

| Rol | Onay | Tarih |
|---|---|---|
| ARENA1 (doc-only rehearsal) | ⏳ CI yeşil sonrası | 2026-07-22 |
| Ayaz (canlı operator drill) | ⏳ donanım/host gerekli | — |

*Bu log G4 doc-only rehearsal'ıdır. CI run linkleri eklenerek kapatılır; "kapalı" işareti ancak bağımsız doğrulanabilir kanıtla (CI run) kullanılır (talimat genel kural 3).*
