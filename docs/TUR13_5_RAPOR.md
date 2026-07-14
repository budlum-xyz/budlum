# TUR 13.5 RAPOR — Tek repo + PoW light-client + operasyon

**Tarih:** 2026-07-14  
**Dal:** `arena/019f5dd7-budlum`

## Tamamlananlar

### 1. Budlum + BudZero tek repo

- `lubosruler/BudZero` kaynak ağacı `budzero/` altına alındı.
- L1 path dependency'leri artık in-tree.
- CI iki bağımsız kapı çalıştırır: Budlum Core ve tam BudZero workspace.
- Docker build harici repo klonlamaz; aynı commit'ten prover/verifier üretir.

### 2. PoW header-chain finality ve bridge

- Yeni `PoWHeader`, `PoWDomainParameters`, `PoWHeaderChain` proof'u ve
  `pow-header-chain-v1` adapter'ı.
- Target header commitment height/parent/state/tx/event root'larına bağlıdır.
- Her hash, nonce, difficulty, parent link, height, timestamp ve work yeniden
  hesaplanır; header sayısı 4096 mutlak tavan + domain tavanıyla sınırlıdır.
- Mint yalnız header-chain adapter'lı ve applied contiguous tip üzerindeki PoW
  commitment'larından yapılır.
- Eski `pow-confirmation-depth` decode/arsiv uyumluluğu için kalır, mint yetkisi
  yoktur.
- Pozitif mint + bozuk parent-link negatif regresyon testleri eklendi.

### 3. Archive / backup / restore

- Archive rolü pruning açıkken veya backup kapalıyken başlamaz.
- Sled backup: flush → SHA-256 payload checksum → `.partial` → fsync → atomic
  rename → decode/schema/key doğrulama → retention.
- Restore yalnız boş hedefe bounded batch import eder ve normal
  migration/integrity yolunu çalıştırır.
- `--backup-now`, `--restore-backup`, periyodik backup ve
  `ops/backup_restore_drill.sh` eklendi.

### 4. RPC ve observability

- Per-IP quota map'i 10.000 aktif istemciyle sınırlandı; expired kayıtlar
  opportunistic temizlenir.
- İmzasız yönetim yardımcıları public RPC'de reddedilir (domain/asset kaydı,
  global header seal, legacy direct bond); permissionless signed Stake yolu
  public kalır.
- Block propagation, consensus round ve storage read/write histogramları canlı
  yollara bağlandı; settlement sayaçları bağlandı.

### 5. BudZero Phase 10 baseline

```bash
cargo bench --manifest-path budzero/Cargo.toml -p bud-proof --bench proof_baseline
```

Harness JSON olarak sample sayısı, trace row, proof bytes ve ortalama
prove/verify süresini basar. Bu bir performans iddiası değil, karşılaştırılabilir
başlangıç ölçümüdür.

## Persona uyumu

| Yüzey | User | Developer | Enterprise PoA |
| --- | --- | --- | --- |
| Aynı binary / aynı repo commit | ✓ | ✓ | ✓ |
| Public RPC quota | localhost | configurable | auth + network policy |
| PoW bridge verify | header-chain verify | proof üret/test | policy kontrollü |
| PoA üretim | — | devnet | PKCS#11 Ed25519; BLS/PQ Tur 13.9 |
| Backup/restore | isteğe bağlı | drill | zorunlu operasyon politikası |

## Açık kalan (Tur 13.9)

- BLS/PQ HSM protection yolu ve dürüst capability matrisi.
- Finality live-path son taraması.
- ConsensusStateV2 staged migration dokümanı/hook'u.
- Harici audit teslim checklist'i (audit yapılmış sayılmayacak).
- README roadmap kapanış tablosu ve devir notunun son güncellemesi.

**B.U.D. kodu bu turda yazılmadı; tamamı Tur 14 kapsamındadır.**
