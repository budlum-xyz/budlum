# -*- coding: utf-8 -*-
"""Anket dönüştürücü (ARENA3): 100 soruyu AYNEN korur, non-teknik satırları uzun
jargonsuz metinlerle değiştirir, Q101-Q120'yi 'Son not' öncesine ekler.
Kanıt: python3 scripts/anket_expand_apply.py && git diff --stat"""

import io, sys, importlib.util

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

p1 = load("scripts/anket_expand_p1.py", "p1").NTE
p2 = load("scripts/anket_expand_p2.py", "p2").NTE2
NTE = dict(p1); NTE.update(p2)

SRC = "docs/BUDLUM_100_KARAR_ANKETI_ARENA2_2026-07-17.md"

# ── Q101..Q120: (başlık, teknik, [seçenekler]) — non-teknik NTE'den gelir ──
NEW = [
("Q101 — Köprü geri-dönüş eşleştirmesi: burn mesajı ↔ kilit transferi (correlation zorunluluğu)",
 "`CrossDomainMessage::new_correlated` dönüş (burn) mesajına KENDİ içerik-id'sini verir, `correlation_id = Some(lock_msg_id)` taşır; `BridgeState.transfers` kilit-id ile anahtarlı. `pipeline.unlock` artık `correlation_id.ok_or(PipelineError::MissingCorrelationId)` ile çözümlüyor (d1c89a3), production `blockchain.rs:1388` ile aynı fail-closed model; 2 CI kırmızısının kök nedeni buydu (561/2 → 563/563 mühür c52beb6). (bridge_relayer.rs:255-265, 093d795'ten beri latent)",
 ["A) Correlation zorunlu + fail-closed kalsın (mevcut, production ile birebir)",
  "B) Correlation opsiyonel olsun, yoksa mesaj-id'ye düş (fallback)",
  "C) Köprü dönüşü (burn→unlock) tamamen kaldırılsın, tek yönlü kalsın",
  "D) Transfers haritası her iki id ile de anahtarlansın (dual-index)"]),

("Q102 — Köprüde tek-aktif-transfer kuralı (double-lock koruması)",
 "`BridgeState.lock` → `require_asset_status(asset, Active{domain})`: bir varlık kilitliyken ikinci kez kilitlenemez (`asset_locations` tek-durum haritası). `event_tree_grows_with_locks` testi bu kuralı ihlal ettiği için kırıktı; test iki farklı varlıkla düzeltildi (18bf437, ARENA3 teşhisiyle birebir örtüştü). (bridge.rs:354-368)",
 ["A) Kural kalsın: aynı anda tek aktif transfer (NFT-benzeri model, mevcut)",
  "B) Aynı varlık çoklu kilitlenebilsin (miktar-fungible model, harita yeniden tasarımı)",
  "C) Kural kaldırılsın, replay koruması nonce'a emanet"]),

("Q103 — Otomatik bağımlılık-bump PR'ları (dependabot) politikası",
 "7 açık dependabot PR'ı (#20,#21,#22,#23,#24,#26,#27) CI-matrisinde 7/7 kırmızı: p3 0.5.2→0.6.1 14 paketin yalnız 4'ünü çapraz-uyumsuz bırakıyor (STARK kanıt formatı riski), bincode 2→3 konsensus-kritik byte formatını bozuyor, jsonrpsee 0.26 derlenmiyor. (ARENA3 triyaj 2026-07-17, check-runs kanıtlı)",
 ["A) 7/7 CLOSE + mainnet öncesi bağımlılık dondurma + koordine göç mainnet sonrası",
  "B) Seçmeli kapat (derlenmeyenler hemen, p3'ler açık kalsın)",
  "C) PR'lar açık kalsın, branch'leri elle güncelle",
  "D) Dependabot tamamen kapatılsın"]),

("Q104 — Konsensus-kritik kütüphane göç protokolü (bincode / p3 / byte-format)",
 "bincode 2→3 Encode/Decode API overhaul ve p3 0.5.2→0.6.1 familiy-wide geçiş: ikisi de konsensus-kritik byte formatlarını ve STARK kanıt byte'larını etkileyebilir → eski kanıtlar/veriler okunamaz hale gelebilir. (PR #21/#27 log: Encode trait eksik)",
 ["A) Dondur + tek koordine göç penceresi: tüm familia aynı anda, format-versiyon testiyle (öneri)",
  "B) Sadece güvenlik yamaları, minor/patch serbest, major her durumda dondurulmuş",
  "C) Serbest güncelleme, CI yeşilse geç",
  "D) Vendoring: kritik kütüphaneleri repo içine kopyala, upstream'i takip etme"]),

("Q105 — Push öncesi yerel kalite kapısı (pre-push-check.sh) zorunluluğu",
 "CI kök-neden analizi: kırmızı zincirler fmt/clippy'siz push'tan (9be811b, 749d27f, dbc99b0). `scripts/pre-push-check.sh` (fmt+clippy+test) önerildi; bu soru protokol seviyesini belirler. (CI_ROOT_CAUSE_ANALYSIS_ARENA5.md, Q92)",
 ["A) Zorunlu kural: push öncesi script koşmadan push yok (CI kanıtı yerine yerel kanıt)",
  "B) Öneri olarak kalsın, disiplin ekip pratiğiyle",
  "C) CI'a güven yeterli, script gereksiz",
  "D) Script CI'da da pre-step olsun, iki katman"]),

("Q106 — Chaos felaket senaryoları kapsamı (chain-halt / zehirleme / disk yarıda-kesilme)",
 "Chaos v2 teslimleri: `test_chaos_v2_chain_halt_full_silence_and_resume` (73bf82d, disaster_recovery.rs) + mempool poison mühürleri (conflicting-nonce latest-fee + flooder-evicted, chaos.rs). Aday genişletme: snapshot/dis coruption graceful-fallback, auth-partition. (ADIM5 §5.4)",
 ["A) Üç senaryo ailesi de zorunlu mühür: halt+resume, mempool-poison, disk/snapshot corruption (genişletme onayı)",
  "B) Mevcut set yeterli (halt + poison), yeni senaryo ertele",
  "C) Chaos v2 tamamen kaldırılsın, disaster_recovery yeterli",
  "D) Senaryolar prod-shadow düğümüne taşınsın, CI'a karışmasın"]),

("Q107 — StoragePrune fiziksel silme tetikleyicisi (R1: zero-caller)",
 "`NodeCommand::StoragePrune{cid}` + `NetworkMessage::StoragePrune` prototip yazıldı (Q-X1) ama düğüm tarafında tetikleyici caller yok (R1 bulgusu) — F1 hard-prune zinciri worker'da kopuksa fiziksel chunk silme tetiklenmiyor. (node.rs, STATUS_ONLINE ARENA3)",
 ["A) NftBurn worker'ından otomatik tetik (executor→StoragePrune→gossip, tam zincir)",
  "B) RPC ile manuel tetik (operatör komutu), otomasyon yok",
  "C) Gossip aktif + executor sonrası verified burn şartı ikisi birden",
  "D) Prune tetikleyicisi Görev-sonrasına ertele"]),

("Q108 — Zincir tam-geçmiş export/import tooling (zincir-fork-tam-gecmis-spec.md)",
 "`docs/zincir-fork-tam-gecmis-spec.md` ile zincirin tam geçmişinin dışa/içe aktarımı spec'lendi: fork senaryolarında geçmiş kaybı olmadan taşıma. Implementasyon kapsamı kararı gerekli. (yeni ADIM adayı, user upload)",
 ["A) Spec'in tamamı implemente edilsin (export + import + doğrulama testleri)",
  "B) Sadece snapshot-level export yeterli (tam geçmiş değil)",
  "C) Tooling mainnet sonrasına ertelensin",
  "D) Spec iptal, fork hiç desteklenmesin"]),

("Q109 — Rozet (badge) botu yarış koruması (B-RACE) kalıcılığı",
 "Badge botu `git commit && push` yapıyordu; araya giren commit'ler job'ı sahte-kırmızı yapıyordu (aa9cfcd). Yama: bounded-retry — fetch + `git reset --hard origin/main` + idempotent rozet recompute; ilk ırk `3fa09f2` ile canlı kanıtlı. (ci.yml badge step)",
 ["A) Bounded-retry koruması kalıcı kalsın (mevcut)",
  "B) Eski basit push'a dön (yarış kabul)",
  "C) Badge botu `'pull_request'` tetikine taşınsın, main'e hiç yazmasın",
  "D) Badge tamamen kaldırılsın"]),

("Q110 — Köprü gelen-transfer ücret kesintisi (relayer fee) modeli",
 "ADIM5 Q9: inbound bridge transfer'larda relayer fee deduction implementasyonu — dışarıdan gelen varlıktan taşıyıcının payı işlem içinden kesiliyor, Q40 'zero-fee inbound' vaadiyle dengeleniyor. (8ba9779, bridge.rs)",
 ["A) Gelen değerin içinden kesinti kalsın (mevcut, kullanıcı önden para aramaz)",
  "B) Sabit giriş ücreti (flat fee), içerikten bağımsız",
  "C) Tamamen ücretsiz inbound, fee relayer'a hazineden",
  "D) Fee uint oranı config-driven yapılsın, kod sabiti olmasın"]),

("Q111 — Boost %80 payı: devnet-burn / mainnet-treasury davranış ayrımı (config-driven)",
 "NftBoost protocol_share %80: `burn_reserve_address=Some` ise treasury'ye, `None` (devnet_genesis) ise burn. Yani aynı kod iki ağda farklı ekonomi davranışı üretiyor; devnet testleri burn görür, mainnet treasury. (6dd66e5, genesis.rs:155)",
 ["A) Config-driven ayrım kalsın (devnet burn, mainnet treasury, mevcut)",
  "B) Her iki ağda da treasury (devnet'te de treasury adres tanımla)",
  "C) Her iki ağda da burn (treasury tamamen kaldır)",
  "D) %80'in kaderini böl: yarısı burn yarısı treasury"]),

("Q112 — Mempool politika parametreleri (RBF %10 / per-sender 100 / min fee 1)",
 "`MempoolConfig` default: `max_size=20000, max_per_sender=100, min_fee=1, rbf_bump_percent=10`; RBF replace `fee + fee*10/100` eşiği, `evict_lowest_fee` strict-greater, imza kontrolü pool'da YOK (validate_pool_transaction'da). (pool.rs:22-35,82-96,218)",
 ["A) Mevcut parametreler kalsın (20000/100/1/%10)",
  "B) Sıkılaştır: min fee yükselsin, per-sender düşsün (spam ağır)",
  "C) Gevşet: per-sender artsın (burst kullanımı)",
  "D) Parametreler config dosyasına taşınsın, hard-coded olmasın"]),

("Q113 — Felaket alarm zinciri (kim/hangi kanal/kaç dakika)",
 "Runbook'larda fail-closed §4 var ama canlı felaket (zincir durması, HSM erişim kaybı, köprü takılması) için kişi-bazlı çağrı zinciri ve zaman bütçesi tanımlı değil. (operations/* eksik madde)",
 ["A) On-call matrisi + 15dk ilk-yanıt SLA'sı runbook'a yazılsın",
  "B) STATUS_ONLINE kanalı yeterli (AI birliği gözetlemede)",
  "C) Sadece otomatik alarm (metrics alert), kişi ataması yok",
  "D) Mainnet sonrasına ertele"]),

("Q114 — Restart replay-parity zorunluluğu (F4 replay-divergence)",
 "Boost dağıtım hook'ları yalnız produce (`blockchain.rs:2460-2462`) ve validate (`:2673-2675`) yollarında; `apply_block_effects`+`commit_block_durable` (restore/replay) hook'ları ÇALIŞTIRMIYOR → restart eden node'un `pending_bud_boost_share`/kredi bakiyesi canlı node'dan sapabilir. (STATUS_ONLINE ARENA3 bulgu)",
 ["A) Hook'ları `apply_block_effects` içine taşı + replay-parity testi mühürle (replay==live assert)",
  "B) Divergence kabul edilir sayılsın, ilk canlı epoch'ta düzelir beklentisi",
  "C) Boost dağıtımı tamamen executor içine taşınsın (hook yok, tek yol)",
  "D) Dokümante et, düzeltmeyi mainnet sonrasına bırak"]),

("Q115 — Zincir veri boyutu tavanı ve arşiv düğümü ayrımı",
 "Full node diski geçmişle büyür; prune (F1/Q-X1) içerik-silme içindir, zincir geçmişi arşiv politikası tanımsız. Arşiv node / pruned node ikiliği mainnet öncesi karar ister. (MAINNET_READINESS boşluğu)",
 ["A) Arşiv + pruned ikili tip: default pruned, arşiv gönüllü",
  "B) Tek tip: herkes tam geçmiş tutar (tavan yok)",
  "C) Tek tip: herkes pruned, arşiv merkezi servis",
  "D) Tavan config-driven, default beklemede"]),

("Q116 — Devnet/testnet kullanıcı verisi mainnet'e taşınır mı (genesis seed)",
 "Devnet'te yaşayan NFT/SocialFi/BNS kayıtları gerçek ağ başlangıcına dahil edilirse ilk gün canlı içerik doğar; edilmezse temiz ama boş başlangıç. (MAINNET_GENESIS_CEREMONY karar boşluğu)",
 ["A) Taşınmasın: mainnet temiz doğar (deneme kalıntısı yok)",
  "B) Whitelist taşıma: doğrulanmış yaratıcıların içeriği seed edilir",
  "C) Tam taşıma: devnet state'i genesis'e gömülür",
  "D) Topluluk oylamasıyla karar verilsin"]),

("Q117 — Harici audit firması seçim kriterleri (M7)",
 "Task 0.43'te audit firması seçimi + kickoff var ama kriter/kapsam matrisi yok: kaç firma, hangi kapsam (kripto+consensus+ekonomi?), kim seçer. (TASK0.42_PLAN boşluğu)",
 ["A) Çift audit: biri kripto/konsensus, biri ekonomi/mantık; ekip önerir, kullanıcı onaylar",
  "B) Tek firma tam kapsam, teklif+röportajla seçim",
  "C) Bug bounty yeterli, formal audit ertele",
  "D) Kriter matrisi önce yazılsın, firma sonra"]),

("Q118 — Açık kaynak lisans politikası",
 "Repo lisansı kararı mainnet öncesi netleşmeli: permissive (MIT/Apache-2.0), copyleft (GPL/AGPL) ya da karma (çekirdek permissive + uygulama copyleft). Bu karar ekosistem büyümesini ve ticari forku belirler. (repo kökünde lisans kararı boşluğu)",
 ["A) Dual MIT+Apache-2.0 (maksimum benimseme)",
  "B) AGPL (ağ-kullanımı da kaynak zorunlu, ticari fork caydırıcı)",
  "C) Karma: consensus çekirdeği permissive, SocialFi/ekonomi copyleft",
  "D) Proprietary/source-available (BSL) ile başla, sonra aç"]),

("Q119 — Genesis ceremony sonrası anahtar-kalıntı imha protokolü",
 "Ceremony'de üretilen genesis anahtarlarının ara kopyaları (RAM kalıntısı, geçici dosyalar, HSM dışı yedekler) için imha/doğrulama tutanağı tanımsız; tören hijyeni son adımı eksik. (MAINNET_GENESIS_CEREMONY 7.1 sonrası boşluk)",
 ["A) İmha tutanağı + çoklu tanık imzası checklist'e eklensin",
  "B) Kalıntılar HSM escrow'a kilitlensin (imha yok)",
  "C) Hava-boşluklu (air-gapped) üretim imha gerektirmez sayılsın",
  "D) Tören dokümanına tek maddelik not yeterli"]),

("Q120 — Mainnet ilk 30 gün: no-rollback ilkesi ve geri dönüş sınırı",
 "Zincir bir kez canlıya geçince tarihi geri sarma (rollback) prensip olarak yok; kritik hata yalnızca ileri-yönlü düzeltmeyle giderilir. Emergency halt (Q44) ile ilişki ve ilk 30 gün özel durumu tanımsız. (CONSTITUTION §7 + launch)",
 ["A) No-rollback mutlak: hata ileri düzeltilir, tarih kutsal (ilke beyanı docs'a)",
  "B) İlk 30 gün istisna: tek genesis-yeniden-doğuş hakkı saklı",
  "C) Emergency halt sonrası rollback mümkün (halting = zaman dondurma)",
  "D) Karar topluluk referandumuna bırakılsın"])]

def fmt_block(qline, tech, opts, nte):
    out = [f"## {qline}", f"**Teknik:** {tech}", f"**Non-teknik (herkes için):** {nte}"]
    out += [f"- {o}" for o in opts]
    out.append("")
    return "\n".join(out)

def main():
    with io.open(SRC, encoding="utf-8") as f:
        lines = f.read().split("\n")
    out = []
    n = 0
    for ln in lines:
        if ln.startswith("# Budlum — Alınmış Tüm Kararlar için 100 Soruluk Anket"):
            out.append("# Budlum — Alınmış Tüm Kararlar için 120 Soruluk Anket (ARENA2 + ARENA3 genişletmesi, 2026-07-17)")
            continue
        if ln.startswith("**(Non-teknik:"):
            n += 1
            if n not in NTE:
                print(f"HATA: Q{n} icin metin yok", file=sys.stderr); sys.exit(1)
            out.append(f"**Non-teknik (herkes için):** {NTE[n]}")
            continue
        out.append(ln)
    if n != 100:
        print(f"HATA: {n} adet non-teknik satir (100 bekleniyor)", file=sys.stderr); sys.exit(1)
    # Q101-120'yi '**Son not:**' satirindan once ekle
    key = next(i for i, ln in enumerate(out) if ln.startswith("**Son not:**"))
    blocks = []
    for idx, (qline, tech, opts) in enumerate(NEW, start=101):
        if idx not in NTE:
            print(f"HATA: Q{idx} NTE yok", file=sys.stderr); sys.exit(1)
        blocks.append(fmt_block(qline, tech, opts, NTE[idx]))
    insert = "---\n\n" + "\n".join(blocks).rstrip() + "\n\n---\n"
    out = out[:key] + insert.split("\n") + out[key:]
    # Amaç satirina revize notu
    for i, ln in enumerate(out):
        if ln.startswith("> **Amaç:**"):
            out[i] = ln + " **Revizyon (ARENA3):** Sorular değiştirilmeden tüm non-teknik açıklamalar uzun/jargonsuz/sonuç-odaklı hale getirildi (hiçbir teknik kelime yok); Q101-Q120 eklendi."
            break
    with io.open(SRC, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"OK: {n} non-teknik satir genisletildi, {len(NEW)} yeni soru eklendi")

if __name__ == "__main__":
    main()
