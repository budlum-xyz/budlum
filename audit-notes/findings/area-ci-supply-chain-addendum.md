# Denetim Bulgulari: CI Tetikleyici Kapsama Eklentisi

Ek: `area-ci-supply-chain.md`. Tarih: 2026-11-17. Dal: `audit-notes` (PR #197).

## B-CI-04: Kapilar yigin taban dallarinda hic calismiyor

- **Kimlik**: B-CI-04
- **Konum**: `.github/workflows/ci.yml`, satir 11 (duzeltme oncesi):
  `branches: [main, fix/architecture-tip-adlari, consensus-of-consensuses, testnet-quantum, testnet]`
  Ayni filtre 24 is akisinda daha var: `audit-guard.yml`, `benchmark.yml`, `cargo-vet.yml`,
  `code-scanning-sarif.yml`, `dependency-review.yml`, `determinism.yml`, `diverse-double-compiling.yml`,
  `docker-smoke.yml`, `extra-tooling.yml`, `fmt-diff-surface.yml`, `grype.yml`, `miri.yml`,
  `osv-scanner.yml`, `pkcs11-pq.yml`, `release-signature.yml`, `rust.yml`, `security-audit.yml`,
  `semgrep.yml`, `semver.yml`, `solidity.yml`, `supply-chain-extra.yml`, `testnet-rehearsal.yml`, `typos.yml`.
- **Onem derecesi**: Yuksek.
- **Ne yanlis**: `pull_request` tetikleyicisi taban dallarini elle yazilmis bir listeye sabitliyor.
  Yigin PR'larda taban arada bir daldir. PR #194 tabani `budlum-stack`, PR #183 tabani `garden`.
  Ikisi de listede yok.
- **Neden yanlis**: GitHub `pull_request.branches` filtresini taban ada gore degerlendirir. Taban listede
  yoksa is akisi hic tetiklenmez. Hata sesi cikarmaz, kuyrukta beklemez, kirmizi olmaz. Yok olur.
- **Neye yol acar**: Yiginin ust PR'lari icin fmt, clippy `-D warnings`, test, Semgrep, CodeQL, Gitleaks,
  cargo-deny, Zizmor, dependency-review, Audit Guard calismadan merge edilebilir. Denetim siniri yiginin
  kendi icinde devre disi kalir. Ayrica listedeki `consensus-of-consensuses` adi artik yok; dal
  `budlum-consensus-of-consensuses` olarak yeniden adlandirildi, yani tek gercek taban listesi de eskidi.
- **Nasil duzeltildi**: Iki adim. Ilk once kirmizi test: `xtask/tools/src/audit_guard.rs` icine
  `pull_request_has_base_filter` kurali ve iki mutant eklendi; 147 birim test ve `--self-test` (16 mutant)
  gecti, gercek denetim duzeltilmemis agacta 24 is akisini FAIL verdi (commit 1). Sonra 24 is
  akisindaki taban filtrleri kaldirildi; tetikleyici tum tabanlar icin calisir (commit 2). `push`
  filtrelerine dokunulmadi, bu yuzden eski ikiz calisma sorunu geri gelmez.
- **Dogrulama**: `audit-guard` PASS (32 is akisi), `cargo test` 147/147, `cargo fmt --check` ve
  `cargo clippy --all-targets -- -D warnings` temiz.
- **Durum**: Cozuldu, kod bu dalda. Yesil CI run numarasi bekleniyor; agirlikli denetim kaniti olmadan
  merge hazir sayilmaz.

## B-CI-05: Kuyruk tikanmasi (acik, kod disi karar gerekiyor)

- **Onem derecesi**: Orta.
- **Kanit**: 2026-11-17 23:0x UTC olcumu, `actions/runs?status=queued`: 86 calisma kuyrukta.
  En yasli `CI` calismasi 277 dakikadir kuyrukta. Son 100 tamamlanmis calismada dagilim:
  48 cancelled, 45 skipped, 7 success. Repo 43 aktif is akisi, her push, bes PR'lik yigin.
- **Neye yol acar**: Kapilar calissa bile sonucu saatler sonra veriyor. Bu, "CI yesil mi" sorusunu
  PR sirasinda anlamsiz kiliyor ve Strix inceleme dongusunu de bekletiyor.
- **Onerilen karar**: Agir derinlik islerini (kani, miri, fuzz, benchmark, grype, osv, supply-chain-extra)
  PR olayinda haftalik programdan gelen isarete ya da etikete baglamak, ya da kosu kotasi artirmak.
  Bu bir kapasite karari, bir kod duzeltmesi degil. Kapilari gevsetme secenegi bilincli olarak elendi.
