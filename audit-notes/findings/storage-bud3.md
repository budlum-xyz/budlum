# storage-bud3

PR #183 Strix bulguları, `budlum-stack` head `ec3a697` uzerinde kodla dogrulandi.

- B-0003: DOGRULANDI. `src/execution/executor.rs:867` ag bond tabani yerine `registry.params().min_stake` kullaniyor.
- B-0004: DOGRULANDI. `src/storage/bud3/registry.rs:2212-2235` attestation kolu `new_root`u turetmiyor.
- B-0005: COZULMUS gorunuyor. `replace.rs:54-115` yerlesim ozeti digest icinde; `mempool/pool.rs:600-625` duty yasam zorlamasi duzeltilmis.

Duzeltmeler bu turda uygulanmadi; stack sahibinin dali.
