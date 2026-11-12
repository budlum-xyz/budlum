# Denetim raporu

## Başlangıç durumu

- main: `95c07fd72faaf21656e1e44d2dff51ed4dee05f3`.
- PR #110: `e7658eb5049e526fdaf00ed3d1d8b43924fa26ba`. GitHub mergeable=true ve mergeable_state=unstable döndürdü.
- PR #126: `6cc4dad41248c90cb6cd04848303c0388cce529e`. GitHub mergeable=false ve mergeable_state=dirty döndürdü.
- Durumlar başlangıç anına aittir; işlem öncesi yeniden doğrulanır. CI run numaraları henüz toplanmadı.

## Sınırlamalar

- Bu ortamda cargo, rustc, rustup ve docker PATH üzerinde bulunamadı. Testler henüz çalıştırılmadı.
- Çoklu işletim sistemi çalıştırmaları ve kapsamlı inceleme tamamlanmadı.
- Kapsamlı Strix kayıt defteri henüz tamamlanmadı.
- Üçüncü taraf güvenlik denetimi ve BADGE_PUSH_TOKEN riski henüz doğrulanmadı.
- Yasak yöntem kullanılmadı.
