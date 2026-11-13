# Bulgu B-0004

## Kimlik

B-0004

## Konum

`src/rpc/server.rs`, `branch_json` kapanisi (duzeltmeden once 4595-4607)

```rust
let branch_json = |b: &crate::bns::types::BnsMerkleBranch| -> serde_json::Value {
    serde_json::json!({
        "name": b.name,
        "owner": Self::to_0x_hash(b.owner.to_hex()),
        "address": b.address.map(|a| Self::to_0x_hash(a.to_hex())),
        "expires_at": b.expires_at,
        "content_id": b.content_id.map(|c| format!("0x{}", hex::encode(c.0))),
        "storage_root": b.storage_root.map(|r| format!("0x{}", hex::encode(r))),
        "extras_digest": format!("0x{}", hex::encode(b.extras_digest)),
        "leaf": format!("0x{}", hex::encode(b.leaf)),
        "siblings": ...,
        "directions": b.directions,
    })
};
```

## Onem

Yuksek

## Ne yanlis

`bud_bnsGetProof` yaniti dalı alan alan JSON'a yaziyor. `BnsMerkleBranch`
yapisina bu turda uc alan eklendi ve ucu de bu yazicida yok:

- `leaf_index`: yaprak konumu
- `tree_size`: agac boyu
- `extras`: `extras_digest` on-imaji

## Neden yanlis

Duzeltme kayit defterinde ve dogrulayicida tamamlandi, ama ikisi arasindaki
telde eksik kaldi. `verify_state_proof` bir dala `leaf_index` ve `tree_size`
olmadan bakinca yokluk kanitini reddeder. `extras` olmadan `address`, kayitlar,
alt alan adlari ve B.U.D. 3.0 referansi dogrulanmamis kalir.

Bu bir "daha dar yanit" degil. Eski yanitin ta kendisi. Iki bulgu tam olarak bu
eski yanit hakkinda yazilmisti.

## Neye yol acar

- Butun RPC istemcileri, `bud bns proof`, cuzdan ve ag gecidi eksik alan alir.
- Yokluk kaniti RPC uzerinden hic dogrulanamaz. Istemci "ad yok" cevabini
  teyit edemez.
- Profil basan bir istemci `address` alanini dogrulanmis sanar.
- Duzeltme kagitta tamam, uctan uca etkisiz olur.

## Nasil duzeltilir

1. `server.rs` icinde `extras_json` kapanisi yaz: resolver, address,
   consensus_domain_id, storage_domain_id, storage_root_height, bud3_content,
   subdomains, records.
2. `branch_json` ciktisina `leaf_index`, `tree_size` ve `extras` ekle.
3. `bud3_content` tam ya da hic yazilsin. Yarim referans farkli bir ozete
   katlanir.
4. `src/bin/bud.rs` icindeki `parse_merkle_branch_json` ayni alanlari okusun.
   Yeni `parse_branch_extras_json` ve `parse_bud3_ref_json` yardimcilari yaz.
5. Alan yoksa `None` kalsin. Eksik alan hata degil, daha dar bir kanittir.
6. `cargo fmt --all --check` calistir.

## Durum

cozuldu

- Commit: `bd1e6a79`
- CI run: yok. Kuyruk tikali.
