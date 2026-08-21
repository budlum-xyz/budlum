//! Arweave `data_root` dogrulamasi.
//!
//! Bir `.eth` adi ENS `contenthash` alaninda bir Arweave islem kimligine
//! isaret edebilir. Islem kimligi imzanin hash'idir ve **iceriğin** hash'i
//! degildir; iceriğe baglanan alan `data_root`'tur: veri 256 KiB'lik yiginlara
//! bolunur, her yigin bir yaprak olur ve agacin koku islemde taahhut edilir.
//!
//! Bu modul o agaci yeniden kurar. Getirilen baytlar `data_root`'u uretmiyorsa
//! sayfa gosterilmez.
//!
//! # Neden SHA-384
//!
//! Arweave'in secimi; burada yeniden secilmiyor. Yaprak ve dal hash'lerinin
//! hepsi SHA-384, ve `note` alani 32 baytlik **big-endian** bir ofsettir.
//! Bunlarin herhangi biri degistirilirse uretilen kok Arweave'in kokU olmaz.
//!
//! # Ne dogrulanmiyor
//!
//! Islem imzasi (RSA-PSS) dogrulanmiyor, cunku bu tarayicinin sordugu soru
//! "bu baytlar bu koke ait mi", "bu islemi kim imzaladi" degil. Kok bir
//! ENS kaydindan geliyor ve o kaydin dogrulanmasi ENS tarafinin isi. Ikisini
//! karistirmak, tek bir "dogrulandi" rozetinin arkasina iki ayri iddiayi
//! koymak olurdu.

use sha2::{Digest, Sha384};

/// Arweave'in azami yigin boyutu.
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Arweave'in asgari yigin boyutu (son yigin yeniden dengelemesi icin).
pub const MIN_CHUNK_SIZE: usize = 32 * 1024;

/// `note`: 32 baytlik big-endian ofset.
fn note_bytes(offset: usize) -> [u8; 32] {
    let mut note = [0u8; 32];
    let be = (offset as u128).to_be_bytes(); // 16 bayt
    note[16..].copy_from_slice(&be);
    note
}

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[derive(Debug, Clone, Copy)]
struct Node {
    id: [u8; 48],
    max_byte_range: usize,
}

/// Baytlari Arweave'in yigin kuralina gore bol.
///
/// Son yigin `MIN_CHUNK_SIZE`'in altina duserse, bir onceki yiginla birlikte
/// yeniden dengelenir. Bu kural arweave-js'in kendi kurali; atlanirsa son iki
/// yigin farkli sinirlara duser ve kok tutmaz.
fn split_chunks(data: &[u8]) -> Vec<(usize, usize)> {
    if data.is_empty() {
        return vec![(0, 0)];
    }
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let end = (start + MAX_CHUNK_SIZE).min(data.len());
        spans.push((start, end));
        start = end;
    }
    if spans.len() >= 2 {
        let last = spans[spans.len() - 1];
        if last.1 - last.0 < MIN_CHUNK_SIZE {
            let prev = spans[spans.len() - 2];
            let remaining_start = prev.0;
            let remaining_end = last.1;
            let total = remaining_end - remaining_start;
            let first_half = total.div_ceil(2);
            spans.truncate(spans.len() - 2);
            spans.push((remaining_start, remaining_start + first_half));
            spans.push((remaining_start + first_half, remaining_end));
        }
    }
    spans
}

fn build_layers(mut nodes: Vec<Node>) -> Node {
    while nodes.len() > 1 {
        let mut next: Vec<Node> = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut i = 0;
        while i < nodes.len() {
            if i + 1 < nodes.len() {
                let left = nodes[i];
                let right = nodes[i + 1];
                let id = sha384(&[
                    &sha384(&[&left.id]),
                    &sha384(&[&right.id]),
                    &sha384(&[&note_bytes(left.max_byte_range)]),
                ]);
                next.push(Node {
                    id,
                    max_byte_range: right.max_byte_range,
                });
            } else {
                next.push(nodes[i]);
            }
            i += 2;
        }
        nodes = next;
    }
    nodes[0]
}

/// Baytlarin `data_root`'unu hesapla (32 bayta kirpilmis SHA-384 degil, tam
/// 48 baytlik dugum kimliginin ilk 32 bayti: Arweave `data_root`'u 32 bayttir).
///
/// Arweave dugum kimlikleri 48 bayt (SHA-384) uretir ve `data_root` alani
/// base64url ile 32 bayt tasir. Uygulamada arweave-js kok dugumun `id`sini
/// oldugu gibi kullanir ve o 48 bayttir; islem alanina yazilan deger de 48
/// bayttir. Bu yuzden burada kirpma yapilmiyor: donen deger tam dugum kimligi.
#[must_use]
pub fn data_root(data: &[u8]) -> [u8; 48] {
    let leaves: Vec<Node> = split_chunks(data)
        .into_iter()
        .map(|(start, end)| {
            let chunk = &data[start..end];
            let data_hash = sha384(&[chunk]);
            let id = sha384(&[&sha384(&[&data_hash]), &sha384(&[&note_bytes(end)])]);
            Node {
                id,
                max_byte_range: end,
            }
        })
        .collect();
    build_layers(leaves).id
}

/// Bir Arweave hedefi hakkinda verilebilecek karar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArweaveVerdict {
    Verified,
    RootMismatch { expected: String, produced: String },
}

/// Getirilen baytlari beklenen `data_root`'a karsi dogrula.
#[must_use]
pub fn verify(expected_root: &[u8], data: &[u8]) -> ArweaveVerdict {
    let produced = data_root(data);
    // Strix HIGH (CWE-354): kisa gelen beklenen kok bir on-ek olarak
    // kabul ediliyordu; saldirgan 1-47 baytlık bir on-ek icin icerik
    // kaba-kuvvetleyebilir ve kirpilmis koku tam dogrulama gucune
    // yukseltebilirdi. Kirpilmis kok artik reddedilir: dogrulama yalnizca
    // birebir esitlikte verilir.
    let matches = expected_root.len() == produced.len() && expected_root == &produced[..];
    if matches {
        ArweaveVerdict::Verified
    } else {
        ArweaveVerdict::RootMismatch {
            expected: hex::encode(expected_root),
            produced: hex::encode(produced),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_chunk_root_is_the_leaf_id() {
        let data = b"budlum";
        let root = data_root(data);
        let data_hash = sha384(&[data.as_slice()]);
        let leaf = sha384(&[&sha384(&[&data_hash]), &sha384(&[&note_bytes(data.len())])]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn the_root_changes_with_one_byte() {
        assert_ne!(data_root(b"budlum"), data_root(b"budlun"));
    }

    #[test]
    fn multi_chunk_data_builds_a_tree() {
        let data = vec![7u8; MAX_CHUNK_SIZE * 2 + MIN_CHUNK_SIZE];
        let root = data_root(&data);
        // Iki yigindan farkli olmali: yigin sayisi degisti.
        let smaller = vec![7u8; MAX_CHUNK_SIZE * 2];
        assert_ne!(root, data_root(&smaller));
    }

    #[test]
    fn a_short_tail_is_rebalanced_not_left_tiny() {
        let data = vec![3u8; MAX_CHUNK_SIZE + 10];
        let spans = split_chunks(&data);
        assert_eq!(spans.len(), 2);
        for (start, end) in spans {
            assert!(end - start >= MIN_CHUNK_SIZE, "kucuk kuyruk kaldi");
        }
    }

    #[test]
    fn verify_reports_both_roots_on_mismatch() {
        let data = b"budlum";
        match verify(&[0u8; 32], data) {
            ArweaveVerdict::RootMismatch { expected, produced } => {
                assert_ne!(expected, produced);
            }
            ArweaveVerdict::Verified => panic!("sifir kok dogrulanmamaliydi"),
        }
        assert_eq!(verify(&data_root(data), data), ArweaveVerdict::Verified);
    }

    #[test]
    fn a_truncated_expected_root_is_rejected_not_verified() {
        // Strix HIGH (CWE-354) regresyonu: 1-47 baytlık kirpilmis bir kok,
        // tam uzunluktaki dogru kokun on-eki oldugu icin Verified'e
        // yukseltilmemeli. 48 baytlık tam kokun 32 baytlık on-eki
        // kullanilir ve reddedilmelidir.
        let data = vec![9u8; MAX_CHUNK_SIZE + 1];
        let full_root = data_root(&data);
        assert_eq!(full_root.len(), 48, "sabit onkosul: 48 baytlık kok");
        let truncated = &full_root[..32];
        match verify(truncated, &data) {
            ArweaveVerdict::RootMismatch { .. } => {}
            ArweaveVerdict::Verified => {
                panic!("kirpilmis kok Verified'e yukseltilmemeliydi (CWE-354)")
            }
        }
    }
}
