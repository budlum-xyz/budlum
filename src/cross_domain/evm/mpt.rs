//! In-tree Merkle-Patricia Trie (MPT) **verifier** - Ethereum Yellow Paper
//! Appendix D.
//!
//! **Verify-only** (RFC Q1 = relayer_produces): proof üretimi relayer binary'sinde
//!; Budlum yalnız `(proof_nodes, root, key) → value` doğrular.
//! Deterministik, network'süz - konsensüs güvenliği için kritik.
//!
//! # MPT node tipleri (RLP-decode sonrası)
//!
//! - **Null**: empty string `""` → boş trie / eksik child.
//! - **Leaf**: `[hp_encoded_path, value]` - path terminator flag=1.
//! - **Extension**: `[hp_encoded_path, child_ref]` - terminator flag=0.
//! - **Branch**: `[c0, c1, ..., c15, value]` - 17 eleman (16 child + optional value).
//!
//! `child_ref` ya 32-byte keccak256 hash'tir (node_map'te lookup) ya da inline
//! RLP-encoded node (≤32 byte, küçük node optimizasyonu).
//!
//! # Güvenlik
//!
//! - Node hash = `keccak256(rlp(node))`. Root = kök node'unun hash'i.
//! - Eksik node, bozuk path, yanlış root → `Err` (kanıt geçersiz).
//! - `keccak256` `sha3` crate'inden (mevcut; yeni dependency YOK).

use crate::cross_domain::evm::rlp::{self, Item, RlpError};
use sha3::{Digest, Keccak256};

/// Hard bound on trie descent.
///
/// A path is `keccak256(key)` expanded to nibbles, so an honest proof
/// descends at most 64 levels and each step consumes at least one nibble.
/// Extension nodes are the exception: a hex-prefix path can decode to an
/// *empty* nibble list (`hp_decode(&[0x00])`), and `nibbles.starts_with(&[])`
/// is always true, so `remaining` comes back the same length it went in.
///
/// Two such nodes pointing at each other never terminate. Measured against
/// the unbounded version:
///
/// ```text
/// A -> B, B -> A, both empty-path extensions
/// fatal runtime error: stack overflow, aborting
/// ```
///
/// The proof bytes come from a bridge relayer, so that is a remote abort of
/// the node process, not a local misuse. The depth is generous, twice the
/// longest honest descent - because the goal is to stop non-termination, not
/// to second-guess a legitimate trie.
pub const MAX_WALK_DEPTH: usize = 128;
use std::collections::HashMap;

/// MPT doğrulama hatası.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MptError {
    /// Key trie'de yok (null child / boş value slot).
    KeyNotFound,
    /// Proof'ta eksik node (referans hash node_map'te yok).
    MissingNode,
    /// Node RLP decode hatası.
    Rlp(RlpError),
    /// Geçersiz node yapısı (bilinmeyen liste uzunluğu vb.).
    InvalidNode,
    /// Geçersiz hex-prefix encoding.
    InvalidHpEncoding,
    /// Geçersiz node referansı (32-byte hash değil, inline RLP de değil).
    InvalidNodeRef,
    /// Path eşleşmiyor (leaf/extension path uyuşmazlığı).
    PathMismatch,
    /// Trie descent exceeded [`MAX_WALK_DEPTH`].
    ///
    /// Reached when a proof's nodes do not make progress, an empty-path
    /// extension leaves the remaining nibbles unchanged, so a cycle among
    /// such nodes would otherwise recurse until the stack is exhausted.
    NestingTooDeep,
}

impl std::fmt::Display for MptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MptError::KeyNotFound => write!(f, "mpt: key not found in trie"),
            MptError::MissingNode => write!(f, "mpt: missing node in proof"),
            MptError::Rlp(e) => write!(f, "mpt: rlp decode error: {e}"),
            MptError::InvalidNode => write!(f, "mpt: invalid node structure"),
            MptError::InvalidHpEncoding => write!(f, "mpt: invalid hex-prefix encoding"),
            MptError::InvalidNodeRef => write!(f, "mpt: invalid node reference"),
            MptError::PathMismatch => write!(f, "mpt: path does not match"),
            MptError::NestingTooDeep => {
                write!(f, "mpt: trie descent exceeded {MAX_WALK_DEPTH} levels")
            }
        }
    }
}

impl std::error::Error for MptError {}

impl From<RlpError> for MptError {
    fn from(e: RlpError) -> Self {
        MptError::Rlp(e)
    }
}

/// Keccak-256 digest (32 bytes).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Boş trie root = `keccak256(rlp(""))` = `keccak256(0x80)`.
/// Ethereum'da kanonik sabit; tüm boş trie'ler bu root'a sahiptir.
/// Değer CI-kanıtlı (keccak256(0x80) - lokalde hesaplanamadı, CI test
/// `empty_trie_root_constant_correct` otorite değeridir).
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// 32-byte hash'i 64 nibble'a açar (MPT path = keccak256(key) nibble'ları).
pub fn to_nibbles(hash: &[u8; 32]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(64);
    for &b in hash {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    nibbles
}

/// Hex-prefix encode (Yellow Paper Appendix D \mathrm{compact} fonksiyonu).
///
/// `is_leaf=true` → terminator flag; `nibbles` tek/çift uzunluk olabilir.
pub fn hp_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 2u8 } else { 0u8 };
    let odd = nibbles.len() % 2 == 1;
    let prefix_nibble = flag + if odd { 1 } else { 0 };
    let mut out = Vec::new();
    if odd {
        // İlk path nibble'ı prefix ile aynı byte'a paketlenir.
        out.push((prefix_nibble << 4) | nibbles[0]);
        for pair in nibbles[1..].chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    } else {
        out.push(prefix_nibble << 4);
        for pair in nibbles.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    }
    out
}

/// Hex-prefix decode → (is_leaf, path_nibbles).
pub fn hp_decode(bytes: &[u8]) -> Result<(bool, Vec<u8>), MptError> {
    if bytes.is_empty() {
        return Err(MptError::InvalidHpEncoding);
    }
    let first = bytes[0];
    let flag_byte = first >> 4;
    if flag_byte > 3 {
        return Err(MptError::InvalidHpEncoding); // sadece 0/1/2/3 geçerli
    }
    let is_leaf = (flag_byte & 0b10) != 0;
    let odd = (flag_byte & 0b01) != 0;

    let mut nibbles = Vec::new();
    if odd {
        nibbles.push(first & 0x0f);
    }
    for &b in &bytes[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    Ok((is_leaf, nibbles))
}

/// Bir MPT proof'unu doğrular ve key'e karşı value döner.
///
/// - `proof_nodes`: RLP-encoded node byte'ları (hash → bytes map'i kurulur).
/// - `root`: beklenen kök hash (`keccak256(rlp(kök_node))`).
/// - `key`: ham key byte'ları (path = `keccak256(key)` nibble'ları).
///
/// Başarı → value byte'ları (leaf value veya branch value slot, ham).
/// Başarısız → kanıt geçersiz (MissingNode/PathMismatch/KeyNotFound/...).
pub fn verify(proof_nodes: &[Vec<u8>], root: &[u8; 32], key: &[u8]) -> Result<Vec<u8>, MptError> {
    // Node map: hash → RLP bytes (relayer proof'tan).
    let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    for node_bytes in proof_nodes {
        node_map.insert(keccak256(node_bytes), node_bytes.clone());
    }

    // Kök node'u çöz.
    let root_bytes = node_map.get(root).ok_or(MptError::MissingNode)?;
    let root_item = rlp::decode(root_bytes)?;
    let path = to_nibbles(&keccak256(key));

    walk(&root_item, &path, &node_map, 0)
}

/// Recursive trie walk. `nibbles` = kalan path nibble'ları.
fn walk(
    node: &Item,
    nibbles: &[u8],
    node_map: &HashMap<[u8; 32], Vec<u8>>,
    depth: usize,
) -> Result<Vec<u8>, MptError> {
    if depth > MAX_WALK_DEPTH {
        return Err(MptError::NestingTooDeep);
    }
    match node {
        // Null node → boş/eksik.
        Item::String(b) if b.is_empty() => Err(MptError::KeyNotFound),

        // 2-eleman liste: leaf veya extension.
        Item::List(items) if items.len() == 2 => {
            let path_bytes = rlp::as_bytes(&items[0])?;
            let (is_leaf, node_path) = hp_decode(path_bytes)?;
            if !nibbles.starts_with(&node_path) {
                return Err(MptError::PathMismatch);
            }
            let remaining = &nibbles[node_path.len()..];
            if is_leaf {
                // Leaf: tüm path tüketilmeli → value döner.
                if !remaining.is_empty() {
                    return Err(MptError::PathMismatch);
                }
                return Ok(rlp::as_bytes(&items[1])?.to_vec());
            }
            // Extension: child referansını çöz ve devam et.
            let child = resolve_ref(&items[1], node_map)?;
            walk(&child, remaining, node_map, depth + 1)
        }

        // 17-eleman liste: branch.
        Item::List(items) if items.len() == 17 => {
            if nibbles.is_empty() {
                // Tüm path tükendi → branch value slot (index 16).
                let value_slot = &items[16];
                return match value_slot {
                    Item::String(b) if b.is_empty() => Err(MptError::KeyNotFound),
                    _ => Ok(rlp::as_bytes(value_slot)?.to_vec()),
                };
            }
            let nibble = nibbles[0] as usize;
            let child = resolve_ref(&items[nibble], node_map)?;
            walk(&child, &nibbles[1..], node_map, depth + 1)
        }

        _ => Err(MptError::InvalidNode),
    }
}

/// Node referansını çözer: 32-byte hash (node_map lookup) veya inline RLP node.
fn resolve_ref(item: &Item, node_map: &HashMap<[u8; 32], Vec<u8>>) -> Result<Item, MptError> {
    match item {
        Item::String(b) if b.is_empty() => Err(MptError::KeyNotFound),
        Item::String(b) if b.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(b);
            let node_bytes = node_map.get(&hash).ok_or(MptError::MissingNode)?;
            rlp::decode(node_bytes).map_err(MptError::from)
        }
        Item::String(b) => {
            // Inline node (≤32 byte RLP) - decode et ve yerinde işle.
            rlp::decode(b).map_err(MptError::from)
        }
        Item::List(_) => {
            // İç içe decode edilmiş inline node (branch child doğrudan liste).
            Ok(item.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::rlp::{decode as rlp_decode, encode as rlp_encode};

    /// Test-yardımcı: leaf node RLP byte'ları üretir (test trie builder).
    fn leaf_node_bytes(nibbles: &[u8], value: &[u8]) -> Vec<u8> {
        let node = Item::List(vec![
            Item::String(hp_encode(nibbles, true)),
            Item::String(value.to_vec()),
        ]);
        rlp_encode(&node)
    }

    /// Test-yardımcı: extension node RLP byte'ları.
    fn extension_node_bytes(nibbles: &[u8], child_hash: &[u8; 32]) -> Vec<u8> {
        let node = Item::List(vec![
            Item::String(hp_encode(nibbles, false)),
            Item::String(child_hash.to_vec()),
        ]);
        rlp_encode(&node)
    }

    /// Test-yardımcı: branch node RLP byte'ları (16 child + value).
    fn branch_node_bytes(children: [Option<Vec<u8>>; 16], value: Option<Vec<u8>>) -> Vec<u8> {
        let mut items: Vec<Item> = children
            .iter()
            .map(|c| match c {
                Some(b) => Item::String(b.clone()),
                None => Item::String(vec![]),
            })
            .collect();
        items.push(match value {
            Some(v) => Item::String(v),
            None => Item::String(vec![]),
        });
        rlp_encode(&Item::List(items))
    }

    // ---- Hex-prefix KAT ----

    #[test]
    fn hp_encode_decode_leaf_even() {
        let nibbles = vec![1, 2, 3, 4];
        let enc = hp_encode(&nibbles, true);
        assert_eq!(enc, vec![0x20, 0x12, 0x34]); // leaf+even → 0x20, then 1234
        let (is_leaf, decoded) = hp_decode(&enc).unwrap();
        assert!(is_leaf);
        assert_eq!(decoded, nibbles);
    }

    #[test]
    fn hp_encode_decode_leaf_odd() {
        let nibbles = vec![1, 2, 3];
        let enc = hp_encode(&nibbles, true);
        assert_eq!(enc, vec![0x31, 0x23]); // leaf+odd → 0x31, first nibble 1 packed, then 23
        let (is_leaf, decoded) = hp_decode(&enc).unwrap();
        assert!(is_leaf);
        assert_eq!(decoded, nibbles);
    }

    #[test]
    fn hp_encode_decode_extension_even() {
        let nibbles = vec![0xa, 0xb, 0xc, 0xd];
        let enc = hp_encode(&nibbles, false);
        assert_eq!(enc, vec![0x00, 0xab, 0xcd]);
        let (is_leaf, decoded) = hp_decode(&enc).unwrap();
        assert!(!is_leaf);
        assert_eq!(decoded, nibbles);
    }

    #[test]
    fn hp_decode_invalid_flag_rejected() {
        // Flag_byte = 4 (>3) → InvalidHpEncoding
        assert_eq!(hp_decode(&[0x40]).unwrap_err(), MptError::InvalidHpEncoding);
    }

    // ---- keccak256 + EMPTY_TRIE_ROOT doğrulama ----

    #[test]
    fn empty_trie_root_constant_correct() {
        // rlp("") = 0x80; keccak256(0x80) = EMPTY_TRIE_ROOT
        let computed = keccak256(&[0x80]);
        assert_eq!(computed, EMPTY_TRIE_ROOT);
    }

    // ---- verify: tek-leaf trie ----

    #[test]
    fn verify_single_leaf_hit() {
        // Tek girişli trie: key → value (tek leaf node = root).
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let root = keccak256(&node_bytes);

        let result = verify(std::slice::from_ref(&node_bytes), &root, key).unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn verify_single_leaf_wrong_key_misses() {
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let root = keccak256(&node_bytes);

        // Farklı key → path uyuşmazlığı (leaf path nibbles'ı farklı).
        let err = verify(&[node_bytes], &root, b"different").unwrap_err();
        assert_eq!(err, MptError::PathMismatch);
    }

    // ---- verify: leaf + extension + branch (çok node) ----

    #[test]
    fn verify_two_keys_share_branch() {
        // İki key'in ilk nibble'ları farklı → branch root, her child bir leaf.
        // Keccak256("a") ve keccak256("b") ilk nibble'ları farklı olmalı (büyük olasılıkla).
        let key_a = b"a";
        let val_a = b"alpha";
        let key_b = b"b";
        let val_b = b"beta";

        let nib_a = to_nibbles(&keccak256(key_a));
        let nib_b = to_nibbles(&keccak256(key_b));
        assert_ne!(
            nib_a[0], nib_b[0],
            "test precondition: distinct first nibble"
        );

        let leaf_a_bytes = leaf_node_bytes(&nib_a[1..], val_a);
        let leaf_b_bytes = leaf_node_bytes(&nib_b[1..], val_b);
        let hash_a = keccak256(&leaf_a_bytes);
        let hash_b = keccak256(&leaf_b_bytes);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[nib_a[0] as usize] = Some(hash_a.to_vec());
        children[nib_b[0] as usize] = Some(hash_b.to_vec());

        // Absent-key kontrolü children move olmadan ÖNCE (branch_node_bytes
        // Ownership alır). c-key ilk nibble slot'u dolu mu?
        let absent = b"c";
        let nib_c = to_nibbles(&keccak256(absent));
        let absent_slot_empty = children[nib_c[0] as usize].is_none();

        let branch_bytes = branch_node_bytes(children, None);
        let root = keccak256(&branch_bytes);

        let proof = vec![branch_bytes, leaf_a_bytes, leaf_b_bytes];

        assert_eq!(verify(&proof, &root, key_a).unwrap(), val_a);
        assert_eq!(verify(&proof, &root, key_b).unwrap(), val_b);

        // Absent key → KeyNotFound (null child branch slot).
        if absent_slot_empty {
            assert_eq!(
                verify(&proof, &root, absent).unwrap_err(),
                MptError::KeyNotFound
            );
        }
    }

    // ---- verify: extension node (shared prefix) ----

    #[test]
    fn verify_extension_path() {
        // İki key ortak prefix paylaşsın diye yapay nibble'larla test:
        // Root = extension([0,1,2,3] → branch); branch child'lar leaf.
        // Gerçek key yerine doğrudan nibble-walk'u hp_encode ile test ediyoruz.
        let shared = vec![0u8, 1, 2, 3];
        // Branch'ın 4. child'ı bir leaf (path = [] → branch value).
        let leaf_nibbles: Vec<u8> = vec![9, 9, 9, 9]; // branch'in 9. child'ına
        let leaf_bytes = leaf_node_bytes(&leaf_nibbles, b"leaf-val");
        let leaf_hash = keccak256(&leaf_bytes);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[9] = Some(leaf_hash.to_vec());
        let branch_bytes = branch_node_bytes(children, None);
        let branch_hash = keccak256(&branch_bytes);

        let ext_bytes = extension_node_bytes(&shared, &branch_hash);
        let root = keccak256(&ext_bytes);

        // Path = shared + [9] + leaf_nibbles; key = nibbles_to_bytes(shared+[9]+leaf)
        let full_path: Vec<u8> = shared
            .iter()
            .cloned()
            .chain(std::iter::once(9))
            .chain(leaf_nibbles.iter().cloned())
            .collect();
        // Key bytes (path'in her çift nibble'ı bir byte), tam 64 nibble olması
        // Şart değil çünkü verify keccak256(key)'i kullanır; burada doğrudan
        // Walk test etmek için verify yerine walk çağırıyoruz.
        let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        node_map.insert(keccak256(&ext_bytes), ext_bytes.clone());
        node_map.insert(keccak256(&branch_bytes), branch_bytes.clone());
        node_map.insert(keccak256(&leaf_bytes), leaf_bytes.clone());

        let root_item = rlp_decode(&ext_bytes).unwrap();
        let result = walk(&root_item, &full_path, &node_map, 0).unwrap();
        assert_eq!(result, b"leaf-val");

        // Yanlış path (shared prefix değil) → PathMismatch
        let bad_path = vec![5u8, 6, 7, 8];
        assert_eq!(
            walk(&root_item, &bad_path, &node_map, 0).unwrap_err(),
            MptError::PathMismatch
        );

        // Root hash doğrulama
        assert_eq!(keccak256(&ext_bytes), root);
    }

    // ---- negatif: missing node ----

    #[test]
    fn verify_missing_node_rejected() {
        // Proof'tan bir node'u atla → MissingNode.
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let root = keccak256(&node_bytes);

        // Boş proof → kök node map'te yok.
        let err = verify(&[], &root, key).unwrap_err();
        assert_eq!(err, MptError::MissingNode);
    }

    #[test]
    fn verify_wrong_root_rejected() {
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let real_root = keccak256(&node_bytes);
        let wrong_root = [0xffu8; 32];

        let err = verify(&[node_bytes], &wrong_root, key).unwrap_err();
        assert_eq!(err, MptError::MissingNode); // wrong root → lookup miss
        let _ = real_root; // (real root doğrulandı önceki testte)
    }

    #[test]
    fn verify_empty_trie_root_key_not_found() {
        // Root = EMPTY_TRIE_ROOT ama proof'ta rlp("") node'u var.
        let empty_node = vec![0x80]; // rlp("") = 0x80
        let err = verify(&[empty_node], &EMPTY_TRIE_ROOT, b"any").unwrap_err();
        assert_eq!(err, MptError::KeyNotFound);
    }

    // ---- inline node desteği ----

    #[test]
    fn verify_inline_branch_child() {
        // Branch'in child'ı hash yerine inline leaf (≤32 byte RLP). Gerçek
        // Ethereum leaf'leri 64-nibble path'le inline olmaz; burada yapay kısa
        // Path ile inline mekanizmasını test ediyoruz (walk + resolve_ref yolu).
        // Path = 2 nibble [0xa, 0xb], value = 1 byte → küçük leaf.
        let inline_leaf = leaf_node_bytes(&[0xa, 0xb], b"v");
        assert!(inline_leaf.len() <= 32, "precondition: inline-able");

        // Branch'in 5. child slot'una inline leaf koy; path = [5, 0xa, 0xb].
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[5] = Some(inline_leaf.clone());
        let branch_bytes = branch_node_bytes(children, None);
        let root = keccak256(&branch_bytes);

        // Verify keccak256(key)'i path yapar - biz doğrudan walk ile test edelim
        // Çünkü key'den path = keccak256(key) geliyor ve yapay path'e uymaz.
        let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        node_map.insert(keccak256(&branch_bytes), branch_bytes.clone());

        let root_item = rlp_decode(&branch_bytes).unwrap();
        let path = vec![5u8, 0xa, 0xb];
        let result = walk(&root_item, &path, &node_map, 0).unwrap();
        assert_eq!(result, b"v");

        // Root hash doğrulama
        assert_eq!(keccak256(&branch_bytes), root);
    }

    // ---- fuzz-benzeri: rastgele node bytes → hata (panic değil) ----

    #[test]
    fn garbage_proof_does_not_panic() {
        let garbage_sets: Vec<Vec<Vec<u8>>> = vec![
            vec![vec![0x00]],
            vec![vec![0xff; 100]],
            vec![vec![0xc0]],             // empty list
            vec![vec![0xc1, 0x80]],       // 1-elem list (invalid node)
            vec![vec![0xd2, 0x80, 0x80]], // 2-elem list but value empty
        ];
        let root = [0x42u8; 32];
        for proof in &garbage_sets {
            // Sonuç Err olmalı (MissingNode / InvalidNode / Rlp), panic değil.
            let _ = verify(proof, &root, b"key");
        }
        // Root hash'leri proof'ta olmadığı için MissingNode beklenir, önemli
        // Olan panic olmaması (DoS güvenliği).
    }
}

#[cfg(test)]
mod depth_bound_locks {
    use super::*;
    use crate::cross_domain::evm::rlp::encode as rlp_encode;

    /// A cycle of empty-path extension nodes must be refused, not recursed.
    ///
    /// `hp_decode(&[0x00])` yields an empty nibble list, and
    /// `nibbles.starts_with(&[])` is always true, so an extension node with an
    /// empty path hands `walk` the same `remaining` it received. Two such
    /// nodes referring to each other never make progress. Measured against the
    /// unbounded version:
    ///
    /// ```text
    /// A -> B, B -> A, both empty-path extensions
    /// fatal runtime error: stack overflow, aborting
    /// ```
    ///
    /// The proof bytes arrive from a bridge relayer, so this was a remote
    /// abort of the node process.
    #[test]
    fn a_cycle_of_empty_path_extensions_is_refused() {
        let a_ref = [0xAAu8; 32];
        let b_ref = [0xBBu8; 32];

        let node_a = Item::List(vec![
            Item::String(hp_encode(&[], false)),
            Item::String(b_ref.to_vec()),
        ]);
        let node_b = Item::List(vec![
            Item::String(hp_encode(&[], false)),
            Item::String(a_ref.to_vec()),
        ]);
        let bytes_a = rlp_encode(&node_a);
        let bytes_b = rlp_encode(&node_b);

        let mut map = std::collections::HashMap::new();
        map.insert(a_ref, bytes_a.clone());
        map.insert(b_ref, bytes_b.clone());

        let path = to_nibbles(&[0x11u8; 32]);
        let root_item = rlp::decode(&bytes_a).expect("node A decodes");

        assert_eq!(
            walk(&root_item, &path, &map, 0),
            Err(MptError::NestingTooDeep),
            "a non-progressing cycle must terminate with an error"
        );
    }

    /// The bound has to clear the deepest descent a real trie can produce.
    ///
    /// Comparing two constants would be folded away at compile time (clippy
    /// calls it a constant assertion, correctly), so this builds an actual
    /// branch chain 64 levels deep, the maximum a keccak256 path allows,
    /// and checks it resolves. Lowering `MAX_WALK_DEPTH` below the honest
    /// maximum would make this fail with `NestingTooDeep`.
    #[test]
    fn a_maximum_depth_honest_descent_still_resolves() {
        let key = b"deep";
        let path = to_nibbles(&keccak256(key));
        assert_eq!(path.len(), 64, "keccak256 expands to 64 nibbles");
        let value = b"found";

        // Build bottom-up: a leaf consuming nothing, then 64 branch nodes each
        // consuming one nibble of the path.
        let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let leaf = Item::List(vec![
            Item::String(hp_encode(&[], true)),
            Item::String(value.to_vec()),
        ]);
        let mut current_bytes = rlp_encode(&leaf);
        let mut current_hash = keccak256(&current_bytes);
        node_map.insert(current_hash, current_bytes.clone());

        for level in (0..64).rev() {
            let nibble = path[level] as usize;
            let mut children: Vec<Item> = (0..17).map(|_| Item::String(Vec::new())).collect();
            children[nibble] = Item::String(current_hash.to_vec());
            let branch = Item::List(children);
            current_bytes = rlp_encode(&branch);
            current_hash = keccak256(&current_bytes);
            node_map.insert(current_hash, current_bytes.clone());
        }

        let nodes: Vec<Vec<u8>> = node_map.values().cloned().collect();
        assert_eq!(
            verify(&nodes, &current_hash, key),
            Ok(value.to_vec()),
            "a 64-level descent is honest and must not hit the depth bound"
        );
    }

    /// An existing round-trip must still work - the bound is a ceiling, not a
    /// behaviour change.
    #[test]
    fn a_normal_leaf_lookup_still_resolves() {
        let key = b"balance";
        let value = b"42";
        let path = to_nibbles(&keccak256(key));

        let leaf = Item::List(vec![
            Item::String(hp_encode(&path, true)),
            Item::String(value.to_vec()),
        ]);
        let leaf_bytes = rlp_encode(&leaf);
        let root = keccak256(&leaf_bytes);

        assert_eq!(
            verify(&[leaf_bytes], &root, key),
            Ok(value.to_vec()),
            "a single-leaf trie must still verify"
        );
    }
}
