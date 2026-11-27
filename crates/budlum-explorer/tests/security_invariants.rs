//! Security regression tests for `budlum-explorer`:
//! 1. `resolve::open` refuses a BNS record whose `name` differs from the
//!    requested `.bud` name even when the substituted record carries a valid
//!    Merkle proof against the trusted `bns_v1` root.
//! 2. Under `BnsInclusionProof::PerName`, an uncommitted `content_id` (when
//!    `content_binding` is `None`) is refused, and an unopened `content_binding`
//!    never receives `Strength::Verified`.
//! 3. `BudManifest::describes` refuses duplicate data shard indices and
//!    `erasure_k` mismatches.
//! 4. `HeaderStore::accept` refuses headers with empty `hash` or `state_root`.

use budlum_explorer::bns_proof::{BnsInclusionProof, ResolvedName};
use budlum_explorer::content_id::ContentId;
use budlum_explorer::evidence::Strength;
use budlum_explorer::fetch::{BudManifest, BudShard, Target, Transport};
use budlum_explorer::light_client::{HeaderStore, TrackedHeader};
use budlum_explorer::resolve::{self, NameResolver};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn compute_per_name_root(
    name: &str,
    owner: [u8; 32],
    expires_at: u64,
    content_binding: Option<[u8; 32]>,
    storage_root: Option<[u8; 32]>,
    extras_digest: [u8; 32],
    meta_digest: [u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_BNS_LEAF_V1");
    h.update((name.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.update(owner);
    h.update(expires_at.to_le_bytes());
    match content_binding {
        Some(b) => {
            h.update([1u8]);
            h.update(b);
        }
        None => h.update([0u8]),
    }
    match storage_root {
        Some(sr) => {
            h.update([1u8]);
            h.update(sr);
        }
        None => h.update([0u8]),
    }
    h.update(extras_digest);
    let leaf: [u8; 32] = h.finalize().into();

    let mut kh = Sha256::new();
    kh.update(b"BDLM_BNS_KEY_V1");
    kh.update(name.as_bytes());
    let key: [u8; 32] = kh.finalize().into();

    let mut sh = Sha256::new();
    sh.update(b"BDLM_BNS_SMT_LEAF_V1");
    sh.update(key);
    sh.update(leaf);
    let names_root: [u8; 32] = sh.finalize().into();

    let mut rh = Sha256::new();
    rh.update(b"BDLM_BNS_REGISTRY_V3");
    rh.update(meta_digest);
    rh.update(names_root);
    rh.finalize().into()
}

struct StubResolver {
    record: ResolvedName,
    proof: BnsInclusionProof,
    root: [u8; 32],
    epoch: u64,
}

impl NameResolver for StubResolver {
    fn resolve_bud(&self, _name: &str) -> Result<(ResolvedName, BnsInclusionProof), String> {
        Ok((self.record.clone(), self.proof.clone()))
    }
    fn bns_root(&self) -> Option<[u8; 32]> {
        Some(self.root)
    }
    fn current_epoch(&self) -> u64 {
        self.epoch
    }
    fn resolve_eth(&self, _name: &str) -> Result<(Vec<u8>, bool), String> {
        Err("not used".into())
    }
}

struct StubTransport {
    pages: BTreeMap<ContentId, (BudManifest, Vec<u8>)>,
}

impl Transport for StubTransport {
    fn fetch(&self, target: &Target, _max_bytes: usize) -> Result<Vec<u8>, String> {
        let Target::Bud(id) = target else {
            return Err("unexpected target".into());
        };
        self.pages
            .get(id)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| "missing".into())
    }
    fn fetch_bud_manifest(&self, manifest_id: &ContentId) -> Result<BudManifest, String> {
        self.pages
            .get(manifest_id)
            .map(|(m, _)| m.clone())
            .ok_or_else(|| "missing manifest".into())
    }
}

#[test]
fn bns_name_substitution_with_valid_proof_for_other_name_is_refused() {
    let phishing = b"<html>phishing</html>".to_vec();
    let manifest = BudManifest::single_shard(&phishing);
    let manifest_id = manifest.manifest_id();
    let mut pages = BTreeMap::new();
    pages.insert(manifest_id, (manifest, phishing));
    let transport = StubTransport { pages };

    let owner = [0xAAu8; 32];
    let extras = [0x11u8; 32];
    let meta = [0x22u8; 32];
    let binding = Some([0x33u8; 32]);
    let root = compute_per_name_root("attacker.bud", owner, 100, binding, None, extras, meta);

    // Malicious RPC returns a cryptographically valid proof for "attacker.bud"
    // when the user requested "bank.bud".
    let resolver = StubResolver {
        record: ResolvedName {
            name: "attacker.bud".into(),
            owner,
            storage_root: None,
            content_id: Some(manifest_id),
            content_binding: binding,
            is_expired: false,
        },
        proof: BnsInclusionProof::PerName {
            expires_at: 100,
            extras_digest: extras,
            meta_digest: meta,
            siblings: vec![],
        },
        root,
        epoch: 10,
    };

    let page = resolve::open(&resolver, &transport, "bank.bud").expect("returns refusal page");
    assert_eq!(
        page.evidence.weakest(),
        Strength::Refused,
        "proof for attacker.bud must NEVER verify or render under bank.bud"
    );
    assert!(!page.is_renderable());
}

#[test]
fn per_name_proof_refuses_uncommitted_content_id_and_downgrades_unopened_binding() {
    let payload = b"<html>spoofed</html>".to_vec();
    let manifest = BudManifest::single_shard(&payload);
    let manifest_id = manifest.manifest_id();
    let mut pages = BTreeMap::new();
    pages.insert(manifest_id, (manifest, payload));
    let transport = StubTransport { pages };

    let owner = [0xBBu8; 32];
    let extras = [0x44u8; 32];
    let meta = [0x55u8; 32];

    // 1. Leaf commits to content_binding = None, yet RPC injects content_id -> MUST be Refused.
    let root_none = compute_per_name_root("bank.bud", owner, 100, None, None, extras, meta);
    let resolver_none = StubResolver {
        record: ResolvedName {
            name: "bank.bud".into(),
            owner,
            storage_root: None,
            content_id: Some(manifest_id),
            content_binding: None,
            is_expired: false,
        },
        proof: BnsInclusionProof::PerName {
            expires_at: 100,
            extras_digest: extras,
            meta_digest: meta,
            siblings: vec![],
        },
        root: root_none,
        epoch: 10,
    };
    let uncommitted_res =
        resolve::open(&resolver_none, &transport, "bank.bud").expect("refusal page");
    assert_eq!(
        uncommitted_res.evidence.weakest(),
        Strength::Refused,
        "content_id with no on-chain content_binding must be refused"
    );
    assert!(!uncommitted_res.is_renderable());

    // 2. Leaf commits to content_binding = Some(hash), but content_id is not opened
    // against that binding -> MUST NOT receive Strength::Verified!
    let binding = Some([0x77u8; 32]);
    let root_bound = compute_per_name_root("bank.bud", owner, 100, binding, None, extras, meta);
    let resolver_bound = StubResolver {
        record: ResolvedName {
            name: "bank.bud".into(),
            owner,
            storage_root: None,
            content_id: Some(manifest_id),
            content_binding: binding,
            is_expired: false,
        },
        proof: BnsInclusionProof::PerName {
            expires_at: 100,
            extras_digest: extras,
            meta_digest: meta,
            siblings: vec![],
        },
        root: root_bound,
        epoch: 10,
    };
    let unopened_res = resolve::open(&resolver_bound, &transport, "bank.bud").expect("page");
    assert_eq!(
        unopened_res.evidence.weakest(),
        Strength::RpcClaimOnly,
        "unopened content_binding must downgrade content_id to RpcClaimOnly, never Verified"
    );
}

#[test]
fn manifest_describes_refuses_duplicate_shard_index_and_erasure_k_mismatch() {
    let part = b"abcd";
    let dup_manifest = BudManifest {
        shards: vec![
            BudShard {
                index: 0,
                shard_id: ContentId::of(part),
                size: 4,
                parity: false,
            },
            BudShard {
                index: 0, // duplicate index!
                shard_id: ContentId::of(part),
                size: 4,
                parity: false,
            },
        ],
        erasure_k: 2,
        erasure_n: 2,
        encryption_tag: 0,
        content_size: 8,
        total_size: 8,
        source_commitment: vec![],
        edition_commitment: vec![],
        dictionary_id: None,
    };
    assert!(
        !dup_manifest.describes(b"abcdabcd"),
        "duplicate data shard indices must fail closed"
    );

    let mut bad_k = BudManifest::single_shard(b"hello");
    bad_k.erasure_k = 2; // claims 2 data shards, only 1 present
    assert!(
        !bad_k.describes(b"hello"),
        "erasure_k mismatch must fail closed"
    );
}

#[test]
fn header_store_refuses_empty_hash_or_state_root() {
    let mut store = HeaderStore::new();
    assert!(store
        .accept(TrackedHeader {
            index: 10,
            epoch: 1,
            state_root: String::new(),
            hash: "h10".into(),
        })
        .is_err());
    assert!(store
        .accept(TrackedHeader {
            index: 10,
            epoch: 1,
            state_root: "r10".into(),
            hash: String::new(),
        })
        .is_err());
}
