use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use tiny_keccak::{Hasher, Keccak};

pub type Hash = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
    pub code_hash: Hash,
    pub storage_root: Hash,
}

pub trait StateBackend {
    fn get_account(&self, id: u64) -> Option<Account>;
    fn set_account(&mut self, id: u64, account: Account);
    fn root(&self) -> Hash;
    fn begin_transaction(&mut self);
    fn commit(&mut self) -> Result<(), String>;
    fn rollback(&mut self);
}

pub struct State {
    accounts: HashMap<u64, Account>,
    path: String,
    backup_stack: Vec<HashMap<u64, Account>>,
}

pub fn hash_account(acc: &Account) -> Hash {
    let mut hasher = Keccak::v256();
    hasher.update(&acc.balance.to_le_bytes());
    hasher.update(&acc.nonce.to_le_bytes());
    hasher.update(&acc.code_hash);
    hasher.update(&acc.storage_root);
    let mut res = [0u8; 32];
    hasher.finalize(&mut res);
    res
}

use std::sync::LazyLock;

static EMPTY_HASHES: LazyLock<[[u8; 32]; 65]> = LazyLock::new(|| {
    let mut hashes = [[0u8; 32]; 65];
    for i in 1..=64 {
        let mut hasher = Keccak::v256();
        hasher.update(&hashes[i - 1]);
        hasher.update(&hashes[i - 1]);
        hasher.finalize(&mut hashes[i]);
    }
    hashes
});

pub fn get_empty_hash(depth: usize) -> Hash {
    EMPTY_HASHES[depth]
}

fn compute_subtree_root(leaves: &[(u64, Hash)], depth: usize, prefix: u64) -> Hash {
    if leaves.is_empty() {
        return get_empty_hash(depth);
    }
    if depth == 0 {
        return leaves[0].1;
    }

    let bit_mask = 1u64 << (depth - 1);
    let partition_idx = leaves
        .binary_search_by_key(&(prefix | bit_mask), |l| l.0)
        .unwrap_or_else(|idx| idx);

    let left_leaves = &leaves[..partition_idx];
    let right_leaves = &leaves[partition_idx..];

    let left_root = compute_subtree_root(left_leaves, depth - 1, prefix);
    let right_root = compute_subtree_root(right_leaves, depth - 1, prefix | bit_mask);

    let mut hasher = Keccak::v256();
    hasher.update(&left_root);
    hasher.update(&right_root);
    let mut res = [0u8; 32];
    hasher.finalize(&mut res);
    res
}

fn compute_subtree_proof(
    leaves: &[(u64, Hash)],
    depth: usize,
    prefix: u64,
    target_key: u64,
    proof: &mut Vec<Hash>,
) {
    if depth == 0 {
        return;
    }

    let bit_mask = 1u64 << (depth - 1);
    let target_bit = (target_key & bit_mask) != 0;

    let partition_idx = leaves
        .binary_search_by_key(&(prefix | bit_mask), |l| l.0)
        .unwrap_or_else(|idx| idx);

    let left_leaves = &leaves[..partition_idx];
    let right_leaves = &leaves[partition_idx..];

    if target_bit {
        let sibling_hash = compute_subtree_root(left_leaves, depth - 1, prefix);
        proof.push(sibling_hash);
        compute_subtree_proof(
            right_leaves,
            depth - 1,
            prefix | bit_mask,
            target_key,
            proof,
        );
    } else {
        let sibling_hash = compute_subtree_root(right_leaves, depth - 1, prefix | bit_mask);
        proof.push(sibling_hash);
        compute_subtree_proof(left_leaves, depth - 1, prefix, target_key, proof);
    }
}

pub fn verify_account_proof(root: Hash, id: u64, account_hash: Hash, proof: &[Hash]) -> bool {
    if proof.len() != 64 {
        return false;
    }

    let mut current = account_hash;
    for depth in 0..64 {
        let bit_mask = 1u64 << depth;
        let target_bit = (id & bit_mask) != 0;
        let sibling = proof[63 - depth];

        let mut hasher = Keccak::v256();
        if target_bit {
            hasher.update(&sibling);
            hasher.update(&current);
        } else {
            hasher.update(&current);
            hasher.update(&sibling);
        }
        hasher.finalize(&mut current);
    }

    current == root
}

impl State {
    pub fn load(path: &str) -> Result<Self, String> {
        let accounts = if std::path::Path::new(path).exists() {
            let data = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read state file: {}", e))?;
            serde_json::from_str(&data).map_err(|e| format!("Failed to parse state JSON: {}", e))?
        } else {
            HashMap::new()
        };
        Ok(Self {
            accounts,
            path: path.to_string(),
            backup_stack: Vec::new(),
        })
    }

    /// Persist state to disk. Returns an error on I/O failure instead of panicking
    /// (Tur 11.5 / A10 — disk full / permission errors must not abort the process).
    pub fn save(&self) -> Result<(), String> {
        self.save_atomic()
    }

    pub fn save_to(&self, path: &str) -> Result<(), String> {
        let data = serde_json::to_string_pretty(&self.accounts)
            .map_err(|e| format!("Failed to serialize state: {}", e))?;
        let temp_path = format!("{}.tmp", path);
        let mut file = fs::File::create(&temp_path)
            .map_err(|e| format!("Failed to create temp state file: {}", e))?;
        file.write_all(data.as_bytes())
            .map_err(|e| format!("Failed to write to temp state file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temp state file: {}", e))?;
        drop(file);
        fs::rename(&temp_path, path)
            .map_err(|e| format!("Failed to rename temp state file to final: {}", e))?;
        Ok(())
    }

    pub fn save_atomic(&self) -> Result<(), String> {
        self.save_to(&self.path)
    }

    pub fn root(&self) -> Hash {
        let mut leaves: Vec<(u64, Hash)> = self
            .accounts
            .iter()
            .map(|(&id, acc)| (id, hash_account(acc)))
            .collect();
        leaves.sort_by_key(|l| l.0);
        compute_subtree_root(&leaves, 64, 0)
    }

    pub fn get_account_proof(&self, id: u64) -> Vec<Hash> {
        let mut leaves: Vec<(u64, Hash)> = self
            .accounts
            .iter()
            .map(|(&k, acc)| (k, hash_account(acc)))
            .collect();
        leaves.sort_by_key(|l| l.0);

        let mut proof = Vec::new();
        compute_subtree_proof(&leaves, 64, 0, id, &mut proof);
        proof
    }
}

impl StateBackend for State {
    fn get_account(&self, id: u64) -> Option<Account> {
        self.accounts.get(&id).cloned()
    }

    fn set_account(&mut self, id: u64, account: Account) {
        self.accounts.insert(id, account);
    }

    fn root(&self) -> Hash {
        self.root()
    }

    fn begin_transaction(&mut self) {
        // Tur 11.5 / A9: nested transactions via LIFO backup stack.
        // A second begin no longer clobbers the outer snapshot.
        self.backup_stack.push(self.accounts.clone());
    }

    fn commit(&mut self) -> Result<(), String> {
        // Drop the innermost snapshot; parent frames stay intact.
        self.backup_stack.pop();
        self.save_atomic()
    }

    fn rollback(&mut self) {
        // Restore the parent transaction's unmodified state.
        if let Some(backup) = self.backup_stack.pop() {
            self.accounts = backup;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_crud() {
        let temp_file = "test_state_crud.json";
        let mut state = State::load(temp_file).unwrap();
        assert!(state.get_account(1).is_none());

        let acc = Account {
            nonce: 5,
            balance: 1000,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };
        state.set_account(1, acc.clone());
        assert_eq!(state.get_account(1), Some(acc));

        state.save().unwrap();
        assert!(std::path::Path::new(temp_file).exists());

        let loaded = State::load(temp_file).unwrap();
        assert_eq!(
            loaded.get_account(1),
            Some(Account {
                nonce: 5,
                balance: 1000,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            })
        );

        fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_state_transactions() {
        let temp_file = "test_state_tx.json";
        let mut state = State::load(temp_file).unwrap();
        state.set_account(
            1,
            Account {
                nonce: 1,
                balance: 500,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        state.save().unwrap();

        state.begin_transaction();
        state.set_account(
            1,
            Account {
                nonce: 2,
                balance: 1000,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        state.set_account(
            2,
            Account {
                nonce: 1,
                balance: 200,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        assert_eq!(state.get_account(1).unwrap().balance, 1000);

        state.rollback();
        assert_eq!(state.get_account(1).unwrap().balance, 500);
        assert!(state.get_account(2).is_none());

        state.begin_transaction();
        state.set_account(
            1,
            Account {
                nonce: 3,
                balance: 1500,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        state.commit().unwrap();

        let loaded = State::load(temp_file).unwrap();
        assert_eq!(loaded.get_account(1).unwrap().balance, 1500);

        fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_state_root_determinism() {
        let mut state1 = State::load("temp1.json").unwrap();
        let mut state2 = State::load("temp2.json").unwrap();

        let acc_a = Account {
            nonce: 1,
            balance: 100,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };
        let acc_b = Account {
            nonce: 2,
            balance: 200,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };

        // Insert in different order
        state1.set_account(1, acc_a.clone());
        state1.set_account(2, acc_b.clone());

        state2.set_account(2, acc_b.clone());
        state2.set_account(1, acc_a.clone());

        assert_eq!(state1.root(), state2.root());
    }

    #[test]
    fn test_smt_proofs() {
        let mut state = State::load("temp_smt.json").unwrap();

        let acc_a = Account {
            nonce: 1,
            balance: 100,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };
        let acc_b = Account {
            nonce: 2,
            balance: 200,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };

        state.set_account(42, acc_a.clone());
        state.set_account(1337, acc_b.clone());

        let root = state.root();

        // 1. Verify proof for an active account (42)
        let hash_a = hash_account(&acc_a);
        let proof_a = state.get_account_proof(42);
        assert_eq!(proof_a.len(), 64);
        assert!(verify_account_proof(root, 42, hash_a, &proof_a));

        // 2. Verify proof for a non-existent account (non-membership proof)
        let proof_empty = state.get_account_proof(999);
        assert_eq!(proof_empty.len(), 64);
        assert!(verify_account_proof(
            root,
            999,
            get_empty_hash(0),
            &proof_empty
        ));
    }

    /// Tur 11.5 / A9: nested begin/rollback must restore each frame independently.
    #[test]
    fn tur115_nested_transaction_stack() {
        let temp_file = "test_state_nested.json";
        let _ = fs::remove_file(temp_file);
        let mut state = State::load(temp_file).unwrap();
        state.set_account(
            1,
            Account {
                nonce: 0,
                balance: 100,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );

        // Outer transaction
        state.begin_transaction();
        state.set_account(
            1,
            Account {
                nonce: 1,
                balance: 200,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );

        // Inner transaction (must not clobber outer backup)
        state.begin_transaction();
        state.set_account(
            1,
            Account {
                nonce: 2,
                balance: 300,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        assert_eq!(state.get_account(1).unwrap().balance, 300);

        // Roll back inner -> outer's post-begin state (balance 200)
        state.rollback();
        assert_eq!(state.get_account(1).unwrap().balance, 200);
        assert_eq!(state.get_account(1).unwrap().nonce, 1);

        // Roll back outer -> original state (balance 100)
        state.rollback();
        assert_eq!(state.get_account(1).unwrap().balance, 100);
        assert_eq!(state.get_account(1).unwrap().nonce, 0);

        // Nested commit: outer begin, inner begin+commit, outer rollback
        // must restore pre-outer state (inner commit only drops its snapshot).
        state.begin_transaction(); // outer
        state.set_account(
            1,
            Account {
                nonce: 5,
                balance: 500,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        state.begin_transaction(); // inner
        state.set_account(
            1,
            Account {
                nonce: 6,
                balance: 600,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        state.commit().unwrap(); // pop inner only
        assert_eq!(state.get_account(1).unwrap().balance, 600);
        state.rollback(); // restore outer snapshot (balance 100)
        assert_eq!(state.get_account(1).unwrap().balance, 100);

        let _ = fs::remove_file(temp_file);
        let _ = fs::remove_file(format!("{}.tmp", temp_file));
    }

    /// Tur 11.5 / A10: save() returns Result; success path still works.
    #[test]
    fn tur115_save_returns_result_on_success() {
        let temp_file = "test_state_save_result.json";
        let _ = fs::remove_file(temp_file);
        let mut state = State::load(temp_file).unwrap();
        state.set_account(
            7,
            Account {
                nonce: 1,
                balance: 42,
                code_hash: [0u8; 32],
                storage_root: [0u8; 32],
            },
        );
        state.save().expect("save must succeed on a writable path");
        let loaded = State::load(temp_file).unwrap();
        assert_eq!(loaded.get_account(7).unwrap().balance, 42);
        fs::remove_file(temp_file).unwrap();
    }

    /// Tur 11.5 / A10: save() must not panic on I/O failure; it returns Err.
    #[test]
    fn tur115_save_returns_err_on_unwritable_path() {
        // Point state path at a non-existent directory so rename/create fails.
        let bad_path = "/this/path/definitely/does/not/exist/state.json";
        let state = State {
            accounts: HashMap::new(),
            path: bad_path.to_string(),
            backup_stack: Vec::new(),
        };
        let err = state
            .save()
            .expect_err("save to missing directory must return Err, not panic");
        assert!(
            !err.is_empty(),
            "error message should be non-empty, got: {err:?}"
        );
    }
}
