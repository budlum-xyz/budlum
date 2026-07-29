use crate::core::address::Address;
use crate::core::transaction::Transaction;
use std::collections::{BTreeMap, BTreeSet, HashMap};

// (2026-07-21) consensus determinizmi — aynı fee'deki
// Işlemler HashSet iteration sırasıyla (process-random) geliyordu;
// `get_sorted_transactions` → `collect_block_transactions` → blok gövdesi
// Sırası node'dan node'a değişebilirdi (aynı-fee tie durumunda farklı blok
// Hash'i / potansiyel split). Tie-break artık canonik: `BTreeSet<String>`
// Ile tx.hash lexikografik düzeni — ücret DESC, hash ASC. Bu kuralı değiştirmek
// Consensus davranışını değiştirir: dokümante ve testli (`test_same_fee_canonical_order_by_hash`).

#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_size: usize,

    pub max_per_sender: usize,

    pub min_fee: u64,

    pub tx_ttl_secs: u64,

    pub rbf_bump_percent: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            max_size: 20000,
            max_per_sender: 100,
            min_fee: 1,
            tx_ttl_secs: 3600,
            rbf_bump_percent: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MempoolError {
    PoolFull,
    DuplicateTransaction,
    FeeTooLow,
    SenderLimitReached,
    InvalidNonce,
    TransactionExpired,
    RbfFeeTooLow,
    InvalidTransaction(String),
}

#[derive(Debug, Clone)]
struct PendingTx {
    tx: Transaction,
    added_at: u128,
}

#[derive(Clone)]
pub struct Mempool {
    config: MempoolConfig,

    transactions: HashMap<String, PendingTx>,

    by_sender: HashMap<Address, BTreeMap<u64, String>>,

    by_fee: BTreeMap<u64, BTreeSet<String>>,
}

impl Mempool {
    pub fn new(config: MempoolConfig) -> Self {
        Mempool {
            config,
            transactions: HashMap::new(),
            by_sender: HashMap::new(),
            by_fee: BTreeMap::new(),
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), MempoolError> {
        // Verify transaction signature BEFORE
        // Accepting into mempool. Without this, an attacker can flood the
        // Mempool with invalid-signature transactions that propagate via
        // Gossip, wasting every node's CPU on signature verification.
        if tx.from != crate::core::address::Address::zero() && !tx.verify() {
            return Err(MempoolError::InvalidTransaction(
                "Invalid transaction signature".into(),
            ));
        }

        if self.transactions.contains_key(&tx.hash) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if tx.fee < self.config.min_fee {
            return Err(MempoolError::FeeTooLow);
        }

        if self.transactions.len() >= self.config.max_size && !self.evict_lowest_fee(&tx) {
            return Err(MempoolError::PoolFull);
        }

        let sender_count = self.by_sender.get(&tx.from).map_or(0, |v| v.len());

        if let Some(existing_hash) = self.find_tx_by_sender_nonce(&tx.from, tx.nonce) {
            let existing = self.transactions.get(&existing_hash).unwrap();
            // RBF bump her zaman POZİTİF olmalı. Tamsayı bölmesiyle
            // Küçük fee'lerde bump 0'a yuvarlanıyordu (fee=1, %10 → bump 0)
            // → aynı fee ile limitsiz replace-churn (ucuz DoS vektörü).
            // Artık: bump = max(1, ceil(fee * pct / 100)); replace fee > eski
            // Fee olmak ZORUNDA. Overflow'a karşı u128 ara hesaplama.
            let bump =
                (existing.tx.fee as u128 * self.config.rbf_bump_percent as u128).div_ceil(100);
            let min_new_fee = existing
                .tx
                .fee
                .saturating_add(u64::try_from(bump.max(1)).unwrap_or(u64::MAX));
            if tx.fee < min_new_fee {
                return Err(MempoolError::RbfFeeTooLow);
            }

            self.remove_transaction(&existing_hash);
        } else {
            if sender_count >= self.config.max_per_sender {
                return Err(MempoolError::SenderLimitReached);
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        self.by_sender
            .entry(tx.from)
            .or_default()
            .insert(tx.nonce, tx.hash.clone());
        self.by_fee
            .entry(tx.fee)
            .or_default()
            .insert(tx.hash.clone());

        self.transactions
            .insert(tx.hash.clone(), PendingTx { tx, added_at: now });

        Ok(())
    }

    pub fn remove_transaction(&mut self, hash: &str) -> Option<Transaction> {
        if let Some(pending) = self.transactions.remove(hash) {
            if let Some(sender_txs) = self.by_sender.get_mut(&pending.tx.from) {
                sender_txs.remove(&pending.tx.nonce);
                if sender_txs.is_empty() {
                    self.by_sender.remove(&pending.tx.from);
                }
            }

            if let Some(fee_txs) = self.by_fee.get_mut(&pending.tx.fee) {
                fee_txs.remove(hash);
                if fee_txs.is_empty() {
                    self.by_fee.remove(&pending.tx.fee);
                }
            }
            return Some(pending.tx);
        }
        None
    }

    pub fn get_sorted_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut result = Vec::with_capacity(limit);

        for (_, hashes) in self.by_fee.iter().rev() {
            for hash in hashes {
                if result.len() >= limit {
                    return result;
                }
                if let Some(pending) = self.transactions.get(hash) {
                    result.push(pending.tx.clone());
                }
            }
        }
        result
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let ttl_ms = self.config.tx_ttl_secs as u128 * 1000;
        let expired: Vec<String> = self
            .transactions
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.added_at) > ttl_ms)
            .map(|(h, _)| h.clone())
            .collect();

        let count = expired.len();
        for hash in expired {
            self.remove_transaction(&hash);
        }
        count
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn get(&self, hash: &str) -> Option<&Transaction> {
        self.transactions.get(hash).map(|p| &p.tx)
    }

    pub fn sender_transactions(&self, sender: &Address) -> Vec<Transaction> {
        self.by_sender
            .get(sender)
            .map(|nonces| {
                nonces
                    .values()
                    .filter_map(|hash| {
                        self.transactions
                            .get(hash)
                            .map(|pending| pending.tx.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn drain(&mut self) -> Vec<Transaction> {
        let txs: Vec<Transaction> = self.transactions.values().map(|p| p.tx.clone()).collect();
        self.transactions.clear();
        self.by_sender.clear();
        self.by_fee.clear();
        txs
    }

    fn find_tx_by_sender_nonce(&self, sender: &Address, nonce: u64) -> Option<String> {
        self.by_sender
            .get(sender)
            .and_then(|nonces| nonces.get(&nonce).cloned())
    }

    fn evict_lowest_fee(&mut self, new_tx: &Transaction) -> bool {
        if let Some((&lowest_fee, hashes)) = self.by_fee.iter().next() {
            if new_tx.fee > lowest_fee {
                if let Some(hash) = hashes.iter().next().cloned() {
                    self.remove_transaction(&hash);
                    return true;
                }
            }
        }
        false
    }

    pub fn set_min_fee(&mut self, min_fee: u64) {
        self.config.min_fee = min_fee;
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(MempoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx_from_seed(seed_byte: u8, nonce: u64, fee: u64) -> Transaction {
        // Deterministic test keypair from single byte seed (avoids hard-coded crypto literal).
        let seed = [seed_byte; 32];
        let keypair = crate::crypto::primitives::KeyPair::from_seed(&seed).unwrap();
        let from = crate::core::address::Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new(from, crate::core::address::Address::zero(), 100, vec![]);
        tx.nonce = nonce;
        tx.fee = fee;
        tx.hash = tx.calculate_hash();
        tx.sign(&keypair);
        tx
    }

    #[test]
    fn test_add_and_get() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 10);
        assert!(pool.add_transaction(tx.clone()).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&tx.hash).is_some());
    }

    #[test]
    fn cleanup_tolerates_wall_clock_rollback() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 10);
        let hash = tx.hash.clone();
        pool.add_transaction(tx).unwrap();
        pool.transactions.get_mut(&hash).unwrap().added_at = u128::MAX;

        assert_eq!(pool.cleanup_expired(), 0);
        assert!(pool.get(&hash).is_some());
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 10);
        pool.add_transaction(tx.clone()).unwrap();
        assert_eq!(
            pool.add_transaction(tx),
            Err(MempoolError::DuplicateTransaction)
        );
    }

    #[test]
    fn test_fee_too_low() {
        let mut pool = Mempool::default();
        let tx = create_test_tx_from_seed(1, 0, 0);
        assert_eq!(pool.add_transaction(tx), Err(MempoolError::FeeTooLow));
    }

    #[test]
    fn test_sender_limit() {
        let config = MempoolConfig {
            max_per_sender: 2,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);

        let alice_seed = 1u8;
        pool.add_transaction(create_test_tx_from_seed(alice_seed, 0, 10))
            .unwrap();
        pool.add_transaction(create_test_tx_from_seed(alice_seed, 1, 10))
            .unwrap();
        assert_eq!(
            pool.add_transaction(create_test_tx_from_seed(alice_seed, 2, 10)),
            Err(MempoolError::SenderLimitReached)
        );
    }

    #[test]
    fn test_sorted_by_fee() {
        let mut pool = Mempool::default();
        pool.add_transaction(create_test_tx_from_seed(1, 0, 5))
            .unwrap();
        pool.add_transaction(create_test_tx_from_seed(2, 0, 20))
            .unwrap();
        pool.add_transaction(create_test_tx_from_seed(3, 0, 10))
            .unwrap();

        let sorted = pool.get_sorted_transactions(10);
        assert_eq!(sorted[0].fee, 20);
        assert_eq!(sorted[1].fee, 10);
        assert_eq!(sorted[2].fee, 5);
    }

    #[test]
    fn test_rbf() {
        let mut pool = Mempool::default();
        let alice_seed = 1u8;
        let tx1 = create_test_tx_from_seed(alice_seed, 0, 10);
        pool.add_transaction(tx1).unwrap();

        // Same sender+nonce, higher fee — RBF replace.
        let tx2 = create_test_tx_from_seed(alice_seed, 0, 15);
        assert!(pool.add_transaction(tx2).is_ok());
        assert_eq!(pool.len(), 1);
    }

    /// Aynı fee tie-break canonik (tx.hash ASC). Farklı ekleme
    /// Sırası sonucu DEĞİŞTİRMEMELİ — eski HashSet yolu process-random
    /// Iteration ile bu testin iki havuzunda fark verirdi (flaky/üretimde
    /// Nondeterministik blok gövdesi sırası).
    #[test]
    fn test_same_fee_canonical_order_by_hash() {
        // Three different senders with same fee — canonical order by tx.hash.
        let tx_a = create_test_tx_from_seed(1, 0, 10);
        let tx_b = create_test_tx_from_seed(2, 0, 10);
        let tx_c = create_test_tx_from_seed(3, 0, 10);

        let mut hashes = vec![tx_a.hash.clone(), tx_b.hash.clone(), tx_c.hash.clone()];
        hashes.sort();
        // Verify all hashes are distinct
        assert_eq!(hashes.len(), 3);

        let mut pool1 = Mempool::default();
        pool1.add_transaction(tx_c.clone()).unwrap();
        pool1.add_transaction(tx_a.clone()).unwrap();
        pool1.add_transaction(tx_b.clone()).unwrap();
        let order1: Vec<String> = pool1
            .get_sorted_transactions(10)
            .iter()
            .map(|t| t.hash.clone())
            .collect();
        assert_eq!(order1, hashes);

        // Farklı ekleme sırası, aynı canonik çıktı.
        let mut pool2 = Mempool::default();
        pool2.add_transaction(tx_b).unwrap();
        pool2.add_transaction(tx_c).unwrap();
        pool2.add_transaction(tx_a).unwrap();
        let order2: Vec<String> = pool2
            .get_sorted_transactions(10)
            .iter()
            .map(|t| t.hash.clone())
            .collect();
        assert_eq!(order1, order2);
    }

    /// RBF replace her zaman kat'i pozitif bump ister.
    /// Eski yol: fee=1, %10 → bump=0 → aynı fee ile replace (churn vektörü).
    #[test]
    fn test_rbf_requires_strict_positive_bump() {
        let mut pool = Mempool::default();
        let alice_seed = 1u8;
        let tx1 = create_test_tx_from_seed(alice_seed, 0, 1);
        pool.add_transaction(tx1).unwrap();

        // Aynı fee ile replace RED — farklı hash için nonce'u 1 kullan,
        // Sonra geri nonce 0'a dönüp fee bump kontrolünü test et.
        // Tx2: same sender, same nonce (0), same fee (1), different data → different hash.
        let seed = [alice_seed; 32];
        let keypair = crate::crypto::primitives::KeyPair::from_seed(&seed).unwrap();
        let from = crate::core::address::Address::from(keypair.public_key_bytes());

        let mut tx2 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v2".to_vec(),
        );
        tx2.nonce = 0;
        tx2.fee = 1;
        tx2.hash = tx2.calculate_hash();
        tx2.sign(&keypair);
        assert_eq!(pool.add_transaction(tx2), Err(MempoolError::RbfFeeTooLow));

        // Fee=2 (%10 ⇒ ceil(0.1)=1 ⇒ min 2) KABUL.
        let mut tx3 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v3".to_vec(),
        );
        tx3.nonce = 0;
        tx3.fee = 2;
        tx3.hash = tx3.calculate_hash();
        tx3.sign(&keypair);
        assert!(pool.add_transaction(tx3).is_ok());
        assert_eq!(pool.len(), 1);

        // Fee=100 (%10 ⇒ bump=10 ⇒ min 110): 109 RED, 110 KABUL.
        let mut tx4 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v4".to_vec(),
        );
        tx4.nonce = 1;
        tx4.fee = 100;
        tx4.hash = tx4.calculate_hash();
        tx4.sign(&keypair);
        pool.add_transaction(tx4).unwrap();

        let mut tx5 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v5".to_vec(),
        );
        tx5.nonce = 1;
        tx5.fee = 109;
        tx5.hash = tx5.calculate_hash();
        tx5.sign(&keypair);
        assert_eq!(pool.add_transaction(tx5), Err(MempoolError::RbfFeeTooLow));

        let mut tx6 = Transaction::new(
            from,
            crate::core::address::Address::zero(),
            100,
            b"v6".to_vec(),
        );
        tx6.nonce = 1;
        tx6.fee = 110;
        tx6.hash = tx6.calculate_hash();
        tx6.sign(&keypair);
        assert!(pool.add_transaction(tx6).is_ok());
    }

    #[test]
    fn test_cleanup_expired() {
        let config = MempoolConfig {
            tx_ttl_secs: 1,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);

        let tx = create_test_tx_from_seed(1, 0, 10);
        pool.add_transaction(tx).unwrap();
        assert_eq!(pool.len(), 1);

        std::thread::sleep(std::time::Duration::from_secs(2));

        let removed = pool.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }
}
