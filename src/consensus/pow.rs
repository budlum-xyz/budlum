use super::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use std::sync::RwLock;
use tracing::info;

/// A 256-bit unsigned integer, carrying exactly the three operations
/// accumulated proof-of-work needs: `2^n`, addition, and comparison.
///
/// Chainwork does not fit 128 bits (see [`PoWEngine::accumulated_work`]), and
/// pulling in a bignum crate to add four numbers would be a dependency, an
/// audit obligation and a supply-chain entry for arithmetic that is a dozen
/// lines. Stored as four little-endian 64-bit limbs; `Ord` is derived over the
/// big-endian view via an explicit comparison so ordering matches magnitude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct U256 {
    /// Little-endian limbs: `limbs[0]` is the least significant.
    limbs: [u64; 4],
}

impl U256 {
    pub const ZERO: Self = Self { limbs: [0; 4] };
    pub const MAX: Self = Self {
        limbs: [u64::MAX; 4],
    };

    /// `2^exponent`, saturating at [`U256::MAX`] rather than wrapping.
    ///
    /// Wrapping here would be the same class of bug this type exists to fix:
    /// a huge amount of work would score as a small one.
    #[must_use]
    pub const fn pow2(exponent: u32) -> Self {
        if exponent >= 256 {
            return Self::MAX;
        }
        let limb = (exponent / 64) as usize;
        let bit = exponent % 64;
        let mut limbs = [0u64; 4];
        limbs[limb] = 1u64 << bit;
        Self { limbs }
    }

    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        let mut limbs = [0u64; 4];
        let mut carry = 0u64;
        // Indexed rather than iterated: `const fn` has no iterators, and the
        // carry chain is inherently sequential across limbs anyway.
        let mut i = 0;
        while i < 4 {
            let (sum, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            limbs[i] = sum;
            carry = c1 as u64 + c2 as u64; // bool as u64: const fn, From unavailable
            i += 1;
        }
        if carry > 0 {
            Self::MAX
        } else {
            Self { limbs }
        }
    }

    /// The low 128 bits, saturating if anything is set above them.
    ///
    /// Only for reporting. A saturating value cannot order two chains, which
    /// is why `is_better_chain` compares `U256` directly.
    #[must_use]
    pub const fn saturating_to_u128(self) -> u128 {
        if self.limbs[2] != 0 || self.limbs[3] != 0 {
            return u128::MAX;
        }
        (self.limbs[0] as u128) | ((self.limbs[1] as u128) << 64)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Most significant limb first, so ordering follows magnitude rather
        // than the little-endian storage order.
        for (lhs, rhs) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match lhs.cmp(rhs) {
                std::cmp::Ordering::Equal => (),
                non_equal => return non_equal,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
#[derive(Debug, Clone)]
pub struct PoWConfig {
    pub difficulty: usize,
    pub target_block_time: u64,
    pub adjustment_interval: u64,
}
impl Default for PoWConfig {
    fn default() -> Self {
        PoWConfig {
            difficulty: 2,
            target_block_time: 10,
            adjustment_interval: 100,
        }
    }
}
pub struct PoWEngine {
    pub config: PoWConfig,
    current_difficulty: RwLock<usize>,
}
impl PoWEngine {
    pub fn new(difficulty: usize) -> Self {
        PoWEngine {
            config: PoWConfig {
                difficulty,
                ..Default::default()
            },
            current_difficulty: RwLock::new(difficulty),
        }
    }

    #[cfg(test)]
    pub fn adjusted_difficulty_for_test(&self, current: usize, actual_time_sn: u64) -> usize {
        let expected_time = self
            .config
            .target_block_time
            .saturating_mul(self.config.adjustment_interval);
        let ratio_scaled = (expected_time as u128 * 100) / (actual_time_sn as u128).max(1);
        let ratio_capped = ratio_scaled.clamp(25, 400);
        ((current as u128 * ratio_capped) / 100).clamp(1, 32) as usize
    }
    /// Uretici tick araligina kalibre edilmis motor.
    ///
    /// `new` her zaman `PoWConfig::default()` degerini (10 sn hedef) alir.
    /// Uretici ise `slot_ms` ile tick atar: devnet 1 sn, testnet 3 sn,
    /// mainnet 6 sn. Iki sayi birbirinden habersiz oldugu icin retarget
    /// zinciri "cok hizli" sayip zorlugu her 100 blokta 4 katina cikarir.
    ///
    /// Canli devnet dugumunde olculdu: 100. blokta zorluk 2 -> 8 (32 sifir
    /// bit), ardindan 364 milyon iterasyonda blok bulunamadi ve zincir
    /// durdu. Tirmanis 2 -> 8 -> 32 (tavan) diye devam ettigi icin geri
    /// donusu yoktur.
    ///
    /// Bu kurucu hedefi uretim hizina esitler; retarget boylece gercek
    /// sapmayi olcer, sabit bir kalibrasyon hatasini degil.
    pub fn calibrated(difficulty: usize, slot_ms: u64) -> Self {
        let target_block_time = (slot_ms / 1000).max(1);
        PoWEngine::with_config(PoWConfig {
            difficulty,
            target_block_time,
            ..Default::default()
        })
    }

    pub fn with_config(config: PoWConfig) -> Self {
        let d = config.difficulty;
        PoWEngine {
            config,
            current_difficulty: RwLock::new(d),
        }
    }
    /// Accumulated proof-of-work across `chain`, in 256 bits.
    ///
    /// Work per block is `16^difficulty` - one hex digit of leading zeroes per
    /// difficulty step. `adjusted_difficulty` clamps difficulty to 32, and
    /// `16^32` is exactly `2^128`, so the retarget ceiling sits precisely at
    /// the boundary of a `u128`. That is not a coincidence to design around;
    /// it is the same 128 appearing on both sides.
    ///
    /// The previous accumulator saturated instead of widening:
    ///
    /// ```text
    /// let work = 16u128.checked_pow(d).unwrap_or(u128::MAX);
    /// score = score.saturating_add(work.max(1));
    /// ```
    ///
    /// Measured, all of these produced the identical score:
    ///
    /// ```text
    /// difficulty 32, any chain length  -> u128::MAX
    /// difficulty 31, 16 blocks or more -> u128::MAX
    /// ```
    ///
    /// Once two candidates both saturate they compare equal, `is_better_chain`
    /// returns false for every reorg, and the node locks onto whichever chain
    /// it saw first with no way to be corrected. Saturation is not a
    /// conservative failure here: it disables fork choice silently, at exactly
    /// the difficulties a mature chain reaches.
    ///
    /// Scaling every term down by a shared constant would preserve ordering at
    /// the top but destroy it at the bottom - devnet runs at difficulty 1 or 2,
    /// and a shift large enough to save difficulty 32 flattens those to zero.
    /// Bitcoin carries chainwork in 256 bits for this reason, so this does too.
    #[must_use]
    pub fn accumulated_work(&self, chain: &[Block]) -> U256 {
        let mut score = U256::ZERO;
        for index in 1..chain.len() {
            let difficulty = self.difficulty_for_next_block(&chain[..index]);
            // 16^d == 2^(4d); take the exponent directly so no intermediate
            // has to fit a narrower type.
            let work = U256::pow2(
                u32::try_from(difficulty)
                    .unwrap_or(u32::MAX)
                    .saturating_mul(4),
            );
            score = score.saturating_add(work);
        }
        score
    }

    pub fn get_difficulty(&self) -> usize {
        *self
            .current_difficulty
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn meets_difficulty_at(hash_hex: &str, difficulty: usize) -> bool {
        let hash_bytes = match hex::decode(hash_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let leading_zero_bits = difficulty.saturating_mul(4);
        let full_bytes = leading_zero_bits / 8;
        let remaining_bits = leading_zero_bits % 8;
        if hash_bytes.len() < full_bytes + usize::from(remaining_bits > 0) {
            return false;
        }
        if hash_bytes[..full_bytes].iter().any(|byte| *byte != 0) {
            return false;
        }
        if remaining_bits > 0 {
            let mask = 0xFFu8 << (8 - remaining_bits);
            if hash_bytes[full_bytes] & mask != 0 {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    fn meets_difficulty(&self, hash_hex: &str) -> bool {
        Self::meets_difficulty_at(hash_hex, self.get_difficulty())
    }

    fn mine_at_difficulty(&self, block: &mut Block, difficulty: usize) {
        let mut iterations: u64 = 0;
        info!(
            "Mining started (difficulty: {}, binary target: {} leading zero bits)",
            difficulty,
            difficulty.saturating_mul(4),
        );
        while !Self::meets_difficulty_at(&block.hash, difficulty) {
            block.nonce = block.nonce.saturating_add(1);
            block.hash = block.calculate_hash();
            iterations = iterations.saturating_add(1);
            if iterations.is_multiple_of(100_000) {
                info!(
                    "Mining progress: {} iterations, nonce: {}",
                    iterations, block.nonce
                );
            }
        }
        info!(
            "Mining complete: {} iterations, nonce: {}",
            iterations, block.nonce
        );
    }

    fn adjusted_difficulty(&self, current: usize, first: &Block, last: &Block) -> usize {
        let actual_time = last.timestamp.saturating_sub(first.timestamp) / 1000;
        let expected_time = self
            .config
            .target_block_time
            .saturating_mul(self.config.adjustment_interval);
        let ratio_scaled = (expected_time as u128 * 100) / actual_time.max(1);
        let ratio_capped = ratio_scaled.clamp(25, 400);
        ((current as u128 * ratio_capped) / 100).clamp(1, 32) as usize
    }

    pub fn difficulty_for_next_block(&self, chain: &[Block]) -> usize {
        let interval = self.config.adjustment_interval as usize;
        let mut difficulty = self.config.difficulty;
        if interval == 0 {
            return difficulty;
        }
        let mut boundary = interval;
        while boundary < chain.len() {
            let boundary_block = &chain[boundary];
            if boundary_block.index > 0
                && boundary_block
                    .index
                    .is_multiple_of(self.config.adjustment_interval)
            {
                let first_index = boundary.saturating_add(1).saturating_sub(interval);
                difficulty =
                    self.adjusted_difficulty(difficulty, &chain[first_index], boundary_block);
            }
            boundary = boundary.saturating_add(interval);
        }
        difficulty
    }

    pub fn calculate_new_difficulty(&self, chain: &[Block]) -> usize {
        self.difficulty_for_next_block(chain)
    }

    /// (security audit §3) difficulty-adjustment driver invoked
    /// From `blockchain.rs` after a block has been durably committed.
    /// Public so the blockchain can drive the adjustment with the full
    /// Post-commit chain in hand. The previous design mutated
    /// `current_difficulty` from inside `validate_block`, which was
    /// Both impure and vulnerable to re-validation attacks.
    pub fn record_block_with_chain(&self, block: &Block, chain: &[Block]) {
        if block.index > 0 && block.index.is_multiple_of(self.config.adjustment_interval) {
            let new_diff = self.calculate_new_difficulty(chain);
            if let Ok(mut d) = self.current_difficulty.write() {
                *d = new_diff;
            }
        }
    }
}
impl ConsensusEngine for PoWEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        block.hash = block.calculate_hash();
        self.mine_at_difficulty(block, self.get_difficulty());
        Ok(())
    }

    fn prepare_block_with_chain(
        &self,
        block: &mut Block,
        _state: &AccountState,
        chain: &[Block],
    ) -> Result<(), ConsensusError> {
        let difficulty = self.difficulty_for_next_block(chain);
        block.hash = block.calculate_hash();
        self.mine_at_difficulty(block, difficulty);
        Ok(())
    }

    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        if block.index == 0 {
            if block.hash != block.calculate_hash() {
                return Err(ConsensusError("Invalid genesis block hash".into()));
            }
            return Ok(());
        }
        if let Some(prev_block) = chain.last() {
            if block.previous_hash != prev_block.hash {
                return Err(ConsensusError(format!(
                    "Previous hash mismatch. Expected: {}, Got: {}",
                    prev_block.hash, block.previous_hash
                )));
            }
        }
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid block hash. Calculated: {}, Existing: {}",
                calculated_hash, block.hash
            )));
        }

        // Difficulty is replayed from the candidate prefix. Validation never
        // Trusts process-local cache state, so restart and fork validation use
        // Exactly the target that the historical chain implies.
        let expected_difficulty = self.difficulty_for_next_block(chain);
        if !Self::meets_difficulty_at(&block.hash, expected_difficulty) {
            return Err(ConsensusError(format!(
                "Invalid PoW. {} leading-zero nibbles required, hash: {}",
                expected_difficulty, block.hash
            )));
        }
        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        // (security audit §3) the trait `record_block` hook is
        // Intentionally a no-op for PoW. The actual difficulty
        // Adjustment lives in `record_block_with_chain` (overridden
        // Below), which is called from `blockchain.rs` after a block
        // Is durably committed and the chain is in its post-commit
        // State. Keeping the trait hook as a no-op makes the
        // Contract explicit: validation is pure, and the only
        // State mutation triggered by a block landing on the chain
        // Is the chain-aware record path.
        Ok(())
    }

    fn record_block_with_chain(
        &self,
        block: &Block,
        chain: &[Block],
        _storage: Option<&crate::storage::db::Storage>,
    ) {
        // See `record_block_with_chain` in `consensus/mod.rs` for the
        // Contract. The difficulty adjustment fires here, exactly
        // Once per block, after the block has been accepted and
        // Durably committed (see `produce_block` and
        // `validate_and_add_block` in blockchain.rs, which call this
        // Method after `commit_block_durable`).
        if block.index > 0 && block.index.is_multiple_of(self.config.adjustment_interval) {
            let new_diff = self.calculate_new_difficulty(chain);
            if let Ok(mut d) = self.current_difficulty.write() {
                *d = new_diff;
            }
        }
    }
    fn consensus_type(&self) -> &'static str {
        "PoW"
    }
    fn info(&self) -> String {
        format!(
            "PoW (difficulty: {}, binary target: {} leading zero bits)",
            self.get_difficulty(),
            self.get_difficulty() * 4
        )
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        // Retained for the trait's reporting use. Chain comparison goes
        // through `accumulated_work`, which does not truncate; this value is
        // the low 128 bits and can saturate, so it must not decide a reorg.
        self.accumulated_work(chain).saturating_to_u128()
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        self.accumulated_work(candidate) > self.accumulated_work(current)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pow_mining() {
        let engine = PoWEngine::new(1);
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        let state = AccountState::new();
        engine.prepare_block(&mut block, &state).unwrap();
        assert!(block.hash.starts_with("0"));
    }
    #[test]
    fn test_pow_validation() {
        let engine = PoWEngine::new(1);
        let mut block = Block::new(1, "0".repeat(64), vec![]);
        let state = AccountState::new();
        engine.prepare_block(&mut block, &state).unwrap();
        assert!(engine.validate_block(&block, &[], &state).is_ok());
        let mut tampered = block.clone();
        tampered.hash = "invalid_hash".to_string();
        assert!(engine.validate_block(&tampered, &[], &state).is_err());
    }
    #[test]
    fn test_difficulty_levels() {
        let easy = PoWEngine::new(1);
        let hard = PoWEngine::new(2);
        let mut block1 = Block::new(1, "0".repeat(64), vec![]);
        let mut block2 = Block::new(1, "0".repeat(64), vec![]);
        let state = AccountState::new();
        easy.prepare_block(&mut block1, &state).unwrap();
        hard.prepare_block(&mut block2, &state).unwrap();
        assert!(block1.hash.starts_with("0"));
        assert!(block2.hash.starts_with("00"));
    }

    /// (security audit §3) `validate_block` must be PURE, calling
    /// It twice on the same block must produce the same result AND
    /// Must not mutate the engine's `current_difficulty`. The
    /// Previous implementation mutated difficulty from inside
    /// Validation, so the *second* call could see a different
    /// Difficulty than the first.
    #[test]
    fn validate_block_is_pure_and_idempotent() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 100,
        });
        let state = AccountState::new();

        // Build a chain with a real genesis block so `validate_block`
        // Can match `block.previous_hash` against the previous block.
        let mut genesis = Block::new(0, "0".repeat(64), vec![]);
        genesis.hash = genesis.calculate_hash();

        // Mine a child block at difficulty 1.
        let mut child = Block::new(1, genesis.hash.clone(), vec![]);
        engine.prepare_block(&mut child, &state).unwrap();

        let chain = vec![genesis];
        let diff_before = engine.get_difficulty();
        let result_1 = engine.validate_block(&child, &chain, &state);
        let diff_after_1 = engine.get_difficulty();
        let result_2 = engine.validate_block(&child, &chain, &state);
        let diff_after_2 = engine.get_difficulty();
        assert!(
            result_1.is_ok(),
            "first validate must succeed: {:?}",
            result_1.err()
        );
        assert!(
            result_2.is_ok(),
            "second validate must also succeed: {:?}",
            result_2.err()
        );
        assert_eq!(
            diff_before, diff_after_1,
            "validate must not mutate difficulty (first call)"
        );
        assert_eq!(
            diff_after_1, diff_after_2,
            "validate must not mutate difficulty (second call)"
        );
    }

    /// (security audit §3) difficulty adjustment must fire
    /// From `record_block_with_chain`, NOT from `validate_block`.
    /// Here, an adjustment-boundary block is *validated* without a
    /// Prior `record_block_with_chain` call, and the difficulty
    /// Must remain at its pre-adjustment value. The adjustment only
    /// Fires once the chain-aware record path is invoked.
    #[test]
    fn difficulty_adjustment_fires_only_from_record_block_with_chain() {
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 1,
            target_block_time: 10,
            adjustment_interval: 4,
        });
        assert_eq!(engine.get_difficulty(), 1);

        // Build a synthetic chain of 4 blocks (adjustment boundary
        // At index 4, which is `is_multiple_of(4)`). Difficulty 1
        // Mining is fast - we don't need the chain to be long.
        let mut chain: Vec<Block> = Vec::new();
        let mut genesis = Block::new(0, "0".repeat(64), vec![]);
        genesis.hash = genesis.calculate_hash();
        chain.push(genesis);
        for i in 1..=4u64 {
            let prev_hash = chain[(i - 1) as usize].hash.clone();
            let mut b = Block::new(i, prev_hash, vec![]);
            let state = AccountState::new();
            engine.prepare_block(&mut b, &state).unwrap();
            chain.push(b);
        }
        let boundary = &chain[4usize];

        // Validating the boundary block alone must NOT trigger the
        // Adjustment (validate is pure). The chain passed to
        // `validate_block` is everything *before* the boundary block
        // (genesis + blocks 1..4), since the block being validated is
        // Not yet part of the chain the validator sees.
        let state = AccountState::new();
        let prefix = &chain[..4];
        assert!(engine.validate_block(boundary, prefix, &state).is_ok());
        assert_eq!(
            engine.get_difficulty(),
            1,
            "validate must not adjust difficulty"
        );

        // Now drive the adjustment through the chain-aware record
        // Path. The post-adjustment difficulty must stay within the
        // [1, 32] clamp. The chain here is the *post-commit* chain
        // (boundary is the last block in the chain).
        engine.record_block_with_chain(boundary, &chain);
        let diff_after_record = engine.get_difficulty();
        assert!(
            (1..=32).contains(&diff_after_record),
            "adjusted difficulty must be within [1, 32] clamp, got {}",
            diff_after_record
        );
    }

    #[test]
    fn test_difficulty_adjustment_safely_handles_non_monotonic_timestamps() {
        let mut engine = PoWEngine::new(1);
        engine.config.adjustment_interval = 2;
        let mut block1 = Block::new(1, "g".into(), vec![]);
        block1.timestamp = 2000;
        let mut block2 = Block::new(2, "b1".into(), vec![]);
        block2.timestamp = 1000;
        let chain = vec![block1, block2.clone()];
        engine.record_block_with_chain(&block2, &chain);
        assert!((1..=32).contains(&engine.get_difficulty()));
    }

    /// Binary difficulty check correctly validates
    /// Hashes with leading zero bits.
    #[test]
    fn meets_difficulty_binary_check() {
        let engine = PoWEngine::new(1);
        // Difficulty=1 → 4 leading zero bits → first hex char must be '0'
        assert!(engine.meets_difficulty("0abc1234"));
        assert!(!engine.meets_difficulty("1abc1234"));

        let engine2 = PoWEngine::new(2);
        // Difficulty=2 → 8 leading zero bits → first two hex chars "00"
        assert!(engine2.meets_difficulty("00abcdef"));
        assert!(!engine2.meets_difficulty("01abcdef"));

        // Odd difficulty: difficulty=3 → 12 leading zero bits → "000" prefix
        let engine3 = PoWEngine::new(3);
        assert!(engine3.meets_difficulty("000abcde"));
        assert!(!engine3.meets_difficulty("001abcde"));

        // Invalid hex should return false, not panic
        assert!(!engine.meets_difficulty("not-a-hex-string"));
    }
    /// BULGU: uretici tick araligi (`slot_ms`) ile PoW retarget hedefi
    /// (`target_block_time`) birbirinden habersiz kuruluyor. `PoWEngine::new`
    /// her zaman `PoWConfig::default()` degerini (10 sn) aliyor, oysa devnet
    /// slotu 1 sn. Olculdu: canli devnet dugumu 100. blokta zorlugu 2'den 8'e
    /// (32 sifir bit) sicratti, 285 milyon iterasyonda blok bulamadi ve zincir
    /// durdu. Retarget her 100 blokta en fazla 4x artabildigi icin tirmanis
    /// 2 -> 8 -> 32 (tavan) diye devam eder; bu geri donusu olmayan bir kilit.
    /// Mevcut testler yalnizca [1,32] clamp'ini dogruluyordu, orantiligi degil.
    #[test]
    fn retarget_uretici_hizina_gore_kalibre_edilmeli() {
        // Zincirin gercekten urettigi hiz: 1 sn/blok (devnet slot_ms=1000).
        let gercek_slot_sn = 1u64;
        // Hedef bu hiza kalibre edilirse zorluk sabit kalmali.
        let engine = PoWEngine::with_config(PoWConfig {
            difficulty: 2,
            target_block_time: gercek_slot_sn,
            adjustment_interval: 100,
        });
        // 100 blok x 1 sn = 100 sn gecti; beklenen de 100 sn.
        let d = engine.adjusted_difficulty_for_test(2, 100);
        assert_eq!(
            d, 2,
            "uretici hizi hedefe esitken zorluk degismemeli, {d} bulundu"
        );

        // Kalibrasyon yoksa (varsayilan 10 sn hedef) ayni zincir zorlugu
        // 4 katina cikarir - canli dugumde olculen davranis budur.
        let kalibresiz = PoWEngine::new(2);
        let d2 = kalibresiz.adjusted_difficulty_for_test(2, 100);
        assert_eq!(
            d2, 8,
            "kalibresiz motor 100 sn'lik 100 blogu 10x hizli sayip zorlugu 8'e cikarir"
        );
    }

    /// `calibrated` her ag icin retargeti uretim hizina esitler.
    #[test]
    fn calibrated_uretim_hizina_esitler() {
        // (slot_ms, beklenen hedef sn)
        for (slot_ms, beklenen) in [(1_000u64, 1u64), (3_000, 3), (6_000, 6)] {
            let e = PoWEngine::calibrated(2, slot_ms);
            assert_eq!(
                e.config.target_block_time, beklenen,
                "slot {slot_ms}ms icin hedef {beklenen} sn olmali"
            );
            // Zincir tam bu hizda uretirken zorluk sabit kalmali.
            let gecen = beklenen.saturating_mul(e.config.adjustment_interval);
            assert_eq!(
                e.adjusted_difficulty_for_test(2, gecen),
                2,
                "uretim hedefe esitken zorluk degismemeli (slot {slot_ms}ms)"
            );
        }
    }

    /// Kalibrasyon sifira bolunmeye yol acmamali: 1 sn altindaki slotlar
    /// tabana oturur.
    #[test]
    fn calibrated_alt_sinirda_sifirlanmaz() {
        let e = PoWEngine::calibrated(2, 200);
        assert_eq!(e.config.target_block_time, 1, "hedef en az 1 sn olmali");
    }
}
