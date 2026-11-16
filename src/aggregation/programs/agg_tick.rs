//! `AggTick`: the program behind a tick proof.
//!
//! Input, in memory: the domain (4 bytes, big endian), the aggregator (32
//! bytes), a count, and that many object records (signer, message hash,
//! public key, signature). For every object the program
//!
//! * verifies the signature and that the signer is the address of the
//!   key ([`super::object`]), and
//! * computes the digest of the claim the object stands for.
//!
//! It then computes the Merkle root of the claim digests, in the order of
//! the objects, and
//!
//! `tick_pi = H("BDLM_AGG_TICK_V1" || domain || claims_root || count ||
//! aggregator)`.
//!
//! `tick_pi` is the only thing the program publishes: eight storage
//! writes, slot `k` holding bytes `4k` to `4k + 3` of the digest as a
//! little endian number. The storage writes of a run are what its proof
//! commits to in order; the event log is a sum and binds nothing of this
//! size.
//!
//! One object that does not verify stops the run, so no proof exists for a
//! list with a bad object in it.

use super::asm::{Asm, AsmError, Program, R, ZERO};
use super::bytes::{emit_constant, emit_copy, Bytes};
use super::keccak::{Domain, Keccak, Rate};
use super::mldsa::{MlDsa, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use super::object::{ObjectRules, ObjectVerifier, HASH_BYTES, OBJECT_CELLS};

/// Bytes of a domain id.
const DOMAIN_BYTES: u64 = 4;
/// Bytes of a count.
const COUNT_BYTES: u64 = 4;
/// Limbs of a digest: 32 bytes in 32 bit limbs.
const DIGEST_LIMBS: u64 = HASH_BYTES / 4;

/// The digests and encodings of the claim layer the program reproduces.
#[derive(Debug, Clone, Copy)]
pub struct TickRules<'a> {
    /// How an object is verified.
    pub object: ObjectRules<'a>,
    /// Tag of a claim digest.
    pub tag_claim: &'a [u8],
    /// Tag of the claim Merkle tree.
    pub tag_claim_root: &'a [u8],
    /// Tag of the public input of a tick proof.
    pub tag_tick: &'a [u8],
    /// The bytes of a signature claim before the signer: the kind byte and
    /// the scheme id.
    pub claim_prefix: &'a [u8],
    /// The prefix byte of a leaf of the tree.
    pub leaf_prefix: u8,
    /// The prefix byte of an inner node of the tree.
    pub node_prefix: u8,
}

/// The program and the cells its inputs go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggTick {
    /// The bytecode.
    pub program: Program,
    /// The most objects one run takes.
    pub capacity: u64,
    /// First cell of the 4 bytes of the domain.
    pub domain: u64,
    /// First cell of the 32 bytes of the aggregator.
    pub aggregator: u64,
    /// The cell of the object count.
    pub count: u64,
    /// First cell of the object records, [`OBJECT_CELLS`] cells each.
    pub objects: u64,
}

/// The memory of the claim tree: one level of digests, rewritten in place
/// until one is left.
#[derive(Debug, Clone, Copy)]
pub struct Tree {
    /// First cell of the level: 32 byte cells a node.
    pub level: u64,
    /// The hash input of an inner node: tag, prefix, left, right.
    pub node_in: u64,
    /// Its length in bytes.
    pub node_len: u64,
    /// Where the two children go in that input.
    pub children: u64,
    /// The cell of the width of the current level.
    pub width: u64,
    /// The cell of the pair counter.
    pub pair: u64,
}

impl Tree {
    /// Reduce the `count` leaves in the level to the root, which ends in
    /// its first 32 cells. Pairs are hashed; an odd last node is promoted
    /// as it is. The cell `count` holds the number of leaves, at least 1.
    ///
    /// WIRING: [`agg_tick`] is the caller; the tests also run the tree on
    /// its own, against the root of the claim layer for every width.
    pub fn emit_root(&self, asm: &mut Asm, keccak: &Keccak, bytes: &Bytes, count: u64) {
        let digest_bytes = Asm::address(HASH_BYTES);
        asm.region("merkle");
        asm.load_abs(R[1], count);
        asm.store_abs(self.width, R[1]);
        let next_level = asm.here();
        let root_ready = asm.label();
        asm.load_abs(R[10], self.width);
        asm.li(R[11], 1);
        asm.eq(R[12], R[10], R[11]);
        asm.jnz(R[12], root_ready);
        asm.store_abs(self.pair, ZERO);
        let next_pair = asm.here();
        let pairs_done = asm.label();
        asm.load_abs(R[10], self.width);
        asm.load_abs(R[11], self.pair);
        // A pair exists while 2 * pair + 1 < width.
        asm.add(R[12], R[11], R[11]);
        asm.li(R[13], 1);
        asm.add(R[14], R[12], R[13]);
        asm.gte(R[15], R[14], R[10]);
        asm.jnz(R[15], pairs_done);
        // Nodes 2 * pair and 2 * pair + 1 go into the hash input.
        asm.li(R[16], digest_bytes);
        asm.mul(R[1], R[12], R[16]);
        asm.li(R[17], Asm::address(self.level));
        asm.add(R[1], R[1], R[17]);
        asm.li(R[2], Asm::address(self.children));
        asm.add(R[3], R[16], R[16]);
        asm.add(R[3], R[3], R[1]);
        bytes.call_copy(asm);
        keccak.emit_hash(asm, self.node_in, self.node_len, Rate::R136, Domain::Keccak);
        asm.load_abs(R[11], self.pair);
        asm.li(R[16], digest_bytes);
        asm.mul(R[1], R[11], R[16]);
        keccak.emit_squeeze(asm, Some(R[1]), self.level, DIGEST_LIMBS);
        asm.li(R[13], 1);
        asm.add(R[11], R[11], R[13]);
        asm.store_abs(self.pair, R[11]);
        asm.jmp(next_pair);
        asm.bind(pairs_done);
        // odd = width - 2 * pair is 0 or 1; the last node moves down as
        // it is.
        asm.sub(R[14], R[10], R[12]);
        asm.add(R[15], R[11], R[14]);
        asm.store_abs(self.width, R[15]);
        asm.eq(R[18], R[14], ZERO);
        asm.jnz(R[18], next_level);
        asm.li(R[16], digest_bytes);
        asm.li(R[17], Asm::address(self.level));
        asm.sub(R[1], R[10], R[13]);
        asm.mul(R[1], R[1], R[16]);
        asm.add(R[1], R[1], R[17]);
        asm.mul(R[2], R[11], R[16]);
        asm.add(R[2], R[2], R[17]);
        asm.add(R[3], R[1], R[16]);
        bytes.call_copy(asm);
        asm.jmp(next_level);
        asm.bind(root_ready);
    }
}

fn len_of(bytes: &[u8]) -> Result<u64, AsmError> {
    u64::try_from(bytes.len()).map_err(|_| AsmError::AddressOutOfRange(0))
}

/// A hash input with a constant head: its first cell, the length of the
/// head and the length of the whole input.
#[derive(Debug, Clone, Copy)]
struct HashInput {
    at: u64,
    head: u64,
    len: u64,
}

impl HashInput {
    /// Reserve the input and the room its padding takes.
    const fn new(asm: &mut Asm, head: u64, tail: u64) -> Self {
        let len = head.saturating_add(tail);
        Self {
            at: asm.alloc(len.saturating_add(Rate::R136.bytes())),
            head,
            len,
        }
    }

    /// The first cell after the constant head.
    const fn tail(&self) -> u64 {
        self.at.saturating_add(self.head)
    }
}

/// The memory of the tick program.
struct TickMem {
    object: ObjectVerifier,
    domain: u64,
    aggregator: u64,
    count: u64,
    /// Loop state lives in memory: every hash uses every register.
    index: u64,
    source: u64,
    /// tag || domain || claim prefix, then signer || message hash.
    claim: HashInput,
    /// tag || leaf prefix, then the claim digest.
    leaf: HashInput,
    /// tag || domain, then `claims_root` || count || aggregator.
    tick: HashInput,
    tree: Tree,
    objects: u64,
}

impl TickMem {
    fn new(asm: &mut Asm, rules: &TickRules<'_>, capacity: u64) -> Result<Self, AsmError> {
        let object = ObjectVerifier::new(asm, &rules.object)?;
        let domain = asm.alloc(DOMAIN_BYTES);
        let aggregator = asm.alloc(HASH_BYTES);
        let count = asm.alloc(1);
        let index = asm.alloc(1);
        let source = asm.alloc(1);
        let claim_head = len_of(rules.tag_claim)?
            .saturating_add(DOMAIN_BYTES)
            .saturating_add(len_of(rules.claim_prefix)?);
        let claim = HashInput::new(asm, claim_head, 2 * HASH_BYTES);
        let tree_head = len_of(rules.tag_claim_root)?.saturating_add(1);
        let leaf = HashInput::new(asm, tree_head, HASH_BYTES);
        let node = HashInput::new(asm, tree_head, 2 * HASH_BYTES);
        let tick_head = len_of(rules.tag_tick)?.saturating_add(DOMAIN_BYTES);
        let tick = HashInput::new(asm, tick_head, HASH_BYTES + COUNT_BYTES + HASH_BYTES);
        let tree = Tree {
            level: asm.alloc(capacity.saturating_mul(HASH_BYTES)),
            node_in: node.at,
            node_len: node.len,
            children: node.tail(),
            width: asm.alloc(1),
            pair: asm.alloc(1),
        };
        let objects = asm.alloc(capacity.saturating_mul(OBJECT_CELLS));
        Ok(Self {
            object,
            domain,
            aggregator,
            count,
            index,
            source,
            claim,
            leaf,
            tick,
            tree,
            objects,
        })
    }

    /// Check the fixed inputs and write the constant head of every hash
    /// input.
    fn emit_init(&self, asm: &mut Asm, bytes: &Bytes, rules: &TickRules<'_>, capacity: u64) {
        bytes.check(asm, self.domain, DOMAIN_BYTES);
        bytes.check(asm, self.aggregator, HASH_BYTES);
        // 1 <= count <= capacity: an empty list has no root.
        asm.load_abs(R[1], self.count);
        asm.li(R[2], capacity);
        asm.gt(R[3], R[1], ZERO);
        asm.assert(R[3]);
        asm.lte(R[3], R[1], R[2]);
        asm.assert(R[3]);

        let domain_in_claim = self
            .claim
            .tail()
            .saturating_sub(DOMAIN_BYTES.saturating_add(len_of(rules.claim_prefix).unwrap_or(0)));
        emit_constant(asm, self.claim.at, rules.tag_claim);
        emit_copy(asm, domain_in_claim, self.domain, DOMAIN_BYTES);
        emit_constant(
            asm,
            domain_in_claim.saturating_add(DOMAIN_BYTES),
            rules.claim_prefix,
        );
        emit_constant(asm, self.leaf.at, rules.tag_claim_root);
        emit_constant(
            asm,
            self.leaf.tail().saturating_sub(1),
            &[rules.leaf_prefix],
        );
        emit_constant(asm, self.tree.node_in, rules.tag_claim_root);
        emit_constant(
            asm,
            self.tree.children.saturating_sub(1),
            &[rules.node_prefix],
        );
        emit_constant(asm, self.tick.at, rules.tag_tick);
        emit_copy(
            asm,
            self.tick.tail().saturating_sub(DOMAIN_BYTES),
            self.domain,
            DOMAIN_BYTES,
        );
        emit_copy(
            asm,
            self.tick.tail().saturating_add(HASH_BYTES + COUNT_BYTES),
            self.aggregator,
            HASH_BYTES,
        );
        asm.store_abs(self.index, ZERO);
        asm.li(R[1], Asm::address(self.objects));
        asm.store_abs(self.source, R[1]);
    }

    /// Every object: read it, verify it, and put the leaf of its claim
    /// into the level.
    fn emit_objects(&self, asm: &mut Asm, keccak: &Keccak, mldsa: &MlDsa, bytes: &Bytes) {
        let next_object = asm.here();
        asm.region("read_object");
        asm.load_abs(R[1], self.source);
        bytes.copy_from_pointer(asm, self.object.signer, HASH_BYTES);
        bytes.copy_from_pointer(asm, self.object.message, HASH_BYTES);
        bytes.copy_from_pointer(asm, self.object.public_key, PUBLIC_KEY_BYTES);
        bytes.copy_from_pointer(asm, self.object.signature, SIGNATURE_BYTES);
        asm.store_abs(self.source, R[1]);
        self.object.emit_verify(asm, keccak, mldsa);

        asm.region("claim_digest");
        emit_copy(asm, self.claim.tail(), self.object.signer, HASH_BYTES);
        emit_copy(
            asm,
            self.claim.tail().saturating_add(HASH_BYTES),
            self.object.message,
            HASH_BYTES,
        );
        keccak.emit_hash(
            asm,
            self.claim.at,
            self.claim.len,
            Rate::R136,
            Domain::Keccak,
        );
        keccak.emit_squeeze(asm, None, self.leaf.tail(), DIGEST_LIMBS);
        keccak.emit_hash(asm, self.leaf.at, self.leaf.len, Rate::R136, Domain::Keccak);
        // The leaf goes to slot `index` of the level.
        asm.load_abs(R[10], self.index);
        asm.li(R[11], Asm::address(HASH_BYTES));
        asm.mul(R[1], R[10], R[11]);
        keccak.emit_squeeze(asm, Some(R[1]), self.tree.level, DIGEST_LIMBS);
        asm.li(R[11], 1);
        asm.add(R[10], R[10], R[11]);
        asm.store_abs(self.index, R[10]);
        asm.load_abs(R[12], self.count);
        asm.neq(R[13], R[10], R[12]);
        asm.jnz(R[13], next_object);
    }

    /// `tick_pi` from the root in the level, published as eight storage
    /// writes.
    fn emit_tick_pi(&self, asm: &mut Asm, keccak: &Keccak) {
        asm.region("tick_pi");
        emit_copy(asm, self.tick.tail(), self.tree.level, HASH_BYTES);
        // The count as four bytes, most significant first.
        asm.load_abs(R[10], self.count);
        asm.li(R[11], 255);
        asm.li(R[12], 256);
        for at in (0..COUNT_BYTES).rev() {
            asm.and(R[13], R[10], R[11]);
            asm.store_abs(
                self.tick
                    .tail()
                    .saturating_add(HASH_BYTES)
                    .saturating_add(at),
                R[13],
            );
            asm.sub(R[10], R[10], R[13]);
            asm.div(R[10], R[10], R[12]);
        }
        keccak.emit_hash(asm, self.tick.at, self.tick.len, Rate::R136, Domain::Keccak);
        for (slot, limb) in (0u32..).zip(0..DIGEST_LIMBS) {
            asm.load_abs(R[1], keccak.state().saturating_add(limb));
            asm.swrite(slot, R[1]);
        }
    }
}

/// Build the program for at most `capacity` objects a run.
///
/// WIRING: the STARK backend of phase 3 proves runs of this program; until
/// it exists the tests and `benches/agg_tick_steps` run it on the VM.
///
/// # Errors
///
/// [`AsmError`] when the program does not assemble.
pub fn agg_tick(rules: &TickRules<'_>, capacity: u64) -> Result<AggTick, AsmError> {
    let mut asm = Asm::new();
    let keccak = Keccak::new(&mut asm);
    let mldsa = MlDsa::new(&mut asm);
    let bytes = Bytes::new(&mut asm);
    let mem = TickMem::new(&mut asm, rules, capacity)?;

    asm.region("init");
    keccak.emit_init(&mut asm);
    mem.object.emit_init(&mut asm, &rules.object);
    mem.emit_init(&mut asm, &bytes, rules, capacity);
    mem.emit_objects(&mut asm, &keccak, &mldsa, &bytes);
    mem.tree.emit_root(&mut asm, &keccak, &bytes, mem.count);
    mem.emit_tick_pi(&mut asm, &keccak);
    asm.halt();

    bytes.emit_subroutines(&mut asm);
    mldsa.emit_subroutines(&mut asm, &keccak);
    keccak.emit_subroutines(&mut asm);
    Ok(AggTick {
        program: asm.finish()?,
        capacity,
        domain: mem.domain,
        aggregator: mem.aggregator,
        count: mem.count,
        objects: mem.objects,
    })
}
