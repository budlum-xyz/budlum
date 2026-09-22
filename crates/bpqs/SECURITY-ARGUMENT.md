# Budlum-BPQS Security Argument (research bar item 1)

Status: WRITTEN 2026-09-22 for crates/bpqs as of `60e69f3` (M2 canonical
backend landed). Verdict line is at the end of section 6: the document
closes everything it can prove from first principles and opens exactly one
decision item it cannot settle by fiat (decision item 7, pending user
decision). Bar item 1 therefore sits at "written, one open decision" -
it is not marked complete here, and nothing in this file should be read
as a promotion signal. The `BudlumBpqsReserved` production slot stays
fail-closed regardless.

Writing rules of this document: every claim is one of PROVEN (follows from
a cited standard reference or a first-principles computation printed in
full), ASSUMED (explicit workload assumption, tagged A1..A4), or OPEN
(deferred, with an owner). Anything else is implementation description,
cross-checked against the code, and every security-relevant behavior has a
pinned test named in section 9.

## 1. Scope

Covers: the BPQS construction exactly as implemented in `crates/bpqs`:
epoch-chained Winternitz few-time signatures over a Merkle epoch tree,
with all three hash backends (canonical Poseidon2-Goldilocks-16, FIPS-202
SHA3-256 and SHAKE-256) and both parameter rows (L5 canonical, L3
transportable; test rows share the same hash discipline).

Does not cover, and explicitly does not claim: committee ceremony
operations (seed generation, destruction, transport), the keybook format,
HSM integration, the anchor consensus flow that consumes these signatures,
side channels (the reference implementation is not constant-time hostile
but is also not constant-time audited - all secret-dependent work is
integer/finite-field arithmetic with data-independent control flow on
public-domain index data, which is noted, not proven).

## 2. Construction, as the code does it

Notation: H(dom, parts) = the canonical framing (u16le dom length, dom,
u32le part length, part) digested once per hash call; every construction
step uses one `BpqsHash` backend. N is the row's digest width in bytes
(L5: 32, L3: 24); lanes are 32-byte arrays with a meaningful N-byte prefix
and zero tail (canonicity enforced at generation; the fuzz harness mutates
tails to prove the tail is invisible by design).

1. Window/epoch: `epoch(h) = floor(h / W)`, W = EpochWindow, nonzero
   enforced (`epoch_of`; BadEpochWindow on W = 0). Epoch headroom
   `epoch < 2^T_LOG2` refused at both sign and verify.
2. Per-epoch seed: `seed_e = H(PRF_EPOCH_SEED, root_seed || u32le(e))`,
   32 bytes at both rows.
3. Epoch secret chains: `c_i = H(WOTS_CHAIN_SEED, seed_e || u32le(i))[..N]`
   for i in 0..LEN-1 (L5: LEN=67, L3: LEN=51; LEN1 = 2N message nibbles,
   LEN2 = 3 checksum nibbles, w = 16).
4. Chain step: `step(x, i) = H(WOTS_CHAIN_STEP, x[..N] || u32le(i))[..N]`.
   Walking to position d: `walk(c_i, d, i) = step applied d times`.
5. Message binding: `bound = H(MESSAGE_BIND, msg)`, full 32 bytes.
   Digits: the N-byte prefix of `bound` split into 2N nibbles (LEN1), plus
   LEN2 base-16 nibbles of `sum(w-1 - d_i)` (the Winternitz checksum).
6. Signature: chain segments at digit positions per chain (walk-forward
   from c_i), the epoch, and the Merkle auth path of e.
7. Epoch verification digest: `vk_e = H(WOTS_VK_COMPRESS, heads concat)[..N]`
   where heads = chain endpoints (all walked to d=15).
8. Merkle: `leaf_e = H(MERKLE_LEAF, vk_e)[..N]`, binary tree over
   `node = H(MERKLE_NODE, l || r)[..N]`, height T_LOG2 = 16, root is the
   member's public anchor together with W and the row name.
9. Verify: row-name equality first (no cross-row interpretation), then
   `sig.epoch == floor(h/W)`, headroom, rebuilt vk from walked segments,
   then path validation against the member root.

Wire shape: epoch (4 B) + LEN significant chain lanes (LEN x 32 B) +
T_LOG2 path nodes (T_LOG2 x 32 B); L5 wire 2660 B, L3 wire 2148 B
(pinned by `signature_wire_size_matches_the_cost_model`).

## 3. Threat model

Attacker classes in scope:

- T1: passive quantum-capable observer with the full epoch transcript
  (all signatures the committee publishes for an epoch), targeting
  existential forgery of (msg, sig) accepted at some height.
- T2: a single malicious committee member (at most 2 of 6 in the
  3-of-6 arrangement; the collusion class is outside this document -
  the protocol layer bounds it separately), who can sign only
  protocol-weight anchors but wants a second valid anchor in an epoch
  the quorum did not approve.
- T3: influence on anchor payload entropy: anchors are protocol content
  (finality roots, subtree digests); a T3-style attacker can present
  candidate payloads for honest members to sign only through the
  protocol channels; the document assesses per class how much of the
  signed-digest entropy each class effectively controls.

Out of scope: full committee collusion (3+ members), ceremony compromise
(root seed theft - that is total loss by definition of any such scheme),
consensus-layer anchor validity rules (consumed by the protocol, checked
outside this signature layer).

## 4. Lemma stack

Each lemma ends with the strongest honest statement it earns.

### Lemma 1 (PRF independence of epoch keys)

Statement: epoch secret material of distinct epochs is independent random
under the assumption H is a PRF when keyed from a uniform 32-byte root
seed (A1: H-dom-deKey behaves as PRF in the random-key-use pattern
H(DOM, key || counter) - a standard hash-function usage at all relevant
digest widths).

Argument: seed_e values differ in exactly the u32le counter part under a
fixed domain; A1 gives pairwise independence; chain expansion
(WOTS_CHAIN_SEED) inherits it as a second independent application.

Test pins: `prf_epoch_seed` domain distinctness (domains table), KAT row
digests are backend-consistent across two independent seeds.

### Lemma 2 (Winternitz core)

Statement: forging a signature segment for a chain position not
"approachable forward" from any revealed position requires a preimage of
H under WOTS_CHAIN_STEP at the row's digest width, i.e. work 2^(8N)
classical / 2^(4N) under a generic quantum model for 1% success via
Grover (A2 baselines in section 5).

Proviso (carried to section 6): the WOTS checksum binds the digit vectors
so that a non-domination forgery path never arises: any forged message
whose digits are all individually approachable is dominated; any message
that is not dominated has at least one chain requiring inversion. The
checksum arithmetic in `digits_of` is the standard Winternitz encoding
(sum of w-1-d_i over message digits, LEN2 base-16 nibbles) and is pinned
by the checksum roundtrip tests; the reduction argument (non-dominating
forgery => inversion) is the Buchmann-line argument, cited: Dods, Smart,
Stam 2005; Huelsing 2013 (W-OTS+).

### Lemma 3 (Merkle binding)

Statement: presenting a path for a vk_e the tree did not commit to
requires a second preimage at MERKLE_LEAF or MERKLE_NODE at the row's
digest width (2^(8N) classical / 2^(4N) Grover), or a collision at
WOTS_VK_COMPRESS/MERKLE_NODE (2^(4N) classical / ~2^(2.67N) quantum via
BHT). The leaf-set size 2^16 does not help the attacker: membership is
proved against the fixed root.

Standard construction; no tailor-made parts. Test pins: auth-path tamper
refusals across three backends and two rows (`tamper_refuses_*`).

### Lemma 4 (epoch binding / replay classes)

Statement: re-placing a signature into a different epoch requires either
(a) changing h so `floor(h/W)` changes - a consensus action, not a
signature-layer one, or (b) forging the mismatch, which is refused
before hash evaluation (`EpochMismatch`: the verifier recomputes the
epoch from h and the member's W; signatures carry the epoch explicitly).

Off-by-one safety is a CODE property here, pinned: window-zero refusal,
flips exactly at multiples of W (`epoch_flips_exactly_at_the_window_boundary`),
moved-to-another-epoch refusal per backend (`epoch_replay_refuses_*`).

## 5. Hash workload budgets (A2, A3, A4)

Classical-quantum summary used below; "work" = calls to the primitive.

- A2 (FIPS-202 rows): SHA3-256 and SHAKE-256(32B read) are taken at their
  standardized budgets: preimage 2^256 classical / 2^128 Grover,
  second-preimage same, collision 2^128 classical / ~2^85 BHT. These are
  the mature end of the tree and not argued in this document.
- A3 (Poseidon2-Goldilocks-16, canonical): the sponge runs with 8 x
  64-bit capacity elements = 512 bits of capacity, which is what a 256
  1st-preimage/128 collision budget asks of an ideal sponge. The
  assumption on record: the Poseidon2 permutation used induces no
  structure that makes the BPQS-POSEIDON2-SPONGE-v0 binding easier than
  its capacity budgets. This is the heaviest explicit assumption of the
  design (risk R3 of the pre-registration): the PQ-hash literature for
  algebraic hashes is thin compared to FIPS-202, and this document does
  not raise it past ASSUMED. Section 6's residual-risk line is the
  reason the SHAKE-256 backend exists and is exercised on every CI run:
  if A3 is ever doubted, the canonical label moves by decision, not by
  re-engineering.
- A4 (framing injectivity): the packaging (u16/u32 length prefixes) is
  injective on (domain, parts); the Poseidon backend's u32-per-element
  chunking is injective modulo exactly one ambiguity class - a final
  partial chunk's zero padding - which is killed because the chunk's
  byte length is itself recoverable from the frame's own length prefixes.
  Pinned: `tail_padding_ambiguity_is_killed_by_frame_lengths`,
  `frame_matches_the_documented_sketch`, per-backend packaging tests.

L3 truncation: rows with N=24 use the 24-byte prefix of a 32-byte digest
under the same per-step domains. Preimage/second-preimage at the truncated
width: 2^192 classical / 2^96 Grover (Grover over a 192-bit target);
collision degraded to 2^96 classical (~2^64 BHT). The L3 row's security
labels are therefore stated at "classical 192-bit one-way class, 96-bit
collision class" rather than borrowing L5 numbers. The chain-step domain
interaction (truncated prefix of one step feeds the next step) is
collision-irrelevant for the scheme's reduction (which needs
second-preimage, not collision, at CHAIN_STEP); WOTS_VK_COMPRESS and
MERKLE_NODE are where collision enters. This is the deferred-from-M1
truncation argument, now written.

## 6. The few-time relaxation, priced honestly

This is the section the pre-registration did not price, and the reason
this document does not close itself as "complete".

Attack (domination hunt): a T1 observer holds the q <= q_max signatures
of one epoch. For chain i the observer can produce the segment at any
position >= min_j d_i^(j) (walk forward from the least revealed
position); positions below min are inversion-locked. Forgery of a NEW
message succeeds exactly when every one of the LEN digit positions of
H(MESSAGE_BIND, msg) lies at or above the per-chain minima (the 3
checksum digits included; their dependence on the message digits is a
refinement stated below, not swept).

The candidate message space the observer hunts over is free: he varies
msg bytes (protocol-weight anchor candidates, rejections cost nothing -
a rejected candidate is simply not submitted). First-order arithmetic,
computed exactly, no constants hidden:

- per-digit success: for digits uniform in {0..15}, with m = min of q
  uniform observations, P(d* >= m) averaged over m is 1 - E[m]/16 with
  E[m] = sum_{k>=1} ((16-k)/16)^q. q=1: E[m] = 7.500, per-digit 0.5312;
  q=2: per-digit 0.6973; q=4: E[m] = 2.721, per-digit 0.8299.
- joint over the LEN = 67 dims of the L5 row (51 dims at L3, strictly
  easier for the attacker and stated as such): independence across dims
  of one random message digest, treating checksum dims as uniform
  (stated bound, first-order column; the checksum half of the bound is
  computed EXACTLY in the refinement below):
  q=1: 2^-61.1 per candidate -> hunt ~ 2^61 classical / ~2^31 Grover
  q=2: 2^-34.9
  q=4: 2^-18.0 (approx. one in 2.6 x 10^5 candidates)

### Exact checksum refinement (pinned 2026-09-22)

The checksum digits are not uniform, and the uniform treatment is the
checksum half of the "first-order" label above. The exact checksum side
is computable by full enumeration: T = sum of 64 iid uniform nibbles has
an exact 961-bin distribution (convolution, exact integers), and the
digit ranks are (T mod 16, (T div 16) mod 16, T div 256). The script
`tools/bpqs_checksum_domination_exact.py` does this with exact rational
arithmetic; the numbers below are its stdout, reproducible with no
randomness and no dependencies.

Exact marginals (one checksum vector from one honest message):

- rank 0 (T mod 16): EXACTLY uniform on {0..15} (sum of iid uniforms
  mod 16 is uniform - the one uniform digit in the row).
- rank 1: strongly right-skewed: P(12..15) = 0.614, P(14,15) = 0.309,
  P(0) = 0.098. Honest rank-1 digits sit HIGH: E = 10.38 vs 7.5 uniform.
- rank 2 (T div 256): mass concentrated on {1, 2}: P(1) = 0.803,
  P(2) = 0.197; P(0) = 2^-32.4, P(3) = 2^-53.3. Honest rank-2 digits
  sit LOW - the one position that is cheaper for the hunter than the
  uniform column said.

E[min over a pool of q honest draws] per rank (uniform column repeated):

    q=1:  rank0 7.500 | rank1 10.38 | rank2 1.197 | uniform 7.500
    q=2:  rank0 4.844 | rank1  7.85 | rank2 1.039 | uniform 4.844
    q=4:  rank0 2.721 | rank1  4.88 | rank2 1.002 | uniform 2.721
    q=8:  rank0 1.319 | rank1  2.12 | rank2 1.000 | uniform 1.319

Exact checksum-side domination term, joint over all three ranks of the
honest digit VECTOR (componentwise min over the q honest draws, then
candidate dominates it); uniform first-order column in parentheses:

    q=1: P = 0.203832  log2 = -2.295   (uniform: 0.1499, -2.737)
    q=2: P = 0.072460  log2 = -3.787   (uniform: 0.3389, -1.560)
    q=4: P = 0.017499  log2 = -5.837   (uniform: 0.5705, -0.808)
    q=8: P = 0.002487  log2 = -8.651   (uniform: -,      -0.491)

Refined per-candidate success (64 message positions kept exact-and-
independent as above; the 3 checksum positions replaced by the exact
joint term):

    q=1: 58.40 + 2.295 = 2^60.7   (first-order said 2^61.1)
    q=2: 33.27 + 3.787 = 2^37.1   (first-order said 2^34.9)
    q=4: 17.23 + 5.837 = 2^23.1   (first-order said 2^18.0;
                                   approx. one in 1.1 x 10^7 candidates)
    q=8: 14.45 + 8.651 = 2^23.1   (pool attack SATURATES: message-digit
                                   minima floor at 0 while rank-1 minima
                                   stay high; more signatures stop
                                   helping the hunter past q ~ 4)

Direction of the correction (read both halves): the refinement moves
q=1 DOWN by 0.44 bit (rank-2 concentration makes chain 67 nearly free
for the hunter) and moves q >= 2 UP by +2.2..+5.1 bits (the rank-1
right-skew dominates the joint once pooling starts: honest checksum
minima stay high across chains 65..66 while message minima collapse).
The remaining un-priced term, exactly one: the checksum digits of the
CANDIDATE are a deterministic function of its 64 message digits, so the
event "candidate tuple inside the hyper-box imposed by the pool minima"
correlates with "its induced checksum dominates the checksum minima"
(and the honest side has the same self-correlation). The enumeration
above prices each side's checksum law exactly but treats the
message-into-checksum coupling first-order; bounding that coupling
tightly is the checksum-correlation refinement the review is still
asked for (question 1 of the review call), now with exact marginals and
the exact self-joint handed over as reference computation instead of an
open question.

Read: the few-time relaxation to q_max = 4 lowers the existential-forgery
resistance of one epoch key from the hash budgets of section 5 to about
2^23 classical for an offline hunter (checksum-exact; first-order had
2^18). The q=1 one-time floor of the same raw dimensions is ~2^61
classical / ~2^31 quantum (~2^60.7 checksum-exact - unchanged to within
half a bit) - above the L3
collision class but far below the NIST level-5 target line this research
line is named after. No choice of w, N, or backend repairs this term:
it is a property of "sign verifier-walkable chain digests
deterministically", visible the moment it is priced, and is precisely
the line item the decision record must now face.

Design responses the literature and this codebase can actually support:

- R-1 (protocol-context pinning): the hunt produces existential forgeries
  of arbitrary byte strings. An anchor that does damage must also pass
  the chain's own structural rules at height h (the attacker must
  influence real protocol content toward a dominated digest; the
  structurally meaningful anchor space per (h, window) is tiny).
  Honest reading: this constraint is real but quantitatively not yet
  priced; leaning on it alone recasts BPQS' security as a property of
  the anchor flow rather than the primitive - inside this document the
  flow is out of scope, so R-1 is recorded as context, not as a fix.
- R-2 (signer-side message randomization): sign H(MESSAGE_BIND,
  r || msg) with fresh 16-byte r carried in the signature. This closes
  the *adaptive* amplification (an attacker steering an honest member's
  future minima by feeding it crafted payloads), but it does NOT close
  the offline hunt on already-revealed minima (the hunter varies both
  msg and r'). Residual: 2^61 at q=1 unchanged at the same dimensions.
- R-3 (one-time posture): set q_max = 1, which is what the code's
  quota machinery enforces with a constant change and no redesign;
  combined with R-2 this is the strongest in-family posture available:
  every epoch key is one-time, randomized per mint, existential-hunt
  floor ~2^61 classical.
- R-4 (family change toward FORS/hyperstructure): the textbook answer
  to "WOTS under few-time/many-hunt pressure" is the SPHINCS class
  answer (sign verifiably-uncontrolled short strings with WOTS, put the
  hash-few-time core into FORS). This is a design family revision, i.e.
  a research decision, not a patch.

Decision item 7 (PENDING, user decision follows the standing pattern of
the 2026-09-19 session): choose the residual-risk posture for bar-1
closure. Recommended interim posture (this document's own weighing):
R-2 + R-3 now (small code delta, strongest in-family posture), with the
family review (R-4) handed to bar 3 (independent review) as a named
question. Until the item is decided, bar item 1 is "written, open
decision", the production slot stays fail-closed, and no claim in this
document should be quoted without section 6 attached.

## 7. Quantum accounting summary

Per mechanism, classical / generic-quantum work, L5 row (L3 row's labels
are inside-out as section 5 states):

- chain-step preimage: 2^256 / 2^128
- PRF/seed and chain expansion: follows the same budgets
- Merkle leaf/node second-preimage: 2^256 / 2^128
- vk/leaf/node collision (where collision matters): 2^128 / ~2^85
- few-time domination hunt (q=4): ~2^23 / ~2^12 (checksum-exact
  refinement, section 6; first-order uniform said ~2^18 / ~2^9) - THE
  binding term today
- one-time posture floor (q=1): ~2^61 / ~2^31 (exact checksum: 2^60.7)

NIST level-5 target (classical ~2^256-class, quantum >= 2^128): met by
every mechanism except the few-time term; that term is decision item 7.

## 8. Remaining work owned by other bar items

- bar 3 (independent review): check section 6's arithmetic; the
  checksum side now arrives PARTIALLY pre-answered (exact marginals,
  exact joint domination over the three checksum ranks, pool saturation
  at q ~ 4-8; script-pinned). What is still open is the
  message-into-checksum cross-correlation stated at the end of the
  refinement, plus the family question: settle whether the in-family
  posture (R-2/R-3) suffices for the cold-committee use case or whether
  R-4 becomes the recommendation.
- bar 4 (VerifyMerkle expressibility): unchanged by this document; the
  verify chain's primitive projection (Poseidon single-primitive lane)
  stands as section 5/A3 records.
- constant-time audit: named in section 1 as out of scope; a sideways
  open item listed here so it is owned by exactly one list.

## 9. Test map (claim -> pin)

- PRF/chain independence and domains: `domains` table in lib.rs, KAT
  per-backend rows in `kat/bpqs-kat-v1.txt` verified by
  `kat_file_matches_computation` and frozen by `kat_rows_are_frozen`.
- Framing injectivity (A4): `frame_matches_the_documented_sketch`,
  `tail_padding_ambiguity_is_killed_by_frame_lengths`,
  `packaging_is_length_honest` (x3 backends via hash-face tests).
- WOTS checksum behavior: `digits_of` unit tests + per-backend tamper
  matrices (`tamper_refuses_*`, 6 cases) + mutated-walk panic safety
  (`bpqs_wots_reject` fuzz harness, wired into quick and nightly fuzz).
- Epoch semantics: `epoch_flips_exactly_at_the_window_boundary`,
  window-zero refusal, `signature_moved_to_another_epoch_refuses`,
  per-backend `epoch_replay_refuses_*`.
- Quota machinery: `quota_violation_is_epoch_scoped_not_window_scoped`,
  per-backend `quota_refuses_*` (the q_max = [4] constant is the single
  knob the R-3 posture tightens).
- Merkle: path tamper + L3-row path checks in the backend battery;
  node/leaf domains as section 2.
- Backend equivalence: `backends_are_three_distinct_functions`; full
  24-case cross-backend battery; permutation-level p3 KAT pinned at
  module level and from an external caller; SHAKE-256 FIPS-202 vectors
  at four rate boundaries.

## 10. Appendix: domain tags and parameters

Domain tags (exact bytes, from `lib.rs` `domains`):
BPQS-PRF-EPOCH-SEED-v0, BPQS-WOTS-CHAIN-SEED-v0, BPQS-WOTS-CHAIN-STEP-v0,
BPQS-WOTS-VK-COMPRESS-v0, BPQS-MERKLE-LEAF-v0, BPQS-MERKLE-NODE-v0,
BPQS-MESSAGE-BIND-v0.

Rows: L5 - N=32, w=16, LEN1=64, LEN2=3, LEN=67, T_LOG2=16, Q_MAX=4,
wire 2660 B; L3 - N=24, LEN1=48, LEN2=3, LEN=51, T_LOG2=16, Q_MAX=4,
wire 2148 B. Test lanes share hash discipline at T_LOG2 = 4.
