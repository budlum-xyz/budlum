# Post-quantum threat model

This is the attacker model of the post-quantum program. It restates sections 1.2 to 1.4 of the
 and ties each assumption to the decision and the claim
(`CLAIMS.md`) that answers it. Nothing here is a claim by itself.

## 1. The attacker

The attacker has five capabilities. The design is judged against all of them at once.

| # | Capability | Consequence for Budlum | Answer |
|---|---|---|---|
| A1 | Runs Shor's algorithm. | Elliptic-curve, pairing and RSA schemes fall: Ed25519, sr25519, BLS12-381, secp256k1, P-256, X25519. | No signature stands on a classical scheme alone. The five permitted classical components are named, and each is paired or marked. |
| A2 | Runs Grover's algorithm. | Symmetric key search and hash preimage search speed up by a square root. | Symmetric keys are 256 bits, no AES-128. Every hash output that binds security is at least 256 bits. Grover reductions of the proof system are written next to its parameters. |
| A3 | Records today's traffic and decrypts it later. | Anything encrypted under a classical key exchange is already lost. | Transport key exchange is X25519MLKEM768 only. Data sharing is HPKE with the hybrid KEM 0x647a, and the X25519-only KEM 0x0020 is refused on mainnet. |
| A4 | Hides the ability to break a scheme. | The system cannot wait for a public break. | Defence does not depend on an announcement: classical components are always paired, and the Frost Alarm (the quantum canary of section 6.4) turns a proven break into an automatic state change in the same block. |
| A5 | Finds a classical attack on a lattice scheme. | A scheme that was the only line of defence falls. | Value-bearing keys depend on a second assumption family: the composite user signature is ML-DSA-87 and Ed25519, and every address is bound to a hash-based SLH-DSA-SHAKE-256s recovery key. The recovery path opens only when the ML-DSA family is `Disabled`. |

## 2. What "complete" means

Every cryptographic object Budlum produces or verifies meets five conditions.

1. Its security rests on a NIST post-quantum standard (FIPS 203, 204, 205) or on a hash assumption only.
2. A classical component is never accepted alone. It is always required together with a post-quantum component.
3. The security level of every layer is measured and written down (`MEASUREMENTS.md`).
4. The classical cryptography of external networks is marked in the profile, and those networks are isolated
   automatically when a break is proven on chain.
5. Every claim is bound to a test and to a CI run (`CLAIMS.md`, the `pq_claims_are_backed` gate).

## 3. The claim ladder

Only the sentence of the rung that has been reached is used. The sentences are in `CLAIMS.md`.

| Rung | Condition |
|---|---|
| I-0 | is in force. |
| I-1 | Phases 1, 2, 3 and 5 are DONE: every signature rests on NIST post-quantum standards. |
| I-2 | I-1 and phase 6: transport and data sharing use hybrid ML-KEM key exchange. |
| I-3 | I-2 and phases 4, 7, 8, 10 and 11: the signature, key exchange, randomness and proof layers rest on NIST post-quantum standards or on hashes only. |
| I-4 | I-3 and the phase 12 audits are closed. |

Words that are never used: "unbreakable", "quantum-proof", "100% quantum safe", and "quantum-resistant" without a named layer.

## 4. Layers, assumptions and security floors

| Layer | Primitive | Assumption family | Floor |
|---|---|---|---|
| User signature | ML-DSA-87 and Ed25519 (composite), SLH-DSA-SHAKE-256s recovery | module lattices and a classical group; hash-based for recovery | Category 5 |
| Validator signature | ML-DSA-65 and Ed25519 (composite), BLS12-381 finality peer | module lattices; classical pairing for the peer only | Category 3 |
| Anchor and seal | 2-of-3 ML-DSA-87 anchor, SLH-DSA-SHAKE-256s root seal, 3-of-6 SLH-DSA cold committee | module lattices and hashes; hashes only for the seals | Category 5 |
| Transport | TLS 1.3 with X25519MLKEM768 | module lattices and a classical group | Category 3 hybrid |
| Data sharing | HPKE, KEM 0x647a, HKDF-SHA256, ChaCha20-Poly1305 | module lattices and a classical group; symmetric 256 bit | Category 3 hybrid |
| Hashes | SHA-256, SHA3-256, Keccak-256 outside the VM | hash assumption | 256 bit output |
| In-VM hash | Poseidon over Goldilocks, width 12, 8 full and 22 partial rounds, capacity 4, output 4 elements | algebraic hash assumption, short lived only | 256 bit output |
| Proofs | BudZero STARK, Keccak-256 Merkle commitments, FRI | hash assumption, no pairing | at least 128 bit provable |
| Long-lived few-time signature (research) | BPQS, canonical hash SHAKE-256 | hash assumption | reserved slot, fail closed |

An algebraic hash such as Poseidon is never the hash of a long-lived signature or commitment (, section 11 of the
). It lives inside the VM, where the proof system needs a hash that is cheap to arithmetise, and its output
binds only within one proof.

## 5. Out of scope and where it stands

- $LUM, DeEd, DeArt, SocialFi, Budlum Go, and the bridge and swap modules are not developed here. They inherit the
  account layer's cryptography.
- Budlum Network (mesh), Budweb and Lubot follow one rule from the first line: to apply.
- TEE attestation is not on the security path. It carries the label "classical vendor signature" in the profile,
  and TEE shortcuts close on a Kiragi (Watch) alarm.
- FN-DSA has a reserved scheme id and is closed. It opens only when four conditions hold, and it is never described as a
  final standard before then.
- No pairing-based SNARK (Groth16, KZG-based PLONK, anything over BN254) is on a verification path. Those names stay
  only as labels for external networks.

## 6. What this model does not claim

- It does not claim a lattice scheme is unbreakable. It says value-bearing keys do not depend on lattices alone.
- It does not claim the proof system's quantum reading equals its classical one. `MEASUREMENTS.md` prints both and the
  quantum value is lower; the Fiat-Shamir loss in the quantum random oracle model is quadratic in the number of oracle
  queries (Chiesa, Manohar, Spooner, eprint 2019/834).
- It does not claim an independent audit before rung I-4.
- The BudZero proof system does not support recursion today. The size gains that depend on it are tracked in the
  recursion plan and no claim depends on them.
