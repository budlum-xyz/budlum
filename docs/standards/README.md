# Budlum open standards

| Field | Value |
|---|---|
| Status | Published, versioned, machine-testable |
| Audience | Implementers outside the Budlum team: adapter authors, verifier contracts, wallets |
| Rule | An interface may not leave the "prove" rung for the "open" rung without its document and test vectors living in this directory |

Each standard here is a **byte-level contract**, not a prose description. The test
vectors under `docs/standards/vectors/` are the arbitration: two implementations written from the
same document must agree on every vector, and must reject every negative vector.

## Standards

| # | Standard | Document | Vectors |
|---|---|---|---|
| 1 | Assurance bundle (reversibility, `quantum_posture`, attestation, slashability, fault tolerance) | [01-assurance-bundle.md](01-assurance-bundle.md) | `docs/standards/vectors/assurance-bundle-v1.json` |
| 3 | Finality certificate and inclusion proof | [03-finality-certificate-and-inclusion-proof.md](03-finality-certificate-and-inclusion-proof.md) | `docs/standards/vectors/finality-certificate-v1.json` |
| 4 | `IBudlumFinality` read surface and family counterparts | [04-ibudlum-finality.md](04-ibudlum-finality.md) | `docs/standards/vectors/ibudlum-finality-v1.json` |

The executable form of all three is [`check_vectors.py`](check_vectors.py): it recomputes
every published number from the document's rules alone, with no dependency beyond the
Python standard library, so a reader can check the vectors before trusting any
implementation of ours.

Numbers are permanent. A revision of standard 3 is `BDLM_FINALITY_CERT_V2`, published
next to `V1` with its own vectors, never in place of them: a certificate that was valid
on the day it was sealed stays verifiable forever, or the seal means nothing.

## The ladder this directory sits on

| Rung | Meaning | Gate to the next rung |
|---|---|---|
| 1 Build | the code path exists | a test calls it |
| 2 Prove | a test passes | the behaviour is measured in CI, not asserted |
| 3 Document | an outsider can rebuild it | this directory: normative text + vectors |
| 4 Open | someone else has rebuilt it | a second implementation, not written by this team, passes the vectors |

A standard that reaches rung 3 without its document and vectors in this directory is
not at rung 4. This rule is the reason the directory exists: documentation deferred to
"after launch" never arrives, and an interface nobody outside the team can implement is
a private protocol with a public repository.

## Verifying a vector file

Every vector file is one JSON object: a `domain_tag`, an `encoding` block, `positive`
cases, `negative` cases, and for standard 3 a `limits` block. A conforming verifier must:

1. rebuild each `positive[].expected` from `positive[].input` using the rules in the
   document it tests - digests, roots, counts and folded guarantee alike;
2. for standard 3, rebuild each published inclusion proof from the same rows and require
   the opening it produces to be identical to the published one, not merely to verify;
3. reject every `negative` case, for the reason it states. Proof-level negatives carry a
   complete `proof` object and must fail `verify`; row-set negatives carry `rows` with
   `"expect": "compose_rejects"` and must fail composition; standard 4 negatives name a
   `basis` case and a `mutate` overlay, and both digests must fall out of that derivation;
4. fail if any `negative` carries no `why_rejected`. A case nothing rejects is not a
   negative test, and a reason is what tells a later reviewer the case still guards
   something.

`check_vectors.py` in this directory does all four with the Python standard library and
nothing else - no node, no build, no third-party package:

```
python3 docs/standards/check_vectors.py              # verify every published number
python3 docs/standards/check_vectors.py --self-test  # prove the check can fail
```

`--self-test` mutates one published value at a time and requires the mismatch to be
caught, because a checker that cannot fail is decoration. It takes tens of seconds on a
small machine (the reference Keccak is pure Python and the registry ceiling is probed at
4096 rows); the plain verification takes about a second.

## What these documents do not claim

They pin the *encoding and the verification algebra*, which is decidable and tested.
They do not claim that the consensus rules that produced a certificate are sound, that
an adapter's own finality rule is correct, or that a domain has not been reorganised.
Those are properties of the domain the certificate describes; the certificate only
proves that Budlum's settlement layer recorded a verdict for it at a checkpoint.
