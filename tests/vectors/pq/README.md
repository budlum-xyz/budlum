# Post-quantum test vectors

These files are subsets of public vector sets. They are data, never edited by hand.
`src/crypto/pq_vector_tests.rs` replays them through both ML-DSA libraries and through the
facade, and `crates/wallet-core` runs the same tests on the wallet build (wasm32 included).

| File | Source | Selection |
|---|---|---|
| `acvp-mldsa-keygen.json` | NIST ACVP-Server `ML-DSA-keyGen-FIPS204/internalProjection.json` | ML-DSA-65 and ML-DSA-87, first 5 tests each |
| `acvp-mldsa-siggen.json` | `ML-DSA-sigGen-FIPS204/internalProjection.json` | external interface, pure, deterministic, ML-DSA-65 and ML-DSA-87, messages up to 4096 bytes, first 4 per set |
| `acvp-mldsa-sigver.json` | `ML-DSA-sigVer-FIPS204/internalProjection.json` | external interface, pure, ML-DSA-65 and ML-DSA-87, all tests with messages up to 8192 bytes |
| `acvp-slhdsa-keygen.json` | `SLH-DSA-keyGen-FIPS205/internalProjection.json` | SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-256s, all tests |
| `acvp-slhdsa-siggen.json` | `SLH-DSA-sigGen-FIPS205/internalProjection.json` | external interface, pure, deterministic, SHAKE-128s and SHAKE-256s, messages up to 2048 bytes, first 2 per set |
| `acvp-slhdsa-sigver.json` | `SLH-DSA-sigVer-FIPS205/internalProjection.json` | external interface, pure, SHAKE-128s and SHAKE-256s, 7 tests per set covering valid, modified message, modified R, SIGFORS and SIGHT, too large and too small signatures |
| `wycheproof-mldsa-65.json`, `wycheproof-mldsa-87.json` | C2SP Wycheproof `testvectors_v1/mldsa_65_verify_test.json`, `mldsa_87_verify_test.json` | every test with a length, context, modified-signature or hint-encoding flag, plus the first few of each remaining flag and 6 valid tests |

Upstream locations (branch `master` for ACVP-Server, `main` for Wycheproof):

* `https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/<set>/internalProjection.json`
* `https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mldsa_<65|87>_verify_test.json`

SHA-256 of the upstream files these subsets were cut from (fetched 2026-10-26):

```
e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf  ML-DSA-keyGen-FIPS204/internalProjection.json
72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22  ML-DSA-sigGen-FIPS204/internalProjection.json
47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437  ML-DSA-sigVer-FIPS204/internalProjection.json
d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920  SLH-DSA-keyGen-FIPS205/internalProjection.json
62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba  SLH-DSA-sigGen-FIPS205/internalProjection.json
a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792  SLH-DSA-sigVer-FIPS205/internalProjection.json
1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034  mldsa_65_verify_test.json
54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14  mldsa_87_verify_test.json
```

Extraction is `jq -c -f <filter> <upstream file>`. The filters keep the selected tests,
lower-case the hex, drop fields no test reads, rename `testPassed` to `valid`, and for Wycheproof
group the selected tests by public key. NIST ACVP vectors are published by NIST (a work of the
US government); Wycheproof is Apache-2.0.

The explicit bug vectors (a duplicated hint index in the shape of CVE-2026-24850, an
infinity-norm violation in the shape of RUSTSEC-2026-0077, non-canonical hint encodings, wrong
lengths, a context longer than 255 bytes) are not stored as files: the tests build them from a
genuine signature by overwriting the named section, so the construction is readable next to the
assertion.

## Required tests

The test names that replay these vectors are listed in
`xtask/gates/src/gates/pq_core_gate.rs` and must stay real `#[test]` functions that appear as
`ok` in the CI log of the PQ core job.
