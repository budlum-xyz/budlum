# Security Policy

Budlum Core is experimental Layer-1 blockchain infrastructure. Security reports are taken seriously, especially issues affecting consensus safety, deterministic execution, networking, storage integrity, cryptography, privacy, or validator operation.

Please do not disclose serious vulnerabilities publicly until they have been reviewed and patched.

---

## Supported Versions

Budlum Core is currently pre-release research software.

| Version | Supported |
| :--- | :--- |
| `main` branch | Best-effort security review |
| Tagged releases | Best-effort, when available |
| Old commits/forks | Not actively supported |

Until stable releases exist, security fixes are expected to land on `main`.

---

## Reporting a Vulnerability

If you believe you found a vulnerability, please report it privately.

Preferred process:

1. Open a private security advisory on GitHub if available.
2. If private advisories are not available, contact the project maintainer directly.
3. Include enough detail to reproduce the issue.
4. Do not publish exploit code or public issue details before coordination.

Useful report details:

- Affected commit, branch, or release
- Impacted component, such as consensus, execution, networking, storage, RPC, mempool, or crypto
- Reproduction steps
- Minimal proof of concept, if safe to share privately
- Expected behavior vs actual behavior
- Suggested fix, if you have one

---

## Scope

High-priority areas include:

- Consensus safety failures
- Block validation bypasses
- Transaction signature or chain ID replay issues
- Deterministic execution failures
- Reorg or restart replay divergence
- State-root corruption
- Storage integrity failures
- Snapshot sync validation failures
- Mempool spam or resource exhaustion attacks
- P2P protocol denial-of-service vectors
- Peer reputation bypasses
- JSON-RPC input validation issues
- Cryptographic misuse or weak domain separation
- ZKVM proof verification bypasses
- Private VM or privacy-layer leakage, when those features land
- Validator key handling risks

Out of scope:

- Social engineering
- Physical attacks
- Vulnerabilities only affecting a heavily modified fork
- Reports without a plausible security impact
- Dependency CVEs that are not reachable from Budlum behavior
- Denial-of-service claims that require unrealistic local machine access

---

## Security Expectations for Contributors

When changing protocol-sensitive code:

- Avoid panics on untrusted input
- Validate payload sizes and encoded fields
- Keep consensus and execution deterministic
- Treat network messages as hostile
- Keep replay and reorg behavior reproducible
- Avoid leaking secrets in logs
- Do not commit private keys, validator credentials, seeds, or production configs
- Add tests for invalid and adversarial cases

Sensitive paths include:

- `src/consensus/`
- `src/execution/`
- `src/chain/`
- `src/core/`
- `src/network/`
- `src/mempool/`
- `src/storage/`
- `src/rpc/`
- `proto/protocol.proto`

---

## Coordinated Disclosure

The expected disclosure flow:

1. Reporter privately submits the issue.
2. Maintainers acknowledge and triage.
3. A fix is prepared and tested.
4. A patch is released or merged.
5. Public disclosure happens after users have had reasonable time to update.

For critical vulnerabilities, public details may be delayed until a safe patch path exists.

---

## Bug Bounty

Budlum Core, mainnet v1 lansmanından itibaren bir bug bounty programı yürütecektir.

**Detaylar:** [docs/BUG_BOUNTY.md](docs/BUG_BOUNTY.md)

| Seviye | Ödül (USD) |
|--------|------------|
| Kritik (consensus bypass, key extraction, bridge drain) | $50,000–$100,000 |
| Yüksek (DoS, RPC bypass, P2P eclipse) | $10,000–$25,000 |
| Orta (rate limit bypass, info leak) | $2,500–$5,000 |
| Düşük (best practice, docs) | $500–$1,000 |

**Raporlama:** `security@budlum.network` veya GitHub private security advisory.
**Triage:** 72 saat içinde ilk yanıt. Coordinated disclosure: 90 gün.

> Program henüz aktif değil — mainnet lansmanıyla birlikte Immunefi üzerinden açılacaktır.

### Triage Kanalları

- **Discord:** `#security-reports` (yalnızca reporter + security lead görür)
- **Telegram:** `@budlum_security` (alternatif — PGP key talep edilir)
- **GitHub:** Private security advisory (önerilen — audit trail)

### Safe Harbor (İyi Niyetli Araştırmacı Koruması)

Aşağıdaki koşulları sağlayan araştırmacılar iyi niyetli kabul edilir:

1. Yalnızca **test hesapları** kullanılır; üçüncü parti fon/veriye dokunulmaz.
2. Mainnet'te **fon/veri riske atmayan** salt-kanıt test (read-only).
3. Bulgu paylaşılmadan önce `security@budlum.network`'e raporlanır.
4. 90 gün coordinated disclosure penceresine uyulur.

**Kapsam dışı:** sosyal mühendislik, üçüncü parti altyapı (RPC/HSM vendor),
mainnet'te gerçek fon drain, kullanıcı verisi sızıntısı.

---

## Disclaimer

Budlum Core is experimental software. Do not use it to secure real funds, production validator keys, or sensitive private data without an independent security review.
