# Budlum Constitution: Social & Economic Framework (+)

**Date:** 2026-07-16
**Author:** ARENA1 (Core/R&D)
**Status:** Canonical / User-Decided

Based on the strategic decisions made by the owner (Ayaz), the following rules are now part of the Budlum "Digital Constitution". These rules will govern the development of SocialFi, BNS, and AI integration.

---

## 1. Content & Moderation
-   **Policy:** Community Voting. Reported content will be voted on by validators/governance.
-   **Right to be Forgotten:** Hard Pruning. If an NFT is burned via an `NftBurn` transaction, the linked data in B.U.D. storage is physically deleted from the network nodes holding that shard. **NFT = Ownership, Control, and Kill-Switch.**
-   **Content Portability:** Social posts and D-Web content are bound to the NFT. If an NFT is transferred to another Budlum wallet, the content is automatically "moved" to the new owner's profile and SocialFi feed. Content mobility is driven by NFT ownership.

---

## 2. Identity & Access (BNS & Accounts)
-   **Social Recovery:** No recovery. If the HSM key is lost, the account and its data are locked forever (Maximum Security).
-   **BNS Disputes:** First Come, First Served. Name rights are absolute upon registration; no trademark arbitration.
-   **Privacy:** Selective Encryption. Users choose between "Public" or "Encrypted" for each SocialFi post (NFT).

---

## 3. Data Sovereignty & Economics
-   **Spam Protection:** Fee per post. Every SocialFi interaction (NFT Mint) incurs a transaction fee.
-   **Longevity:** Permanent by default. Data remains on the network until the owner explicitly burns the NFT.
-   **Self-Hosting Option:** Users who do not wish to pay annual storage rent can opt to "Self-Host" their data via their local B.U.D. node. This data remains fully resolveable and accessible via the B.U.D. protocol as long as the user's device is online.
-   **Rewards:** Storage Provider Heavy. The majority of new $BUD issuance goes to B.U.D. operators (Storage Proofs).
-   **Advertising & Highlighting Model:**
    -   When an NFT is "Highlighted" (Boosted/Ads):
        -   4% to B.U.D. (Storage Operators/Providers).
        -   16% to the Content Creator/Context Origin (The profile or app where the ad appeared).
        -   80% to Budlum Protocol (Treasury/Burn).
-   **Social Ranking (Luminance):** Content ranking is driven by the "Light Score" (Işık Şiddeti) algorithm. Every NFT starts with 1 cd (candela) and gains/loses light based on organic interaction (time spent, "sparkling", or "darkening").
-   **Content Mobility (Digital Bud):** NFTs are "Digital Buds" (Dijital Tomurcuk). Transferring an NFT transfers the content visibility, authority, and all future earnings to the new owner's profile.
-   **Interoperability:** Universal Bridge Hub (Master Key for all Web3).
-   **Zero-Fee Inbound Bridge:** Inbound transfers to Budlum have no upfront $BUD cost. If a fee is required by the source chain or relayer, it is deducted automatically from the arriving asset, ensuring a frictionless entry for new users without $BUD holdings.
-   **Universal Consensus Layer:** Budlum is the "Universal Consensus Layer"—the next layer of the internet focused on data sovereignty and societal flourishing. It is not just a chain; it is a paradigm shift towards a decentralized, human-centric digital world.

---

## 4. Universal Ecosystem & Relayer
-   **Budlum Hub:** A unified ecosystem interface where any blockchain application (dApp) can register. The Hub is an open registration platform (Democratic Hub).
-   **Universal Relayer:** The Budlum Relayer acts as a master translator, allowing Budlum wallets/HSMs to sign and execute transactions on external chains (EVM, Solana, etc.) using $BUD as the gas currency.
-   **Relayer Incentives:** Relayers are rewarded by the protocol via $BUD minting for providing the service, and for inbound bridges, they take a small portion of the arriving asset as a fee.
-   **Master Key Security:** Critical cross-chain operations require Multi-Sig/Multi-Device approval (e.g., Mobile + HSM) for maximum security.

---

## 5. Artificial Intelligence (AI) Layer
-   **Access Policy:** Permissioned & Monetized.
-   **Data Marketplace:** Users "market" their data to Arena AI agents. AI access requires explicit user permission and payment in $BUD.

---

## 6. Infrastructure & Devices
-   **Physical Hardware:** Pre-configured physical nodes available for purchase with $BUD (Plug & Play storage economy).
-   **Mobile Integration:** Mobile devices are high-priority storage and validation nodes. Users can host their own B.U.D. data directly from their phones.

---

## 7. Social & BNS Rules
-   **Verified Status:** Premium BNS records (High-tier annual payment) can grant a "Verified" badge.
-   **Data Portability:** Internal focus. No focus on external "Export" compatibility to maintain internal sovereignty.
-   **Sub-BNS Market:** Parent-controlled. Sub-domains (x.ayaz.bud) are managed by the parent name owner.
-   **Emergency Protocol:** DAO Halt. The community can vote to temporarily halt the chain during critical failures.
-   **Token Boosters:** $BUD can be spent to "Boost" storage access speed and network priority for specific CIDs.

---

**These decisions are final and will be implemented across the codebase in upcoming steps.**

---

## 8.  Constitution Engine Binding

The first on-chain binding of this document is `core::constitution`.
It is intentionally conservative:

- AI data reads remain default-deny unless a valid Pollen/AccessGrant exists.
- Governance cannot create read/decrypt override authority.
- Permissionless core membership cannot be converted into admin or whitelist admission.
- PoA / sovereign-domain rules must not leak into permissionless domains.
- DAO/protocol state cannot custody user private keys.
- Passport, Atlas and public evidence APIs must expose commitments/evidence, not plaintext.

Mutable constitution parameters are bounded and require a non-zero rationale hash.
Hard guardrails are immutable through ordinary governance proposals.
