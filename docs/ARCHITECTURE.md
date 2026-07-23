# Budlum Mimari Atlası

> **Durum:** Kod haritası ve hedef mimariyi birlikte gösterir. Diyagramlardaki
> `feature-gated`, `planlı` ve `mainnet blocker` etiketleri tamamlanmış üretim
> özelliği iddiası değildir.

## 1. Genel sistem mimarisi

```mermaid
flowchart TB
  Client[Wallet / dApp / Operator] --> RPC[JSON-RPC + admission]
  RPC --> MP[Mempool]
  MP --> Chain[ChainActor / Blockchain]
  Chain --> Exec[Transaction Executor]
  Chain --> Consensus[PoW / PoS / PoA / BFT finality]
  Exec --> State[(AccountState)]
  Consensus --> State
  State --> Store[(Durable storage + snapshots)]
  Chain --> Net[P2P / Gossip]
  Exec --> ZK[BudZero / BudZKVM]
  State --> XD[Cross-domain / bridge state]
  State --> Apps[BNS · B.U.D. · Pollen · Hub · SocialFi · AI]
```

## 2. Consensus-domain izolasyonu

```mermaid
flowchart LR
  POW[Permissionless PoW] --> FA[DomainFinalityAdapter]
  POS[Permissionless PoS] --> FA
  BFT[Permissionless BFT] --> FA
  ZK[ZK proof domain] --> FA
  POA[Isolated PoA / KYC membership] --> PFA[PoA finality adapter]
  FA --> Settlement[Global settlement commitment]
  PFA --> Settlement
  Reg[Permissionless stake registry] -. never shared .-> POA
  PoAReg[Separate PoA membership registry] -. isolated .-> Reg
```

## 3. Transaction admission and V4 signing

```mermaid
sequenceDiagram
  participant C as Client
  participant R as RPC / P2P decoder
  participant M as Mempool
  participant E as Executor
  C->>C: Canonical V4 payload + signature
  C->>R: Transaction
  R->>R: signature_version == V4?
  R->>R: canonical hash + signature verify
  R->>M: admitted transaction
  M->>E: selected block transaction
  E->>E: nonce / balance / type rules
  E-->>C: state transition or typed rejection
```

## 4. Cross-domain bridge lifecycle

```mermaid
flowchart LR
  Lock[Lock on source domain] --> Event[Committed lock event]
  Event --> Proof[Relayer proof]
  Proof --> Verify[Header / receipt / MPT verification]
  Verify --> Mint[Mint on target]
  Mint --> Burn[Burn on target]
  Burn --> BurnProof[Verified burn event]
  BurnProof --> Unlock[Unlock on original source]
  Verify --> Replay[Replay / correlation / state-machine gates]
  Replay --> Mint
  Replay --> Unlock
```

## 5. EVM receipt verification path

```mermaid
flowchart TB
  Headers[Target header + confirmation chain] --> HC[Parent hash / height checks]
  Receipt[Receipt envelope bytes] --> RLP[Strict RLP decoder]
  Proof[MPT proof nodes + receipt key] --> MPT[Merkle-Patricia verifier]
  HC --> Root[receiptsRoot]
  Root --> MPT
  RLP --> Log[Status + emitter + topic0 + payload checks]
  MPT --> ReceiptValue[Committed receipt bytes]
  ReceiptValue --> RLP
  Log --> Deposit[Verified deposit facts]
```

## 6. Snapshot trust and schema migration

```mermaid
flowchart LR
  Live[AccountState] --> S4[Schema-4 canonical digest]
  S4 --> Sign[Manifest signer / signature]
  Sign --> Disk[(Snapshot storage)]
  Disk --> Load[Loader]
  Load --> Integrity[Digest + field manifest verify]
  Integrity --> Auth[External trust policy verify]
  Auth --> Restore[Restore state]
  Integrity --> Quarantine[Quarantine / fail-loud]
  Auth --> Quarantine
  Legacy[Schema-2/3 legacy import] --> Versioned[Version-specific digest]
  Versioned --> Integrity
```

## 7. Critical durability boundary

```mermaid
flowchart LR
  Input[Verified bridge / QC / finality input] --> Stage[Stage next state]
  Stage --> Batch[Atomic durable batch]
  Batch --> Flush[Apply + flush]
  Flush --> Publish[Publish in-memory state]
  Flush -->|failure| Stop[Fail-stop / operator recovery]
  Publish --> Next[Relay / finality continuation]
```

## 8. BudZero execution and proof boundary

```mermaid
flowchart LR
  Contract[Contract bytecode] --> VM[bud-vm execution]
  VM --> Trace[Execution trace]
  Trace --> Proof[bud-proof / STARK proof]
  Proof --> Verify[Budlum verifier]
  Verify --> Exec[Executor state transition]
  VM --> Host[Host calls: AI request / chain integration]
```

## 9. AI inference lifecycle

```mermaid
flowchart LR
  Model[Model registration] --> Request[Inference request + fee escrow]
  Request --> Verifiers[Permissionless AI verifiers]
  Verifiers --> Results[Signed result commitments]
  Results --> Threshold[Agreement / equivocation checks]
  Threshold --> Outcome[Finalized outcome + callback]
  Threshold --> Reclaim[Expired no-consensus fee reclaim]
```

## 10. B.U.D. storage lifecycle

```mermaid
flowchart LR
  Content[Content manifest + shards] --> Deal[Permissionless storage deal]
  Deal --> Operator[Storage operator]
  Operator --> Challenge[Interim retrieval challenge]
  Challenge --> Outcome[Challenge outcome]
  Gate[VerifyMerkle 64-depth gate] -. required for real Proof-of-Storage .-> Production[Production proof-of-storage]
```

## 11. Mainnet launch gates

```mermaid
flowchart TD
  V29[V29 signing V4] --> P2[P2 snapshot integrity]
  P2 --> V19[Critical durability]
  V19 --> Audit[External audit / bounty]
  Audit --> Fuzz[Long-running fuzz campaign]
  Fuzz --> HSM[Vendor-native HSM decision/test]
  HSM --> Ceremony[Genesis ceremony + bootnodes]
  Ceremony --> Freeze[Genesis hash freeze]
  Freeze --> Launch[Mainnet launch approval]
  ZKGate[VerifyMerkle soundness or explicit feature gate] --> Launch
```

## 12. CI and security gates

```mermaid
flowchart LR
  Push[Commit / PR] --> Fmt[Format + lint]
  Fmt --> Core[Core / BudZero tests]
  Core --> Invariants[BNS · B.U.D. · PoA invariant gates]
  Invariants --> Coverage[Coverage ratchet]
  Coverage --> Supply[deny · SBOM · secret scan · geiger · udeps]
  Supply --> Smoke[Docker / multinode smoke]
  Smoke --> CI[CI verdict]
  Fuzz[Fuzz quick + nightly campaigns] -. ongoing evidence .-> CI
```


---

# Kapsamlı Sistem Diyagramları (Detaylı Veri Akışı)

## 13. Executor — tam state transition pipeline

```mermaid
flowchart TD
  subgraph Admission["RPC / P2P Admission"]
    Raw[Raw tx bytes] --> Decode[Transaction::decode V4]
    Decode --> SigCheck[canonical_signing_hash + ed25519 verify]
    SigCheck -->|fail| RejectSig[REJECT: invalid_signature]
    SigCheck -->|pass| Nonce[nonce == expected_nonce?]
    Nonce -->|fail| RejectNonce[REJECT: nonce_mismatch]
    Nonce -->|pass| Pool[Mempool admission]
  end

  subgraph Execution["apply_transaction_checked"]
    Pool --> Type{TransactionType?}
    Type -->|Transfer| T1[sender.balance.checked_sub total_cost]
    T1 --> T2[receiver.balance.checked_add amount]
    T2 --> T3[sender.nonce += 1]
    Type -->|Stake| S1[add_validator or increase stake]
    S1 --> S2[C3: has_consensus_keys? → reject if new + no keys]
    S2 --> S3[sync_validator_registration]
    Type -->|Unstake| U1[current_stake >= amount?]
    U1 --> U2[reduce_vote_weight for active proposals]
    U2 --> U3[validator.stake -= amount]
    U3 --> U4[unbonding_queue.push release_epoch]
    Type -->|AiInferenceRequest| AI1[sender.balance >= max_fee + fee?]
    AI1 --> AI2[ai_registry.submit_request]
    AI2 --> AI3[escrow max_fee from sender]
    Type -->|AiAttachExecutionProof| AE1[structural verify + program_hash bind]
    AE1 --> AE2[STARK verify via DefaultAdapter]
    AE2 --> AE3[attach_execution_proof]
    AE3 --> AE4[try_finalize_with_proofs]
    Type -->|PrivateTransferSubmit| P1[note_registry.apply_transfer]
    P1 --> P2[live_commitments.remove spent]
    P2 --> P3[spent_nullifiers.insert]
    P3 --> P4[output_commitments.insert]
    Type -->|BridgeLock| BL1[bridge_state.lock]
    BL1 --> BL2[expiry_queue.push]
    Type -->|NftBoost| NB1[booster.balance >= amount + fee]
    NB1 --> NB2[creator.checked_add creator_share 16%]
    NB2 --> NB3[pending_bud_boost_share += bud_share 4%]
    NB3 --> NB4[treasury.checked_add protocol_share 80%]
  end

  subgraph FeeDeduction["Fee deduction (all tx types)"]
    T3 --> Fee[sender.balance.saturating_sub tx.fee]
    Fee --> NonceInc[sender.nonce.saturating_add 1]
  end
```

## 14. Privacy layer — Poseidon circuit + note registry state machine

```mermaid
flowchart TD
  subgraph Wallet["Wallet-side key derivation"]
    Seed[wallet_seed 32 bytes] --> DS[derive_spend_secret SHA3-256 seed||commitment → u64]
    Seed --> DB[derive_blinding SHA3-256 seed||counter → u64]
    Seed --> DV[derive_view_key SHA3-256 seed||0xVIEW → 32 bytes]
    Addr[address] --> Tag[address_to_recipient_tag SHA3-256 → u64]
  end

  subgraph Commitment["PrivacyCommit opcode (0x20)"]
    Amount[rs1 = amount u64] --> PC[Poseidon4_hash3 amount blinding recipient_tag]
    Blinding[rs2 = blinding u64 full] --> PC
    RecipTag[imm = recipient_tag i32] --> PC
    PC --> CommitOut[rd = commitment u64]
    CommitOut --> Insert[note_registry.insert_note commitment]
    Insert --> LiveSet[live_commitments BTreeSet]
  end

  subgraph Nullifier["NullifierCheck opcode (0x21)"]
    Secret[rs2 = spend_secret] --> NC[Poseidon4_hash secret DOMAIN_NULLIFIER]
    NC --> NullOut[derived_nullifier u64]
    Claimed[rs1 = claimed_nullifier] --> EqCheck{derived == claimed?}
    NullOut --> EqCheck
    EqCheck -->|yes| Rd1[rd = 1 valid]
    EqCheck -->|no| Rd0[rd = 0 invalid]
    Rd1 --> SpentSet[spent_nullifiers BTreeSet insert]
    SpentSet --> DoubleSpend{already in set?}
    DoubleSpend -->|yes| Reject[REJECT: double-spend]
  end

  subgraph Conservation["SumConservation opcode (0x22)"]
    SumIn[rs1 = Σ input amounts] --> SC{sum_in == sum_out AND both < P}
    SumOut[rs2 = Σ output amounts] --> SC
    SC -->|yes| Rd1c[rd = 1 balanced]
    SC -->|no| Rd0c[rd = 0 unbalanced]
  end

  subgraph AIR["AIR constraints (plonky3_air.rs)"]
    Selector[is_privacy_commit selector → opcode 0x20]
    PoseidonState[s0=rs1 s1=rs2 blinding s2=imm recipient s3..7=0]
    NullSelector[is_nullifier_check → opcode 0x21]
    NullState[s0=rs2 secret s1=DOMAIN_NULLIFIER s2..7=0]
    SumSelector[is_sum_conservation → opcode 0x22]
    SumState[s0=rs1 sum_in s1=rs2 sum_out]
    S2Guard[Goldilocks P bound: both < 0xFFFFFFFF00000001]
  end
```

## 15. Bridge — full cross-domain message verification pipeline

```mermaid
flowchart TD
  subgraph Source["Source domain (e.g. Ethereum)"]
    Tx[Lock transaction] --> Event[Emitted lock event]
    Event --> Block[Block with receipts_root]
    Block --> Confirm[N confirmation blocks]
  end

  subgraph Relayer["Relayer proof construction"]
    Confirm --> Header[Target header + confirmation chain]
    Header --> Receipt[Receipt envelope bytes]
    Receipt --> MPTProof[MPT proof nodes + receipt key]
    MPTProof --> CrossMsg[CrossDomainMessage constructed]
    CrossMsg --> MsgId[message_id = hash fields]
    CrossMsg --> PayloadHash[payload_hash = bridge_payload_hash asset_id amount]
    CrossMsg --> Correlation[correlation_id for burn→unlock]
  end

  subgraph Verification["Budlum verification pipeline"]
    MsgId --> VerifyId[message.verify_id hash check]
    VerifyId -->|fail| Reject1[REJECT: invalid_message_id]
    VerifyId -->|pass| ParentCheck[parent_hash + height checks]
    ParentCheck --> RLPLDecode[Strict RLP decoder]
    RLPLDecode --> MPTVerify[Merkle-Patricia verifier]
    MPTVerify --> ReceiptValue[Committed receipt bytes]
    ReceiptValue --> StatusCheck[status == Success?]
    StatusCheck -->|fail| Reject2[REJECT: receipt_failed]
    StatusCheck -->|pass| EmitterCheck[emitter + topic0 match?]
    EmitterCheck --> PayloadCheck[B2: payload_hash == bridge_payload_hash]
    PayloadCheck -->|fail| Reject3[REJECT: payload_hash_mismatch]
    PayloadCheck -->|pass| ReplayCheck[replay.is_processed?]
    ReplayCheck -->|yes| Reject4[REJECT: already_processed]
    ReplayCheck -->|pass| Kind{MessageKind?}
    Kind -->|BridgeLock| Mint[bridge_state.mint → add_balance recipient]
    Kind -->|BridgeBurn| Unlock[bridge_state.unlock → refund owner]
  end

  subgraph Safety["Safety gates"]
    Expiry[expiry_height check] --> Mint
    Correlation2[correlation_id mandatory for burn] --> Unlock
    AmountCheck[amount <= u64::MAX] --> Mint
    FeeCheck[1% relayer fee calculation] --> Mint
    ReplayNonce[B3: ReplayNonceStore pruning MAX=65536] --> ReplayCheck
  end
```

## 16. AI inference + execution proof — full lifecycle with STARK

```mermaid
flowchart TD
  subgraph Registration["Model registration"]
    Owner[Model owner address] --> Spec[AiModelSpec: model_hash + version + thresholds]
    Spec --> Class[execution_class: FixedPointMlpV1 = 1]
    Class --> ProgHash[execution_program_hash = matmul_program_hash spec]
    Spec --> RequireProof[require_execution_proof flag]
    Spec --> Reg[ai_registry.models.insert model_id → spec]
    Reg --> ModelRoot[ai_root → AccountState.calculate_state_root]
  end

  subgraph Request["Inference request"]
    User[Requester] --> Req[AiInferenceRequest: model_id + input_commitment + max_fee]
    Req --> Balance[sender.balance >= max_fee + tx.fee]
    Balance -->|fail| Reject1[REJECT: insufficient_balance]
    Balance -->|pass| Submit[ai_registry.submit_request]
    Submit --> Escrow[escrow max_fee from sender]
    Submit --> ReqId[request_id = calculate_id canonical hash]
  end

  subgraph Verification["Verifier responses"]
    Req --> V1[Verifier 1: compute output → sign result]
    Req --> V2[Verifier 2: compute output → sign result]
    Req --> VN[Verifier N: compute output → sign result]
    V1 --> R1[AiInferenceResult: output_commitment + signature]
    V2 --> R2[AiInferenceResult: output_commitment + signature]
    VN --> RN[AiInferenceResult: output_commitment + signature]
  end

  subgraph Threshold["Agreement threshold"]
    R1 --> Agree[agreeing_verifiers: same output_commitment]
    R2 --> Agree
    RN --> Agree
    Agree --> Count{count >= agreement_threshold?}
    Count -->|yes| Finalize[Finalized outcome]
    Count -->|no| Wait[Wait for more results]
    Wait --> Deadline{deadline_block exceeded?}
    Deadline -->|yes| Reclaim[requester reclaims escrowed max_fee]
    Deadline -->|no| Wait
  end

  subgraph Execution["Execution proof pipeline"]
    Model2[FixedPointMlpSpec dims+weights+biases] --> Host[eval_fixed_point_mlp i32 MAC host]
    Host --> Output[output limbs i32 vec]
    Model2 --> Guest[build_matmul_guest_program: Load+Mul+Add+ReLU+Poseidon+Halt]
    Guest --> Bytecode[encoded u64 instructions]
    Bytecode --> ProgHash2[program_hash_from_words SHA3-256]
    Model2 --> Weights[weights_digest SHA3-256]
    Bytecode --> Prove[prove_bytecode → STARK proof]
    Prove --> Envelope[ProofEnvelope: degree_bits + proof_bytes postcard]
    Envelope --> Proof[AiExecutionProof: input_commitment + output_commitment + program_hash + proof_bytes]
  end

  subgraph Attach["Proof attachment + finalization"]
    Proof --> AttachTx[AiAttachExecutionProof tx]
    AttachTx --> StructVerify[verify_execution_proof_structural_with_model]
    StructVerify --> CommitCheck[commitments_match request+result]
    StructVerify --> ModelBind[program_hash == spec.execution_program_hash]
    StructVerify --> SizeCheck[proof_bytes <= MAX_PROOF_BYTES]
    AttachTx --> StarkVerify[verify_execution_proof_stark via DefaultAdapter]
    StarkVerify --> Envelope2[deserialize ProofEnvelope postcard]
    Envelope2 --> PUBCheck[public_inputs_hash match]
    Envelope2 --> DegreeCheck[degree_bits <= MAX_DEGREE_BITS]
    Envelope2 --> BackendCheck[backend contains Plonky3 or test]
    StarkVerify --> FRI[FRI verification]
    AttachTx --> Attach[attach_execution_proof request_id verifier]
    Attach --> TryFinal[try_finalize_with_proofs]
    TryFinal --> RequireCheck{require_execution_proof?}
    RequireCheck -->|yes| ProofRequired[proof must be attached]
    RequireCheck -->|no| AttestOnly[attestation sufficient]
  end

  subgraph Gas["Gas metering"]
    GasEst[estimate_full_gas spec proof_bytes_len]
    GasEst --> Structural[GAS_BASE_STRUCTURAL 500 + 2/param + 50/layer]
    GasEst --> Stark[GAS_BASE_STARK 10000 + 100/KiB proof]
    GasEst --> Budget{gas <= max_fee?}
    Budget -->|no| RejectGas[REJECT: gas_exceeded]
  end
```

## 17. Consensus finality — all 5 domain adapters

```mermaid
flowchart TD
  subgraph PoW["PoW domain adapter"]
    PowCommit[DomainCommitment: domain_block_hash + cumulative_work]
    PowProof[FinalityProof::PoW: nonce + extra_nonce]
    PowVerify[verify: declared_head_hash == commitment.domain_block_hash]
    PowVerify --> WorkCheck[cumulative_work internal consistency]
    WorkCheck --> MinWork[min_work threshold check]
  end

  subgraph PoS["PoS domain adapter"]
    PosCommit[DomainCommitment: validators_root + epoch]
    PosProof[FinalityProof::PoS: BLS certificate]
    PosVerify[verify: cert.verify BLS aggregate signature]
    PosVerify --> SignerCheck[signers ⊆ validator_set]
    SignerCheck --> Threshold[2/3+ stake threshold]
    PosVRF[VRF: calculate_seed → validator selection]
    PosVRF --> SeedRisk[C2: poison fallback → predictable seed]
  end

  subgraph BFT["BFT domain adapter"]
    BftCommit[DomainCommitment: round + state_hash]
    BftProof[FinalityProof::BFT: BLS certificate]
    BftVerify[verify: BLS cert with signer_count]
    BftVerify --> QuorumCheck[quorum threshold met]
  end

  subgraph ZK["ZK domain adapter"]
    ZkCommit[DomainCommitment: proof_hash + program_hash]
    ZkProof[FinalityProof::ZK: STARK ProofEnvelope]
    ZkVerify[verify: ProofClaimRegistry first-valid-wins]
    ZkVerify --> StarkCheck[DefaultAdapter::verify envelope]
    StarkCheck --> PublicInputs[public_inputs_hash match]
  end

  subgraph PoA["PoA domain adapter (isolated)"]
    PoaCommit[DomainCommitment: authorities_root + round]
    PoaProof[FinalityProof::PoA: authorities + signatures vec]
    PoaVerify[verify: ed25519 signature set]
    PoaVerify --> PoaMsg[poa_commit_signing_message commitment-bound]
    PoaMsg --> QuorumPoa[quorum count met no stake]
    PoaIsolation[PoA NO stake in PermissionlessRegistry]
    PoaIsolation --> SeparateReg[PoaMembershipRegistry KYC-only]
  end

  subgraph Settlement["Global settlement"]
    PowVerify --> Global[GlobalBlockHeader 12+ roots]
    PosVerify --> Global
    BftVerify --> Global
    ZkVerify --> Global
    PoaVerify --> Global
    Global --> DomainSep[BDLM_GLOBAL_BLOCK_V2 domain separation]
    Global --> Seal[seal_global_header operator-only RPC]
  end
```

## 18. Registry — complete stake + slash + unbond state machine

```mermaid
stateDiagram-v2
  [*] --> Unregistered
  Unregistered --> Staked: Stake tx (amount >= MIN_STAKE)
  Staked --> Active: sync_validator_registration
  Active --> Active: additional Stake (increase stake)
  Active --> Slashed: SlashingReport (DoubleSign/MaliciousBehaviour)
  Active --> Jailed: SlashingReport (LivenessFault)
  Active --> Unbonding: Unstake tx
  Slashed --> Unregistered: stake = 0 (100% slash)
  Slashed --> Active: partial slash (stake > 0)
  Jailed --> Active: jail_until <= current_epoch
  Jailed --> Slashed: escalated evidence
  Unbonding --> Unregistered: epoch >= release_epoch → balance refund
  Unbonding --> Slashed: slash during unbonding

  note right of Active
    RoleId: VALIDATOR VERIFIER RELAYER
    PROVER STORAGE_OPERATOR AI_VERIFIER
    ATTESTER LUBOT_OPERATOR CONTENT_VALIDATOR
    Cross-role: slash one → jail ALL
  end note

  note right of Slashed
    slash_ratio configurable per condition
    DoubleSign: 100%
    MaliciousBehaviour: 100%
    LivenessFault: configurable %
    slash_amount = stake × ratio
  end note
```

## 19. Wallet — complete signing + privacy + TEE pipeline

```mermaid
flowchart TD
  subgraph KeyDerivation["Key derivation"]
    Entropy[CSPRNG 16/32 bytes getrandom] --> Mnemonic[BIP39 2048-word English wordlist]
    Mnemonic --> Checksum[checksum verify: SHA256 first N bits]
    Mnemonic --> Seed[PBKDF2-HMAC-SHA512 2048 iterations → 32 bytes]
    Seed --> SLIP10[SLIP-10 Ed25519 hardened HD m/44'/coin'/account']
    SLIP10 --> SigningKey[ed25519_dalek SigningKey]
    SigningKey --> VerifyingKey[VerifyingKey 32 bytes]
    VerifyingKey --> Address[SHA3-256 → BudlumAddress]
  end

  subgraph Signing["V4 transaction signing"]
    Payload[Transaction payload] --> Canonical[canonical_signing_hash V4]
    Canonical --> Fields[chain_id + nonce + to + amount + fee + data + type]
    Fields --> Preimage[SHA3-256 domain-separated preimage]
    Preimage --> Ed25519Sign[SigningKey.sign preimage]
    Ed25519Sign --> Signature[ed25519 Signature 64 bytes]
    Signature --> Tx[Transaction: payload + signature + V4 marker]
  end

  subgraph Privacy["Privacy key derivation"]
    Seed --> SpendSecret[derive_spend_secret seed||commitment → u64]
    Seed --> Blinding[derive_blinding seed||counter → u64]
    Seed --> ViewKey[derive_view_key seed||0xVIEW → 32 bytes]
    SpendSecret --> Nullifier[Poseidon2 secret DOMAIN_NULLIFIER]
    Blinding --> Commit[Poseidon3 amount blinding recipient_tag]
  end

  subgraph TEE["TEE execution-time confidentiality"]
    TeeConfig[TeeBackendKind: None/ClientSgx/ServerNitro]
    TeeConfig -->|None| NoTee[Plaintext signing path]
    TeeConfig -->|Sgx/Nitro| TeeRuntime[TeeRuntime.seal_private_intent]
    TeeRuntime -->|available| Sealed[Sealed intent → enclave]
    TeeRuntime -->|unavailable| FailClosed[FAIL-CLOSED: refuse plaintext]
  end

  subgraph Cleanup["Memory safety"]
    Drop[Wallet::drop] --> ZeroizeMnemonic[mnemonic.zeroize]
    Drop --> ZeroizeSeed[seed.zeroize]
    Drop --> ZeroizeKey[signing_key zeroize internal]
  end

  subgraph Recovery["Social recovery"]
    Guardians[GuardianApproval: threshold + timelock] --> Proposal[RecoveryProposal]
    Proposal --> Digest[BDLM_WALLET_RECOVERY_PROPOSAL_V1 domain-separated]
    Proposal --> Timelock[executable_after = created_block + timelock]
    Proposal --> Rotate[rotate_guardian for compromised]
  end
```

## 20. BudZero STARK — bytecode to verified proof pipeline

```mermaid
flowchart TD
  subgraph Bytecode["Guest program construction"]
    Spec[FixedPointMlpSpec] --> Guest[build_matmul_guest_program]
    Guest --> Load[Load instructions: weights + inputs from memory]
    Guest --> Mul[Mul instructions: weight × input]
    Guest --> Add[Add instructions: accumulate + bias]
    Guest --> ReLU[Lt + Jnz conditional: if acc < 0 → acc = 0]
    Guest --> Poseidon[Poseidon commitment over outputs]
    Guest --> Halt[Halt instruction]
    Guest --> Words[Vec u64 encoded instructions]
    Words --> ProgHash[program_hash_from_words SHA3-256]
  end

  subgraph VM["bud-vm execution"]
    Words --> Decode[decode_instruction raw u64 → Instruction]
    Decode --> MainnetGate[MainnetActivation: VerifyMerkle + VerifyInference gates]
    MainnetGate --> S5[S5: env var gate REMOVED — always full activation]
    Decode --> Execute[opcode dispatch: Add/Sub/Mul/Load/Store/Poseidon/etc]
    Execute --> Trace[Execution trace: Vec Step]
    Trace --> Fields[pc next_pc opcode rs1 rs2 rd imm registers memory]
    Trace --> MerkleExp[VerifyMerkle: 64 expansion rows per path step]
    Trace --> InferExp[VerifyInference: 8 expansion rows commitment chain]
    Trace --> GasUsed[gas_used accumulation per opcode cost]
  end

  subgraph AIR["bud-proof AIR constraints (plonky3_air.rs)"]
    Trace --> Matrix[RowMajorMatrix TRACE_WIDTH=414 columns]
    Matrix --> Selectors[38 opcode selectors boolean + exclusive sum]
    Matrix --> RegBus[Register bus LogUp argument]
    Matrix --> MemBus[Memory bus LogUp argument]
    Matrix --> ProgBus[Program bus LogUp argument]
    Matrix --> PoseidonC[Poseidon gadget: 4 rounds α=7 MDS 8×8]
    Matrix --> MerkleC[Merkle path: 64-round Poseidon chain + root check]
    Matrix --> InferC[VerifyInference: selector + expansion commitment consistency]
    Matrix --> S2C[SumConservation: Goldilocks P bound guard]
    Matrix --> S6C[Syscall: unknown imm → rd_val_new = 0 polynomial guard]
    Matrix --> PrivacyC[PrivacyCommit: s0=amount s1=blinding s2=recipient_tag]
    Matrix --> PublicInputs[48 public values: chain_id roots gas exit_code trace_len event_digest]
  end

  subgraph Prover["Plonky3 STARK prover"]
    Matrix --> Commit1[Commit phase 1: main trace Merkle]
    Commit1 --> Commit2[Commit phase 2: auxiliary trace LogUp]
    Commit2 --> FRI[FRI folding: degree reduction]
    FRI --> Query[Query phase: random openings]
    Query --> ProofBytes[Proof bytes serialized]
    ProofBytes --> Envelope[ProofEnvelope: version backend degree_bits public_inputs_hash proof_bytes]
    Envelope --> Postcard[postcard serialize]
  end

  subgraph Verifier["Verifier"]
    Postcard --> Deserialize[postcard deserialize ProofEnvelope]
    Deserialize --> PUBHash[public_inputs_hash match]
    Deserialize --> DegreeCheck[degree_bits <= MAX_DEGREE_BITS]
    Deserialize --> BackendCheck[backend ∈ Plonky3 test]
    Deserialize --> FRIVerify[FRI verification]
    FRIVerify --> Result{valid?}
    Result -->|yes| Accept[ACCEPT: proof verified]
    Result -->|no| Reject[REJECT: invalid proof]
  end
```

## 21. Governance — proposal to execution pipeline

```mermaid
flowchart TD
  subgraph Proposal["Proposal creation"]
    Proposer[Proposer address] --> Type{ProposalType?}
    Type -->|ChangeBlockReward| P1[value: new reward amount]
    Type -->|ChangeFeeParams| P2[value: new fee parameters]
    Type -->|SetConstitutionParameter| P3[key + value bounded]
    Type -->|SetEncryptionPolicy| P4[policy: version + suite + limits]
    P1 --> Gov[governance.proposals.push]
    P2 --> Gov
    P3 --> Gov
    P4 --> Gov
    Gov --> Epoch[start_epoch + end_epoch]
    Gov --> Activation[activation_epoch timelock]
  end

  subgraph Voting["Voting period"]
    Epoch --> Active[Active status]
    Active --> Vote[Voter: stake-weighted]
    Vote --> For[votes_for += voter.stake]
    Vote --> Against[votes_against += voter.stake]
    Vote --> Snapshot[voter_weights snapshot]
    Snapshot --> Unstake[Unstake during voting → reduce_vote_weight]
    Active --> Cancel[cancel_proposal owner-only]
  end

  subgraph Finalization["Epoch advance → finalize"]
    EndEpoch[current_epoch >= end_epoch] --> Finalize[proposal.finalize]
    Finalize --> TotalStake[total_stake = get_total_stake]
    TotalStake --> Quorum[quorum_pct = 33%]
    Quorum --> Check{votes >= quorum AND for > against?}
    Check -->|yes| Passed[Status: Passed]
    Check -->|no| Rejected[Status: Rejected]
  end

  subgraph Execution["Activation → execute"]
    Passed --> ActCheck[current_epoch >= activation_epoch?]
    ActCheck -->|yes| Execute[execute_proposal]
    ActCheck -->|no| Wait[Wait for activation]
    Execute -->|ChangeBlockReward| SetReward[block_reward = new_value]
    Execute -->|ChangeFeeParams| SetFee[fee_params = new_value]
    Execute -->|SetConstitutionParameter| SetConst[parameter update with whitelist check]
    Execute -->|SetEncryptionPolicy| SetEnc[encryption_policies.insert DAO-managed]
    Execute --> Whitelist[GOVERNANCE_PARAMETER_WHITELIST validation]
    Whitelist -->|not whitelisted| RejectParam[REJECT: non_whitelisted_parameter]
  end
```

## 22. Tokenomics — burn + vesting + reward state machine

```mermaid
flowchart TD
  subgraph Genesis["Genesis allocation (100M BUD, 6 decimals)"]
    Total[100_000_000 × BUD_UNIT] --> Community[10M → community accounts]
    Total --> Liquidity[10M → liquidity accounts]
    Total --> Ecosystem[20M → ecosystem accounts]
    Total --> Team[20M → team_vesting cliff+linear]
    Total --> BurnReserve[40M → burn_reserve_address]
  end

  subgraph TimedBurn["process_timed_burn (epoch-triggered)"]
    Epoch[advance_epoch] --> Trigger[process_timed_burn called]
    Trigger --> Rate[annual_burn_rate × BUD_UNIT / epochs_per_year]
    Rate --> BurnFrom[burn_from burn_reserve_address amount]
    BurnFrom --> Supply[circulating_supply decreases]
    BurnFrom --> Exhausted{reserve == 0?}
    Exhausted -->|yes| Stop[Stop burning]
    Exhausted -->|no| Continue[Continue next epoch]
  end

  subgraph FeeBurn["Metabolic tx-fee burn"]
    Tx[Transaction applied] --> Fee[tx.fee collected]
    Fee --> Ratio[tx_fee_burn_ratio × fee]
    Ratio --> BurnFee[burn_from sender amount]
    Fee --> Remainder[remainder → proposer/treasury]
  end

  subgraph Vesting["Team vesting (cliff + linear)"]
    TeamAlloc[20M team allocation] --> Cliff[cliff_epochs: no unlock]
    Cliff --> Linear[linear unlock per epoch after cliff]
    Linear --> Spendable[spendable_balance = balance - locked_at epoch]
    Spendable --> Transfer{transfer amount <= spendable?}
    Transfer -->|yes| Allow[Transfer allowed]
    Transfer -->|no| RejectVest[REJECT: vesting_locked]
  end

  subgraph Cap["Supply cap enforcement (V144)"]
    BlockReward[block_reward mint] --> CapCheck[total_bud_committed <= 100M?]
    CapCheck -->|yes| Mint[Allow mint]
    CapCheck -->|no| CapReject[REJECT: supply_cap_exceeded]
    TotalBud[total_bud_committed = circulating + staked + unbonding]
    TotalBud --> CapCheck
  end

  subgraph EIP1559["Fee market (EIP-1559)"]
    BaseFee[block N-1 base_fee] --> Adjust[±12.5% based on gas usage]
    Adjust --> NewBase[block N base_fee]
    Tx2[Transaction] --> Effective[effective_fee = min max_fee base_fee+priority]
    Effective --> Burn2[base_fee portion burned]
    Effective --> Tip[priority_fee → proposer]
  end
```

## 23. P2P protocol stack — libp2p to application

```mermaid
flowchart TD
  subgraph Transport["Transport layer"]
    TCP[TCP /ip4/0.0.0.0/tcp/4001]
    QUIC[QUIC /ip4/0.0.0.0/udp/4001/quic-v1]
    Identity[Ed25519 PeerId identity key]
    TCP --> Libp2p[libp2p Swarm]
    QUIC --> Libp2p
    Identity --> Libp2p
  end

  subgraph Discovery["Peer discovery"]
    Kademlia[Kademlia DHT]
    Bootstrap[Bootstrap nodes from config]
    DNS[Dns seed resolution]
    Kademlia --> Peers[PeerManager known peers]
    Bootstrap --> Kademlia
    DNS --> Bootstrap
  end

  subgraph Gossipsub["Gossipsub messaging"]
    Topics[Topic: blocks txs finality snapshots]
    MsgIn[Incoming message] --> Dedup[MessageId dedup SipHash]
    Dedup --> Validate[Message validation]
    Validate --> SizeCheck[MAX_MESSAGE_SIZE 10MB]
    SizeCheck -->|oversized| Score1[report_oversized_message penalty]
    SizeCheck -->|ok| Dispatch[Dispatch to handler]
    Dispatch --> BlockHandler[block received → validate_and_add_block]
    Dispatch --> TxHandler[tx received → mempool admission]
    Dispatch --> FinalityHandler[finality cert → apply_qc_fault_verdict]
  end

  subgraph PeerScoring["Reputation scoring"]
    Score[PeerScore: -100 to 100]
    Score --> Good[Valid block/tx relay: +reward]
    Score --> Bad1[Invalid block: report_invalid_block penalty]
    Score --> Bad2[Invalid tx: report_invalid_tx penalty]
    Score --> Bad3[Oversized msg: report_oversized_message penalty]
    Score --> RateLimit[Rate limit exhaustion: dedicated penalty]
    Score --> Ban{score <= -100?}
    Ban -->|yes| BanPeer[Ban peer + disconnect]
    Ban -->|no| Continue[Continue connection]
    Eclipse[max_peers_per_subnet /24 = 4] --> Score
    Eclipse --> Idempotent[note_connected/disconnected idempotent]
  end

  subgraph SnapshotSync["Snapshot synchronization"]
    SnapReq[Snapshot request] --> Chunks[MAX_SNAPSHOT_CHUNKS = 4096]
    Chunks --> Concurrent[MAX_CONCURRENT_SNAPSHOTS = 10]
    Chunks --> Verify[Schema-4 digest + field manifest verify]
    Verify --> Restore[Restore AccountState]
    Verify --> Quarantine[Quarantine on failure]
  end
```

## 24. Pollen data marketplace — full grant + encryption + AI gate

```mermaid
flowchart TD
  subgraph Asset["DataAsset registration"]
    Owner[Data owner address] --> Asset[DataAsset: asset_id + metadata]
    Asset --> Registry[MarketplaceRegistry.data_assets.insert]
    Asset --> Root1[data_assets_root → Pollen root → state_root]
  end

  subgraph Grant["AccessGrant lifecycle"]
    Asset --> Grant[AccessGrant: grant_id + grantee + scope + expiry + max_reads]
    Grant --> GrantReg[MarketplaceRegistry.access_grants.insert]
    Grant --> Root2[access_grants_root → Pollen root]
    Grant --> Revoke[Revoke: owner-only → remove from registry]
    Grant --> Expire[Expiry: block > expiry_block → invalid]
    Grant --> Exhaust[max_reads reached → exhausted]
  end

  subgraph Sale["SaleAuthorization + purchase"]
    Asset --> Sale[SaleAuthorization: seller + buyer + price + duration]
    Sale --> SaleReg[MarketplaceRegistry.sale_authorizations.insert]
    Sale --> Purchase[PollenPurchaseReceipt: seller auth + buyer + grant + payment]
    Purchase --> IssueGrant[issue_grant_from_sale_authorization]
    IssueGrant --> NewGrant[New AccessGrant for buyer]
    Purchase --> ReceiptReg[purchase_receipts.insert → root]
  end

  subgraph Encryption["EncryptionPolicy (DAO-managed)"]
    DAO[Governance proposal] --> SetPolicy[SetEncryptionPolicy action]
    SetPolicy --> Policy[EncryptionPolicy: version + hpke_suite + min_key + max_duration]
    Policy --> PolicyReg[MarketplaceRegistry.encryption_policies.insert]
    Policy --> NoDecrypt[NO decrypt/key/read override fields]
    Policy --> AssetPolicy[AssetEncryptionPolicy per-asset]
    AssetPolicy --> Validate[validate_static: algorithm + key_length + rotation]
    Validate --> RejectNone[EncryptionAlgorithm::None REJECTED]
  end

  subgraph AIGate["AI inference data gate"]
    Req[AiInferenceRequest] --> InputRef[input_ref: Pollen data reference?]
    InputRef -->|no poll| Legacy[Legacy opaque path — no grant needed]
    InputRef -->|yes poll| GrantCheck{valid AccessGrant exists?}
    GrantCheck -->|no grant| Deny1[REJECT: ai_data_access_denied]
    GrantCheck -->|expired| Deny2[REJECT: grant_expired]
    GrantCheck -->|revoked| Deny3[REJECT: grant_revoked]
    GrantCheck -->|exhausted| Deny4[REJECT: grant_exhausted]
    GrantCheck -->|wrong grantee| Deny5[REJECT: grantee_mismatch]
    GrantCheck -->|valid| Allow[ALLOW: data read permitted]
    Allow --> Consume[Increment read count]
    Consume --> FailCheck[Failed request does NOT consume grant]
  end

  subgraph Passport["D-Web Passport evidence"]
    BNSName[BNS name] --> Profile[DwebPassportProfile]
    Profile --> Evidence[EvidenceCard: BNS verified/expired]
    Profile --> PollenSummary[Pollen lineage counts]
    Profile --> Bundle[PassportProofBundle deterministic root]
    Bundle --> Warning[Warning hash only — NO plaintext]
    Profile --> RPC[bud_passportGetProfile read-only]
    Bundle --> RPC2[bud_passportGetProofBundle read-only]
  end
```

## 25. Cross-domain message verification — EVM MPT deep dive

```mermaid
flowchain TD
  subgraph Header["Target chain header validation"]
    BlockNum[block_number] --> Height[source_height >= deployment_height]
    ParentHash[parent_hash] --> Chain[chain continuity check]
    Confirm[N confirmations] --> Depth[depth >= min_confirmations]
    ReceiptsRoot[receipts_root] --> MPT[MPT root for proof verification]
    StateRoot[state_root] --> AccRoot[account state verification]
  end

  subgraph RLP["Strict RLP decoding"]
    Bytes[Receipt envelope bytes] --> Prefix[RLP prefix byte]
    Prefix -->|0xf7..0xff| List[RLP list header]
    Prefix -->|0x80..0xb7| String[RLP string]
    List --> Status[Status field: 0x0 = fail 0x1 = success]
    List --> Logs[Logs array]
    Logs --> Topic0[topic0: event signature]
    Logs --> Emitter[Emitter address: known contract?]
    Logs --> Data[Data: payload bytes]
  end

  subgraph MPT["Merkle-Patricia trie verification"]
    Key[RLP encode receipt index] --> Nibble[Convert to nibbles]
    Nibble --> Root[Start at receipts_root]
    Root --> Node{Node type?}
    Node -->|Branch| Branch[16 children + value]
    Node -->|Extension| Extension[shared nibbles + next]
    Node -->|Leaf| Leaf[remaining nibbles + value]
    Branch --> Match[Match next nibble → child]
    Extension --> Shared[Verify shared prefix matches]
    Leaf --> Remain[Verify remaining nibbles match]
    Match --> Next[Recurse into child node]
    Shared --> Next
    Remain --> Value[Extract leaf value = receipt bytes]
  end

  subgraph Payload["Payload verification"]
    Value --> DecodeReceipt[Decode receipt bytes]
    DecodeReceipt --> StatusCheck{status == 0x1 success?}
    StatusCheck -->|no| Reject1[REJECT: transaction_failed]
    StatusCheck -->|yes| EmitterCheck{emitter in allowlist?}
    EmitterCheck -->|no| Reject2[REJECT: unknown_emitter]
    EmitterCheck -->|yes| TopicCheck{topic0 matches expected event?}
    TopicCheck -->|no| Reject3[REJECT: wrong_event_type]
    TopicCheck -->|yes| PayloadHash[B2: payload_hash == bridge_payload_hash asset_id amount]
    PayloadHash -->|fail| Reject4[REJECT: payload_hash_mismatch]
    PayloadHash -->|pass| Accept[ACCEPT: verified deposit/lock facts]
  end
```
## 26. Privacy layer — note lifecycle (D2)

```mermaid
flowchart LR
  Seed[Wallet seed] --> Derive[derive_spend_secret + derive_blinding]
  Derive --> Note[PrivateNoteInput / PrivateNoteOutput]
  Note --> Commit[PrivacyCommit opcode → Poseidon3]
  Commit --> Reg[L1NoteRegistry live_commitments]
  Note --> Null[NullifierCheck opcode → Poseidon2]
  Null --> Spent[spent_nullifiers set]
  Reg --> Transfer[PrivateTransferSubmit tx]
  Transfer --> Verify[SumConservation opcode]
  Transfer --> Apply[apply_transfer: remove commitment + insert nullifier]
  ViewKey[View key disclosure] -. selective .-> Audit[Auditor / authority]
  TEE[TEE opt-in] -. encrypt .-> Note
```

## 27. Wallet-core architecture

```mermaid
flowchart TD
  Entropy[CSPRNG entropy] --> BIP39[BIP39 mnemonic 12/24 words]
  BIP39 --> Seed[PBKDF2 → 32-byte seed]
  Seed --> SLIP10[SLIP-10 Ed25519 HD derivation]
  SLIP10 --> KeyPair[SigningKey + VerifyingKey]
  KeyPair --> Address[SHA3-256 → BudlumAddress]
  KeyPair --> Sign[V4 canonical signing]
  Seed --> Privacy[derive_spend_secret / derive_blinding]
  Seed --> ViewKey[derive_view_key]
  TEE[TeeRuntime opt-in] -. seal .-> Sign
  Zeroize[Zeroize on drop] -. cleanup .-> Seed
  Zeroize -. cleanup .-> BIP39
  Recovery[Social recovery guardians] -. restore .-> Seed
```

## 28. Governance lifecycle

```mermaid
flowchart LR
  Propose[Proposal submitted] --> Active[Active voting period]
  Active --> Vote[Stake-weighted votes for/against]
  Active --> Timelock[activation_epoch timelock]
  Vote --> Finalize[Epoch advance → finalize]
  Finalize -->|quorum met + majority| Passed[Passed]
  Finalize -->|quorum not met| Rejected[Rejected]
  Passed --> Execute[Execute governance action]
  Timelock --> Execute
  Execute --> Params[Update chain parameters]
  Execute --> BlockReward[Change block reward]
  Execute --> Constitution[Update constitution guardrails]
  Cancel[Proposal cancellation] -. owner only .-> Active
```

## 29. Tokenomics flow

```mermaid
flowchart TD
  Genesis[100M BUD genesis] --> Community[Community 10M]
  Genesis --> Liquidity[Liquidity 10M]
  Genesis --> Ecosystem[Ecosystem 20M]
  Genesis --> Team[Team 20M vesting cliff+linear]
  Genesis --> BurnReserve[Burn reserve 40M]
  BurnReserve --> TimedBurn[process_timed_burn epoch-triggered]
  TxnFee[Tx fee] --> FeeBurn[tx_fee_burn_ratio metabolic burn]
  TxnFee --> Proposer[Proposer tip]
  TxnFee --> Treasury[Treasury share]
  BlockReward[block_reward mint] --> Proposer2[Block producer]
  TimedBurn --> Sink[Burn sink — supply decreases]
  FeeBurn --> Sink
```

## 30. P2P network topology

```mermaid
flowchart TB
  Node[Budlum node] --> Gossip[Gossipsub topics]
  Gossip --> Blocks[Block announcements]
  Gossip --> Txs[Transaction relay]
  Gossip --> Finality[Finality certificates]
  Node --> Peers[PeerManager]
  Peers --> MaxPeers[MAX_PEERS = 50]
  Peers --> Subnet[max_peers_per_subnet /24 = 4]
  Peers --> Score[Reputation scoring]
  Score --> Ban[Ban threshold ≤ -100]
  Node --> Snap[Snapshot sync]
  Snap --> Chunks[MAX_SNAPSHOT_CHUNKS = 4096]
  Snap --> Concurrent[MAX_CONCURRENT_SNAPSHOTS = 10]
  Node --> Identity[Ed25519 identity key]
  Identity --> Auth[Peer authentication]
```

## 31. Permissionless registry architecture

```mermaid
flowchart LR
  Stake[Stake tx] --> Reg[PermissionlessRegistry]
  Reg --> Roles[RoleId: VALIDATOR · VERIFIER · RELAYER · PROVER · STORAGE_OPERATOR · AI_VERIFIER · ATTESTER · LUBOT_OPERATOR · CONTENT_VALIDATOR]
  Reg --> Slash[SlashingReport → slash]
  Slash --> DoubleSign[DoubleSign → 100%]
  Slash --> Liveness[LivenessFault → configurable]
  Slash --> Malicious[MaliciousBehaviour → 100%]
  Reg --> Unbond[Unbond tx → unbonding_queue]
  Unbond --> Epoch[Epoch advance → release]
  CrossRole[Cross-role slashing] -. slash one .-> AllRoles[All roles jailed]
```

## 32. PoA domain lifecycle

```mermaid
flowchart LR
  KYC[KYC / identity verification] --> Membership[PoaMembershipRegistry]
  Membership --> Admin[Admin approval]
  Admin --> Active[Active PoA member]
  Active --> Sign[Ed25519 finality signatures]
  Active --> Compliance[PoaComplianceRegistry]
  Compliance --> Screen[Address screening]
  Compliance --> Freeze[Asset freeze]
  Compliance --> TravelRule[Travel rule metadata hash]
  Compliance --> Audit[Append-only audit log]
  Isolation[PoA isolated from permissionless domains] -. no shared registry .-> Permissionless
```

## 33. Validator lifecycle

```mermaid
flowchart TD
  Genesis[Genesis config] --> Val[Validator created with keys]
  Stake[Stake tx] --> Active[Active validator]
  Active --> Propose[Block proposal via VRF]
  Active --> Finality[BLS finality signing]
  Active --> Slash[Slashing evidence]
  Slash --> Jailed[Jailed until epoch N]
  Jailed --> Release[Jail release]
  Release --> Active
  Unstake[Unstake tx] --> Unbonding[Unbonding queue]
  Unbonding --> Epoch[Epoch advance → release stake]
  Liveness[Missed epochs > threshold] --> LivenessSlash[Liveness report → slash]
```

## 34. Pollen data rights lifecycle

```mermaid
flowchart LR
  Asset[DataAsset registered] --> Grant[AccessGrant issued]
  Grant --> Grantee[Grantee address + scope + expiry]
  Asset --> Sale[SaleAuthorization]
  Sale --> Buyer[Buyer purchases access]
  Buyer --> Purchase[PollenPurchaseReceipt]
  Grant --> AI[AI inference request]
  AI --> Gate[Pollen data gate: valid grant required]
  Gate -->|grant valid| Allow[Allow data read]
  Gate -->|no grant| Deny[Deny — strict default-deny]
  Encrypt[EncryptionPolicy DAO-managed] -. parameters .-> Asset
  Revoke[Revoke grant/asset] -. owner only .-> Grant
```

## 35. Relayer policy layer

```mermaid
flowchart LR
  User[User intent] --> Intent[UserIntent signed]
  Intent --> Pool[Intent pool]
  Pool --> Solver[Solver bids]
  Solver --> Best[Best bid selection]
  Best --> Settle[IntentSettlement]
  Settle --> Execute[Execute settlement]
  Policy[PolicyEnvelope] --> FeeCap[Fee cap enforcement]
  Policy --> Deadline[Deadline validation]
  Policy --> Domain[Domain allowlist]
  Policy --> Replay[Replay nonce check]
  Slashing[Relayer slashing] --> Griefing[Griefing → 100%]
  Slashing --> FrontRunning[Front-running → 100%]
  Slashing --> WrongRelay[Wrong-relay → 100%]
```

## 36. Fee market (EIP-1559)

```mermaid
flowchart LR
  Block[Block N-1 base_fee] --> Calc[next_base_fee calculation]
  Calc --> Adjustment[±12.5% adjustment based on gas usage]
  Adjustment --> BaseFee[Block N base_fee]
  Tx[Transaction] --> Bid[FeeBid: max_fee + max_priority_fee]
  Bid --> Effective[effective_fee = min(max_fee, base_fee + priority)]
  Effective --> Check[effective_fee ≥ base_fee?]
  Check -->|yes| Accept[Accepted]
  Check -->|no| Reject[Rejected — underpriced]
  Accept --> Burn[base_fee burned]
  Accept --> Tip[priority_fee → proposer]
```

## 37. AI execution proof pipeline

```mermaid
flowchart TD
  Model[FixedPointMlpSpec] --> Host[Host eval_fixed_point_mlp i32 MAC]
  Host --> Output[Output limbs]
  Model --> Guest[build_matmul_guest_program BudZKVM instructions]
  Guest --> ProgramHash[program_hash_from_words]
  Model --> Weights[weights_digest SHA3-256]
  Weights --> Bytecode[Guest bytecode: Load + Mul + Add + ReLU + Poseidon + Halt]
  Bytecode --> Prove[prove_bytecode → STARK proof]
  Prove --> Envelope[ProofEnvelope postcard]
  Envelope --> Attach[AiAttachExecutionProof tx]
  Attach --> Verify[Structural verify + program_hash bind]
  Verify --> STARK[STARK verify via DefaultAdapter]
  STARK --> Finalize[try_finalize_with_proofs]
```

## 38. DeEd content manifest architecture

```mermaid
flowchart LR
  Content[Raw content bytes] --> Hash[ContentId = SHA3-256 domain-tagged]
  Content --> Shards[Off-chain sharding]
  Shards --> ShardRef[ShardRef: shard_id + size]
  Hash --> Manifest[ContentManifest: shards + metadata + owner]
  Manifest --> ManifestId[ManifestId = deterministic hash]
  ManifestId --> Chain[On-chain registration]
  Chain --> Deal[Storage deal per shard]
  Deal --> Operator[Storage operator bonds]
  Deal --> Challenge[Retrieval challenge]
  Challenge --> Proof[VerifyMerkle 64-depth proof]
  Roles[Permissionless roles: STORAGE_OPERATOR · ATTESTER] -. no whitelist .-> Deal
```

## 39. BNS (Budlum Name Service) lifecycle

```mermaid
flowchart LR
  Register[Register name 3-32 chars] --> Cost[Cost = base × multiplier × duration]
  Cost --> Owner[Owner address bound]
  Owner --> Resolve[resolve_content → address]
  Owner --> SetContent[set_content → CID/hash]
  Owner --> Transfer[Transfer to new owner]
  Owner --> Renew[Renew before expiry]
  Expiry[Expiry epoch reached] --> Grace[Grace period 3000 epochs]
  Grace -->|original owner| Renew2[Renew only by original owner]
  Grace -->|expired| Available[Name available for re-registration]
  Squat[Front-running squatting protection] -. grace period .-> Grace
```

## 40. SocialFi NFT lifecycle

```mermaid
flowchart LR
  Mint[Mint NFT owner-only] --> Metadata[CID + luminance=0]
  Metadata --> Luminance[update_luminance delta i128]
  Luminance --> Positive[Positive: amplify reach]
  Luminance --> Negative[Negative: reduce reach]
  Mint --> Transfer[Transfer to new owner]
  Mint --> Burn[Burn → CID returned]
  Registry[NftRegistry next_id auto-increment] --> Mint
  Guard[Luminance clamp i128 → safe range] --> Luminance
```

## 41. Hub app registry

```mermaid
flowchart LR
  Developer[Developer address] --> Register[register_app auto-increment ID]
  Register --> Manifest[AppManifest: URL + metadata]
  Manifest --> Update[update_app URL/manifest]
  Register --> SelfVerify[verify_app developer self-verify]
  SelfVerify --> Attested[developer_attested = true]
  Attested --> Verified[verified = true DAO override reserved]
  Root[Registry root hash] --> StateRoot[AccountState state_root]
  Audit[Attestation audit trail] --> SelfVerify
```

## 42. Mempool internals

```mermaid
flowchart TD
  Tx[Incoming transaction] --> Decode[V4 decode + signature verify]
  Decode --> Admit[Admission: nonce + balance + type rules]
  Admit --> Pool[Mempool pool max_size=20000]
  Pool --> PerSender[max_per_sender=100]
  Pool --> Evict[evict_lowest_fee when full]
  Pool --> RBF[Replace-By-Fee: higher fee replaces]
  Pool --> Dedup[Duplicate tx rejection]
  Pool --> Select[Block producer selects by fee priority]
  Select --> Block[Included in next block]
  Select --> Expire[Stale tx removed after N blocks]
```

## 43. Developer OS / SDK architecture

```mermaid
flowchart LR
  Manifest[DeveloperOsManifest deterministic] --> Project[Project ID + labels]
  Project --> DevNet[Local devnet topology]
  Project --> BudL[BudL package fixtures]
  Project --> Proof[Proof fixtures]
  Project --> Pollen[Pollen fixtures]
  Project --> Relayer[Relayer policy fixtures]
  Manifest --> Flags[SDK feature flags]
  Flags --> Offline[Offline default: no external network]
  Flags --> Safety[Safety fixtures: verified proof required]
  Safety --> NoMock[Pollen fixture cannot bypass AI grant]
  Project --> Traversal[Path traversal rejection]
```

## 44. Gateway — Atlas + Passport evidence

```mermaid
flowchart LR
  Address[BudlumAddress] --> Atlas[AtlasWalletContext]
  Atlas --> Account[Account state evidence]
  Atlas --> Pollen[Pollen lineage summary]
  Atlas --> Domain[Domain trace + wallet graph]
  Name[BNS name] --> Passport[DwebPassportProfile]
  Passport --> Evidence[EvidenceCard: verified/expired/pending]
  Passport --> Bundle[PassportProofBundle deterministic root]
  Bundle --> Warning[Warning hash only — no plaintext]
  Atlas --> RPC[bud_atlasGetWalletContext read-only]
  Passport --> RPC2[bud_passportGetProofBundle read-only]
  NoPlaintext[Endpoint never returns raw data] -. enforced .-> RPC
  NoPlaintext -. enforced .-> RPC2
```

## 45. Settlement commitment tree

```mermaid
flowchart TD
  Block[Block commitment] --> Roots[12+ root fields]
  Roots --> DomainReg[domain_registry_root]
  Roots --> Commitment[commitment_root]
  Roots --> Message[message_root]
  Roots --> Bridge[bridge_root]
  Roots --> Replay[replay_root]
  Roots --> Settlement[settlement_root]
  Roots --> Storage[storage_root]
  Roots --> AI[ai_root]
  Roots --> Pollen[pollen_root]
  DomainSep[BDLM_GLOBAL_BLOCK_V2 domain separation] --> Hash[GlobalBlockHeader hash]
  Proof[SettlementProofVerifier] --> Merkle[Merkle proof + domain/height/index check]
  Merkle --> Forge[expected_block_hash forgery gate]
```

## 46. Prover market — proof verification

```mermaid
flowchart LR
  Task[ProofTask created] --> Assign[Assigned to prover]
  Assign --> Prove[Prover generates STARK proof]
  Prove --> Receipt[ProofReceipt: task_id + prover + hash + reward]
  Receipt --> Verify[Verification: task_id + prover + epoch + hash + reward cap]
  Verify -->|valid| Complete[complete_task → reward committed]
  Verify -->|invalid| Reject[Reject — task stays active]
  Policy[First valid receipt wins] --> Complete
  Policy --> Duplicate[Identical duplicate → idempotent]
  Limits[Active tasks + pending receipts bounded] --> Task
```

## 47. Sovereign domain kit

```mermaid
flowchart LR
  Template[SovereignDomainTemplate] --> Class[SovereignClass enum]
  Class --> PoA[EnterprisePoa → requires PoA consensus]
  Class --> Custom[Custom class label validated]
  Template --> Compliance[ComplianceEvidence hash/root only]
  Compliance --> NoPII[No private KYC/passport on-chain]
  Template --> Lifecycle[Lifecycle: draft → active → retired]
  Lifecycle --> NoReactivate[Retired cannot re-activate]
  Template --> Audit[AuditExportBundle template + compliance root]
  Audit --> Bounded[Bounded height span]
```

## 48. Constitution engine

```mermaid
flowchart TD
  Guardrails[Hard guardrails immutable] --> NoWhitelist[No permissionless whitelist]
  Guardrails --> NoDecrypt[No AI read/decrypt override]
  Guardrails --> PoAIsolation[PoA domain isolation]
  Guardrails --> NoCustody[No private key custody]
  Guardrails --> EvidenceOnly[Evidence-only API]
  Params[Mutable bounded params] --> HaltMax[emergency_halt_max_epochs]
  Params --> PropMin[constitution_proposal_min_epochs]
  Governance[SetConstitutionParameter proposal] --> Params
  Governance -->|hard guardrail update| Reject[Fail-closed rejected]
  Root[Constitution root hash] --> StateRoot[AccountState state_root]
```

## 49. Mobile self-hosting profile

```mermaid
flowchart LR
  Profile[MobileNodeProfile] --> Power[PowerMode: battery/saver/performance]
  Power --> Battery[BatteryStatus validated]
  Profile --> Network[NetworkStatus: bandwidth + latency + NAT]
  Profile --> Storage[StorageStatus: capacity + availability]
  Network --> Relay[Relay address for NAT traversal]
  Storage --> Critical[Critical content requires paid replica]
  Profile --> Opportunistic[Opportunistic hosting — not always-on]
  Profile --> Scheduled[Scheduled replication windows]
  Validation[Impossible battery state rejected] --> Battery
  Validation[Zero bandwidth rejected] --> Network
```

## 50. Encryption DAO policy lifecycle

```mermaid
flowchart LR
  DAO[Governance proposal] --> SetPolicy[SetEncryptionPolicy action]
  SetPolicy --> Policy[EncryptionPolicy: version + suite + limits]
  Policy --> Active[active = true]
  Policy --> Deprecated[deprecated_after_block set]
  Policy --> MinKey[min_public_key_bytes enforced]
  Policy --> MaxGrant[max_grant_duration_blocks enforced]
  Policy --> NoDecrypt[No decrypt/key/read override fields]
  Asset[AssetEncryptionPolicy per-asset] --> Validate[validate_static: algorithm + key length + rotation]
  Validate --> Reject[EncryptionAlgorithm::None rejected]
  Root[Pollen root hash] --> StateRoot[AccountState state_root]
```

## 51. Pre-mortem security audit — attack graph

```mermaid
flowchart TD
  CIPat[CI PAT leak] --> MainBranch[main branch compromise]
  MainBranch --> CodeManip[Code manipulation]
  PKCS11[PKCS11 data object] --> BLSExtract[BLS key extraction]
  BLSExtract --> FinalityForge[Finality forge]
  BLSBias[BLS hash_to_g1 bias] --> FinalityManip[Finality manipulation]
  RPCNoAuth[RPC no auth] --> BridgeMint[Unauth bridge mint]
  BridgeNoPayload[Bridge mint no payload check] --> FundInflation[Fund inflation]
  SaturatingArith[saturating arithmetic] --> SilentLoss[Silent BUD loss]
  BlindingTrunc[Blinding truncation] --> PrivacyBreak[Privacy break]
  NullifierCollision[Nullifier collision] --> DoubleSpend[Double-spend]
  PoseidonDesync[Poseidon constants desync] --> AllProofsFail[All proofs rejected]
  SeedMemory[Seed in memory] --> TotalLoss[Total fund loss]
  C1 --> C1Fix[dual SHA3-256 LO/HI ✅]
  H1 --> H1Fix[Extractable=false ✅]
  R2 --> R2Fix[require_operator ✅]
  S1 --> S1Fix[register-based blinding ✅]
  B2 --> B2Fix[payload_hash verify ✅]
  E1 --> E1Fix[checked arithmetic ✅]
```
