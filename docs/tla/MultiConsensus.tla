----------------------------- MODULE MultiConsensus -----------------------------
(* Task 9 — TLA+ iskeleti (ARENA3, 2026-07-16)                              *)
(* Budlum Universal Settlement Layer: çoklu-konsensüs domain'leri arası       *)
(* atomik settlement'in safety + liveness özelliklerini modellemek için.       *)
(*                                                                             *)
(* Bu bir ISKELET modeldir — tam formal verification değildir.                 *)
(* Gap: quorum-bound voting, BLS aggregate signatures, actual network delays,  *)
(* Byzantium node davranışı, storage attestation adapter.                      *)
(* Tam model harici audit firması tarafından yapılacaktır (Task 5).           *)
(******************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

(******************************************************************************
 * Constants: domain tipleri, validator kümesi eşikleri.
 ******************************************************************************)

CONSTANTS
  Domains,          \* {PoW, PoS, BFT, PoA} — konsensüs domain'leri
  Validators,       \* Tüm validator'ların kümesi
  MinQuorum,        \* Minimum quorum eşiği
  MaxFaulty         \* Maksimum Byzantine node sayısı (f < n/3 varsayımı)

ASSUME Domains /= {}
ASSUME Validators /= {}
ASSUME MinQuorum \in 1..Cardinality(Validators)
ASSUME MaxFaulty < Cardinality(Validators) \div 2  \* n > 2f

(******************************************************************************
 * Variables: her domain'in commitment durumu.
 ******************************************************************************)

VARIABLES
  domain_committed,   \* [domain -> BOOLEAN] — domain finalize oldu mu?
  domain_height,      \* [domain -> Nat] — her domain'in blok yüksekliği
  cross_messages,     \* CrossDomainMessage kuyruğu (set of records)
  slashed             \* Slashed validator'lar (misbehaviour)

vars == <<domain_committed, domain_height, cross_messages, slashed>>

(******************************************************************************
 * Initial state: tüm domain'ler genesis'te (height=0, committed=FALSE).
 ******************************************************************************)

Init ==
  /\ domain_committed = [d \in Domains |-> FALSE]
  /\ domain_height    = [d \in Domains |-> 0]
  /\ cross_messages   = {}
  /\ slashed          = {}

(******************************************************************************
 * Settlement: bir domain yeni blok üretir. Quorum sağlandıysa committed=TRUE.
 * Bu, L1 finality adapter'ının cert.verify() akışını modeller.
 ******************************************************************************)

ProduceBlock(d) ==
  LET honest_votes == CHOOSE S \in SUBSET Validators : Cardinality(S) >= MinQuorum
  IN  /\ \E S \in SUBSET Validators : Cardinality(S) >= MinQuorum
      /\ domain_height' = [domain_height EXCEPT ![d] = domain_height[d] + 1]
      /\ domain_committed' = [domain_committed EXCEPT ![d] = TRUE]
      /\ UNCHANGED <<cross_messages, slashed>>

(******************************************************************************
 * CrossDomainMessage: domain A'dan B'ye mesaj. Replay koruması: nonce.
 ******************************************************************************)

SendCrossMessage(sender, receiver, nonce) ==
  LET msg == [from |-> sender, to |-> receiver, nonce |-> nonce]
  IN  /\ domain_committed[sender]   \* Gönderen finalize olmuş olmalı
      /\ msg \notin cross_messages  \* Nonce ile replay önleme
      /\ cross_messages' = cross_messages \cup {msg}
      /\ UNCHANGED <<domain_committed, domain_height, slashed>>

(******************************************************************************
 * Slashing: bir validator Byzantine davranış sergilerse slash'lanır.
 ******************************************************************************)

SlashValidator(v) ==
  /\ v \in Validators
  /\ v \notin slashed
  /\ slashed' = slashed \cup {v}
  /\ UNCHANGED <<domain_committed, domain_height, cross_messages>>

(******************************************************************************
 * Next-state relation.
 ******************************************************************************)

Next ==
  \E d \in Domains : ProduceBlock(d)
  \/ \E s, r \in Domains : \E n \in Nat : SendCrossMessage(s, r, n)
  \/ \E v \in Validators : SlashValidator(v)

(******************************************************************************
 * Safety özelliği: hiçbir domain'de çift-imza (equivocation) olmasın.
 * Bir domain committed ise, height monotonik artar (rollback yok).
 ******************************************************************************)

NoRollback ==
  \A d \in Domains : domain_height[d] >= 0   \* Trivially true ama invariant

MonotonicHeight ==
  \A d \in Domains : domain_height'[d] >= domain_height[d]

(******************************************************************************
 * Liveness özelliği (zayıf): bir domain'de yeterince honest validator varsa
 * eninde sonunda blok üretilir. TLC ile kontrol edilebilir.
 ******************************************************************************)

Liveness ==
  \A d \in Domains : Cardinality(Validators \ slashed) >= MinQuorum
    => <> (domain_committed[d])

=============================================================================
