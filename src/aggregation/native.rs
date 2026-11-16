//! The native backend: the proof of a frame is the list of its objects, and
//! checking it means verifying every object again.
//!
//! It proves nothing succinctly and saves no bytes. It exists so the claim
//! layer, the pool, the block rules and the fees can run and be tested before
//! the STARK backend does, and so the STARK backend has a reference to be
//! compared with. It is compiled for tests and for devnet builds only: a
//! production build has no native backend.
//!
//! WIRING: a devnet node built with `agg-native-backend` hands a
//! [`NativeBackend`] to its aggregator and to block validation. The gate
//! `agg-native-backend-is-devnet-only` keeps every such use behind the
//! feature.

use super::backend::{AggBackend, AggError, TickCtx};
use super::envelope::Envelope;
use super::frame::{ClaimFrame, FrameLimits};
use super::object::derive_claim;
use super::pool::PoolItem;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::DomainId;

/// First bytes of a native proof.
const MAGIC: [u8; 4] = *b"NATV";

/// The backend that carries the objects as the proof.
#[derive(Debug, Clone)]
pub struct NativeBackend {
    registry: SchemeStatusRegistry,
    limits: FrameLimits,
    parameter_set: u32,
}

impl NativeBackend {
    /// A native backend under the scheme statuses of a chain. `limits` bound
    /// the frames it accepts. Two backends with different `parameter_set`
    /// values refuse each other's proofs.
    #[must_use]
    pub const fn new(
        registry: SchemeStatusRegistry,
        limits: FrameLimits,
        parameter_set: u32,
    ) -> Self {
        Self {
            registry,
            limits,
            parameter_set,
        }
    }

    fn encode_proof(&self, objects: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.parameter_set.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(objects.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for object in objects {
            out.extend_from_slice(
                &u32::try_from(object.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            out.extend_from_slice(object);
        }
        out
    }

    /// The encoded envelopes of a native proof, in claim order.
    fn decode_proof<'a>(&self, proof: &'a [u8]) -> Result<Vec<&'a [u8]>, AggError> {
        let (magic, rest) = proof
            .split_first_chunk::<4>()
            .ok_or(AggError::MalformedProof)?;
        if *magic != MAGIC {
            return Err(AggError::MalformedProof);
        }
        let (set, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(AggError::MalformedProof)?;
        if u32::from_be_bytes(*set) != self.parameter_set {
            return Err(AggError::WrongParameterSet);
        }
        let (count, mut rest) = rest
            .split_first_chunk::<4>()
            .ok_or(AggError::MalformedProof)?;
        let count = usize::try_from(u32::from_be_bytes(*count)).unwrap_or(usize::MAX);
        if count > self.limits.max_claims {
            return Err(AggError::MalformedProof);
        }
        // Every object carries a four-byte length: capacity follows the bytes.
        let mut objects = Vec::with_capacity(count.min(rest.len() / 4));
        for _ in 0..count {
            let (len, tail) = rest
                .split_first_chunk::<4>()
                .ok_or(AggError::MalformedProof)?;
            let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
            let (object, tail) = tail.split_at_checked(len).ok_or(AggError::MalformedProof)?;
            objects.push(object);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(AggError::MalformedProof);
        }
        Ok(objects)
    }
}

impl AggBackend for NativeBackend {
    fn prove_tick(&self, ctx: &TickCtx, items: &[PoolItem]) -> Result<ClaimFrame, AggError> {
        let mut keyed = Vec::with_capacity(items.len());
        for item in items {
            if item.envelope.domain != ctx.domain {
                return Err(AggError::WrongDomain);
            }
            if item.envelope.payload.is_empty() {
                return Err(AggError::PayloadPruned);
            }
            keyed.push((item.claim.digest(ctx.domain), item));
        }
        // The frame sorts its claims by digest; the objects follow the same order.
        keyed.sort_unstable_by_key(|(digest, _)| *digest);
        let objects: Vec<Vec<u8>> = keyed
            .iter()
            .map(|(_, item)| item.envelope.encode())
            .collect();
        let claims = keyed.iter().map(|(_, item)| item.claim.clone()).collect();
        let frame = ClaimFrame::tick(
            ctx.domain,
            ctx.aggregator,
            claims,
            self.encode_proof(&objects),
        )?;
        Ok(frame)
    }

    fn prove_merge(&self, left: &ClaimFrame, right: &ClaimFrame) -> Result<Vec<u8>, AggError> {
        let mut objects: Vec<Vec<u8>> = Vec::new();
        for proof in [&left.proof, &right.proof] {
            objects.extend(self.decode_proof(proof)?.into_iter().map(<[u8]>::to_vec));
        }
        Ok(self.encode_proof(&objects))
    }

    fn verify(&self, frame: &ClaimFrame, domain: DomainId) -> Result<(), AggError> {
        frame.check_structure(domain, &self.limits)?;
        let objects = self.decode_proof(&frame.proof)?;
        if objects.len() != frame.claims.len() {
            return Err(AggError::ProofMismatch);
        }
        for (object, claim) in objects.iter().zip(&frame.claims) {
            // The payload limit is the proof limit: the object sits inside the proof.
            let envelope = Envelope::decode(object, self.limits.max_proof_bytes)
                .map_err(|_| AggError::MalformedProof)?;
            if envelope.domain != domain {
                return Err(AggError::WrongDomain);
            }
            if derive_claim(&self.registry, &envelope)? != *claim {
                return Err(AggError::ProofMismatch);
            }
        }
        Ok(())
    }
}
