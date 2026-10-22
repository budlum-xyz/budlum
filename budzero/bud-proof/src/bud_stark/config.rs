use core::marker::PhantomData;

use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

pub type Val<SC> = <<<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain as PolynomialSpace>::Val;

pub type Domain<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;

pub type PackedVal<SC> = <Val<SC> as Field>::Packing;

pub type PackedChallenge<SC> =
    <<SC as StarkGenericConfig>::Challenge as ExtensionField<Val<SC>>>::ExtensionPacking;

pub type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

pub type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

pub type ProverData<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::ProverData;

pub type PcsError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Error;

pub trait StarkGenericConfig: Clone {
    /// The [`Pcs`] implementation used to commit to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger>;
    /// The extension field used for challenges and auxiliary traces.
    type Challenge: ExtensionField<Val<Self>>;
    /// The challenger type used for Fiat-Shamir.
    type Challenger: FieldChallenger<Val<Self>> + CanObserve<Com<Self>> + CanSample<Self::Challenge>;

    fn pcs(&self) -> &Self::Pcs;
    fn initialise_challenger(&self) -> Self::Challenger;
    fn is_zk(&self) -> bool;

    /// The security parameters this instance was proved under, as field
    /// elements both sides absorb before sampling any challenge.
    ///
    /// The transcript already carries the degrees, the commitments and the
    /// public values. It does not carry the FRI parameters, and those are what
    /// decide how much the proof is worth: `num_queries` and `log_blowup` set
    /// the soundness error, and the proof-of-work bits set the grinding cost.
    /// Measured on the current configuration, `log_blowup = 3`,
    /// `num_queries = 100` and 16 grinding bits are roughly 316 bits of
    /// security; `num_queries = 1`, `log_blowup = 1` and no grinding is one
    /// bit, and produces a proof of the same shape.
    ///
    /// Least Authority's audit of Plonky3 found this exact class: a challenger
    /// that did not absorb the FRI config or the polynomial degree let a
    /// prover tamper with unabsorbed data. Our degrees were already absorbed;
    /// the FRI parameters were not.
    ///
    /// Nothing today can exploit it, because `build_config` is the only
    /// constructor and it hard-codes one parameter set, so prover and verifier
    /// cannot disagree. That is a property of having exactly one caller, not
    /// something the transcript enforces, and a second configuration is the
    /// kind of thing that gets added for a benchmark.
    ///
    /// Implementations must return the parameters that actually govern this
    /// instance. A constant unrelated to the configuration would satisfy the
    /// type and bind nothing.
    fn security_parameters(&self) -> Vec<Val<Self>>;
}

#[derive(Clone, Debug)]
pub struct StarkConfig<Pcs, Challenge, Challenger> {
    pcs: Pcs,
    challenger: Challenger,
    /// The FRI parameters, carried alongside the PCS so both sides of the
    /// protocol can absorb them. See
    /// [`StarkGenericConfig::security_parameters`].
    ///
    /// They are held as plain integers rather than read back out of the PCS
    /// because `Pcs` has no generic accessor for them, and adding one would
    /// mean changing an upstream trait rather than this crate.
    security: Vec<u64>,
    _phantom: PhantomData<Challenge>,
}

impl<Pcs, Challenge, Challenger> StarkConfig<Pcs, Challenge, Challenger> {
    /// Build a configuration whose security parameters are stated.
    ///
    /// `security` must be the parameters that actually govern this instance,
    /// in a fixed order. Passing anything else compiles and binds nothing,
    /// which is why `build_config` derives them from the same
    /// `FriParameters` value it hands to the PCS rather than writing them out
    /// a second time.
    pub fn new_with_security(pcs: Pcs, challenger: Challenger, security: Vec<u64>) -> Self {
        Self {
            pcs,
            challenger,
            security,
            _phantom: PhantomData,
        }
    }
}

impl<PcsT, Challenge, Challenger> StarkGenericConfig for StarkConfig<PcsT, Challenge, Challenger>
where
    PcsT: Pcs<Challenge, Challenger> + Clone,
    Challenge: ExtensionField<<PcsT::Domain as PolynomialSpace>::Val> + Clone,
    Challenger: FieldChallenger<<PcsT::Domain as PolynomialSpace>::Val>
        + CanObserve<PcsT::Commitment>
        + CanSample<Challenge>
        + Clone,
{
    type Pcs = PcsT;
    type Challenge = Challenge;
    type Challenger = Challenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }

    fn is_zk(&self) -> bool {
        Self::Pcs::ZK
    }

    /// Supplied by the concrete configuration through [`SecurityParameters`],
    /// because `Pcs` does not expose the FRI parameters generically.
    fn security_parameters(&self) -> Vec<Val<Self>> {
        self.security
            .iter()
            .map(|&x| <Val<Self>>::from_u64(x))
            .collect()
    }
}
