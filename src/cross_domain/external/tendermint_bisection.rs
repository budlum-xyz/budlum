//! WIRING: wired - multi-step ICS-07 bisection header-skip verifier, consumed
//! in production by `IntakeState::rotate_tendermint_anchor_bisection`
//! (non-adjacent Tendermint anchor rotation door) and by the CLI/IBC relayer
//! bisection submission paths.

use super::{
    rule, TendermintCommitEvidence, TendermintLightClient, VerifiedTendermintSkip,
    MAX_BISECTION_STEPS,
};
use crate::cross_domain::external::spec::AdapterError;

impl TendermintLightClient {
    /// Atomically verify and apply a multi-step bisection chain `steps` against
    /// this light client, leaving client state unchanged if any step fails.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if the client is frozen, `steps` is empty or
    /// exceeds [`MAX_BISECTION_STEPS`], or any step fails verification.
    ///
    /// Convenience: kept for the CLI and IBC relayer bisection submission.
    pub fn verify_bisection(
        &mut self,
        steps: &[TendermintCommitEvidence],
        now_secs: u64,
    ) -> Result<VerifiedTendermintSkip, AdapterError> {
        if self.is_frozen() {
            return Err(rule("Tendermint light client is permanently frozen"));
        }
        if steps.is_empty() || steps.len() > MAX_BISECTION_STEPS {
            return Err(rule(format!(
                "bisection step count {} outside 1..={MAX_BISECTION_STEPS}",
                steps.len()
            )));
        }
        let mut staged = self.clone();
        let mut last_skip: Option<VerifiedTendermintSkip> = None;
        for step in steps {
            last_skip = Some(staged.update(step, now_secs)?);
        }
        let final_skip = last_skip.ok_or_else(|| rule("bisection produced no step"))?;
        *self = staged;
        Ok(final_skip)
    }
}
