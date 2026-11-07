//! EVM migration dependency report (directive 8.12.2 item 8).
//!
//! Combines static EVM bytecode disassembly (`PUSH20` and 12-zero-prefixed
//! `PUSH32` address constants across all basic blocks up to the Solidity CBOR
//! metadata boundary `0xfe`) with traced runtime call targets.

/// `INVALID` (`0xfe`): separates runtime EVM code from trailing CBOR metadata.
const INVALID_METADATA_BOUNDARY: u8 = 0xfe;
/// `PUSH1`: first push opcode.
const PUSH1: u8 = 0x60;
/// `PUSH32`: last push opcode.
const PUSH32: u8 = 0x7f;

/// Dependency report of one contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyReport {
    /// Contract under inspection.
    pub contract: [u8; 20],
    /// Sorted unique 20-byte targets extracted statically from bytecode.
    pub static_targets: Vec<[u8; 20]>,
    /// Sorted unique 20-byte targets observed in execution traces.
    pub trace_targets: Vec<[u8; 20]>,
}

impl DependencyReport {
    /// Union of static and traced external contract dependencies, sorted and unique.
    ///
    /// exposed for: `bud-migrate` dependency planning and callers.
    #[must_use]
    pub fn required_migrations(&self) -> Vec<[u8; 20]> {
        let mut required = self.static_targets.clone();
        required.extend(self.trace_targets.iter().copied());
        required.sort_unstable();
        required.dedup();
        required
    }
}

fn normalised(targets: &[[u8; 20]], contract: &[u8; 20]) -> Vec<[u8; 20]> {
    let mut out: Vec<[u8; 20]> = targets
        .iter()
        .copied()
        .filter(|address| address != contract && *address != [0u8; 20])
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn static_targets(code: &[u8]) -> Vec<[u8; 20]> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while let Some(&opcode) = code.get(index) {
        if opcode == INVALID_METADATA_BOUNDARY {
            break;
        }
        if (PUSH1..=PUSH32).contains(&opcode) {
            let width = usize::from(opcode - PUSH1) + 1;
            let start = index + 1;
            let Some(end) = start.checked_add(width) else {
                break;
            };
            let Some(operand) = code.get(start..end) else {
                break;
            };
            if width == 20 {
                if let Ok(address) = <[u8; 20]>::try_from(operand) {
                    out.push(address);
                }
            } else if width == 32
                && operand.get(..12).is_some_and(|hi| hi.iter().all(|b| *b == 0))
            {
                if let Some(lo) = operand.get(12..32) {
                    if let Ok(address) = <[u8; 20]>::try_from(lo) {
                        out.push(address);
                    }
                }
            }
            index = end;
        } else {
            index += 1;
        }
    }
    out
}

/// Builds the dependency report of `contract` from its EVM `code` and optional `trace`.
#[must_use]
pub fn dependency_report(
    contract: [u8; 20],
    code: &[u8],
    trace: &[[u8; 20]],
) -> DependencyReport {
    DependencyReport {
        contract,
        static_targets: normalised(&static_targets(code), &contract),
        trace_targets: normalised(trace, &contract),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STOP: u8 = 0x00;
    const PUSH20: u8 = 0x73;

    fn push20(address: &[u8; 20]) -> Vec<u8> {
        let mut out = vec![PUSH20];
        out.extend_from_slice(address);
        out.push(0xf1);
        out
    }

    fn push32(address: &[u8; 20]) -> Vec<u8> {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(address);
        let mut out = vec![PUSH32];
        out.extend_from_slice(&word);
        out
    }

    #[test]
    fn migration_dependency_report_lists_static_and_trace_targets() {
        let contract = [0x11u8; 20];
        let first = [0xaau8; 20];
        let second = [0xbbu8; 20];
        let third_after_stop = [0xddu8; 20];
        let traced = [0xccu8; 20];

        let mut code = push20(&first);
        code.push(STOP);
        code.push(0x5b); // JUMPDEST in second Solidity function branch
        code.extend_from_slice(&push32(&second));
        code.extend_from_slice(&push20(&third_after_stop));
        code.extend_from_slice(&push20(&contract));
        code.push(INVALID_METADATA_BOUNDARY);
        code.extend_from_slice(&push20(&[0xeeu8; 20])); // ignored CBOR metadata tail

        let report = dependency_report(contract, &code, &[traced, first, [0u8; 20]]);
        assert_eq!(report.static_targets, vec![first, second, third_after_stop]);
        assert_eq!(report.trace_targets, vec![first, traced]);
        assert_eq!(
            report.required_migrations(),
            vec![first, second, traced, third_after_stop]
        );
    }

    #[test]
    fn migration_dependency_report_skips_push_data_and_the_zero_address() {
        let mut code = vec![PUSH32];
        let mut word = [0x73u8; 32];
        word[31] = 0x01;
        code.extend_from_slice(&word);
        code.extend_from_slice(&push20(&[0u8; 20]));

        let report = dependency_report([0x11u8; 20], &code, &[]);
        assert!(report.static_targets.is_empty());
        assert!(report.required_migrations().is_empty());

        let mut truncated = vec![PUSH20];
        truncated.extend_from_slice(&[0x33u8; 10]);
        let report = dependency_report([0x11u8; 20], &truncated, &[]);
        assert!(report.static_targets.is_empty());
    }
}
