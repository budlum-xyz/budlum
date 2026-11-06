//! The migration kit's dependency report (directive 8.12.2 item 8).
//!
//! The kit lists the external contracts a contract calls, so an operator knows
//! which dependencies must migrate too: a migrated contract that calls one left
//! behind is the failure this prevents.
//!
//! The EVM has no static call graph, so the pass reads the two patterns that are
//! address literals and nothing else: `PUSH20 <address>` (`0x73`), and `PUSH32
//! <word>` whose first twelve bytes are zero, which is how Solidity stores an
//! `address` constant. The walk skips each `PUSH` operand, as the EVM
//! does, and stops at `STOP` (`0x00`). A target computed at run time is not a
//! literal, so the report also takes a trace list; the union of the two is the
//! report.

/// `STOP`: the EVM halts here.
const STOP: u8 = 0x00;
/// `PUSH1`: the first push opcode.
const PUSH1: u8 = 0x60;
/// `PUSH32`: the last push opcode.
const PUSH32: u8 = 0x7f;

/// The dependency report of one contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyReport {
    /// The contract the report is for.
    pub contract: [u8; 20],
    /// Target addresses the bytecode names as literals, sorted and unique.
    pub static_targets: Vec<[u8; 20]>,
    /// Target addresses the call trace names, sorted and unique.
    pub trace_targets: Vec<[u8; 20]>,
}

impl DependencyReport {
    /// Every dependency either pass found, sorted and unique. These are the
    /// contracts that have to migrate for this one to keep working.
    #[must_use]
    pub fn required_migrations(&self) -> Vec<[u8; 20]> {
        let mut required = self.static_targets.clone();
        required.extend(self.trace_targets.iter().copied());
        required.sort_unstable();
        required.dedup();
        required
    }
}

/// Sorts and de-duplicates a target list, dropping the zero address and the
/// contract itself.
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

/// Reads the address literals out of contract bytecode.
fn static_targets(code: &[u8]) -> Vec<[u8; 20]> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < code.len() {
        let opcode = code[index];
        if opcode == STOP {
            break;
        }
        if (PUSH1..=PUSH32).contains(&opcode) {
            let width = usize::from(opcode - PUSH1) + 1;
            let start = index + 1;
            let end = start.saturating_add(width);
            if end > code.len() {
                break;
            }
            let operand = &code[start..end];
            if width == 20 {
                let mut address = [0u8; 20];
                address.copy_from_slice(operand);
                out.push(address);
            } else if width == 32 && operand[..12].iter().all(|byte| *byte == 0) {
                let mut address = [0u8; 20];
                address.copy_from_slice(&operand[12..]);
                out.push(address);
            }
            index = end;
        } else {
            index += 1;
        }
    }
    out
}

/// Builds the dependency report of one contract from its bytecode and a trace.
///
/// `trace` is the list of targets a traced run called, which is how a target
/// computed at run time is found. Pass an empty slice when no trace was taken.
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

    /// `PUSH20 <address>` followed by `CALL`.
    fn push20(address: &[u8; 20]) -> Vec<u8> {
        let mut out = vec![PUSH20];
        out.extend_from_slice(address);
        out.push(0xf1);
        out
    }

    /// `PUSH32 <word>`, the address in the low twenty bytes of the word.
    fn push32(address: &[u8; 20]) -> Vec<u8> {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(address);
        let mut out = vec![PUSH32];
        out.extend_from_slice(&word);
        out
    }

    /// The `PUSH20` opcode, named for the fixtures.
    const PUSH20: u8 = 0x73;

    #[test]
    fn migration_dependency_report_lists_static_and_trace_targets() {
        let contract = [0x11u8; 20];
        let first = [0xaau8; 20];
        let second = [0xbbu8; 20];
        let traced = [0xccu8; 20];

        let mut code = push20(&first);
        code.extend_from_slice(&push32(&second));
        code.extend_from_slice(&push20(&contract));
        code.push(STOP);

        let report = dependency_report(contract, &code, &[traced, first, [0u8; 20]]);
        assert_eq!(report.static_targets, vec![first, second]);
        assert_eq!(report.trace_targets, vec![first, traced]);
        assert_eq!(report.required_migrations(), vec![first, second, traced]);
    }

    #[test]
    fn migration_dependency_report_skips_push_data_and_the_zero_address() {
        // A PUSH32 word that is not an address is not one, a byte that looks like
        // PUSH20 inside push data is not an opcode, and the zero address is not a
        // dependency.
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
