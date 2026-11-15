//! Inspect a route file. Success means policy consistency, never settlement.
#![forbid(unsafe_code)]
use budlum_intent_policy::{
    assess_route, AssetLocation, DomainView, LegKind, PaymentIntent, RouteLeg,
    SettlementRequirement, MAX_DOMAIN_VIEWS, MAX_ROUTE_LEGS,
};
use std::path::Path;

const MAX_FILE_BYTES: u64 = 32 * 1024;

fn hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.is_ascii() {
        return Err("identity must contain exactly 64 ASCII hex digits".into());
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "identity contains a non-hex digit")?;
    }
    Ok(result)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected an unsigned decimal integer".into());
    }
    text.parse().map_err(|_| "integer out of range".into())
}

fn flag(text: &str) -> Result<bool, String> {
    match text {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("capability flag must be 0 or 1".into()),
    }
}

fn asset(domain: &str, local: &str) -> Result<AssetLocation, String> {
    Ok(AssetLocation {
        domain: hash(domain)?,
        asset: hash(local)?,
    })
}

fn evaluate(text: &str) -> Result<String, String> {
    let mut height = None;
    let mut intent = None;
    let mut views = Vec::new();
    let mut legs = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() || fields[0].starts_with('#') {
            continue;
        }
        let parsed = (|| -> Result<(), String> {
            match fields.as_slice() {
                ["height", value] if height.is_none() => height = Some(number::<u64>(value)?),
                ["domain", key, snapshot, active, swap, transfer, atomic, escrow]
                    if views.len() < MAX_DOMAIN_VIEWS =>
                {
                    views.push(DomainView {
                        domain: hash(key)?,
                        snapshot_height: number(snapshot)?,
                        active: flag(active)?,
                        can_swap: flag(swap)?,
                        can_transfer: flag(transfer)?,
                        local_atomic: flag(atomic)?,
                        conditional_escrow: flag(escrow)?,
                    })
                }
                ["intent", sd, sa, td, ta, debit, credit, expiry, mode] if intent.is_none() => {
                    let settlement = match *mode {
                        "atomic" => SettlementRequirement::LocalAtomic,
                        "conditional" => SettlementRequirement::Conditional,
                        _ => return Err("mode must be atomic or conditional".into()),
                    };
                    intent = Some(PaymentIntent {
                        source: asset(sd, sa)?,
                        destination: asset(td, ta)?,
                        max_debit: number(debit)?,
                        min_credit: number(credit)?,
                        valid_until: number(expiry)?,
                        settlement,
                    });
                }
                ["leg", kind, sd, sa, td, ta, input, output, fee]
                    if legs.len() < MAX_ROUTE_LEGS =>
                {
                    let kind = match *kind {
                        "swap" => LegKind::Swap,
                        "transfer" => LegKind::Transfer,
                        _ => return Err("leg must be swap or transfer".into()),
                    };
                    legs.push(RouteLeg {
                        source: asset(sd, sa)?,
                        destination: asset(td, ta)?,
                        amount_in: number(input)?,
                        amount_out: number(output)?,
                        fee_in: number(fee)?,
                        kind,
                    });
                }
                _ => return Err("unknown/duplicate record, field count or record limit".into()),
            }
            Ok(())
        })();
        parsed.map_err(|reason| format!("line {}: {reason}", index + 1))?;
    }
    let assessment = assess_route(
        &intent.ok_or("missing intent")?,
        &legs,
        &views,
        height.ok_or("missing height")?,
    )
    .map_err(|reason| format!("route refused: {reason:?}"))?;
    Ok(format!(
        "POLICY_ONLY debit={} credit={} legs={} snapshot={}; no funds moved; evidence not authenticated",
        assessment.debit, assessment.credit, assessment.legs, assessment.snapshot_height,
    ))
}

fn run() -> Result<String, String> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("usage: budlum-intent-policy ROUTE_FILE")?;
    if args.next().is_some() {
        return Err("expected one route file".into());
    }
    let file = std::fs::File::open(Path::new(&path)).map_err(|_| "cannot open route file")?;
    use std::io::Read;
    let mut text = String::new();
    // Bound the read itself, not only metadata: a growing file or a pipe
    // must not turn the route checker into an unbounded allocation.
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| "cannot read UTF-8 route file")?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err("route file exceeds 32 KiB".into());
    }
    evaluate(&text)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(summary) => {
            println!("{summary}");
            std::process::ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("{reason}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_duplicate_records_are_rejected() {
        assert!(evaluate("height 10\nheight 11\n")
            .unwrap_err()
            .contains("line 2"));
        assert!(evaluate("height -1").is_err());
        assert!(evaluate("unknown 10").is_err());
        assert!(evaluate("").is_err());
    }

    #[test]
    fn identity_and_flag_parsers_are_strict() {
        assert_eq!(hash(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(hash(&"é".repeat(32)).is_err());
        assert!(hash(&"zz".repeat(32)).is_err());
        assert!(flag("true").is_err());
        assert!(number::<u128>("+1").is_err());
    }
}
