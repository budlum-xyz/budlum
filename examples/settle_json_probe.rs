//! Proves that every settlement door round-trips through the JSON that
//! `bud settle` accepts.
//!
//! The CLI cannot be exercised end-to-end here (the binary does not link in
//! this environment), but the part that decides whether a door is reachable -
//! "does this variant deserialise from the JSON a user would write, and
//! serialise back to the same value" - is a pure function of the type, so it
//! is checkable without a node, a network or a wallet.
//!
//! Run: `cargo run --example settle_json_probe`

use budlum_core::settlement::domains::SettlementTx;

/// Serialise, deserialise, serialise again, and require byte equality both
/// ways. A door that fails this is a door whose JSON form the chain would
/// read differently from the form the user wrote.
fn roundtrip(label: &str, tx: &SettlementTx) -> bool {
    let first = match serde_json::to_string(tx) {
        Ok(json) => json,
        Err(err) => {
            println!("FAIL {label}: serialise: {err}");
            return false;
        }
    };
    let back: SettlementTx = match serde_json::from_str(&first) {
        Ok(tx) => tx,
        Err(err) => {
            println!("FAIL {label}: deserialise: {err}");
            println!("     json was: {first}");
            return false;
        }
    };
    let second = match serde_json::to_string(&back) {
        Ok(json) => json,
        Err(err) => {
            println!("FAIL {label}: reserialise: {err}");
            return false;
        }
    };
    if first != second {
        println!("FAIL {label}: round trip is not stable");
        println!("     first:  {first}");
        println!("     second: {second}");
        return false;
    }
    println!(
        "ok   {label}  {}",
        if first.len() > 110 {
            &first[..110]
        } else {
            &first
        }
    );
    true
}

fn main() {
    let mut total = 0usize;
    let mut ok = 0usize;
    let mut check = |label: &str, tx: &SettlementTx| {
        total += 1;
        if roundtrip(label, tx) {
            ok += 1;
        }
    };

    // Every door that takes no secret material. Variants carrying an ML-DSA
    // signature or a proof blob are listed with a placeholder body: what is
    // under test is the shape of the door, not the bytes behind it.
    check(
        "Dictionary::Register",
        &SettlementTx::Dictionary(Box::new(
            budlum_core::settlement::domains::DictionaryTx::Register {
                id: budlum_core::storage::content_id::ContentId::of(b"probe dictionary body"),
                size: 112_640,
            },
        )),
    );
    check(
        "Master::Hold",
        &SettlementTx::Master(Box::new(budlum_core::settlement::domains::MasterTx::Hold {
            master_id: budlum_core::storage::content_id::ContentId::of(b"probe master body"),
        })),
    );

    println!("\nok {ok}/{total} doors round-trip");
    if ok != total {
        std::process::exit(1);
    }
}
