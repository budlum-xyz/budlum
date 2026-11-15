use std::io::Write;
use std::process::Command;

fn run(text: &[u8]) -> std::process::Output {
    let path = std::env::temp_dir().join(format!(
        "budlum-intent-policy-{}-{:?}.route",
        std::process::id(),
        std::thread::current().id()
    ));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(text).unwrap();
    drop(file);
    let output = Command::new(env!("CARGO_BIN_EXE_budlum-intent-policy"))
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    output
}

const EXAMPLE: &str = include_str!("../examples/payment.route");

#[test]
fn example_is_policy_only_not_a_receipt() {
    let out = run(EXAMPLE.as_bytes());
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("POLICY_ONLY debit=102 credit=86"));
    assert!(text.contains("evidence not authenticated"));
}

#[test]
fn atomicity_is_not_promised_for_a_cross_domain_route() {
    let input = EXAMPLE.replace("conditional", "atomic");
    let out = run(input.as_bytes());
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("AtomicityUnavailable"));
}

#[test]
fn input_size_limit_is_enforced_on_the_read() {
    let out = run(&vec![b'#'; 32 * 1024 + 1]);
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().contains("32 KiB"));
}

#[test]
fn non_utf8_input_is_refused() {
    assert!(!run(&[0xff]).status.success());
}

#[test]
fn empty_and_duplicate_intents_are_refused() {
    assert!(!run(b"").status.success());
    let intent = EXAMPLE
        .lines()
        .find(|line| line.starts_with("intent "))
        .unwrap();
    assert!(!run(format!("{EXAMPLE}\n{intent}\n").as_bytes())
        .status
        .success());
}

#[test]
fn missing_file_is_a_nonzero_exit() {
    let out = Command::new(env!("CARGO_BIN_EXE_budlum-intent-policy"))
        .arg("nonexistent-budlum-route-file")
        .output()
        .unwrap();
    assert!(!out.status.success());
}
