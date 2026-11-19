use bud_proof::adapter::ProofEnvelope;

// Cargo writes dependency arrays in this canonical, multiline format. Reject
// unfamiliar formatting rather than silently missing a dependency edge.
fn check_postcard_has_no_heapless_dependency(lockfile: &str) -> Result<(), String> {
    let mut found = false;
    for package in lockfile.split("[[package]]").skip(1) {
        let lines: Vec<_> = package.lines().map(str::trim).collect();
        let Some(name) = lines
            .iter()
            .find(|line| line.starts_with("name"))
            .and_then(|line| line.strip_prefix("name = \""))
            .and_then(|line| line.strip_suffix('"'))
        else {
            return Err("non-canonical lockfile package name".to_string());
        };
        if name != "postcard" {
            continue;
        }
        found = true;
        let Some(dependencies) = lines
            .iter()
            .position(|line| line.starts_with("dependencies"))
        else {
            return Err("postcard dependency list is missing".to_string());
        };
        if lines.get(dependencies).copied() != Some("dependencies = [") {
            return Err("non-canonical postcard dependency list".to_string());
        }
        let mut closed = false;
        for line in lines.get(dependencies + 1..).unwrap_or(&[]) {
            if *line == "]" {
                closed = true;
                break;
            }
            let Some(entry) = line
                .strip_suffix(',')
                .unwrap_or(line)
                .strip_prefix('"')
                .and_then(|entry| entry.strip_suffix('"'))
            else {
                return Err("non-canonical postcard dependency entry".to_string());
            };
            let Some(dependency) = entry.split_whitespace().next() else {
                return Err("empty postcard dependency entry".to_string());
            };
            if dependency == "heapless" {
                return Err(
                    "postcard must not enable the unnecessary heapless dependency".to_string(),
                );
            }
        }
        if !closed {
            return Err("postcard dependency list is not closed".to_string());
        }
    }
    if !found {
        return Err("postcard was not found in the lockfile".to_string());
    }
    Ok(())
}

fn assert_postcard_has_no_heapless_dependency(lockfile: &str) {
    if let Err(reason) = check_postcard_has_no_heapless_dependency(lockfile) {
        panic!("{reason}");
    }
}

#[test]
fn root_lock_does_not_enable_postcard_heapless() {
    assert_postcard_has_no_heapless_dependency(include_str!("../../../Cargo.lock"));
}

#[test]
fn budzero_lock_does_not_enable_postcard_heapless() {
    assert_postcard_has_no_heapless_dependency(include_str!("../../Cargo.lock"));
}

#[test]
fn fuzz_lock_does_not_enable_postcard_heapless() {
    assert_postcard_has_no_heapless_dependency(include_str!("../../../fuzz/Cargo.lock"));
}

#[test]
fn guard_rejects_unversioned_heapless() {
    let err = check_postcard_has_no_heapless_dependency(
        "[[package]]\nname = \"postcard\"\ndependencies = [\n \"heapless\",\n]\n",
    )
    .unwrap_err();
    assert!(err.contains("postcard must not enable the unnecessary heapless dependency"));
}

#[test]
fn guard_rejects_version_qualified_heapless() {
    let err = check_postcard_has_no_heapless_dependency(
        "[[package]]\nname = \"postcard\"\ndependencies = [\n \"heapless 0.7.17\",\n]\n",
    )
    .unwrap_err();
    assert!(err.contains("postcard must not enable the unnecessary heapless dependency"));
}

#[test]
fn guard_rejects_unrecognized_dependency_format() {
    let err = check_postcard_has_no_heapless_dependency(
        "[[package]]\nname = \"postcard\"\ndependencies = [\"heapless\"]\n",
    )
    .unwrap_err();
    assert!(err.contains("non-canonical postcard dependency list"));
}

#[test]
fn guard_rejects_a_missing_postcard_package() {
    let err = check_postcard_has_no_heapless_dependency("[[package]]\nname = \"unrelated\"\n")
        .unwrap_err();
    assert!(err.contains("postcard was not found in the lockfile"));
}

#[test]
fn guard_ignores_heapless_in_an_unrelated_package() {
    assert_postcard_has_no_heapless_dependency(
        "[[package]]\nname = \"postcard\"\ndependencies = [\n \"serde\",\n]\n\
         [[package]]\nname = \"unrelated\"\ndependencies = [\n \"heapless\",\n]\n",
    );
}

#[test]
fn postcard_alloc_apis_preserve_the_proof_envelope_wire_format() -> Result<(), postcard::Error> {
    let envelope = ProofEnvelope {
        proof_format_version: 1,
        backend: "plonky3".to_owned(),
        p3_version: "0.8.0".to_owned(),
        fri_params_id: "FRI-1".to_owned(),
        public_inputs_hash: [0x5a; 32],
        proof_bytes: vec![0x00, 0xff, 0x80, 0x01, 0x7f],
        degree_bits: 12,
    };
    let expected: &[u8] = &[
        0x01, 0x07, 0x70, 0x6c, 0x6f, 0x6e, 0x6b, 0x79, 0x33, 0x05, 0x30, 0x2e, 0x38, 0x2e, 0x30,
        0x05, 0x46, 0x52, 0x49, 0x2d, 0x31, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x05, 0x00, 0xff, 0x80, 0x01, 0x7f, 0x0c,
    ];
    let encoded = postcard::to_allocvec(&envelope)?;
    assert_eq!(encoded, expected);
    let decoded: ProofEnvelope = postcard::from_bytes(expected)?;
    assert_eq!(decoded.proof_format_version, envelope.proof_format_version);
    assert_eq!(decoded.backend, envelope.backend);
    assert_eq!(decoded.p3_version, envelope.p3_version);
    assert_eq!(decoded.fri_params_id, envelope.fri_params_id);
    assert_eq!(decoded.public_inputs_hash, envelope.public_inputs_hash);
    assert_eq!(decoded.proof_bytes, envelope.proof_bytes);
    assert_eq!(decoded.degree_bits, envelope.degree_bits);
    let mut framed = encoded;
    framed.extend_from_slice(&[0xaa, 0xbb]);
    let (decoded_prefix, remainder): (ProofEnvelope, _) = postcard::take_from_bytes(&framed)?;
    assert_eq!(decoded_prefix.proof_bytes, envelope.proof_bytes);
    assert_eq!(remainder, &[0xaa, 0xbb]);
    Ok(())
}

#[test]
fn postcard_alloc_handles_varints_options_and_sequences() -> Result<(), postcard::Error> {
    let value = (150_u32, true, Some(300_u64), vec![0_u8, 255, 7], "bud");
    let expected: &[u8] = &[
        0x96, 0x01, 0x01, 0x01, 0xac, 0x02, 0x03, 0x00, 0xff, 0x07, 0x03, 0x62, 0x75, 0x64,
    ];
    assert_eq!(postcard::to_allocvec(&value)?, expected);
    let decoded: (u32, bool, Option<u64>, Vec<u8>, String) = postcard::from_bytes(expected)?;
    assert_eq!(
        decoded,
        (150, true, Some(300), vec![0, 255, 7], "bud".to_owned())
    );
    Ok(())
}
