//! Release signing and verification.
//!
//! ```text
//! cargo run --release --manifest-path xtask/release/Cargo.toml -- <command>
//!
//!   keygen <seed-file> <public-key-file>
//!   sign-release <seed-file> <base-dir> <out-dir> <file>...
//!   verify-release <public-key-file> <manifest> <signature>
//!   --self-test
//! ```
//!
//! The signed object is the manifest: one line per release file, `<SHA3-256
//! hex>  <path>`, paths relative to the release directory, sorted, unique.
//! The signature is SLH-DSA-SHAKE-256s (FIPS 205) with the context string
//! `BDLM/RELEASE/V1`, so it cannot be moved to another kind of object. The
//! public key is pinned in the repository (`release/RELEASE_PUBKEY.hex`); the
//! seed stays offline.
//!
//! A pinned key of all zero bytes means the key ceremony has not happened:
//! verification refuses it rather than accept anything.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use sha3::{Digest, Sha3_256};
use slh_dsa::{Shake256s, Signature, SigningKey, VerifyingKey};

/// FIPS 205 context string of a release signature.
const CONTEXT: &[u8] = b"BDLM/RELEASE/V1";
/// `sk_seed || sk_prf || pk_seed`, three blocks of `n = 32`.
const SEED_LEN: usize = 96;
/// An SLH-DSA-SHAKE-256s public key.
const PUBLIC_KEY_LEN: usize = 64;
/// An SLH-DSA-SHAKE-256s signature.
const SIGNATURE_LEN: usize = 29_792;
/// Randomizer of the hedged signing mode.
const RANDOMIZER_LEN: usize = 32;

const MANIFEST_NAME: &str = "RELEASE.manifest";
const SIGNATURE_NAME: &str = "RELEASE.manifest.sig";

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return Err("hex string has an odd length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "hex string holds a non-hex character".to_string())
        })
        .collect()
}

fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut buffer = vec![0u8; len];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(buffer)
}

fn signing_key(seed: &[u8]) -> Result<SigningKey<Shake256s>, String> {
    if seed.len() != SEED_LEN {
        return Err(format!("seed must be {SEED_LEN} bytes, got {}", seed.len()));
    }
    let (sk_seed, rest) = seed.split_at(32);
    let (sk_prf, pk_seed) = rest.split_at(32);
    Ok(SigningKey::<Shake256s>::slh_keygen_internal(
        sk_seed, sk_prf, pk_seed,
    ))
}

fn public_key_of(key: &SigningKey<Shake256s>) -> Vec<u8> {
    let verifying: &VerifyingKey<Shake256s> = key.as_ref();
    verifying.to_vec()
}

/// A manifest path is relative, has no `..`, and fits on one line.
fn check_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\n') || path.contains('\r') {
        return Err(format!("unusable manifest path {path:?}"));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(format!("manifest path {path:?} must be relative and plain"));
    }
    Ok(())
}

fn sha3_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha3_256::digest(bytes))
}

/// The manifest text of `files` under `base`.
fn build_manifest(base: &Path, files: &[String]) -> Result<String, String> {
    let mut entries = Vec::new();
    for file in files {
        check_path(file)?;
        let bytes = fs::read(base.join(file)).map_err(|e| format!("cannot read {file}: {e}"))?;
        entries.push((file.clone(), sha3_hex(&bytes)));
    }
    entries.sort();
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("a file is listed twice".into());
    }
    if entries.is_empty() {
        return Err("a release needs at least one file".into());
    }
    let mut manifest = String::new();
    for (path, hash) in entries {
        manifest.push_str(&hash);
        manifest.push_str("  ");
        manifest.push_str(&path);
        manifest.push('\n');
    }
    Ok(manifest)
}

/// The `(hash, path)` pairs of a manifest, strictly checked.
fn parse_manifest(text: &str) -> Result<Vec<(String, String)>, String> {
    if !text.ends_with('\n') {
        return Err("manifest does not end with a newline".into());
    }
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let (hash, path) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed manifest line {line:?}"))?;
        let well_formed = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed {
            return Err(format!("manifest hash {hash:?} is not 64 lowercase hex"));
        }
        check_path(path)?;
        if entries
            .last()
            .is_some_and(|(_, last)| last.as_str() >= path)
        {
            return Err("manifest paths are not sorted and unique".into());
        }
        entries.push((hash.to_string(), path.to_string()));
    }
    if entries.is_empty() {
        return Err("manifest is empty".into());
    }
    Ok(entries)
}

fn sign_manifest(key: &SigningKey<Shake256s>, manifest: &str) -> Result<Vec<u8>, String> {
    let randomizer = random_bytes(RANDOMIZER_LEN)?;
    let signature = key
        .try_sign_with_context(manifest.as_bytes(), CONTEXT, Some(&randomizer))
        .map_err(|e| format!("signing failed: {e}"))?;
    Ok(signature.to_vec())
}

fn verify_manifest(public_key: &[u8], manifest: &str, signature: &[u8]) -> Result<(), String> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(format!(
            "public key must be {PUBLIC_KEY_LEN} bytes, got {}",
            public_key.len()
        ));
    }
    if public_key.iter().all(|&b| b == 0) {
        return Err("the pinned release key is unset: the key ceremony has not happened".into());
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(format!(
            "signature must be {SIGNATURE_LEN} bytes, got {}",
            signature.len()
        ));
    }
    let verifying = VerifyingKey::<Shake256s>::try_from(public_key)
        .map_err(|_| "public key does not decode".to_string())?;
    let signature = Signature::<Shake256s>::try_from(signature)
        .map_err(|_| "signature does not decode".to_string())?;
    verifying
        .try_verify_with_context(manifest.as_bytes(), CONTEXT, &signature)
        .map_err(|_| "release signature is invalid".to_string())
}

fn keygen(seed_file: &Path, public_key_file: &Path) -> Result<(), String> {
    let seed = random_bytes(SEED_LEN)?;
    let key = signing_key(&seed)?;
    fs::write(seed_file, format!("{}\n", hex_encode(&seed)))
        .map_err(|e| format!("cannot write the seed: {e}"))?;
    fs::set_permissions(seed_file, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot restrict the seed file: {e}"))?;
    fs::write(
        public_key_file,
        format!("{}\n", hex_encode(&public_key_of(&key))),
    )
    .map_err(|e| format!("cannot write the public key: {e}"))
}

fn sign_release(
    seed_file: &Path,
    base: &Path,
    out_dir: &Path,
    files: &[String],
) -> Result<(), String> {
    let seed = hex_decode(
        &fs::read_to_string(seed_file).map_err(|e| format!("cannot read the seed: {e}"))?,
    )?;
    let key = signing_key(&seed)?;
    let manifest = build_manifest(base, files)?;
    let signature = sign_manifest(&key, &manifest)?;
    // Verify what was just made before it leaves the machine.
    verify_manifest(&public_key_of(&key), &manifest, &signature)?;
    fs::create_dir_all(out_dir).map_err(|e| format!("cannot create the output: {e}"))?;
    fs::write(out_dir.join(MANIFEST_NAME), &manifest)
        .map_err(|e| format!("cannot write the manifest: {e}"))?;
    fs::write(
        out_dir.join(SIGNATURE_NAME),
        format!("{}\n", hex_encode(&signature)),
    )
    .map_err(|e| format!("cannot write the signature: {e}"))
}

fn verify_release(
    public_key_file: &Path,
    manifest_file: &Path,
    signature_file: &Path,
) -> Result<usize, String> {
    let public_key = hex_decode(
        &fs::read_to_string(public_key_file)
            .map_err(|e| format!("cannot read the public key: {e}"))?,
    )?;
    let manifest =
        fs::read_to_string(manifest_file).map_err(|e| format!("cannot read the manifest: {e}"))?;
    let signature = hex_decode(
        &fs::read_to_string(signature_file)
            .map_err(|e| format!("cannot read the signature: {e}"))?,
    )?;
    verify_manifest(&public_key, &manifest, &signature)?;
    let entries = parse_manifest(&manifest)?;
    let base: PathBuf = manifest_file
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    for (hash, path) in &entries {
        let bytes = fs::read(base.join(path)).map_err(|e| format!("cannot read {path}: {e}"))?;
        if sha3_hex(&bytes) != *hash {
            return Err(format!("{path} does not match the signed manifest"));
        }
    }
    Ok(entries.len())
}

fn self_test() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("budlum-release-selftest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let result = self_test_in(&dir);
    let _ = fs::remove_dir_all(&dir);
    result
}

fn expect_err<T>(what: &str, outcome: Result<T, String>) -> Result<(), String> {
    match outcome {
        Err(_) => Ok(()),
        Ok(_) => Err(format!("self-test: {what} was accepted")),
    }
}

fn self_test_in(dir: &Path) -> Result<(), String> {
    let seed = dir.join("seed.hex");
    let public = dir.join("public.hex");
    keygen(&seed, &public)?;
    fs::write(dir.join("a.bin"), b"artifact a").map_err(|e| e.to_string())?;
    fs::write(dir.join("b.bin"), b"artifact b").map_err(|e| e.to_string())?;
    let out = dir.join("out");
    sign_release(
        &seed,
        dir,
        &out,
        &["b.bin".to_string(), "a.bin".to_string()],
    )?;
    fs::copy(dir.join("a.bin"), out.join("a.bin")).map_err(|e| e.to_string())?;
    fs::copy(dir.join("b.bin"), out.join("b.bin")).map_err(|e| e.to_string())?;
    let manifest = out.join(MANIFEST_NAME);
    let signature = out.join(SIGNATURE_NAME);
    if verify_release(&public, &manifest, &signature)? != 2 {
        return Err("self-test: wrong file count".into());
    }

    // A changed artifact.
    fs::write(out.join("a.bin"), b"artifact A").map_err(|e| e.to_string())?;
    expect_err(
        "a modified artifact",
        verify_release(&public, &manifest, &signature),
    )?;
    fs::write(out.join("a.bin"), b"artifact a").map_err(|e| e.to_string())?;

    // A changed manifest: the first hash digit flips.
    let original = fs::read_to_string(&manifest).map_err(|e| e.to_string())?;
    let flipped = if original.starts_with('0') { "1" } else { "0" };
    fs::write(&manifest, format!("{flipped}{}", &original[1..])).map_err(|e| e.to_string())?;
    expect_err(
        "a modified manifest",
        verify_release(&public, &manifest, &signature),
    )?;
    fs::write(&manifest, &original).map_err(|e| e.to_string())?;

    // Another key.
    let other_seed = dir.join("other-seed.hex");
    let other_public = dir.join("other-public.hex");
    keygen(&other_seed, &other_public)?;
    expect_err(
        "a signature under another key",
        verify_release(&other_public, &manifest, &signature),
    )?;

    // The unset pinned key.
    let unset = dir.join("unset.hex");
    fs::write(&unset, format!("{}\n", hex_encode(&[0u8; PUBLIC_KEY_LEN])))
        .map_err(|e| e.to_string())?;
    expect_err(
        "the all-zero pinned key",
        verify_release(&unset, &manifest, &signature),
    )?;

    // Paths that would leave the release directory.
    for bad in ["../x", "/etc/passwd", "a/../b", ""] {
        expect_err("an unsafe path", check_path(bad))?;
    }
    // A manifest that is unsorted or malformed.
    let hash = "0".repeat(64);
    expect_err(
        "an unsorted manifest",
        parse_manifest(&format!("{hash}  b\n{hash}  a\n")),
    )?;
    expect_err(
        "an upper case hash",
        parse_manifest(&format!("{}  a\n", "A".repeat(64))),
    )?;
    expect_err(
        "a manifest without a final newline",
        parse_manifest(&format!("{hash}  a")),
    )?;
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let argument = |i: usize| -> Result<&String, String> {
        args.get(i).ok_or_else(|| "missing argument".to_string())
    };
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(Path::new(argument(1)?), Path::new(argument(2)?)),
        Some("sign-release") => sign_release(
            Path::new(argument(1)?),
            Path::new(argument(2)?),
            Path::new(argument(3)?),
            args.get(4..).unwrap_or_default(),
        ),
        Some("verify-release") => {
            let count = verify_release(
                Path::new(argument(1)?),
                Path::new(argument(2)?),
                Path::new(argument(3)?),
            )?;
            println!("release signature valid, {count} files match the manifest");
            Ok(())
        }
        Some("--self-test") => {
            self_test()?;
            println!("self-test passed");
            Ok(())
        }
        _ => Err(
            "usage: keygen <seed> <pub> | sign-release <seed> <base> <out> <file>... | verify-release <pub> <manifest> <sig> | --self-test"
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("budlum-release: {message}");
            ExitCode::FAILURE
        }
    }
}
