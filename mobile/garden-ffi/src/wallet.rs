//! The phone's own Budlum wallet.
//!
//! No cryptography is written here. Every call lands in
//! `budlum_core::wallet`, the module the desktop tools already use, so a
//! wallet made on a phone and a wallet made on a workstation are the same
//! wallet: twenty-four BIP39 words, an ML-DSA-87 key derived through
//! `BUDLUM_MLDSA87_SEED_V1`, a V3 account at `(0, 0)` and an Address V3.
//!
//! The sealed file is the core's own `KeyFile`: PBKDF2-HMAC-SHA256 over the
//! password at the core's default iteration count, then XChaCha20-Poly1305
//! over the entropy. The address is kept in the clear inside it, which is
//! what lets a screen show who this phone is without asking for the
//! password first.
//!
//! One phone holds one wallet. There is no account list and no second
//! wallet to add: the file either exists or it does not.

use std::path::{Path, PathBuf};

use budlum_core::wallet::{self, KeyFile};

/// The sealed wallet, inside the directory the app owns.
const FILE: &str = "wallet.json";

/// The shortest password this phone will seal a wallet under.
const MIN_PASSWORD: usize = 8;

/// Where the sealed wallet lives.
#[must_use]
pub fn file_path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// Whether this phone already holds a wallet.
#[must_use]
pub fn exists(dir: &Path) -> bool {
    file_path(dir).is_file()
}

fn read_file(dir: &Path) -> Result<KeyFile, String> {
    let raw = std::fs::read_to_string(file_path(dir))
        .map_err(|e| format!("this phone holds no wallet yet: {e}"))?;
    serde_json::from_str::<KeyFile>(&raw)
        .map_err(|e| format!("the wallet file on this phone cannot be read: {e}"))
}

fn write_file(dir: &Path, file: &KeyFile) -> Result<(), String> {
    let raw = serde_json::to_string(file)
        .map_err(|e| format!("the wallet could not be written out: {e}"))?;
    std::fs::write(file_path(dir), raw).map_err(|e| format!("the wallet could not be saved: {e}"))
}

fn check_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(format!(
            "the password needs at least {MIN_PASSWORD} characters"
        ));
    }
    Ok(())
}

/// The address the sealed wallet names, read without the password.
///
/// # Errors
///
/// No wallet on this phone, or a file that is not a wallet.
pub fn address(dir: &Path) -> Result<String, String> {
    read_file(dir).map(|f| f.address)
}

/// Make this phone's wallet and seal it under `password`.
///
/// Returns the twenty-four words and the address. The words are returned
/// once and never stored in the clear; whoever asked for them has to write
/// them down.
///
/// # Errors
///
/// A wallet already on this phone, a password under the floor, a key the
/// core cannot derive, or a directory it cannot write.
pub fn create(dir: &Path, password: &str) -> Result<(String, String), String> {
    if exists(dir) {
        return Err("this phone already holds a wallet".to_owned());
    }
    check_password(password)?;
    let entropy = wallet::generate_entropy();
    let words = wallet::mnemonic_from_entropy(&entropy);
    let sealed = KeyFile::seal(&entropy, password, wallet::DEFAULT_KDF_ITERATIONS)
        .map_err(|e| e.to_string())?;
    let address = sealed.address.clone();
    write_file(dir, &sealed)?;
    Ok((words, address))
}

/// Put back the wallet of `mnemonic` and seal it under `password`.
///
/// The checksum is checked by the core, so a wrong or reordered word is
/// refused here rather than becoming a wallet nobody owns.
///
/// # Errors
///
/// A phrase that is not twenty-four known words with a matching checksum,
/// a password under the floor, or a directory it cannot write.
pub fn restore(dir: &Path, mnemonic: &str, password: &str) -> Result<String, String> {
    check_password(password)?;
    let entropy = wallet::entropy_from_mnemonic(mnemonic).map_err(|e| e.to_string())?;
    let sealed = KeyFile::seal(&entropy, password, wallet::DEFAULT_KDF_ITERATIONS)
        .map_err(|e| e.to_string())?;
    let address = sealed.address.clone();
    write_file(dir, &sealed)?;
    Ok(address)
}

/// Prove `password` opens this phone's wallet, and say which address it is.
///
/// The entropy is dropped as soon as the check is done; this call is the
/// unlock screen, not a way to hand a key to the app.
///
/// # Errors
///
/// No wallet, a wrong password, or a file whose key does not derive the
/// address it names.
pub fn open(dir: &Path, password: &str) -> Result<String, String> {
    let file = read_file(dir)?;
    file.open(password).map_err(|e| e.to_string())?;
    Ok(file.address)
}

/// How many words a mnemonic has here. Twenty-four, and the screens that
/// lay out the grid read it from the core rather than hard-coding it.
#[must_use]
pub fn word_count() -> u32 {
    u32::try_from(wallet::MNEMONIC_WORDS).unwrap_or(24)
}
