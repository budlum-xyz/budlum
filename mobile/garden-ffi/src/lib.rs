//! The Garden a phone runs, as the app calls it.
//!
//! Section 9.1 of the optimisation directive says the APK carries the same
//! core the testnet node carries, and that no separate Garden node, demo or
//! simulation is written for it. So this crate holds no Garden logic at
//! all: every call below hands straight over to `budlum_core::garden`,
//! which is the code the Linux validators run. What it does add is the two
//! things a phone needs and a server does not: somewhere to run async code
//! from a synchronous Kotlin call, and the self test of section 4.
//!
//! `GardenService::new` takes the Budlum chain handle as an `Option`. A
//! Garden is a sovereign PoA domain with no bridge, so the phone passes
//! `None` and still runs a complete validator: it proposes, it votes, it
//! holds parts and it executes blocks. The chain handle only adds the
//! domain registry and the finality adapter, neither of which a Garden
//! needs in order to be a Garden. That is what lets the phone be a full
//! validator (sections 1.2 and 6.1) rather than a viewer.
//!
//! Section 2.8 keeps message, post and trace queries out of the app, so
//! they are not exported here even though the core has them.

use std::path::PathBuf;
use std::sync::Arc;

use budlum_core::garden::{GardenOptions, GardenService};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// What the screens get back: the JSON the Garden RPC already answers
/// with, as text.
///
/// The shapes are the ones `bud_garden*` returns, so the app and a Linux
/// operator read the same fields and nothing is redefined on the phone.
#[derive(uniffi::Record)]
pub struct GardenAnswer {
    /// The JSON body, verbatim from the core.
    pub json: String,
}

/// One check of the first run self test.
#[derive(uniffi::Record)]
pub struct SelfTestStep {
    /// What was tried, in words a person can read.
    pub name: String,
    /// Whether it worked.
    pub passed: bool,
    /// What went wrong, when something did.
    pub detail: String,
}

/// The whole self test of section 4.
#[derive(uniffi::Record)]
pub struct SelfTestReport {
    /// Every step, in the order they ran.
    pub steps: Vec<SelfTestStep>,
    /// True only when every step passed.
    pub passed: bool,
    /// How long the whole thing took.
    pub elapsed_ms: u64,
}

/// What a Garden call can refuse with.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GardenError {
    /// The core refused, and this is what it said.
    #[error("{reason}")]
    Refused {
        /// The refusal, passed through unchanged.
        reason: String,
    },
}

impl GardenError {
    fn of(reason: impl Into<String>) -> Self {
        Self::Refused {
            reason: reason.into(),
        }
    }
}

/// The phone's Garden validator.
#[derive(uniffi::Object)]
pub struct GardenPhone {
    runtime: Runtime,
    service: GardenService,
    data_dir: PathBuf,
}

#[uniffi::export]
impl GardenPhone {
    /// Open the validator against a directory the app owns.
    ///
    /// Nothing is asked of the person: section 4 puts the identity and the
    /// seed in the hands of the APK, and the core makes its own validator
    /// key when a Garden is created or joined.
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Result<Arc<Self>, GardenError> {
        let dir = PathBuf::from(&data_dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| GardenError::of(format!("the app directory is not writable: {e}")))?;
        // A phone has few cores and a battery. The core's own round timing
        // does the pacing, so the runtime only has to not fight it.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| GardenError::of(format!("no async runtime: {e}")))?;
        let service = GardenService::new(None, Some(dir.clone()));
        Ok(Arc::new(Self {
            runtime,
            service,
            data_dir: dir,
        }))
    }

    /// Start a Garden and become its host.
    pub fn create(&self, title: String, name: String) -> Result<GardenAnswer, GardenError> {
        let options = Self::options();
        answer(
            self.runtime
                .block_on(self.service.create(title, name, options)),
        )
    }

    /// The invite record to hand out, with its QR content.
    ///
    /// This is the Invite screen of section 2.5: the link, the QR and
    /// something to share.
    pub fn invite(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.invite()))
    }

    /// Read an invite record without acting on it, so the Join screen can
    /// show who is inviting and until when before anybody taps yes.
    pub fn read_record(&self, record: String) -> Result<GardenAnswer, GardenError> {
        answer(GardenService::read_record(&record))
    }

    /// Join the Garden an invite record names.
    pub fn join(&self, record: String, name: String) -> Result<GardenAnswer, GardenError> {
        let options = Self::options();
        answer(
            self.runtime
                .block_on(self.service.join(record, name, options)),
        )
    }

    /// Return to the Garden this phone already belongs to.
    ///
    /// An app is closed and opened again, a phone is carried out of range
    /// and back. The seat is kept in either case, so the Status screen
    /// calls this on the way up rather than asking for the invite a
    /// second time. The core keeps the key and the Garden on disk; this
    /// only puts the validator back on the network.
    pub fn rejoin(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.rejoin()))
    }

    /// The Garden as this phone sees it: its status and its validators.
    pub fn status(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.status()))
    }

    /// Leave, and wipe the Garden from this phone.
    pub fn leave(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.leave()))
    }

    /// The section 4 self test, run before a Garden is created or joined.
    ///
    /// It tries the four things the phone has to be able to do, and it
    /// tries them for real: a file is written and read back, a key is made
    /// and used to sign, a socket is bound, and an object goes down the
    /// B.U.D. 3.0 path and comes back. None of it touches the network.
    pub fn self_test(&self) -> SelfTestReport {
        let started = std::time::Instant::now();
        let steps = vec![
            self.check_private_storage(),
            check_key_generation(),
            check_network_listen(),
            check_object_round_trip(),
        ];
        let passed = steps.iter().all(|step| step.passed);
        SelfTestReport {
            steps,
            passed,
            elapsed_ms: started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        }
    }
}

impl GardenPhone {
    /// The listen address a phone uses: every interface, a port the system
    /// picks. A phone moves between networks and cannot be told a port.
    fn options() -> GardenOptions {
        serde_json::from_value(serde_json::json!({ "listen": "/ip4/0.0.0.0/tcp/0" }))
            .unwrap_or_default()
    }

    fn check_private_storage(&self) -> SelfTestStep {
        let path = self.data_dir.join("self-test.tmp");
        let written = std::fs::write(&path, b"garden")
            .and_then(|()| std::fs::read(&path))
            .inspect(|_| {
                let _ = std::fs::remove_file(&path);
            });
        match written {
            Ok(read) if read == b"garden" => step("write to private storage", true, String::new()),
            Ok(_) => step(
                "write to private storage",
                false,
                "the file read back as something else".into(),
            ),
            Err(e) => step("write to private storage", false, e.to_string()),
        }
    }
}

fn step(name: &str, passed: bool, detail: String) -> SelfTestStep {
    SelfTestStep {
        name: name.to_string(),
        passed,
        detail,
    }
}

fn answer(result: Result<serde_json::Value, String>) -> Result<GardenAnswer, GardenError> {
    match result {
        Ok(value) => Ok(GardenAnswer {
            json: value.to_string(),
        }),
        Err(reason) => Err(GardenError::of(reason)),
    }
}

fn check_key_generation() -> SelfTestStep {
    // Making a key proves nothing on its own: it has to sign, and the
    // signature has to verify, or the phone cannot be a validator.
    let name = "make a key and sign with it";
    match budlum_core::crypto::primitives::KeyPair::generate() {
        Ok(key) => {
            let signature = key.sign(b"garden self test");
            match budlum_core::crypto::primitives::verify_signature(
                b"garden self test",
                &signature,
                &key.public_key_bytes(),
            ) {
                Ok(()) => step(name, true, String::new()),
                Err(e) => step(name, false, format!("the signature did not verify: {e:?}")),
            }
        }
        Err(e) => step(name, false, format!("{e:?}")),
    }
}

fn check_network_listen() -> SelfTestStep {
    let name = "listen on the network";
    match std::net::TcpListener::bind("0.0.0.0:0") {
        Ok(listener) => match listener.local_addr() {
            Ok(address) => step(name, true, format!("port {}", address.port())),
            Err(e) => step(name, false, e.to_string()),
        },
        Err(e) => step(name, false, e.to_string()),
    }
}

fn check_object_round_trip() -> SelfTestStep {
    let name = "code and rebuild a small object";
    match budlum_core::garden::self_test_object_round_trip() {
        Ok(()) => step(name, true, String::new()),
        Err(e) => step(name, false, e),
    }
}
