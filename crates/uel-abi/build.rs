// A build script reports failure through its `Result`, never through `expect`:
// the workspace denies `expect` and a build script is not exempt from that.

use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=../../proto/budlum/execution/v1/ee.proto");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROTOC");

    // protoc: PROTOC env, then the usual install locations, then PATH. The
    // same search order as the node's own build script.
    let protoc = std::env::var("PROTOC").map_or_else(
        |_| {
            for candidate in ["/usr/bin/protoc", "/usr/local/bin/protoc"] {
                let path = PathBuf::from(candidate);
                if path.exists() {
                    return path;
                }
            }
            PathBuf::from("protoc")
        },
        PathBuf::from,
    );

    prost_build::Config::new()
        .protoc_executable(protoc)
        .compile_protos(&["budlum/execution/v1/ee.proto"], &["../../proto/"])?;
    Ok(())
}
