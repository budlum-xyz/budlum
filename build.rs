// The workspace denies `expect` because a panic in a running node aborts it.
// A build script is not a running node: it executes at compile time, and a
// failure to generate the protobuf bindings must stop the build loudly.
#![allow(clippy::expect_used)]

fn main() {
    println!("cargo:rerun-if-changed=proto/budlum/network/protocol.proto");

    // Find protoc: PROTOC env > known locations > PATH. In the Docker image
    // prost-build could not find it on PATH and said "Could not find protoc"
    // (docker-smoke); it is passed explicitly via Config::protoc_executable.
    let protoc = std::env::var("PROTOC")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            for cand in [
                "/usr/bin/protoc",
                "/usr/local/bin/protoc",
                "/usr/bin/protoc-3.21",
            ] {
                let p = std::path::PathBuf::from(cand);
                if p.exists() {
                    return p;
                }
            }
            std::path::PathBuf::from("protoc")
        });

    // For Buf's STANDARD PACKAGE_DIRECTORY_MATCH rule the file moved under
    // proto/budlum/network/ (the package name did not change, so no wire
    // effect; the input is given relative to the include root, a prost convention).
    prost_build::Config::new()
        .protoc_executable(protoc)
        .compile_protos(&["budlum/network/protocol.proto"], &["proto/"])
        .expect("Failed to compile Protobuf schemas");
}
