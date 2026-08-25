// The workspace denies `expect` because a panic in a running node aborts it.
// A build script is not a running node: it executes at compile time, and a
// failure to generate the protobuf bindings must stop the build loudly.
#![allow(clippy::expect_used)]

fn main() {
    println!("cargo:rerun-if-changed=proto/budlum/network/protocol.proto");

    // protoc'u bul: PROTOC env > bilinen konumlar > PATH. Docker imajinda
    // prost-build PATH'ten bulamayip "Could not find protoc" veriyordu
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

    // Buf STANDARD PACKAGE_DIRECTORY_MATCH uyumu, dosya
    // Proto/budlum/network/ altina tasindi (package adi degismedi → wire
    // No effect; the input is given relative to the include root, a prost convention).
    prost_build::Config::new()
        .protoc_executable(protoc)
        .compile_protos(&["budlum/network/protocol.proto"], &["proto/"])
        .expect("Failed to compile Protobuf schemas");
}
