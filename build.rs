fn main() {
    println!("cargo:rerun-if-changed=proto/budlum/network/protocol.proto");

    // protoc'u bul: PROTOC env > bilinen konumlar > PATH. Docker imajinda
    // prost-build PATH'ten bulamayip "Could not find protoc" veriyordu
    // (docker-smoke); Config::protoc_executable ile acikca verilir.
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
    // Etkisiz; input include-root'a goreli verilir, prost konvansiyonu).
    prost_build::Config::new()
        .protoc_executable(protoc)
        .compile_protos(&["budlum/network/protocol.proto"], &["proto/"])
        .expect("Failed to compile Protobuf schemas");
}
