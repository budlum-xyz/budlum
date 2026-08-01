fn main() {
    println!("cargo:rerun-if-changed=proto/budlum/network/protocol.proto");

    // Buf STANDARD PACKAGE_DIRECTORY_MATCH uyumu, dosya
    // Proto/budlum/network/ altina tasindi (package adi degismedi → wire
    // Etkisiz; input include-root'a goreli verilir, prost konvansiyonu).
    prost_build::Config::new()
        .compile_protos(&["budlum/network/protocol.proto"], &["proto/"])
        .expect("Failed to compile Protobuf schemas");
}
