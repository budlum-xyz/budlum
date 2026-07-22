fn main() {
    println!("cargo:rerun-if-changed=proto/budlum/network/protocol.proto");

    // Task 8.11: buf STANDARD PACKAGE_DIRECTORY_MATCH uyumu — dosya
    // proto/budlum/network/ altina tasindi (package adi degismedi → wire
    // etkisiz; input include-root'a goreli verilir, prost konvansiyonu).
    prost_build::Config::new()
        .compile_protos(&["budlum/network/protocol.proto"], &["proto/"])
        .expect("Failed to compile Protobuf schemas");
}
