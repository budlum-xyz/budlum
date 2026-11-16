//! The UniFFI binding generator, pinned to the crate's UniFFI version so the
//! generated Kotlin and Swift match the scaffolding compiled into the library.

fn main() {
    uniffi::uniffi_bindgen_main();
}
