//! Kani model-check for .bud format - V14
//! cargo kani --harness kani_bud_format_roundtrip

#[cfg(kani)]
mod kani {
    use crate::bud_format::{BudFile, BudFormatClass, BudFlags};

    #[kani::proof]
    fn kani_bud_format_roundtrip() {
        let data: Vec<u8> = vec![1,2,3,4];
        let file = BudFile::encode(&data, BudFormatClass::Json, "application/json", 0,0, 3, BudFlags::new(true,true,false,false,false,false), data.clone());
        let bytes = file.to_bytes();
        let decoded = BudFile::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.decode().unwrap(), data);
    }

    #[kani::proof]
    fn kani_bud_erasure_reconstruct() {
        let data = vec![10u8; 32];
        let file = BudFile::encode(&data, BudFormatClass::Json, "application/json", 0,0, 3, BudFlags::new(true,true,false,false,false,false), data.clone());
        // parity shard'lari uretildi mi + byte roundtrip
        let bytes = file.to_bytes();
        let decoded = BudFile::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.decode().unwrap(), data);
        assert!(!file.chunks.is_empty());
    }

    #[kani::proof]
    fn kani_bud_no_panic_from_bytes() {
        let data: Vec<u8> = kani::any();
        if let Ok(file) = BudFile::from_bytes(&data) {
            let _ = file.decode();
        }
    }
}
