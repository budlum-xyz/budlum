//! # lubot-data - kapalı-devre veri katmanı
//!
//! Lubot yalnızca Pollen grant'li, B.U.D. StorageDeal etiketli veya
//! SocialFi kaynaklı veriyi okur. Bu crate dış veri okuyan tek bir yol
//! içermez: dış veri setleri bile önce B.U.D.'a kaydedilir.
//!
//! Derinleştirme (2026-08-13): içerik doğrulaması gerçek SHA-256'dır;
//! uyuşmazlık `HashMismatch` üretir ve veri akmaz.

pub mod jsonl;
pub mod source;
pub mod template;
pub mod verify;
