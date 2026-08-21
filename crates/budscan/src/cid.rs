//! IPFS CID cozumleme ve bayt dogrulamasi.
//!
//! Bir `.eth` adi ENS uzerinden bir IPFS CID'sine isaret edebilir. O CID
//! icerik adreslidir, yani Budlum manifest'i olmasa da **dogrulanabilir**:
//! getirilen baytlarin hash'i CID'nin tasidigi multihash'e esit olmalidir.
//!
//! # Ne destekleniyor, ne desteklenmiyor
//!
//! Desteklenen: `CIDv0` (`Qm...`, base58btc, `dag-pb`, `sha2-256`) ve `CIDv1`'in
//! `raw` (0x55) kodekli, `sha2-256` multihash'li bicimi. Bunlar bir dosyanin
//! **tek blok** halinde adreslenmis halidir ve dogrulamasi bir esitlik
//! kontroludur.
//!
//! Desteklenmeyen: `dag-pb` altinda **coklu blok** (`UnixFS` DAG) icerik.
//! Sebep, dogrulamanin orada bir esitlik degil bir DAG yurumesi olmasi: kok
//! blogun protobuf'unu ayristirip cocuk baglantilarini cikarmak, her cocugu
//! ayri getirmek ve sirasiyla birlestirmek gerekir. Bu, sessizce yanlis
//! yapilabilecek bir istir; yapilmadi ve **yapilmadigi soyleniyor**. Boyle bir
//! CID'ye [`CidVerdict::UnsupportedMultiblock`] donuyor ve tarayici sayfayi
//! `dogrulandi` diye gostermiyor.
//!
//! Bu ayrimi silmek, bu tarayicinin tek iddiasini silerdi.

use sha2::{Digest, Sha256};

/// base58btc alfabesi (Bitcoin).
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// multicodec: sha2-256 multihash kodu.
const MH_SHA2_256: u64 = 0x12;
/// multicodec: `raw` icerik tipi.
const CODEC_RAW: u64 = 0x55;
/// multicodec: `dag-pb` icerik tipi.
const CODEC_DAG_PB: u64 = 0x70;

/// Cozulmus bir CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cid {
    pub version: u8,
    pub codec: u64,
    pub digest: [u8; 32],
}

/// Bir CID hakkinda verilebilecek karar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidVerdict {
    /// Baytlar dogrulanabilir ve dogrulandi.
    Verified,
    /// Baytlar dogrulanabilirdi ve dogrulanmadi: hash tutmuyor.
    DigestMismatch { expected: String, produced: String },
    /// dag-pb: tek blok olmayabilir, bu surum DAG yurumuyor.
    UnsupportedMultiblock,
}

/// base58btc coz.
fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let val = u32::try_from(B58.iter().position(|c| *c == ch)?).ok()?;
        let mut carry = val;
        for byte in out.iter_mut().rev() {
            let x = u32::from(*byte) * 58 + carry;
            *byte = (x & 0xff) as u8;
            carry = x >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Bastaki '1'ler sifir baytlardir.
    for ch in s.bytes() {
        if ch == b'1' {
            out.insert(0, 0);
        } else {
            break;
        }
    }
    Some(out)
}

/// multibase base32 (RFC 4648, kucuk harf, dolgusuz) coz.
fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let v = match ch {
            'a'..='z' => ch as u32 - 'a' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return None,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// unsigned-varint oku; (deger, tuketilen bayt).
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

/// Bir CID dizgisini coz.
///
/// # Errors
///
/// Tanimayan multibase, desteklenmeyen surum/kodek/hash, ya da bozuk uzunluk.
pub fn parse(s: &str) -> Result<Cid, String> {
    let bytes = if s.len() == 46 && s.starts_with("Qm") {
        b58_decode(s).ok_or_else(|| String::from("base58btc cozulemedi"))?
    } else if let Some(rest) = s.strip_prefix('b') {
        b32_decode(rest).ok_or_else(|| String::from("base32 cozulemedi"))?
    } else if let Some(rest) = s.strip_prefix('z') {
        b58_decode(rest).ok_or_else(|| String::from("base58btc cozulemedi"))?
    } else if let Some(rest) = s.strip_prefix('f') {
        hex::decode(rest).map_err(|e| format!("base16 cozulemedi: {e}"))?
    } else {
        return Err(format!(
            "taninmayan multibase oneki; CID {:?} ne CIDv0 ne de destekli bir CIDv1 kodlamasi",
            s.chars().next().unwrap_or('?')
        ));
    };
    parse_bytes(&bytes)
}

/// Ikili bir CID'yi coz.
///
/// # Errors
///
/// Spec'in reddetmeyi sart kostugu her sekil: bilinmeyen surum, `0x12 0x20`
/// olmayan cikplak multihash, yanlis uzunluk, bilinmeyen hash tipi.
pub fn parse_bytes(bytes: &[u8]) -> Result<Cid, String> {
    // CIDv0: cikplak 34 baytlik sha2-256 multihash.
    if bytes.len() == 34 && bytes[0] == 0x12 && bytes[1] == 0x20 {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[2..34]);
        return Ok(Cid {
            version: 0,
            codec: CODEC_DAG_PB,
            digest,
        });
    }

    let (version, n) = read_varint(bytes).ok_or_else(|| String::from("surum varint'i bozuk"))?;
    if version != 1 {
        return Err(format!(
            "CID surumu {version} desteklenmiyor; yalniz CIDv0 ve CIDv1 var"
        ));
    }
    let rest = &bytes[n..];
    let (codec, n2) = read_varint(rest).ok_or_else(|| String::from("kodek varint'i bozuk"))?;
    let rest = &rest[n2..];
    let (mh_code, n3) = read_varint(rest).ok_or_else(|| String::from("multihash kodu bozuk"))?;
    let rest = &rest[n3..];
    let (mh_len, n4) = read_varint(rest).ok_or_else(|| String::from("multihash uzunlugu bozuk"))?;
    let rest = &rest[n4..];

    if mh_code != MH_SHA2_256 {
        return Err(format!(
            "multihash {mh_code:#x} desteklenmiyor; bu tarayici sha2-256 disinda bir \
             ozet fonksiyonunu dogrulayamaz ve dogrulayamadigini gizlemez"
        ));
    }
    if mh_len != 32 || rest.len() != 32 {
        return Err(format!(
            "sha2-256 ozeti 32 bayt olmali, {mh_len} bildirildi ve {} bayt var",
            rest.len()
        ));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(rest);
    Ok(Cid {
        version: 1,
        codec,
        digest,
    })
}

/// Getirilen baytlari CID'ye karsi dogrula.
#[must_use]
pub fn verify(cid: &Cid, bytes: &[u8]) -> CidVerdict {
    // dag-pb: baytlar bir protobuf dugumu, ham icerik degil. Tek blok mu coklu
    // blok mu oldugunu ayristirmadan bilemeyiz ve bu surum ayristirmiyor.
    if cid.codec == CODEC_DAG_PB {
        return CidVerdict::UnsupportedMultiblock;
    }
    if cid.codec != CODEC_RAW {
        return CidVerdict::UnsupportedMultiblock;
    }
    let produced: [u8; 32] = Sha256::digest(bytes).into();
    if produced == cid.digest {
        CidVerdict::Verified
    } else {
        CidVerdict::DigestMismatch {
            expected: hex::encode(cid.digest),
            produced: hex::encode(produced),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_v1_raw_hello_from_the_spec() {
        // specs.ipfs.tech/cid: "hello" baytlarinin CIDv1 raw hali.
        let s = "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq";
        let cid = parse(s).expect("spec ornegi cozulmeli");
        assert_eq!(cid.version, 1);
        assert_eq!(cid.codec, CODEC_RAW);
        assert_eq!(
            hex::encode(cid.digest),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(verify(&cid, b"hello"), CidVerdict::Verified);
    }

    #[test]
    fn wrong_bytes_are_refused_with_both_digests() {
        let cid = parse("bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq").unwrap();
        match verify(&cid, b"goodbye") {
            CidVerdict::DigestMismatch { expected, produced } => {
                assert_ne!(expected, produced);
            }
            other => panic!("beklenen uyusmazlik, gelen {other:?}"),
        }
    }

    #[test]
    fn cid_v0_parses_but_is_not_claimed_verified() {
        // Qm... dag-pb'dir: baytlar bir UnixFS dugumu olabilir. Ozeti okuruz,
        // ama "dogrulandi" demeyiz.
        let s = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        let cid = parse(s).expect("CIDv0 cozulmeli");
        assert_eq!(cid.version, 0);
        assert_eq!(cid.codec, CODEC_DAG_PB);
        assert_eq!(verify(&cid, b"whatever"), CidVerdict::UnsupportedMultiblock);
    }

    #[test]
    fn an_unknown_multibase_is_refused_not_guessed() {
        assert!(parse("Xnotacid").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn a_non_sha256_multihash_is_refused_by_name() {
        // CIDv1 + raw + blake2b-256 (0xb220) + 32 bayt.
        let mut bytes = vec![0x01, 0x55, 0xa0, 0xe4, 0x02, 0x20];
        bytes.extend_from_slice(&[0u8; 32]);
        let err = parse_bytes(&bytes).unwrap_err();
        assert!(err.contains("desteklenmiyor"), "{err}");
    }

    #[test]
    fn a_truncated_digest_is_refused() {
        let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
        bytes.extend_from_slice(&[0u8; 31]);
        assert!(parse_bytes(&bytes).is_err());
    }
}
