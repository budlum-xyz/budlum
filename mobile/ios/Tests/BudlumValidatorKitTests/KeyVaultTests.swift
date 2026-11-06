//
//  KeyVaultTests.swift
//  BudlumValidatorKitTests
//

import XCTest
@testable import BudlumValidatorKit

final class KeyVaultTests: XCTestCase {
    private let store = InMemoryWrapKeyStore()

    func test_wrap_and_unwrap_round_trip() throws {
        let key = try KeyVault.wrappingKey(store: store)
        // A stand-in for an ML-DSA-65 operator key. The vault does not care
        // what the bytes are, only that they come back unchanged.
        let plaintext = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let blob = try KeyVault.wrap(plaintext, using: key)
        XCTAssertNotEqual(blob, plaintext)
        // 12-byte nonce plus a 16-byte GCM tag.
        XCTAssertEqual(blob.count, plaintext.count + KeyVault.nonceBytes + 16)
        XCTAssertEqual(try KeyVault.unwrap(blob, using: key), plaintext)
    }

    /// A tampered blob fails the tag check. That failure is the only signal
    /// that a blob was modified off this device.
    func test_tampered_blob_fails_the_tag_check() throws {
        let key = try KeyVault.wrappingKey(store: store)
        var blob = try KeyVault.wrap(Data([0x01, 0x02]), using: key)
        blob[blob.count - 1] ^= 0x01
        XCTAssertThrowsError(try KeyVault.unwrap(blob, using: key))
    }

    func test_too_short_blob_is_refused_before_any_crypto() throws {
        let key = try KeyVault.wrappingKey(store: store)
        XCTAssertThrowsError(try KeyVault.unwrap(Data([0x01]), using: key)) { error in
            XCTAssertEqual(error as? KeyVaultError, .blobTooShort)
        }
    }

    /// The wrapping key is generated once and reused: a key regenerated per
    /// write would leave previously wrapped blobs unreadable.
    func test_wrapping_key_is_generated_once_and_reused() throws {
        XCTAssertNil(try store.load())
        let first = try KeyVault.wrappingKey(store: store)
        let second = try KeyVault.wrappingKey(store: store)
        XCTAssertEqual(first.withUnsafeBytes { Data($0) }, second.withUnsafeBytes { Data($0) })
    }

    func test_storage_helpers_round_trip() throws {
        let plaintext = Data("operator key material".utf8)
        let blob = try KeyVault.wrapForStorage(plaintext, store: store)
        XCTAssertEqual(try KeyVault.unwrapFromStorage(blob, store: store), plaintext)
    }

    /// The account names are storage keys shared with the Android app's naming,
    /// so a bug report naming one is readable on both platforms.
    func test_account_names_are_stable() {
        XCTAssertEqual(KeyVault.operatorKeyAccount, "budlum_operator_key_v1")
        XCTAssertEqual(KeyVault.blsKeyAccount, "budlum_bls_asset_key_v1")
        XCTAssertEqual(KeyVault.wrappingKeyAccount, "budlum_keywrap_v1")
        XCTAssertEqual(KeyVault.service, "dev.budlum.validator.keywrap")
    }
}
