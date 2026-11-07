//
//  KeyVault.swift
//  BudlumValidatorKit
//
//  Device key wrapping. Directive 7.9.6, applied to iOS.
//
//  - The owner key (ML-DSA-87, 24 words) lives in the wallet and is *not*
//    here. Nothing in this file can spend a stake.
//  - The operator key (ML-DSA-65) and the BLS asset key are generated on the
//    device and wrapped with an AES-256-GCM key held in the Keychain.
//  - The operator key is used while the app is not in the foreground, so its
//    Keychain entry is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:
//    readable without a user presence check, and never migrated to another
//    device nor included in an iCloud backup.
//
//  # The trade-off, written rather than hidden
//
//  Android's version of this file sets `setUserAuthenticationRequired(false)`
//  and `setUnlockedDeviceRequired(false)` for the same reason, and states the
//  same consequence: someone who seizes the *unlocked* device can sign duty
//  transactions, and cannot spend the stake. The two platforms buy the same
//  property with the same trade. Device loss is handled by sending
//  `RotateOperatorKey` from the owner wallet on another device (R-16).
//
//  # What is deliberately absent
//
//  A Secure Enclave tier. The Enclave holds P-256 keys, so it cannot hold an
//  ML-DSA-65 operator key directly, and wrapping the AES key to an Enclave key
//  would add an ECIES round trip without changing the one property that
//  matters here: the blob is unreadable off this device. If a later revision
//  wants the Enclave tier, it belongs in a device test, not in this file.
//

import CryptoKit
import Foundation

/// Errors from wrapping and unwrapping.
public enum KeyVaultError: Error, Equatable, Sendable {
    /// The blob is too short to carry a nonce and a tag.
    case blobTooShort
    /// The Keychain refused the query.
    case keychainFailure(status: OSStatus)
    /// The stored blob is not a 32-byte AES-256 key.
    case malformedWrappingKey(byteCount: Int)
}

/// Where the wrapping key lives. Split out so the unit tests never touch the
/// Keychain.
public protocol WrapKeyStore: Sendable {
    func load() throws -> SymmetricKey?
    func save(_ key: SymmetricKey) throws
}

/// A store that keeps the key in memory. Tests only.
public final class InMemoryWrapKeyStore: WrapKeyStore, @unchecked Sendable {
    private var key: SymmetricKey?

    public init(key: SymmetricKey? = nil) {
        self.key = key
    }

    public func load() throws -> SymmetricKey? {
        key
    }

    public func save(_ key: SymmetricKey) throws {
        self.key = key
    }
}

public enum KeyVault {
    /// The Keychain service the wrapping key is stored under.
    public static let service = "dev.budlum.validator.keywrap"
    /// The Keychain account of the wrapping key.
    public static let wrappingKeyAccount = "budlum_keywrap_v1"
    /// The account of the wrapped operator key (ML-DSA-65).
    public static let operatorKeyAccount = "budlum_operator_key_v1"
    /// The account of the wrapped BLS asset key.
    public static let blsKeyAccount = "budlum_bls_asset_key_v1"

    /// AES-256-GCM nonce length, in bytes.
    public static let nonceBytes = 12

    /// Wrap `plaintext` with `key`.
    ///
    /// Output layout, the same as the Android app's so a blob written on one
    /// platform is readable on the other: 12-byte nonce || ciphertext || 16-byte
    /// GCM tag.
    public static func wrap(_ plaintext: Data, using key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw KeyVaultError.blobTooShort
        }
        return combined
    }

    /// Unwrap a blob produced by `wrap`. Throws on a failed tag check, which is
    /// the only signal that the blob was tampered with.
    public static func unwrap(_ blob: Data, using key: SymmetricKey) throws -> Data {
        guard blob.count > nonceBytes else {
            throw KeyVaultError.blobTooShort
        }
        let box = try AES.GCM.SealedBox(combined: blob)
        return try AES.GCM.open(box, using: key)
    }

    /// The wrapping key, loaded from `store` or generated and saved into it.
    ///
    /// Generating on first use rather than at install keeps the key out of any
    /// backup of an app that was never run.
    public static func wrappingKey(store: WrapKeyStore) throws -> SymmetricKey {
        if let existing = try store.load() {
            return existing
        }
        let key = SymmetricKey(size: .bits256)
        try store.save(key)
        return key
    }

    /// Wrap a duty key for storage.
    public static func wrapForStorage(_ plaintext: Data, store: WrapKeyStore) throws -> Data {
        try wrap(plaintext, using: wrappingKey(store: store))
    }

    /// Read a duty key back.
    public static func unwrapFromStorage(_ blob: Data, store: WrapKeyStore) throws -> Data {
        try unwrap(blob, using: wrappingKey(store: store))
    }
}
