import CryptoKit
import Foundation

public enum SecureEnclaveKeyStoreError: Error, Equatable {
    case secureEnclaveUnavailable
}

/// Runtime ECDH/AES-GCM wrapping for device duty-key bytes.
///
/// The P-256 wrapping private key must be created inside the Secure Enclave;
/// there is no software fallback. This type is deliberately not presented as
/// a persistent Keychain vault or an ML-DSA/BLS signer. Persistent references,
/// owner-key access control, and canonical post-quantum signing remain mobile-
/// core integration work.
public final class SecureEnclaveKeyStore {
    public struct WrappedPostQuantumKey: Equatable, Sendable {
        public let label: String
        public let ephemeralPublicKeyRaw: Data
        public let sealedBoxCombined: Data
    }

    private let wrappingPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey

    public init() throws {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveKeyStoreError.secureEnclaveUnavailable
        }
        self.wrappingPrivateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }

    private func wrappingKey(label: String, ephemeralPublicKey: P256.KeyAgreement.PublicKey) throws
        -> SymmetricKey
    {
        let sharedSecret = try wrappingPrivateKey.sharedSecretFromKeyAgreement(
            with: ephemeralPublicKey
        )
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("budlum/ios/se-wrap/v1".utf8),
            sharedInfo: Data(label.utf8),
            outputByteCount: 32
        )
    }

    public func wrapPostQuantumKey(
        label: String,
        secretKeyBytes: Data
    ) throws -> WrappedPostQuantumKey {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let key = try wrappingKey(label: label, ephemeralPublicKey: ephemeral.publicKey)
        let sealed = try AES.GCM.seal(secretKeyBytes, using: key)
        guard let combined = sealed.combined else {
            throw CocoaError(.coderInvalidValue)
        }
        return WrappedPostQuantumKey(
            label: label,
            ephemeralPublicKeyRaw: ephemeral.publicKey.rawRepresentation,
            sealedBoxCombined: combined
        )
    }

    public func unwrapPostQuantumKey(_ wrapped: WrappedPostQuantumKey) throws -> Data {
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
            rawRepresentation: wrapped.ephemeralPublicKeyRaw
        )
        let key = try wrappingKey(label: wrapped.label, ephemeralPublicKey: ephemeralPublicKey)
        let box = try AES.GCM.SealedBox(combined: wrapped.sealedBoxCombined)
        return try AES.GCM.open(box, using: key)
    }
}
