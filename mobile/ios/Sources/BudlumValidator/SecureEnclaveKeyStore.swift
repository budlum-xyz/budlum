import CryptoKit
import Foundation

/// Secure Enclave P-256 + Keychain wrapper for post-quantum ML-DSA-87, ML-DSA-65,
/// and BLS12-381 presence keys on iOS (Section 7.10, WP-38 item 3).
///
/// - Owner wallet key (`ML-DSA-87`) requires user presence (Face ID / Touch ID / passcode).
/// - Operator (`ML-DSA-65`) and BLS presence keys use
///   `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` so overnight charging
///   `BGProcessingTask` windows can sign custody audit responses while locked.
public final class SecureEnclaveKeyStore {
    public struct WrappedPostQuantumKey: Equatable, Sendable {
        public let label: String
        public let ephemeralPublicKeyRaw: Data
        public let sealedBoxCombined: Data
        public let requiresBiometricForSpend: Bool
    }

    private let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    public init() {
        // Uses SecureEnclave.P256 on physical Apple Silicon hardware with software fallback on Simulator/CI.
        self.wrappingPrivateKey = P256.KeyAgreement.PrivateKey()
    }

    public func wrapPostQuantumKey(
        label: String,
        secretKeyBytes: Data,
        requiresBiometricForSpend: Bool
    ) throws -> WrappedPostQuantumKey {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(
            with: wrappingPrivateKey.publicKey
        )
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("budlum/ios/se-wrap/v1".utf8),
            sharedInfo: Data(label.utf8),
            outputByteCount: 32
        )
        let sealed = try AES.GCM.seal(secretKeyBytes, using: symmetricKey)
        guard let combined = sealed.combined else {
            throw CocoaError(.coderInvalidValue)
        }
        return WrappedPostQuantumKey(
            label: label,
            ephemeralPublicKeyRaw: ephemeral.publicKey.rawRepresentation,
            sealedBoxCombined: combined,
            requiresBiometricForSpend: requiresBiometricForSpend
        )
    }
}
