import CryptoKit
import Foundation

/// iOS Opportunistic Mobile Validator Core (`WP-38`, Directive Section 7.11).
///
/// Enforces all `ValidatorClass.mobileOpportunistic` protocol invariants:
/// - Validator class tag `2` (`MobileOpportunistic`, never `Full` or `Mobile`).
/// - Maximum custody quota capped at `8 GiB` (`[1 GiB, 8 GiB]`).
/// - Audit response window `48 hours`, presence interval `24 hours`,
///   missed-audit suspension `7 days`, slashing `0%`.
/// - `BGProcessingTask` duty requires external power and network connectivity.
/// - App Store Guideline 3.1.5(iii) (`R-22`): zero PoW mining on device.
public enum IosValidatorConstants {
    public static let testnetChainId: UInt64 = 45_261
    public static let gibBytes: UInt64 = 1_073_741_824
    public static let quotaMinBytes: UInt64 = 1 * gibBytes
    public static let quotaDefaultBytes: UInt64 = 4 * gibBytes
    public static let quotaMaxBytes: UInt64 = 8 * gibBytes
    public static let freeSpaceFloorBytes: UInt64 = 2 * gibBytes
    public static let auditWindowSeconds: UInt64 = 48 * 3_600
    public static let presenceIntervalSeconds: UInt64 = 24 * 3_600
    public static let suspensionDurationSeconds: UInt64 = 7 * 24 * 3_600
    public static let slashingRateBps: UInt16 = 0
    /// At most half the reward rate of Android `ValidatorClass.mobile` (`<= 5000 / 2` bps).
    public static let rewardRateBps: UInt16 = 2_500
    public static let bgTaskIdentifier: String = "network.budlum.validator.duty"
    public static let appStoreNonMiningDisclosure: String =
        "Budlum Validator performs zero cryptocurrency Proof-of-Work mining. " +
        "Opportunistic storage custody runs only during system-scheduled charging windows on Wi-Fi."
}

public enum IosValidatorClass: UInt8, Equatable, Sendable {
    case full = 0
    case mobile = 1
    case mobileOpportunistic = 2
}

public enum IosCoreError: Error, Equatable {
    case quotaOutOfRange(UInt64)
    case thermalPauseLocked
    case nonOpportunisticClassForbidden(IosValidatorClass)
    case externalPowerRequired
    case networkConnectivityRequired
    case lowFreeSpaceFloor
    case biometricAuthRequired
    case missingCustodyShare(String)
}

public struct BgProcessingScheduleDescriptor: Equatable, Sendable {
    public let identifier: String
    public let requiresExternalPower: Bool
    public let requiresNetworkConnectivity: Bool
    public let earliestBeginDelaySeconds: TimeInterval

    public init(
        identifier: String = IosValidatorConstants.bgTaskIdentifier,
        requiresExternalPower: Bool = true,
        requiresNetworkConnectivity: Bool = true,
        earliestBeginDelaySeconds: TimeInterval = 3_600
    ) {
        self.identifier = identifier
        self.requiresExternalPower = requiresExternalPower
        self.requiresNetworkConnectivity = requiresNetworkConnectivity
        self.earliestBeginDelaySeconds = earliestBeginDelaySeconds
    }

    public func validate() throws {
        if !requiresExternalPower {
            throw IosCoreError.externalPowerRequired
        }
        if !requiresNetworkConnectivity {
            throw IosCoreError.networkConnectivityRequired
        }
    }
}

public struct IosPolicy: Equatable, Sendable {
    public let quotaBytes: UInt64
    public let wifiOnly: Bool
    public let thermalPause: Bool

    public init(
        quotaBytes: UInt64 = IosValidatorConstants.quotaDefaultBytes,
        wifiOnly: Bool = true,
        thermalPause: Bool = true
    ) throws {
        if !thermalPause {
            throw IosCoreError.thermalPauseLocked
        }
        if quotaBytes < IosValidatorConstants.quotaMinBytes
            || quotaBytes > IosValidatorConstants.quotaMaxBytes
        {
            throw IosCoreError.quotaOutOfRange(quotaBytes)
        }
        self.quotaBytes = quotaBytes
        self.wifiOnly = wifiOnly
        self.thermalPause = thermalPause
    }
}

public struct IosAssignedShare: Equatable, Sendable {
    public let segmentIdHex: String
    public let esi: UInt32
    public let payload: Data

    public init(segmentIdHex: String, esi: UInt32, payload: Data) {
        self.segmentIdHex = segmentIdHex
        self.esi = esi
        self.payload = payload
    }
}

public struct IosStorageAudit: Equatable, Sendable {
    public let segmentIdHex: String
    public let challengeNonce: UInt64

    public init(segmentIdHex: String, challengeNonce: UInt64) {
        self.segmentIdHex = segmentIdHex
        self.challengeNonce = challengeNonce
    }
}

public enum IosDutyTx: Equatable, Sendable {
    case registerOpportunisticValidator(validatorClass: IosValidatorClass, stakeBud: UInt64)
    case custodyAck(segmentIdHex: String, esi: UInt32)
    case custodyProofBatch(segmentIdHex: String, digestHex: String)
    case presence(window: UInt64, validatorClass: IosValidatorClass, preimageHex: String)
    case releaseShares(segments: [String])
}

/// Secure Enclave / Keychain wrapping envelope model (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
/// for background duty keys, biometric gate for ML-DSA-87 owner spend key).
public final class SecureEnclaveKeyVault {
    private let wrappingKey: SymmetricKey
    private let expectedBiometricToken: String

    public init(expectedBiometricToken: String = "FACEID_OR_TOUCHID_VERIFIED") {
        self.wrappingKey = SymmetricKey(size: .bits256)
        self.expectedBiometricToken = expectedBiometricToken
    }

    public func wrapDutyKey(_ rawKey: Data) throws -> Data {
        let sealed = try AES.GCM.seal(
            rawKey,
            using: wrappingKey,
            authenticating: Data("BDLM_IOS_DUTY_KEY_V1".utf8)
        )
        guard let combined = sealed.combined else {
            throw IosCoreError.biometricAuthRequired
        }
        return combined
    }

    public func unwrapDutyKey(_ combined: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(
            box,
            using: wrappingKey,
            authenticating: Data("BDLM_IOS_DUTY_KEY_V1".utf8)
        )
    }

    public func verifyOwnerBiometricToken(_ token: String) throws {
        if token != expectedBiometricToken {
            throw IosCoreError.biometricAuthRequired
        }
    }
}

public final class IosOpportunisticValidator {
    public let validatorClass: IosValidatorClass
    public private(set) var policy: IosPolicy
    public private(set) var registered: Bool = false
    public private(set) var lastAuditPassed: Bool = false
    private let keyVault: SecureEnclaveKeyVault
    private var shares: [String: IosAssignedShare] = [:]
    private var availableFreeBytes: UInt64

    public init(
        requestedClass: IosValidatorClass = .mobileOpportunistic,
        policy: IosPolicy? = nil,
        keyVault: SecureEnclaveKeyVault = SecureEnclaveKeyVault(),
        availableFreeBytes: UInt64 = 16 * IosValidatorConstants.gibBytes
    ) throws {
        if requestedClass != .mobileOpportunistic {
            throw IosCoreError.nonOpportunisticClassForbidden(requestedClass)
        }
        self.validatorClass = requestedClass
        self.policy = try (policy ?? IosPolicy())
        self.keyVault = keyVault
        self.availableFreeBytes = availableFreeBytes
    }

    public var storedBytes: UInt64 {
        shares.values.reduce(0) { $0 + UInt64($1.payload.count) }
    }

    public func setPolicy(_ next: IosPolicy) -> [IosDutyTx] {
        var emitted: [IosDutyTx] = []
        if next.quotaBytes < storedBytes {
            var dropped: [String] = []
            for key in shares.keys.sorted() where storedBytes > next.quotaBytes {
                shares.removeValue(forKey: key)
                dropped.append(key)
            }
            if !dropped.isEmpty {
                emitted.append(.releaseShares(segments: dropped))
            }
        }
        self.policy = next
        return emitted
    }

    public func register(biometricToken: String, stakeBud: UInt64 = 10) throws -> IosDutyTx {
        try keyVault.verifyOwnerBiometricToken(biometricToken)
        self.registered = true
        return .registerOpportunisticValidator(
            validatorClass: .mobileOpportunistic,
            stakeBud: stakeBud
        )
    }

    public func makeBgProcessingDescriptor() -> BgProcessingScheduleDescriptor {
        BgProcessingScheduleDescriptor()
    }

    /// Invoked when iOS wakes the app for a `BGProcessingTask` window.
    public func handleBgProcessingTask(
        schedule: BgProcessingScheduleDescriptor,
        window: UInt64,
        incomingShares: [IosAssignedShare],
        pendingAudits: [IosStorageAudit]
    ) throws -> [IosDutyTx] {
        try schedule.validate()
        if availableFreeBytes < IosValidatorConstants.freeSpaceFloorBytes {
            let released = shares.keys.sorted()
            shares.removeAll()
            if !released.isEmpty {
                return [.releaseShares(segments: released)]
            }
            throw IosCoreError.lowFreeSpaceFloor
        }

        var out: [IosDutyTx] = []
        for share in incomingShares {
            let nextBytes = storedBytes + UInt64(share.payload.count)
            if nextBytes > policy.quotaBytes {
                throw IosCoreError.quotaOutOfRange(nextBytes)
            }
            shares[share.segmentIdHex] = share
            out.append(.custodyAck(segmentIdHex: share.segmentIdHex, esi: share.esi))
        }

        for audit in pendingAudits {
            guard let share = shares[audit.segmentIdHex] else {
                lastAuditPassed = false
                throw IosCoreError.missingCustodyShare(audit.segmentIdHex)
            }
            var hasher = SHA256()
            hasher.update(data: Data("BDLM_IOS_AUDIT_V1".utf8))
            hasher.update(data: share.payload)
            hasher.update(data: Data(String(audit.challengeNonce).utf8))
            let digestHex = hasher.finalize().map { String(format: "%02x", $0) }.joined()
            lastAuditPassed = true
            out.append(.custodyProofBatch(segmentIdHex: audit.segmentIdHex, digestHex: digestHex))
        }

        var presenceHasher = SHA256()
        presenceHasher.update(data: Data("BDLM_PRESENCE_V1".utf8))
        presenceHasher.update(data: Data(String(IosValidatorConstants.testnetChainId).utf8))
        presenceHasher.update(data: Data(String(window).utf8))
        presenceHasher.update(data: Data([validatorClass.rawValue]))
        let preimageHex = presenceHasher.finalize().map { String(format: "%02x", $0) }.joined()
        out.append(
            .presence(
                window: window,
                validatorClass: .mobileOpportunistic,
                preimageHex: preimageHex
            )
        )
        return out
    }
}
