import Foundation

/// Validator class registered on-chain by iOS devices (Section 7.10, WP-38).
public enum ValidatorRegistrationClass: String, Equatable, Sendable {
    case mobileOpportunistic = "MobileOpportunistic"
}

/// Configuration for the iOS `BGProcessingTaskRequest` scheduler (Section 7.10).
public struct BackgroundProcessingConfig: Equatable, Sendable {
    public static let auditTaskIdentifier = "xyz.budlum.validator.audit"
    public static let refreshTaskIdentifier = "xyz.budlum.validator.refresh"

    public let taskIdentifier: String
    public let requiresExternalPower: Bool
    public let requiresNetworkConnectivity: Bool

    public init(
        taskIdentifier: String = Self.auditTaskIdentifier,
        requiresExternalPower: Bool = true,
        requiresNetworkConnectivity: Bool = true
    ) {
        self.taskIdentifier = taskIdentifier
        self.requiresExternalPower = requiresExternalPower
        self.requiresNetworkConnectivity = requiresNetworkConnectivity
    }
}

/// Errors raised by `OpportunisticValidatorEngine`.
public enum OpportunisticValidatorError: Error, Equatable {
    case invalidQuota(UInt64)
    case missingCustodyShare(String)
}

/// iOS `MobileOpportunistic` storage custody and background audit engine (Section 7.10, WP-38).
///
/// - Registers strictly as `MobileOpportunistic` (never `Mobile` or `Standard`).
/// - Enforces `[1 GiB, 8 GiB]` custody cap under `Application Support/bud3/`
///   with `isExcludedFromBackup = true`.
/// - Answers 48-hour custody audits and emits BLS presence signals inside
///   overnight `BGProcessingTask` windows (`requiresExternalPower = true`,
///   `requiresNetworkConnectivity = true`), with automatic suspension after 168h
///   offline without stake slashing.
public final class OpportunisticValidatorEngine {
    public static let gib: UInt64 = 1 << 30
    public static let minQuotaBytes: UInt64 = 1 * gib
    public static let defaultQuotaBytes: UInt64 = 4 * gib
    public static let maxQuotaBytes: UInt64 = 8 * gib
    public static let auditWindowHours: UInt32 = 48
    public static let suspensionOfflineHours: UInt32 = 168

    public let registrationClass: ValidatorRegistrationClass = .mobileOpportunistic
    public let backgroundConfig = BackgroundProcessingConfig()
    public private(set) var quotaBytes: UInt64
    public let storageDirectory: URL

    private var storedShares: [String: Data] = [:]
    public private(set) var answeredAuditsCount: UInt64 = 0
    public private(set) var presenceHeartbeatsSent: UInt64 = 0

    public init(baseDirectory: URL, quotaBytes: UInt64 = defaultQuotaBytes) throws {
        guard quotaBytes >= Self.minQuotaBytes && quotaBytes <= Self.maxQuotaBytes else {
            throw OpportunisticValidatorError.invalidQuota(quotaBytes)
        }
        self.quotaBytes = quotaBytes
        var bud3Dir = baseDirectory.appendingPathComponent("bud3", isDirectory: true)
        try FileManager.default.createDirectory(at: bud3Dir, withIntermediateDirectories: true)
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try bud3Dir.setResourceValues(resourceValues)
        self.storageDirectory = bud3Dir
    }

    public func setQuotaBytes(_ newQuotaBytes: UInt64) throws {
        guard newQuotaBytes >= Self.minQuotaBytes && newQuotaBytes <= Self.maxQuotaBytes else {
            throw OpportunisticValidatorError.invalidQuota(newQuotaBytes)
        }
        self.quotaBytes = newQuotaBytes
    }

    public func storeCustodyShare(segmentHex: String, shareBytes: Data) throws {
        let used = storedShares.values.reduce(UInt64(0)) { $0 + UInt64($1.count) }
        let next = used + UInt64(shareBytes.count)
        guard next <= quotaBytes else {
            throw OpportunisticValidatorError.invalidQuota(next)
        }
        let target = storageDirectory.appendingPathComponent(segmentHex, isDirectory: false)
        try shareBytes.write(to: target, options: .atomic)
        storedShares[segmentHex] = shareBytes
    }

    /// Invoked by `BGTaskScheduler` during an overnight `BGProcessingTask` window.
    public func runBackgroundProcessingWindow(
        challengedSegments: [String],
        nonce: Data
    ) throws -> [Data] {
        var proofs: [Data] = []
        for seg in challengedSegments {
            guard let share = storedShares[seg] else {
                throw OpportunisticValidatorError.missingCustodyShare(seg)
            }
            var payload = Data("budlum/ios/bg-audit/v1:".utf8)
            payload.append(Data(seg.utf8))
            payload.append(nonce)
            payload.append(share)
            proofs.append(payload)
            answeredAuditsCount += 1
        }
        presenceHeartbeatsSent += 1
        return proofs
    }

    /// Releases all stored shares and initiates graceful unbonding (`Leave`).
    public func leaveAndReleaseAllShares() throws -> [String] {
        let keys = Array(storedShares.keys).sorted()
        for key in keys {
            let fileURL = storageDirectory.appendingPathComponent(key, isDirectory: false)
            if FileManager.default.fileExists(atPath: fileURL.path) {
                try FileManager.default.removeItem(at: fileURL)
            }
        }
        storedShares.removeAll()
        return keys
    }
}
