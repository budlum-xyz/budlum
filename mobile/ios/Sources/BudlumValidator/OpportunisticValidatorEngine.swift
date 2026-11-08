import Foundation

/// Validator class registered on-chain by iOS devices (Section 7.10).
public enum ValidatorRegistrationClass: String, Equatable, Sendable {
    case mobileOpportunistic = "MobileOpportunistic"
}

/// Configuration for the iOS `BGProcessingTaskRequest` scheduler (Section 7.10).
public struct BackgroundProcessingConfig: Equatable, Sendable {
    public static let auditTaskIdentifier = "xyz.budlum.validator.audit"

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

public enum OpportunisticValidatorError: Error, Equatable {
    case invalidQuota(UInt64)
    case quotaBelowStoredBytes(requested: UInt64, stored: UInt64)
    case invalidSegmentId(String)
    case missingCustodyShare(String)
    case auditSigningUnavailable
}

/// Production boundary for custody-audit signing. The mobile core must provide
/// the canonical challenge decoder and signature transport; raw shares are not
/// an audit proof and are never returned by the storage engine itself.
public protocol CustodyAuditSigning: Sendable {
    func signAudit(segmentHex: String, share: Data, nonce: Data) throws -> Data
}

/// Local custody storage for the iOS `MobileOpportunistic` class.
///
/// This type enforces the 1...8 GiB quota and persists shares on disk. It does
/// not register a validator, publish presence, or claim a completed audit when
/// no production signing implementation is connected.
public final class OpportunisticValidatorEngine {
    public static let registrationTag: UInt64 = 2
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
    public private(set) var answeredAuditsCount: UInt64 = 0

    private let auditSigner: (any CustodyAuditSigning)?

    public init(
        baseDirectory: URL,
        quotaBytes: UInt64 = defaultQuotaBytes,
        auditSigner: (any CustodyAuditSigning)? = nil
    ) throws {
        guard quotaBytes >= Self.minQuotaBytes && quotaBytes <= Self.maxQuotaBytes else {
            throw OpportunisticValidatorError.invalidQuota(quotaBytes)
        }
        self.quotaBytes = quotaBytes
        self.auditSigner = auditSigner
        let bud3Directory = baseDirectory.appendingPathComponent("bud3", isDirectory: true)
        try FileManager.default.createDirectory(at: bud3Directory, withIntermediateDirectories: true)
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try bud3Directory.setResourceValues(resourceValues)
        try Self.applyFileProtection(to: bud3Directory)
        self.storageDirectory = bud3Directory
    }

    public func setQuotaBytes(_ newQuotaBytes: UInt64) throws {
        guard newQuotaBytes >= Self.minQuotaBytes && newQuotaBytes <= Self.maxQuotaBytes else {
            throw OpportunisticValidatorError.invalidQuota(newQuotaBytes)
        }
        let stored = try storedBytes()
        guard newQuotaBytes >= stored else {
            throw OpportunisticValidatorError.quotaBelowStoredBytes(
                requested: newQuotaBytes,
                stored: stored
            )
        }
        self.quotaBytes = newQuotaBytes
    }

    private static func normalizedSegmentId(_ segmentHex: String) throws -> String {
        let bytes = Array(segmentHex.utf8)
        guard bytes.count == 64, bytes.allSatisfy({ byte in
            (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte)
        }) else {
            throw OpportunisticValidatorError.invalidSegmentId(segmentHex)
        }
        return segmentHex.lowercased()
    }

    private static func applyFileProtection(to url: URL) throws {
        #if os(iOS)
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
        #endif
    }

    private func shareURL(segmentHex: String) throws -> (id: String, url: URL) {
        let id = try Self.normalizedSegmentId(segmentHex)
        return (id, storageDirectory.appendingPathComponent(id, isDirectory: false))
    }

    private func storedBytes(excluding excludedURL: URL? = nil) throws -> UInt64 {
        guard FileManager.default.fileExists(atPath: storageDirectory.path) else {
            return 0
        }
        let files = try FileManager.default.contentsOfDirectory(
            at: storageDirectory,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]
        )
        var total: UInt64 = 0
        for file in files {
            if let excludedURL, file.standardizedFileURL == excludedURL.standardizedFileURL {
                continue
            }
            let values = try file.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
            guard values.isRegularFile == true else {
                continue
            }
            let size = UInt64(max(values.fileSize ?? 0, 0))
            let (next, overflow) = total.addingReportingOverflow(size)
            guard !overflow else {
                throw OpportunisticValidatorError.invalidQuota(UInt64.max)
            }
            total = next
        }
        return total
    }

    public func storeCustodyShare(segmentHex: String, shareBytes: Data) throws {
        let (_, target) = try shareURL(segmentHex: segmentHex)
        let used = try storedBytes(excluding: target)
        let (next, overflow) = used.addingReportingOverflow(UInt64(shareBytes.count))
        guard !overflow && next <= quotaBytes else {
            throw OpportunisticValidatorError.invalidQuota(next)
        }
        try shareBytes.write(to: target, options: .atomic)
        try Self.applyFileProtection(to: target)
    }

    /// Signs challenged shares through the connected mobile-core boundary.
    /// Without that boundary the duty fails explicitly and no success counter
    /// or presence claim is emitted.
    public func runBackgroundProcessingWindow(
        challengedSegments: [String],
        nonce: Data
    ) throws -> [Data] {
        guard let auditSigner else {
            throw OpportunisticValidatorError.auditSigningUnavailable
        }
        var proofs: [Data] = []
        for segment in challengedSegments {
            let (id, file) = try shareURL(segmentHex: segment)
            guard FileManager.default.fileExists(atPath: file.path) else {
                throw OpportunisticValidatorError.missingCustodyShare(id)
            }
            let share = try Data(contentsOf: file)
            proofs.append(try auditSigner.signAudit(segmentHex: id, share: share, nonce: nonce))
            answeredAuditsCount += 1
        }
        return proofs
    }

    /// Removes only canonical share files. Unknown application data in the
    /// directory is preserved rather than deleted by a broad cleanup.
    public func leaveAndReleaseAllShares() throws -> [String] {
        let files = try FileManager.default.contentsOfDirectory(
            at: storageDirectory,
            includingPropertiesForKeys: [.isRegularFileKey]
        )
        var released: [String] = []
        for file in files {
            let name = file.lastPathComponent
            guard let canonical = try? Self.normalizedSegmentId(name), canonical == name else {
                continue
            }
            let values = try file.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else {
                continue
            }
            try FileManager.default.removeItem(at: file)
            released.append(name)
        }
        return released.sorted()
    }
}
