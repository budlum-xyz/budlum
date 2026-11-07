//
//  MobileCoreBinding.swift
//  BudlumValidatorKit
//
//  The UniFFI binding surface of the mobile core. Directive 7.9.1 names the
//  eight calls and the event callback; this file is the Swift side of that
//  contract, written so the app and its tests compile and run before the
//  generated UniFFI module exists.
//
//  # Why a protocol and not the generated module
//
//  `budlum-mobile-core` is built by `mobile/core` (WP-36 2/N) and exposes
//  `BudlumMobileCoreFFI` through UniFFI. Importing that module here would make
//  this package unbuildable until the Rust crate lands in the tree, and the
//  tests would then be unable to run on any branch that does not carry it.
//  So the surface is a protocol, the shipped app will satisfy it with a thin
//  adapter over the generated module, and the tests satisfy it with
//  `FakeMobileCore`.
//
//  The protocol is the contract: an adapter may add nothing to it. Adding a
//  call here without adding it to `mobile/core` is a compile error in the
//  adapter, which is the point.
//

import Foundation

/// What the core reports about the validator it is running.
public struct CoreStatus: Equatable, Sendable {
    /// Bytes of share data currently held on the device.
    public let storedBytes: UInt64
    /// The quota the validator declared, in bytes.
    public let quotaBytes: UInt64
    /// The number of the last custody audit answered, or `nil` if none was
    /// answered yet.
    public let lastAuditSequence: UInt64?
    /// Whether the last custody audit passed, or `nil` if none was answered.
    public let lastAuditPassed: Bool?
    /// Whether the peer-to-peer connections are up.
    public let connected: Bool
    /// Rewards accrued and not yet claimed, in the smallest BUD unit.
    public let claimableRewards: UInt64

    public init(
        storedBytes: UInt64,
        quotaBytes: UInt64,
        lastAuditSequence: UInt64?,
        lastAuditPassed: Bool?,
        connected: Bool,
        claimableRewards: UInt64
    ) {
        self.storedBytes = storedBytes
        self.quotaBytes = quotaBytes
        self.lastAuditSequence = lastAuditSequence
        self.lastAuditPassed = lastAuditPassed
        self.connected = connected
        self.claimableRewards = claimableRewards
    }

    /// The status of a core that has not started.
    public static let idle = CoreStatus(
        storedBytes: 0,
        quotaBytes: 0,
        lastAuditSequence: nil,
        lastAuditPassed: nil,
        connected: false,
        claimableRewards: 0
    )
}

/// One outstanding custody audit the device must answer.
public struct PendingAudit: Equatable, Sendable {
    /// The audit sequence number the network assigned.
    public let sequence: UInt64
    /// The segment the audit challenges.
    public let segmentId: Data
    /// The latest height at which an answer is still accepted.
    public let deadlineHeight: UInt64

    public init(sequence: UInt64, segmentId: Data, deadlineHeight: UInt64) {
        self.sequence = sequence
        self.segmentId = segmentId
        self.deadlineHeight = deadlineHeight
    }
}

/// The answer the core produces for one audit, or the reason it has none.
public enum AuditOutcome: Equatable, Sendable {
    /// The audit was answered, from the shares held on the device.
    case answered(sequence: UInt64)
    /// No audit was outstanding.
    case nothingPending
    /// The audit was outstanding but the device does not hold the segment.
    case missingSegment(sequence: UInt64)
}

/// What the core broadcasts about itself.
public enum CoreEvent: Equatable, Sendable {
    case started
    case stopped
    case shareStored(segmentId: Data, bytes: UInt64)
    case shareReleased(segmentId: Data)
    case auditAnswered(sequence: UInt64, passed: Bool)
    case presenceSigned(window: UInt64)
    case finalityRejected(peer: String, reason: String)
}

/// Errors the core returns.
public enum MobileCoreError: Error, Equatable, Sendable {
    /// The core is already running.
    case alreadyRunning
    /// The core is not running, so the call has nothing to act on.
    case notRunning
    /// The declared quota exceeds the ceiling consensus allows the class.
    case quotaAboveClassCeiling(declared: UInt64, ceiling: UInt64)
    /// The node refused the duty transaction.
    case refused(reason: String)
}

/// The eight calls of directive 7.9.1 plus the event callback.
///
/// Implemented in the shipped app by an adapter over the UniFFI-generated
/// module; implemented in tests by `FakeMobileCore`.
public protocol MobileCore: AnyObject, Sendable {
    /// Start the node, the audit responder and the presence signer.
    func start() throws
    /// Stop them. A mobile validator may leave at any moment (V-1); stopping
    /// is always allowed and never a fault.
    func stop() throws
    /// The current status.
    func status() throws -> CoreStatus
    /// Replace the working policy.
    func setPolicy(_ policy: AppPolicy) throws
    /// Send `RegisterValidator` for the given class and quota.
    func registerValidator(class: ValidatorClass, quotaBytes: UInt64) throws
    /// Send `ResumeValidator` after a suspension. Suspension is not a slash
    /// (V-4), so resuming needs no appeal.
    func resume() throws
    /// Claim the accrued storage reward.
    func claimRewards() throws
    /// Release every share and begin unbonding the stake. A validator that
    /// leaves harms nothing (V-1).
    func leave() throws

    /// The audits the network is waiting for.
    func pendingAudits() throws -> [PendingAudit]
    /// Answer one audit from the shares held on the device.
    func answerAudit(sequence: UInt64) throws -> AuditOutcome
    /// Sign and publish the presence signal of the current window.
    func signPresence(window: UInt64) throws

    /// Called on every event. Set before `start()`.
    var onEvent: (@Sendable (CoreEvent) -> Void)? { get set }
}

/// A core that records what it was asked to do. Used by the tests, and by the
/// SwiftUI previews.
public final class FakeMobileCore: MobileCore, @unchecked Sendable {
    /// Every call, in order, so a test can assert the duty the background task
    /// performed rather than the state it left behind.
    public private(set) var calls: [String] = []
    /// The audits the fake reports as outstanding.
    public var audits: [PendingAudit] = []
    /// The segments the fake holds. An audit over a segment not in this set
    /// answers `missingSegment`.
    public var heldSegments: Set<Data> = []
    /// The status the fake returns.
    public var nextStatus: CoreStatus = .idle
    /// The error the next call raises, if any.
    public var errorToThrow: MobileCoreError?
    /// Whether `start()` was called and `stop()` was not.
    public private(set) var isRunning = false

    public var onEvent: (@Sendable (CoreEvent) -> Void)?

    public init() {}

    private func fail(_ call: String) throws {
        calls.append(call)
        if let error = errorToThrow {
            throw error
        }
    }

    public func start() throws {
        try fail("start")
        isRunning = true
        onEvent?(.started)
    }

    public func stop() throws {
        try fail("stop")
        isRunning = false
        onEvent?(.stopped)
    }

    public func status() throws -> CoreStatus {
        try fail("status")
        return nextStatus
    }

    public func setPolicy(_ policy: AppPolicy) throws {
        try fail("setPolicy(\(policy.quota.quotaBytes))")
    }

    public func registerValidator(class: ValidatorClass, quotaBytes: UInt64) throws {
        try fail("registerValidator(\(`class`.rawValue),\(quotaBytes))")
        if let ceiling = ClassParameters.parameters(for: `class`).maxCustodyQuotaBytes,
           quotaBytes > ceiling {
            throw MobileCoreError.quotaAboveClassCeiling(declared: quotaBytes, ceiling: ceiling)
        }
    }

    public func resume() throws {
        try fail("resume")
    }

    public func claimRewards() throws {
        try fail("claimRewards")
    }

    public func leave() throws {
        try fail("leave")
    }

    public func pendingAudits() throws -> [PendingAudit] {
        try fail("pendingAudits")
        return audits
    }

    public func answerAudit(sequence: UInt64) throws -> AuditOutcome {
        try fail("answerAudit(\(sequence))")
        guard let audit = audits.first(where: { $0.sequence == sequence }) else {
            return .nothingPending
        }
        guard heldSegments.contains(audit.segmentId) else {
            return .missingSegment(sequence: sequence)
        }
        onEvent?(.auditAnswered(sequence: sequence, passed: true))
        return .answered(sequence: sequence)
    }

    public func signPresence(window: UInt64) throws {
        try fail("signPresence(\(window))")
        onEvent?(.presenceSigned(window: window))
    }
}
