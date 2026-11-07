//
//  ValidatorClass.swift
//  BudlumValidatorKit
//
//  The validator class and the per-class numbers. Directive sections 7.2 and
//  7.10; mirrored from `crates/budlum-types/src/class.rs`.
//
//  # Where the truth lives
//
//  The source of truth is Rust: `ValidatorClass` in
//  `crates/budlum-types/src/class.rs` (WP-11, live on PR #44 for the `Address`
//  move and PR #91 for the class and presence message). The Rust crate is what
//  the node and the Android app read, and the iOS app reads it too through the
//  UniFFI surface in `MobileCoreBinding.swift`. Nothing here is a second
//  definition.
//
//  What this file holds is the *reference copy* used while the Rust crate is
//  not yet in this branch, and used by the tests to pin the numbers. Drift
//  between the two is not checked by hand:
//  `Scripts/check_class_parity.py` parses the Rust source, and the `mobile-ios`
//  workflow fails when the two disagree. It reports green with a written
//  reason while the crate is absent, so this branch is not blocked on WP-11.
//

import Foundation

/// The class of a validator. Wire tags are fixed: they enter the presence
/// message and the directory root, so they may never be renumbered.
public enum ValidatorClass: String, CaseIterable, Codable, Sendable {
    /// Runs every block, proposes, holds a finality seat.
    case full
    /// A phone: stores content, answers audits, holds no seat.
    case mobile
    /// An iPhone: the same duties, only while the app is open or charging.
    case mobileOpportunistic

    /// The byte written into signing preimages and the directory root.
    public var tag: UInt8 {
        switch self {
        case .full: return 0
        case .mobile: return 1
        case .mobileOpportunistic: return 2
        }
    }

    /// The class a tag names, or `nil` for a byte no class writes.
    public static func from(tag: UInt8) -> ValidatorClass? {
        allCases.first { $0.tag == tag }
    }

    /// Whether the class holds a consensus seat.
    public var holdsSeat: Bool {
        switch self {
        case .full: return true
        case .mobile, .mobileOpportunistic: return false
        }
    }
}

/// How the directive states an audit window: Full validators in epochs, phones
/// in hours (section 7.2).
public enum AuditWindow: Equatable, Sendable {
    case epochs(UInt64)
    case hours(UInt64)
}

/// The per-class parameters, as `crates/budlum-types/src/class.rs` defines
/// them. Every value below is asserted by `ClassParametersTests` and checked
/// against the Rust source by `Scripts/check_class_parity.py`.
public struct ClassParameters: Equatable, Sendable {
    /// The class these parameters describe.
    public let `class`: ValidatorClass

    /// The presence window, in epochs (section 7.8 item 1).
    public let presenceWindowEpochs: UInt64

    /// How long a validator may stay unseen before it is suspended (section
    /// 7.2). Suspension is not a slash (V-4).
    public let suspensionHours: UInt64

    /// The custody audit answer window (section 7.2).
    public let auditWindow: AuditWindow

    /// The largest custody quota the class may declare, if consensus sets a
    /// ceiling for it. Only the iOS opportunistic class has one; the Android
    /// range of 1 to 64 GiB is the app's quota manager, not a chain rule.
    public let maxCustodyQuotaBytes: UInt64?

    /// The reference table. Mirrors `ValidatorClass` in
    /// `crates/budlum-types/src/class.rs` item for item.
    public static let reference: [ValidatorClass: ClassParameters] = [
        .full: ClassParameters(
            class: .full,
            presenceWindowEpochs: 1,
            suspensionHours: 24,
            auditWindow: .epochs(2),
            maxCustodyQuotaBytes: nil
        ),
        .mobile: ClassParameters(
            class: .mobile,
            presenceWindowEpochs: 4,
            suspensionHours: 72,
            auditWindow: .hours(24),
            maxCustodyQuotaBytes: nil
        ),
        .mobileOpportunistic: ClassParameters(
            class: .mobileOpportunistic,
            presenceWindowEpochs: 4,
            suspensionHours: 168,
            auditWindow: .hours(48),
            maxCustodyQuotaBytes: ClassParameters.iosQuotaCeilingBytes
        ),
    ]

    /// The custody quota ceiling of an iOS opportunistic validator: 8 GiB
    /// (section 7.10 item 5). Consensus enforces this ceiling; the app only
    /// refuses to declare more.
    public static let iosQuotaCeilingBytes: UInt64 = 8 * 1024 * 1024 * 1024

    /// The parameters of one class.
    public static func parameters(for `class`: ValidatorClass) -> ClassParameters {
        // The table is exhaustive over a three-case enum; the fallback keeps
        // this a total function rather than a trapping subscript.
        reference[`class`] ?? ClassParameters(
            class: `class`,
            presenceWindowEpochs: 0,
            suspensionHours: 0,
            auditWindow: .epochs(0),
            maxCustodyQuotaBytes: nil
        )
    }

    /// The audit answer window in epochs. Hours are converted with section
    /// 6.21.3 item 2, `ceil(hours * 3600 / (slot * epoch length))`, in integer
    /// arithmetic only (G-2).
    public func auditWindowEpochs(slotMs: UInt64, epochLength: UInt64) -> UInt64 {
        switch auditWindow {
        case .epochs(let epochs):
            return epochs
        case .hours(let hours):
            return ClassParameters.hoursToEpochs(hours: hours, slotMs: slotMs, epochLength: epochLength)
        }
    }

    /// The suspension threshold in epochs (section 6.21.3).
    public func suspensionThresholdEpochs(slotMs: UInt64, epochLength: UInt64) -> UInt64 {
        ClassParameters.hoursToEpochs(hours: suspensionHours, slotMs: slotMs, epochLength: epochLength)
    }

    /// `ceil(hours * 3600 / (slot * epoch length))`, in `UInt128`-free integer
    /// arithmetic. A zero slot or a zero epoch length reads as one, so a broken
    /// parameter set yields a long window rather than a division by zero.
    public static func hoursToEpochs(hours: UInt64, slotMs: UInt64, epochLength: UInt64) -> UInt64 {
        let epochMs = UInt64(max(slotMs, 1)) * UInt64(max(epochLength, 1))
        let (windowMs, overflowed) = UInt64(hours).multipliedReportingOverflow(by: 3_600_000)
        if overflowed {
            return UInt64.max
        }
        let epoch = max(epochMs, 1)
        return windowMs / epoch + (windowMs % epoch == 0 ? 0 : 1)
    }
}
