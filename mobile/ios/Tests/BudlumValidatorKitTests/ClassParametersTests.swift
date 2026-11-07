//
//  ClassParametersTests.swift
//  BudlumValidatorKitTests
//
//  The per-class numbers of directive sections 7.2 and 7.10.
//
//  These values are consensus numbers, not app constants. They are mirrored
//  from `crates/budlum-types/src/class.rs`; `Scripts/check_class_parity.py`
//  fails when the Rust source and this file disagree, so a test that passes
//  here and a parity check that passes in CI together say the phone and the
//  node read the same table.
//

import XCTest
@testable import BudlumValidatorKit

final class ClassParametersTests: XCTestCase {
    /// Testnet profile: 3 s slots, 50-slot epochs (`src/core/chain_config.rs`).
    private let slotMs: UInt64 = 3_000
    private let epochLength: UInt64 = 50

    /// Directive 7.10 item 5: the iOS app registers the opportunistic class.
    ///
    /// Not a preference and not a setting: iOS cannot hold a persistent
    /// connection, so the class is a property of the platform.
    func test_ios_class_is_opportunistic() {
        let `class` = ValidatorClass.mobileOpportunistic
        XCTAssertEqual(`class`.tag, 2)
        XCTAssertEqual(ValidatorClass.from(tag: 2), .mobileOpportunistic)
        XCTAssertFalse(`class`.holdsSeat, "no phone class holds a finality seat")
        XCTAssertTrue(ValidatorClass.full.holdsSeat)
        XCTAssertFalse(ValidatorClass.mobile.holdsSeat)
    }

    /// Directive 7.10 item 5: the custody quota ceiling is 8 GiB.
    func test_ios_quota_cap_is_8_gib() {
        XCTAssertEqual(ClassParameters.iosQuotaCeilingBytes, 8 * 1024 * 1024 * 1024)
        let parameters = ClassParameters.parameters(for: .mobileOpportunistic)
        XCTAssertEqual(parameters.maxCustodyQuotaBytes, 8 * 1024 * 1024 * 1024)
        // The app's own range ends where the class ceiling is, so the UI can
        // never offer a quota the node would refuse.
        XCTAssertEqual(QuotaPolicy.maxQuotaBytes, ClassParameters.iosQuotaCeilingBytes)
        // No other class has a consensus ceiling.
        XCTAssertNil(ClassParameters.parameters(for: .full).maxCustodyQuotaBytes)
        XCTAssertNil(ClassParameters.parameters(for: .mobile).maxCustodyQuotaBytes)
    }

    /// The tags are wire bytes: they enter the presence message and the
    /// directory root, so they may never be renumbered.
    func test_class_tags_are_fixed_wire_bytes() {
        XCTAssertEqual(ValidatorClass.full.tag, 0)
        XCTAssertEqual(ValidatorClass.mobile.tag, 1)
        XCTAssertEqual(ValidatorClass.mobileOpportunistic.tag, 2)
        for `class` in ValidatorClass.allCases {
            XCTAssertEqual(ValidatorClass.from(tag: `class`.tag), `class`)
        }
        XCTAssertNil(ValidatorClass.from(tag: 3))
    }

    /// Section 7.2: one day, 72 hours, seven days. Suspension is not a slash
    /// (V-4), so the numbers only decide when a validator stops being counted.
    func test_suspension_thresholds_follow_section_7_2() {
        for `class` in ValidatorClass.allCases {
            let parameters = ClassParameters.parameters(for: `class`)
            XCTAssertEqual(
                parameters.suspensionThresholdEpochs(slotMs: slotMs, epochLength: epochLength),
                expectedSuspensionEpochs[`class`],
                "suspension threshold of \(`class`)"
            )
        }
        XCTAssertEqual(ClassParameters.parameters(for: .mobileOpportunistic).suspensionHours, 168)
    }

    /// Section 7.2: two epochs for a Full validator, 24 hours for an Android
    /// phone, 48 hours for an iPhone.
    func test_audit_windows_follow_section_7_2() {
        XCTAssertEqual(ClassParameters.parameters(for: .full).auditWindow, .epochs(2))
        XCTAssertEqual(ClassParameters.parameters(for: .mobile).auditWindow, .hours(24))
        XCTAssertEqual(ClassParameters.parameters(for: .mobileOpportunistic).auditWindow, .hours(48))
        XCTAssertEqual(
            ClassParameters.parameters(for: .mobileOpportunistic)
                .auditWindowEpochs(slotMs: slotMs, epochLength: epochLength),
            1_152
        )
    }

    /// Section 7.8 item 1: the presence window is one epoch for a Full
    /// validator and four for both phone classes.
    func test_presence_windows_follow_section_7_8() {
        XCTAssertEqual(ClassParameters.parameters(for: .full).presenceWindowEpochs, 1)
        XCTAssertEqual(ClassParameters.parameters(for: .mobile).presenceWindowEpochs, 4)
        XCTAssertEqual(ClassParameters.parameters(for: .mobileOpportunistic).presenceWindowEpochs, 4)
    }

    /// The conversion rounds up, and a broken parameter set yields a long
    /// window rather than a division by zero (G-2, section 6.21.3).
    func test_hours_to_epochs_rounds_up_and_never_divides_by_zero() {
        XCTAssertEqual(ClassParameters.hoursToEpochs(hours: 1, slotMs: 7_000, epochLength: 50), 11)
        XCTAssertEqual(ClassParameters.hoursToEpochs(hours: 0, slotMs: slotMs, epochLength: epochLength), 0)
        XCTAssertEqual(ClassParameters.hoursToEpochs(hours: 1, slotMs: 0, epochLength: 0), 3_600_000)
        XCTAssertEqual(
            ClassParameters.hoursToEpochs(hours: UInt64.max, slotMs: 1, epochLength: 1),
            UInt64.max
        )
    }

    private let expectedSuspensionEpochs: [ValidatorClass: UInt64] = [
        .full: 576,
        .mobile: 1_728,
        .mobileOpportunistic: 4_032,
    ]
}
