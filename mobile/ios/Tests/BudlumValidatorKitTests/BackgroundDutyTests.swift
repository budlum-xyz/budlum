//
//  BackgroundDutyTests.swift
//  BudlumValidatorKitTests
//
//  The background duty. Directive 7.10 items 1 and 4.
//

import XCTest
@testable import BudlumValidatorKit

final class BackgroundDutyTests: XCTestCase {
    private let segment = Data([0x0a, 0x1b, 0x2c, 0x3d])

    /// Directive 7.10 item 4: the background task answers an audit.
    ///
    /// This is the simulator acceptance test of the WP-38 card, written as a
    /// unit test of the duty rather than of `BGTaskScheduler`: the scheduler is
    /// platform glue that either submits a request or does not, and the part
    /// that can be wrong is the duty behind it. The scheduler's two required
    /// conditions are asserted in the test below, and the end-to-end simulator
    /// run is `mobile/ios/devicetests/README.md`.
    func test_ios_bg_task_answers_audit() throws {
        let core = FakeMobileCore()
        core.audits = [PendingAudit(sequence: 41, segmentId: segment, deadlineHeight: 900)]
        core.heldSegments = [segment]

        let report = try DutyRunner().run(
            core: core,
            policy: .default,
            state: DeviceState(isCharging: true, batteryPercent: 100),
            window: 7
        )

        XCTAssertEqual(report.decision, .run)
        XCTAssertEqual(report.answered, [41])
        XCTAssertTrue(report.presenceSigned)
        XCTAssertTrue(core.calls.contains("answerAudit(41)"))
        // Presence is signed last, so the signal witnesses a device that has
        // just answered rather than one that is about to try.
        XCTAssertTrue(
            core.calls.firstIndex(of: "answerAudit(41)")! < core.calls.firstIndex(of: "signPresence(7)")!
        )
    }

    /// Directive 7.10 item 4: the task requests external power and network
    /// connectivity. Both are required, not preferred.
    func test_bg_task_requires_external_power_and_network() {
        let task = BackgroundDutyTask.default
        XCTAssertTrue(task.requiresExternalPower)
        XCTAssertTrue(task.requiresNetworkConnectivity)
        XCTAssertEqual(BackgroundDutyTask.identifier, "dev.budlum.validator.duty")
    }

    /// A pass the policy paused answers nothing and signs nothing; the duty log
    /// records why the window produced nothing.
    func test_paused_pass_answers_nothing_and_signs_nothing() throws {
        let core = FakeMobileCore()
        core.audits = [PendingAudit(sequence: 41, segmentId: segment, deadlineHeight: 900)]
        core.heldSegments = [segment]

        // The iOS background duty runs on external power, so the pause that can
        // happen here is thermal or network.
        let report = try DutyRunner().run(
            core: core,
            policy: .default,
            state: DeviceState(isCharging: true, batteryPercent: 100, thermalState: .serious),
            window: 7
        )

        XCTAssertEqual(report.decision, .pausedThermal)
        XCTAssertTrue(report.answered.isEmpty)
        XCTAssertFalse(report.presenceSigned)
        XCTAssertFalse(core.calls.contains("answerAudit(41)"))
        XCTAssertFalse(core.calls.contains("signPresence(7)"))
    }

    /// A segment the device does not hold is reported as missing, not as a
    /// failure to answer. The network repairs; the validator is not penalised
    /// for a share it never took.
    func test_missing_segment_is_reported_not_failed() throws {
        let core = FakeMobileCore()
        core.audits = [PendingAudit(sequence: 42, segmentId: segment, deadlineHeight: 900)]

        let report = try DutyRunner().run(
            core: core,
            policy: .default,
            state: DeviceState(isCharging: true, batteryPercent: 100),
            window: 7
        )

        XCTAssertTrue(report.answered.isEmpty)
        XCTAssertEqual(report.missing, [42])
        XCTAssertTrue(report.presenceSigned, "a missing segment does not stop the presence signal")
    }

    /// Every outstanding audit is answered in one pass, not one per pass.
    func test_one_pass_answers_every_outstanding_audit() throws {
        let core = FakeMobileCore()
        let ids: [Data] = [
            Data([0x01]), Data([0x02]), Data([0x03]),
        ]
        core.audits = ids.enumerated().map { index, id in
            PendingAudit(sequence: UInt64(index + 1), segmentId: id, deadlineHeight: 900)
        }
        core.heldSegments = Set(ids)

        let report = try DutyRunner().run(
            core: core,
            policy: .default,
            state: DeviceState(isCharging: true, batteryPercent: 100),
            window: 7
        )

        XCTAssertEqual(report.answered, [1, 2, 3])
    }
}
