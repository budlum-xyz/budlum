//
//  DutyLogTests.swift
//  BudlumValidatorKitTests
//
//  The log format is the contract with `mobile/tools/log-analyzer`
//  (WP-37, PR #92). These tests exist so an iOS-only line cannot be added
//  silently: every line the app writes is one the analyzer counts, and a line
//  it does not know becomes `lines.unknown` in the field-test report.
//

import XCTest
@testable import BudlumValidatorKit

final class DutyLogTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("budlum-duty-log-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func log() -> DutyLog {
        DutyLog(directory: directory, now: { Date(timeIntervalSince1970: 1_762_000_000) })
    }

    /// Every decision the engine can make, in the spelling the analyzer reads.
    func test_decision_lines_match_the_analyzer_spelling() {
        let dutyLog = log()
        dutyLog.record(decision: .run)
        dutyLog.record(decision: .pausedThermal)
        dutyLog.record(decision: .pausedNetwork)
        dutyLog.record(decision: .pausedPower)
        XCTAssertEqual(dutyLog.lines(), [
            "1762000000000 RUN",
            "1762000000000 PAUSED_THERMAL",
            "1762000000000 PAUSED_NETWORK",
            "1762000000000 PAUSED_POWER",
        ])
    }

    func test_audit_and_battery_lines_match_the_analyzer_spelling() {
        let dutyLog = log()
        dutyLog.recordAudit(passed: true)
        dutyLog.recordAudit(passed: false)
        dutyLog.recordBattery(percent: 87)
        XCTAssertEqual(dutyLog.lines(), [
            "1762000000000 AUDIT pass",
            "1762000000000 AUDIT fail",
            "1762000000000 BATTERY 87",
        ])
    }

    /// A battery percent outside 0...255 would become an unknown line, so it is
    /// clamped at write time rather than lost.
    func test_battery_percent_is_clamped_into_one_byte() {
        let dutyLog = log()
        dutyLog.recordBattery(percent: -5)
        dutyLog.recordBattery(percent: 400)
        XCTAssertEqual(dutyLog.lines(), [
            "1762000000000 BATTERY 0",
            "1762000000000 BATTERY 255",
        ])
    }

    /// Appends survive across instances, which is what a background task needs:
    /// it opens the log, writes, exits, and the next task continues the file.
    func test_lines_append_across_instances() {
        log().record(decision: .run)
        log().record(decision: .pausedPower)
        XCTAssertEqual(log().lines(), [
            "1762000000000 RUN",
            "1762000000000 PAUSED_POWER",
        ])
    }

    func test_an_empty_log_reads_as_no_lines() {
        XCTAssertEqual(log().lines(), [])
    }

    /// The file name is the one the analyzer's documentation names.
    func test_file_name_is_duty_log() {
        XCTAssertEqual(DutyLog.fileName, "duty.log")
        XCTAssertEqual(log().logFile.lastPathComponent, "duty.log")
    }
}
