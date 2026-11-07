//
//  DutyLog.swift
//  BudlumValidatorKit
//
//  The append-only duty log.
//
//  This file writes exactly the format `mobile/tools/log-analyzer`
//  (WP-37, PR #92) parses, so one analyzer reads both platforms:
//
//      <millis> RUN | PAUSED_THERMAL | PAUSED_NETWORK | PAUSED_POWER
//      <millis> AUDIT pass|fail
//      <millis> BATTERY <percent>
//
//  Nothing else is written. A line the analyzer does not recognise lands in
//  its `lines.unknown` counter, which is the reason the format is copied
//  rather than extended: an iOS-only line would silently become noise in the
//  field-test report.
//

import Foundation

/// Writes the duty log, one line per event.
public final class DutyLog: @unchecked Sendable {
    /// The file name, the same one the Android app uses.
    public static let fileName = "duty.log"

    private let file: URL
    private let lock = NSLock()
    private let now: () -> Date

    public init(directory: URL, now: @escaping () -> Date = Date.init) {
        self.file = directory.appendingPathComponent(DutyLog.fileName)
        self.now = now
    }

    /// Where the log is written.
    public var logFile: URL { file }

    /// Record one policy decision.
    public func record(decision: RunDecision) {
        append(line: "\(millis) \(logKind(decision))")
    }

    /// Record the outcome of one custody audit.
    public func recordAudit(passed: Bool) {
        append(line: "\(millis) AUDIT \(passed ? "pass" : "fail")")
    }

    /// Record a battery sample.
    public func recordBattery(percent: Int) {
        append(line: "\(millis) BATTERY \(max(0, min(percent, 255)))")
    }

    /// Every line written so far, oldest first.
    public func lines() -> [String] {
        guard let text = try? String(contentsOf: file, encoding: .utf8) else {
            return []
        }
        return text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    /// The `RunDecision` as the analyzer spells it.
    private func logKind(_ decision: RunDecision) -> String {
        switch decision {
        case .run: return "RUN"
        case .pausedThermal: return "PAUSED_THERMAL"
        case .pausedNetwork: return "PAUSED_NETWORK"
        case .pausedPower: return "PAUSED_POWER"
        }
    }

    private var millis: UInt64 {
        UInt64(max(now().timeIntervalSince1970, 0) * 1000)
    }

    /// Append one line under a lock and flush it, so a crash mid-write loses at
    /// most the line being written and never truncates an earlier one.
    private func append(line: String) {
        lock.lock()
        defer { lock.unlock() }
        let payload = line + "\n"
        guard let data = payload.data(using: .utf8) else {
            return
        }
        let manager = FileManager.default
        try? manager.createDirectory(
            at: file.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if !manager.fileExists(atPath: file.path) {
            try? data.write(to: file, options: .atomic)
            return
        }
        guard let handle = try? FileHandle(forWritingTo: file) else {
            return
        }
        defer { try? handle.close() }
        try? handle.seekToEnd()
        try? handle.write(contentsOf: data)
    }
}
