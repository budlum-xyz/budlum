//
//  BackgroundDuty.swift
//  BudlumValidatorKit
//
//  Background duty. Directive 7.10 items 1 and 4.
//
//  # The platform limit, stated rather than worked around
//
//  iOS does not allow a persistent background network connection. That is a
//  platform limit, not a bug: no amount of scheduling turns a suspended app
//  into a listening peer, and this file does not claim otherwise. What iOS
//  offers is `BGProcessingTaskRequest`, which the system runs at its own
//  discretion, usually while the device is charging and idle. So:
//
//  * while the app is open: shares are taken, symbols are served, audits are
//    answered, the presence signal is published (7.10 item 3);
//  * while the app is not open: the background task answers audits and
//    publishes the presence signal, and nothing else (7.10 item 4).
//
//  The task requests external power and network connectivity. Both are
//  required, not preferred: an audit answered over a metered path on a
//  discharging phone is a worse outcome than an audit answered late, and the
//  class suspension threshold of seven days (section 7.10 item 5) is what
//  absorbs the lateness.
//
//  The duty itself lives in `DutyRunner`, which talks to `MobileCore` and
//  knows nothing about `BGTaskScheduler`. That split is what makes
//  `ios_bg_task_answers_audit` a unit test rather than a simulator-only
//  integration test: the scheduler is ten lines of platform glue, the duty is
//  the part that can be wrong.
//

import Foundation
#if canImport(BackgroundTasks) && !os(macOS)
import BackgroundTasks
#endif

/// The registration of the background processing task.
public struct BackgroundDutyTask: Equatable, Sendable {
    /// The identifier registered under `BGTaskSchedulerPermittedIdentifiers`.
    public static let identifier = "dev.budlum.validator.duty"

    /// External power is required, not preferred (7.10 item 4).
    public let requiresExternalPower: Bool
    /// Network connectivity is required (7.10 item 4).
    public let requiresNetworkConnectivity: Bool

    /// The task as directive 7.10 item 4 specifies it.
    public static let `default` = BackgroundDutyTask(
        requiresExternalPower: true,
        requiresNetworkConnectivity: true
    )

    public init(requiresExternalPower: Bool, requiresNetworkConnectivity: Bool) {
        self.requiresExternalPower = requiresExternalPower
        self.requiresNetworkConnectivity = requiresNetworkConnectivity
    }
}

/// What one duty pass did.
public struct DutyReport: Equatable, Sendable {
    /// The decision the policy engine made before the pass started.
    public let decision: RunDecision
    /// Audit sequences answered.
    public let answered: [UInt64]
    /// Audit sequences the device could not answer because it does not hold
    /// the segment. Not a fault: the network repairs and the validator is not
    /// penalised for a share it never took.
    public let missing: [UInt64]
    /// Whether the presence signal was signed.
    public let presenceSigned: Bool

    public init(
        decision: RunDecision,
        answered: [UInt64],
        missing: [UInt64],
        presenceSigned: Bool
    ) {
        self.decision = decision
        self.answered = answered
        self.missing = missing
        self.presenceSigned = presenceSigned
    }

    /// A pass that did nothing because the policy paused the validator.
    public static func paused(_ decision: RunDecision) -> DutyReport {
        DutyReport(decision: decision, answered: [], missing: [], presenceSigned: false)
    }
}

/// Runs one duty pass: answer every outstanding audit, then sign presence.
public struct DutyRunner: Sendable {
    public init() {}

    /// Perform one pass.
    ///
    /// The order is binding: presence is signed last, so the signal reflects a
    /// device that has just answered rather than one that is about to try.
    /// A pass that the policy paused answers nothing and signs nothing; the
    /// decision is recorded in the report so the duty log shows *why* the
    /// window produced nothing.
    public func run(
        core: MobileCore,
        policy: AppPolicy,
        state: DeviceState,
        window: UInt64
    ) throws -> DutyReport {
        let decision = PolicyEngine.decision(policy: policy, state: state)
        guard decision == .run else {
            return .paused(decision)
        }

        var answered: [UInt64] = []
        var missing: [UInt64] = []
        for audit in try core.pendingAudits() {
            switch try core.answerAudit(sequence: audit.sequence) {
            case .answered(let sequence):
                answered.append(sequence)
            case .missingSegment(let sequence):
                missing.append(sequence)
            case .nothingPending:
                break
            }
        }

        try core.signPresence(window: window)
        return DutyReport(
            decision: .run,
            answered: answered,
            missing: missing,
            presenceSigned: true
        )
    }
}

#if canImport(BackgroundTasks) && !os(macOS)
/// The `BGTaskScheduler` glue. Ten lines on purpose: everything that can be
/// wrong is in `DutyRunner`.
public enum BackgroundDutyScheduler {
    /// Register the task and install its handler.
    ///
    /// Returns `false` when the system refused the registration, which happens
    /// when the identifier is missing from `BGTaskSchedulerPermittedIdentifiers`
    /// in the app's `Info.plist`. The launcher is a closure so a test may
    /// observe it without a scheduler.
    @discardableResult
    public static func register(
        task: BackgroundDutyTask = .default,
        handler: @escaping @Sendable () -> Void
    ) -> Bool {
        let ok = BGTaskScheduler.shared.register(
            forTaskWithIdentifier: BackgroundDutyTask.identifier,
            using: nil
        ) { bgTask in
            handler()
            bgTask.setTaskCompleted(success: true)
            schedule(task: task)
        }
        if ok {
            schedule(task: task)
        }
        return ok
    }

    /// Submit the next request.
    public static func schedule(task: BackgroundDutyTask = .default) {
        let request = BGProcessingTaskRequest(identifier: BackgroundDutyTask.identifier)
        request.requiresExternalPower = task.requiresExternalPower
        request.requiresNetworkConnectivity = task.requiresNetworkConnectivity
        // Not an assertion of a time: the system decides when to run it. The
        // call exists so the request is in the queue at all.
        try? BGTaskScheduler.shared.submit(request)
    }
}
#endif
