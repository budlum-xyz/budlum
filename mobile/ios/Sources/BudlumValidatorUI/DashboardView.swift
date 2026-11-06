//
//  DashboardView.swift
//  BudlumValidatorUI
//
//  The running dashboard. Directive 7.9.9 item 3: stored bytes, audit results,
//  reward and connection state.
//

import BudlumValidatorKit
import SwiftUI

@MainActor
public struct DashboardView: View {
    @ObservedObject var model: ValidatorModel

    public init(model: ValidatorModel) {
        self.model = model
    }

    public var body: some View {
        List {
            Section("This device") {
                row("Class", "Opportunistic (iOS)")
                row("Seat", model.validatorClass.holdsSeat ? "Yes" : "No")
                row("Quota", ByteCountFormatter.string(
                    fromByteCount: Int64(model.policy.quota.quotaBytes),
                    countStyle: .binary
                ))
                row("Suspension after", "\(ClassParameters.parameters(for: .mobileOpportunistic).suspensionHours) h unseen")
                row("Audit window", "\(auditWindowText) h")
            }

            Section("Storage") {
                row("Stored", ByteCountFormatter.string(
                    fromByteCount: Int64(model.status.storedBytes),
                    countStyle: .binary
                ))
                row("Last audit", lastAuditText)
                row("Connection", model.status.connected ? "connected" : "disconnected")
            }

            Section("Reward") {
                row("Claimable", "\(model.status.claimableRewards)")
                Button("Claim") {
                    model.claim()
                }
            }

            Section("Recent events") {
                if model.events.isEmpty {
                    Text("none yet").foregroundStyle(.secondary)
                } else {
                    ForEach(Array(model.events.suffix(20).enumerated()), id: \.offset) { _, event in
                        Text(eventText(event))
                            .font(.footnote)
                    }
                }
            }

            Section {
                NavigationLink("Security and keys") {
                    SecurityView()
                }
                Button(role: .destructive) {
                    model.leave()
                } label: {
                    Text("Leave the network")
                }
            } footer: {
                Text("Leaving releases the shares this device holds and starts unbonding your stake. The network is not harmed: absence is never a fault.")
            }

            if let error = model.lastError {
                Section {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Validator")
        .onAppear(perform: model.refresh)
    }

    private var auditWindowText: String {
        switch ClassParameters.parameters(for: .mobileOpportunistic).auditWindow {
        case .epochs(let epochs): return "\(epochs) epochs"
        case .hours(let hours): return "\(hours)"
        }
    }

    private var lastAuditText: String {
        guard let sequence = model.status.lastAuditSequence else {
            return "none yet"
        }
        guard let passed = model.status.lastAuditPassed else {
            return "#\(sequence)"
        }
        return "#\(sequence) \(passed ? "pass" : "fail")"
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value).foregroundStyle(.secondary)
        }
    }

    private func eventText(_ event: CoreEvent) -> String {
        switch event {
        case .started: return "started"
        case .stopped: return "stopped"
        case .shareStored(let segmentId, let bytes):
            return "share stored \(segmentId.hexPrefix) (\(bytes) bytes)"
        case .shareReleased(let segmentId):
            return "share released \(segmentId.hexPrefix)"
        case .auditAnswered(let sequence, let passed):
            return "audit #\(sequence) \(passed ? "pass" : "fail")"
        case .presenceSigned(let window):
            return "presence signed for window \(window)"
        case .finalityRejected(_, let reason):
            return "finality rejected: \(reason)"
        }
    }
}

extension Data {
    /// The first four bytes of a segment id, enough to tell two ids apart on a
    /// phone screen.
    fileprivate var hexPrefix: String {
        prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
