//
//  OnboardingView.swift
//  BudlumValidatorUI
//
//  Setup and registration. Directive 7.9.9 items 1, 2 and 5, and 7.10 item 7.
//
//  The registration screen carries the two statements the directive requires
//  on it, not behind a link:
//
//  * what the phone stores (7.9.9 item 5);
//  * that the app does not mine on the device (7.10 item 7, risk R-22).
//

import BudlumValidatorKit
import SwiftUI

@MainActor
public struct OnboardingView: View {
    @ObservedObject var model: ValidatorModel
    @State private var quotaBytes: UInt64 = QuotaPolicy.defaultQuotaBytes

    public init(model: ValidatorModel) {
        self.model = model
    }

    public var body: some View {
        Form {
            Section {
                Text(Strings.welcome)
                    .font(.headline)
                Text(Strings.iosPlatformLimit)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Section("What this phone stores") {
                Text(Strings.storageDisclosure)
            }

            Section("No mining on this device") {
                Text(Strings.noMiningStatement)
            }

            Section("Storage quota") {
                QuotaPicker(quotaBytes: $quotaBytes)
                Text(String(
                    format: Strings.quotaCeilingNote,
                    ByteCountFormatter.string(
                        fromByteCount: Int64(ClassParameters.iosQuotaCeilingBytes),
                        countStyle: .binary
                    )
                ))
                .font(.footnote)
                .foregroundStyle(.secondary)
            }

            Section("When the validator runs") {
                Toggle("Wi-Fi only", isOn: Binding(
                    get: { model.policy.network.wifiOnly },
                    set: { model.policy.network.wifiOnly = $0 }
                ))
                Toggle("Serve symbols to the network", isOn: Binding(
                    get: { model.policy.symbol.serveSymbols },
                    set: { model.policy.symbol.serveSymbols = $0 }
                ))
                Text(Strings.symbolServingNote)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Picker("Power", selection: Binding(
                    get: { model.policy.power.mode },
                    set: { model.policy.power.mode = $0 }
                )) {
                    Text("Charging, or battery above 50%").tag(PowerMode.any)
                    Text("Charging only").tag(PowerMode.chargingOnly)
                }
            }

            Section {
                Button {
                    model.register(quotaBytes: quotaBytes)
                } label: {
                    Text(Strings.registerButton)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            } footer: {
                Text(Strings.registrationStakeNote)
            }

            if let error = model.lastError {
                Section {
                    Text(error)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Budlum Validator")
    }
}

/// A quota slider over the whole range the iOS class may declare.
@MainActor
public struct QuotaPicker: View {
    @Binding var quotaBytes: UInt64

    public init(quotaBytes: Binding<UInt64>) {
        self._quotaBytes = quotaBytes
    }

    public var body: some View {
        VStack(alignment: .leading) {
            Slider(
                value: Binding(
                    get: { Double(quotaBytes) },
                    set: { quotaBytes = PolicyEngine.clampQuota(bytes: UInt64($0)) }
                ),
                in: Double(QuotaPolicy.minQuotaBytes)...Double(QuotaPolicy.maxQuotaBytes),
                step: Double(256 * 1024 * 1024)
            )
            Text(ByteCountFormatter.string(fromByteCount: Int64(quotaBytes), countStyle: .binary))
        }
    }
}

public enum Strings {
    public static let welcome = """
        Turn this iPhone into a Budlum validator. It stores pieces of content, \
        answers the network's audits of what it stores, and earns a share of \
        the storage reward.
        """

    public static let iosPlatformLimit = """
        iOS does not keep a network connection open while the app is closed. \
        The validator works while the app is open, and answers audits through \
        the system's background processing task while the phone is charging. \
        It earns less than an Android validator, by design.
        """

    /// Directive 7.9.9 item 5.
    public static let storageDisclosure = """
        Your phone stores content pieces. These pieces alone do not reveal the \
        content. Public content is everyone's content; sealed content is \
        encrypted.
        """

    /// Directive 7.10 item 7, risk R-22.
    public static let noMiningStatement = """
        This app does not mine. It performs no proof-of-work, no repeated \
        hashing and no computation for its own sake. It stores data it was \
        given and answers questions about that data. Nothing runs on battery \
        in the background.
        """

    public static let quotaCeilingNote = """
        The opportunistic class may declare at most %@ of storage. This is a \
        network rule, not an app preference.
        """

    public static let symbolServingNote = """
        Turning symbol serving off halves the storage reward.
        """

    public static let registerButton = "Register this device"

    public static let registrationStakeNote = """
        Registration is a transaction and bonds 10 BUD. Leaving releases the \
        shares you hold and starts unbonding; unbonded stake returns to its \
        owner when the unbonding period ends.
        """
}
