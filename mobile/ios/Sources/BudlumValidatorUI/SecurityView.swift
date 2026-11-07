//
//  SecurityView.swift
//  BudlumValidatorUI
//
//  The security page. Directive 7.9.6 item 3: the operator-key trade-off is
//  written in the app, not only in the repository.
//

import SwiftUI

@MainActor
public struct SecurityView: View {
    public init() {}

    public var body: some View {
        List {
            Section("Owner key") {
                Text("""
                    Your owner key (ML-DSA-87, 24 words) is your wallet. It is \
                    not stored by this app and it is never used without your \
                    confirmation. Only it can spend your stake.
                    """)
            }

            Section("Operator key") {
                Text("""
                    The operator key (ML-DSA-65) and the BLS asset key are \
                    generated on this device and wrapped with an AES-256-GCM \
                    key held in the iOS Keychain. The wrapping key is marked \
                    device-only: it is never included in a backup and never \
                    migrates to another device.
                    """)
            }

            Section("The trade-off") {
                Text("""
                    The operator key must be usable while the app is not in \
                    the foreground, so it is readable without a Face ID or \
                    passcode prompt. Someone who seizes this device while it \
                    is unlocked can sign duty transactions with it. They \
                    cannot spend your stake: spending needs the owner key, \
                    which is not here.
                    """)
            }

            Section("If you lose this device") {
                Text("""
                    Send RotateOperatorKey from your owner wallet on another \
                    device. The old operator key stops being accepted and no \
                    stake is lost.
                    """)
            }

            Section("What this app does not do") {
                Text("""
                    It does not mine, it does not run a persistent background \
                    connection, and it does not upload anything it was not \
                    given. Absence is never a fault: leaving or going offline \
                    never slashes a validator.
                    """)
            }
        }
        .navigationTitle("Security")
    }
}
