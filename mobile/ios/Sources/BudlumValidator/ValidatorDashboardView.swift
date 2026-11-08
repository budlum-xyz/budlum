#if canImport(SwiftUI)
import SwiftUI

/// Read-only onboarding/dashboard shell. Registration stays disabled until a
/// production mobile-core adapter is connected; a local boolean is not an
/// on-chain registration or unbonding receipt.
@available(iOS 16.0, macOS 13.0, *)
public struct ValidatorDashboardView: View {
    @State private var locale: ValidatorLocale = .english
    @State private var quotaGib: Double = 4.0

    public init() {}

    public var body: some View {
        let strings = LocalizedStrings.resolve(locale)
        VStack(alignment: .leading, spacing: 14) {
            Text(strings.title)
                .font(.title2)
                .bold()
            Text(strings.classBadge)
                .font(.subheadline)
            Text(strings.custodyDisclosure)
                .font(.body)
            Slider(value: $quotaGib, in: 1...8, step: 1)
            Text("Custody Quota: \(Int(quotaGib)) GiB (Cap: 8 GiB)")
            Text(strings.coreUnavailable)
                .font(.footnote)
            Button(strings.registerAction) {}
                .disabled(true)
        }
        .padding(20)
    }
}
#endif
