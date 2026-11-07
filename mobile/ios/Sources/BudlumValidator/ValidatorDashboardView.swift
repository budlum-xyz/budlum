#if canImport(SwiftUI)
import SwiftUI

/// SwiftUI onboarding, dashboard, earnings, quota, and graceful `Leave` view for
/// the iOS `MobileOpportunistic` validator ( item 5).
@available(iOS 16.0, macOS 13.0, *)
public struct ValidatorDashboardView: View {
    @State private var locale: ValidatorLocale = .english
    @State private var isRegistered: Bool = false
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

            if !isRegistered {
                Button(strings.registerAction) {
                    isRegistered = true
                }
            } else {
                Button(strings.leaveAction) {
                    isRegistered = false
                }
            }
        }
        .padding(20)
    }
}
#endif
