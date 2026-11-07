import Foundation

/// Bilingual localization bundle (EN and TR) for the iOS `MobileOpportunistic` app
/// (Section 7.10,  item 5).
///
/// Turkish codepoints are represented with explicit Unicode scalar escapes so source
/// files remain pure ASCII across repository-wide lint gates.
public enum ValidatorLocale: String, Sendable {
    case english = "en"
    case turkish = "tr"
}

public struct LocalizedStrings: Sendable {
    public let title: String
    public let classBadge: String
    public let custodyDisclosure: String
    public let registerAction: String
    public let leaveAction: String

    public static func resolve(_ locale: ValidatorLocale) -> LocalizedStrings {
        switch locale {
        case .english:
            return LocalizedStrings(
                title: "Budlum Opportunistic Validator",
                classBadge: "Class: MobileOpportunistic (Max 8 GiB, 48h Audit Window)",
                custodyDisclosure: "Runs during overnight Wi-Fi charging via iOS Background Processing. Stores erasure-coded B.U.D. 3.0 shares excluded from iCloud backup. Zero cryptocurrency mining runs on this iPhone.",
                registerAction: "Create 24-Word Wallet & Enable Opportunistic Custody",
                leaveAction: "Leave & Release Custody Shares (Unbond)"
            )
        case .turkish:
            return LocalizedStrings(
                title: "Budlum F\u{0131}rsat\u{00E7}\u{0131} Validator",
                classBadge: "S\u{0131}n\u{0131}f: MobileOpportunistic (En fazla 8 GiB, 48s Denetim)",
                custodyDisclosure: "Gece Wi-Fi ve \u{015F}arj s\u{0131}ras\u{0131}nda iOS Arka Plan g\u{00F6}reviyle \u{00E7}al\u{0131}\u{015F}\u{0131}r. iCloud yede\u{011F}i d\u{0131}\u{015F}\u{0131}nda B.U.D. 3.0 paylar\u{0131} tutar; cihazda madencilik yap\u{0131}lmaz.",
                registerAction: "24 Kelime C\u{00FC}zdan & Validator Etkinle\u{015F}tir",
                leaveAction: "Ayr\u{0131}l & Paylar\u{0131} B\u{0131}rak (Stake \u{00C7}\u{00F6}z)"
            )
        }
    }
}
