//
//  PolicyEngine.swift
//  BudlumValidatorKit
//
//  The working policy of the iOS opportunistic validator. Directive 7.9.4 and
//  7.10, with the two iOS differences written where they apply.
//
//  # The two differences from the Android app
//
//  1. **Quota range.** The Android range is 1 to 64 GiB because that is the
//     app's quota manager. The iOS opportunistic class has a consensus ceiling
//     of 8 GiB (section 7.10 item 5,
//     `MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES`), so the iOS range is 1 to 8 GiB
//     and the ceiling is not a preference the user may raise.
//  2. **Power.** iOS never runs the validator on an unattended battery
//     (section 7.10 item 1). `PowerMode.any` therefore describes the
//     foreground and the background processing task still requires external
//     power (see `BackgroundDuty.swift`); the mode only decides whether the
//     app volunteers while it is open.
//
//  The thermal rule is not part of the user-editable policy: pausing at a
//  serious or critical thermal state is not changeable (risk R-35).
//

import Foundation

/// Which networks the validator may use.
public struct NetworkPolicy: Equatable, Sendable {
    /// Default: unmetered (Wi-Fi) only. Risk R-33.
    public var wifiOnly: Bool = true
    /// Daily mobile-data ceiling in MB. Consulted only when `wifiOnly` is
    /// false; `nil` means no ceiling.
    public var dailyMobileCapMb: Int?

    public init(wifiOnly: Bool = true, dailyMobileCapMb: Int? = nil) {
        self.wifiOnly = wifiOnly
        self.dailyMobileCapMb = dailyMobileCapMb
    }
}

/// When the validator volunteers to run while the app is open.
public enum PowerMode: String, CaseIterable, Codable, Sendable {
    /// Charging, or battery above 50% with low power mode off.
    case any
    /// Charging only.
    case chargingOnly
}

public struct PowerPolicy: Equatable, Sendable {
    public var mode: PowerMode = .any

    public init(mode: PowerMode = .any) {
        self.mode = mode
    }
}

/// How much of the device the validator may fill.
///
/// The range is 1 to 8 GiB: the low end is the app's own minimum and the high
/// end is the consensus ceiling of the iOS opportunistic class
/// (section 7.10 item 5). It is a `require`, not a clamp, because a quota
/// outside the range is a programming error and must be loud in a test.
public struct QuotaPolicy: Equatable, Sendable {
    public let quotaBytes: UInt64

    public init(quotaBytes: UInt64) {
        precondition(
            quotaBytes >= QuotaPolicy.minQuotaBytes && quotaBytes <= QuotaPolicy.maxQuotaBytes,
            "quota must be within 1 GiB..8 GiB (directive 7.10 item 5)"
        )
        self.quotaBytes = quotaBytes
    }

    /// The smallest quota the app offers: 1 GiB.
    public static let minQuotaBytes: UInt64 = 1 * 1024 * 1024 * 1024
    /// The largest quota the iOS opportunistic class may declare: 8 GiB.
    public static let maxQuotaBytes: UInt64 = ClassParameters.iosQuotaCeilingBytes
    /// The default: 4 GiB, the same default as Android (7.9.4).
    public static let defaultQuotaBytes: UInt64 = 4 * 1024 * 1024 * 1024
}

public struct SymbolPolicy: Equatable, Sendable {
    /// Default: serve symbols. Turning it off halves the storage reward
    /// (7.9.4).
    public var serveSymbols: Bool = true

    public init(serveSymbols: Bool = true) {
        self.serveSymbols = serveSymbols
    }
}

public struct AppPolicy: Equatable, Sendable {
    public var network: NetworkPolicy = NetworkPolicy()
    public var power: PowerPolicy = PowerPolicy()
    public var quota: QuotaPolicy = QuotaPolicy(quotaBytes: QuotaPolicy.defaultQuotaBytes)
    public var symbol: SymbolPolicy = SymbolPolicy()

    public init(
        network: NetworkPolicy = NetworkPolicy(),
        power: PowerPolicy = PowerPolicy(),
        quota: QuotaPolicy = QuotaPolicy(quotaBytes: QuotaPolicy.defaultQuotaBytes),
        symbol: SymbolPolicy = SymbolPolicy()
    ) {
        self.network = network
        self.power = power
        self.quota = quota
        self.symbol = symbol
    }

    /// The policy a freshly installed app shows on the registration screen.
    public static let `default` = AppPolicy()
}

/// The device state the engine decides on.
public struct DeviceState: Equatable, Sendable {
    /// Whether the current network path is metered (cellular or a hotspot).
    public var isMetered: Bool
    /// Mobile data used today, in MB.
    public var mobileUsedMbToday: UInt64
    /// Whether the device is on external power.
    public var isCharging: Bool
    /// Battery charge, 0 to 100.
    public var batteryPercent: Int
    /// Whether Low Power Mode is on.
    public var lowPowerModeOn: Bool
    /// `ProcessInfo.ProcessInfo.thermalState`.
    public var thermalState: ThermalState

    public init(
        isMetered: Bool = false,
        mobileUsedMbToday: UInt64 = 0,
        isCharging: Bool = false,
        batteryPercent: Int = 100,
        lowPowerModeOn: Bool = false,
        thermalState: ThermalState = .nominal
    ) {
        self.isMetered = isMetered
        self.mobileUsedMbToday = mobileUsedMbToday
        self.isCharging = isCharging
        self.batteryPercent = batteryPercent
        self.lowPowerModeOn = lowPowerModeOn
        self.thermalState = thermalState
    }
}

/// `ProcessInfo.ProcessInfoThermalState`, restated so the engine does not
/// import UIKit and so a test can name a state without a device.
public enum ThermalState: Int, CaseIterable, Codable, Sendable {
    case nominal = 0
    case fair = 1
    case serious = 2
    case critical = 3
}

/// Why the engine is not running the validator.
public enum RunDecision: String, Equatable, Sendable {
    case run
    /// Thermal state at or above serious. Not changeable (R-35).
    case pausedThermal
    case pausedNetwork
    case pausedPower
}

public enum PolicyEngine {
    /// Battery above this percent counts as "enough", with Low Power Mode off.
    public static let batteryPercentThreshold = 50

    /// The thermal state at or above which the validator pauses.
    public static let pauseThermalState: ThermalState = .serious

    /// Storage reward multiplier: symbol serving off halves the reward
    /// (7.9.4). Returned as a rational pair so nothing here is a float: the
    /// reward arithmetic is integer (G-2).
    public static func rewardMultiplierPermille(policy: AppPolicy) -> UInt64 {
        policy.symbol.serveSymbols ? 1000 : 500
    }

    /// Clamp a user-chosen quota into the range the class may declare.
    public static func clampQuota(bytes: UInt64) -> UInt64 {
        min(max(bytes, QuotaPolicy.minQuotaBytes), QuotaPolicy.maxQuotaBytes)
    }

    /// Decision order is binding: thermal first (immutable), then network,
    /// then power.
    public static func decision(policy: AppPolicy, state: DeviceState) -> RunDecision {
        if state.thermalState.rawValue >= pauseThermalState.rawValue {
            return .pausedThermal
        }
        if !networkAllowed(policy.network, state: state) {
            return .pausedNetwork
        }
        if !powerAllowed(policy.power, state: state) {
            return .pausedPower
        }
        return .run
    }

    public static func networkAllowed(_ network: NetworkPolicy, state: DeviceState) -> Bool {
        if !state.isMetered {
            return true
        }
        if network.wifiOnly {
            return false
        }
        guard let cap = network.dailyMobileCapMb else {
            return true
        }
        return state.mobileUsedMbToday < UInt64(cap)
    }

    public static func powerAllowed(_ power: PowerPolicy, state: DeviceState) -> Bool {
        switch power.mode {
        case .any:
            return state.isCharging
                || (state.batteryPercent > batteryPercentThreshold && !state.lowPowerModeOn)
        case .chargingOnly:
            return state.isCharging
        }
    }
}
