//
//  PolicyEngineTests.swift
//  BudlumValidatorKitTests
//

import XCTest
@testable import BudlumValidatorKit

final class PolicyEngineTests: XCTestCase {
    /// Unmetered (Wi-Fi) only is the default. Risk R-33.
    func test_wifi_only_is_the_default() {
        let policy = AppPolicy.default
        XCTAssertTrue(policy.network.wifiOnly)
        XCTAssertFalse(PolicyEngine.networkAllowed(
            policy.network,
            state: DeviceState(isMetered: true)
        ))
        XCTAssertTrue(PolicyEngine.networkAllowed(
            policy.network,
            state: DeviceState(isMetered: false)
        ))
    }

    /// The daily mobile-data ceiling is consulted only when Wi-Fi-only is off.
    func test_daily_mobile_cap_applies_only_when_cellular_is_allowed() {
        var policy = NetworkPolicy(wifiOnly: false, dailyMobileCapMb: 100)
        XCTAssertTrue(PolicyEngine.networkAllowed(policy, state: DeviceState(isMetered: true, mobileUsedMbToday: 99)))
        XCTAssertFalse(PolicyEngine.networkAllowed(policy, state: DeviceState(isMetered: true, mobileUsedMbToday: 100)))
        policy.dailyMobileCapMb = nil
        XCTAssertTrue(PolicyEngine.networkAllowed(policy, state: DeviceState(isMetered: true, mobileUsedMbToday: 100)))
    }

    /// The thermal pause is not a user-editable policy (R-35): it is applied
    /// from the device state alone and no policy can turn it off.
    func test_thermal_pause_cannot_be_disabled() {
        let hot = DeviceState(thermalState: .serious)
        for mode in PowerMode.allCases {
            for wifiOnly in [true, false] {
                let policy = AppPolicy(
                    network: NetworkPolicy(wifiOnly: wifiOnly),
                    power: PowerPolicy(mode: mode),
                    quota: QuotaPolicy(quotaBytes: QuotaPolicy.defaultQuotaBytes),
                    symbol: SymbolPolicy()
                )
                XCTAssertEqual(
                    PolicyEngine.decision(policy: policy, state: hot),
                    .pausedThermal,
                    "no policy may unpause a serious thermal state"
                )
            }
        }
        // `.nominal` and `.fair` both run.
        XCTAssertEqual(
            PolicyEngine.decision(policy: .default, state: DeviceState(thermalState: .fair)),
            .run
        )
    }

    /// Decision order is binding: thermal, then network, then power.
    func test_decision_order_is_thermal_then_network_then_power() {
        let hot = DeviceState(isMetered: true, thermalState: .critical)
        XCTAssertEqual(PolicyEngine.decision(policy: .default, state: hot), .pausedThermal)

        let metered = DeviceState(isMetered: true, isCharging: true)
        XCTAssertEqual(PolicyEngine.decision(policy: .default, state: metered), .pausedNetwork)

        let low = DeviceState(isCharging: false, batteryPercent: 10)
        XCTAssertEqual(PolicyEngine.decision(policy: .default, state: low), .pausedPower)
    }

    func test_power_modes() {
        let charging = DeviceState(isCharging: true, batteryPercent: 5)
        let halfCharged = DeviceState(isCharging: false, batteryPercent: 51)
        let lowPower = DeviceState(isCharging: false, batteryPercent: 90, lowPowerModeOn: true)

        XCTAssertTrue(PolicyEngine.powerAllowed(PowerPolicy(mode: .any), state: charging))
        XCTAssertTrue(PolicyEngine.powerAllowed(PowerPolicy(mode: .any), state: halfCharged))
        XCTAssertFalse(PolicyEngine.powerAllowed(PowerPolicy(mode: .any), state: lowPower))
        XCTAssertTrue(PolicyEngine.powerAllowed(PowerPolicy(mode: .chargingOnly), state: charging))
        XCTAssertFalse(PolicyEngine.powerAllowed(PowerPolicy(mode: .chargingOnly), state: halfCharged))
    }

    /// The iOS quota range is 1 to 8 GiB: the app minimum, and the consensus
    /// ceiling of the opportunistic class (section 7.10 item 5).
    func test_quota_range_is_one_to_eight_gib() {
        XCTAssertEqual(QuotaPolicy.minQuotaBytes, 1 * 1024 * 1024 * 1024)
        XCTAssertEqual(QuotaPolicy.maxQuotaBytes, 8 * 1024 * 1024 * 1024)
        XCTAssertEqual(QuotaPolicy.defaultQuotaBytes, 4 * 1024 * 1024 * 1024)
        XCTAssertEqual(PolicyEngine.clampQuota(bytes: 512 * 1024 * 1024), QuotaPolicy.minQuotaBytes)
        XCTAssertEqual(PolicyEngine.clampQuota(bytes: 64 * 1024 * 1024 * 1024), QuotaPolicy.maxQuotaBytes)
        XCTAssertEqual(PolicyEngine.clampQuota(bytes: 2 * 1024 * 1024 * 1024), 2 * 1024 * 1024 * 1024)
    }

    /// Symbol serving off halves the reward. Returned in permille, never as a
    /// float: the reward arithmetic is integer (G-2).
    func test_symbol_serving_off_halves_the_reward() {
        XCTAssertEqual(PolicyEngine.rewardMultiplierPermille(policy: .default), 1000)
        var off = AppPolicy.default
        off.symbol.serveSymbols = false
        XCTAssertEqual(PolicyEngine.rewardMultiplierPermille(policy: off), 500)
    }
}
