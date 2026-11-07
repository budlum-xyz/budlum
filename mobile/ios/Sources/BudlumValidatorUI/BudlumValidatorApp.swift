//
//  BudlumValidatorApp.swift
//  BudlumValidatorUI
//
//  The iOS opportunistic validator. Directive 7.10.
//
//  The app is deliberately small. Everything it can do wrong is in
//  `BudlumValidatorKit`, which the `mobile-ios` workflow unit-tests on every
//  push; this target is the SwiftUI shell around it.
//

import BudlumValidatorKit
import SwiftUI

/// The state the views share.
@MainActor
public final class ValidatorModel: ObservableObject {
    /// The policy the user chose.
    @Published public var policy: AppPolicy = .default
    /// The last status the core reported.
    @Published public var status: CoreStatus = .idle
    /// Every event the core has emitted, newest last.
    @Published public var events: [CoreEvent] = []
    /// Whether the validator has been registered on this device.
    @Published public var isRegistered = false
    /// The last error, shown on the dashboard until it is dismissed.
    @Published public var lastError: String?

    /// The core this model drives. The shipped app replaces it with an adapter
    /// over the UniFFI-generated module; the previews use the fake.
    private let core: MobileCore

    public init(core: MobileCore) {
        self.core = core
        core.onEvent = { [weak self] event in
            Task { @MainActor in
                self?.events.append(event)
            }
        }
    }

    /// The class this device registers as. iOS is always the opportunistic
    /// class (section 7.10 item 5); there is no user-visible choice, because
    /// the choice is made by the platform, not by preference.
    public var validatorClass: ValidatorClass { .mobileOpportunistic }

    public func refresh() {
        do {
            status = try core.status()
            lastError = nil
        } catch let error as MobileCoreError {
            lastError = String(describing: error)
        } catch {
            lastError = error.localizedDescription
        }
    }

    public func register(quotaBytes: UInt64) {
        do {
            try core.setPolicy(policy)
            try core.registerValidator(class: validatorClass, quotaBytes: quotaBytes)
            isRegistered = true
            lastError = nil
            refresh()
        } catch let error as MobileCoreError {
            lastError = String(describing: error)
        } catch {
            lastError = error.localizedDescription
        }
    }

    public func claim() {
        do {
            try core.claimRewards()
            lastError = nil
            refresh()
        } catch let error as MobileCoreError {
            lastError = String(describing: error)
        } catch {
            lastError = error.localizedDescription
        }
    }

    public func leave() {
        do {
            try core.leave()
            isRegistered = false
            lastError = nil
        } catch let error as MobileCoreError {
            lastError = String(describing: error)
        } catch {
            lastError = error.localizedDescription
        }
    }
}

/// The app entry point.
///
/// No `@main` here on purpose: this module is a library, and `@main` belongs in
/// the module that owns the top level code, which is the Xcode app target that
/// wraps `Sources/BudlumValidatorUI` (WP-38 2/N). Keeping the attribute out is
/// what lets `swift test` build this package on a runner with no app target at
/// all.
public struct BudlumValidatorApp: App {
    public init() {}

    public var body: some Scene {
        WindowGroup {
            RootView(model: ValidatorModel(core: ProductionCore.shared))
                .onAppear {
                    // The task is registered as early as the scene allows. In the
                    // Xcode app target this moves into the app delegate, which is the
                    // only place `BGTaskScheduler` accepts a registration before the
                    // first scene; both call the same `register` below.
                    ProductionCore.shared.registerBackgroundDuty()
                }
        }
    }
}

/// Adapter over the UniFFI-generated module.
///
/// `budlum-mobile-core` (WP-36 2/N) generates `BudlumMobileCoreFFI`. Until
/// that module is in the tree this adapter holds a `FakeMobileCore`, which is
/// visible in the previews and in TestFlight builds that predate the binding.
/// The adapter adds no call of its own: it implements `MobileCore` and nothing
/// more, so replacing the fake with the generated type changes this file and
/// no other.
public final class ProductionCore: MobileCore, @unchecked Sendable {
    public static let shared = ProductionCore()

    private let inner: MobileCore

    private init(inner: MobileCore = FakeMobileCore()) {
        self.inner = inner
    }

    /// Register the background duty task.
    ///
    /// `BGTaskScheduler` accepts a registration only before the app finishes
    /// launching. In the Xcode app target this is called from the app
    /// delegate's `didFinishLaunching`; here it is called when the first scene
    /// appears, which is the earliest point a library-only package has. Both
    /// paths run the same code, and registering twice is a no-op because the
    /// identifier is the same.
    public func registerBackgroundDuty() {
        #if canImport(BackgroundTasks) && !os(macOS)
        BackgroundDutyScheduler.register {
            Self.shared.runBackgroundDuty()
        }
        #endif
    }

    /// One background duty pass, recorded in the duty log.
    public func runBackgroundDuty() {
        let log = DutyLog(directory: Self.logDirectory)
        do {
            let report = try DutyRunner().run(
                core: inner,
                policy: .default,
                state: Self.currentDeviceState(),
                window: 0
            )
            log.record(decision: report.decision)
            for _ in report.answered {
                log.recordAudit(passed: true)
            }
        } catch {
            log.record(decision: .pausedPower)
        }
    }

    /// Where the duty log lives: the app's Application Support directory,
    /// excluded from backup.
    public static var logDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("bud3", isDirectory: true)
    }

    /// Reads the device state the policy engine needs.
    public static func currentDeviceState() -> DeviceState {
        #if canImport(UIKit)
        let device = UIDevice.current
        device.isBatteryMonitoringEnabled = true
        let state = DeviceState(
            isMetered: false,
            mobileUsedMbToday: 0,
            isCharging: device.batteryState == .charging || device.batteryState == .full,
            batteryPercent: Int(max(device.batteryLevel, 0) * 100),
            lowPowerModeOn: ProcessInfo.processInfo.isLowPowerModeEnabled,
            thermalState: ThermalState(rawValue: ProcessInfo.processInfo.thermalState.rawValue) ?? .nominal
        )
        return state
        #else
        return DeviceState()
        #endif
    }

    public var onEvent: (@Sendable (CoreEvent) -> Void)? {
        get { inner.onEvent }
        set { inner.onEvent = newValue }
    }

    public func start() throws { try inner.start() }
    public func stop() throws { try inner.stop() }
    public func status() throws -> CoreStatus { try inner.status() }
    public func setPolicy(_ policy: AppPolicy) throws { try inner.setPolicy(policy) }
    public func registerValidator(class: ValidatorClass, quotaBytes: UInt64) throws {
        try inner.registerValidator(class: `class`, quotaBytes: quotaBytes)
    }
    public func resume() throws { try inner.resume() }
    public func claimRewards() throws { try inner.claimRewards() }
    public func leave() throws { try inner.leave() }
    public func pendingAudits() throws -> [PendingAudit] { try inner.pendingAudits() }
    public func answerAudit(sequence: UInt64) throws -> AuditOutcome { try inner.answerAudit(sequence: sequence) }
    public func signPresence(window: UInt64) throws { try inner.signPresence(window: window) }
}

/// The screen the app opens on: registration until the device is registered,
/// the dashboard afterwards.
@MainActor
public struct RootView: View {
    @ObservedObject var model: ValidatorModel

    public init(model: ValidatorModel) {
        self.model = model
    }

    public var body: some View {
        if model.isRegistered {
            DashboardView(model: model)
        } else {
            OnboardingView(model: model)
        }
    }
}
