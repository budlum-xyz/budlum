import XCTest
@testable import BudlumValidatorCore

final class IosValidatorTests: XCTestCase {
    func test_ios_bg_task_answers_audit() throws {
        let vault = SecureEnclaveKeyVault()
        let rawDutyKey = Data(repeating: 0x5c, count: 32)
        let wrapped = try vault.wrapDutyKey(rawDutyKey)
        XCTAssertNotEqual(wrapped, rawDutyKey)
        XCTAssertEqual(try vault.unwrapDutyKey(wrapped), rawDutyKey)

        let validator = try IosOpportunisticValidator(keyVault: vault)
        let regTx = try validator.register(biometricToken: "FACEID_OR_TOUCHID_VERIFIED")
        XCTAssertEqual(
            regTx,
            .registerOpportunisticValidator(validatorClass: .mobileOpportunistic, stakeBud: 10)
        )

        let descriptor = validator.makeBgProcessingDescriptor()
        XCTAssertTrue(descriptor.requiresExternalPower)
        XCTAssertTrue(descriptor.requiresNetworkConnectivity)

        // BGProcessingTask must refuse execution if external power constraint is disabled.
        XCTAssertThrowsError(
            try validator.handleBgProcessingTask(
                schedule: BgProcessingScheduleDescriptor(requiresExternalPower: false),
                window: 10,
                incomingShares: [],
                pendingAudits: []
            )
        )

        let share = IosAssignedShare(
            segmentIdHex: "deadbeef01",
            esi: 3,
            payload: Data(repeating: 0xab, count: 2_048)
        )
        let audit = IosStorageAudit(segmentIdHex: "deadbeef01", challengeNonce: 99)
        let emitted = try validator.handleBgProcessingTask(
            schedule: descriptor,
            window: 11,
            incomingShares: [share],
            pendingAudits: [audit]
        )

        XCTAssertTrue(validator.lastAuditPassed)
        XCTAssertEqual(validator.storedBytes, 2_048)
        XCTAssertEqual(emitted.count, 3)
        XCTAssertEqual(emitted[0], .custodyAck(segmentIdHex: "deadbeef01", esi: 3))
        if case let .custodyProofBatch(segmentIdHex, digestHex) = emitted[1] {
            XCTAssertEqual(segmentIdHex, "deadbeef01")
            XCTAssertEqual(digestHex.count, 64)
        } else {
            XCTFail("expected custodyProofBatch in BGProcessingTask output")
        }
        if case let .presence(window, validatorClass, _) = emitted[2] {
            XCTAssertEqual(window, 11)
            XCTAssertEqual(validatorClass, .mobileOpportunistic)
        } else {
            XCTFail("expected opportunistic presence signal in BGProcessingTask output")
        }
    }

    func test_ios_quota_cap_is_8_gib() throws {
        // Default 4 GiB and max 8 GiB succeed.
        let defaultPolicy = try IosPolicy()
        XCTAssertEqual(defaultPolicy.quotaBytes, 4 * IosValidatorConstants.gibBytes)
        let maxPolicy = try IosPolicy(quotaBytes: 8 * IosValidatorConstants.gibBytes)
        XCTAssertEqual(maxPolicy.quotaBytes, 8 * IosValidatorConstants.gibBytes)

        // 8 GiB + 1 byte and 16 GiB are strictly rejected on iOS.
        XCTAssertThrowsError(
            try IosPolicy(quotaBytes: 8 * IosValidatorConstants.gibBytes + 1)
        ) { error in
            XCTAssertEqual(
                error as? IosCoreError,
                .quotaOutOfRange(8 * IosValidatorConstants.gibBytes + 1)
            )
        }
        XCTAssertThrowsError(
            try IosPolicy(quotaBytes: 16 * IosValidatorConstants.gibBytes)
        )
        // Below 1 GiB is also rejected.
        XCTAssertThrowsError(
            try IosPolicy(quotaBytes: IosValidatorConstants.gibBytes - 1)
        )
    }

    func test_ios_class_is_opportunistic() throws {
        let validator = try IosOpportunisticValidator()
        XCTAssertEqual(validator.validatorClass, .mobileOpportunistic)
        XCTAssertEqual(validator.validatorClass.rawValue, 2)
        XCTAssertEqual(IosValidatorConstants.auditWindowSeconds, 48 * 3_600)
        XCTAssertEqual(IosValidatorConstants.presenceIntervalSeconds, 24 * 3_600)
        XCTAssertEqual(IosValidatorConstants.suspensionDurationSeconds, 7 * 24 * 3_600)
        XCTAssertEqual(IosValidatorConstants.slashingRateBps, 0)
        XCTAssertLessThanOrEqual(IosValidatorConstants.rewardRateBps, 2_500)
        XCTAssertTrue(
            IosValidatorConstants.appStoreNonMiningDisclosure.contains("Proof-of-Work")
        )

        // Attempting to instantiate an iOS validator as Full or Android Mobile is rejected.
        XCTAssertThrowsError(try IosOpportunisticValidator(requestedClass: .full)) { error in
            XCTAssertEqual(error as? IosCoreError, .nonOpportunisticClassForbidden(.full))
        }
        XCTAssertThrowsError(try IosOpportunisticValidator(requestedClass: .mobile)) { error in
            XCTAssertEqual(error as? IosCoreError, .nonOpportunisticClassForbidden(.mobile))
        }
    }
}
