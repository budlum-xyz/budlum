import Foundation
import XCTest
@testable import BudlumValidator

final class OpportunisticValidatorTests: XCTestCase {

    func test_ios_class_is_opportunistic() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        XCTAssertEqual(engine.registrationClass, .mobileOpportunistic)
        XCTAssertEqual(OpportunisticValidatorEngine.auditWindowHours, 48)
        XCTAssertEqual(OpportunisticValidatorEngine.suspensionOfflineHours, 168)
        XCTAssertTrue(engine.backgroundConfig.requiresExternalPower)
        XCTAssertTrue(engine.backgroundConfig.requiresNetworkConnectivity)
    }

    func test_ios_quota_cap_is_8_gib() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let maxAllowed = try OpportunisticValidatorEngine(
            baseDirectory: tmp,
            quotaBytes: 8 * OpportunisticValidatorEngine.gib
        )
        XCTAssertEqual(maxAllowed.quotaBytes, 8 * OpportunisticValidatorEngine.gib)

        XCTAssertThrowsError(
            try maxAllowed.setQuotaBytes(8 * OpportunisticValidatorEngine.gib + 1)
        ) { error in
            XCTAssertEqual(
                error as? OpportunisticValidatorError,
                .invalidQuota(8 * OpportunisticValidatorEngine.gib + 1)
            )
        }
    }

    func test_ios_bg_task_answers_audit() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        let segHex = String(repeating: "c", count: 64)
        try engine.storeCustodyShare(segmentHex: segHex, shareBytes: Data([0x10, 0x20, 0x30, 0x40]))

        let proofs = try engine.runBackgroundProcessingWindow(
            challengedSegments: [segHex],
            nonce: Data([0x01, 0x02, 0x03, 0x04])
        )
        XCTAssertEqual(proofs.count, 1)
        XCTAssertEqual(engine.answeredAuditsCount, 1)
        XCTAssertEqual(engine.presenceHeartbeatsSent, 1)

        let values = try engine.storageDirectory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }
}
