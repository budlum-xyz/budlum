import CryptoKit
import Foundation
import XCTest
@testable import BudlumValidator

private struct TestAuditSigner: CustodyAuditSigning {
    func signAudit(segmentHex: String, share: Data, nonce: Data) throws -> Data {
        var signature = Data("test-only-audit-signature:".utf8)
        signature.append(Data(segmentHex.utf8))
        signature.append(nonce)
        return signature
    }
}

final class OpportunisticValidatorTests: XCTestCase {
    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    func test_ios_class_is_opportunistic() throws {
        let tmp = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        XCTAssertEqual(engine.registrationClass, .mobileOpportunistic)
        XCTAssertEqual(OpportunisticValidatorEngine.registrationTag, 2)
        XCTAssertEqual(OpportunisticValidatorEngine.auditWindowHours, 48)
        XCTAssertEqual(OpportunisticValidatorEngine.suspensionOfflineHours, 168)
        XCTAssertTrue(engine.backgroundConfig.requiresExternalPower)
        XCTAssertTrue(engine.backgroundConfig.requiresNetworkConnectivity)
    }

    func test_ios_quota_cap_is_8_gib() throws {
        let tmp = try temporaryDirectory()
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

    func test_ios_bg_task_answers_audit_after_reopen_without_returning_share() throws {
        let tmp = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let segment = String(repeating: "c", count: 64)
        let share = Data([0x10, 0x20, 0x30, 0x40])
        let nonce = Data([0x01, 0x02, 0x03, 0x04])
        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        try engine.storeCustodyShare(segmentHex: segment, shareBytes: share)

        // A new engine has no in-memory share map: the duty must read the file.
        let reopened = try OpportunisticValidatorEngine(
            baseDirectory: tmp,
            auditSigner: TestAuditSigner()
        )
        let proofs = try reopened.runBackgroundProcessingWindow(
            challengedSegments: [segment],
            nonce: nonce
        )
        XCTAssertEqual(proofs.count, 1)
        XCTAssertNil(proofs[0].range(of: share))
        XCTAssertEqual(reopened.answeredAuditsCount, 1)
        let values = try reopened.storageDirectory.resourceValues(
            forKeys: [.isExcludedFromBackupKey]
        )
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }

    func test_ios_bg_task_without_signer_fails_closed() throws {
        let tmp = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        XCTAssertThrowsError(
            try engine.runBackgroundProcessingWindow(
                challengedSegments: [String(repeating: "a", count: 64)],
                nonce: Data()
            )
        ) { error in
            XCTAssertEqual(error as? OpportunisticValidatorError, .auditSigningUnavailable)
        }
        XCTAssertEqual(engine.answeredAuditsCount, 0)
    }

    func test_segment_id_cannot_escape_share_directory() throws {
        let tmp = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        XCTAssertThrowsError(
            try engine.storeCustodyShare(segmentHex: "../escape", shareBytes: Data([1, 2, 3]))
        ) { error in
            XCTAssertEqual(
                error as? OpportunisticValidatorError,
                .invalidSegmentId("../escape")
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: tmp.appendingPathComponent("escape").path))
    }

    func test_leave_preserves_unknown_files_and_removes_only_shares() throws {
        let tmp = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = try OpportunisticValidatorEngine(baseDirectory: tmp)
        let segment = String(repeating: "A", count: 64)
        try engine.storeCustodyShare(segmentHex: segment, shareBytes: Data([1, 2, 3]))
        let unknown = engine.storageDirectory.appendingPathComponent("notes.txt")
        try Data("keep".utf8).write(to: unknown)

        XCTAssertEqual(try engine.leaveAndReleaseAllShares(), [segment.lowercased()])
        XCTAssertTrue(FileManager.default.fileExists(atPath: unknown.path))
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: engine.storageDirectory.appendingPathComponent(segment.lowercased()).path
            )
        )
    }

    func test_secure_enclave_wrap_round_trip_when_hardware_is_available() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave is unavailable on this runner")
        }
        let store = try SecureEnclaveKeyStore()
        let secret = Data(repeating: 0x42, count: 64)
        let wrapped = try store.wrapPostQuantumKey(label: "operator", secretKeyBytes: secret)
        XCTAssertNotEqual(wrapped.sealedBoxCombined, secret)
        XCTAssertEqual(try store.unwrapPostQuantumKey(wrapped), secret)

        let differentDeviceKey = try SecureEnclaveKeyStore()
        XCTAssertThrowsError(try differentDeviceKey.unwrapPostQuantumKey(wrapped))
    }
}
