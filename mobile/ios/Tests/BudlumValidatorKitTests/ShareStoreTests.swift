//
//  ShareStoreTests.swift
//  BudlumValidatorKitTests
//

import XCTest
@testable import BudlumValidatorKit

final class ShareStoreTests: XCTestCase {
    private var root: URL!
    private var store: ShareStore!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("budlum-share-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        store = ShareStore(root: root)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    /// One file per segment, named with the lowercase hex form of the segment
    /// id. The Android app writes the same name for the same segment.
    func test_share_file_name_is_lowercase_hex() throws {
        let id = Data([0x0a, 0x1b, 0xff])
        XCTAssertEqual(try store.shareFileName(segmentId: id), "0a1bff")
        XCTAssertEqual(
            try store.shareFile(segmentId: id).lastPathComponent,
            "0a1bff"
        )
        XCTAssertEqual(try store.segmentId(fileName: "0a1bff"), id)
        XCTAssertThrowsError(try store.shareFileName(segmentId: Data()))
        XCTAssertThrowsError(try store.segmentId(fileName: "0a1"))
        XCTAssertThrowsError(try store.segmentId(fileName: "zzzz"))
    }

    func test_write_and_read_round_trip() throws {
        let id = Data([0x01, 0x02])
        XCTAssertTrue(try store.writeShare(segmentId: id, bytes: Data([0xde, 0xad]), quotaBytes: 1 << 30))
        XCTAssertEqual(store.readShare(segmentId: id), Data([0xde, 0xad]))
        XCTAssertEqual(store.storedBytes(), 2)
    }

    /// The quota is never exceeded.
    func test_write_refuses_to_exceed_the_quota() throws {
        let quota: UInt64 = 10
        XCTAssertTrue(try store.writeShare(segmentId: Data([0x01]), bytes: Data(count: 6), quotaBytes: quota))
        XCTAssertFalse(try store.writeShare(segmentId: Data([0x02]), bytes: Data(count: 6), quotaBytes: quota))
        XCTAssertEqual(store.storedBytes(), 6)
        XCTAssertNil(store.readShare(segmentId: Data([0x02])), "a refused write writes nothing")
    }

    /// Lowering the quota releases the oldest shares first. Release is not a
    /// penalty, so the order is age and nothing else.
    func test_enforce_quota_releases_oldest_first() throws {
        let ids: [Data] = [Data([0x01]), Data([0x02]), Data([0x03])]
        for id in ids {
            XCTAssertTrue(try store.writeShare(segmentId: id, bytes: Data(count: 4), quotaBytes: 1 << 30))
            // Distinct modification timestamps: the filesystem clock is coarse
            // enough that three files written in one pass can tie.
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertEqual(store.storedBytes(), 12)
        let released = try store.enforceQuota(quotaBytes: 4)
        XCTAssertEqual(released, [Data([0x01]), Data([0x02])])
        XCTAssertEqual(store.storedBytes(), 4)
    }

    func test_release_shares_returns_what_was_really_released() throws {
        XCTAssertTrue(try store.writeShare(segmentId: Data([0x01]), bytes: Data(count: 4), quotaBytes: 1 << 30))
        let released = try store.releaseShares(segmentIds: [Data([0x01]), Data([0x09])])
        XCTAssertEqual(released, [Data([0x01])], "a share the device never held cannot be released")
    }

    /// R-34: free space below 2 GiB triggers `ReleaseShares`.
    func test_low_space_triggers_release() {
        XCTAssertFalse(store.needsReleaseDueToLowSpace())
        let nearlyFull = ShareStore(root: root, freeSpaceProvider: { ShareStore.lowSpaceBytes - 1 })
        XCTAssertTrue(nearlyFull.needsReleaseDueToLowSpace())
        let exactlyAt = ShareStore(root: root, freeSpaceProvider: { ShareStore.lowSpaceBytes })
        XCTAssertFalse(exactlyAt.needsReleaseDueToLowSpace())
    }
}
