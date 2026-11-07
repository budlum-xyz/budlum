//
//  ShareStore.swift
//  BudlumValidatorKit
//
//  Share storage. Directive 7.9.5, applied to iOS.
//
//  - Shares live in a directory the app marks with
//    `isExcludedFromBackup`, which is the iOS equivalent of Android's
//    `noBackupFilesDir`: they never enter an iCloud or iTunes backup.
//  - One file per segment; the file name is the lowercase hex form of the
//    segment id. The Android app writes the same name for the same segment, so
//    a segment id identifies one file on both platforms.
//  - The quota is never exceeded. Lowering the quota releases the overflow with
//    `StorageTx::ReleaseShares` and triggers repair. Release is not a penalty.
//  - When free space drops below 2 GiB the store reports that shares must be
//    released (R-34).
//
//  The embedded-database choice (redb versus plain file versus WAL; never
//  sled) is measured inside WP-11. This delivery uses the plain-file
//  candidate, the same one the Android app uses, so the two stay comparable in
//  the field test (WP-37).
//

import Foundation

/// Errors from the share store.
public enum ShareStoreError: Error, Equatable, Sendable {
    /// The segment id is empty, so it cannot name a file.
    case emptySegmentId
    /// A file name in the share directory is not valid hex, so it does not
    /// name a segment.
    case corruptFileName(name: String)
}

/// Holds the shares of one device.
public final class ShareStore: @unchecked Sendable {
    /// Free space below this triggers `ReleaseShares` (R-34).
    public static let lowSpaceBytes: UInt64 = 2 * 1024 * 1024 * 1024

    /// The root of the store.
    public let root: URL
    /// Reads the free space of the volume holding the store. Injected so a
    /// test can name a full disk.
    private let freeSpaceProvider: () -> UInt64

    public init(root: URL, freeSpaceProvider: (() -> UInt64)? = nil) {
        self.root = root
        if let freeSpaceProvider {
            self.freeSpaceProvider = freeSpaceProvider
        } else {
            self.freeSpaceProvider = {
                let values = try? root.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
                if let bytes = values?.volumeAvailableCapacityForImportantUsage, bytes >= 0 {
                    return UInt64(bytes)
                }
                return UInt64.max
            }
        }
    }

    /// The directory the share files live in.
    public var bud3Directory: URL {
        root.appendingPathComponent("bud3", isDirectory: true)
    }

    /// The file name of one segment. Lowercase hex, the same string the Android
    /// app writes.
    public func shareFileName(segmentId: Data) throws -> String {
        guard !segmentId.isEmpty else {
            throw ShareStoreError.emptySegmentId
        }
        return segmentId.map { String(format: "%02x", $0) }.joined()
    }

    /// The file of one segment.
    public func shareFile(segmentId: Data) throws -> URL {
        bud3Directory.appendingPathComponent(try shareFileName(segmentId: segmentId))
    }

    /// Bytes currently held.
    public func storedBytes() -> UInt64 {
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: bud3Directory,
            includingPropertiesForKeys: [.fileSizeKey]
        )) ?? []
        var total: UInt64 = 0
        for url in contents {
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
            total += UInt64(max(size, 0))
        }
        return total
    }

    /// Write one share. Returns false and writes nothing when the write would
    /// exceed `quotaBytes`.
    @discardableResult
    public func writeShare(segmentId: Data, bytes: Data, quotaBytes: UInt64) throws -> Bool {
        if storedBytes() + UInt64(bytes.count) > quotaBytes {
            return false
        }
        try FileManager.default.createDirectory(at: bud3Directory, withIntermediateDirectories: true)
        try bytes.write(to: try shareFile(segmentId: segmentId), options: .atomic)
        try excludeFromBackup()
        return true
    }

    /// Read one share back, or `nil` when the device does not hold it.
    public func readShare(segmentId: Data) -> Data? {
        guard let file = try? shareFile(segmentId: segmentId) else {
            return nil
        }
        return try? Data(contentsOf: file)
    }

    /// Release the given segments and return the ids that were really
    /// released. The caller turns those into `StorageTx::ReleaseShares`.
    @discardableResult
    public func releaseShares(segmentIds: [Data]) throws -> [Data] {
        var released: [Data] = []
        for id in segmentIds {
            let file = try shareFile(segmentId: id)
            if (try? FileManager.default.removeItem(at: file)) != nil {
                released.append(id)
            }
        }
        return released
    }

    /// Enforce the quota: release the oldest shares first until the stored
    /// bytes fit. Returns the released segment ids, oldest first.
    @discardableResult
    public func enforceQuota(quotaBytes: UInt64) throws -> [Data] {
        let manager = FileManager.default
        guard let contents = try? manager.contentsOfDirectory(
            at: bud3Directory,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]
        ) else {
            return []
        }
        let sorted = contents.sorted { lhs, rhs in
            let l = (try? lhs.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
            let r = (try? rhs.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
            return l < r
        }
        var total = storedBytes()
        var released: [Data] = []
        for file in sorted {
            if total <= quotaBytes {
                break
            }
            let size = UInt64(max((try? file.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0, 0))
            guard let id = try? segmentId(fileName: file.lastPathComponent) else {
                // A file that is not a segment id is not ours. Leave it: the
                // store never deletes what it cannot name.
                continue
            }
            do {
                try manager.removeItem(at: file)
                total -= min(size, total)
                released.append(id)
            } catch {
                continue
            }
        }
        return released
    }

    /// Whether shares must be released because the volume is nearly full
    /// (R-34).
    public func needsReleaseDueToLowSpace() -> Bool {
        freeSpaceProvider() < ShareStore.lowSpaceBytes
    }

    /// The segment id a file name carries.
    public func segmentId(fileName: String) throws -> Data {
        let name = (fileName as NSString).lastPathComponent
        guard !name.isEmpty, name.count % 2 == 0 else {
            throw ShareStoreError.corruptFileName(name: fileName)
        }
        var bytes = Data()
        bytes.reserveCapacity(name.count / 2)
        var index = name.startIndex
        while index < name.endIndex {
            let next = name.index(index, offsetBy: 2)
            guard let byte = UInt8(name[index..<next], radix: 16) else {
                throw ShareStoreError.corruptFileName(name: fileName)
            }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    /// Keep the share directory out of device backups. Called after every
    /// write rather than once at install: the flag is per URL, and a restore
    /// onto a new device must not bring shares with it.
    private func excludeFromBackup() {
        #if os(iOS)
        var url = bud3Directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
        #endif
    }
}
