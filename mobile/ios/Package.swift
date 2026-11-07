// swift-tools-version:5.9
//
// The iOS opportunistic validator (WP-38, directive section 7.10).
//
// Two library targets and one test target, deliberately split so the unit
// tests never link SwiftUI: `swift test` on a macOS runner builds only
// `BudlumValidatorKit` and its tests, and a SwiftUI build needs an SDK that a
// plain toolchain run does not have to provide.
//
// The app target that ships to TestFlight is assembled in Xcode from
// `Sources/BudlumValidatorUI` (see `APP_STORE.md`); this package is what CI
// compiles and tests.

import PackageDescription

let package = Package(
    name: "BudlumValidator",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "BudlumValidatorKit", targets: ["BudlumValidatorKit"]),
        .library(name: "BudlumValidatorUI", targets: ["BudlumValidatorUI"]),
    ],
    targets: [
        .target(
            name: "BudlumValidatorKit",
            path: "Sources/BudlumValidatorKit"
        ),
        .target(
            name: "BudlumValidatorUI",
            dependencies: ["BudlumValidatorKit"],
            path: "Sources/BudlumValidatorUI"
        ),
        .testTarget(
            name: "BudlumValidatorKitTests",
            dependencies: ["BudlumValidatorKit"],
            path: "Tests/BudlumValidatorKitTests"
        ),
    ]
)
