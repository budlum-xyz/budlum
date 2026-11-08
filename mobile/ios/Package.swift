// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BudlumValidator",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "BudlumValidator",
            targets: ["BudlumValidator"]
        ),
    ],
    targets: [
        .target(
            name: "BudlumValidator",
            path: "Sources/BudlumValidator"
        ),
        .testTarget(
            name: "BudlumValidatorTests",
            dependencies: ["BudlumValidator"],
            path: "Tests/BudlumValidatorTests"
        ),
    ]
)
