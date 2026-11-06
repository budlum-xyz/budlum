// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BudlumValidator",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "BudlumValidatorCore",
            targets: ["BudlumValidatorCore"]
        ),
    ],
    targets: [
        .target(
            name: "BudlumValidatorCore",
            path: "BudlumValidator"
        ),
        .testTarget(
            name: "BudlumValidatorTests",
            dependencies: ["BudlumValidatorCore"],
            path: "Tests/BudlumValidatorTests"
        ),
    ]
)
