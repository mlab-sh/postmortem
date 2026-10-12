// swift-tools-version:6.0
import PackageDescription
let package = Package(
  name: "App",
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.70.0"),
    .package(url: "https://github.com/apple/swift-collections.git", branch: "main"),
  ],
  targets: [ .executableTarget(name: "App", dependencies: [
    .product(name: "ArgumentParser", package: "swift-argument-parser"),
    .product(name: "Logging", package: "swift-log"),
    .product(name: "NIO", package: "swift-nio"),
    .product(name: "Collections", package: "swift-collections"),
  ]) ]
)
