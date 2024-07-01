// swift-tools-version:5.2

//
// Copyright 2020-2021 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

let rustBuildDir = "../target/debug/"

let package = Package(
    name: "LibMochiClient",
    platforms: [
        .macOS(.v10_15), .iOS(.v13),
    ],
    products: [
        .library(
            name: "LibMochiClient",
            targets: ["LibMochiClient"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0"),
    ],
    targets: [
        .systemLibrary(name: "MochiFfi"),
        .target(
            name: "LibMochiClient",
            dependencies: ["MochiFfi"]
        ),
        .testTarget(
            name: "LibMochiClientTests",
            dependencies: ["LibMochiClient"],
            linkerSettings: [.unsafeFlags(["-L\(rustBuildDir)"])]
        ),
    ]
)
