# Swift / iOS (CocoaPods, SwiftPM)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Two ecosystems, reported
separately: `cocoapods` and `swift`.

## Manifests

| File | Notes |
| --- | --- |
| `Podfile.lock` | CocoaPods - every pod (subspecs folded into it) with its own dependencies: **full graph**. `DEPENDENCIES` is the direct set. |
| `Package.resolved` | SwiftPM (v1, v2, v3) - every pin, **no edges**. Found at the root, in `X.xcworkspace/xcshareddata/swiftpm/`, or in `X.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/`. |
| `Package.swift` | Its `.package(url:)` calls give the direct set, when the resolved file is the package's own (at the root). |

## Identity

- **CocoaPods** - the pod name. A subspec (`Firebase/Core`) is folded into its
  pod: one node per pod and version, whose edges are the union of its
  subspecs' (purl `pkg:cocoapods/Firebase@10.0.0`).
- **SwiftPM** - the repository path, case kept (`github.com/apple/swift-nio`),
  like a Go module. It is the package's identity, its purl
  (`pkg:swift/github.com/apple/swift-nio@2.65.0`) and its source repo. A pin
  on a branch or a commit carries that instead of a version.

## Graph

CocoaPods: complete. SwiftPM: **flat**, with a `flat_graph` diagnostic, and
without `Package.swift` (an Xcode app) nothing is claimed as direct.

## Dependency scopes

None: neither format records a test/dev split, everything is `prod`.

## Online resolution

- **CocoaPods:** trunk (`trunk.cocoapods.org/api/v1/pods/<pod>/specs/<version>`,
  redirected to the podspec JSON) → `source.git`, then `homepage`; `license`
  gives the license. A pod taken from `:git:` (`EXTERNAL SOURCES` /
  `CHECKOUT OPTIONS`) is resolved to **that** repo, never to trunk: a fork
  shares its upstream's name, and trunk would describe the upstream.
- **SwiftPM:** no registry - the name is the repo.

## Vulnerabilities

Through vuln.mlab.sh, as everything else. mlab does not parse
`Package.resolved`, so its pins are sent as OSV `SwiftURL` coordinates.
CocoaPods has no OSV ecosystem: **no advisory data exists** for it.

## Not covered yet

- Source-code scanning of Swift / Objective-C.
- Typosquatting (no corpus).
