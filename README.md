# GitHub Actions build-ready package

This tree is prepared for the user's existing **Git Bash → GitHub → Actions** workflow. See `GITHUB-BUILD.md`.

# RCInjectAnalysis 1.0.17 — RootHide build-handoff / release-pipeline build

Target baseline: exact `com.roothide.manager` / RootHide Manager `1.3.9+bindtrust1` executable SHA-256 `c12b596acd1856677b8fb9753fcebdd88c7601318f10b6b7a8926e2568de687e`.

## Safety boundary

Analysis 1.0.17 remains deliberately read-only. It does not change blacklist / `RootHideConfig.plist`, unregister LaunchServices records, delete/move tweak or App files, rebuild icon cache, respring, or modify RootHide Core behavior.

## Current release guarantees

### Build-source provenance and deterministic BuildID

1.0.17 binds the packaged signed dylib to the exact release-critical source tree (`VERSION`, `Makefile`, `Sources/**`, `Integration/**`). `source_fingerprint.py` computes a canonical tree SHA-256 over relative path, mode, size, and file SHA-256. Manifest Schema 3 stores `SourceTreeSHA256`, `SourceFileCount`, and a deterministic `BuildID` derived from version + source-tree digest + signed dylib digest + pinned RootHide executable baseline. The runtime report surfaces the same BuildID and source-tree digest alongside the loaded LC_UUID.

### Exact build-source snapshot in the deployment kit

The release pipeline creates a deterministic `RCInjectAnalysis-1.0.17-BUILD-SOURCE.zip` plus `RCInjectAnalysis-1.0.17-SOURCE-PROVENANCE.json`. The deployment kit binds both by SHA-256 and verifies that the snapshot reconstructs the same canonical source-tree digest recorded in the packaged build manifest and release receipt. This is an integrity/reproducibility chain, not a cryptographic publisher signature.

### Deployment Schema 2 / machine-readable pre-install contract

`DEPLOYMENT-MANIFEST.json` now includes `BuildIdentity` and `PreInstall` sections. It pins the install deb, rollback deb, source snapshot, source provenance, BuildID, source-tree SHA, dylib SHA and per-slice UUIDs while keeping `RuntimeDeviceTest=NOT_PERFORMED`. `verify_deployment_kit.py` fails closed if any of these disagree.


### Complete original-deb pin

`Integration/verify_original_deb.py` now pins the complete rollback/build-input deb SHA-256 (`5392005d50c2a3e6189545e408aa4723bad401995ec508efcb48010c53d57f28`) plus Package/Version/Architecture. This prevents a package with the same RootHide executable but altered resources/control files from becoming the Analysis baseline or rollback artifact.

### First-device install-state self-check

The runtime self-check now reports the installed RootHide executable file state in addition to Mach-O/manifest identity. The unchanged RootHide `postinst` is expected to leave `/Applications/RootHide.app/RootHide` as uid `0`, gid `0`, executable + setuid; actual mode is reported. A mismatch is reported as `host-postinstall-state`; the dylib is also checked to be a regular executable file. This remains read-only (`stat(2)` only).

### Archive metadata preservation

The final package gate now compares deb data/control archive metadata directly, not just extracted bytes. Existing RootHide entries must preserve numeric uid/gid/mode; the pinned RootHide tar headers use the unusual but real combination numeric uid `501`, gid `20`, while storing `uname=root` / `gname=wheel`. Existing entries preserve that tuple together with type/mode/mtime. The new `Frameworks` directory/dylib/buildinfo inherit the `RootHide.app` ownership/name/mtime model and use modes `0755` / `0755` / `0644`. Packaging is now performed by a baseline-aware tar/ar repacker, so build-host uid/gid, root privileges, and `fakeroot` no longer determine archive ownership.

### Postinstall contract gate

`Integration/verify_postinstall_contract.py` pins the exact original RootHide `postinst` SHA-256 and verifies that the final Analysis package keeps it byte-for-byte unchanged. This complements the package-delta verifier and makes the expected `uicache` / `chown 0:0` / `chmod +s` installation behavior explicit.

### Deployment kit with exact rollback baseline

A successful release pipeline now creates `RCInjectAnalysis-1.0.17-DEPLOYMENT-KIT.zip`. The kit contains the final Analysis deb, the exact untouched RootHide rollback deb, release receipt, first-run documents, deployment manifest, and SHA256SUMS. `verify_deployment_kit.py` re-runs the static final-deb and postinstall gates against the package pair before the kit is accepted.

### One version source

The repository root now contains:

```text
VERSION
```

`Integration/generate_version_header.py` converts it into `Sources/RCVersion.generated.h` before Theos compilation. `RCBuildInfo.m` consumes that generated macro, while the Python release tools and shell builder read the same root VERSION. `verify_version_consistency.py` fails closed if any of those layers drift.

This removes the previous risk of an Objective-C UI/report version, Manifest version, package suffix, and verifier version disagreeing with one another.

### Real build-host preflight

Before building, `Integration/check_toolchain.py` checks:

- Python 3.9+;
- `make`, `dpkg-deb`, and `ldid`;
- a valid `$THEOS` tree;
- an iPhoneOS SDK, either under `$THEOS/sdks` or through `xcrun`;
- Foundation/UIKit presence in that SDK.

A missing build prerequisite is a hard stop. The script does not substitute the Linux host toolchain for a real iOS SDK build.

### Fail-closed Theos artifact selection

`Integration/find_built_dylib.py` recursively searches the Theos output tree for `RCInjectAnalysis.dylib`, but accepts only a Mach-O dylib containing both `arm64` and `arm64e` and the exact install name:

```text
@executable_path/Frameworks/RCInjectAnalysis.dylib
```

If multiple valid files exist but their SHA-256 values differ, selection is refused. A developer must explicitly set `RC_ANALYSIS_DYLIB=/exact/path/...` instead of silently packaging a stale debug/release artifact.

### One-command release pipeline

On a real Theos/iOS SDK machine:

```sh
Integration/release_pipeline.sh \
  '/path/to/com.roothide.manager 1.3.9+bindtrust1.deb' \
  /path/to/output-directory
```

The pipeline performs:

```text
toolchain preflight
→ generate/verify central version header
→ deterministic build-source snapshot + provenance verification
→ source/rule/baseline release gate
→ make clean + make
→ choose exactly one valid universal dylib
→ candidate dylib release gate
→ RootHide weak-load/sign/build integration
→ reopen final deb
→ final release gate + exact package-delta gate
→ release receipt with BuildID/source-tree binding
→ deployment kit with exact source snapshot + rollback
→ deployment-kit re-verification
```

It does not declare device runtime success. A real RootHide launch/test is still mandatory.

### Release receipt

A successful pipeline creates:

```text
RCInjectAnalysis-1.0.17-RELEASE-RECEIPT.txt
```

The receipt records original/built deb SHA-256, packaged dylib SHA-256, Manifest binding, `BuildID`, `SourceTreeSHA256`, `SourceFileCount`, schema/load mode/install-name, arm64/arm64e LC_UUID values, and explicitly states `RuntimeDeviceTest=NOT_PERFORMED`. The receipt generator re-runs the exact built-deb release gate before writing `StaticReleaseGate=PASS`.

### Field-report template

`FIELD-REPORT-TEMPLATE.md` defines the minimum first-device observations to return alongside the in-app full diagnostic report and any affected single-App report. Matching `Scan-ID` values keep reports tied to the same Analysis snapshot.

## Runtime identity retained

The existing runtime identity chain remains intact. The in-app report records the loaded Analysis path, runtime architecture, in-memory `LC_UUID`, host `LC_LOAD_WEAK_DYLIB`, Menu Hook state, and `RCInjectAnalysis.buildinfo.plist` values. Manifest schema 3 stores the signed dylib SHA-256, per-slice arm64/arm64e UUIDs, exact source-tree digest/file count, and deterministic BuildID. A normal builder-produced device run should report `Runtime Self-Check: PASS` before scanner output is interpreted.

## Current Analysis behavior

1.0.17 keeps the read-only safety boundary while using the current injection classification model:

- three-panel Analysis home: `扫描摘要` / `系统注入` / `App 注入`;
- App-centric `DEB（包管理器）` / `TrollFools` grouping, with scanner-centric technical evidence kept in reports;
- full/per-App in-memory diagnostic reports and `Scan-ID`;
- 50,000 entries/App, 1.5s/App, 12s/global TrollFools soft budgets;
- runtime capability fail-unknown behavior;
- RootHide `jbroot` environment profile;
- conservative orphan LaunchServices registration detection;
- stale blacklist detection;
- multi-plugin `Filter.Bundles` matching;
- DPKG exact-path high-confidence and basename-only medium-confidence ownership;
- TrollStore `_TrollStore` / `_TrollStoreLite` marker classification;
- TrollFools `.troll-fools.bak` vs current Load Command difference;
- conservative RootHide + embedded dual-source evidence wording.

Configuration/filesystem evidence is not upgraded into a claim that a target process definitely loaded a dylib or that multiple tweaks definitely conflict.

## Manual build path

If the one-command pipeline is not used, first generate/check the version binding and static baseline:

```sh
python3 Integration/generate_version_header.py
python3 Integration/verify_version_consistency.py
python3 Integration/verify_release.py '/path/to/original.deb'
python3 Integration/make_source_snapshot.py /path/to/RCInjectAnalysis-1.0.17-BUILD-SOURCE.zip /path/to/RCInjectAnalysis-1.0.17-SOURCE-PROVENANCE.json
python3 Integration/verify_source_snapshot.py /path/to/RCInjectAnalysis-1.0.17-BUILD-SOURCE.zip /path/to/RCInjectAnalysis-1.0.17-SOURCE-PROVENANCE.json
```

Then compile in the real Theos environment:

```sh
make clean
make
```

Verify the produced universal dylib:

```sh
python3 Integration/verify_release.py '/path/to/original.deb' \
  --dylib /path/to/RCInjectAnalysis.dylib
```

Build the RootHide package:

```sh
Integration/build_roothide_deb.sh \
  '/path/to/original.deb' \
  /path/to/RCInjectAnalysis.dylib \
  /path/to/com.roothide.manager_1.3.9+bindtrust1+analysis1.0.17.deb
```

Finally reopen and verify the exact install artifact:

```sh
python3 Integration/verify_release.py '/path/to/original.deb' \
  --built-deb /path/to/com.roothide.manager_1.3.9+bindtrust1+analysis1.0.17.deb
```

Expected final package delta is limited to the patched `RootHide` executable, `DEBIAN/control` Version field, and the two new Frameworks files `RCInjectAnalysis.dylib` and `RCInjectAnalysis.buildinfo.plist`. No baseline file may be removed or otherwise changed.

## Device validation

Use `FIRST-RUN-TEST.md`. Return the app's full report and `FIELD-REPORT-TEMPLATE.md` observations before changing device state. 1.0.17 intentionally contains no cleanup/unregister action.
