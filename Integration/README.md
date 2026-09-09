# RootHide integration layer — Analysis 1.0.17

This directory builds and validates a separately linked universal `RCInjectAnalysis.dylib` into the exact RootHide `1.3.9+bindtrust1` Manager baseline without changing RootHide Core logic.

## Preferred one-command path

On a real Theos + iOS SDK machine:

```sh
./Integration/release_pipeline.sh \
  '/path/to/com.roothide.manager 1.3.9+bindtrust1.deb' \
  /path/to/dist
```

The pipeline performs toolchain preflight, central-version generation/checking, deterministic build-source snapshot/provenance creation, source/rule/baseline gates, Theos build, fail-closed dylib selection, candidate dylib verification, RootHide integration/signing, final package verification, exact package-delta verification, and release-receipt generation.

If the Theos tree contains multiple different valid `RCInjectAnalysis.dylib` files, the pipeline stops. Set `RC_ANALYSIS_DYLIB=/exact/path/RCInjectAnalysis.dylib` to explicitly resolve the ambiguity.

## Weak load integration

The patcher adds exactly one command per RootHide slice:

```text
LC_LOAD_WEAK_DYLIB
@executable_path/Frameworks/RCInjectAnalysis.dylib
```

The exact baseline has enough zero-filled header padding in both arm64 and arm64e, so no section or FAT slice is moved.

## Version binding

`../VERSION` is the single release version source. `generate_version_header.py` creates `Sources/RCVersion.generated.h`; `versioning.py` supplies the same value to Manifest/package/release Python tools; `build_roothide_deb.sh` reads the same VERSION for the package suffix. `verify_version_consistency.py` rejects drift.

## Pinned archive metadata model

The exact RootHide deb uses an unusual tar-header combination: every baseline data/control entry has numeric `uid=501`, `gid=20`, while the stored names are `uname=root`, `gname=wheel`. The repacker preserves that tuple, type, mode, mtime, and link metadata for every existing entry. New Analysis Frameworks entries inherit the `RootHide.app` ownership/name/mtime model. This is intentionally independent of the Linux/macOS build user's uid/gid.

## Manual integration order

`build_roothide_deb.sh` performs source/version and dylib verification, exact baseline SHA validation, original entitlement extraction, weak-load patching, embedded dylib signing, signed-dylib Manifest creation/verification, host re-signing with the original entitlements, baseline-aware tar/ar repacking, final artifact reopening, entitlement equality check, and exact package-delta/archive-metadata verification.

The input deb is never modified in place.

## Helpers

- `check_toolchain.py` — real Theos/iPhoneOS SDK prerequisite gate.
- `generate_version_header.py` / `verify_version_consistency.py` — single-version-source enforcement.
- `verify_source_invariants.py` / `rule_matrix_selftest.py` — read-only and conservative-analysis gates.
- `source_fingerprint.py` — canonical release-critical source-tree SHA-256.
- `make_source_snapshot.py` / `verify_source_snapshot.py` — deterministic exact build-source archive and provenance gate.
- `verify_roothide_baseline.py` — exact RootHide executable SHA/architecture/entitlement/header-padding gate.
- `verify_dylib.py` — arm64+arm64e Mach-O dylib/install-name gate.
- `find_built_dylib.py` — fail-closed Theos artifact selector.
- `make_build_manifest.py` / `verify_build_manifest.py` — signed-dylib SHA/UUID + SourceTreeSHA256 + deterministic BuildID binding.
- `patch_load_command.py` / `verify_macho.py` — idempotent host weak-load integration.
- `repack_deb_preserving_metadata.py` — rebuilds the deb from the pinned baseline tar metadata instead of host filesystem ownership.
- `verify_package_delta.py` — exact allowed final-package delta plus ar/tar metadata preservation.
- `verify_release.py` — static pre-install release gate.
- `make_release_receipt.py` — self-verifying static release receipt including BuildID/source-tree binding.
- `make_deployment_kit.py` / `verify_deployment_kit.py` — deterministic install/rollback/source-provenance deployment bundle and machine-readable pre-install contract.
- `release_pipeline.sh` — end-to-end real-build-host orchestration.

None of these helpers performs device-side cleanup, LaunchServices unregister, blacklist mutation, or Analysis-driven icon-cache rebuild/respring.
