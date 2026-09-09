# RCInjectAnalysis 1.0.17 — release checklist

Target: exact RootHide `com.roothide.manager` `1.3.9+bindtrust1` baseline. Full deb SHA-256 must be `5392005d50c2a3e6189545e408aa4723bad401995ec508efcb48010c53d57f28`.

## Preferred release path

Run on the real Theos/iPhoneOS SDK build host:

```sh
Integration/release_pipeline.sh \
  '/path/to/com.roothide.manager 1.3.9+bindtrust1.deb' \
  /path/to/dist
```

Required end state:

```text
RELEASE PIPELINE PASS
<dist>/com.roothide.manager_1.3.9+bindtrust1+analysis1.0.17.deb
<dist>/RCInjectAnalysis-1.0.17-RELEASE-RECEIPT.txt
<dist>/RCInjectAnalysis-1.0.17-SOURCE-PROVENANCE.json
<dist>/RCInjectAnalysis-1.0.17-BUILD-SOURCE.zip
<dist>/RCInjectAnalysis-1.0.17-DEPLOYMENT-KIT.zip
```

The receipt must say `StaticReleaseGate=PASS` and `RuntimeDeviceTest=NOT_PERFORMED` before installation. The deployment kit must pass `Integration/verify_deployment_kit.py`.

## Stop conditions before build

Stop if `check_toolchain.py` reports missing `$THEOS`, iPhoneOS SDK, `ldid`, `dpkg-deb`, required Frameworks, or Python 3.9+. Stop if central VERSION/header consistency, source invariants, conservative rule matrix, exact baseline SHA, or 199-key entitlement baseline fails.

## Dylib requirements

The selected output must be a Mach-O dylib with both `arm64` and `arm64e` and:

```text
LC_ID_DYLIB = @executable_path/Frameworks/RCInjectAnalysis.dylib
```

If multiple different valid Theos outputs exist, do not guess. Delete stale outputs or explicitly set `RC_ANALYSIS_DYLIB` to the intended file and rerun the pipeline.

## Final deb static requirements

The exact final deb must pass:

```sh
python3 Integration/verify_release.py '/path/to/original.deb' \
  --built-deb '/path/to/+analysis1.0.17.deb'
```

The package-delta gate must report preservation of deb ar metadata plus tar type/mode/numeric uid/gid/uname/gname/mtime. The pinned RootHide data/control tar entries use numeric uid `501`, gid `20`, `uname=root`, `gname=wheel`; new Analysis Frameworks entries inherit the `RootHide.app` ownership/name/mtime model.

Allowed delta only:

```text
CHANGED
Applications/RootHide.app/RootHide
DEBIAN/control                  # Version only

NEW
Applications/RootHide.app/Frameworks/RCInjectAnalysis.dylib
Applications/RootHide.app/Frameworks/RCInjectAnalysis.buildinfo.plist

REMOVED
none
```

## First device launch

Keep the original `1.3.9+bindtrust1` deb available as rollback. Before interpreting scanner results, require a normal packaged run to report a non-empty loaded-image UUID, expected Frameworks path, host weak load present, Manifest present/version matching/current-slice UUID matching, Menu Hook installed, and `Runtime Self-Check: PASS`.

The first runtime self-check should also report the host executable as uid `0`, gid `0`, executable + setuid; actual mode is reported, matching the unchanged RootHide postinst contract.

If Manager fails to launch, native blacklist behavior changes, Analysis menu duplicates, runtime identity warns, or an unavailable source is shown as definitively clean, stop and return the full report/logs. Do not add cleanup/unregister workarounds during first validation.

## Field feedback

Return the full in-app report plus `FIELD-REPORT-TEMPLATE.md`. For a wrong per-App result, also return that App's read-only report with the same `Scan-ID`.

## Provenance gate

- `SOURCE-PROVENANCE.json` and `BUILD-SOURCE.zip` must verify with `verify_source_snapshot.py`.
- Packaged Manifest Schema must be 3.
- `BuildID`, `SourceTreeSHA256`, `SourceFileCount`, signed dylib SHA and arm64/arm64e UUIDs must agree across build manifest, receipt and deployment manifest.
- `RuntimeDeviceTest` must remain `NOT_PERFORMED` before the first real device run.
