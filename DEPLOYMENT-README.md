# RCInjectAnalysis 1.0.17 — First-device deployment kit

This kit is for the first real RootHide device test. It deliberately contains both the Analysis package and the exact original RootHide rollback package.

## Before installation

The release verifier must report full archive metadata preservation. The pinned RootHide tar headers are numeric uid `501`, gid `20` with `uname=root` / `gname=wheel`; this deliberately does not get normalized through the build host. The baseline-aware repacker catches and prevents host ownership drift before the package reaches the device.

1. Run the release/deployment-kit verifier on the build host.
2. Keep the `rollback/` deb available and do not overwrite it.
3. Confirm the install deb and rollback deb SHA-256 values against `DEPLOYMENT-MANIFEST.json` / `SHA256SUMS`.

## Install expectation

The Analysis deb preserves the original RootHide `postinst` byte-for-byte. That script performs:

```text
uicache -p /Applications/RootHide.app
chown 0:0 /Applications/RootHide.app/RootHide
chmod +s /Applications/RootHide.app/RootHide
```

Therefore the running Analysis environment expects `/Applications/RootHide.app/RootHide` to report uid `0`, gid `0`, executable + setuid; actual mode is reported. A mismatch is reported as `host-postinstall-state`; it is not silently treated as a scanner problem.

## First launch

Open RootHide Manager and go to `环境检查`. Before interpreting any scan results, record:

- Runtime Self-Check
- Host postinstall file state
- Dylib file state
- Manifest UUID match
- Host weak-load status
- Menu Hook status

Then follow `FIRST-RUN-TEST.md` and export the full read-only report.

## Rollback

If RootHide Manager fails to launch or the runtime identity/self-check is inconsistent, reinstall the exact deb under `rollback/`. That is the untouched `1.3.9+bindtrust1` baseline included in the same deployment kit. Do not use Analysis cleanup actions; Analysis 1.0.17 contains none.

After rollback, verify RootHide Manager launches and its original blacklist workflow still works. The deployment manifest keeps the rollback SHA-256 so the exact baseline can be identified later.

## Scope

A passing deployment-kit verifier is still static/pre-install evidence. It does not claim that iOS accepted the code signature or that the dylib loaded successfully. Those are established only by the real device Runtime Self-Check and first-run report.

## Build provenance

The kit contains `provenance/RCInjectAnalysis-1.0.17-BUILD-SOURCE.zip` and `provenance/SOURCE-PROVENANCE.json`. The verifier reconstructs the source fingerprint and requires it to match the packaged Manifest Schema 3 `SourceTreeSHA256` / `BuildID`. This makes the first-device report reproducible back to the exact build-critical source snapshot, but it is not a publisher-authentication signature.
