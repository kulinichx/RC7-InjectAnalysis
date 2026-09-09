# RCInjectAnalysis 1.0.17 — first device test protocol

This protocol is intentionally read-only. Do not add cleanup, unregister, uicache, respring or blacklist-write actions during this test pass.

## 0. Build receipt before installation

Before installing anything, keep the pipeline-generated `RCInjectAnalysis-1.0.17-RELEASE-RECEIPT.txt` next to the final deb. Confirm it records the intended package version/SHA, both arm64/arm64e UUIDs, `StaticReleaseGate=PASS`, and `RuntimeDeviceTest=NOT_PERFORMED`. Use `FIELD-REPORT-TEMPLATE.md` for the observations returned after the run.

Before install, also confirm `BuildID` and `SourceTreeSHA256` are present in the release receipt and deployment manifest. Keep the `provenance/` source snapshot intact; the first in-app report should show the same BuildID/source-tree digest. A mismatch is a packaging/build-identity warning, not a scanner result.

If there is no release receipt or the exact final deb was changed after the receipt was generated, rerun the release pipeline/static gate before installing. Prefer installing from `RCInjectAnalysis-1.0.17-DEPLOYMENT-KIT.zip`; verify the kit first and keep its `rollback/` deb untouched.

## A. Install / launch sanity

1. Keep the original `1.3.9+bindtrust1` deb available as rollback.
2. Install the generated `+analysis1.0.17` deb.
3. Launch RootHide Manager normally.
4. Confirm original blacklist/settings functions still open and render normally.
5. Confirm a new `Analysis 1.0.17` section appears with `注入分析` and `环境检查`.
6. Open both pages repeatedly and return to the native menu. There must be no duplicate Analysis section and no launch crash.

Record PASS/FAIL, crash time if any, and the shared full diagnostic report.

## B. Build / runtime identity

Before interpreting any scanner result, open `环境检查` and verify the first two rows plus the full report `[Build / Runtime Identity]`.

Expected for a deb produced by the 1.0.17 builder:

- `AnalysisVersion=1.0.17`;
- runtime architecture is `arm64` or `arm64e` as appropriate for the loaded slice;
- `LoadedImage` resolves to `RootHide.app/Frameworks/RCInjectAnalysis.dylib`;
- `LoadedImageUUID` is non-empty;
- `LoadedPathExpected=YES`;
- `HostWeakLoadPresent=YES`;
- `MenuHooksInstalled=YES`;
- hook install attempts is normally `1` (a later successful retry is acceptable if the host class was not ready on the first constructor attempt);
- `ManifestPresent=YES`;
- manifest version matches 1.0.17;
- manifest UUID for the current runtime architecture matches the in-memory loaded slice UUID;
- `ManifestLoadMode=weak`;
- install-name equals `@executable_path/Frameworks/RCInjectAnalysis.dylib`;
- manifest signed-dylib SHA-256 is non-empty;
- `RuntimeSelfCheck=PASS`;
- `HostExecutableState=YES`, with uid `0`, gid `0`, executable + setuid; actual mode is reported;
- `DylibFileState=YES`.

If the Analysis menu is visible but the manifest is missing, the current slice UUID mismatches the manifest, or the host weak load is absent, treat that as a loose/development load or packaging mismatch and return the full report before debugging scanner logic. If the menu is not visible, capture device crash/logging and verify the built deb with `Integration/verify_release.py` before changing detection code.

## B2. Static final-package gate

Before installing the generated deb, run:

```sh
python3 Integration/verify_release.py \
  '/path/to/original.deb' \
  --built-deb '/path/to/com.roothide.manager_1.3.9+bindtrust1+analysis1.0.17.deb'
```

Expected: `RELEASE GATE PASS`. The package-delta subcheck must report that only the RootHide executable and Version field changed and only the Analysis dylib/buildinfo files were added. Any other changed/removed/new original package entry is a stop condition.

## C. RootHide runtime profile

Open `环境检查` → `RootHide 运行环境` before interpreting scan results.

Expected on the target RootHide baseline:

- `RootHide: 检测到`;
- `jbroot: 可用`;
- `jbroot image` identifies the image that exports the symbol when resolvable;
- logical and mapped paths are displayed for TweakInject, DPKG status/info and RootHideConfig.

Do not require `Path mapping: ACTIVE` as a universal PASS condition. Compare the mapped paths with the capability checks instead.

## D. Capability / preflight gate

Inspect `启动自检`.

Expected on a normal packaged RootHide target:

- `Analysis loaded path` PASS;
- `RootHide host weak load` PASS;
- `Analysis build manifest` PASS;
- `RootHide menu hooks` PASS;
- `Runtime release self-check` PASS;
- `RootHide jbroot` PASS;
- `SettingViewController` PASS;
- `LSApplicationWorkspace` PASS;
- `TweakInject path` PASS;
- `DPKG status` PASS;
- `DPKG info` PASS;
- RootHide config is either present or explicitly using RootHide default semantics.

A WARN is not automatically an Analysis bug. Return the complete report before interpreting dependent empty results.

## E. Scan timeline / performance

Record:

- `Scan-ID` for each refresh;
- total duration;
- tweak + DPKG phase;
- LaunchServices phase;
- blacklist phase;
- match-graph phase;
- TrollFools / embedded phase;
- embedded entries visited;
- Apps actually deep-scanned;
- incomplete App count;
- `timeLimitedApps`;
- `globalSkippedApps`;
- slowest embedded App + duration.

1.0.17 budgets are deliberately soft: 50,000 entries/App, 1.5s/App and 12s total for the TrollFools phase. If any budget fires, verify that the report contains `[Budget / Anomaly Locator]` and the exact stop reason (`entry-limit`, `per-app-time` or `global-time`).

A budget hit must change only the TrollFools/embedded source to partial/not-scanned. DPKG, Filter, blacklist and orphan-registration results must remain available. An App skipped after the global budget expires must never be presented as a clean TrollFools result.

Open Analysis/Environment repeatedly without pressing `重新扫描`; the current snapshot should be reused. Explicit rescan behavior is verified in section L.

## F. Analysis home contract

Open `注入分析`.

Expected:

- the home page contains only `扫描摘要`, `系统注入`, and `App 注入`;
- Apps with neither DPKG-owned tweak evidence nor TrollFools evidence are not listed in `App 注入`;
- `系统注入` contains only confirmed system-process / explicit system Bundle targets;
- unresolved Filter targets are not promoted to system injection;
- no scanner-centric evidence-count/Mach-O/Load summary is used as the App-row label.

## G. DEB App injection

Choose an App known to be affected by a RootHide tweak whose package ownership is confirmed by DPKG.

Expected:

- the App appears in `App 注入`;
- the row identifies `DEB（包管理器）` and the number of matching plugins;
- opening the App shows a `DEB（包管理器）` section before technical App state;
- each plugin shows display name, Package, Version, and RootHide blacklist/injection configuration state;
- the UI does not claim the frontend was definitely Sileo or another package-manager frontend unless separately proven.

If DPKG ownership is unavailable or ambiguous, the UI must not invent a DEB/package-manager source.

## H. TrollFools App injection

Use an App whose TrollFools state is already known.

Expected active case:

- the App appears in `App 注入`;
- the row identifies `TrollFools` and counts unique Load Paths when available;
- opening the App shows a `TrollFools` section directly;
- each unique injected dylib is listed by load-path filename;
- `.troll-fools.bak` evidence plus a current Mach-O Load Command absent from the backup confirms the active difference.

Expected fallback case:

- if high-confidence evidence exists but a reliable unique Load Path count is unavailable, show `TrollFools · 已发现注入证据`;
- raw evidence-record count must not be labelled as a plugin count.

Expected inactive/skipped case:

- backup marker alone is not called active injection;
- missing/nonexistent Bundle Path or an ineligible path is `NOT SCANNED` / `未执行`, not `未发现 TrollFools`.

## I. App with both injection sources

If available, choose an App with both DPKG-owned RootHide tweak matches and TrollFools evidence.

Expected:

- the App appears only once in `App 注入`;
- the row summarizes both sources;
- the App detail contains both `DEB（包管理器）` and `TrollFools` sections;
- no separate home panel claims that coexistence proves a runtime conflict or runtime load.

## J. System injection

Use known system-targeting tweaks.

Expected:

- `Filter.Bundles` explicit system targets such as SpringBoard are shown in `系统注入`;
- `Filter.Executables` targets confirmed through the system process/launchd model are shown in `系统注入`;
- an executable matching a registered App's `bundleExecutable` stays in `App 注入`, not `系统注入`;
- arbitrary unresolved identifiers are not called system injection.

## K. Unresolved Filter targets

Open `环境检查`.

Expected:

- `未解析 Filter 目标` is absent when there are zero unresolved targets;
- when unresolved Bundle/Executable targets really exist, the section appears;
- unresolved does not mean system injection and does not mean an App is uninstalled;
- confirmed system targets are not duplicated into this section.

## L. Snapshot reuse / explicit rescan

Without pressing `重新扫描`, switch between `注入分析` and `环境检查` repeatedly.

Expected:

- the same process-local snapshot is reused;
- scan time remains unchanged;
- pages do not start duplicate full scans just by opening them.

Then press `重新扫描` once.

Expected:

- the button changes to `扫描中…` and is temporarily disabled;
- the old snapshot may remain visible, but the UI explicitly says `当前显示上一次结果`;
- when the scan completes, the button returns to `重新扫描`;
- the scan time advances to the new snapshot time;
- concurrent requests coalesce into one active scan rather than starting duplicate scans.

## M. Orphan / white-icon registration

Test controls first:

- normal App → must not be reported;
- TrollStore App → must not be reported merely because of install source;
- normal RootHide App → must not be reported.

Then test one genuine white-icon residual registration if available.

High-confidence orphan report requires all of:

- LaunchServices registration present;
- Bundle ID present;
- file URL/path obtainable;
- path is a `.app` path;
- actual `.app` path does not exist.

For such an orphan, TrollFools deep scan should be shown as not executed because the `.app` path is missing. No unregister or icon-cache action should be offered in 1.0.17.

## N. Stale blacklist record

Expected residue requires:

- `appconfig[bundleID]` stored truthy;
- Bundle ID absent from the current LaunchServices snapshot.

Stored false entries must not be reported as stale blacklist residue.

If `blacklistDisabled=YES`, treat ordinary per-App blacklist state as unsupported/unknown for injection-permission inference.

## O. Per-App report

On each test App, tap `报告`.

Verify the report contains:

- `APP READ ONLY REPORT`;
- Bundle ID / path / installation-source evidence;
- snapshot capabilities;
- `Scan-ID`;
- `EmbeddedScanAttempted`, `Truncated`, `Entries`, `Duration`, `StopReason`, time-budget/global-skip state and `Status`;
- `[Evidence Layers]` including Layer 4 runtime-proof-not-collected wording;
- RootHide Filter matches with plist/Bundles evidence;
- TrollFools backup/load evidence when present;
- interpretation wording that does not claim a runtime conflict.

The report is shared as an in-memory string; Analysis should not create a diagnostic file.

## P. Full report handling

Tap `报告` on `注入分析` or `环境检查` and return:

1. the complete full report;
2. the per-App report for each failed/interesting case;
3. the App used for the multi-tweak test;
4. the tweak used for DPKG ownership;
5. the Apps used for TrollStore/TrollFools tests;
6. whether a genuine white-icon residual registration was available.

Reports may include App names, Bundle IDs, package IDs/versions and filesystem paths. Review them before sharing outside a trusted debugging context.

## Stop conditions

Rollback immediately to the original RootHide deb if any of these occur:

- RootHide Manager no longer launches;
- original blacklist UI/functionality changes unexpectedly;
- repeated Analysis menu insertion;
- scan causes persistent UI hang;
- a normal control App is reported as high-confidence orphan registration;
- a skipped/unavailable source is presented as a definitive clean result;
- Analysis performs any state-changing action.
