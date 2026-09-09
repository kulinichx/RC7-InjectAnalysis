#!/usr/bin/env python3
"""Fail closed on the current Analysis release source invariants that protect the RootHide baseline."""
import re
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
src = root / 'Sources'
errors = []

# Public UI/release surfaces use product names only; internal release codenames must not leak.
_public_release_labels = ('RC' + '7', 'RC' + '8')
_public_release_files = [
    src / 'RCEntry.mm', src / 'RCBlacklistStateScanner.m', src / 'RCDiagnostics.m',
    src / 'RCAnalysisViewController.m', src / 'RCAppDetailViewController.m', src / 'RCEnvironmentViewController.m',
    root / 'FIELD-REPORT-TEMPLATE.md', root / 'DEPLOYMENT-README.md',
    root / 'RELEASE-CHECKLIST.md', root / 'FIRST-RUN-TEST.md',
    root / 'Integration' / 'README.md', root / 'Integration' / 'BASELINE.md',
    root / 'Integration' / 'make_deployment_kit.py', root / 'Integration' / 'make_release_receipt.py',
    root / 'Integration' / 'verify_deployment_kit.py',
]
for _path in _public_release_files:
    if not _path.exists():
        errors.append(f'public release surface missing: {_path.name}')
        continue
    _text = _path.read_text(encoding='utf-8', errors='replace')
    for _label in _public_release_labels:
        if _label in _text:
            errors.append(f'public release surface contains internal codename: {_path.name}')


# Build-source filenames use neutral RootHide naming as well.
for _path in (root / 'Integration').iterdir():
    _name = _path.name.lower()
    if ('rc' + '7') in _name or ('rc' + '8') in _name:
        errors.append(f'build-source filename contains internal codename: {_path.name}')
for _required in ('build_roothide_deb.sh', 'verify_roothide_baseline.py', 'RootHide-1.3.9+bindtrust1.entitlements.plist'):
    if not (root / 'Integration' / _required).exists():
        errors.append(f'neutral RootHide build-source file missing: {_required}')


entry = (src / 'RCEntry.mm').read_text(encoding='utf-8')
if '@"URL"' in entry or '[@"URL"]' in entry:
    errors.append('RCEntry uses uppercase URL key; RootHide native schema is lowercase url')
for token in ('@"type": @"url"', '@"url": @"rcanalysis://injection"', '@"url": @"rcanalysis://environment"'):
    if token not in entry:
        errors.append(f'RCEntry missing required native-menu token: {token}')

all_text = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in src.iterdir() if p.suffix in ('.h', '.m', '.mm'))
for pattern, label in [
    (r'\bremoveItemAt(?:Path|URL)\s*:', 'file deletion'),
    (r'\bunregisterApplication\s*:', 'LaunchServices unregister'),
    (r'\bwriteToFile\s*:', 'file write'),
    (r'\bwriteToURL\s*:', 'file write'),
    (r'\bsetDefaults\s*:', 'RootHide settings write'),
    (r'\b(?:unlink|unlinkat|rmdir|rename)\s*\(', 'POSIX filesystem mutation'),
    (r'\b(?:system|posix_spawn|posix_spawnp)\s*\(', 'external process spawn'),
]:
    if re.search(pattern, all_text):
        errors.append(f'forbidden Analysis mutation primitive present: {label}')

black = (src / 'RCBlacklistStateScanner.m').read_text(encoding='utf-8')
if 'RootHideConfig.plist' not in black or 'appconfig' not in black or 'blacklistDisabled' not in black:
    errors.append('read-only blacklist scanner is missing expected RootHide config keys')

dpkg = (src / 'RCDpkgResolver.m').read_text(encoding='utf-8')
if 'RCDetectionConfidenceHigh' not in dpkg or 'RCDetectionConfidenceMedium' not in dpkg or 'ownersByBasename' not in dpkg:
    errors.append('DPKG resolver does not preserve exact-path vs basename confidence split')

tweak_scanner = (src / 'RCTweakScanner.m').read_text(encoding='utf-8')
for token in ('Bundles', 'Executables', 'executableIdentifiers', 'installedTargetExecutableIdentifiers',
              'systemTargetExecutableIdentifiers', 'unresolvedTargetExecutableIdentifiers', 'packageOwningInstalledPath'):
    if token not in tweak_scanner:
        errors.append(f'current-release tweak target/source scanner token missing: {token}')

app = (src / 'RCAppScanner.m').read_text(encoding='utf-8')
for token in ('bundleURL.isFileURL', 'pathExtension.lowercaseString', '_TrollStore', '_TrollStoreLite'):
    if token not in app:
        errors.append(f'App scanner missing conservative/source token: {token}')

mach = (src / 'RCMachOScanner.m').read_text(encoding='utf-8')
for token in ('/var/containers/Bundle/Application/', '.troll-fools.bak', 'minusSet:before', 'activeDifferenceConfirmed = YES', 'result.scanAttempted = YES', '不作未发现结论'):
    if token not in mach:
        errors.append(f'Mach-O scanner missing TrollFools evidence invariant: {token}')
for token in ('maxEntries', 'result.truncated = YES', 'result.entriesVisited', 'deadline', 'timeBudgetExceeded', '@"entry-limit"', '@"per-app-time"'):
    if token not in mach:
        errors.append(f'current-release bounded evidence-scan invariant missing: {token}')

manager = (src / 'RCAnalysisManager.m').read_text(encoding='utf-8')
for token in ('scanInProgress', 'pendingCompletions', 'loadSnapshotWithCompletion',
              'requestSnapshotForceRefresh', 'analysis request coalesced into active scan',
              'RCEmbeddedEntryLimitPerApp', 'RCEmbeddedTimeLimitPerApp', 'RCEmbeddedTotalTimeLimit', 'embeddedAppsTruncated',
              'embeddedAppsTimeLimited', 'embeddedAppsSkippedByGlobalBudget',
              'embeddedIdentities', 'targetMachOPath', 'backupPath', 'loadPath',
              'appsByExecutable', 'bundleExecutable', 'RCSystemExecutableIdentifiers',
              '/System/Library/LaunchDaemons', '/System/Library/LaunchAgents',
              'installedTargetExecutableIdentifiers', 'systemTargetExecutableIdentifiers',
              'unresolvedTargetExecutableIdentifiers', 'containsObject:tweak',
              'launchServicesAvailable', 'tweakScanAvailable', 'dpkgStatusAvailable', 'dpkgInfoAvailable'):
    if token not in manager:
        errors.append(f'current-release scan-coalescing/budget invariant missing: {token}')

view = (src / 'RCAnalysisViewController.m').read_text(encoding='utf-8')
for token in ('扫描摘要', '系统注入', 'App 注入', '本次分析不完整', 'embeddedAppsTruncated',
              '当前进程内结果可复用', '重新扫描', '扫描中…', '正在重新扫描…', '当前显示上一次结果',
              'rescanButton', 'loadSnapshot', 'forceRefresh',
              'systemInjectionTweaks', 'Filter.Executables', 'systemTargetExecutableIdentifiers',
              'injectedApps', 'dpkgTweaksForApp', 'trollFoolsSummaryForApp',
              'DEB（包管理器）', 'TrollFools', '未注入 App 已收纳', 'shareReport', 'fullReadOnlyReportForSnapshot'):
    if token not in view:
        errors.append(f'current-release three-panel injection UI invariant missing: {token}')
for forbidden in ('单 App 深度分析', '多插件 Filter 匹配', '其它注入（按 App）', 'RootHide 允许 + TrollFools 活动注入', '证据 %lu 条'):
    if forbidden in view:
        errors.append(f'current-release Analysis home has obsolete panel/debug wording: {forbidden}')


env = (src / 'RCEnvironmentViewController.m').read_text(encoding='utf-8')
for token in ('孤立注册扫描不可用', '未解析 Filter 目标', 'unresolvedFilterTweaks',
              'com.apple.springboard', 'SpringBoard 系统进程',
              'com.apple.backboardd', 'backboardd 系统进程',
              'Filter.Executables 未解析目标', 'Filter.Bundles 未解析目标',
              '未解析不代表系统注入，也不代表 App 已卸载', '此项仅在确有未解析目标时显示',
              '扫描中…', '当前显示上一次结果', 'rescanButton',
              'shareReport', 'fullReadOnlyReportForSnapshot'):
    if token not in env:
        errors.append(f'current-release fail-unknown environment UI invariant missing: {token}')
if '系统级 / 未解析 Filter 目标' in env:
    errors.append('current-release Environment UI must not mix confirmed system targets with unresolved Filter targets')
if 'hasPrefix:@"com.apple."' in env or 'hasPrefix:@"com.apple."' in view:
    errors.append('current-release system injection must not classify every com.apple.* identifier as a system process')


diag = (src / 'RCDiagnostics.m').read_text(encoding='utf-8')
for token in ('READ ONLY DIAGNOSTIC REPORT', '[Capabilities]', '[Metrics]', '[Budget / Anomaly Locator]', 'Scan-ID:', '[Multi-match Apps]', '[Orphan Registrations]', '[Embedded / TrollFools Evidence]'):
    if token not in diag:
        errors.append(f'current-release diagnostic-report invariant missing: {token}')
if 'writeToFile' in diag or 'writeToURL' in diag:
    errors.append('current-release diagnostic report must remain in-memory/read-only')

detail = (src / 'RCAppDetailViewController.m').read_text(encoding='utf-8')
for token in ('DEB（包管理器）', 'TrollFools', 'App 状态', 'dpkgTweaks', 'trollFoolsGroups',
              'Package：', 'Version：', 'RootHide：允许', '活动注入已确认',
              '不代表已确认冲突', 'LaunchServices：已注册', '实际 .app：存在',
              '孤立注册：数据源不完整，未判定', '名单残留：数据源不完整，未判定'):
    if token not in detail:
        errors.append(f'current-release injection-source App detail invariant missing: {token}')
for forbidden in ('未发现 Bundle ID Filter 匹配', 'RootHide Bundles Filter 匹配', '证据层级', 'Layer 0 · 数据源完整性', 'Layer 4 · 运行时进程证明'):
    if forbidden in detail:
        errors.append(f'ordinary injected-App detail has obsolete scanner-first wording: {forbidden}')

path = (src / 'RCPath.mm').read_text(encoding='utf-8')
for token in ('RCResolveJBRoot', 'RCJBRootAvailable', 'RCJBRootImagePath', 'dladdr'):
    if token not in path:
        errors.append(f'current-release RootHide compatibility token missing: {token}')

models = (src / 'RCModels.h').read_text(encoding='utf-8')
for token in ('RCEnvironmentProfile', 'RCScanTimelineEvent', 'environmentProfile', 'timeline', 'scanIdentifier',
              'embeddedTimeLimitPerApp', 'embeddedTotalTimeLimit', 'executableIdentifiers',
              'installedTargetExecutableIdentifiers', 'systemTargetExecutableIdentifiers',
              'unresolvedTargetExecutableIdentifiers'):
    if token not in models:
        errors.append(f'current-release environment/timeline model token missing: {token}')

manager = (src / 'RCAnalysisManager.m').read_text(encoding='utf-8')
for token in ('RCTimelineAdd', '@"preflight"', '@"tweak+dpkg"', '@"launchservices"', '@"blacklist"', '@"match-graph"', '@"embedded"', 'environmentProfile'):
    if token not in manager:
        errors.append(f'current-release timeline/environment manager token missing: {token}')

diag = (src / 'RCDiagnostics.m').read_text(encoding='utf-8')
for token in ('[Environment Profile]', '[Timeline]', 'RootHideDetected=', 'TweakInject:', 'DPKG-status:', 'RootHideConfig:'):
    if token not in diag:
        errors.append(f'current-release report compatibility token missing: {token}')

env = (src / 'RCEnvironmentViewController.m').read_text(encoding='utf-8')
for token in ('RootHide 运行环境', '扫描时间线', 'environmentProfile', 'pathMappingActive'):
    if token not in env:
        errors.append(f'current-release compatibility UI token missing: {token}')

detail = (src / 'RCAppDetailViewController.m').read_text(encoding='utf-8')
for token in ('DEB（包管理器）', 'Package：', 'Version：', 'RootHide：允许'):
    if token not in detail:
        errors.append(f'current-release App package-source token missing: {token}')


# current release: every registered App must be reachable through a searchable, read-only
# deep-analysis browser. Detail UI must keep capability-aware fail-unknown behavior.
browser_path = src / 'RCAppBrowserViewController.m'
if not browser_path.exists():
    errors.append('current-release App browser implementation missing')
else:
    browser = browser_path.read_text(encoding='utf-8')
    for token in ('UISearchController', '名称或 Bundle ID', 'LaunchServices 不可用',
                  'initWithAppRecord:app snapshot:self.snapshot'):
        if token not in browser:
            errors.append(f'current-release App-browser invariant missing: {token}')

view = (src / 'RCAnalysisViewController.m').read_text(encoding='utf-8')
for token in ('App 注入', 'initWithAppRecord:app snapshot:self.snapshot'):
    if token not in view:
        errors.append(f'current-release injected-App detail entry invariant missing: {token}')

detail = (src / 'RCAppDetailViewController.m').read_text(encoding='utf-8')
for token in ('readOnlyReportForApp:self.record snapshot:self.snapshot',
              'DEB（包管理器）', 'Package：', 'Version：',
              '不代表已确认冲突', 'TrollFools', 'App 状态'):
    if token not in detail:
        errors.append(f'current-release App injection-detail invariant missing: {token}')

diag = (src / 'RCDiagnostics.m').read_text(encoding='utf-8')
for token in ('APP READ ONLY REPORT', '[RootHide Filter Matches]', 'Filter.Executables contains',
              '[System / Unresolved Filter Targets]', '[Embedded / TrollFools Evidence]',
              '[Evidence Layers]', 'Layer4-RuntimeProcessProof', '[Interpretation]',
              'dual-source injection evidence, not proof of a runtime conflict', 'NOT SCANNED:', 'EmbeddedScanAttempted='):
    if token not in diag:
        errors.append(f'current-release per-App report invariant missing: {token}')

mk = (root / 'Makefile').read_text(encoding='utf-8')
source_files = sorted(p.relative_to(root).as_posix() for p in src.iterdir() if p.suffix in ('.m', '.mm'))
listed = re.findall(r'Sources/[A-Za-z0-9_+.-]+\.(?:mm|m)\b', mk)
if set(source_files) != set(listed):
    errors.append(f'Makefile source mismatch: missing={sorted(set(source_files)-set(listed))}, extra={sorted(set(listed)-set(source_files))}')
if len(listed) != len(set(listed)):
    errors.append('Makefile contains duplicate source entries')


# current-release build/runtime identity must be centralized and report the actually loaded dylib.
build_h = src / 'RCBuildInfo.h'
build_m = src / 'RCBuildInfo.m'
entry_status_h = src / 'RCEntryStatus.h'
for required in (build_h, build_m, entry_status_h):
    if not required.exists():
        errors.append(f'current-release build/runtime identity file missing: {required.name}')
if build_h.exists():
    build_header = build_h.read_text(encoding='utf-8')
    if 'extern "C"' not in build_header:
        errors.append('current-release RCBuildInfo C linkage guard missing for Objective-C++ caller')
if entry_status_h.exists():
    status_header = entry_status_h.read_text(encoding='utf-8')
    if 'extern "C"' not in status_header:
        errors.append('current-release RCEntryStatus C linkage guard missing for Objective-C caller')
if build_m.exists():
    build_text = build_m.read_text(encoding='utf-8')
    for token in ('kRCAnalysisVersion = RC_ANALYSIS_VERSION', 'RCAnalysisLoadedImagePath', 'RCAnalysisLoadedImageUUID', 'LC_UUID', 'RCAnalysisRuntimeArchitecture', 'RCAnalysisBuildManifest', 'RCInjectAnalysis.buildinfo.plist'):
        if token not in build_text:
            errors.append(f'current-release build identity token missing: {token}')
entry = (src / 'RCEntry.mm').read_text(encoding='utf-8')
for token in ('RCAnalysisVersion()', 'RCAnalysisMenuHooksInstalled', 'RCAnalysisMenuHookInstallAttempts', 'gInstallAttempts'):
    if token not in entry:
        errors.append(f'current-release menu-hook identity token missing: {token}')
models = (src / 'RCModels.h').read_text(encoding='utf-8')
for token in ('analysisImageUUID', 'analysisBuildManifestPresent', 'analysisBuildManifestVersionMatches', 'analysisMenuHooksInstalled', 'analysisMenuHookInstallAttempts'):
    if token not in models:
        errors.append(f'current-release runtime identity model token missing: {token}')
diag = (src / 'RCDiagnostics.m').read_text(encoding='utf-8')
for token in ('[Build / Runtime Identity]', 'LoadedImageUUID=', 'ManifestPresent=', 'ManifestDylibSHA256=', 'MenuHooksInstalled=', 'Analysis build manifest', 'Analysis dylib identity'):
    if token not in diag:
        errors.append(f'current-release runtime identity report/preflight token missing: {token}')
env = (src / 'RCEnvironmentViewController.m').read_text(encoding='utf-8')
for token in ('Analysis / RootHide 运行环境', '载入状态：', 'analysisImageUUID', 'analysisBuildManifestDylibSHA256'):
    if token not in env:
        errors.append(f'current-release runtime identity UI token missing: {token}')

# Keep the user-visible Analysis version single-sourced from RCBuildInfo.m.
for source in src.iterdir():
    if source.suffix not in ('.h', '.m', '.mm') or source.name == 'RCBuildInfo.m':
        continue
    text = source.read_text(encoding='utf-8', errors='replace')
    if source.name == 'RCVersion.generated.h':
        continue
    if 'RC_ANALYSIS_VERSION' in text and source.name != 'RCBuildInfo.m':
        errors.append(f'generated version macro referenced outside RCBuildInfo.m: {source.name}')

integ = root / 'Integration'
for required in ('make_build_manifest.py', 'verify_build_manifest.py', 'verify_release.py', 'verify_package_delta.py'):
    if not (integ / required).exists():
        errors.append(f'current-release integration identity verifier missing: {required}')
builder = (integ / 'build_roothide_deb.sh').read_text(encoding='utf-8')
for token in ('RCInjectAnalysis.buildinfo.plist', 'make_build_manifest.py', 'verify_build_manifest.py', 'SUFFIX="+analysis$VERSION"'):
    if token not in builder:
        errors.append(f'current-release builder identity token missing: {token}')

# current release: runtime self-check must bind loaded image UUID to the signed build manifest
# and prove the host executable contains the expected weak load command.
build_text = (src / 'RCBuildInfo.m').read_text(encoding='utf-8')
for token in ('RCAnalysisLoadedImagePathLooksExpected', 'RCAnalysisHostHasExpectedWeakLoad', 'RCAnalysisHostWeakLoadDetail',
              'RCDiskHostHasExpectedWeakLoad', 'NSBundle.mainBundle.executablePath', 'FAT_MAGIC',
              'current-architecture slice', '_dyld_get_image_header(0)', 'LC_LOAD_WEAK_DYLIB'):
    if token not in build_text:
        errors.append(f'current-release runtime self-check build token missing: {token}')
models = (src / 'RCModels.h').read_text(encoding='utf-8')
for token in ('analysisImagePathExpected', 'analysisHostWeakLoadPresent', 'analysisBuildManifestUUIDMatches', 'analysisBuildManifestSchema', 'analysisBuildID', 'analysisBuildManifestSourceTreeSHA256', 'analysisBuildManifestSourceFileCount', 'analysisRuntimeSelfCheckStatus', 'analysisRuntimeSelfCheckSummary'):
    if token not in models:
        errors.append(f'current-release runtime self-check model token missing: {token}')
diag = (src / 'RCDiagnostics.m').read_text(encoding='utf-8')
for token in ('DylibUUIDs', 'manifest-uuid', 'manifest-schema', 'manifest-build-id', 'manifest-source-provenance', 'BuildID=', 'SourceTreeSHA256=', 'host-weak-load', '[Runtime Release Self-Check]', 'RuntimeSelfCheck=', 'RootHide host weak load', 'Runtime release self-check'):
    if token not in diag:
        errors.append(f'current-release runtime self-check diagnostic token missing: {token}')
env = (src / 'RCEnvironmentViewController.m').read_text(encoding='utf-8')
for token in ('Runtime Self-Check', 'analysisHostWeakLoadPresent', 'analysisBuildManifestUUIDMatches'):
    if token not in env:
        errors.append(f'current-release runtime self-check UI token missing: {token}')

manifest_maker = (root / 'Integration' / 'make_build_manifest.py').read_text(encoding='utf-8')
manifest_verify = (root / 'Integration' / 'verify_build_manifest.py').read_text(encoding='utf-8')
for text, name in ((manifest_maker, 'make_build_manifest.py'), (manifest_verify, 'verify_build_manifest.py')):
    for token in ('ManifestSchema', 'DylibUUIDs', 'arm64', 'arm64e'):
        if token not in text:
            errors.append(f'current-release UUID manifest token missing in {name}: {token}')
if '"ManifestSchema": 3' not in manifest_maker:
    errors.append('current-release build manifest schema must be 3')
if 'm.get("ManifestSchema") == 3' not in manifest_verify:
    errors.append('current-release build manifest verifier must require schema 3')
for token in ('SourceTreeSHA256', 'SourceFileCount', 'BuildID', 'source_fingerprint'):
    if token not in manifest_maker or token not in manifest_verify:
        errors.append(f'current-release build provenance token missing: {token}')

delta = root / 'Integration' / 'verify_package_delta.py'
if not delta.exists():
    errors.append('current-release package-delta verifier missing')
else:
    delta_text = delta.read_text(encoding='utf-8')
    for token in ('ALLOWED_CHANGED', 'ALLOWED_NEW', 'RCInjectAnalysis.dylib', 'RCInjectAnalysis.buildinfo.plist', 'DEBIAN/control'):
        if token not in delta_text:
            errors.append(f'current-release package-delta token missing: {token}')
release_text = (root / 'Integration' / 'verify_release.py').read_text(encoding='utf-8')
if 'verify_package_delta.py' not in release_text:
    errors.append('current-release release gate must run package-delta verifier')
builder_text = (root / 'Integration' / 'build_roothide_deb.sh').read_text(encoding='utf-8')
if 'VERIFY_DELTA' not in builder_text or 'verify_package_delta.py' not in builder_text:
    errors.append('current-release builder must run package-delta verifier')

# Build-handoff invariants: one version source, generated ObjC header, fail-closed Theos artifact selection, and one-command release pipeline.
for required in ('versioning.py', 'generate_version_header.py', 'verify_version_consistency.py', 'check_toolchain.py', 'find_built_dylib.py', 'release_pipeline.sh', 'make_release_receipt.py', 'source_fingerprint.py', 'make_source_snapshot.py', 'verify_source_snapshot.py'):
    if not (integ / required).exists():
        errors.append(f'build-handoff tool missing: {required}')
version_file = root / 'VERSION'
version_header = src / 'RCVersion.generated.h'
if not version_file.is_file() or not version_header.is_file():
    errors.append('central VERSION or generated Objective-C version header missing')
else:
    version_value = version_file.read_text(encoding='utf-8').strip()
    if f'#define RC_ANALYSIS_VERSION @"{version_value}"' not in version_header.read_text(encoding='utf-8'):
        errors.append('generated Objective-C version header does not match VERSION')
if 'Integration/generate_version_header.py' not in mk or 'before-all::' not in mk:
    errors.append('Makefile does not regenerate the Objective-C version header before build')
pipeline = (integ / 'release_pipeline.sh').read_text(encoding='utf-8') if (integ / 'release_pipeline.sh').exists() else ''
for token in ('check_toolchain.py', 'verify_version_consistency.py', 'make_source_snapshot.py', 'verify_source_snapshot.py', 'find_built_dylib.py', 'build_roothide_deb.sh', 'verify_release.py', 'make_release_receipt.py'):
    if token not in pipeline:
        errors.append(f'release pipeline missing stage: {token}')
finder = (integ / 'find_built_dylib.py').read_text(encoding='utf-8') if (integ / 'find_built_dylib.py').exists() else ''
for token in ('multiple different valid dylib builds found', 'arm64', 'arm64e', 'RC_ANALYSIS_DYLIB'):
    if token not in finder and token != 'RC_ANALYSIS_DYLIB':
        errors.append(f'fail-closed dylib selector invariant missing: {token}')
if 'RC_ANALYSIS_DYLIB' not in pipeline:
    errors.append('release pipeline lacks explicit RC_ANALYSIS_DYLIB override for ambiguous builds')

receipt = (integ / 'make_release_receipt.py').read_text(encoding='utf-8') if (integ / 'make_release_receipt.py').exists() else ''
if 'verify_release.py' not in receipt or '--built-deb' not in receipt:
    errors.append('release receipt must self-verify the exact built deb before claiming PASS')
for token in ('BuildID=', 'SourceTreeSHA256=', 'SourceFileCount='):
    if token not in receipt:
        errors.append(f'release receipt missing source/build provenance token: {token}')

baseline = (root / 'Integration' / 'verify_roothide_baseline.py').read_text(encoding='utf-8')
for token in ('EXPECTED_SHA256', 'c12b596acd1856677b8fb9753fcebdd88c7601318f10b6b7a8926e2568de687e', 'SHA-256 mismatch'):
    if token not in baseline:
        errors.append(f'exact RootHide baseline gate missing: {token}')


# current-release first-device installation contract + deployment-kit invariants.
build_h_text = (src / 'RCBuildInfo.h').read_text(encoding='utf-8')
build_m_text = (src / 'RCBuildInfo.m').read_text(encoding='utf-8')
for token in ('RCAnalysisHostExecutableFileState', 'RCAnalysisLoadedDylibFileState'):
    if token not in build_h_text or token not in build_m_text:
        errors.append(f'current-release runtime file-state API missing: {token}')
for token in ('expected uid=0 gid=0 regular executable with setuid', 'S_ISUID', 'stat(path.fileSystemRepresentation'):
    if token not in build_m_text:
        errors.append(f'current-release postinstall runtime-state invariant missing: {token}')
models_text = (src / 'RCModels.h').read_text(encoding='utf-8')
for token in ('analysisHostExecutablePostInstallStateExpected', 'analysisHostExecutableMode', 'analysisHostExecutableSetUID', 'analysisDylibFileStateExpected'):
    if token not in models_text:
        errors.append(f'current-release install-state model token missing: {token}')
diag_text = (src / 'RCDiagnostics.m').read_text(encoding='utf-8')
for token in ('host-postinstall-state', 'dylib-file-state', 'HostExecutableState=', 'HostPostInstallState=', 'RootHide postinstall file state'):
    if token not in diag_text:
        errors.append(f'current-release install-state diagnostic token missing: {token}')
env_text = (src / 'RCEnvironmentViewController.m').read_text(encoding='utf-8')
if '安装后文件状态' not in env_text:
    errors.append('current-release environment UI missing install-state row')
for required in ('verify_original_deb.py', 'verify_postinstall_contract.py', 'make_deployment_kit.py', 'verify_deployment_kit.py'):
    if not (integ / required).exists():
        errors.append(f'current-release deployment tool missing: {required}')

orig_deb_gate = (integ / 'verify_original_deb.py').read_text(encoding='utf-8') if (integ/'verify_original_deb.py').exists() else ''
for token in ('EXPECTED_DEB_SHA256', '5392005d50c2a3e6189545e408aa4723bad401995ec508efcb48010c53d57f28', '1.3.9+bindtrust1', 'iphoneos-arm64e'):
    if token not in orig_deb_gate:
        errors.append(f'current-release exact original-deb gate token missing: {token}')

postinstall_text = (integ / 'verify_postinstall_contract.py').read_text(encoding='utf-8') if (integ/'verify_postinstall_contract.py').exists() else ''
for token in ('EXPECTED_POSTINST_SHA256', 'uicache -p /Applications/RootHide.app', 'chown 0:0 /Applications/RootHide.app/RootHide', 'chmod +s /Applications/RootHide.app/RootHide'):
    if token not in postinstall_text:
        errors.append(f'current-release postinstall contract token missing: {token}')
pipeline_text = (integ / 'release_pipeline.sh').read_text(encoding='utf-8')
for token in ('make_deployment_kit.py', 'verify_deployment_kit.py', 'DEPLOYMENT_KIT', 'SOURCE_PROVENANCE', 'SOURCE_SNAPSHOT'):
    if token not in pipeline_text:
        errors.append(f'current-release release pipeline deployment/provenance stage missing: {token}')
kit_make=(integ/'make_deployment_kit.py').read_text(encoding='utf-8') if (integ/'make_deployment_kit.py').exists() else ''
kit_verify=(integ/'verify_deployment_kit.py').read_text(encoding='utf-8') if (integ/'verify_deployment_kit.py').exists() else ''
for token in ('DeploymentSchema', 'BuildIdentity', 'SourceProvenance', 'SourceSnapshot', 'PreInstall', 'BuildID', 'SourceTreeSHA256'):
    if token not in kit_make or token not in kit_verify:
        errors.append(f'current-release deployment provenance token missing: {token}')
if '--preverified' not in kit_make or '--preverified' not in pipeline_text:
    errors.append('current-release pipeline preverified optimization missing; final verify_deployment_kit must remain mandatory')
for _doc in ('README.md', 'GITHUB-BUILD.md', 'FIELD-REPORT-TEMPLATE.md', 'DEPLOYMENT-README.md', 'RELEASE-CHECKLIST.md', 'FIRST-RUN-TEST.md'):
    if _doc not in kit_make:
        errors.append(f'current-release deployment kit missing replay document input: {_doc}')
for _token in ('release-replay', 'source_root', "--project-root", 'replay release document missing'):
    if _token not in kit_verify:
        errors.append(f'current-release deployment verifier is not snapshot-replay self-contained: {_token}')
release_text = (integ / 'verify_release.py').read_text(encoding='utf-8')
if 'verify_original_deb.py' not in release_text:
    errors.append('current-release release gate must pin the exact original RootHide deb')
if 'verify_postinstall_contract.py' not in release_text:
    errors.append('current-release final release gate must verify unchanged postinstall contract')


# Current release documentation must match the three-panel UI and current rescan semantics.
_current_docs = [root / 'README.md', root / 'GITHUB-BUILD.md', root / 'FIELD-REPORT-TEMPLATE.md', root / 'FIRST-RUN-TEST.md']
for _path in _current_docs:
    if not _path.exists():
        errors.append(f'current-release documentation missing: {_path.name}')
        continue
    _text = _path.read_text(encoding='utf-8', errors='replace')
    for _stale_version in ('1.0.14', '1.0.15', '1.0.16'):
        if _stale_version in _text:
            errors.append(f'current-release documentation has stale Analysis version: {_path.name}: {_stale_version}')
_first_run = (root / 'FIRST-RUN-TEST.md').read_text(encoding='utf-8')
for _token in ('扫描摘要', '系统注入', 'App 注入', 'DEB（包管理器）', 'TrollFools', '未解析 Filter 目标', '扫描中…', '当前显示上一次结果'):
    if _token not in _first_run:
        errors.append(f'current-release first-run documentation token missing: {_token}')
for _obsolete in ('单 App 深度分析', 'RootHide 允许 + TrollFools 活动注入', '多插件 Filter 匹配'):
    if _obsolete in _first_run:
        errors.append(f'current-release first-run documentation has obsolete UI token: {_obsolete}')

# README must describe the current user-facing Analysis model.
_readme = (root / 'README.md').read_text(encoding='utf-8')
for _token in ('扫描摘要', '系统注入', 'App 注入', 'DEB（包管理器）', 'TrollFools'):
    if _token not in _readme:
        errors.append(f'current-release README model token missing: {_token}')
for _obsolete in ('does not broaden the detection surface',
                  'searchable single-App deep analysis',
                  'evidence Layer 0–4 wording'):
    if _obsolete in _readme:
        errors.append(f'current-release README has obsolete Analysis description: {_obsolete}')

# Archive-level package metadata must remain baseline-exact; build-host uid/gid must not leak into the deb.
delta_text = (integ / 'verify_package_delta.py').read_text(encoding='utf-8')
for token in ('archive_metadata', 'verify_archive_metadata', 'ar_metadata', 'verify_ar_metadata', 'EXPECTED_NEW_MODES', 'uname', 'gname', 'mtime'):
    if token not in delta_text:
        errors.append(f'current-release archive-metadata gate missing: {token}')
repack_text = (integ / 'repack_deb_preserving_metadata.py').read_text(encoding='utf-8') if (integ/'repack_deb_preserving_metadata.py').exists() else ''
for token in ('numeric uid=501/gid=20', 'uname/gname are root/wheel', 'rebuild_tar', 'FORMAT_ALONE', 'BASELINE_PARENT'):
    if token not in repack_text:
        errors.append(f'current-release baseline-aware repacker token missing: {token}')
builder_text = (integ / 'build_roothide_deb.sh').read_text(encoding='utf-8')
for token in ('repack_deb_preserving_metadata.py', 'numeric uid=501/gid=20', 'uname=root/gname=wheel', 'chmod 0755 "$APP/Frameworks"'):
    if token not in builder_text:
        errors.append(f'current-release metadata-preserving builder token missing: {token}')
pipeline_text = (integ / 'release_pipeline.sh').read_text(encoding='utf-8')
if 'fakeroot' in pipeline_text or 'chown -R 0:20' in builder_text:
    errors.append('current-release pipeline must not depend on fakeroot/chown normalization; tar metadata is rebuilt from baseline')

if errors:
    for e in errors:
        print('ERROR:', e, file=sys.stderr)
    raise SystemExit(2)
print(f'source invariants verified: {len(source_files)} implementation files; read-only/menu/source-detection gates present')
print('current-release operational invariants verified: prior evidence/budget gates + UUID-bound runtime self-check + host weak-load proof + package-delta verifier')
