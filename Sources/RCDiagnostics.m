#import "RCDiagnostics.h"
#import "RCPath.h"
#import "RCModels.h"
#import "RCBuildInfo.h"
#import "RCEntryStatus.h"
#import <objc/runtime.h>
#import <stdarg.h>

@implementation RCDiagnosticItem
@end

void RCLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *body = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[RCInjectAnalysis] %@", body);
}

static RCDiagnosticItem *RCCheck(NSString *name, BOOL passed, NSString *detail) {
    RCDiagnosticItem *i = [RCDiagnosticItem new];
    i.name = name ?: @"";
    i.passed = passed;
    i.detail = detail ?: @"";
    return i;
}

static NSString *RCBoolText(BOOL value) { return value ? @"YES" : @"NO"; }

static NSString *RCTweakMatchReasonForApp(RCTweakRecord *tweak, RCAppRecord *app) {
    NSMutableArray<NSString *> *reasons = [NSMutableArray array];
    if (app.bundleIdentifier.length && [tweak.bundleIdentifiers containsObject:app.bundleIdentifier]) {
        [reasons addObject:[NSString stringWithFormat:@"Filter.Bundles contains %@", app.bundleIdentifier]];
    }
    if (app.bundleExecutable.length && [tweak.executableIdentifiers containsObject:app.bundleExecutable]) {
        [reasons addObject:[NSString stringWithFormat:@"Filter.Executables contains %@", app.bundleExecutable]];
    }
    return reasons.count ? [reasons componentsJoinedByString:@" + "] : @"matched by analysis graph";
}

@implementation RCDiagnostics
- (RCEnvironmentProfile *)environmentProfile {
    RCEnvironmentProfile *p = [RCEnvironmentProfile new];
    p.jbrootAvailable = RCJBRootAvailable();
    p.jbrootImagePath = RCJBRootImagePath() ?: @"";

    p.tweakInjectLogicalPath = @"/usr/lib/TweakInject";
    p.dpkgStatusLogicalPath = @"/Library/dpkg/status";
    p.dpkgInfoLogicalPath = @"/Library/dpkg/info";
    p.rootHideConfigLogicalPath = @"/var/mobile/Library/RootHide/RootHideConfig.plist";

    p.tweakInjectMappedPath = RCRootPath(p.tweakInjectLogicalPath) ?: @"";
    p.dpkgStatusMappedPath = RCRootPath(p.dpkgStatusLogicalPath) ?: @"";
    p.dpkgInfoMappedPath = RCRootPath(p.dpkgInfoLogicalPath) ?: @"";
    p.rootHideConfigMappedPath = RCRootPath(p.rootHideConfigLogicalPath) ?: @"";

    p.pathMappingActive = ![p.tweakInjectMappedPath isEqualToString:p.tweakInjectLogicalPath] ||
                          ![p.dpkgStatusMappedPath isEqualToString:p.dpkgStatusLogicalPath] ||
                          ![p.dpkgInfoMappedPath isEqualToString:p.dpkgInfoLogicalPath] ||
                          ![p.rootHideConfigMappedPath isEqualToString:p.rootHideConfigLogicalPath];
    // The exported jbroot symbol is the strongest runtime signal available to this
    // read-only module. Mapping activity is additional evidence, not a requirement.
    p.rootHideDetected = p.jbrootAvailable;

    NSDictionary *info = NSBundle.mainBundle.infoDictionary ?: @{};
    p.hostBundleIdentifier = NSBundle.mainBundle.bundleIdentifier ?: @"";
    p.hostVersion = info[@"CFBundleShortVersionString"] ?: info[@"CFBundleVersion"] ?: @"";

    p.analysisVersion = RCAnalysisVersion();
    p.analysisArchitecture = RCAnalysisRuntimeArchitecture();
    p.analysisImagePath = RCAnalysisLoadedImagePath();
    p.analysisImageUUID = RCAnalysisLoadedImageUUID();
    p.analysisImagePathExpected = RCAnalysisLoadedImagePathLooksExpected();
    p.analysisHostWeakLoadPresent = RCAnalysisHostHasExpectedWeakLoad();
    NSDictionary *manifest = RCAnalysisBuildManifest();
    p.analysisBuildManifestPresent = manifest.count > 0;
    p.analysisBuildManifestSchema = [manifest[@"ManifestSchema"] respondsToSelector:@selector(integerValue)] ? [manifest[@"ManifestSchema"] integerValue] : 0;
    p.analysisBuildID = [manifest[@"BuildID"] isKindOfClass:NSString.class] ? manifest[@"BuildID"] : @"";
    p.analysisBuildManifestSourceTreeSHA256 = [manifest[@"SourceTreeSHA256"] isKindOfClass:NSString.class] ? manifest[@"SourceTreeSHA256"] : @"";
    p.analysisBuildManifestSourceFileCount = [manifest[@"SourceFileCount"] respondsToSelector:@selector(unsignedIntegerValue)] ? [manifest[@"SourceFileCount"] unsignedIntegerValue] : 0;
    p.analysisBuildManifestVersion = [manifest[@"AnalysisVersion"] isKindOfClass:NSString.class] ? manifest[@"AnalysisVersion"] : @"";
    p.analysisBuildManifestDylibSHA256 = [manifest[@"DylibSHA256"] isKindOfClass:NSString.class] ? manifest[@"DylibSHA256"] : @"";
    p.analysisBuildManifestBaselineSHA256 = [manifest[@"SourceBaselineExecutableSHA256"] isKindOfClass:NSString.class] ? manifest[@"SourceBaselineExecutableSHA256"] : @"";
    p.analysisBuildManifestInstallName = [manifest[@"ExpectedInstallName"] isKindOfClass:NSString.class] ? manifest[@"ExpectedInstallName"] : @"";
    p.analysisBuildManifestLoadMode = [manifest[@"LoadMode"] isKindOfClass:NSString.class] ? manifest[@"LoadMode"] : @"";
    p.analysisBuildManifestVersionMatches = p.analysisBuildManifestPresent && [p.analysisBuildManifestVersion isEqualToString:RCAnalysisVersion()];
    NSDictionary *uuidMap = [manifest[@"DylibUUIDs"] isKindOfClass:NSDictionary.class] ? manifest[@"DylibUUIDs"] : @{};
    NSString *expectedUUID = [uuidMap[p.analysisArchitecture] isKindOfClass:NSString.class] ? uuidMap[p.analysisArchitecture] : @"";
    p.analysisBuildManifestUUIDMatches = expectedUUID.length > 0 && p.analysisImageUUID.length > 0 && [expectedUUID caseInsensitiveCompare:p.analysisImageUUID] == NSOrderedSame;
    p.analysisMenuHooksInstalled = RCAnalysisMenuHooksInstalled();
    p.analysisMenuHookInstallAttempts = RCAnalysisMenuHookInstallAttempts();

    NSDictionary *hostState = RCAnalysisHostExecutableFileState();
    p.analysisHostExecutablePath = [hostState[@"Path"] isKindOfClass:NSString.class] ? hostState[@"Path"] : @"";
    p.analysisHostExecutableMode = [hostState[@"Mode"] isKindOfClass:NSString.class] ? hostState[@"Mode"] : @"";
    p.analysisHostExecutableUID = [hostState[@"UID"] respondsToSelector:@selector(unsignedIntegerValue)] ? [hostState[@"UID"] unsignedIntegerValue] : NSUIntegerMax;
    p.analysisHostExecutableGID = [hostState[@"GID"] respondsToSelector:@selector(unsignedIntegerValue)] ? [hostState[@"GID"] unsignedIntegerValue] : NSUIntegerMax;
    p.analysisHostExecutableSetUID = [hostState[@"SetUID"] boolValue];
    p.analysisHostExecutablePostInstallStateExpected = [hostState[@"Expected"] boolValue];
    p.analysisHostExecutableStateDetail = [hostState[@"Reason"] isKindOfClass:NSString.class] ? hostState[@"Reason"] : @"";

    NSDictionary *dylibState = RCAnalysisLoadedDylibFileState();
    p.analysisDylibFileMode = [dylibState[@"Mode"] isKindOfClass:NSString.class] ? dylibState[@"Mode"] : @"";
    p.analysisDylibFileStateExpected = [dylibState[@"Expected"] boolValue];
    p.analysisDylibFileStateDetail = [dylibState[@"Reason"] isKindOfClass:NSString.class] ? dylibState[@"Reason"] : @"";

    NSMutableArray<NSString *> *selfCheckIssues = [NSMutableArray array];
    if (!p.analysisImagePathExpected) [selfCheckIssues addObject:@"loaded-image-path"];
    if (!p.analysisImageUUID.length) [selfCheckIssues addObject:@"loaded-image-uuid"];
    if (!p.analysisHostWeakLoadPresent) [selfCheckIssues addObject:@"host-weak-load"];
    if (!p.analysisBuildManifestPresent) [selfCheckIssues addObject:@"manifest-missing"];
    if (!p.analysisBuildManifestVersionMatches) [selfCheckIssues addObject:@"manifest-version"];
    if (p.analysisBuildManifestSchema != 3) [selfCheckIssues addObject:@"manifest-schema"];
    if (!p.analysisBuildID.length) [selfCheckIssues addObject:@"manifest-build-id"];
    if (!p.analysisBuildManifestSourceTreeSHA256.length || p.analysisBuildManifestSourceFileCount == 0) [selfCheckIssues addObject:@"manifest-source-provenance"];
    if (![p.analysisBuildManifestInstallName isEqualToString:RCAnalysisExpectedInstallName()]) [selfCheckIssues addObject:@"manifest-install-name"];
    if (![p.analysisBuildManifestLoadMode isEqualToString:@"weak"]) [selfCheckIssues addObject:@"manifest-load-mode"];
    if (!p.analysisBuildManifestUUIDMatches) [selfCheckIssues addObject:@"manifest-uuid"];
    if (!p.analysisHostExecutablePostInstallStateExpected) [selfCheckIssues addObject:@"host-postinstall-state"];
    if (!p.analysisDylibFileStateExpected) [selfCheckIssues addObject:@"dylib-file-state"];
    if (!p.analysisMenuHooksInstalled) [selfCheckIssues addObject:@"menu-hook"];
    p.analysisRuntimeSelfCheckStatus = selfCheckIssues.count ? @"WARN" : @"PASS";
    p.analysisRuntimeSelfCheckSummary = selfCheckIssues.count ? [selfCheckIssues componentsJoinedByString:@","] : @"loaded image, weak load, manifest UUID, installed file state, and menu hook agree";
    return p;
}

- (NSArray<RCDiagnosticItem *> *)runPreflight {
    NSMutableArray<RCDiagnosticItem *> *items = [NSMutableArray array];
    NSFileManager *fm = NSFileManager.defaultManager;
    RCEnvironmentProfile *profile = [self environmentProfile];

    BOOL imageIdentityAvailable = profile.analysisImagePath.length > 0 && profile.analysisImageUUID.length > 0;
    [items addObject:RCCheck(@"Analysis dylib identity", imageIdentityAvailable,
                            imageIdentityAvailable
                                ? [NSString stringWithFormat:@"v%@ %@ UUID=%@ path=%@", profile.analysisVersion, profile.analysisArchitecture, profile.analysisImageUUID, profile.analysisImagePath]
                                : @"loaded Analysis image path/LC_UUID could not be resolved")];

    [items addObject:RCCheck(@"Analysis loaded path", profile.analysisImagePathExpected,
                            profile.analysisImagePathExpected ? @"loaded from RootHide.app/Frameworks/RCInjectAnalysis.dylib" : [NSString stringWithFormat:@"unexpected/development load path: %@", profile.analysisImagePath.length ? profile.analysisImagePath : @"(unknown)"])];
    [items addObject:RCCheck(@"RootHide host weak load", profile.analysisHostWeakLoadPresent, RCAnalysisHostWeakLoadDetail())];
    [items addObject:RCCheck(@"RootHide postinstall file state", profile.analysisHostExecutablePostInstallStateExpected,
                            [NSString stringWithFormat:@"path=%@ uid=%lu gid=%lu mode=%@ setuid=%@ %@", profile.analysisHostExecutablePath.length ? profile.analysisHostExecutablePath : @"(unknown)", (unsigned long)profile.analysisHostExecutableUID, (unsigned long)profile.analysisHostExecutableGID, profile.analysisHostExecutableMode.length ? profile.analysisHostExecutableMode : @"?", RCBoolText(profile.analysisHostExecutableSetUID), profile.analysisHostExecutableStateDetail.length ? profile.analysisHostExecutableStateDetail : @"matches original postinst root:root + setuid contract"] )];
    [items addObject:RCCheck(@"Analysis dylib file state", profile.analysisDylibFileStateExpected,
                            [NSString stringWithFormat:@"mode=%@ %@", profile.analysisDylibFileMode.length ? profile.analysisDylibFileMode : @"?", profile.analysisDylibFileStateDetail.length ? profile.analysisDylibFileStateDetail : @"regular executable dylib"] )];

    BOOL manifestIdentityOK = profile.analysisBuildManifestPresent && profile.analysisBuildManifestSchema == 3 && profile.analysisBuildID.length > 0 && profile.analysisBuildManifestSourceTreeSHA256.length > 0 && profile.analysisBuildManifestSourceFileCount > 0 && profile.analysisBuildManifestVersionMatches && profile.analysisBuildManifestUUIDMatches &&
                              [profile.analysisBuildManifestInstallName isEqualToString:RCAnalysisExpectedInstallName()] &&
                              [profile.analysisBuildManifestLoadMode isEqualToString:@"weak"];
    [items addObject:RCCheck(@"Analysis build manifest", manifestIdentityOK,
                            profile.analysisBuildManifestPresent
                                ? [NSString stringWithFormat:@"schema=%ld buildID=%@ source=%@ files=%lu version=%@ versionMatch=%@ uuidMatch=%@ load=%@ installName=%@", (long)profile.analysisBuildManifestSchema, profile.analysisBuildID, profile.analysisBuildManifestSourceTreeSHA256, (unsigned long)profile.analysisBuildManifestSourceFileCount, profile.analysisBuildManifestVersion, RCBoolText(profile.analysisBuildManifestVersionMatches), RCBoolText(profile.analysisBuildManifestUUIDMatches), profile.analysisBuildManifestLoadMode, profile.analysisBuildManifestInstallName]
                                : [NSString stringWithFormat:@"missing %@; loose/development load or packaging mismatch", RCAnalysisBuildManifestPath()])];

    [items addObject:RCCheck(@"RootHide menu hooks", profile.analysisMenuHooksInstalled,
                            [NSString stringWithFormat:@"installed=%@ attempts=%lu", RCBoolText(profile.analysisMenuHooksInstalled), (unsigned long)profile.analysisMenuHookInstallAttempts])];
    [items addObject:RCCheck(@"Runtime release self-check", [profile.analysisRuntimeSelfCheckStatus isEqualToString:@"PASS"],
                            [NSString stringWithFormat:@"%@ — %@", profile.analysisRuntimeSelfCheckStatus, profile.analysisRuntimeSelfCheckSummary])];

    [items addObject:RCCheck(@"RootHide jbroot", profile.jbrootAvailable,
                            profile.jbrootAvailable
                                ? [NSString stringWithFormat:@"jbroot symbol available%@", profile.jbrootImagePath.length ? [NSString stringWithFormat:@" in %@", profile.jbrootImagePath] : @""]
                                : @"jbroot symbol unavailable; logical paths will not be assumed to be RootHide-mapped")];

    Class settings = NSClassFromString(@"SettingViewController");
    [items addObject:RCCheck(@"SettingViewController", settings != Nil,
                            settings ? @"RootHide menu host class is available" : @"RootHide menu host class not found")];

    Class workspace = NSClassFromString(@"LSApplicationWorkspace");
    [items addObject:RCCheck(@"LSApplicationWorkspace", workspace != Nil,
                            workspace ? @"LaunchServices scanner API class is available" : @"LaunchServices class not found")];

    NSString *tweakDir = profile.tweakInjectMappedPath;
    BOOL tweakIsDir = NO;
    BOOL tweakExists = tweakDir.length && [fm fileExistsAtPath:tweakDir isDirectory:&tweakIsDir] && tweakIsDir;
    [items addObject:RCCheck(@"TweakInject path", tweakExists,
                            [NSString stringWithFormat:@"%@ -> %@", profile.tweakInjectLogicalPath, tweakDir ?: @"(nil)"])];

    NSString *statusPath = profile.dpkgStatusMappedPath;
    BOOL statusExists = statusPath.length && [fm fileExistsAtPath:statusPath];
    [items addObject:RCCheck(@"DPKG status", statusExists,
                            [NSString stringWithFormat:@"%@ -> %@", profile.dpkgStatusLogicalPath, statusPath ?: @"(nil)"])];

    NSString *infoDir = profile.dpkgInfoMappedPath;
    BOOL infoIsDir = NO;
    BOOL infoExists = infoDir.length && [fm fileExistsAtPath:infoDir isDirectory:&infoIsDir] && infoIsDir;
    [items addObject:RCCheck(@"DPKG info", infoExists,
                            [NSString stringWithFormat:@"%@ -> %@", profile.dpkgInfoLogicalPath, infoDir ?: @"(nil)"])];

    NSString *configPath = profile.rootHideConfigMappedPath;
    BOOL configExists = configPath.length && [fm fileExistsAtPath:configPath];
    [items addObject:RCCheck(@"RootHide config", YES,
                            configExists ? [NSString stringWithFormat:@"config present: %@", configPath] : @"config absent: RootHide defaults apply")];

    BOOL allPassed = YES;
    for (RCDiagnosticItem *item in items) {
        RCLog(@"preflight %@: %@ — %@", item.name, item.passed ? @"PASS" : @"WARN", item.detail);
        if (!item.passed) allPassed = NO;
    }
    RCLog(@"preflight summary: %@", allPassed ? @"PASS" : @"WARNINGS");
    return items;
}

+ (NSString *)plainTextReportForItems:(NSArray<RCDiagnosticItem *> *)items {
    NSMutableString *s = [NSMutableString stringWithString:@"RCInjectAnalysis preflight\n"];
    for (RCDiagnosticItem *item in items) {
        [s appendFormat:@"[%@] %@ — %@\n", item.passed ? @"PASS" : @"WARN", item.name, item.detail];
    }
    return s;
}

+ (NSString *)fullReadOnlyReportForSnapshot:(RCAnalysisSnapshot *)snapshot {
    if (!snapshot) return [NSString stringWithFormat:@"RCInjectAnalysis %@\nNo snapshot available.\n", RCAnalysisVersion()];

    NSMutableString *s = [NSMutableString string];
    NSDictionary *info = NSBundle.mainBundle.infoDictionary ?: @{};
    NSString *hostVersion = info[@"CFBundleShortVersionString"] ?: @"?";
    NSString *hostBuild = info[@"CFBundleVersion"] ?: @"?";
    NSString *generated = snapshot.generatedAt ? [NSDateFormatter localizedStringFromDate:snapshot.generatedAt dateStyle:NSDateFormatterShortStyle timeStyle:NSDateFormatterMediumStyle] : @"?";

    [s appendFormat:@"RCInjectAnalysis %@ — READ ONLY DIAGNOSTIC REPORT\n", RCAnalysisVersion()];
    [s appendFormat:@"Generated: %@\n", generated];
    [s appendFormat:@"Scan-ID: %@\n", snapshot.scanIdentifier.length ? snapshot.scanIdentifier : @"?"];
    [s appendFormat:@"Host: %@ %@ (%@)\n", NSBundle.mainBundle.bundleIdentifier ?: @"?", hostVersion, hostBuild];
    [s appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString ?: @"?"];
    [s appendString:@"Safety: report only; no delete / unregister / blacklist write / icon-cache rebuild\n\n"];

    RCEnvironmentProfile *e = snapshot.environmentProfile;
    [s appendString:@"[Build / Runtime Identity]\n"];
    [s appendFormat:@"AnalysisVersion=%@ Architecture=%@\n", e.analysisVersion.length ? e.analysisVersion : RCAnalysisVersion(), e.analysisArchitecture.length ? e.analysisArchitecture : @"?"];
    [s appendFormat:@"LoadedImage=%@\n", e.analysisImagePath.length ? e.analysisImagePath : @"(unknown)"];
    [s appendFormat:@"LoadedImageUUID=%@\n", e.analysisImageUUID.length ? e.analysisImageUUID : @"(unknown)"];
    [s appendFormat:@"LoadedPathExpected=%@ HostWeakLoadPresent=%@\n", RCBoolText(e.analysisImagePathExpected), RCBoolText(e.analysisHostWeakLoadPresent)];
    [s appendFormat:@"HostExecutableState=%@ path=%@ uid=%lu gid=%lu mode=%@ setuid=%@ detail=%@\n", RCBoolText(e.analysisHostExecutablePostInstallStateExpected), e.analysisHostExecutablePath.length ? e.analysisHostExecutablePath : @"(unknown)", (unsigned long)e.analysisHostExecutableUID, (unsigned long)e.analysisHostExecutableGID, e.analysisHostExecutableMode.length ? e.analysisHostExecutableMode : @"?", RCBoolText(e.analysisHostExecutableSetUID), e.analysisHostExecutableStateDetail.length ? e.analysisHostExecutableStateDetail : @"OK"];
    [s appendFormat:@"DylibFileState=%@ mode=%@ detail=%@\n", RCBoolText(e.analysisDylibFileStateExpected), e.analysisDylibFileMode.length ? e.analysisDylibFileMode : @"?", e.analysisDylibFileStateDetail.length ? e.analysisDylibFileStateDetail : @"OK"];
    [s appendFormat:@"MenuHooksInstalled=%@ HookInstallAttempts=%lu\n", RCBoolText(e.analysisMenuHooksInstalled), (unsigned long)e.analysisMenuHookInstallAttempts];
    [s appendFormat:@"ManifestPresent=%@ Schema=%ld ManifestVersion=%@ VersionMatches=%@ UUIDMatches=%@\n", RCBoolText(e.analysisBuildManifestPresent), (long)e.analysisBuildManifestSchema, e.analysisBuildManifestVersion.length ? e.analysisBuildManifestVersion : @"(none)", RCBoolText(e.analysisBuildManifestVersionMatches), RCBoolText(e.analysisBuildManifestUUIDMatches)];
    [s appendFormat:@"BuildID=%@\n", e.analysisBuildID.length ? e.analysisBuildID : @"(none)"];
    [s appendFormat:@"SourceTreeSHA256=%@ SourceFileCount=%lu\n", e.analysisBuildManifestSourceTreeSHA256.length ? e.analysisBuildManifestSourceTreeSHA256 : @"(none)", (unsigned long)e.analysisBuildManifestSourceFileCount];
    [s appendFormat:@"ManifestLoadMode=%@ InstallName=%@\n", e.analysisBuildManifestLoadMode.length ? e.analysisBuildManifestLoadMode : @"(none)", e.analysisBuildManifestInstallName.length ? e.analysisBuildManifestInstallName : @"(none)"];
    [s appendFormat:@"ManifestDylibSHA256=%@\n", e.analysisBuildManifestDylibSHA256.length ? e.analysisBuildManifestDylibSHA256 : @"(none)"];
    [s appendFormat:@"SourceBaselineSHA256=%@\n", e.analysisBuildManifestBaselineSHA256.length ? e.analysisBuildManifestBaselineSHA256 : @"(none)"];
    [s appendFormat:@"RuntimeSelfCheck=%@ Summary=%@\n\n", e.analysisRuntimeSelfCheckStatus.length ? e.analysisRuntimeSelfCheckStatus : @"WARN", e.analysisRuntimeSelfCheckSummary.length ? e.analysisRuntimeSelfCheckSummary : @"unknown"];

    [s appendString:@"[Runtime Release Self-Check]\n"];
    [s appendFormat:@"ImagePath=%@\n", e.analysisImagePathExpected ? @"PASS" : @"WARN"];
    [s appendFormat:@"ImageUUID=%@\n", e.analysisImageUUID.length ? @"PASS" : @"WARN"];
    [s appendFormat:@"HostWeakLoad=%@\n", e.analysisHostWeakLoadPresent ? @"PASS" : @"WARN"];
    [s appendFormat:@"HostPostInstallState=%@\n", e.analysisHostExecutablePostInstallStateExpected ? @"PASS" : @"WARN"];
    [s appendFormat:@"DylibFileState=%@\n", e.analysisDylibFileStateExpected ? @"PASS" : @"WARN"];
    [s appendFormat:@"ManifestSchema=%@\n", e.analysisBuildManifestSchema == 3 ? @"PASS" : @"WARN"];
    [s appendFormat:@"BuildProvenance=%@\n", (e.analysisBuildID.length && e.analysisBuildManifestSourceTreeSHA256.length && e.analysisBuildManifestSourceFileCount > 0) ? @"PASS" : @"WARN"];
    [s appendFormat:@"ManifestVersion=%@\n", e.analysisBuildManifestVersionMatches ? @"PASS" : @"WARN"];
    [s appendFormat:@"ManifestUUID=%@\n", e.analysisBuildManifestUUIDMatches ? @"PASS" : @"WARN"];
    [s appendFormat:@"MenuHook=%@\n\n", e.analysisMenuHooksInstalled ? @"PASS" : @"WARN"];

    [s appendString:@"[Environment Profile]\n"];
    [s appendFormat:@"RootHideDetected=%@ jbroot=%@ pathMappingActive=%@\n", RCBoolText(e.rootHideDetected), RCBoolText(e.jbrootAvailable), RCBoolText(e.pathMappingActive)];
    [s appendFormat:@"jbrootImage=%@\n", e.jbrootImagePath.length ? e.jbrootImagePath : @"(unknown)"];
    [s appendFormat:@"TweakInject: %@ -> %@\n", e.tweakInjectLogicalPath ?: @"", e.tweakInjectMappedPath ?: @""];
    [s appendFormat:@"DPKG-status: %@ -> %@\n", e.dpkgStatusLogicalPath ?: @"", e.dpkgStatusMappedPath ?: @""];
    [s appendFormat:@"DPKG-info: %@ -> %@\n", e.dpkgInfoLogicalPath ?: @"", e.dpkgInfoMappedPath ?: @""];
    [s appendFormat:@"RootHideConfig: %@ -> %@\n\n", e.rootHideConfigLogicalPath ?: @"", e.rootHideConfigMappedPath ?: @""];

    [s appendString:@"[Capabilities]\n"];
    [s appendFormat:@"LaunchServices=%@\n", RCBoolText(snapshot.launchServicesAvailable)];
    [s appendFormat:@"TweakInject=%@\n", RCBoolText(snapshot.tweakScanAvailable)];
    [s appendFormat:@"DPKG-status=%@\n", RCBoolText(snapshot.dpkgStatusAvailable)];
    [s appendFormat:@"DPKG-info=%@\n", RCBoolText(snapshot.dpkgInfoAvailable)];
    [s appendFormat:@"Blacklist-state=%@\n", RCBoolText(snapshot.blacklistStateAvailable)];
    [s appendFormat:@"Embedded-evidence=%@\n\n", RCBoolText(snapshot.embeddedEvidenceAvailable)];

    RCScanMetrics *m = snapshot.metrics;
    [s appendString:@"[Metrics]\n"];
    [s appendFormat:@"total=%.3fs tweak+dpkg=%.3fs apps=%.3fs blacklist=%.3fs embedded=%.3fs\n", m.totalDuration, m.tweakAndPackageDuration, m.appDuration, m.blacklistDuration, m.embeddedDuration];
    [s appendFormat:@"apps=%lu tweaks=%lu multi=%lu orphan=%lu blacklistResidue=%lu suspicious=%lu uninstalledTargets=%lu embeddedRecords=%lu\n", (unsigned long)snapshot.apps.count, (unsigned long)snapshot.tweaks.count, (unsigned long)snapshot.multiMatchApps.count, (unsigned long)snapshot.orphanRegistrations.count, (unsigned long)snapshot.blacklistResidues.count, (unsigned long)snapshot.suspiciousTweaks.count, (unsigned long)snapshot.uninstalledTargetTweaks.count, (unsigned long)snapshot.embeddedInjectionRecords.count];
    [s appendFormat:@"embeddedEntries=%lu embeddedApps=%lu incompleteApps=%lu timeLimitedApps=%lu globalSkippedApps=%lu\n", (unsigned long)m.embeddedEntriesVisited, (unsigned long)m.embeddedAppsScanned, (unsigned long)m.embeddedAppsTruncated, (unsigned long)m.embeddedAppsTimeLimited, (unsigned long)m.embeddedAppsSkippedByGlobalBudget];
    [s appendFormat:@"budgets: entriesPerApp=%lu timePerApp=%.3fs globalEmbedded=%.3fs\n", (unsigned long)m.embeddedEntryLimitPerApp, m.embeddedTimeLimitPerApp, m.embeddedTotalTimeLimit];
    [s appendFormat:@"slowestEmbeddedApp=%@ duration=%.3fs\n\n", m.slowestEmbeddedAppBundleIdentifier.length ? m.slowestEmbeddedAppBundleIdentifier : @"(none)", m.slowestEmbeddedAppDuration];

    [s appendString:@"[Budget / Anomaly Locator]\n"];
    BOOL hasBudgetAnomaly = NO;
    for (RCAppRecord *app in snapshot.apps) {
        if (!app.embeddedScanTruncated && !app.embeddedSkippedByGlobalBudget) continue;
        hasBudgetAnomaly = YES;
        [s appendFormat:@"%@ | stop=%@ | attempted=%@ | duration=%.3fs | entries=%lu | status=%@\n",
         app.bundleIdentifier ?: @"?", app.embeddedScanStopReason.length ? app.embeddedScanStopReason : @"budget",
         RCBoolText(app.embeddedScanAttempted), app.embeddedScanDuration,
         (unsigned long)app.embeddedScanEntriesVisited, app.embeddedScanStatus ?: @""];
    }
    if (!hasBudgetAnomaly) [s appendString:@"(none)\n"];
    [s appendString:@"\n"];

    [s appendString:@"[Timeline]\n"];
    if (!snapshot.timeline.count) [s appendString:@"(none)\n"];
    for (RCScanTimelineEvent *event in snapshot.timeline) {
        [s appendFormat:@"[%07.3f] %@ — %@\n", event.offset, event.phase ?: @"", event.detail ?: @""];
    }

    [s appendString:@"\n[Preflight]\n"];
    for (RCDiagnosticItem *item in snapshot.diagnostics) {
        [s appendFormat:@"[%@] %@ — %@\n", item.passed ? @"PASS" : @"WARN", item.name ?: @"", item.detail ?: @""];
    }

    [s appendString:@"\n[Multi-match Apps]\n"];
    if (!snapshot.multiMatchApps.count) [s appendString:@"(none / or unavailable; see capabilities)\n"];
    for (RCAppRecord *app in snapshot.multiMatchApps) {
        NSString *blackState = !app.blacklistStateKnown ? @"unknown" : (app.blacklisted ? @"blacklisted" : @"permitted");
        [s appendFormat:@"%@ | %@ | tweaks=%lu | blacklist=%@\n", app.name ?: @"", app.bundleIdentifier ?: @"", (unsigned long)app.matchedTweaks.count, blackState];
        for (RCTweakRecord *t in app.matchedTweaks) {
            [s appendFormat:@"  - %@ | package=%@ | version=%@ | source=%@ | confidence=%@\n", t.displayName ?: @"", t.package.packageIdentifier ?: @"?", t.package.version ?: @"?", RCTweakInstallSourceText(t.installSource), RCConfidenceText(t.sourceConfidence)];
            [s appendFormat:@"    match=%@ | plist=%@ | bundles=%@ | executables=%@\n",
             RCTweakMatchReasonForApp(t, app), t.plistPath ?: @"?",
             [t.bundleIdentifiers componentsJoinedByString:@","] ?: @"",
             [t.executableIdentifiers componentsJoinedByString:@","] ?: @""];
        }
    }

    [s appendString:@"\n[Orphan Registrations]\n"];
    if (!snapshot.orphanRegistrations.count) [s appendString:@"(none / or unavailable; see capabilities)\n"];
    for (RCAppRecord *app in snapshot.orphanRegistrations) {
        [s appendFormat:@"%@ | %@ | path=%@ | exists=%@\n", app.name ?: @"", app.bundleIdentifier ?: @"", app.bundlePath ?: @"?", RCBoolText(app.bundlePathExists)];
    }

    [s appendString:@"\n[Blacklist Residues]\n"];
    if (!snapshot.blacklistResidues.count) [s appendString:@"(none / or unavailable; see capabilities)\n"];
    for (RCBlacklistResidueRecord *r in snapshot.blacklistResidues) {
        [s appendFormat:@"%@ | confidence=%@ | globallyDisabled=%@ | evidence=%@\n", r.bundleIdentifier ?: @"", RCConfidenceText(r.confidence), RCBoolText(r.blacklistGloballyDisabled), r.evidence ?: @""];
    }

    [s appendString:@"\n[Suspicious Tweaks]\n"];
    if (!snapshot.suspiciousTweaks.count) [s appendString:@"(none / or unavailable; see capabilities)\n"];
    for (RCTweakRecord *t in snapshot.suspiciousTweaks) {
        [s appendFormat:@"%@ | severity=%@ | plist=%@ | dylib=%@\n", t.displayName ?: @"", RCTweakIssueSeverityText(t.issueSeverity), t.plistPath ?: @"?", t.dylibPath ?: @"?"];
        for (NSString *issue in t.issues) [s appendFormat:@"  - %@\n", issue];
    }

    [s appendString:@"\n[System / Unresolved Filter Targets]\n"];
    if (!snapshot.uninstalledTargetTweaks.count) [s appendString:@"(none / or unavailable; see capabilities)\n"];
    for (RCTweakRecord *t in snapshot.uninstalledTargetTweaks) {
        [s appendFormat:@"%@ | unresolvedBundles=%@ | systemExecutables=%@ | unresolvedExecutables=%@ | appExecutables=%@\n",
         t.displayName ?: @"",
         [t.uninstalledTargetBundleIdentifiers componentsJoinedByString:@","] ?: @"",
         [t.systemTargetExecutableIdentifiers componentsJoinedByString:@","] ?: @"",
         [t.unresolvedTargetExecutableIdentifiers componentsJoinedByString:@","] ?: @"",
         [t.installedTargetExecutableIdentifiers componentsJoinedByString:@","] ?: @""];
    }

    [s appendString:@"\n[Embedded / TrollFools Evidence]\n"];
    if (!snapshot.embeddedInjectionRecords.count) {
        if (m.embeddedAppsTruncated || m.embeddedAppsSkippedByGlobalBudget) [s appendString:@"(no records collected; embedded scan is partial, so this is not a clean conclusion)\n"];
        else [s appendString:@"(none / or unavailable; see capabilities)\n"];
    }
    for (RCEmbeddedInjectionRecord *r in snapshot.embeddedInjectionRecords) {
        [s appendFormat:@"%@ | source=%@ | activeDiff=%@ | confidence=%@ | load=%@ | backup=%@\n  evidence=%@\n", r.appBundleIdentifier ?: @"", RCEmbeddedSourceText(r.source), RCBoolText(r.activeDifferenceConfirmed), RCConfidenceText(r.confidence), r.loadPath ?: @"?", r.backupPath ?: @"?", r.evidence ?: @""];
    }

    [s appendString:@"\nEND OF READ ONLY REPORT\n"];
    return s;
}

+ (NSString *)readOnlyReportForApp:(RCAppRecord *)app snapshot:(RCAnalysisSnapshot *)snapshot {
    if (!app || !snapshot) return [NSString stringWithFormat:@"RCInjectAnalysis %@ — APP READ ONLY REPORT\nNo App/snapshot available.\n", RCAnalysisVersion()];
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"RCInjectAnalysis %@ — APP READ ONLY REPORT\n", RCAnalysisVersion()];
    [s appendString:@"Safety: report only; no delete / unregister / blacklist write / icon-cache rebuild\n"];
    [s appendFormat:@"Scan-ID: %@\n", snapshot.scanIdentifier.length ? snapshot.scanIdentifier : @"?"];
    RCEnvironmentProfile *env = snapshot.environmentProfile;
    [s appendFormat:@"AnalysisIdentity: v%@ %@ UUID=%@\n", env.analysisVersion.length ? env.analysisVersion : RCAnalysisVersion(), env.analysisArchitecture.length ? env.analysisArchitecture : @"?", env.analysisImageUUID.length ? env.analysisImageUUID : @"?"];
    [s appendFormat:@"BuildID=%@ SourceTreeSHA256=%@\n", env.analysisBuildID.length ? env.analysisBuildID : @"(none)", env.analysisBuildManifestSourceTreeSHA256.length ? env.analysisBuildManifestSourceTreeSHA256 : @"(none)"];
    [s appendFormat:@"Manifest: present=%@ version=%@ versionMatch=%@ uuidMatch=%@ weakLoad=%@ hooks=%@ attempts=%lu selfCheck=%@\n\n", RCBoolText(env.analysisBuildManifestPresent), env.analysisBuildManifestVersion.length ? env.analysisBuildManifestVersion : @"(none)", RCBoolText(env.analysisBuildManifestVersionMatches), RCBoolText(env.analysisBuildManifestUUIDMatches), RCBoolText(env.analysisHostWeakLoadPresent), RCBoolText(env.analysisMenuHooksInstalled), (unsigned long)env.analysisMenuHookInstallAttempts, env.analysisRuntimeSelfCheckStatus.length ? env.analysisRuntimeSelfCheckStatus : @"WARN"];
    [s appendFormat:@"Name=%@\nBundleID=%@\nBundlePath=%@\nBundleExecutable=%@\nApplicationType=%@\n",
     app.name ?: @"", app.bundleIdentifier ?: @"", app.bundlePath ?: @"(none)", app.bundleExecutable ?: @"(none)", app.applicationType ?: @"(none)"];
    [s appendFormat:@"LaunchServicesRegistered=%@ BundlePathExists=%@ HighConfidenceOrphan=%@\n",
     RCBoolText(app.launchServicesRegistered), RCBoolText(app.bundlePathExists), RCBoolText(app.highConfidenceOrphanRegistration)];
    [s appendFormat:@"EmbeddedScanAttempted=%@ Truncated=%@ Entries=%lu Duration=%.3fs TimeBudgetExceeded=%@ GlobalBudgetSkip=%@ StopReason=%@ Status=%@\n",
     RCBoolText(app.embeddedScanAttempted), RCBoolText(app.embeddedScanTruncated), (unsigned long)app.embeddedScanEntriesVisited,
     app.embeddedScanDuration, RCBoolText(app.embeddedTimeBudgetExceeded), RCBoolText(app.embeddedSkippedByGlobalBudget),
     app.embeddedScanStopReason.length ? app.embeddedScanStopReason : @"none", app.embeddedScanStatus ?: @""];
    [s appendFormat:@"InstallSource=%@ Confidence=%@ Evidence=%@\n",
     RCAppInstallSourceText(app.installSource), RCConfidenceText(app.installSourceConfidence), app.installSourceEvidence ?: @""];
    NSString *blackState = !app.blacklistStateKnown ? @"unknown" : (app.blacklisted ? @"blacklisted" : @"permitted");
    [s appendFormat:@"BlacklistSupported=%@ BlacklistState=%@ Evidence=%@\n\n",
     RCBoolText(app.blacklistSupported), blackState, app.blacklistEvidence ?: @""];

    [s appendString:@"[Capabilities]\n"];
    [s appendFormat:@"LaunchServices=%@ TweakInject=%@ DPKG-status=%@ DPKG-info=%@ Blacklist=%@ Embedded=%@\n\n",
     RCBoolText(snapshot.launchServicesAvailable), RCBoolText(snapshot.tweakScanAvailable),
     RCBoolText(snapshot.dpkgStatusAvailable), RCBoolText(snapshot.dpkgInfoAvailable),
     RCBoolText(snapshot.blacklistStateAvailable), RCBoolText(snapshot.embeddedEvidenceAvailable)];

    [s appendString:@"[Evidence Layers]\n"];
    NSString *embeddedCompleteness = !snapshot.embeddedEvidenceAvailable ? @"unavailable" : (!app.embeddedScanAttempted ? @"not-scanned/not-applicable" : (app.embeddedScanTruncated ? @"partial" : @"complete"));
    [s appendFormat:@"Layer0-SourceCompleteness: LS=%@ Tweak=%@ DPKG=%@ Blacklist=%@ Embedded=%@\n",
     RCBoolText(snapshot.launchServicesAvailable), RCBoolText(snapshot.tweakScanAvailable),
     (snapshot.dpkgStatusAvailable && snapshot.dpkgInfoAvailable) ? @"complete" : @"partial",
     snapshot.blacklistStateAvailable ? @"available" : @"partial", embeddedCompleteness];
    [s appendFormat:@"Layer1-Configuration: FilterMatches=%lu BlacklistSupported=%@ BlacklistKnown=%@ Blacklisted=%@\n",
     (unsigned long)app.matchedTweaks.count, RCBoolText(app.blacklistSupported), RCBoolText(app.blacklistStateKnown), RCBoolText(app.blacklisted)];
    NSUInteger dpkgHigh = 0, dpkgLower = 0, dpkgUnknown = 0;
    for (RCTweakRecord *t in app.matchedTweaks) {
        if (t.installSource == RCTweakInstallSourceDPKG && t.sourceConfidence == RCDetectionConfidenceHigh) dpkgHigh++;
        else if (t.installSource == RCTweakInstallSourceDPKG) dpkgLower++;
        else dpkgUnknown++;
    }
    [s appendFormat:@"Layer2-Ownership: AppSource=%@ AppSourceConfidence=%@ DPKG-high=%lu DPKG-lower=%lu Unknown=%lu\n",
     RCAppInstallSourceText(app.installSource), RCConfidenceText(app.installSourceConfidence), (unsigned long)dpkgHigh, (unsigned long)dpkgLower, (unsigned long)dpkgUnknown];
    NSUInteger layer3Active = 0;
    for (RCEmbeddedInjectionRecord *r in app.embeddedInjections) if (r.activeDifferenceConfirmed) layer3Active++;
    [s appendFormat:@"Layer3-BinaryDiff: ActiveTrollFoolsLoadDiffs=%lu ScanStop=%@\n", (unsigned long)layer3Active, app.embeddedScanStopReason.length ? app.embeddedScanStopReason : @"none"];
    [s appendFormat:@"Layer4-RuntimeProcessProof: NOT COLLECTED by Analysis %@; configuration/file evidence is not upgraded to runtime-load or conflict proof\n\n", RCAnalysisVersion()];

    [s appendString:@"[RootHide Filter Matches]\n"];
    if (!snapshot.tweakScanAvailable) {
        [s appendString:@"UNAVAILABLE: TweakInject preflight failed; empty result must not be interpreted as no match\n"];
    } else if (!app.matchedTweaks.count) {
        [s appendString:@"(none)\n"];
    } else {
        for (RCTweakRecord *t in app.matchedTweaks) {
            [s appendFormat:@"- %@ | package=%@ | version=%@ | source=%@ | confidence=%@\n",
             t.displayName ?: @"", t.package.packageIdentifier ?: @"?", t.package.version ?: @"?", RCTweakInstallSourceText(t.installSource), RCConfidenceText(t.sourceConfidence)];
            [s appendFormat:@"  match=%@\n  plist=%@\n  bundles=%@\n  executables=%@\n  sourceEvidence=%@\n",
             RCTweakMatchReasonForApp(t, app), t.plistPath ?: @"?",
             [t.bundleIdentifiers componentsJoinedByString:@","] ?: @"",
             [t.executableIdentifiers componentsJoinedByString:@","] ?: @"",
             t.installSourceEvidence ?: @""];
        }
    }

    [s appendString:@"\n[Embedded / TrollFools Evidence]\n"];
    if (!snapshot.embeddedEvidenceAvailable) {
        [s appendString:@"UNAVAILABLE: App bundle evidence source unavailable\n"];
    } else if (!app.embeddedScanAttempted) {
        [s appendFormat:@"NOT SCANNED: %@; do not interpret as no TrollFools evidence\n", app.embeddedScanStatus.length ? app.embeddedScanStatus : @"reason unknown"];
    } else if (!app.embeddedInjections.count) {
        [s appendFormat:@"(none)%@\n", app.embeddedScanTruncated ? @"; scan truncated" : @""];
    } else {
        for (RCEmbeddedInjectionRecord *r in app.embeddedInjections) {
            [s appendFormat:@"- source=%@ activeDiff=%@ confidence=%@\n  target=%@\n  backup=%@\n  load=%@\n  evidence=%@\n",
             RCEmbeddedSourceText(r.source), RCBoolText(r.activeDifferenceConfirmed), RCConfidenceText(r.confidence),
             r.targetMachOPath ?: @"?", r.backupPath ?: @"?", r.loadPath ?: @"?", r.evidence ?: @""];
        }
    }
    [s appendFormat:@"embeddedEntriesVisited=%lu truncated=%@ duration=%.3fs stop=%@ timeBudgetExceeded=%@ globalBudgetSkip=%@\n", (unsigned long)app.embeddedScanEntriesVisited, RCBoolText(app.embeddedScanTruncated), app.embeddedScanDuration, app.embeddedScanStopReason.length ? app.embeddedScanStopReason : @"none", RCBoolText(app.embeddedTimeBudgetExceeded), RCBoolText(app.embeddedSkippedByGlobalBudget)];

    NSUInteger activeEmbedded = 0;
    for (RCEmbeddedInjectionRecord *r in app.embeddedInjections) if (r.activeDifferenceConfirmed) activeEmbedded++;
    BOOL rootPermitted = app.matchedTweaks.count > 0 && app.blacklistSupported && app.blacklistStateKnown && !app.blacklisted;
    [s appendString:@"\n[Interpretation]\n"];
    [s appendFormat:@"RootHideFilterMatches=%lu RootHideConfigurationPermits=%@ ActiveEmbeddedDiffs=%lu\n",
     (unsigned long)app.matchedTweaks.count, RCBoolText(rootPermitted), (unsigned long)activeEmbedded];
    if (rootPermitted && activeEmbedded) [s appendString:@"NOTICE: RootHide configuration permits matching tweaks AND TrollFools active Load Command difference is confirmed. This is dual-source injection evidence, not proof of a runtime conflict.\n"];
    else if (app.matchedTweaks.count >= 2) [s appendString:@"NOTICE: multiple RootHide tweak filters match this App. Multiple matches are not proof of a conflict.\n"];
    else if (app.highConfidenceOrphanRegistration) [s appendString:@"NOTICE: high-confidence orphan LaunchServices registration criteria are met.\n"];
    else [s appendString:@"No high-confidence combined notice triggered. Review source capabilities before interpreting empty evidence.\n"];

    [s appendString:@"\nEND OF APP READ ONLY REPORT\n"];
    return s;
}

@end
