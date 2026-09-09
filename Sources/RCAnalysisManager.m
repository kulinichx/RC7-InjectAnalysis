#import "RCAnalysisManager.h"
#import "RCAppScanner.h"
#import "RCDpkgResolver.h"
#import "RCTweakScanner.h"
#import "RCMachOScanner.h"
#import "RCBlacklistStateScanner.h"
#import "RCDiagnostics.h"

static const NSUInteger RCEmbeddedEntryLimitPerApp = 50000;
static const NSTimeInterval RCEmbeddedTimeLimitPerApp = 1.5;
static const NSTimeInterval RCEmbeddedTotalTimeLimit = 12.0;

static BOOL RCDiagnosticPassed(NSArray<RCDiagnosticItem *> *items, NSString *name) {
    for (RCDiagnosticItem *item in items) {
        if ([item.name isEqualToString:name]) return item.passed;
    }
    return NO;
}

static void RCTimelineAdd(NSMutableArray<RCScanTimelineEvent *> *timeline, NSDate *start, NSString *phase, NSString *detail) {
    RCScanTimelineEvent *event = [RCScanTimelineEvent new];
    event.offset = -[start timeIntervalSinceNow];
    event.phase = phase ?: @"";
    event.detail = detail ?: @"";
    [timeline addObject:event];
    RCLog(@"timeline %.3f %@ — %@", event.offset, event.phase, event.detail);
}


typedef void (^RCAnalysisCompletion)(RCAnalysisSnapshot *snapshot);

@interface RCAnalysisManager ()
@property (atomic, strong, readwrite) RCAnalysisSnapshot *snapshot;
@property (nonatomic) dispatch_queue_t scanQueue;
@property (nonatomic) BOOL scanInProgress;
@property (nonatomic, strong) NSMutableArray<RCAnalysisCompletion> *pendingCompletions;
- (void)requestSnapshotForceRefresh:(BOOL)forceRefresh
                         completion:(void (^)(RCAnalysisSnapshot *snapshot))completion;
@end

@implementation RCAnalysisManager
+ (instancetype)sharedManager {
    static RCAnalysisManager *m;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ m = [RCAnalysisManager new]; });
    return m;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _scanQueue = dispatch_queue_create("cn.zqbb.rcinjectanalysis.scan", DISPATCH_QUEUE_SERIAL);
        _pendingCompletions = [NSMutableArray array];
    }
    return self;
}

- (void)loadSnapshotWithCompletion:(void (^)(RCAnalysisSnapshot *))completion {
    [self requestSnapshotForceRefresh:NO completion:completion];
}

- (void)refreshWithCompletion:(void (^)(RCAnalysisSnapshot *))completion {
    [self requestSnapshotForceRefresh:YES completion:completion];
}

- (void)requestSnapshotForceRefresh:(BOOL)forceRefresh
                         completion:(void (^)(RCAnalysisSnapshot *snapshot))completion {
    BOOL shouldStart = NO;
    RCAnalysisSnapshot *cachedSnapshot = nil;
    @synchronized (self) {
        if (!forceRefresh && self.snapshot && !self.scanInProgress) {
            cachedSnapshot = self.snapshot;
        } else {
            if (completion) [self.pendingCompletions addObject:[completion copy]];
            if (!self.scanInProgress) {
                if (forceRefresh) self.snapshot = nil;
                self.scanInProgress = YES;
                shouldStart = YES;
            }
        }
    }

    if (cachedSnapshot) {
        RCLog(@"reusing in-process analysis snapshot id=%@", cachedSnapshot.scanIdentifier ?: @"?");
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{ completion(cachedSnapshot); });
        }
        return;
    }
    if (!shouldStart) {
        RCLog(@"analysis request coalesced into active scan");
        return;
    }

    dispatch_async(self.scanQueue, ^{
        RCAnalysisSnapshot *snapshot = [self performReadOnlyScan];
        NSArray<RCAnalysisCompletion> *callbacks = nil;
        @synchronized (self) {
            self.snapshot = snapshot;
            callbacks = [self.pendingCompletions copy];
            [self.pendingCompletions removeAllObjects];
            self.scanInProgress = NO;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            for (RCAnalysisCompletion callback in callbacks) callback(snapshot);
        });
    });
}

- (RCAnalysisSnapshot *)performReadOnlyScan {
    NSDate *totalStart = [NSDate date];
    NSString *scanIdentifier = [[NSUUID UUID] UUIDString] ?: @"unknown";
    NSMutableArray<RCScanTimelineEvent *> *timeline = [NSMutableArray array];
    RCTimelineAdd(timeline, totalStart, @"scan", [NSString stringWithFormat:@"read-only analysis started id=%@", scanIdentifier]);

    RCDiagnostics *diagnosticRunner = [RCDiagnostics new];
    RCEnvironmentProfile *environmentProfile = [diagnosticRunner environmentProfile];
    NSMutableArray<RCDiagnosticItem *> *diagnostics = [[diagnosticRunner runPreflight] mutableCopy];
    RCTimelineAdd(timeline, totalStart, @"preflight", [NSString stringWithFormat:@"RootHide=%@ jbroot=%@ mapping=%@", environmentProfile.rootHideDetected ? @"YES" : @"NO", environmentProfile.jbrootAvailable ? @"YES" : @"NO", environmentProfile.pathMappingActive ? @"YES" : @"NO"]);
    RCLog(@"scan started");

    BOOL launchServicesAvailable = RCDiagnosticPassed(diagnostics, @"LSApplicationWorkspace");
    BOOL tweakScanAvailable = RCDiagnosticPassed(diagnostics, @"TweakInject path");
    BOOL dpkgStatusAvailable = RCDiagnosticPassed(diagnostics, @"DPKG status");
    BOOL dpkgInfoAvailable = RCDiagnosticPassed(diagnostics, @"DPKG info");

    NSDate *phase = [NSDate date];
    RCDpkgResolver *resolver = [RCDpkgResolver new];
    NSArray<RCTweakRecord *> *tweaks = tweakScanAvailable ? [[RCTweakScanner new] scanWithPackageResolver:resolver] : @[];
    NSTimeInterval tweakDuration = -[phase timeIntervalSinceNow];
    RCTimelineAdd(timeline, totalStart, @"tweak+dpkg", tweakScanAvailable ? [NSString stringWithFormat:@"tweaks=%lu duration=%.3fs", (unsigned long)tweaks.count, tweakDuration] : @"skipped: TweakInject unavailable");

    phase = [NSDate date];
    NSArray<RCAppRecord *> *apps = launchServicesAvailable ? [[RCAppScanner new] scanRegisteredApplications] : @[];
    NSTimeInterval appDuration = -[phase timeIntervalSinceNow];
    RCTimelineAdd(timeline, totalStart, @"launchservices", launchServicesAvailable ? [NSString stringWithFormat:@"apps=%lu duration=%.3fs", (unsigned long)apps.count, appDuration] : @"skipped: LSApplicationWorkspace unavailable");

    phase = [NSDate date];
    RCBlacklistStateScanner *blacklistScanner = [RCBlacklistStateScanner new];
    if (launchServicesAvailable) [blacklistScanner applyBlacklistStateToApps:apps];
    NSArray<RCBlacklistResidueRecord *> *blacklistResidues = launchServicesAvailable ? [blacklistScanner scanResidualEntriesAgainstApps:apps] : @[];
    NSTimeInterval blacklistDuration = -[phase timeIntervalSinceNow];
    RCTimelineAdd(timeline, totalStart, @"blacklist", launchServicesAvailable ? [NSString stringWithFormat:@"residues=%lu duration=%.3fs", (unsigned long)blacklistResidues.count, blacklistDuration] : @"skipped: LaunchServices unavailable");

    BOOL blacklistStateAvailable = launchServicesAvailable;
    for (RCAppRecord *app in apps) {
        if (!app.blacklistStateKnown && app.blacklistSupported) { blacklistStateAvailable = NO; break; }
    }
    BOOL embeddedEvidenceAvailable = launchServicesAvailable;

    NSMutableSet<NSString *> *installedBundleIDs = [NSMutableSet set];
    for (RCAppRecord *app in apps) {
        if (app.bundleIdentifier.length) [installedBundleIDs addObject:app.bundleIdentifier];
    }

    NSMutableDictionary<NSString *, NSMutableArray<RCTweakRecord *> *> *matches = [NSMutableDictionary dictionary];
    NSMutableArray<RCTweakRecord *> *uninstalledTargetTweaks = [NSMutableArray array];
    for (RCTweakRecord *tweak in tweaks) {
        NSMutableArray<NSString *> *installedTargets = [NSMutableArray array];
        NSMutableArray<NSString *> *uninstalledTargets = [NSMutableArray array];
        for (NSString *bid in tweak.bundleIdentifiers) {
            if (!bid.length) continue;
            if ([installedBundleIDs containsObject:bid]) {
                [installedTargets addObject:bid];
                NSMutableArray *arr = matches[bid];
                if (!arr) matches[bid] = arr = [NSMutableArray array];
                [arr addObject:tweak];
            } else {
                [uninstalledTargets addObject:bid];
            }
        }
        tweak.installedTargetBundleIdentifiers = installedTargets;
        tweak.uninstalledTargetBundleIdentifiers = uninstalledTargets;
        if (uninstalledTargets.count) [uninstalledTargetTweaks addObject:tweak];
    }
    RCTimelineAdd(timeline, totalStart, @"match-graph", [NSString stringWithFormat:@"installedBundleIDs=%lu tweaksWithUninstalledTargets=%lu", (unsigned long)installedBundleIDs.count, (unsigned long)uninstalledTargetTweaks.count]);

    phase = [NSDate date];
    NSTimeInterval embeddedPhaseAbsoluteStart = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval embeddedGlobalDeadline = embeddedPhaseAbsoluteStart + RCEmbeddedTotalTimeLimit;
    RCMachOScanner *mach = [RCMachOScanner new];
    NSMutableArray<RCEmbeddedInjectionRecord *> *allEmbedded = [NSMutableArray array];
    NSMutableArray<RCAppRecord *> *multi = [NSMutableArray array];
    NSMutableArray<RCAppRecord *> *orphans = [NSMutableArray array];
    NSUInteger embeddedEntriesVisited = 0;
    NSUInteger embeddedAppsScanned = 0;
    NSUInteger embeddedAppsTruncated = 0;
    NSUInteger embeddedAppsTimeLimited = 0;
    NSUInteger embeddedAppsSkippedByGlobalBudget = 0;
    NSTimeInterval slowestEmbeddedAppDuration = 0;
    NSString *slowestEmbeddedAppBundleIdentifier = @"";

    for (RCAppRecord *app in apps) {
        NSArray<RCTweakRecord *> *appTweaks = matches[app.bundleIdentifier] ?: @[];
        app.matchedTweaks = [appTweaks sortedArrayUsingComparator:^NSComparisonResult(RCTweakRecord *a, RCTweakRecord *b) {
            return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
        }];
        if (app.matchedTweaks.count >= 2) [multi addObject:app];
        if (app.highConfidenceOrphanRegistration) [orphans addObject:app];

        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
        if (now >= embeddedGlobalDeadline) {
            app.embeddedInjections = @[];
            app.embeddedScanEntriesVisited = 0;
            app.embeddedScanTruncated = YES;
            app.embeddedScanAttempted = NO;
            app.embeddedScanDuration = 0;
            app.embeddedTimeBudgetExceeded = YES;
            app.embeddedSkippedByGlobalBudget = YES;
            app.embeddedScanStopReason = @"global-time";
            app.embeddedScanStatus = [NSString stringWithFormat:@"跳过：全局 TrollFools 扫描 %.1fs 时间预算已用尽；不作未发现结论", RCEmbeddedTotalTimeLimit];
            embeddedAppsTruncated++;
            embeddedAppsSkippedByGlobalBudget++;
            continue;
        }

        NSTimeInterval perAppDeadline = now + RCEmbeddedTimeLimitPerApp;
        NSTimeInterval effectiveDeadline = MIN(perAppDeadline, embeddedGlobalDeadline);
        NSString *timeoutReason = (embeddedGlobalDeadline <= perAppDeadline) ? @"global-time" : @"per-app-time";
        RCEmbeddedScanResult *embeddedResult = [mach scanTrollFoolsEvidenceForApp:app
                                                                       maxEntries:RCEmbeddedEntryLimitPerApp
                                                                         deadline:effectiveDeadline
                                                                    timeoutReason:timeoutReason];
        NSMutableArray<RCEmbeddedInjectionRecord *> *deduplicatedEmbedded = [NSMutableArray array];
        NSMutableSet<NSString *> *embeddedIdentities = [NSMutableSet set];
        for (RCEmbeddedInjectionRecord *record in embeddedResult.records) {
            NSString *identity = [NSString stringWithFormat:@"%@\x1f%@\x1f%@\x1f%@",
                                  record.appBundleIdentifier ?: @"",
                                  record.targetMachOPath ?: @"",
                                  record.backupPath ?: @"",
                                  record.loadPath ?: @""];
            if ([embeddedIdentities containsObject:identity]) continue;
            [embeddedIdentities addObject:identity];
            [deduplicatedEmbedded addObject:record];
        }
        app.embeddedInjections = deduplicatedEmbedded;
        app.embeddedScanEntriesVisited = embeddedResult.entriesVisited;
        app.embeddedScanTruncated = embeddedResult.truncated;
        app.embeddedScanAttempted = embeddedResult.scanAttempted;
        app.embeddedScanDuration = embeddedResult.duration;
        app.embeddedTimeBudgetExceeded = embeddedResult.timeBudgetExceeded;
        app.embeddedSkippedByGlobalBudget = NO;
        app.embeddedScanStopReason = embeddedResult.stopReason ?: @"none";
        app.embeddedScanStatus = embeddedResult.status ?: @"";
        if (embeddedResult.scanAttempted) embeddedAppsScanned++;
        embeddedEntriesVisited += embeddedResult.entriesVisited;
        if (embeddedResult.truncated) embeddedAppsTruncated++;
        if (embeddedResult.timeBudgetExceeded) embeddedAppsTimeLimited++;
        if (embeddedResult.duration > slowestEmbeddedAppDuration) {
            slowestEmbeddedAppDuration = embeddedResult.duration;
            slowestEmbeddedAppBundleIdentifier = app.bundleIdentifier ?: @"";
        }
        [allEmbedded addObjectsFromArray:app.embeddedInjections];
    }
    NSTimeInterval embeddedDuration = -[phase timeIntervalSinceNow];
    RCTimelineAdd(timeline, totalStart, @"embedded", [NSString stringWithFormat:@"records=%lu entries=%lu apps=%lu incomplete=%lu timeLimited=%lu globalSkipped=%lu duration=%.3fs slowest=%@/%.3fs", (unsigned long)allEmbedded.count, (unsigned long)embeddedEntriesVisited, (unsigned long)embeddedAppsScanned, (unsigned long)embeddedAppsTruncated, (unsigned long)embeddedAppsTimeLimited, (unsigned long)embeddedAppsSkippedByGlobalBudget, embeddedDuration, slowestEmbeddedAppBundleIdentifier.length ? slowestEmbeddedAppBundleIdentifier : @"none", slowestEmbeddedAppDuration]);

    [multi sortUsingComparator:^NSComparisonResult(RCAppRecord *a, RCAppRecord *b) {
        if (a.matchedTweaks.count != b.matchedTweaks.count) return a.matchedTweaks.count > b.matchedTweaks.count ? NSOrderedAscending : NSOrderedDescending;
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];

    NSPredicate *issuePredicate = [NSPredicate predicateWithBlock:^BOOL(RCTweakRecord *t, NSDictionary *bindings) {
        (void)bindings;
        return t.issueSeverity >= RCTweakIssueSeveritySuspicious;
    }];

    [uninstalledTargetTweaks sortUsingComparator:^NSComparisonResult(RCTweakRecord *a, RCTweakRecord *b) {
        return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
    }];

    RCScanMetrics *metrics = [RCScanMetrics new];
    metrics.totalDuration = -[totalStart timeIntervalSinceNow];
    metrics.tweakAndPackageDuration = tweakDuration;
    metrics.appDuration = appDuration;
    metrics.blacklistDuration = blacklistDuration;
    metrics.embeddedDuration = embeddedDuration;
    metrics.embeddedEntriesVisited = embeddedEntriesVisited;
    metrics.embeddedAppsScanned = embeddedAppsScanned;
    metrics.embeddedAppsTruncated = embeddedAppsTruncated;
    metrics.embeddedAppsTimeLimited = embeddedAppsTimeLimited;
    metrics.embeddedAppsSkippedByGlobalBudget = embeddedAppsSkippedByGlobalBudget;
    metrics.embeddedEntryLimitPerApp = RCEmbeddedEntryLimitPerApp;
    metrics.embeddedTimeLimitPerApp = RCEmbeddedTimeLimitPerApp;
    metrics.embeddedTotalTimeLimit = RCEmbeddedTotalTimeLimit;
    metrics.slowestEmbeddedAppDuration = slowestEmbeddedAppDuration;
    metrics.slowestEmbeddedAppBundleIdentifier = slowestEmbeddedAppBundleIdentifier ?: @"";

    RCDiagnosticItem *completeness = [RCDiagnosticItem new];
    completeness.name = @"TrollFools evidence scan";
    completeness.passed = launchServicesAvailable && (embeddedAppsTruncated == 0 && embeddedAppsSkippedByGlobalBudget == 0);
    if (!launchServicesAvailable) {
        completeness.detail = @"未执行：LaunchServices 不可用；不能建立 App bundle 列表，因此不作 TrollFools clean 结论";
    } else if (completeness.passed) {
        completeness.detail = [NSString stringWithFormat:@"完整：遍历 %lu 项 / %lu 个 App bundle，耗时 %.2fs；预算 per-App=%0.1fs / global=%0.1fs",
                               (unsigned long)embeddedEntriesVisited, (unsigned long)embeddedAppsScanned, embeddedDuration,
                               RCEmbeddedTimeLimitPerApp, RCEmbeddedTotalTimeLimit];
    } else {
        completeness.detail = [NSString stringWithFormat:@"部分扫描：incomplete=%lu，time-limited=%lu，global-skipped=%lu；预算 entry=%lu / per-App=%0.1fs / global=%0.1fs。仅 TrollFools 证据可能漏报，DPKG/Filter/blacklist/孤立注册扫描不受影响",
                               (unsigned long)embeddedAppsTruncated, (unsigned long)embeddedAppsTimeLimited,
                               (unsigned long)embeddedAppsSkippedByGlobalBudget, (unsigned long)RCEmbeddedEntryLimitPerApp,
                               RCEmbeddedTimeLimitPerApp, RCEmbeddedTotalTimeLimit];
    }
    [diagnostics addObject:completeness];

    if (!launchServicesAvailable) {
        RCDiagnosticItem *d = [RCDiagnosticItem new];
        d.name = @"Result completeness"; d.passed = NO;
        d.detail = @"LaunchServices 不可用：App、孤立注册、blacklist 残留与 TrollFools App 证据均未执行；空结果不能解释为未发现";
        [diagnostics addObject:d];
    }
    if (!tweakScanAvailable) {
        RCDiagnosticItem *d = [RCDiagnosticItem new];
        d.name = @"Tweak result completeness"; d.passed = NO;
        d.detail = @"TweakInject 路径不可用：RootHide tweak / Filter 匹配未执行；空结果不能解释为未发现";
        [diagnostics addObject:d];
    }
    if (tweakScanAvailable && (!dpkgStatusAvailable || !dpkgInfoAvailable)) {
        RCDiagnosticItem *d = [RCDiagnosticItem new];
        d.name = @"DPKG result completeness"; d.passed = NO;
        d.detail = @"DPKG status/info 不完整：仍可扫描 tweak Filter，但 Package / Version / 文件归属信息可能不完整";
        [diagnostics addObject:d];
    }

    RCTimelineAdd(timeline, totalStart, @"result", [NSString stringWithFormat:@"multi=%lu orphan=%lu suspicious=%lu embedded=%lu", (unsigned long)multi.count, (unsigned long)orphans.count, (unsigned long)[tweaks filteredArrayUsingPredicate:issuePredicate].count, (unsigned long)allEmbedded.count]);
    metrics.totalDuration = -[totalStart timeIntervalSinceNow];

    RCAnalysisSnapshot *s = [RCAnalysisSnapshot new];
    s.launchServicesAvailable = launchServicesAvailable;
    s.tweakScanAvailable = tweakScanAvailable;
    s.dpkgStatusAvailable = dpkgStatusAvailable;
    s.dpkgInfoAvailable = dpkgInfoAvailable;
    s.blacklistStateAvailable = blacklistStateAvailable;
    s.embeddedEvidenceAvailable = embeddedEvidenceAvailable;
    s.apps = apps;
    s.tweaks = tweaks;
    s.multiMatchApps = multi;
    s.orphanRegistrations = orphans;
    s.blacklistResidues = blacklistResidues;
    s.suspiciousTweaks = [tweaks filteredArrayUsingPredicate:issuePredicate];
    s.uninstalledTargetTweaks = uninstalledTargetTweaks;
    s.embeddedInjectionRecords = allEmbedded;
    s.diagnostics = diagnostics;
    s.generatedAt = [NSDate date];
    s.metrics = metrics;
    s.environmentProfile = environmentProfile;
    s.timeline = [timeline copy];
    s.scanIdentifier = scanIdentifier;

    RCLog(@"capabilities: LS=%@ Tweak=%@ DPKG-status=%@ DPKG-info=%@ blacklist=%@ embedded=%@",
          launchServicesAvailable ? @"YES" : @"NO", tweakScanAvailable ? @"YES" : @"NO",
          dpkgStatusAvailable ? @"YES" : @"NO", dpkgInfoAvailable ? @"YES" : @"NO",
          blacklistStateAvailable ? @"YES" : @"NO", embeddedEvidenceAvailable ? @"YES" : @"NO");
    RCLog(@"scan finished: %.2fs id=%@ apps=%lu tweaks=%lu multi=%lu orphan=%lu blacklistResidue=%lu suspicious=%lu uninstalledTargets=%lu embedded=%lu embeddedEntries=%lu incompleteApps=%lu timeLimited=%lu globalSkipped=%lu",
          metrics.totalDuration, scanIdentifier, (unsigned long)apps.count, (unsigned long)tweaks.count,
          (unsigned long)multi.count, (unsigned long)orphans.count, (unsigned long)blacklistResidues.count,
          (unsigned long)s.suspiciousTweaks.count, (unsigned long)uninstalledTargetTweaks.count,
          (unsigned long)allEmbedded.count, (unsigned long)embeddedEntriesVisited,
          (unsigned long)embeddedAppsTruncated, (unsigned long)embeddedAppsTimeLimited,
          (unsigned long)embeddedAppsSkippedByGlobalBudget);
    return s;
}
@end
