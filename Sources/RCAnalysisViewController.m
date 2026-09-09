#import "RCAnalysisViewController.h"
#import "RCAnalysisManager.h"
#import "RCAppDetailViewController.h"
#import "RCModels.h"
#import "RCDiagnostics.h"
#import "RCBuildInfo.h"

@interface RCAnalysisViewController ()
@property (nonatomic, strong) RCAnalysisSnapshot *snapshot;
@property (nonatomic) BOOL scanning;
@property (nonatomic) BOOL rescanning;
@property (nonatomic, strong) UIBarButtonItem *rescanButton;
@end

@implementation RCAnalysisViewController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"注入分析";
    self.rescanButton = [[UIBarButtonItem alloc] initWithTitle:@"重新扫描" style:UIBarButtonItemStylePlain target:self action:@selector(forceRefresh)];
    UIBarButtonItem *report = [[UIBarButtonItem alloc] initWithTitle:@"报告" style:UIBarButtonItemStylePlain target:self action:@selector(shareReport)];
    self.navigationItem.rightBarButtonItems = @[self.rescanButton, report];
    self.refreshControl = [UIRefreshControl new];
    [self.refreshControl addTarget:self action:@selector(forceRefresh) forControlEvents:UIControlEventValueChanged];
    [self loadSnapshot];
}

- (void)shareReport {
    if (!self.snapshot) return;
    NSString *report = [RCDiagnostics fullReadOnlyReportForSnapshot:self.snapshot];
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:@[report] applicationActivities:nil];
    vc.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItems.lastObject;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)loadSnapshot {
    if (self.scanning) return;
    self.scanning = YES;
    self.rescanButton.enabled = NO;
    __weak typeof(self) weakSelf = self;
    [[RCAnalysisManager sharedManager] loadSnapshotWithCompletion:^(RCAnalysisSnapshot *snapshot) {
        weakSelf.scanning = NO;
        weakSelf.snapshot = snapshot;
        weakSelf.rescanButton.enabled = YES;
        [weakSelf.refreshControl endRefreshing];
        [weakSelf.tableView reloadData];
    }];
}

- (void)forceRefresh {
    if (self.scanning) return;
    self.scanning = YES;
    self.rescanning = YES;
    self.rescanButton.title = @"扫描中…";
    self.rescanButton.enabled = NO;
    [self.refreshControl beginRefreshing];
    [self.tableView reloadData];
    __weak typeof(self) weakSelf = self;
    [[RCAnalysisManager sharedManager] refreshWithCompletion:^(RCAnalysisSnapshot *snapshot) {
        weakSelf.scanning = NO;
        weakSelf.rescanning = NO;
        weakSelf.snapshot = snapshot;
        weakSelf.rescanButton.title = @"重新扫描";
        weakSelf.rescanButton.enabled = YES;
        [weakSelf.refreshControl endRefreshing];
        [weakSelf.tableView reloadData];
    }];
}

- (NSArray<RCTweakRecord *> *)dpkgTweaksForApp:(RCAppRecord *)app {
    NSMutableArray<RCTweakRecord *> *out = [NSMutableArray array];
    for (RCTweakRecord *tweak in app.matchedTweaks) {
        if (tweak.installSource == RCTweakInstallSourceDPKG && tweak.package) [out addObject:tweak];
    }
    return out;
}

- (NSUInteger)trollFoolsPluginCountForApp:(RCAppRecord *)app {
    NSMutableSet<NSString *> *loadPaths = [NSMutableSet set];
    for (RCEmbeddedInjectionRecord *record in app.embeddedInjections) {
        if (record.loadPath.length) [loadPaths addObject:record.loadPath];
    }
    return loadPaths.count;
}

- (NSString *)trollFoolsSummaryForApp:(RCAppRecord *)app {
    NSUInteger pluginCount = [self trollFoolsPluginCountForApp:app];
    return pluginCount
        ? [NSString stringWithFormat:@"TrollFools · %lu 个插件", (unsigned long)pluginCount]
        : @"TrollFools · 已发现注入证据";
}

- (NSArray<RCAppRecord *> *)injectedApps {
    NSMutableArray<RCAppRecord *> *apps = [NSMutableArray array];
    for (RCAppRecord *app in self.snapshot.apps) {
        BOOL hasDPKG = [self dpkgTweaksForApp:app].count > 0;
        BOOL hasTrollFools = app.embeddedInjections.count > 0;
        if (hasDPKG || hasTrollFools) [apps addObject:app];
    }
    [apps sortUsingComparator:^NSComparisonResult(RCAppRecord *a, RCAppRecord *b) {
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];
    return apps;
}

- (NSString *)systemDescriptionForBundleIdentifier:(NSString *)bundleIdentifier {
    NSString *lower = bundleIdentifier.lowercaseString;
    if ([lower isEqualToString:@"com.apple.springboard"]) return @"SpringBoard";
    if ([lower isEqualToString:@"com.apple.backboardd"]) return @"backboardd";
    return nil;
}

- (NSArray<NSString *> *)systemTargetDescriptionsForTweak:(RCTweakRecord *)tweak {
    NSMutableOrderedSet<NSString *> *targets = [NSMutableOrderedSet orderedSet];
    for (NSString *executable in tweak.systemTargetExecutableIdentifiers) {
        if (executable.length) [targets addObject:[NSString stringWithFormat:@"系统进程：%@", executable]];
    }
    for (NSString *bundleIdentifier in tweak.uninstalledTargetBundleIdentifiers) {
        NSString *system = [self systemDescriptionForBundleIdentifier:bundleIdentifier];
        if (system.length) [targets addObject:[NSString stringWithFormat:@"系统目标：%@", system]];
    }
    return targets.array;
}

- (NSArray<RCTweakRecord *> *)systemInjectionTweaks {
    NSMutableArray<RCTweakRecord *> *out = [NSMutableArray array];
    for (RCTweakRecord *tweak in self.snapshot.tweaks) {
        if ([self systemTargetDescriptionsForTweak:tweak].count) [out addObject:tweak];
    }
    [out sortUsingComparator:^NSComparisonResult(RCTweakRecord *a, RCTweakRecord *b) {
        return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
    }];
    return out;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return self.snapshot ? 3 : 1; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!self.snapshot) return 1;
    if (section == 0) return 1;
    if (section == 1) return MAX((NSUInteger)1, self.systemInjectionTweaks.count);
    return MAX((NSUInteger)1, self.injectedApps.count);
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (!self.snapshot) return [NSString stringWithFormat:@"Analysis %@", RCAnalysisVersion()];
    if (section == 0) return @"扫描摘要";
    if (section == 1) return @"系统注入";
    return @"App 注入";
}

- (UITableViewCell *)emptyCell:(NSString *)text detail:(NSString *)detail {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = text;
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.numberOfLines = 0;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (!self.snapshot) return [self emptyCell:@"正在只读扫描…" detail:@"不会修改 blacklist、不会 unregister、不会删除文件"];

    if (indexPath.section == 0) {
        RCScanMetrics *m = self.snapshot.metrics;
        BOOL incomplete = m.embeddedAppsTruncated || m.embeddedAppsSkippedByGlobalBudget;
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"HH:mm:ss";
        NSString *scanTime = self.snapshot.generatedAt ? [formatter stringFromDate:self.snapshot.generatedAt] : @"刚刚";
        if (self.rescanning) {
            NSString *detail = [NSString stringWithFormat:@"%lu 个 App · %lu 个插件\n当前显示上一次结果 · 上次扫描时间：%@",
                                (unsigned long)self.snapshot.apps.count,
                                (unsigned long)self.snapshot.tweaks.count,
                                scanTime];
            return [self emptyCell:@"正在重新扫描…" detail:detail];
        }
        NSString *status = incomplete ? @"⚠ 本次分析不完整，查看报告了解原因" : @"扫描完成";
        NSString *detail = [NSString stringWithFormat:@"%lu 个 App · %lu 个插件\n扫描时间：%@ · 当前进程内结果可复用",
                            (unsigned long)self.snapshot.apps.count,
                            (unsigned long)self.snapshot.tweaks.count,
                            scanTime];
        return [self emptyCell:status detail:detail];
    }

    if (indexPath.section == 1) {
        if (!self.snapshot.tweakScanAvailable) return [self emptyCell:@"系统注入扫描不可用" detail:@"TweakInject 数据源未通过 preflight；不把未执行解释为未发现。"];
        NSArray<RCTweakRecord *> *systemTweaks = self.systemInjectionTweaks;
        if (!systemTweaks.count) return [self emptyCell:@"未发现系统注入插件" detail:@"已检查系统 launchd 进程对应的 Filter.Executables，以及明确的系统 Bundle 目标；其它未解析目标保留在环境检查/报告中。"];
        RCTweakRecord *tweak = systemTweaks[indexPath.row];
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
        cell.textLabel.text = tweak.displayName;
        NSString *source = tweak.installSource == RCTweakInstallSourceDPKG ? @"DEB（包管理器）" : @"RootHide 插件 · 来源未确认";
        NSString *targets = [[self systemTargetDescriptionsForTweak:tweak] componentsJoinedByString:@" · "];
        cell.detailTextLabel.text = targets.length ? [NSString stringWithFormat:@"%@ · %@", source, targets] : source;
        cell.detailTextLabel.numberOfLines = 0;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    if (!self.snapshot.launchServicesAvailable) return [self emptyCell:@"App 注入分析不可用" detail:@"LaunchServices 未通过 preflight；不能建立 App 注入列表。"];
    NSArray<RCAppRecord *> *apps = self.injectedApps;
    if (!apps.count) {
        BOOL trollFoolsIncomplete = !self.snapshot.embeddedEvidenceAvailable || self.snapshot.metrics.embeddedAppsTruncated || self.snapshot.metrics.embeddedAppsSkippedByGlobalBudget;
        NSString *detail = trollFoolsIncomplete
            ? @"没有确认到 DEB（包管理器）App 注入；TrollFools 扫描不完整，因此不作整体 clean 结论。"
            : @"当前没有检测到 DEB（包管理器）或 TrollFools App 注入。未注入 App 已收纳，不在此列表显示。";
        return [self emptyCell:@"未发现 App 注入" detail:detail];
    }

    RCAppRecord *app = apps[indexPath.row];
    NSArray<RCTweakRecord *> *dpkgTweaks = [self dpkgTweaksForApp:app];
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    if (dpkgTweaks.count) [parts addObject:[NSString stringWithFormat:@"DEB（包管理器） · %lu 个插件", (unsigned long)dpkgTweaks.count]];
    if (app.embeddedInjections.count) [parts addObject:[self trollFoolsSummaryForApp:app]];

    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = app.name.length ? app.name : app.bundleIdentifier;
    cell.detailTextLabel.text = [parts componentsJoinedByString:@" · "];
    cell.detailTextLabel.numberOfLines = 0;
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (!self.snapshot || indexPath.section != 2) return;
    NSArray<RCAppRecord *> *apps = self.injectedApps;
    if (indexPath.row >= (NSInteger)apps.count) return;
    RCAppRecord *app = apps[indexPath.row];
    [self.navigationController pushViewController:[[RCAppDetailViewController alloc] initWithAppRecord:app snapshot:self.snapshot] animated:YES];
}
@end
