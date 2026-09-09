#import "RCAnalysisViewController.h"
#import "RCAnalysisManager.h"
#import "RCAppBrowserViewController.h"
#import "RCAppDetailViewController.h"
#import "RCModels.h"
#import "RCDiagnostics.h"
#import "RCBuildInfo.h"

@interface RCAnalysisViewController ()
@property (nonatomic, strong) RCAnalysisSnapshot *snapshot;
@property (nonatomic) BOOL scanning;
@end

@implementation RCAnalysisViewController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"注入分析";
    UIBarButtonItem *rescan = [[UIBarButtonItem alloc] initWithTitle:@"重新扫描" style:UIBarButtonItemStylePlain target:self action:@selector(forceRefresh)];
    UIBarButtonItem *report = [[UIBarButtonItem alloc] initWithTitle:@"报告" style:UIBarButtonItemStylePlain target:self action:@selector(shareReport)];
    self.navigationItem.rightBarButtonItems = @[rescan, report];
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
    __weak typeof(self) weakSelf = self;
    [[RCAnalysisManager sharedManager] loadSnapshotWithCompletion:^(RCAnalysisSnapshot *snapshot) {
        weakSelf.scanning = NO;
        weakSelf.snapshot = snapshot;
        [weakSelf.refreshControl endRefreshing];
        [weakSelf.tableView reloadData];
    }];
}
- (void)forceRefresh {
    if (self.scanning) return;
    self.scanning = YES;
    [self.refreshControl beginRefreshing];
    __weak typeof(self) weakSelf = self;
    [[RCAnalysisManager sharedManager] refreshWithCompletion:^(RCAnalysisSnapshot *snapshot) {
        weakSelf.scanning = NO;
        weakSelf.snapshot = snapshot;
        [weakSelf.refreshControl endRefreshing];
        [weakSelf.tableView reloadData];
    }];
}
- (NSUInteger)activeEmbeddedCountForApp:(RCAppRecord *)app {
    NSUInteger count = 0;
    for (RCEmbeddedInjectionRecord *r in app.embeddedInjections) if (r.activeDifferenceConfirmed) count++;
    return count;
}
- (BOOL)rootHideInjectionPermittedForApp:(RCAppRecord *)app {
    // Configuration inference only. This is not proof that a matching dylib was
    // loaded into a live App process.
    return app.matchedTweaks.count > 0 && app.blacklistStateKnown && app.blacklistSupported && !app.blacklisted;
}
- (NSArray<RCAppRecord *> *)mixedApps {
    NSMutableArray *a = [NSMutableArray array];
    for (RCAppRecord *app in self.snapshot.apps) {
        if ([self rootHideInjectionPermittedForApp:app] && [self activeEmbeddedCountForApp:app] > 0) [a addObject:app];
    }
    return a;
}
- (NSArray<RCAppRecord *> *)embeddedApps {
    NSMutableArray *apps = [NSMutableArray array];
    for (RCAppRecord *app in self.snapshot.apps) {
        if (app.embeddedInjections.count) [apps addObject:app];
    }
    [apps sortUsingComparator:^NSComparisonResult(RCAppRecord *a, RCAppRecord *b) {
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];
    return apps;
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return self.snapshot ? 5 : 1; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!self.snapshot) return 1;
    if (section == 0) return 1;
    if (section == 1) return 1;
    if (section == 2) return MAX((NSUInteger)1, self.snapshot.multiMatchApps.count);
    if (section == 3) return MAX((NSUInteger)1, self.embeddedApps.count);
    return MAX((NSUInteger)1, self.mixedApps.count);
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (!self.snapshot) return [NSString stringWithFormat:@"Analysis %@", RCAnalysisVersion()];
    if (section == 0) return @"扫描摘要";
    if (section == 1) return @"单 App 深度分析";
    if (section == 2) return @"多插件 Filter 匹配";
    if (section == 3) return @"其它注入（按 App）";
    return @"RootHide 允许 + TrollFools 活动注入";
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
        NSString *status = incomplete ? @"⚠ 本次分析不完整，查看报告了解原因" : @"扫描完成";
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"HH:mm:ss";
        NSString *scanTime = self.snapshot.generatedAt ? [formatter stringFromDate:self.snapshot.generatedAt] : @"刚刚";
        NSString *detail = [NSString stringWithFormat:@"%lu 个 App · %lu 个插件\n扫描时间：%@ · 当前进程内结果可复用",
                            (unsigned long)self.snapshot.apps.count,
                            (unsigned long)self.snapshot.tweaks.count,
                            scanTime];
        return [self emptyCell:status detail:detail];
    }
    if (indexPath.section == 1) {
        if (!self.snapshot.launchServicesAvailable) return [self emptyCell:@"App 深度分析不可用" detail:@"LaunchServices 未通过 preflight；无法建立可搜索 App 列表"];
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
        cell.textLabel.text = @"浏览全部已注册 App";
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu 个 App · 可按名称 / Bundle ID 搜索并查看完整证据链", (unsigned long)self.snapshot.apps.count];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        return cell;
    }
    if (indexPath.section == 2 && !self.snapshot.tweakScanAvailable) return [self emptyCell:@"RootHide tweak 扫描不可用" detail:@"TweakInject 数据源未通过 preflight；这里不显示‘未发现’，避免把未执行误解为空结果"];
    if (indexPath.section == 2 && !self.snapshot.launchServicesAvailable) return [self emptyCell:@"App 扫描不可用" detail:@"LaunchServices 未通过 preflight，无法建立 App ↔ Tweak 匹配关系"];
    if (indexPath.section == 2 && !self.snapshot.multiMatchApps.count) return [self emptyCell:@"未发现多插件匹配" detail:@"扫描已执行；当前没有 App 同时匹配 2 个及以上 RootHide tweak Bundles filter"];
    if (indexPath.section == 3 && !self.snapshot.embeddedEvidenceAvailable) return [self emptyCell:@"TrollFools 证据扫描不可用" detail:@"LaunchServices/App bundle 数据源不可用；空结果不能解释为未发现"];
    if (indexPath.section == 3 && !self.embeddedApps.count) {
        RCScanMetrics *m = self.snapshot.metrics;
        if (m.embeddedAppsTruncated || m.embeddedAppsSkippedByGlobalBudget) return [self emptyCell:@"TrollFools 证据扫描不完整" detail:@"部分 App 因条目/时间预算未完整扫描；当前空记录不能解释为设备没有 TrollFools 高置信度证据"];
        return [self emptyCell:@"未发现 TrollFools 高置信度证据" detail:@"扫描已执行且预算内完成；没有备份证据时不会把普通 Framework 误判为巨魔注入"];
    }
    if (indexPath.section == 4 && (!self.snapshot.tweakScanAvailable || !self.snapshot.launchServicesAvailable || !self.snapshot.blacklistStateAvailable || !self.snapshot.embeddedEvidenceAvailable)) return [self emptyCell:@"双来源判定条件不完整" detail:@"需要 RootHide Filter、LaunchServices、blacklist 状态与 TrollFools 证据均可用；缺任一数据源时不作‘未发现’结论"];
    if (indexPath.section == 4 && !self.mixedApps.count) {
        RCScanMetrics *m = self.snapshot.metrics;
        if (m.embeddedAppsTruncated || m.embeddedAppsSkippedByGlobalBudget) return [self emptyCell:@"双来源判定不完整" detail:@"RootHide 数据可用，但部分 App 的 TrollFools 证据因扫描预算不完整；不能把当前 0 条解释为未发现双来源"];
        return [self emptyCell:@"未发现双来源活动证据" detail:@"要求：RootHide Filter 匹配、RootHide blacklist 配置允许、并确认 TrollFools Load Command 差分。仍不等同于运行时证明。"];
    }

    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    cell.detailTextLabel.numberOfLines = 0;
    if (indexPath.section == 2) {
        RCAppRecord *app = self.snapshot.multiMatchApps[indexPath.row];
        cell.textLabel.text = [NSString stringWithFormat:@"%@     %lu", app.name, (unsigned long)app.matchedTweaks.count];
        NSString *state = !app.blacklistStateKnown ? @"blacklist 状态未知" : (app.blacklisted ? @"已 blacklist" : @"blacklist 允许");
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@", app.bundleIdentifier, state];
    } else if (indexPath.section == 3) {
        RCAppRecord *app = self.embeddedApps[indexPath.row];
        NSMutableSet<NSString *> *machOPaths = [NSMutableSet set];
        NSMutableSet<NSString *> *loadPaths = [NSMutableSet set];
        NSUInteger active = 0;
        for (RCEmbeddedInjectionRecord *r in app.embeddedInjections) {
            if (r.targetMachOPath.length) [machOPaths addObject:r.targetMachOPath];
            if (r.loadPath.length) [loadPaths addObject:r.loadPath];
            if (r.activeDifferenceConfirmed) active++;
        }
        cell.textLabel.text = app.name.length ? app.name : app.bundleIdentifier;
        cell.detailTextLabel.text = [NSString stringWithFormat:@"证据 %lu 条 · 活动差分 %lu · Mach-O %lu · Load %lu",
                                         (unsigned long)app.embeddedInjections.count,
                                         (unsigned long)active,
                                         (unsigned long)machOPaths.count,
                                         (unsigned long)loadPaths.count];
    } else {
        RCAppRecord *app = self.mixedApps[indexPath.row];
        cell.textLabel.text = app.name;
        cell.detailTextLabel.text = [NSString stringWithFormat:@"RootHide Filter %lu 个（blacklist 允许） + TrollFools 活动差分 %lu 个", (unsigned long)app.matchedTweaks.count, (unsigned long)[self activeEmbeddedCountForApp:app]];
    }
    return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (!self.snapshot) return;
    if (indexPath.section == 1 && self.snapshot.launchServicesAvailable) {
        [self.navigationController pushViewController:[[RCAppBrowserViewController alloc] initWithSnapshot:self.snapshot] animated:YES];
        return;
    }
    RCAppRecord *app = nil;
    if (indexPath.section == 2 && self.snapshot.multiMatchApps.count) app = self.snapshot.multiMatchApps[indexPath.row];
    else if (indexPath.section == 3 && self.embeddedApps.count) app = self.embeddedApps[indexPath.row];
    else if (indexPath.section == 4 && self.mixedApps.count) app = self.mixedApps[indexPath.row];
    if (app) [self.navigationController pushViewController:[[RCAppDetailViewController alloc] initWithAppRecord:app snapshot:self.snapshot] animated:YES];
}
@end
