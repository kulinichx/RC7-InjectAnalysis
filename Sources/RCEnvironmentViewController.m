#import "RCEnvironmentViewController.h"
#import "RCAnalysisManager.h"
#import "RCModels.h"
#import "RCDiagnostics.h"
#import "RCBuildInfo.h"

@interface RCEnvironmentViewController ()
@property (nonatomic, strong) RCAnalysisSnapshot *snapshot;
@property (nonatomic) BOOL scanning;
@property (nonatomic) BOOL rescanning;
@property (nonatomic, strong) UIBarButtonItem *rescanButton;
@end

@implementation RCEnvironmentViewController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"环境检查";
    self.rescanButton = [[UIBarButtonItem alloc] initWithTitle:@"重新扫描" style:UIBarButtonItemStylePlain target:self action:@selector(forceRefresh)];
    UIBarButtonItem *report = [[UIBarButtonItem alloc] initWithTitle:@"报告" style:UIBarButtonItemStylePlain target:self action:@selector(shareReport)];
    self.navigationItem.rightBarButtonItems = @[self.rescanButton, report];
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
        [weakSelf.tableView reloadData];
    }];
}
- (void)forceRefresh {
    if (self.scanning) return;
    self.scanning = YES;
    self.rescanning = YES;
    self.rescanButton.title = @"扫描中…";
    self.rescanButton.enabled = NO;
    [self.tableView reloadData];
    __weak typeof(self) weakSelf = self;
    [[RCAnalysisManager sharedManager] refreshWithCompletion:^(RCAnalysisSnapshot *snapshot) {
        weakSelf.scanning = NO;
        weakSelf.rescanning = NO;
        weakSelf.snapshot = snapshot;
        weakSelf.rescanButton.title = @"重新扫描";
        weakSelf.rescanButton.enabled = YES;
        [weakSelf.tableView reloadData];
    }];
}
- (NSString *)systemTargetDescriptionForBundleIdentifier:(NSString *)bundleIdentifier {
    NSString *lower = bundleIdentifier.lowercaseString;
    if ([lower isEqualToString:@"com.apple.springboard"]) return @"SpringBoard 系统进程";
    if ([lower isEqualToString:@"com.apple.backboardd"]) return @"backboardd 系统进程";
    return nil;
}
- (NSArray<RCTweakRecord *> *)unresolvedFilterTweaks {
    NSMutableArray<RCTweakRecord *> *out = [NSMutableArray array];
    for (RCTweakRecord *tweak in self.snapshot.uninstalledTargetTweaks) {
        BOOL hasUnresolved = tweak.unresolvedTargetExecutableIdentifiers.count > 0;
        if (!hasUnresolved) {
            for (NSString *bundleIdentifier in tweak.uninstalledTargetBundleIdentifiers) {
                if (![self systemTargetDescriptionForBundleIdentifier:bundleIdentifier].length) {
                    hasUnresolved = YES;
                    break;
                }
            }
        }
        if (hasUnresolved) [out addObject:tweak];
    }
    return out;
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    if (!self.snapshot) return 1;
    return self.unresolvedFilterTweaks.count ? 7 : 6;
}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!self.snapshot) return 1;
    if (section == 0) return 9;
    if (section == 1) return MAX(1, self.snapshot.timeline.count);
    if (section == 2) return MAX(1, self.snapshot.diagnostics.count);
    if (section == 3) return MAX(1, self.snapshot.blacklistResidues.count);
    if (section == 4) return MAX(1, self.snapshot.orphanRegistrations.count);
    if (section == 5) return MAX(1, self.snapshot.suspiciousTweaks.count);
    return self.unresolvedFilterTweaks.count;
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (!self.snapshot) return [NSString stringWithFormat:@"Analysis %@（只读）", RCAnalysisVersion()];
    if (section == 0) return @"Analysis / RootHide 运行环境";
    if (section == 1) return @"扫描时间线";
    if (section == 2) return @"启动自检";
    if (section == 3) return @"无效 Blacklist 记录";
    if (section == 4) return @"孤立 App 注册";
    if (section == 5) return @"Tweak / Filter 可疑项";
    return @"未解析 Filter 目标";
}
- (UITableViewCell *)cell:(NSString *)text detail:(NSString *)detail {
    UITableViewCell *c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    c.textLabel.text = text;
    c.textLabel.numberOfLines = 0;
    c.detailTextLabel.text = detail;
    c.detailTextLabel.numberOfLines = 0;
    c.selectionStyle = UITableViewCellSelectionStyleNone;
    return c;
}
- (UITableViewCell *)environmentCellForRow:(NSInteger)row {
    RCEnvironmentProfile *e = self.snapshot.environmentProfile;
    if (row == 0) {
        NSString *text = [NSString stringWithFormat:@"Analysis %@ · %@", e.analysisVersion.length ? e.analysisVersion : RCAnalysisVersion(), e.analysisArchitecture.length ? e.analysisArchitecture : @"?"];
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"HH:mm:ss";
        NSString *scanTime = self.snapshot.generatedAt ? [formatter stringFromDate:self.snapshot.generatedAt] : @"未知";
        NSString *scanState = self.rescanning
            ? [NSString stringWithFormat:@"正在重新扫描… 当前显示上一次结果（%@）", scanTime]
            : [NSString stringWithFormat:@"扫描时间：%@", scanTime];
        NSString *detail = [NSString stringWithFormat:@"%@\nUUID: %@\nImage: %@", scanState, e.analysisImageUUID.length ? e.analysisImageUUID : @"未知", e.analysisImagePath.length ? e.analysisImagePath : @"未知"];
        return [self cell:text detail:detail];
    }
    if (row == 1) {
        NSString *text = [NSString stringWithFormat:@"Runtime Self-Check：%@", e.analysisRuntimeSelfCheckStatus.length ? e.analysisRuntimeSelfCheckStatus : @"WARN"];
        NSString *detail = [NSString stringWithFormat:@"%@\nImage path=%@ · Host weak load=%@ · Manifest UUID=%@ · Hook=%@", e.analysisRuntimeSelfCheckSummary.length ? e.analysisRuntimeSelfCheckSummary : @"unknown", e.analysisImagePathExpected ? @"PASS" : @"WARN", e.analysisHostWeakLoadPresent ? @"PASS" : @"WARN", e.analysisBuildManifestUUIDMatches ? @"PASS" : @"WARN", e.analysisMenuHooksInstalled ? @"PASS" : @"WARN"];
        return [self cell:text detail:detail];
    }
    if (row == 2) {
        NSString *text = [NSString stringWithFormat:@"载入状态：%@ · Hook %@", e.analysisBuildManifestPresent ? @"有构建清单" : @"无构建清单", e.analysisMenuHooksInstalled ? @"已安装" : @"未确认"];
        NSString *detail = [NSString stringWithFormat:@"Manifest schema: %ld · version: %@ · version match: %@ · UUID match: %@\nBuildID: %@\nSource: %@ · files=%lu\nload=%@ · hook attempts=%lu\ndylib SHA256: %@", (long)e.analysisBuildManifestSchema, e.analysisBuildManifestVersion.length ? e.analysisBuildManifestVersion : @"(none)", e.analysisBuildManifestVersionMatches ? @"YES" : @"NO", e.analysisBuildManifestUUIDMatches ? @"YES" : @"NO", e.analysisBuildID.length ? e.analysisBuildID : @"(none)", e.analysisBuildManifestSourceTreeSHA256.length ? e.analysisBuildManifestSourceTreeSHA256 : @"(none)", (unsigned long)e.analysisBuildManifestSourceFileCount, e.analysisBuildManifestLoadMode.length ? e.analysisBuildManifestLoadMode : @"(none)", (unsigned long)e.analysisMenuHookInstallAttempts, e.analysisBuildManifestDylibSHA256.length ? e.analysisBuildManifestDylibSHA256 : @"(none)"];
        return [self cell:text detail:detail];
    }
    if (row == 3) {
        NSString *text = [NSString stringWithFormat:@"安装后文件状态：Host %@ · dylib %@", e.analysisHostExecutablePostInstallStateExpected ? @"PASS" : @"WARN", e.analysisDylibFileStateExpected ? @"PASS" : @"WARN"];
        NSString *detail = [NSString stringWithFormat:@"Host uid=%lu gid=%lu mode=%@ setuid=%@\n%@\ndylib mode=%@ · %@", (unsigned long)e.analysisHostExecutableUID, (unsigned long)e.analysisHostExecutableGID, e.analysisHostExecutableMode.length ? e.analysisHostExecutableMode : @"?", e.analysisHostExecutableSetUID ? @"YES" : @"NO", e.analysisHostExecutableStateDetail.length ? e.analysisHostExecutableStateDetail : @"符合原 RootHide postinst: root:root + executable + setuid", e.analysisDylibFileMode.length ? e.analysisDylibFileMode : @"?", e.analysisDylibFileStateDetail.length ? e.analysisDylibFileStateDetail : @"regular executable dylib"];
        return [self cell:text detail:detail];
    }
    if (row == 4) {
        NSString *text = [NSString stringWithFormat:@"RootHide: %@ · jbroot: %@", e.rootHideDetected ? @"检测到" : @"未确认", e.jbrootAvailable ? @"可用" : @"不可用"];
        NSString *detail = [NSString stringWithFormat:@"Path mapping: %@\njbroot image: %@", e.pathMappingActive ? @"ACTIVE" : @"未观察到路径变化", e.jbrootImagePath.length ? e.jbrootImagePath : @"未知"];
        return [self cell:text detail:detail];
    }
    NSArray<NSArray<NSString *> *> *paths = @[
        @[e.tweakInjectLogicalPath ?: @"", e.tweakInjectMappedPath ?: @""],
        @[e.dpkgStatusLogicalPath ?: @"", e.dpkgStatusMappedPath ?: @""],
        @[e.dpkgInfoLogicalPath ?: @"", e.dpkgInfoMappedPath ?: @""],
        @[e.rootHideConfigLogicalPath ?: @"", e.rootHideConfigMappedPath ?: @""]
    ];
    NSArray<NSString *> *pair = paths[row - 5];
    BOOL mapped = ![pair[0] isEqualToString:pair[1]];
    return [self cell:pair[0] detail:[NSString stringWithFormat:@"%@%@", pair[1], mapped ? @"\n✓ jbroot 映射后路径与逻辑路径不同" : @"\nℹ 当前返回逻辑路径本身"]];
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (!self.snapshot) return [self cell:@"正在扫描…" detail:@"仅报告，不删除、不 unregister、不重建 Icon Cache"];

    if (indexPath.section == 0) return [self environmentCellForRow:indexPath.row];

    if (indexPath.section == 1) {
        if (!self.snapshot.timeline.count) return [self cell:@"未生成扫描时间线" detail:@"结果仍可查看，但首轮实机诊断信息不足"];
        RCScanTimelineEvent *event = self.snapshot.timeline[indexPath.row];
        return [self cell:[NSString stringWithFormat:@"[%06.3fs] %@", event.offset, event.phase] detail:event.detail];
    }

    if (indexPath.section == 2) {
        if (!self.snapshot.diagnostics.count) return [self cell:@"未生成自检结果" detail:nil];
        RCDiagnosticItem *d = self.snapshot.diagnostics[indexPath.row];
        return [self cell:[NSString stringWithFormat:@"%@ %@", d.passed ? @"✓" : @"⚠", d.name] detail:d.detail];
    }

    if (indexPath.section == 3) {
        if (!self.snapshot.launchServicesAvailable) return [self cell:@"Blacklist 残留扫描不可用" detail:@"LaunchServices 未通过 preflight，无法判断配置中的 Bundle ID 是否已卸载"];
        if (!self.snapshot.blacklistResidues.count) return [self cell:@"未发现已卸载 App 的 blacklist 残留" detail:@"扫描已执行；只报告 appconfig 中明确为 YES、且 LaunchServices 当前无对应 Bundle ID 的记录"];
        RCBlacklistResidueRecord *r = self.snapshot.blacklistResidues[indexPath.row];
        NSString *state = r.blacklistGloballyDisabled ? @"当前 blacklistDisabled=YES（记录暂不生效）" : @"当前 blacklist 功能启用";
        return [self cell:[NSString stringWithFormat:@"⚠ %@", r.bundleIdentifier]
                    detail:[NSString stringWithFormat:@"置信度：%@ · %@\n%@", RCConfidenceText(r.confidence), state, r.evidence ?: @""]];
    }

    if (indexPath.section == 4) {
        if (!self.snapshot.launchServicesAvailable) return [self cell:@"孤立注册扫描不可用" detail:@"LaunchServices 未通过 preflight；空结果不能解释为未发现"];
        if (!self.snapshot.orphanRegistrations.count) return [self cell:@"未发现高置信度孤立注册" detail:@"扫描已执行；只在 LS 已注册 + Bundle ID/Path 可取 + 实际 .app 不存在时报告"];
        RCAppRecord *a = self.snapshot.orphanRegistrations[indexPath.row];
        return [self cell:[NSString stringWithFormat:@"⚠ %@", a.name] detail:[NSString stringWithFormat:@"%@\n%@", a.bundleIdentifier, a.bundlePath ?: @""]];
    }

    if (indexPath.section == 5) {
        if (!self.snapshot.tweakScanAvailable) return [self cell:@"Tweak 配置扫描不可用" detail:@"TweakInject 路径未通过 preflight；空结果不能解释为未发现"];
        if (!self.snapshot.suspiciousTweaks.count) return [self cell:@"未发现可疑 tweak 配置" detail:@"扫描已执行；第一版对非标准 tweak 结构保持保守，不自动升级为高置信度异常"];
        RCTweakRecord *t = self.snapshot.suspiciousTweaks[indexPath.row];
        return [self cell:[NSString stringWithFormat:@"⚠ %@", t.displayName]
                    detail:[NSString stringWithFormat:@"%@\n%@", RCTweakIssueSeverityText(t.issueSeverity), [t.issues componentsJoinedByString:@"\n"]]];
    }

    if (indexPath.section == 6) {
        NSArray<RCTweakRecord *> *unresolvedTweaks = self.unresolvedFilterTweaks;
        if (indexPath.row >= (NSInteger)unresolvedTweaks.count) return [self cell:@"未解析 Filter 目标不可用" detail:@"列表状态已变化；未执行任何修改操作。"];
        RCTweakRecord *t = unresolvedTweaks[indexPath.row];
        NSMutableArray<NSString *> *unresolvedBundles = [NSMutableArray array];
        for (NSString *bundleIdentifier in t.uninstalledTargetBundleIdentifiers) {
            if (![self systemTargetDescriptionForBundleIdentifier:bundleIdentifier].length) [unresolvedBundles addObject:bundleIdentifier];
        }
        NSMutableArray<NSString *> *parts = [NSMutableArray array];
        if (t.unresolvedTargetExecutableIdentifiers.count) [parts addObject:[NSString stringWithFormat:@"Filter.Executables 未解析目标：\n%@", [t.unresolvedTargetExecutableIdentifiers componentsJoinedByString:@"\n"]]];
        if (unresolvedBundles.count) [parts addObject:[NSString stringWithFormat:@"Filter.Bundles 未解析目标：\n%@", [unresolvedBundles componentsJoinedByString:@"\n"]]];
        [parts addObject:@"未解析不代表系统注入，也不代表 App 已卸载。此项仅在确有未解析目标时显示。"];
        return [self cell:[NSString stringWithFormat:@"ℹ %@", t.displayName] detail:[parts componentsJoinedByString:@"\n\n"]];
    }

    return [self cell:@"环境检查项不可用" detail:@"未知 section；未执行任何修改操作。"];
}
@end
