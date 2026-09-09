#import "RCEnvironmentViewController.h"
#import "RCAnalysisManager.h"
#import "RCModels.h"
#import "RCDiagnostics.h"
#import "RCBuildInfo.h"

@interface RCEnvironmentViewController ()
@property (nonatomic, strong) RCAnalysisSnapshot *snapshot;
@property (nonatomic) BOOL scanning;
@end

@implementation RCEnvironmentViewController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }
- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"环境检查";
    UIBarButtonItem *rescan = [[UIBarButtonItem alloc] initWithTitle:@"重新扫描" style:UIBarButtonItemStylePlain target:self action:@selector(forceRefresh)];
    UIBarButtonItem *report = [[UIBarButtonItem alloc] initWithTitle:@"报告" style:UIBarButtonItemStylePlain target:self action:@selector(shareReport)];
    self.navigationItem.rightBarButtonItems = @[rescan, report];
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
        [weakSelf.tableView reloadData];
    }];
}
- (void)forceRefresh {
    if (self.scanning) return;
    self.scanning = YES;
    __weak typeof(self) weakSelf = self;
    [[RCAnalysisManager sharedManager] refreshWithCompletion:^(RCAnalysisSnapshot *snapshot) {
        weakSelf.scanning = NO;
        weakSelf.snapshot = snapshot;
        [weakSelf.tableView reloadData];
    }];
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return self.snapshot ? 7 : 1; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!self.snapshot) return 1;
    if (section == 0) return 9;
    if (section == 1) return MAX(1, self.snapshot.timeline.count);
    if (section == 2) return MAX(1, self.snapshot.diagnostics.count);
    if (section == 3) return MAX(1, self.snapshot.blacklistResidues.count);
    if (section == 4) return MAX(1, self.snapshot.orphanRegistrations.count);
    if (section == 5) return MAX(1, self.snapshot.suspiciousTweaks.count);
    return MAX(1, self.snapshot.uninstalledTargetTweaks.count);
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (!self.snapshot) return [NSString stringWithFormat:@"Analysis %@（只读）", RCAnalysisVersion()];
    if (section == 0) return @"Analysis / RootHide 运行环境";
    if (section == 1) return @"扫描时间线";
    if (section == 2) return @"启动自检";
    if (section == 3) return @"无效 Blacklist 记录";
    if (section == 4) return @"孤立 App 注册";
    if (section == 5) return @"Tweak / Filter 可疑项";
    return @"系统级 / 未解析 Filter 目标";
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
- (NSString *)systemTargetDescriptionForBundleIdentifier:(NSString *)bundleIdentifier {
    NSString *lower = bundleIdentifier.lowercaseString;
    if ([lower isEqualToString:@"com.apple.springboard"]) return @"SpringBoard 系统进程";
    if ([lower isEqualToString:@"com.apple.backboardd"]) return @"backboardd 系统进程";
    return nil;
}
- (UITableViewCell *)environmentCellForRow:(NSInteger)row {
    RCEnvironmentProfile *e = self.snapshot.environmentProfile;
    if (row == 0) {
        NSString *text = [NSString stringWithFormat:@"Analysis %@ · %@", e.analysisVersion.length ? e.analysisVersion : RCAnalysisVersion(), e.analysisArchitecture.length ? e.analysisArchitecture : @"?"];
        NSString *detail = [NSString stringWithFormat:@"UUID: %@\nImage: %@", e.analysisImageUUID.length ? e.analysisImageUUID : @"未知", e.analysisImagePath.length ? e.analysisImagePath : @"未知"];
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
        if (!self.snapshot.tweakScanAvailable || !self.snapshot.launchServicesAvailable) return [self cell:@"Filter 目标分析不可用" detail:@"需要同时取得 Tweak Filter 与 LaunchServices App 列表；缺任一数据源时不作结论"];
        if (!self.snapshot.uninstalledTargetTweaks.count) return [self cell:@"未发现系统级或未解析 Filter 目标" detail:@"没有在 LaunchServices App 列表命中，不等于 App 已卸载。"];
        RCTweakRecord *t = self.snapshot.uninstalledTargetTweaks[indexPath.row];
        NSMutableArray<NSString *> *systemTargets = [NSMutableArray array];
        NSMutableArray<NSString *> *unresolvedTargets = [NSMutableArray array];
        for (NSString *bundleIdentifier in t.uninstalledTargetBundleIdentifiers) {
            NSString *systemDescription = [self systemTargetDescriptionForBundleIdentifier:bundleIdentifier];
            if (systemDescription.length) {
                [systemTargets addObject:[NSString stringWithFormat:@"%@ → %@", bundleIdentifier, systemDescription]];
            } else {
                [unresolvedTargets addObject:bundleIdentifier];
            }
        }
        NSMutableArray<NSString *> *parts = [NSMutableArray array];
        if (systemTargets.count) [parts addObject:[NSString stringWithFormat:@"系统级目标：\n%@", [systemTargets componentsJoinedByString:@"\n"]]];
        if (unresolvedTargets.count) [parts addObject:[NSString stringWithFormat:@"未匹配到当前 LaunchServices App：\n%@\n不据此判断为‘已卸载 App’或垃圾项。", [unresolvedTargets componentsJoinedByString:@"\n"]]];
        if (t.installedTargetBundleIdentifiers.count) [parts addObject:[NSString stringWithFormat:@"同时匹配已注册 App：%lu 个", (unsigned long)t.installedTargetBundleIdentifiers.count]];
        return [self cell:[NSString stringWithFormat:@"ℹ %@", t.displayName] detail:[parts componentsJoinedByString:@"\n\n"]];
    }

    return [self cell:@"环境检查项不可用" detail:@"未知 section；未执行任何修改操作。"];
}
@end
