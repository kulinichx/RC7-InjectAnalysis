#import "RCAppDetailViewController.h"
#import "RCModels.h"
#import "RCDiagnostics.h"

@interface RCAppDetailViewController ()
@property (nonatomic, strong) RCAppRecord *record;
@property (nonatomic, strong) RCAnalysisSnapshot *snapshot;
@end

@implementation RCAppDetailViewController
- (instancetype)initWithAppRecord:(RCAppRecord *)record snapshot:(RCAnalysisSnapshot *)snapshot {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) { _record = record; _snapshot = snapshot; }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = self.record.name.length ? self.record.name : self.record.bundleIdentifier;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"报告" style:UIBarButtonItemStylePlain target:self action:@selector(shareReport)];
}

- (void)shareReport {
    NSString *report = [RCDiagnostics readOnlyReportForApp:self.record snapshot:self.snapshot];
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:@[report] applicationActivities:nil];
    vc.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItem;
    [self presentViewController:vc animated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return self.record.embeddedInjections.count ? 4 : 3; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return MAX((NSUInteger)1, self.record.matchedTweaks.count);
    if (section == 1) return 2;
    if (section == 2) return 4;
    return 1;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"RootHide Bundles Filter 匹配";
    if (section == 1) return @"注入 / Blacklist 状态";
    if (section == 2) return @"App 注册状态";
    return @"其它注入";
}

- (UITableViewCell *)cellWithTitle:(NSString *)title detail:(NSString *)detail {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.numberOfLines = 0;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) {
        if (!self.snapshot.tweakScanAvailable) return [self cellWithTitle:@"RootHide tweak 扫描不可用" detail:@"TweakInject 数据源未通过 preflight；不把空结果解释为未发现。"];
        if (!self.record.matchedTweaks.count) return [self cellWithTitle:@"未发现 Bundle ID Filter 匹配" detail:@"扫描已执行；当前没有 RootHide tweak 的 Filter.Bundles 包含此 Bundle ID。"];
        RCTweakRecord *t = self.record.matchedTweaks[indexPath.row];
        NSString *detail = [NSString stringWithFormat:@"Package：%@\nVersion：%@\n匹配 Filter：%@",
                            t.package.packageIdentifier ?: @"未识别",
                            t.package.version ?: @"",
                            self.record.bundleIdentifier ?: @""];
        if (self.record.matchedTweaks.count >= 2) {
            detail = [detail stringByAppendingFormat:@"\n\n⚠ %lu 个 RootHide 插件同时匹配\n可能增加兼容性风险；不代表已确认冲突。",
                      (unsigned long)self.record.matchedTweaks.count];
        }
        return [self cellWithTitle:t.displayName detail:detail];
    }

    if (indexPath.section == 1) {
        if (indexPath.row == 0) {
            NSString *title = !self.record.blacklistStateKnown
                ? (self.record.blacklistSupported ? @"RootHide Blacklist：状态未知" : @"RootHide Blacklist：当前环境不支持")
                : (self.record.blacklisted ? @"RootHide Blacklist：已加入" : @"RootHide Blacklist：未加入");
            return [self cellWithTitle:title detail:self.record.blacklistEvidence ?: @""];
        }
        NSString *state = !self.record.blacklistStateKnown ? @"未知" : (self.record.blacklisted ? @"阻止" : @"允许");
        return [self cellWithTitle:[NSString stringWithFormat:@"注入配置：%@", state]
                           detail:@"这是 RootHide 配置层状态，不等同于运行时 dylib 已加载证明。"];
    }

    if (indexPath.section == 2) {
        if (indexPath.row == 0) {
            return [self cellWithTitle:self.record.launchServicesRegistered ? @"LaunchServices：已注册" : @"LaunchServices：未确认注册"
                               detail:self.record.bundleIdentifier ?: @""];
        }
        if (indexPath.row == 1) {
            return [self cellWithTitle:self.record.bundlePath.length ? @"Bundle Path：存在" : @"Bundle Path：不可用"
                               detail:self.record.bundlePath ?: @""];
        }
        if (indexPath.row == 2) {
            return [self cellWithTitle:self.record.bundlePathExists ? @"实际 .app：存在" : @"实际 .app：不存在 / 未确认"
                               detail:self.record.bundlePath ?: @"Bundle Path 不可用"];
        }
        BOOL blacklistResidue = NO;
        for (RCBlacklistResidueRecord *residue in self.snapshot.blacklistResidues) {
            if ([residue.bundleIdentifier isEqualToString:self.record.bundleIdentifier]) {
                blacklistResidue = YES;
                break;
            }
        }
        if (self.record.highConfidenceOrphanRegistration) {
            return [self cellWithTitle:@"⚠ 高置信度孤立 App 注册"
                                detail:@"LaunchServices 仍注册，但对应标准 .app 路径不存在。"];
        }
        if (!self.snapshot.launchServicesAvailable) {
            return [self cellWithTitle:@"孤立注册：数据源不完整，未判定"
                                detail:@"LaunchServices 不可用；不能作‘未发现孤立注册’结论。"];
        }
        if (blacklistResidue) {
            return [self cellWithTitle:@"⚠ Blacklist 名单残留"
                                detail:@"当前 snapshot 中存在与此 Bundle ID 对应的无效 blacklist 记录。"];
        }
        NSString *residueState = self.snapshot.blacklistStateAvailable
            ? @"✓ 未发现名单残留"
            : @"名单残留：数据源不完整，未判定";
        return [self cellWithTitle:@"✓ 未发现孤立注册" detail:residueState];
    }

    NSMutableSet<NSString *> *machOPaths = [NSMutableSet set];
    NSMutableSet<NSString *> *loadPaths = [NSMutableSet set];
    NSUInteger active = 0;
    for (RCEmbeddedInjectionRecord *r in self.record.embeddedInjections) {
        if (r.targetMachOPath.length) [machOPaths addObject:r.targetMachOPath];
        if (r.loadPath.length) [loadPaths addObject:r.loadPath];
        if (r.activeDifferenceConfirmed) active++;
    }
    NSString *title = active ? @"✓ TrollFools / 巨魔注入：已发现活动注入" : @"TrollFools / 巨魔注入：发现来源证据";
    NSString *detail = [NSString stringWithFormat:@"活动差分：%lu\nMach-O：%lu\n不同 Load：%lu",
                        (unsigned long)active,
                        (unsigned long)machOPaths.count,
                        (unsigned long)loadPaths.count];
    return [self cellWithTitle:title detail:detail];
}

@end
