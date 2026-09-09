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

- (NSArray<RCTweakRecord *> *)dpkgTweaks {
    NSMutableArray<RCTweakRecord *> *out = [NSMutableArray array];
    for (RCTweakRecord *tweak in self.record.matchedTweaks) {
        if (tweak.installSource == RCTweakInstallSourceDPKG && tweak.package) [out addObject:tweak];
    }
    return out;
}

- (NSArray<NSDictionary<NSString *, id> *> *)trollFoolsGroups {
    NSMutableDictionary<NSString *, NSMutableArray<RCEmbeddedInjectionRecord *> *> *groups = [NSMutableDictionary dictionary];
    for (RCEmbeddedInjectionRecord *record in self.record.embeddedInjections) {
        NSString *key = record.loadPath.length
            ? [@"load:" stringByAppendingString:record.loadPath]
            : [NSString stringWithFormat:@"evidence:%@:%@", record.targetMachOPath ?: @"", record.backupPath ?: @""];
        NSMutableArray<RCEmbeddedInjectionRecord *> *records = groups[key];
        if (!records) {
            records = [NSMutableArray array];
            groups[key] = records;
        }
        [records addObject:record];
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *out = [NSMutableArray array];
    for (NSString *key in groups) {
        NSArray<RCEmbeddedInjectionRecord *> *records = groups[key];
        RCEmbeddedInjectionRecord *first = records.firstObject;
        NSString *name = first.loadPath.lastPathComponent;
        if (!name.length) name = @"TrollFools 注入";
        BOOL active = NO;
        NSMutableSet<NSString *> *machOPaths = [NSMutableSet set];
        for (RCEmbeddedInjectionRecord *record in records) {
            if (record.activeDifferenceConfirmed) active = YES;
            if (record.targetMachOPath.length) [machOPaths addObject:record.targetMachOPath];
        }
        [out addObject:@{@"name": name,
                         @"active": @(active),
                         @"machOCount": @(machOPaths.count)}];
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSString *nameA = a[@"name"];
        NSString *nameB = b[@"name"];
        return [nameA localizedCaseInsensitiveCompare:nameB];
    }];
    return out;
}

- (BOOL)hasDPKG { return self.dpkgTweaks.count > 0; }
- (BOOL)hasTrollFools { return self.record.embeddedInjections.count > 0; }
- (NSInteger)dpkgSection { return self.hasDPKG ? 0 : NSNotFound; }
- (NSInteger)trollFoolsSection { return self.hasTrollFools ? (self.hasDPKG ? 1 : 0) : NSNotFound; }
- (NSInteger)appStatusSection { return (self.hasDPKG ? 1 : 0) + (self.hasTrollFools ? 1 : 0); }

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return self.appStatusSection + 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == self.dpkgSection) return self.dpkgTweaks.count;
    if (section == self.trollFoolsSection) return self.trollFoolsGroups.count;
    return 4;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == self.dpkgSection) return @"DEB（包管理器）";
    if (section == self.trollFoolsSection) return @"TrollFools";
    return @"App 状态";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == self.dpkgSection && self.dpkgTweaks.count >= 2) {
        return [NSString stringWithFormat:@"⚠ %lu 个 DEB 插件同时作用于此 App；可能增加兼容性风险，但不代表已确认冲突。", (unsigned long)self.dpkgTweaks.count];
    }
    return nil;
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

- (NSString *)rootHideStateText {
    if (!self.record.blacklistSupported) return @"RootHide Blacklist：当前环境不支持";
    if (!self.record.blacklistStateKnown) return @"RootHide Blacklist：状态未知";
    return self.record.blacklisted ? @"RootHide：已加入 Blacklist" : @"RootHide：允许";
}

- (UITableViewCell *)appStatusCellForRow:(NSInteger)row {
    if (row == 0) {
        return [self cellWithTitle:self.record.launchServicesRegistered ? @"LaunchServices：已注册" : @"LaunchServices：未确认注册"
                           detail:self.record.bundleIdentifier ?: @""];
    }
    if (row == 1) {
        return [self cellWithTitle:self.record.bundlePath.length ? @"Bundle Path：存在" : @"Bundle Path：不可用"
                           detail:self.record.bundlePath ?: @""];
    }
    if (row == 2) {
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

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == self.dpkgSection) {
        RCTweakRecord *tweak = self.dpkgTweaks[indexPath.row];
        NSString *detail = [NSString stringWithFormat:@"Package：%@\nVersion：%@\n%@",
                            tweak.package.packageIdentifier ?: @"未识别",
                            tweak.package.version ?: @"",
                            [self rootHideStateText]];
        return [self cellWithTitle:tweak.displayName detail:detail];
    }

    if (indexPath.section == self.trollFoolsSection) {
        NSDictionary<NSString *, id> *group = self.trollFoolsGroups[indexPath.row];
        BOOL active = [group[@"active"] boolValue];
        NSUInteger machOCount = [group[@"machOCount"] unsignedIntegerValue];
        NSString *detail = active
            ? [NSString stringWithFormat:@"活动注入已确认 · 作用于 %lu 个 Mach-O", (unsigned long)machOCount]
            : [NSString stringWithFormat:@"发现 TrollFools 来源证据 · 活动状态未确认 · %lu 个 Mach-O", (unsigned long)machOCount];
        return [self cellWithTitle:group[@"name"] detail:detail];
    }

    return [self appStatusCellForRow:indexPath.row];
}
@end
