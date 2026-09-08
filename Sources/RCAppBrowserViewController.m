#import "RCAppBrowserViewController.h"
#import "RCAppDetailViewController.h"
#import "RCModels.h"

@interface RCAppBrowserViewController ()
@property (nonatomic, strong) RCAnalysisSnapshot *snapshot;
@property (nonatomic, copy) NSArray<RCAppRecord *> *allApps;
@property (nonatomic, copy) NSArray<RCAppRecord *> *filteredApps;
@property (nonatomic, strong) UISearchController *searchController;
@end

@implementation RCAppBrowserViewController
- (instancetype)initWithSnapshot:(RCAnalysisSnapshot *)snapshot {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _snapshot = snapshot;
        _allApps = [snapshot.apps sortedArrayUsingComparator:^NSComparisonResult(RCAppRecord *a, RCAppRecord *b) {
            NSString *an = a.name.length ? a.name : a.bundleIdentifier;
            NSString *bn = b.name.length ? b.name : b.bundleIdentifier;
            NSComparisonResult r = [an localizedCaseInsensitiveCompare:bn];
            if (r == NSOrderedSame) return [a.bundleIdentifier localizedCaseInsensitiveCompare:b.bundleIdentifier];
            return r;
        }];
        _filteredApps = _allApps;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"全部应用";
    self.searchController = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searchController.searchResultsUpdater = self;
    self.searchController.obscuresBackgroundDuringPresentation = NO;
    self.searchController.searchBar.placeholder = @"名称或 Bundle ID";
    self.navigationItem.searchController = self.searchController;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;
}

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    NSString *q = [searchController.searchBar.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!q.length) {
        self.filteredApps = self.allApps;
    } else {
        NSString *needle = q.lowercaseString;
        NSPredicate *p = [NSPredicate predicateWithBlock:^BOOL(RCAppRecord *app, NSDictionary *bindings) {
            (void)bindings;
            return [app.name.lowercaseString containsString:needle] || [app.bundleIdentifier.lowercaseString containsString:needle];
        }];
        self.filteredApps = [self.allApps filteredArrayUsingPredicate:p];
    }
    [self.tableView reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 1; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (!self.snapshot.launchServicesAvailable) return 1;
    return MAX((NSUInteger)1, self.filteredApps.count);
}
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (!self.snapshot.launchServicesAvailable) return @"App 深度分析不可用";
    return [NSString stringWithFormat:@"已注册应用 · %lu", (unsigned long)self.filteredApps.count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.detailTextLabel.numberOfLines = 0;
    if (!self.snapshot.launchServicesAvailable) {
        cell.textLabel.text = @"LaunchServices 不可用";
        cell.detailTextLabel.text = @"无法建立完整 App 列表；空结果不能解释为设备没有应用";
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    if (!self.filteredApps.count) {
        cell.textLabel.text = @"没有匹配的应用";
        cell.detailTextLabel.text = @"请尝试应用名称或 Bundle ID";
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    RCAppRecord *app = self.filteredApps[indexPath.row];
    cell.textLabel.text = app.name.length ? app.name : app.bundleIdentifier;
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    [parts addObject:app.bundleIdentifier ?: @""];
    if (app.matchedTweaks.count) [parts addObject:[NSString stringWithFormat:@"RootHide Filter %lu", (unsigned long)app.matchedTweaks.count]];
    NSUInteger activeEmbedded = 0;
    for (RCEmbeddedInjectionRecord *r in app.embeddedInjections) if (r.activeDifferenceConfirmed) activeEmbedded++;
    if (activeEmbedded) [parts addObject:[NSString stringWithFormat:@"TrollFools active %lu", (unsigned long)activeEmbedded]];
    if (app.embeddedScanTruncated || app.embeddedSkippedByGlobalBudget) [parts addObject:[NSString stringWithFormat:@"Embedded 部分(%@)", app.embeddedScanStopReason.length ? app.embeddedScanStopReason : @"budget"]];
    if (app.highConfidenceOrphanRegistration) [parts addObject:@"⚠ 孤立注册"];
    if (app.blacklistStateKnown && app.blacklisted) [parts addObject:@"已 blacklist"];
    cell.detailTextLabel.text = [parts componentsJoinedByString:@" · "];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (!self.snapshot.launchServicesAvailable || !self.filteredApps.count) return;
    RCAppRecord *app = self.filteredApps[indexPath.row];
    RCAppDetailViewController *vc = [[RCAppDetailViewController alloc] initWithAppRecord:app snapshot:self.snapshot];
    [self.navigationController pushViewController:vc animated:YES];
}
@end
