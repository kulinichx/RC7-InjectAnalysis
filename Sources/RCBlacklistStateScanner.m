#import "RCBlacklistStateScanner.h"
#import "RCPath.h"

@implementation RCBlacklistStateScanner

- (NSString *)configPath {
    return RCRootPath(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
}

- (NSDictionary *)configDictionaryWithExists:(BOOL *)existsOut {
    NSString *path = [self configPath];
    BOOL exists = path.length && [[NSFileManager defaultManager] fileExistsAtPath:path];
    if (existsOut) *existsOut = exists;
    if (!exists) return @{};
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path];
    return [d isKindOfClass:NSDictionary.class] ? d : nil;
}

- (void)applyBlacklistStateToApps:(NSArray<RCAppRecord *> *)apps {
    BOOL exists = NO;
    NSDictionary *defaults = [self configDictionaryWithExists:&exists];

    // RootHide's own UI treats a missing config as default false values. A file that
    // exists but cannot be decoded is different: report unknown instead of guessing.
    if (exists && ![defaults isKindOfClass:NSDictionary.class]) {
        for (RCAppRecord *app in apps) {
            app.blacklistStateKnown = NO;
            app.blacklistSupported = YES;
            app.blacklisted = NO;
            app.blacklistEvidence = @"RootHideConfig.plist 存在但无法解析；不推断 blacklist 状态";
        }
        return;
    }

    BOOL blacklistDisabled = [defaults[@"blacklistDisabled"] boolValue];
    NSDictionary *appconfig = [defaults[@"appconfig"] isKindOfClass:NSDictionary.class] ? defaults[@"appconfig"] : @{};
    for (RCAppRecord *app in apps) {
        if (blacklistDisabled) {
            app.blacklistStateKnown = NO;
            app.blacklistSupported = NO;
            app.blacklisted = NO;
            app.blacklistEvidence = @"RootHide 配置 blacklistDisabled=YES；Manager 本身不提供普通 blacklist 状态";
            continue;
        }
        id value = app.bundleIdentifier.length ? appconfig[app.bundleIdentifier] : nil;
        app.blacklistStateKnown = YES;
        app.blacklistSupported = YES;
        app.blacklisted = [value boolValue];
        if (value) {
            app.blacklistEvidence = [NSString stringWithFormat:@"RootHideConfig.plist appconfig[%@] = %@", app.bundleIdentifier, [value boolValue] ? @"YES" : @"NO"];
        } else if (!exists) {
            app.blacklistEvidence = @"RootHideConfig.plist 不存在；按 RootHide Manager 默认语义视为未加入 blacklist";
        } else {
            app.blacklistEvidence = @"appconfig 中无此 Bundle ID；按 RootHide Manager 默认语义视为未加入 blacklist";
        }
    }
}

- (NSArray<RCBlacklistResidueRecord *> *)scanResidualEntriesAgainstApps:(NSArray<RCAppRecord *> *)apps {
    BOOL exists = NO;
    NSDictionary *defaults = [self configDictionaryWithExists:&exists];
    if (!exists || ![defaults isKindOfClass:NSDictionary.class]) return @[];

    NSDictionary *appconfig = [defaults[@"appconfig"] isKindOfClass:NSDictionary.class] ? defaults[@"appconfig"] : nil;
    if (!appconfig.count) return @[];

    NSMutableSet<NSString *> *registered = [NSMutableSet set];
    for (RCAppRecord *app in apps) {
        if (app.bundleIdentifier.length) [registered addObject:app.bundleIdentifier];
    }

    BOOL blacklistDisabled = [defaults[@"blacklistDisabled"] boolValue];
    NSMutableArray<RCBlacklistResidueRecord *> *out = [NSMutableArray array];
    [appconfig enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
        (void)stop;
        if (![key isKindOfClass:NSString.class] || ![(NSString *)key length]) return;
        // Only a stored YES is treated as an actual blacklist entry. A NO value may
        // simply be an implementation/default artifact and is deliberately ignored.
        if (![value respondsToSelector:@selector(boolValue)] || ![value boolValue]) return;
        NSString *bundleID = (NSString *)key;
        if ([registered containsObject:bundleID]) return;

        RCBlacklistResidueRecord *r = [RCBlacklistResidueRecord new];
        r.bundleIdentifier = bundleID;
        r.storedBlacklistedValue = YES;
        r.blacklistGloballyDisabled = blacklistDisabled;
        r.confidence = RCDetectionConfidenceHigh;
        r.evidence = blacklistDisabled
            ? @"RootHideConfig.plist 中保存为 blacklist=YES，但 LaunchServices 当前无此 Bundle ID；当前 blacklistDisabled=YES，因此该记录暂不生效"
            : @"RootHideConfig.plist 中保存为 blacklist=YES，但 LaunchServices 当前无此 Bundle ID";
        [out addObject:r];
    }];

    [out sortUsingComparator:^NSComparisonResult(RCBlacklistResidueRecord *a, RCBlacklistResidueRecord *b) {
        return [a.bundleIdentifier localizedCaseInsensitiveCompare:b.bundleIdentifier];
    }];
    return out;
}
@end
