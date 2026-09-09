#import "RCTweakScanner.h"
#import "RCDpkgResolver.h"
#import "RCPath.h"

@implementation RCTweakScanner
- (NSArray<NSString *> *)stringValuesFromFilter:(NSDictionary *)filter keys:(NSArray<NSString *> *)keys {
    id value = nil;
    for (NSString *key in keys) {
        value = filter[key];
        if (value) break;
    }
    if ([value isKindOfClass:NSString.class]) return [value length] ? @[(NSString *)value] : @[];
    if (![value isKindOfClass:NSArray.class]) return @[];
    NSMutableOrderedSet<NSString *> *out = [NSMutableOrderedSet orderedSet];
    for (id obj in (NSArray *)value) {
        if ([obj isKindOfClass:NSString.class] && [obj length]) [out addObject:obj];
    }
    return out.array;
}

- (NSDictionary *)filterDictionaryFromPlist:(NSDictionary *)plist {
    id filter = plist[@"Filter"] ?: plist[@"filter"];
    return [filter isKindOfClass:NSDictionary.class] ? filter : @{};
}

- (NSArray<NSString *> *)bundleIDsFromPlist:(NSDictionary *)plist {
    return [self stringValuesFromFilter:[self filterDictionaryFromPlist:plist] keys:@[@"Bundles", @"bundles"]];
}

- (NSArray<NSString *> *)executablesFromPlist:(NSDictionary *)plist {
    return [self stringValuesFromFilter:[self filterDictionaryFromPlist:plist] keys:@[@"Executables", @"executables"]];
}

- (NSArray<RCTweakRecord *> *)scanWithPackageResolver:(RCDpkgResolver *)resolver {
    NSString *dir = RCRootPath(@"/usr/lib/TweakInject");
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil] ?: @[];
    NSMutableArray<RCTweakRecord *> *results = [NSMutableArray array];
    for (NSString *entry in entries) {
        if (![entry.pathExtension.lowercaseString isEqualToString:@"plist"]) continue;
        NSString *plistPath = [dir stringByAppendingPathComponent:entry];
        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (![plist isKindOfClass:NSDictionary.class]) continue;

        NSString *stem = entry.stringByDeletingPathExtension;
        NSString *dylibPath = [dir stringByAppendingPathComponent:[stem stringByAppendingPathExtension:@"dylib"]];
        BOOL dylibExists = [[NSFileManager defaultManager] fileExistsAtPath:dylibPath];

        RCDetectionConfidence packageConfidence = RCDetectionConfidenceLow;
        NSString *packageEvidence = nil;
        RCPackageRecord *package = [resolver packageOwningInstalledPath:plistPath confidence:&packageConfidence evidence:&packageEvidence];
        if (!package && dylibExists) {
            package = [resolver packageOwningInstalledPath:dylibPath confidence:&packageConfidence evidence:&packageEvidence];
        }

        NSMutableArray<NSString *> *issues = [NSMutableArray array];
        RCTweakIssueSeverity issueSeverity = RCTweakIssueSeverityNone;
        if (!dylibExists) {
            [issues addObject:@"plist 存在，但同名 dylib 不存在（非标准结构需人工确认）"];
            issueSeverity = RCTweakIssueSeveritySuspicious;
        }

        RCTweakRecord *r = [RCTweakRecord new];
        r.plistName = stem;
        r.plistPath = plistPath;
        r.dylibPath = dylibExists ? dylibPath : nil;
        r.bundleIdentifiers = [self bundleIDsFromPlist:plist];
        r.executableIdentifiers = [self executablesFromPlist:plist];
        r.installedTargetExecutableIdentifiers = @[];
        r.systemTargetExecutableIdentifiers = @[];
        r.unresolvedTargetExecutableIdentifiers = @[];
        r.installedTargetBundleIdentifiers = @[];
        r.uninstalledTargetBundleIdentifiers = @[];
        r.package = package;
        r.installSource = package ? RCTweakInstallSourceDPKG : RCTweakInstallSourceUnknown;
        r.sourceConfidence = package ? packageConfidence : RCDetectionConfidenceLow;
        r.installSourceEvidence = packageEvidence ?: @"未找到 DPKG 文件归属；可能是手工安装或非标准软件包结构";
        r.issues = issues;
        r.issueSeverity = issueSeverity;
        [results addObject:r];
    }
    [results sortUsingComparator:^NSComparisonResult(RCTweakRecord *a, RCTweakRecord *b) {
        return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
    }];
    return results;
}
@end
