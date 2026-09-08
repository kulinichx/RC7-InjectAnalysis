#import "RCDpkgResolver.h"
#import "RCPath.h"

@interface RCDpkgResolver ()
@property (nonatomic, strong) NSDictionary<NSString *, RCPackageRecord *> *packagesByIdentifier;
@property (nonatomic, strong) NSDictionary<NSString *, NSString *> *ownerByLogicalPath;
@property (nonatomic, strong) NSDictionary<NSString *, NSArray<NSString *> *> *ownersByBasename;
@end

@implementation RCDpkgResolver

- (instancetype)init {
    self = [super init];
    if (self) [self reload];
    return self;
}

- (NSDictionary<NSString *, NSString *> *)fieldsFromParagraph:(NSString *)paragraph {
    NSMutableDictionary *fields = [NSMutableDictionary dictionary];
    NSString *currentKey = nil;
    NSMutableString *currentValue = nil;
    for (NSString *line in [paragraph componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        if (!line.length) continue;
        if ([line hasPrefix:@" "] || [line hasPrefix:@"\t"]) {
            if (currentKey && currentValue) [currentValue appendFormat:@"\n%@", [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet]];
            continue;
        }
        if (currentKey && currentValue) fields[currentKey] = [currentValue copy];
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound) { currentKey = nil; currentValue = nil; continue; }
        currentKey = [line substringToIndex:colon.location];
        NSString *v = [[line substringFromIndex:colon.location + 1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        currentValue = [v mutableCopy];
    }
    if (currentKey && currentValue) fields[currentKey] = [currentValue copy];
    return fields;
}

- (void)reload {
    NSMutableDictionary<NSString *, RCPackageRecord *> *packages = [NSMutableDictionary dictionary];
    NSString *statusPath = RCRootPath(@"/Library/dpkg/status");
    NSString *statusText = [NSString stringWithContentsOfFile:statusPath encoding:NSUTF8StringEncoding error:nil];
    if (![statusText isKindOfClass:NSString.class]) statusText = @"";
    for (NSString *paragraph in [statusText componentsSeparatedByString:@"\n\n"]) {
        NSDictionary *f = [self fieldsFromParagraph:paragraph];
        NSString *pid = f[@"Package"];
        if (!pid.length) continue;
        RCPackageRecord *record = [RCPackageRecord new];
        record.packageIdentifier = pid;
        record.name = [f[@"Name"] length] ? f[@"Name"] : pid;
        record.version = f[@"Version"] ?: @"";
        record.status = f[@"Status"] ?: @"";
        packages[pid] = record;
    }

    NSMutableDictionary<NSString *, NSString *> *ownerByPath = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSMutableOrderedSet<NSString *> *> *basenameOwners = [NSMutableDictionary dictionary];
    NSString *infoPath = RCRootPath(@"/Library/dpkg/info");
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:infoPath error:nil] ?: @[];
    for (NSString *entry in entries) {
        if (![entry hasSuffix:@".list"]) continue;
        NSString *stem = [entry substringToIndex:entry.length - 5];
        NSString *packageID = stem;
        if (!packages[packageID]) {
            NSRange archSep = [stem rangeOfString:@":" options:NSBackwardsSearch];
            if (archSep.location != NSNotFound) {
                NSString *candidate = [stem substringToIndex:archSep.location];
                if (packages[candidate]) packageID = candidate;
            }
        }
        NSString *listPath = [infoPath stringByAppendingPathComponent:entry];
        NSString *list = [NSString stringWithContentsOfFile:listPath encoding:NSUTF8StringEncoding error:nil];
        if (!list.length) continue;
        for (NSString *line in [list componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
            NSString *trim = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            if (!trim.length) continue;
            NSString *logical = RCLogicalPackagePath(trim);
            if (logical.length) ownerByPath[logical] = packageID;
            NSString *base = logical.lastPathComponent;
            if (base.length) {
                NSMutableOrderedSet *set = basenameOwners[base];
                if (!set) basenameOwners[base] = set = [NSMutableOrderedSet orderedSet];
                [set addObject:packageID];
            }
        }
    }

    NSMutableDictionary *frozenBasenames = [NSMutableDictionary dictionary];
    [basenameOwners enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSMutableOrderedSet *obj, BOOL *stop) {
        (void)stop;
        frozenBasenames[key] = obj.array;
    }];
    self.packagesByIdentifier = packages;
    self.ownerByLogicalPath = ownerByPath;
    self.ownersByBasename = frozenBasenames;
}

- (BOOL)isInstalledPackage:(RCPackageRecord *)record {
    if (!record) return NO;
    if (!record.status.length) return YES;
    return [record.status containsString:@"install ok installed"];
}

- (RCPackageRecord *)packageOwningInstalledPath:(NSString *)path {
    return [self packageOwningInstalledPath:path confidence:NULL evidence:NULL];
}

- (RCPackageRecord *)packageOwningInstalledPath:(NSString *)path
                                      confidence:(RCDetectionConfidence *)confidence
                                        evidence:(NSString **)evidence {
    if (confidence) *confidence = RCDetectionConfidenceLow;
    if (evidence) *evidence = @"未找到 DPKG 文件归属";

    NSString *logical = RCLogicalPackagePath(path);
    NSString *pid = self.ownerByLogicalPath[logical];
    if (pid.length) {
        RCPackageRecord *record = self.packagesByIdentifier[pid];
        if (![self isInstalledPackage:record]) return nil;
        if (confidence) *confidence = RCDetectionConfidenceHigh;
        if (evidence) *evidence = [NSString stringWithFormat:@"DPKG .list 完整路径精确命中：%@", logical];
        return record;
    }

    // Basename-only fallback is intentionally weaker: it helps with RootHide path
    // translation edge cases, but cannot prove file ownership as strongly as a full path.
    NSString *base = logical.lastPathComponent;
    NSArray<NSString *> *candidates = base.length ? self.ownersByBasename[base] : nil;
    if (candidates.count == 1) {
        RCPackageRecord *record = self.packagesByIdentifier[candidates.firstObject];
        if (![self isInstalledPackage:record]) return nil;
        if (confidence) *confidence = RCDetectionConfidenceMedium;
        if (evidence) *evidence = [NSString stringWithFormat:@"仅文件名唯一命中 DPKG .list：%@（需人工确认路径映射）", base];
        return record;
    }

    if (candidates.count > 1 && evidence) {
        *evidence = [NSString stringWithFormat:@"文件名 %@ 同时出现在 %lu 个 DPKG 软件包中，无法唯一归属", base, (unsigned long)candidates.count];
    }
    return nil;
}
@end
