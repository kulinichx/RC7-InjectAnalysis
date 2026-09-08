#import "RCMachOScanner.h"
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#include <string.h>

static uint32_t RCSwap32(uint32_t x) { return __builtin_bswap32(x); }
static uint64_t RCSwap64(uint64_t x) { return __builtin_bswap64(x); }

@implementation RCMachOScanner

- (void)collectLoadsFromThinBytes:(const uint8_t *)bytes length:(NSUInteger)length into:(NSMutableSet<NSString *> *)out {
    if (length < sizeof(struct mach_header_64)) return;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
    if (mh->magic != MH_MAGIC_64) return;
    NSUInteger offset = sizeof(struct mach_header_64);
    if (offset + mh->sizeofcmds > length) return;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (offset + sizeof(struct load_command) > length) break;
        const struct load_command *lc = (const struct load_command *)(bytes + offset);
        if (lc->cmdsize < sizeof(struct load_command) || offset + lc->cmdsize > length) break;
        uint32_t cmd = lc->cmd;
        BOOL isDylib = (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_REEXPORT_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB || cmd == LC_LAZY_LOAD_DYLIB);
        if (isDylib && lc->cmdsize >= sizeof(struct dylib_command)) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            uint32_t nameOffset = dc->dylib.name.offset;
            if (nameOffset < lc->cmdsize) {
                const char *name = (const char *)lc + nameOffset;
                size_t maxLen = lc->cmdsize - nameOffset;
                size_t actual = strnlen(name, maxLen);
                if (actual > 0 && actual < maxLen) {
                    NSString *s = [[NSString alloc] initWithBytes:name length:actual encoding:NSUTF8StringEncoding];
                    if (s.length) [out addObject:s];
                }
            }
        }
        offset += lc->cmdsize;
    }
}

- (NSSet<NSString *> *)loadDylibPathsAtMachOPath:(NSString *)path {
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (data.length < 4) return [NSSet set];
    const uint8_t *bytes = data.bytes;
    uint32_t magic = *(const uint32_t *)bytes;
    NSMutableSet<NSString *> *out = [NSMutableSet set];

    if (magic == MH_MAGIC_64) {
        [self collectLoadsFromThinBytes:bytes length:data.length into:out];
        return out;
    }

    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        BOOL swap = (magic == FAT_CIGAM);
        if (data.length < sizeof(struct fat_header)) return out;
        const struct fat_header *fh = (const struct fat_header *)bytes;
        uint32_t nfat = swap ? RCSwap32(fh->nfat_arch) : fh->nfat_arch;
        NSUInteger table = sizeof(struct fat_header);
        for (uint32_t i = 0; i < nfat; i++) {
            if (table + sizeof(struct fat_arch) > data.length) break;
            const struct fat_arch *fa = (const struct fat_arch *)(bytes + table);
            uint32_t off = swap ? RCSwap32(fa->offset) : fa->offset;
            uint32_t size = swap ? RCSwap32(fa->size) : fa->size;
            if ((uint64_t)off + size <= data.length) [self collectLoadsFromThinBytes:bytes + off length:size into:out];
            table += sizeof(struct fat_arch);
        }
        return out;
    }

    if (magic == FAT_CIGAM_64 || magic == FAT_MAGIC_64) {
        BOOL swap = (magic == FAT_CIGAM_64);
        if (data.length < sizeof(struct fat_header)) return out;
        const struct fat_header *fh = (const struct fat_header *)bytes;
        uint32_t nfat = swap ? RCSwap32(fh->nfat_arch) : fh->nfat_arch;
        NSUInteger table = sizeof(struct fat_header);
        for (uint32_t i = 0; i < nfat; i++) {
            if (table + sizeof(struct fat_arch_64) > data.length) break;
            const struct fat_arch_64 *fa = (const struct fat_arch_64 *)(bytes + table);
            uint64_t off = swap ? RCSwap64(fa->offset) : fa->offset;
            uint64_t size = swap ? RCSwap64(fa->size) : fa->size;
            if (off + size <= data.length && off <= NSUIntegerMax && size <= NSUIntegerMax) [self collectLoadsFromThinBytes:bytes + (NSUInteger)off length:(NSUInteger)size into:out];
            table += sizeof(struct fat_arch_64);
        }
    }
    return out;
}

- (NSArray<RCEmbeddedInjectionRecord *> *)scanTrollFoolsEvidenceForApp:(RCAppRecord *)app {
    return [self scanTrollFoolsEvidenceForApp:app maxEntries:0].records;
}

- (RCEmbeddedScanResult *)scanTrollFoolsEvidenceForApp:(RCAppRecord *)app maxEntries:(NSUInteger)maxEntries {
    return [self scanTrollFoolsEvidenceForApp:app maxEntries:maxEntries deadline:0 timeoutReason:@"per-app-time"];
}

- (RCEmbeddedScanResult *)scanTrollFoolsEvidenceForApp:(RCAppRecord *)app
                                            maxEntries:(NSUInteger)maxEntries
                                              deadline:(NSTimeInterval)deadline
                                         timeoutReason:(NSString *)timeoutReason {
    NSTimeInterval started = [NSDate timeIntervalSinceReferenceDate];
    RCEmbeddedScanResult *result = [RCEmbeddedScanResult new];
    result.records = @[];
    result.entriesVisited = 0;
    result.truncated = NO;
    result.scanAttempted = NO;
    result.duration = 0;
    result.timeBudgetExceeded = NO;
    result.stopReason = @"none";
    result.status = @"未开始";

    if (!app.bundlePath.length) {
        result.status = @"Bundle Path 不可用；不能执行 App bundle / TrollFools 深度扫描";
        result.duration = [NSDate timeIntervalSinceReferenceDate] - started;
        return result;
    }
    if (!app.bundlePathExists) {
        result.status = @"实际 .app 路径不存在；不能执行 App bundle / TrollFools 深度扫描";
        result.duration = [NSDate timeIntervalSinceReferenceDate] - started;
        return result;
    }
    if ([app.bundlePath rangeOfString:@"/var/containers/Bundle/Application/"].location == NSNotFound) {
        result.status = @"不在 /var/containers/Bundle/Application；当前 TrollFools 规则不适用，不据此推断不存在其它内嵌注入";
        result.stopReason = @"not-applicable";
        result.duration = [NSDate timeIntervalSinceReferenceDate] - started;
        return result;
    }

    NSFileManager *fm = NSFileManager.defaultManager;
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:[NSURL fileURLWithPath:app.bundlePath]
                                includingPropertiesForKeys:nil
                                                   options:0
                                              errorHandler:^BOOL(NSURL *url, NSError *error) {
                                                  (void)url;
                                                  (void)error;
                                                  return YES;
                                              }];
    if (!enumerator) {
        result.status = @"无法创建 App bundle 枚举器；不作未发现结论";
        result.stopReason = @"enumerator-unavailable";
        result.duration = [NSDate timeIntervalSinceReferenceDate] - started;
        return result;
    }
    result.scanAttempted = YES;
    result.status = @"已执行";
    NSMutableArray<RCEmbeddedInjectionRecord *> *records = [NSMutableArray array];
    NSString *suffix = @".troll-fools.bak";
    for (NSURL *url in enumerator) {
        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
        if (deadline > 0 && now >= deadline) {
            result.truncated = YES;
            result.timeBudgetExceeded = YES;
            result.stopReason = timeoutReason.length ? timeoutReason : @"time-limit";
            break;
        }
        if (maxEntries > 0 && result.entriesVisited >= maxEntries) {
            result.truncated = YES;
            result.stopReason = @"entry-limit";
            break;
        }
        result.entriesVisited++;
        NSString *path = url.path;
        if (![path hasSuffix:suffix]) continue;
        NSString *target = [path substringToIndex:path.length - suffix.length];
        BOOL targetExists = [fm fileExistsAtPath:target];
        NSSet<NSString *> *before = [self loadDylibPathsAtMachOPath:path];
        NSSet<NSString *> *after = targetExists ? [self loadDylibPathsAtMachOPath:target] : [NSSet set];
        NSMutableSet<NSString *> *added = [after mutableCopy];
        [added minusSet:before];

        if (targetExists && added.count) {
            for (NSString *load in added) {
                RCEmbeddedInjectionRecord *r = [RCEmbeddedInjectionRecord new];
                r.appBundleIdentifier = app.bundleIdentifier;
                r.targetMachOPath = target;
                r.backupPath = path;
                r.loadPath = load;
                r.source = RCEmbeddedInjectionSourceTrollFools;
                r.confidence = RCDetectionConfidenceHigh;
                r.activeDifferenceConfirmed = YES;
                r.evidence = @"发现 .troll-fools.bak，且当前 Mach-O 相比注入前备份新增了动态库 Load Command";
                [records addObject:r];
            }
        } else {
            RCEmbeddedInjectionRecord *r = [RCEmbeddedInjectionRecord new];
            r.appBundleIdentifier = app.bundleIdentifier;
            r.targetMachOPath = target;
            r.backupPath = path;
            r.source = RCEmbeddedInjectionSourceTrollFools;
            r.confidence = RCDetectionConfidenceHigh;
            r.activeDifferenceConfirmed = NO;
            r.evidence = targetExists ? @"发现 TrollFools 注入前备份，但未检测到当前新增 Load Command；可能已恢复、停用或版本行为不同" : @"发现 TrollFools 注入前备份，但对应目标 Mach-O 已不存在";
            [records addObject:r];
        }
    }
    result.records = records;
    result.duration = [NSDate timeIntervalSinceReferenceDate] - started;
    if (result.timeBudgetExceeded) {
        result.status = [NSString stringWithFormat:@"已执行但触发 %@ 时间预算；遍历 %lu 项，结果可能不完整",
                         result.stopReason ?: @"time-limit", (unsigned long)result.entriesVisited];
    } else if (result.truncated) {
        result.status = [NSString stringWithFormat:@"已执行但达到每 App %lu 项安全上限；结果可能不完整",
                         (unsigned long)maxEntries];
    } else {
        result.status = [NSString stringWithFormat:@"已执行；遍历 %lu 项；耗时 %.3fs",
                         (unsigned long)result.entriesVisited, result.duration];
    }
    return result;
}

@end
