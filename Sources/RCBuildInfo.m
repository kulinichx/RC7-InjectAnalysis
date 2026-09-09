#import "RCBuildInfo.h"
#import "RCVersion.generated.h"
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <libkern/OSByteOrder.h>
#import <string.h>
#import <sys/stat.h>

static NSString * const kRCAnalysisVersion = RC_ANALYSIS_VERSION;
static NSString * const kRCExpectedInstallName = @"@executable_path/Frameworks/RCInjectAnalysis.dylib";
static NSString * const kRCBuildManifestName = @"RCInjectAnalysis.buildinfo.plist";

NSString *RCAnalysisVersion(void) { return kRCAnalysisVersion; }
NSString *RCAnalysisExpectedInstallName(void) { return kRCExpectedInstallName; }

NSString *RCAnalysisRuntimeArchitecture(void) {
#if defined(__arm64e__)
    return @"arm64e";
#elif defined(__aarch64__) || defined(__arm64__)
    return @"arm64";
#else
    return @"unknown";
#endif
}

static const struct mach_header_64 *RCAnalysisImageHeader(void) {
    Dl_info info = {0};
    if (dladdr((const void *)&RCAnalysisVersion, &info) == 0 || info.dli_fbase == NULL) return NULL;
    const struct mach_header_64 *h = (const struct mach_header_64 *)info.dli_fbase;
    if (h->magic != MH_MAGIC_64) return NULL;
    return h;
}

NSString *RCAnalysisLoadedImagePath(void) {
    Dl_info info = {0};
    if (dladdr((const void *)&RCAnalysisVersion, &info) == 0 || info.dli_fname == NULL) return @"";
    return [NSString stringWithUTF8String:info.dli_fname] ?: @"";
}

BOOL RCAnalysisLoadedImagePathLooksExpected(void) {
    NSString *path = RCAnalysisLoadedImagePath();
    return path.length > 0 && [path hasSuffix:@"/Frameworks/RCInjectAnalysis.dylib"];
}

static BOOL RCHeaderHasExpectedWeakLoad(const struct mach_header_64 *h, NSString **detailOut) {
    if (!h || h->magic != MH_MAGIC_64) {
        if (detailOut) *detailOut = @"main image header unavailable or not MH_MAGIC_64";
        return NO;
    }
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    const uint8_t *limit = cursor + h->sizeofcmds;
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > limit) break;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(struct load_command) || cursor + lc->cmdsize > limit) break;
        if (lc->cmd == LC_LOAD_WEAK_DYLIB && lc->cmdsize >= sizeof(struct dylib_command)) {
            const struct dylib_command *dc = (const struct dylib_command *)cursor;
            uint32_t off = dc->dylib.name.offset;
            if (off < lc->cmdsize) {
                const char *name = (const char *)(cursor + off);
                size_t maxLen = lc->cmdsize - off;
                size_t len = strnlen(name, maxLen);
                if (len < maxLen) {
                    NSString *value = [[NSString alloc] initWithBytes:name length:len encoding:NSUTF8StringEncoding] ?: @"";
                    if ([value isEqualToString:RCAnalysisExpectedInstallName()]) {
                        if (detailOut) *detailOut = [NSString stringWithFormat:@"LC_LOAD_WEAK_DYLIB %@", value];
                        return YES;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
    if (detailOut) *detailOut = [NSString stringWithFormat:@"expected weak load not present: %@", RCAnalysisExpectedInstallName()];
    return NO;
}

static BOOL RCDiskSliceHasExpectedWeakLoad(const uint8_t *bytes, NSUInteger length, NSString **detailOut) {
    if (!bytes || length < sizeof(struct mach_header_64)) {
        if (detailOut) *detailOut = @"disk RootHide slice is too small";
        return NO;
    }
    const struct mach_header_64 *h = (const struct mach_header_64 *)bytes;
    if (h->magic != MH_MAGIC_64) {
        if (detailOut) *detailOut = @"disk RootHide slice is not MH_MAGIC_64";
        return NO;
    }
    uint64_t commandEnd = (uint64_t)sizeof(struct mach_header_64) + (uint64_t)h->sizeofcmds;
    if (commandEnd > length) {
        if (detailOut) *detailOut = @"disk RootHide load-command region exceeds slice";
        return NO;
    }
    return RCHeaderHasExpectedWeakLoad(h, detailOut);
}

static uint32_t RCFat32(uint32_t value, BOOL swapped) { return swapped ? OSSwapInt32(value) : value; }
static uint64_t RCFat64(uint64_t value, BOOL swapped) { return swapped ? OSSwapInt64(value) : value; }

static BOOL RCDiskHostHasExpectedWeakLoad(BOOL *availableOut, NSString **detailOut) {
    if (availableOut) *availableOut = NO;
    NSString *path = NSBundle.mainBundle.executablePath ?: @"";
    NSData *data = path.length ? [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil] : nil;
    if (data.length < sizeof(uint32_t)) {
        if (detailOut) *detailOut = @"disk RootHide executable unavailable";
        return NO;
    }

    const uint8_t *bytes = data.bytes;
    uint32_t magic = 0;
    memcpy(&magic, bytes, sizeof(magic));
    if (magic == MH_MAGIC_64) {
        if (availableOut) *availableOut = YES;
        return RCDiskSliceHasExpectedWeakLoad(bytes, data.length, detailOut);
    }

    BOOL fat64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    BOOL fat32 = magic == FAT_MAGIC || magic == FAT_CIGAM;
    if (!fat64 && !fat32) {
        if (detailOut) *detailOut = @"disk RootHide executable is not a supported thin/FAT Mach-O";
        return NO;
    }

    BOOL swapped = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    if (data.length < sizeof(struct fat_header)) {
        if (detailOut) *detailOut = @"disk RootHide FAT header truncated";
        return NO;
    }
    const struct fat_header *fatHeader = (const struct fat_header *)bytes;
    uint32_t count = RCFat32(fatHeader->nfat_arch, swapped);
    const struct mach_header *runtime = _dyld_get_image_header(0);
    cpu_type_t wantedCPU = runtime ? runtime->cputype : CPU_TYPE_ARM64;
    cpu_subtype_t wantedSubtype = runtime ? (runtime->cpusubtype & ~CPU_SUBTYPE_MASK) : CPU_SUBTYPE_ARM64_ALL;

    NSUInteger cursor = sizeof(struct fat_header);
    for (uint32_t index = 0; index < count; index++) {
        cpu_type_t cpu = 0;
        cpu_subtype_t subtype = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
        if (fat64) {
            if (cursor > data.length || sizeof(struct fat_arch_64) > data.length - cursor) break;
            const struct fat_arch_64 *arch = (const struct fat_arch_64 *)(bytes + cursor);
            cpu = (cpu_type_t)RCFat32((uint32_t)arch->cputype, swapped);
            subtype = (cpu_subtype_t)RCFat32((uint32_t)arch->cpusubtype, swapped);
            offset = RCFat64(arch->offset, swapped);
            size = RCFat64(arch->size, swapped);
            cursor += sizeof(struct fat_arch_64);
        } else {
            if (cursor > data.length || sizeof(struct fat_arch) > data.length - cursor) break;
            const struct fat_arch *arch = (const struct fat_arch *)(bytes + cursor);
            cpu = (cpu_type_t)RCFat32((uint32_t)arch->cputype, swapped);
            subtype = (cpu_subtype_t)RCFat32((uint32_t)arch->cpusubtype, swapped);
            offset = RCFat32(arch->offset, swapped);
            size = RCFat32(arch->size, swapped);
            cursor += sizeof(struct fat_arch);
        }
        if (cpu != wantedCPU || offset > data.length || size > data.length - (NSUInteger)offset) continue;
        cpu_subtype_t baseSubtype = subtype & ~CPU_SUBTYPE_MASK;
        if (baseSubtype != wantedSubtype) continue;
        if (availableOut) *availableOut = YES;
        return RCDiskSliceHasExpectedWeakLoad(bytes + (NSUInteger)offset, (NSUInteger)size, detailOut);
    }

    if (detailOut) *detailOut = @"disk RootHide current-architecture slice unavailable";
    return NO;
}

BOOL RCAnalysisHostHasExpectedWeakLoad(void) {
    BOOL diskAvailable = NO;
    BOOL diskMatch = RCDiskHostHasExpectedWeakLoad(&diskAvailable, NULL);
    if (diskAvailable) return diskMatch;

    const struct mach_header *raw = _dyld_get_image_header(0);
    if (!raw || raw->magic != MH_MAGIC_64) return NO;
    return RCHeaderHasExpectedWeakLoad((const struct mach_header_64 *)raw, NULL);
}

NSString *RCAnalysisHostWeakLoadDetail(void) {
    BOOL diskAvailable = NO;
    NSString *detail = nil;
    BOOL diskMatch = RCDiskHostHasExpectedWeakLoad(&diskAvailable, &detail);
    if (diskAvailable) {
        return [NSString stringWithFormat:@"disk RootHide host: %@", detail ?: (diskMatch ? @"PASS" : @"WARN")];
    }

    const struct mach_header *raw = _dyld_get_image_header(0);
    if (!raw || raw->magic != MH_MAGIC_64) return detail.length ? detail : @"RootHide host image unavailable";
    NSString *runtimeDetail = nil;
    BOOL runtimeMatch = RCHeaderHasExpectedWeakLoad((const struct mach_header_64 *)raw, &runtimeDetail);
    return [NSString stringWithFormat:@"runtime fallback %@: %@", runtimeMatch ? @"PASS" : @"WARN", runtimeDetail ?: @"unknown"];
}

NSString *RCAnalysisLoadedImageUUID(void) {
    const struct mach_header_64 *h = RCAnalysisImageHeader();
    if (!h) return @"";
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    const uint8_t *limit = cursor + h->sizeofcmds;
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > limit) return @"";
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(struct load_command) || cursor + lc->cmdsize > limit) return @"";
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *u = (const struct uuid_command *)cursor;
            const uint8_t *b = u->uuid;
            return [NSString stringWithFormat:
                    @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]];
        }
        cursor += lc->cmdsize;
    }
    return @"";
}

NSString *RCAnalysisBuildManifestPath(void) {
    NSString *frameworks = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"Frameworks"];
    return [frameworks stringByAppendingPathComponent:kRCBuildManifestName];
}

NSDictionary<NSString *, id> *RCAnalysisBuildManifest(void) {
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:RCAnalysisBuildManifestPath()];
    return [manifest isKindOfClass:NSDictionary.class] ? manifest : @{};
}


static NSDictionary<NSString *, id> *RCFileStateForPath(NSString *path, BOOL hostExecutable) {
    if (![path isKindOfClass:NSString.class] || path.length == 0) {
        return @{ @"Path": path ?: @"", @"Exists": @(NO), @"Expected": @(NO), @"Reason": @"empty-path" };
    }
    struct stat st = {0};
    if (stat(path.fileSystemRepresentation, &st) != 0) {
        return @{ @"Path": path, @"Exists": @(NO), @"Expected": @(NO), @"Reason": @"stat-failed" };
    }
    mode_t mode = st.st_mode & 07777;
    BOOL executable = (mode & 0111) != 0;
    BOOL expected = NO;
    NSString *reason = @"";
    if (hostExecutable) {
        // The RootHide blacklist Manager's unchanged official postinst performs chown 0:0 and chmod +s.
        expected = S_ISREG(st.st_mode) && st.st_uid == 0 && st.st_gid == 0 && executable && ((mode & S_ISUID) != 0);
        if (!expected) reason = [NSString stringWithFormat:@"expected uid=0 gid=0 regular executable with setuid; got uid=%u gid=%u mode=%04o", (unsigned)st.st_uid, (unsigned)st.st_gid, (unsigned)mode];
    } else {
        expected = S_ISREG(st.st_mode) && executable;
        if (!expected) reason = [NSString stringWithFormat:@"expected regular executable dylib; mode=%04o", (unsigned)mode];
    }
    return @{
        @"Path": path,
        @"Exists": @(YES),
        @"UID": @((unsigned)st.st_uid),
        @"GID": @((unsigned)st.st_gid),
        @"Mode": [NSString stringWithFormat:@"%04o", (unsigned)mode],
        @"SetUID": @((mode & S_ISUID) != 0),
        @"Executable": @(executable),
        @"Expected": @(expected),
        @"Reason": reason,
    };
}

NSDictionary<NSString *, id> *RCAnalysisHostExecutableFileState(void) {
    NSString *path = NSBundle.mainBundle.executablePath ?: @"";
    return RCFileStateForPath(path, YES);
}

NSDictionary<NSString *, id> *RCAnalysisLoadedDylibFileState(void) {
    return RCFileStateForPath(RCAnalysisLoadedImagePath(), NO);
}
