#import "RCPath.h"
#import <dlfcn.h>

typedef NSString *(*RCJBRootFunction)(NSString *);

static RCJBRootFunction RCResolveJBRoot(void) {
    static RCJBRootFunction fn = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // RootHide exports C++: NSString *jbroot(NSString *)
        fn = (RCJBRootFunction)dlsym(RTLD_DEFAULT, "_Z6jbrootP8NSString");
    });
    return fn;
}

BOOL RCJBRootAvailable(void) {
    return RCResolveJBRoot() != NULL;
}

NSString *RCJBRootImagePath(void) {
    RCJBRootFunction fn = RCResolveJBRoot();
    if (!fn) return @"";
    Dl_info info = { NULL, NULL, NULL, NULL };
    if (dladdr((const void *)fn, &info) && info.dli_fname) {
        NSString *path = [NSString stringWithUTF8String:info.dli_fname];
        return path ?: @"";
    }
    return @"";
}

NSString *RCRootPath(NSString *logicalPath) {
    RCJBRootFunction fn = RCResolveJBRoot();
    if (fn) {
        NSString *mapped = fn(logicalPath);
        if (mapped.length) return mapped;
    }
    return logicalPath;
}

NSString *RCLogicalPackagePath(NSString *path) {
    if (!path.length) return @"";
    NSString *p = [path stringByStandardizingPath];
    NSArray<NSString *> *anchors = @[@"/usr/", @"/Library/", @"/Applications/", @"/var/"];
    NSRange best = NSMakeRange(NSNotFound, 0);
    for (NSString *anchor in anchors) {
        NSRange r = [p rangeOfString:anchor options:NSBackwardsSearch];
        if (r.location != NSNotFound && (best.location == NSNotFound || r.location > best.location)) {
            best = r;
        }
    }
    if (best.location != NSNotFound) return [p substringFromIndex:best.location];
    if (![p hasPrefix:@"/"]) p = [@"/" stringByAppendingString:p];
    return p;
}
