#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "RCAnalysisViewController.h"
#import "RCEnvironmentViewController.h"
#import "RCDiagnostics.h"
#import "RCBuildInfo.h"
#import "RCEntryStatus.h"

static IMP gOriginalReloadMenu = NULL;
static IMP gOriginalDidSelect = NULL;
static BOOL gInstalled = NO;
static NSUInteger gInstallAttempts = 0;

static id RCMsg0(id obj, const char *selName) {
    SEL sel = sel_registerName(selName);
    if (!obj || ![obj respondsToSelector:sel]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(obj, sel);
}
static void RCMsg1(id obj, const char *selName, id arg) {
    SEL sel = sel_registerName(selName);
    if (obj && [obj respondsToSelector:sel]) ((void (*)(id, SEL, id))objc_msgSend)(obj, sel, arg);
}

static BOOL RCIsAnalysisURL(NSString *url) {
    return [url isKindOfClass:NSString.class] && [url hasPrefix:@"rcanalysis://"];
}

static NSDictionary *RCMenuItemAtIndexPath(id controller, NSIndexPath *indexPath) {
    NSArray *menu = RCMsg0(controller, "menuData");
    if (![menu isKindOfClass:NSArray.class] || indexPath.section >= (NSInteger)menu.count) return nil;
    NSDictionary *section = menu[indexPath.section];
    NSArray *items = [section isKindOfClass:NSDictionary.class] ? section[@"items"] : nil;
    if (![items isKindOfClass:NSArray.class] || indexPath.row >= (NSInteger)items.count) return nil;
    id item = items[indexPath.row];
    return [item isKindOfClass:NSDictionary.class] ? item : nil;
}

static BOOL RCMenuAlreadyContainsEntry(NSArray *menu) {
    for (id section in menu) {
        NSArray *items = [section isKindOfClass:NSDictionary.class] ? section[@"items"] : nil;
        for (id item in items) {
            NSString *URL = [item isKindOfClass:NSDictionary.class] ? item[@"url"] : nil;
            if (RCIsAnalysisURL(URL)) return YES;
        }
    }
    return NO;
}

static BOOL RCMenuSupportsURLSchema(NSArray *menu) {
    // RootHide 1.3.9 baseline contains native menu items with type="url" + url.
    // Refuse to inject on an unexpected Manager schema rather than guessing.
    for (id section in menu) {
        NSArray *items = [section isKindOfClass:NSDictionary.class] ? section[@"items"] : nil;
        if (![items isKindOfClass:NSArray.class]) continue;
        for (id item in items) {
            if (![item isKindOfClass:NSDictionary.class]) continue;
            NSString *type = item[@"type"];
            NSString *URL = item[@"url"];
            if ([type isKindOfClass:NSString.class] && [type isEqualToString:@"url"] && [URL isKindOfClass:NSString.class]) return YES;
        }
    }
    return NO;
}

static void RCAppendAnalysisMenu(id controller) {
    NSArray *original = RCMsg0(controller, "menuData");
    if (![original isKindOfClass:NSArray.class] || RCMenuAlreadyContainsEntry(original)) return;
    if (!RCMenuSupportsURLSchema(original)) return;

    NSDictionary *analysis = @{
        @"textLabel": @"注入分析",
        @"detailTextLabel": @"多插件匹配 / 安装来源 / 双重注入",
        @"type": @"url",
        @"url": @"rcanalysis://injection"
    };
    NSDictionary *environment = @{
        @"textLabel": @"环境检查",
        @"detailTextLabel": @"孤立注册 / 插件配置 / DPKG 来源",
        @"type": @"url",
        @"url": @"rcanalysis://environment"
    };
    NSDictionary *section = @{
        @"groupTitle": [NSString stringWithFormat:@"Analysis %@", RCAnalysisVersion()],
        @"items": @[analysis, environment]
    };

    NSMutableArray *newMenu = [NSMutableArray arrayWithArray:original];
    [newMenu addObject:section];
    RCMsg1(controller, "setMenuData:", [newMenu copy]);
    UITableView *tableView = RCMsg0(controller, "tableView");
    [tableView reloadData];
}

static void RCReloadMenu(id self, SEL _cmd) {
    if (gOriginalReloadMenu) ((void (*)(id, SEL))gOriginalReloadMenu)(self, _cmd);
    RCAppendAnalysisMenu(self);
}

static void RCDidSelect(id self, SEL _cmd, UITableView *tableView, NSIndexPath *indexPath) {
    NSDictionary *item = RCMenuItemAtIndexPath(self, indexPath);
    NSString *URL = item[@"url"];
    if (RCIsAnalysisURL(URL)) {
        [tableView deselectRowAtIndexPath:indexPath animated:YES];
        UIViewController *vc = nil;
        if ([URL isEqualToString:@"rcanalysis://injection"]) vc = [RCAnalysisViewController new];
        else if ([URL isEqualToString:@"rcanalysis://environment"]) vc = [RCEnvironmentViewController new];
        UINavigationController *nav = RCMsg0(self, "navigationController");
        if (vc && nav) [nav pushViewController:vc animated:YES];
        return;
    }
    if (gOriginalDidSelect) ((void (*)(id, SEL, UITableView *, NSIndexPath *))gOriginalDidSelect)(self, _cmd, tableView, indexPath);
}

BOOL RCAnalysisMenuHooksInstalled(void) { return gInstalled; }
NSUInteger RCAnalysisMenuHookInstallAttempts(void) { return gInstallAttempts; }

static void RCInstallHooks(void) {
    if (gInstalled) return;
    gInstallAttempts++;
    Class cls = NSClassFromString(@"SettingViewController");
    if (!cls) { RCLog(@"hook install deferred: SettingViewController not found"); return; }

    Method reload = class_getInstanceMethod(cls, sel_registerName("reloadMenu"));
    Method select = class_getInstanceMethod(cls, sel_registerName("tableView:didSelectRowAtIndexPath:"));
    if (!reload || !select) { RCLog(@"hook install refused: expected RootHide methods missing"); return; }

    gOriginalReloadMenu = method_setImplementation(reload, (IMP)RCReloadMenu);
    gOriginalDidSelect = method_setImplementation(select, (IMP)RCDidSelect);
    gInstalled = YES;
    RCLog(@"menu hooks installed on SettingViewController");
}

__attribute__((constructor)) static void RCInjectAnalysisInit(void) {
    RCLog(@"dylib loaded; scheduling RootHide menu hook");
    dispatch_async(dispatch_get_main_queue(), ^{
        RCInstallHooks();
        if (!gInstalled) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ RCInstallHooks(); });
        }
    });
}
