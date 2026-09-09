#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class RCDiagnosticItem;

typedef NS_ENUM(NSInteger, RCDetectionConfidence) {
    RCDetectionConfidenceLow = 0,
    RCDetectionConfidenceMedium,
    RCDetectionConfidenceHigh,
};

typedef NS_ENUM(NSInteger, RCTweakIssueSeverity) {
    RCTweakIssueSeverityNone = 0,
    RCTweakIssueSeverityInformational,
    RCTweakIssueSeveritySuspicious,
    RCTweakIssueSeverityHighConfidence,
};

typedef NS_ENUM(NSInteger, RCAppInstallSource) {
    RCAppInstallSourceUnknown = 0,
    RCAppInstallSourceTrollStore,
    RCAppInstallSourceTrollStoreLite,
};

typedef NS_ENUM(NSInteger, RCTweakInstallSource) {
    RCTweakInstallSourceUnknown = 0,
    RCTweakInstallSourceDPKG,
};

typedef NS_ENUM(NSInteger, RCEmbeddedInjectionSource) {
    RCEmbeddedInjectionSourceUnknown = 0,
    RCEmbeddedInjectionSourceTrollFools,
};


@interface RCEnvironmentProfile : NSObject
@property (nonatomic) BOOL rootHideDetected;
@property (nonatomic) BOOL jbrootAvailable;
@property (nonatomic) BOOL pathMappingActive;
@property (nonatomic, copy) NSString *jbrootImagePath;
@property (nonatomic, copy) NSString *tweakInjectLogicalPath;
@property (nonatomic, copy) NSString *tweakInjectMappedPath;
@property (nonatomic, copy) NSString *dpkgStatusLogicalPath;
@property (nonatomic, copy) NSString *dpkgStatusMappedPath;
@property (nonatomic, copy) NSString *dpkgInfoLogicalPath;
@property (nonatomic, copy) NSString *dpkgInfoMappedPath;
@property (nonatomic, copy) NSString *rootHideConfigLogicalPath;
@property (nonatomic, copy) NSString *rootHideConfigMappedPath;
@property (nonatomic, copy) NSString *hostBundleIdentifier;
@property (nonatomic, copy) NSString *hostVersion;
@property (nonatomic, copy) NSString *analysisVersion;
@property (nonatomic, copy) NSString *analysisArchitecture;
@property (nonatomic, copy) NSString *analysisImagePath;
@property (nonatomic, copy) NSString *analysisImageUUID;
@property (nonatomic) BOOL analysisImagePathExpected;
@property (nonatomic) BOOL analysisHostWeakLoadPresent;
@property (nonatomic) BOOL analysisBuildManifestUUIDMatches;
@property (nonatomic, copy) NSString *analysisRuntimeSelfCheckStatus;
@property (nonatomic, copy) NSString *analysisRuntimeSelfCheckSummary;
@property (nonatomic) BOOL analysisBuildManifestPresent;
@property (nonatomic) NSInteger analysisBuildManifestSchema;
@property (nonatomic, copy) NSString *analysisBuildID;
@property (nonatomic, copy) NSString *analysisBuildManifestSourceTreeSHA256;
@property (nonatomic) NSUInteger analysisBuildManifestSourceFileCount;
@property (nonatomic) BOOL analysisBuildManifestVersionMatches;
@property (nonatomic, copy) NSString *analysisBuildManifestVersion;
@property (nonatomic, copy) NSString *analysisBuildManifestDylibSHA256;
@property (nonatomic, copy) NSString *analysisBuildManifestBaselineSHA256;
@property (nonatomic, copy) NSString *analysisBuildManifestInstallName;
@property (nonatomic, copy) NSString *analysisBuildManifestLoadMode;
@property (nonatomic) BOOL analysisMenuHooksInstalled;
@property (nonatomic) NSUInteger analysisMenuHookInstallAttempts;
@property (nonatomic, copy) NSString *analysisHostExecutablePath;
@property (nonatomic, copy) NSString *analysisHostExecutableMode;
@property (nonatomic) NSUInteger analysisHostExecutableUID;
@property (nonatomic) NSUInteger analysisHostExecutableGID;
@property (nonatomic) BOOL analysisHostExecutableSetUID;
@property (nonatomic) BOOL analysisHostExecutablePostInstallStateExpected;
@property (nonatomic, copy) NSString *analysisHostExecutableStateDetail;
@property (nonatomic, copy) NSString *analysisDylibFileMode;
@property (nonatomic) BOOL analysisDylibFileStateExpected;
@property (nonatomic, copy) NSString *analysisDylibFileStateDetail;
@end

@interface RCScanTimelineEvent : NSObject
@property (nonatomic) NSTimeInterval offset;
@property (nonatomic, copy) NSString *phase;
@property (nonatomic, copy) NSString *detail;
@end

@interface RCPackageRecord : NSObject
@property (nonatomic, copy) NSString *packageIdentifier;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *version;
@property (nonatomic, copy) NSString *status;
@end

@interface RCTweakRecord : NSObject
@property (nonatomic, copy) NSString *plistName;
@property (nonatomic, copy) NSString *plistPath;
@property (nonatomic, copy, nullable) NSString *dylibPath;
@property (nonatomic, copy) NSArray<NSString *> *bundleIdentifiers;
@property (nonatomic, copy) NSArray<NSString *> *executableIdentifiers;
@property (nonatomic, copy) NSArray<NSString *> *installedTargetExecutableIdentifiers;
@property (nonatomic, copy) NSArray<NSString *> *systemTargetExecutableIdentifiers;
@property (nonatomic, copy) NSArray<NSString *> *unresolvedTargetExecutableIdentifiers;
@property (nonatomic, copy) NSArray<NSString *> *installedTargetBundleIdentifiers;
@property (nonatomic, copy) NSArray<NSString *> *uninstalledTargetBundleIdentifiers;
@property (nonatomic, strong, nullable) RCPackageRecord *package;
@property (nonatomic) RCTweakInstallSource installSource;
@property (nonatomic) RCDetectionConfidence sourceConfidence;
@property (nonatomic, copy) NSString *installSourceEvidence;
@property (nonatomic, copy) NSArray<NSString *> *issues;
@property (nonatomic) RCTweakIssueSeverity issueSeverity;
@property (nonatomic, readonly) NSString *displayName;
@end

@interface RCEmbeddedInjectionRecord : NSObject
@property (nonatomic, copy) NSString *appBundleIdentifier;
@property (nonatomic, copy) NSString *targetMachOPath;
@property (nonatomic, copy, nullable) NSString *backupPath;
@property (nonatomic, copy, nullable) NSString *loadPath;
@property (nonatomic) RCEmbeddedInjectionSource source;
@property (nonatomic) RCDetectionConfidence confidence;
@property (nonatomic) BOOL activeDifferenceConfirmed;
@property (nonatomic, copy) NSString *evidence;
@end


@interface RCEmbeddedScanResult : NSObject
@property (nonatomic, copy) NSArray<RCEmbeddedInjectionRecord *> *records;
@property (nonatomic) NSUInteger entriesVisited;
@property (nonatomic) BOOL truncated;
@property (nonatomic) BOOL scanAttempted;
@property (nonatomic) NSTimeInterval duration;
@property (nonatomic) BOOL timeBudgetExceeded;
@property (nonatomic, copy) NSString *stopReason;
@property (nonatomic, copy) NSString *status;
@end

@interface RCScanMetrics : NSObject
@property (nonatomic) NSTimeInterval totalDuration;
@property (nonatomic) NSTimeInterval tweakAndPackageDuration;
@property (nonatomic) NSTimeInterval appDuration;
@property (nonatomic) NSTimeInterval blacklistDuration;
@property (nonatomic) NSTimeInterval embeddedDuration;
@property (nonatomic) NSUInteger embeddedEntriesVisited;
@property (nonatomic) NSUInteger embeddedAppsScanned;
@property (nonatomic) NSUInteger embeddedAppsTruncated;
@property (nonatomic) NSUInteger embeddedAppsTimeLimited;
@property (nonatomic) NSUInteger embeddedAppsSkippedByGlobalBudget;
@property (nonatomic) NSUInteger embeddedEntryLimitPerApp;
@property (nonatomic) NSTimeInterval embeddedTimeLimitPerApp;
@property (nonatomic) NSTimeInterval embeddedTotalTimeLimit;
@property (nonatomic) NSTimeInterval slowestEmbeddedAppDuration;
@property (nonatomic, copy) NSString *slowestEmbeddedAppBundleIdentifier;
@end

@interface RCAppRecord : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy, nullable) NSString *bundlePath;
@property (nonatomic, copy, nullable) NSString *bundleExecutable;
@property (nonatomic, copy, nullable) NSString *applicationType;
@property (nonatomic) BOOL launchServicesRegistered;
@property (nonatomic) BOOL bundlePathExists;
@property (nonatomic) BOOL highConfidenceOrphanRegistration;
@property (nonatomic) BOOL blacklistStateKnown;
@property (nonatomic) BOOL blacklistSupported;
@property (nonatomic) BOOL blacklisted;
@property (nonatomic, copy) NSString *blacklistEvidence;
@property (nonatomic) RCAppInstallSource installSource;
@property (nonatomic) RCDetectionConfidence installSourceConfidence;
@property (nonatomic, copy) NSString *installSourceEvidence;
@property (nonatomic, copy) NSArray<RCTweakRecord *> *matchedTweaks;
@property (nonatomic, copy) NSArray<RCEmbeddedInjectionRecord *> *embeddedInjections;
@property (nonatomic) NSUInteger embeddedScanEntriesVisited;
@property (nonatomic) BOOL embeddedScanTruncated;
@property (nonatomic) BOOL embeddedScanAttempted;
@property (nonatomic) NSTimeInterval embeddedScanDuration;
@property (nonatomic) BOOL embeddedTimeBudgetExceeded;
@property (nonatomic) BOOL embeddedSkippedByGlobalBudget;
@property (nonatomic, copy) NSString *embeddedScanStopReason;
@property (nonatomic, copy) NSString *embeddedScanStatus;
@end

@interface RCBlacklistResidueRecord : NSObject
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic) BOOL storedBlacklistedValue;
@property (nonatomic) BOOL blacklistGloballyDisabled;
@property (nonatomic) RCDetectionConfidence confidence;
@property (nonatomic, copy) NSString *evidence;
@end

@interface RCAnalysisSnapshot : NSObject
@property (nonatomic) BOOL launchServicesAvailable;
@property (nonatomic) BOOL tweakScanAvailable;
@property (nonatomic) BOOL dpkgStatusAvailable;
@property (nonatomic) BOOL dpkgInfoAvailable;
@property (nonatomic) BOOL blacklistStateAvailable;
@property (nonatomic) BOOL embeddedEvidenceAvailable;
@property (nonatomic, copy) NSArray<RCAppRecord *> *apps;
@property (nonatomic, copy) NSArray<RCTweakRecord *> *tweaks;
@property (nonatomic, copy) NSArray<RCAppRecord *> *multiMatchApps;
@property (nonatomic, copy) NSArray<RCAppRecord *> *orphanRegistrations;
@property (nonatomic, copy) NSArray<RCBlacklistResidueRecord *> *blacklistResidues;
@property (nonatomic, copy) NSArray<RCTweakRecord *> *suspiciousTweaks;
@property (nonatomic, copy) NSArray<RCTweakRecord *> *uninstalledTargetTweaks;
@property (nonatomic, copy) NSArray<RCEmbeddedInjectionRecord *> *embeddedInjectionRecords;
@property (nonatomic, copy) NSArray<RCDiagnosticItem *> *diagnostics;
@property (nonatomic, strong) NSDate *generatedAt;
@property (nonatomic, strong) RCScanMetrics *metrics;
@property (nonatomic, strong) RCEnvironmentProfile *environmentProfile;
@property (nonatomic, copy) NSArray<RCScanTimelineEvent *> *timeline;
@property (nonatomic, copy) NSString *scanIdentifier;
@end

FOUNDATION_EXPORT NSString *RCConfidenceText(RCDetectionConfidence confidence);
FOUNDATION_EXPORT NSString *RCTweakIssueSeverityText(RCTweakIssueSeverity severity);
FOUNDATION_EXPORT NSString *RCAppInstallSourceText(RCAppInstallSource source);
FOUNDATION_EXPORT NSString *RCTweakInstallSourceText(RCTweakInstallSource source);
FOUNDATION_EXPORT NSString *RCEmbeddedSourceText(RCEmbeddedInjectionSource source);

NS_ASSUME_NONNULL_END
