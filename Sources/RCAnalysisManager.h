#import <Foundation/Foundation.h>
#import "RCModels.h"
NS_ASSUME_NONNULL_BEGIN
@interface RCAnalysisManager : NSObject
+ (instancetype)sharedManager;
@property (atomic, strong, readonly, nullable) RCAnalysisSnapshot *snapshot;
// Reuse the current RootHide Manager process snapshot when available.
- (void)loadSnapshotWithCompletion:(void (^)(RCAnalysisSnapshot *snapshot))completion;
// Explicit full rescan. Concurrent callers still join the same active scan.
- (void)refreshWithCompletion:(void (^)(RCAnalysisSnapshot *snapshot))completion;
@end
NS_ASSUME_NONNULL_END
