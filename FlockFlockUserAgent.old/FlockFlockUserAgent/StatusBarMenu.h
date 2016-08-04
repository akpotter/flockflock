//
//  StatusBarMenu.h
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 8/4/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/Appkit.h>

enum FlockFlockStatusBarStatus {
    kFlockFlockStatusBarStatusInitializing,
    kFlockFlockStatusBarStatusActive,
    kFlockFlockStatusBarStatusInactive
};

@interface StatusBarMenu : NSObject
{
    NSStatusItem *statusItem;
    NSMenu *statusMenu;
    NSMenuItem *menuItem;
    NSImage *statusImage;
    enum FlockFlockStatusBarStatus statusBarStatus;
}
+ (StatusBarMenu *)sharedInstance;
- (void)setupMenuBar;
- (void)updateStatus: (enum FlockFlockStatusBarStatus)status;
- (void)disableAction:(id)sender;
@end
