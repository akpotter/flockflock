//
//  StatusBarMenu.h
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 8/4/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/Appkit.h>
#include "agent_main.h"

enum FlockFlockStatusBarStatus {
    kFlockFlockStatusBarStatusInitializing,
    kFlockFlockStatusBarStatusActive,
    kFlockFlockStatusBarStatusInactive,
    kFlockFlockStatusBarStatusDisabled
};

@interface StatusBarMenu : NSObject
{
    NSStatusItem *statusItem;
    NSMenu *statusMenu;
    NSMenuItem *statusMenuItem, *actionMenuItem;
    NSImage *statusImage;
    enum FlockFlockStatusBarStatus statusBarStatus;
}
+ (StatusBarMenu *)sharedInstance;
- (void)setupMenuBar;
- (void)updateStatus: (enum FlockFlockStatusBarStatus)status;
- (void)disableAction:(id)sender;
- (void)enableAction:(id)sender;

@property(assign) enum FlockFlockStatusBarStatus statusBarStatus;
@end

