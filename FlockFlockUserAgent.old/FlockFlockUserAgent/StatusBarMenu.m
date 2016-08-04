//
//  StatusBarMenu.m
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 8/4/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#import "StatusBarMenu.h"

@implementation StatusBarMenu

+ (StatusBarMenu *)sharedInstance
{
    static StatusBarMenu *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [ [ StatusBarMenu alloc ] init ];
    });
    return sharedInstance;
}

- (void)setupMenuBar
{
    statusItem = [ [ NSStatusBar systemStatusBar ] statusItemWithLength: NSVariableStatusItemLength ];
    statusImage = [ [ NSImage alloc ] initWithContentsOfFile: @"/Library/Application Support/FlockFlock/lock_icon_alert.png" ];
    
    statusMenu = [ [ NSMenu alloc ] init ];
    menuItem = [ statusMenu addItemWithTitle: @"Disable" action: @selector(disableAction:) keyEquivalent: @""];
    
    [ statusItem setImage: statusImage ];
    [ statusItem setAlternateImage: statusImage];
    [ statusItem setHighlightMode: YES];
    [ statusItem setMenu: statusMenu ];
    
    statusItem.enabled = YES;
    menuItem.enabled = YES;
}

- (void)updateStatus: (enum FlockFlockStatusBarStatus)status
{
    switch(status) {
        case(kFlockFlockStatusBarStatusInitializing):
        case(kFlockFlockStatusBarStatusInactive):
            statusImage = [ [ NSImage alloc ] initWithContentsOfFile: @"/Library/Application Support/FlockFlock/lock_icon_alert.png" ];
            break;
        case(kFlockFlockStatusBarStatusActive):
            statusImage = [ [ NSImage alloc ] initWithContentsOfFile: @"/Library/Application Support/FlockFlock/lock_icon_small.png" ];
            break;
    }
    
    [ statusItem setImage: statusImage ];
    [ statusItem setAlternateImage: statusImage];
    [ statusItem setHighlightMode:YES ];
}

- (void)disableAction:(id)sender
{

}

@end
