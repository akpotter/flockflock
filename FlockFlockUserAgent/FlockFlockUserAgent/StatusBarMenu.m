//
//  StatusBarMenu.m
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 8/4/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#import "StatusBarMenu.h"
#include "../../FlockFlockKext/FlockFlock/FlockFlockClientShared.h"

@implementation StatusBarMenu
@synthesize statusBarStatus;

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
    statusMenuItem = [ statusMenu addItemWithTitle: @"FlockFlock: Initializing" action: NULL keyEquivalent: @"" ];
    statusMenuItem.target = nil;
    
    actionMenuItem = [ statusMenu addItemWithTitle: @"Disable" action: NULL keyEquivalent: @"" ];
    actionMenuItem.target = nil;
    
    [ statusMenu addItem: [ NSMenuItem separatorItem ] ];
    
    aboutMenuItem = [ statusMenu addItemWithTitle: @"About FlockFlock" action: @selector(aboutAction:) keyEquivalent: @"" ];
    aboutMenuItem.target = self;
    
    [ statusItem setImage: statusImage ];
    [ statusItem setAlternateImage: statusImage];
    [ statusItem setHighlightMode: YES];
    [ statusItem setMenu: statusMenu ];
    
    statusItem.enabled = YES;
}

- (void)updateStatus: (enum FlockFlockStatusBarStatus)status
{
    actionMenuItem.target = self;
    actionMenuItem.enabled = YES;
    statusBarStatus = status;
    
    switch(status) {
        case(kFlockFlockStatusBarStatusInitializing):
            actionMenuItem.target = nil;

        case(kFlockFlockStatusBarStatusDisabled):
            actionMenuItem.target = nil;
        case(kFlockFlockStatusBarStatusInactive):
            statusImage = [ [ NSImage alloc ] initWithContentsOfFile: @"/Library/Application Support/FlockFlock/lock_icon_alert.png" ];
            [ statusImage setTemplate: NO ];
            statusMenuItem.title = @"FlockFlock: Disabled";
            actionMenuItem.action = @selector(enableAction:);
            actionMenuItem.title = @"Enable";
            break;
        case(kFlockFlockStatusBarStatusActive):
            statusImage = [ [ NSImage alloc ] initWithContentsOfFile: @"/Library/Application Support/FlockFlock/lock_icon_small.png" ];
            [ statusImage setTemplate: YES ];
            statusMenuItem.title = @"FlockFlock: Enabled";
            actionMenuItem.title = @"Disable";
            actionMenuItem.action = @selector(disableAction:);
            break;
    }
    
    [ statusItem setImage: statusImage ];
    [ statusItem setAlternateImage: statusImage];
    [ statusItem setHighlightMode:YES ];
}

- (void) displayNotice:(const char *)header message:(const char *)message
{
    CFStringRef base = CFSTR("file:///Library/Application%20Support/FlockFlock/lock.png");
    CFURLRef icon = CFURLCreateWithString(NULL, base, NULL);
    CFDictionaryRef parameters;
    CFUserNotificationRef notification;
    SInt32 err;

    
    const void* keys[] = {
        kCFUserNotificationAlertHeaderKey,
        kCFUserNotificationAlertMessageKey,
        kCFUserNotificationDefaultButtonTitleKey,
        kCFUserNotificationIconURLKey
    };
    
    const void* values[] = {
        CFStringCreateWithCString(NULL, header, kCFStringEncodingMacRoman),
        CFStringCreateWithCString(NULL, message, kCFStringEncodingMacRoman),
        CFSTR("OK"),
        icon
    };
    
    /* display the popup to the user and get a response */
    parameters = CFDictionaryCreate(0, keys, values, sizeof(keys)/sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    notification = CFUserNotificationCreate(kCFAllocatorDefault, 60, kCFUserNotificationPlainAlertLevel, &err, parameters);

}

- (void)aboutAction:(id)sender
{
    char version[32];
    snprintf(version, sizeof(version), "FlockFlock %s", FLOCKFLOCK_VERSION);
    [ self displayNotice: version message: "Copyright (c) 2016, by Jonathan Zdziarski\nAll Rights Reserved\n" ];
}

- (void)disableAction:(id)sender
{
    stopFilter();
}

- (void)enableAction:(id)sender
{
    startFilter();
}

@end
