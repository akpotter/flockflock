//
//  AppDelegate.m
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 8/4/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include <pthread.h>
#import "AppDelegate.h"
#import "StatusBarMenu.h"
#include "agent_main.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    
    [ [ StatusBarMenu sharedInstance ] setupMenuBar ];
    
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToBackgroundApplication);
    
    pthread_t thread;
    pthread_create(&thread, NULL, agent_main, NULL);
    pthread_detach(thread);
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}

@end
