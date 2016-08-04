//
//  main.m
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 8/4/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#include <sys/ptrace.h>

int main(int argc, const char * argv[]) {
    
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToBackgroundApplication);
    
#ifdef PERSISTENCE
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif
    return NSApplicationMain(argc, argv);
}
