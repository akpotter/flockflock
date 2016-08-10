//
//  main.c
//  FlockFlockUserAgent
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>
#include <AppKit/AppKit.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <errno.h>
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <libproc.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include "StatusBarMenu.h"
#include "../../FlockFlockKext/FlockFlock/FlockFlockClientShared.h"

#define DEFAULT_FLOCKFLOCKRC "/Library/Application Support/FlockFlock/.flockflockrc"

#ifndef DEBUG
#define LOG( ... )
#else
void LOG_(const char *, const char *, ...);
#define LOG(A...) LOG_(__PRETTY_FUNCTION__,  A)
#endif

void
LOG_ (const char *func, const char *err, ... )
{
    char debug_text[1024];
    va_list args;
    
    va_start (args, err);
    vsnprintf (debug_text, sizeof(debug_text), err, args);
    va_end (args);
    fprintf(stderr, "%s[%d] %s\n", func, getpid(), debug_text);
    
    FILE *tmp = fopen("/tmp/FlockFlockUserAgent.log", "a");
    if (tmp) {
        fprintf(tmp, "%s[%d] %s\n", func, getpid(), debug_text);
        fclose(tmp);
    }
}

io_connect_t g_driverConnection;
pthread_mutex_t g_sharedLock, g_promptLock;
unsigned char g_skey[SKEY_LEN];
int g_lastFilterState = -1;

void displayAlert(const char *header, const char *message)
{
    CFUserNotificationRef notification;
    
    const void* keys[] = {
        kCFUserNotificationAlertHeaderKey,
        kCFUserNotificationAlertMessageKey,
    };
    const void* values[] = {
        CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, strdup(header), kCFStringEncodingMacRoman, kCFAllocatorDefault),
        CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, strdup(message), kCFStringEncodingMacRoman, kCFAllocatorDefault)
    };
    CFDictionaryRef parameters = CFDictionaryCreate(0, keys, values,sizeof(keys)/sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    notification = CFUserNotificationCreate(kCFAllocatorDefault, 0, kCFUserNotificationStopAlertLevel, NULL, parameters);
    CFUserNotificationReceiveResponse(notification, 0, NULL);
}

int startFilter()
{
    LOG("starting filter");
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockRequestStartFilter, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    if (kr == KERN_SUCCESS) {
        if ([ StatusBarMenu sharedInstance ].statusBarStatus != kFlockFlockStatusBarStatusInitializing)
        {
            LOG("filter started");
            [ [ StatusBarMenu sharedInstance ] updateStatus: kFlockFlockStatusBarStatusActive ];
        } else {
            LOG("we're still initializing");
        }
    } else {
        LOG("error %d occurred while attempting to start filter", kr);
    }
    return kr;
}

int stopFilter()
{
    LOG("stopping filter");
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockRequestStopFilter, NULL, 0, g_skey, SKEY_LEN, NULL, NULL, NULL, NULL);
    if (kr == KERN_SUCCESS) {
        LOG("filter stopped");
        [ [ StatusBarMenu sharedInstance ] updateStatus: kFlockFlockStatusBarStatusInactive ];
    } else {
        LOG("error %d occurred while attempting to stop filter", kr);
    }
    return kr;
}

int getPPID(int pid)
{
    struct kinfo_proc info;
    size_t length = sizeof(struct kinfo_proc);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &info, &length, NULL, 0) < 0)
        return UINT_MAX;
    if (length == 0)
        return UINT_MAX;
    return info.kp_eproc.e_ppid;
}

void updateFilterStatus(void) {
    pthread_mutex_lock(&g_sharedLock);
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockFilterStatus, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    pthread_mutex_unlock(&g_sharedLock);

    if (kr == 0) {
        LOG("filter status active");
        pthread_mutex_lock(&g_sharedLock);
        g_lastFilterState = 1;
        pthread_mutex_unlock(&g_sharedLock);

        [ [ StatusBarMenu sharedInstance ] updateStatus: kFlockFlockStatusBarStatusActive ];
    }
    else {
        pthread_mutex_lock(&g_sharedLock);
        g_lastFilterState = 0;
        pthread_mutex_unlock(&g_sharedLock);
        LOG("filter status disabled");
        [ [ StatusBarMenu sharedInstance ] updateStatus: kFlockFlockStatusBarStatusInactive ];
    }
}

void notificationCallback(CFMachPortRef unusedport, void *voidmessage, CFIndex size, void *info)
{
    struct ff_basic_msg *header = (struct ff_basic_msg *)voidmessage;

    LOG("received notification callback type %x", header->query_type);
    
    if (header->query_type == FFQ_SECKEY) {
        LOG("setting skey");
        struct skey_msg *message = (struct skey_msg *)voidmessage;
        pthread_mutex_lock(&g_sharedLock);
        memcpy(g_skey, message->skey, SKEY_LEN);
        pthread_mutex_unlock(&g_sharedLock);
        LOG("skey set");
    } else {
        LOG("unknown notification arrived... oh noes!");
    }
}

void *filterStatusManager(void *ptr) {
    while(1) {
        int last_state;
        pthread_mutex_lock(&g_sharedLock);
        last_state = g_lastFilterState;
        pthread_mutex_unlock(&g_sharedLock);
        
        if (last_state == 1 || last_state == 0)
            sleep(5);
        else
            sleep(1);
        updateFilterStatus();
    }
}

void *authenticateAndProgramModule(void *ptr) {
    int authenticated = 0, cnt=0;
    unsigned char blank[SKEY_LEN];
    CFStringRef str;
    char pid[16];
    
    sleep(1);
    memset(&blank, 0, SKEY_LEN);
    pthread_mutex_lock(&g_sharedLock);
    authenticated = memcmp(g_skey, blank, SKEY_LEN);
    pthread_mutex_unlock(&g_sharedLock);

    while(! authenticated && cnt < 5) {
        sleep(1);
        ++cnt;
        pthread_mutex_lock(&g_sharedLock);
        authenticated = memcmp(g_skey, blank, SKEY_LEN);
        pthread_mutex_unlock(&g_sharedLock);
    }
    
    if (!authenticated) {
        CFUserNotificationRef notification;
        
        LOG("error: could not authenticate with driver");
        
        const void* keys[] = {
            kCFUserNotificationAlertHeaderKey,
            kCFUserNotificationAlertMessageKey,
        };
        const void* values[] = {
            CFSTR("Cannot Connect to FlockFlock"),
            CFSTR("The user agent is unable to connect to FlockFlock. The status menu cannot be displayed.")
        };
        CFDictionaryRef parameters = CFDictionaryCreate(0, keys, values,sizeof(keys)/sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        notification = CFUserNotificationCreate(kCFAllocatorDefault, 0, kCFUserNotificationStopAlertLevel, NULL, parameters);
        CFUserNotificationReceiveResponse(notification, 0, NULL);
        LOG("reboot required");
        return NULL;
    } else {
        LOG("updating filter status");
        updateFilterStatus();
    }
    
    LOG("setting agent pid to %d", getpid());
    uint64_t pid64 = (uint64_t) getpid();
    uint64_t args[1];
    args[0] = (uint64_t) pid64;
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockAssignAgentPID, args, 1, g_skey, SKEY_LEN, NULL, NULL, NULL, NULL);
    if (kr) {
        LOG("error: failed to set agent pid");
    }
    
    snprintf(pid, sizeof(pid), "%d", getpid());
    str = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, strdup(pid), kCFStringEncodingMacRoman, kCFAllocatorDefault);
    IORegistryEntrySetCFProperty(g_driverConnection, CFSTR("pid"), str);
    CFRelease(str);
    
    
    pthread_t thread;
    pthread_create(&thread, NULL, filterStatusManager, NULL);
    pthread_detach(thread);
                   
    LOG("done setup");
    return NULL;
}

int startDriverComms() {
    io_iterator_t iter = 0;
    io_service_t service = 0;
    kern_return_t kr;
    
    CFDictionaryRef matchDict = IOServiceMatching(DRIVER);
    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iter);
    if (kr != KERN_SUCCESS) {
        LOG("IOServiceGetMatchingServices failed on error %d", kr);
        return E_FAIL;
    }
    
    if ((service = IOIteratorNext(iter)) != 0)
    {
        task_port_t owningTask = mach_task_self();
        CFStringRef className;
        uint32_t type = 0;
        kern_return_t kr;
        io_name_t name;
        
        className = IOObjectCopyClass(service);
        IORegistryEntryGetName(service, name);
        
        LOG("found driver '%s'", name);
        
        kr = IOServiceOpen(service, owningTask, type, &g_driverConnection);
        if (kr == KERN_SUCCESS) {
            LOG("connected to driver %s, setting up comms...", DRIVER);
            
            CFRunLoopSourceRef notification_loop;
            CFMachPortRef notification_port;
            CFMachPortContext context;
            
            context.version = 0;
            context.info = &g_driverConnection;
            context.retain = NULL;
            context.release = NULL;
            context.copyDescription = NULL;
            
            LOG("assigning notiication port");
            notification_port = CFMachPortCreate(NULL, notificationCallback, &context, NULL);
            notification_loop = CFMachPortCreateRunLoopSource(NULL, notification_port, 0);
            mach_port_t port = CFMachPortGetPort(notification_port);
            IOConnectSetNotificationPort(g_driverConnection, 0, port, 0);
            
            IOConnectCallMethod(g_driverConnection, kFlockFlockGenTicket, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);

            pthread_t thread;
            pthread_create(&thread, NULL, authenticateAndProgramModule, NULL);
            pthread_detach(thread);
            
            LOG("waiting for notifications");
            CFRunLoopAddSource(CFRunLoopGetCurrent(), notification_loop, kCFRunLoopDefaultMode);
            CFRunLoopRun();
        }
        
        LOG("closing connection to %s", DRIVER);
        IOServiceClose(service);
    } else {
        LOG("IOServiceOpen failed on error %d", kr);
    }
    
    IOObjectRelease(service);
    IOObjectRelease(iter);
    return 0;
}

void * agent_main(void *ptr) {
    static struct termios oldt, newt;
    bool run = true;
#ifdef PERSISTENCE
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON);
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    pthread_mutex_init(&g_sharedLock, NULL);
    pthread_mutex_init(&g_promptLock, NULL);
    
    while(run) {
        startDriverComms();
        [ [ StatusBarMenu sharedInstance ] updateStatus: kFlockFlockStatusBarStatusInactive ];

        sleep(5);
    }
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
    pthread_mutex_destroy(&g_sharedLock);
    pthread_mutex_destroy(&g_promptLock);
    return 0;
}

