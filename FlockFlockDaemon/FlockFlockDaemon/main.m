//
//  main.c
//  FlockFlockDaemon
//
//  Created by Jonathan Zdziarski on 8/8/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

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
#include <sys/stat.h>
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
    
    FILE *tmp = fopen("/tmp/FlockFlockDaemon.log", "a");
    if (tmp) {
        fprintf(tmp, "%s[%d] %s\n", func, getpid(), debug_text);
        fclose(tmp);
    }
}

io_connect_t g_driverConnection;
pthread_mutex_t g_sharedLock;
unsigned char g_skey[SKEY_LEN];

enum FlockFlockPolicyClass get_class_by_name(const char *name) {
    if (!strcmp(name, "allow"))
        return kFlockFlockPolicyClassWhitelistAllMatching;
    if (!strcmp(name, "deny"))
        return kFlockFlockPolicyClassBlacklistAllMatching;
    if (!strcmp(name, "allow!"))
        return kFlockFlockPolicyClassWhitelistAllNotMatching;
    if (!strcmp(name, "deny!"))
        return kFlockFlockPolicyClassBlacklistAllNotMatching;
    return kFlockFlockPolicyClassCount;
}

enum FlockFlockPolicyType get_type_by_name(const char *name) {
    if (!strcmp(name, "prefix"))
        return kFlockFlockPolicyTypePathPrefix;
    if (!strcmp(name, "path"))
        return kFlockFlockPolicyTypeFilePath;
    if (!strcmp(name, "suffix"))
        return kFlockFlockPolicyTypePathSuffix;
    return kFlockFlockPolicyTypeCount;
}

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

int getHome(uid_t uid, char *buf, size_t len)
{
    struct passwd* pwd = getpwuid(uid);
    if (pwd) {
        strncpy(buf, pwd->pw_dir, len-1);
        LOG("home directory is %s", buf);
        return 0;
    }
    
    LOG("unable to determine home directory");
    return errno;
}

int loadConfigurationFile(const char *config_path, uid_t uid, bool is_default)
{
    struct _FlockFlockClientPolicy rule;
    char homedir[PATH_MAX];
    int success = 1;
    
    LOG("size of policy structure is %d\n", sizeof(rule));
    
    if (uid && getHome(uid, homedir, PATH_MAX)) {
        LOG("unable to load configuration file: homedir unknown");
        return errno;
    }
    
    LOG("opening configuration file %s", config_path);
    FILE *file = fopen(config_path, "r");
    char buf[2048];
    if (!file) {
        LOG("unable to open '%s' for reading: %s(%d)", config_path, strerror(errno), errno);
        return errno;
    }
    
    LOG("reading configuration %s", config_path);
    while((fgets(buf, sizeof(buf), file))!=NULL) {
        if (buf[0] == '#' || buf[0] == ';')
            continue;
        if (buf[0] == 0 || buf[0] == '\r' || buf[0] == '\n')
            continue;
        
        char *class = strtok(buf, "\t ");
        char *type = strtok(NULL, "\t ");
        char *path = strtok(NULL, "\"");
        char *pname = strtok(NULL, "\"");
        pname = strtok(NULL, "\"\n");
        
        LOG("parsing rule: class %s type %s path \"%s\" process name \"%s\" uid %d", class, type, path, pname, uid);
        
        rule.ruleClass = get_class_by_name(class);
        rule.ruleType = get_type_by_name(type);
        if (!strcmp(path, "any")) {
            if ( (is_default == true && uid == 0) || (is_default == false && uid > 0) ) {
                rule.rulePath[0] = 0;
            } else {
                LOG("skipping (system rule)");
                continue;
            }
        } else {
            /* the default .flockflockrc file is read in both as root and for each uid
             * on the system; the root load instantiates all global system rules,
             * whereas the user read instantiates all default $HOME rules. the user
             * can also specify their own $HOME rules in their .flockflockrc */
            
            if (!strncmp(path, "$HOME/", 6)) {
                char hpath[PATH_MAX];
                if (uid == 0) {
                    LOG("skipping (user rule)");
                    continue;
                }
                snprintf(hpath, PATH_MAX, "%s/%s", homedir, path+6);
                strncpy(rule.rulePath, hpath, PATH_MAX-1);
            } else {
                if ( (is_default == true && uid == 0) || (is_default == false && uid > 0) ) {
                    strncpy(rule.rulePath, path, PATH_MAX);
                } else {
                    LOG("skipping (system rule)");
                    continue;
                }
            }
        }
        
        if (!strcmp(pname, "any")) {
            rule.processName[0] = 0;
        } else {
            strncpy(rule.processName, pname, PATH_MAX);
        }
        
        rule.temporaryPid = 0;
        rule.temporaryRule = 0;
        
        LOG("class: %d", get_class_by_name(class));
        LOG("type : %d", get_type_by_name(type));
        LOG("path : %s", rule.rulePath);
        LOG("proc : %s (%d)", rule.processName, (int)strlen(rule.processName));
        LOG("temp : %d", rule.temporaryRule);
        LOG("uid  : %d", uid);
        
        memcpy(&rule.skey, g_skey, SKEY_LEN);
        kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockRequestAddClientRule, NULL, 0, &rule, sizeof(rule), NULL, NULL, NULL, NULL);
        if (kr == KERN_SUCCESS) {
            LOG("\tsuccess");
        } else {
            LOG("\tfailed");
            success = 0;
        }
    }
    if (! success) {
        displayAlert("FlockFlock: Policy Programming Error", "An unexpected error occurred while trying to program policies into FlockFlock. Your files may not be protected. Please attempt a reboot to reinitialize FlockFlock.");
    }
    fclose(file);
    return 0;
}

int sendConfiguration()
{
    char path[PATH_MAX];
    struct passwd *p;
    struct stat s;
    
    LOG("clearing old configuration");
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockRequestClearConfiguration, NULL, 0, g_skey, SKEY_LEN, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        LOG("failed to clear old configuration, aborting");
        return E_FAIL;
    }
    
    if (loadConfigurationFile(DEFAULT_FLOCKFLOCKRC, 0, true))
        return errno;
    
    p = getpwent();
    while(p) {
        if (p->pw_uid >= 500 && strcmp(p->pw_shell, "/usr/bin/false")) {
            snprintf(path, sizeof(path), "%s/.flockflockrc", p->pw_dir);
            LOG("loading configuration for user %s (%d)", p->pw_name, p->pw_uid);
            if (! stat(p->pw_dir, &s)) {
                loadConfigurationFile(path, p->pw_uid, false);
            }
            loadConfigurationFile(DEFAULT_FLOCKFLOCKRC, p->pw_uid, true); /* all default $HOME rules */
        }
        p = getpwent();
    }
    endpwent();
    
    return 0;
}

int startFilter()
{
    LOG("starting filter");
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockRequestStartFilter, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        LOG("filter started successfully");
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
        LOG("filter stopped successfully");
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
    } else if (header->query_type == FFQ_STOPPED) {
        LOG("received filter stop notice from driver");
        displayAlert("FlockFlock has been disabled", "FlockFlock has been disabled. Your files are not presently protected. Please re-enable FlockFlock or reboot to restart file protection.");
    } else {
        LOG("unknown notification arrived... oh noes!");
    }
}

void *authenticateAndProgramModule(void *ptr) {
    int authenticated = 0, cnt=0;
    unsigned char blank[SKEY_LEN];
    CFStringRef str;
    char pid[16];
    int r;
    
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
            CFSTR("Critical Failure, Reboot Required"),
            CFSTR("FlockFlock has encountered a critical failure and a reboot is required. Please reboot your system to reinitialize FlockFlock.")
        };
        CFDictionaryRef parameters = CFDictionaryCreate(0, keys, values,sizeof(keys)/sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        notification = CFUserNotificationCreate(kCFAllocatorDefault, 0, kCFUserNotificationStopAlertLevel, NULL, parameters);
        CFUserNotificationReceiveResponse(notification, 0, NULL);
        LOG("reboot required");
        pthread_exit(0);
        return NULL;
    }
    
    LOG("setting daemon pid to %d", getpid());
    uint64_t pid64 = (uint64_t) getpid();
    uint64_t args[1];
    args[0] = (uint64_t) pid64;
    kern_return_t kr = IOConnectCallMethod(g_driverConnection, kFlockFlockAssignDaemonPID, args, 1, g_skey, SKEY_LEN, NULL, NULL, NULL, NULL);
    if (kr) {
        LOG("error: failed to set daemon pid");
    }
    
    snprintf(pid, sizeof(pid), "%d", getpid());
    str = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, strdup(pid), kCFStringEncodingMacRoman, kCFAllocatorDefault);
    IORegistryEntrySetCFProperty(g_driverConnection, CFSTR("pid"), str);
    CFRelease(str);
    
    LOG("sending configuration");
    r = sendConfiguration();
    if (r) {
        LOG("failed to send driver configuration");
        displayAlert("Unable to configure FlockFlock", "FlockFlock was unable to be configured properly. Files are not presently protected. Please reboot to reinitialize FlockFlock.");
    } else {
        LOG("starting filter");
        startFilter();
    }
    pthread_exit(0);
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
            
            LOG("attempting to generate a security ticket");
            kr = IOConnectCallMethod(g_driverConnection, kFlockFlockGenTicket, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
            if (kr != KERN_SUCCESS ){
                LOG("ticket failed");
            }
            
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

int main(int argc, char *argv[]) {
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
    
    while(run) {
        startDriverComms();
        LOG("cycling");
        sleep(5);
    }
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
    pthread_mutex_destroy(&g_sharedLock);
    return 0;
}

