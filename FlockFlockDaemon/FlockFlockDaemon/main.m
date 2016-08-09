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

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <Cocoa/Cocoa.h>
#import <AppKit/AppKit.h>
#import <IOKit/IOKitLib.h>

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
pthread_mutex_t g_sharedLock, g_promptLock;
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

int commitNewRuleToDisk(struct _FlockFlockClientPolicy *rule)
{
    char path[PATH_MAX];
    char rule_data[PATH_MAX * 4];
    CFStringRef consoleUserName = nil;
    char *home;
    uid_t uid;
    gid_t gid;
    struct passwd *p;
    struct stat s;
    FILE *file;
    int e;
    
    
    consoleUserName = SCDynamicStoreCopyConsoleUser(NULL, &uid, &gid);
    
    if (consoleUserName == NULL) {
        LOG("error: unable to determine current user");
        return EINVAL;
    }
    
    LOG("getting homedir for uid %d", uid);
    p = getpwuid(uid);
    if (!p) {
        LOG("error: unable to determine home directory for uid %d", uid);
        return EINVAL;
    }
    CFRelease(consoleUserName);
    home = p->pw_dir;
    snprintf(path, sizeof(path), "%s/.flockflockrc", home);
  
    snprintf(rule_data, sizeof(rule_data), "%s %s \"%s\" \"%s\"",
             (rule->ruleClass == kFlockFlockPolicyClassWhitelistAllMatching) ? "allow" : "deny",
             (rule->ruleType == kFlockFlockPolicyTypeFilePath) ? "path" :
             (rule->ruleType == kFlockFlockPolicyTypePathPrefix) ? "prefix" : "suffix",
             (rule->rulePath[0]) ? rule->rulePath : "any",
             (rule->processName[0]) ? rule->processName : "any");
    
    LOG("%s", rule_data);
    e = stat(path, &s);
    file = fopen(path, "a");
    if (file) {
        fprintf(file, "%s\n", rule_data);
        fclose(file);
    }
    if (e) {
        chown(path, p->pw_uid, p->pw_gid);
        chmod(path, 0644);
    }
    return 0;
}


int promptUserForPermission(struct policy_query *query)
{
    char proc_path[PATH_MAX] = { 0 }, pproc_path[PATH_MAX] = { 0 }, proc_detail[PATH_MAX] = { 0 };
    int ppid = getPPID(query->pid);
    struct _FlockFlockClientPolicy rule;
    char alert_message[4096];
    CFStringRef alert_str, param;
    CFUserNotificationRef notification;
    CFDictionaryRef parameters;
    CFMutableArrayRef popup_options, radio_options;
    CFOptionFlags responseFlags = 0;
    unsigned long selectedIndex;
    CFStringRef selectedElement;
    SInt32 err, response;
    char *path, *extension, *ptr, option[PATH_MAX];
    char *displayName, *appPath, *p;
    CFStringRef base = CFSTR("file:///Library/Application%20Support/FlockFlock/lock.png");
    char operation[32];
    int i;
    
    strncpy(proc_path, query->process_name, PATH_MAX-1);
    proc_pidpath(query->pid, proc_detail, PATH_MAX);
    proc_pidpath(ppid, pproc_path, PATH_MAX);
    
    switch(query->operation) {
        case(FF_FILEOP_OPEN):
            strncpy(operation, "an access", sizeof(operation));
            break;
        case(FF_FILEOP_WRITE):
            strncpy(operation, "a write", sizeof(operation));
            break;
        case(FF_FILEOP_DELETE):
            strncpy(operation, "a delete", sizeof(operation));
            break;
        case(FF_FILEOP_TRUNCATE):
            strncpy(operation, "a truncate", sizeof(operation));
            break;
    }
    
    snprintf(alert_message, sizeof(alert_message), "FlockFlock detected %s attempt to the file:\n%s\n\nApplication:\n%s (%d)\n(%s)\n\nParent:\n%s (%d)\n", operation,
             query->path, proc_path, query->pid, proc_detail, pproc_path, ppid);
    LOG("%s", alert_message);
    alert_str = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, strdup(alert_message), kCFStringEncodingMacRoman, kCFAllocatorDefault);
    
    /* manicure display names and pathname */
    displayName = strdup(query->process_name);
    if (displayName[strlen(displayName)-1] == '/')
        displayName[strlen(displayName)-1] = 0;
    p = strstr(displayName, "/ via ");
    if (p) {
        char *d = strdup(p+1);
        strcpy(p, d);
        free(d);
    }
    
    appPath = strdup(displayName);
    p = strstr(appPath, " via ");
    if (p) {
        char *via = p+5;
        p[0] = 0;
        
        if (strcasestr(via, ".app"))
        {
            char n[PATH_MAX];
            strncpy(n, via, PATH_MAX);
            free(appPath);
            appPath = strdup(n);
        }
    }
    p = strstr(appPath, " (-");
    if (p)
        p[0] = 0;
    
    LOG("finding application icon for %s", appPath);
    NSImage *image = [ [ NSWorkspace sharedWorkspace ] iconForFile: [ NSString stringWithUTF8String: appPath ] ];
    [ image setSize: CGSizeMake(256.0, 256.0) ];
    if (image) { /* write to temp file, since we don't know where it came from */
        
        CGImageRef cgRef = [ image CGImageForProposedRect:NULL
                                                  context: nil
                                                    hints: nil ];
        NSBitmapImageRep *imageRep = [ [ NSBitmapImageRep alloc ] initWithCGImage: cgRef ];
        [ imageRep setSize:[ image size ] ];
        NSDictionary *dict = [ [ NSDictionary alloc ] init ];
        NSData *data = [ imageRep representationUsingType: NSPNGFileType properties: dict ];
        [ data writeToFile: @"/tmp/flockflock_temp.png" atomically: NO ]; /* fugly */
        base = CFSTR("/tmp/flockflock_temp.png");
    }
    CFURLRef icon = CFURLCreateWithString(NULL, base, NULL);
    
    /* construct path dropdown */
    popup_options = CFArrayCreateMutable(NULL, 0, NULL);
    
    /* find extension */
    extension = NULL;
    if (strlen(query->path)>1) {
        ptr = query->path + strlen(query->path)-1;
        while(ptr != query->path && ptr[0] != '/') {
            --ptr;
        }
        if (ptr) {
            extension = strchr(ptr, '.');
            if (extension) {
                snprintf(option, sizeof(option), "All %s Files", extension);
                param = CFStringCreateWithCString(NULL, option, kCFStringEncodingMacRoman);
                CFArrayAppendValue(popup_options, param);
            }
        }
    }
    
    /* build directory hierarchy menu */
    snprintf(option, sizeof(option), "Only %s", query->path);
    param = CFStringCreateWithCString(NULL, option, kCFStringEncodingMacRoman);
    CFArrayAppendValue(popup_options, param);
    
    path = strdup(query->path);
    int dir = 0;
    for(i = (int)strlen(path)-1; i>=0; --i) {
        if (path[i] == '/') {
            path[i+1] = 0;
            if (!dir) {
                snprintf(option, sizeof(option), "Only Files in %s", path);
                param = CFStringCreateWithCString(NULL, option, kCFStringEncodingMacRoman);
                CFArrayAppendValue(popup_options, param);
            }
            dir = 1;
            snprintf(option, sizeof(option), "Files Nested in %s", path);
            if (!strcmp(path, "/")) {
                strcpy(option, "Any Files");
            }
            param = CFStringCreateWithCString(NULL, option, kCFStringEncodingMacRoman);
            CFArrayAppendValue(popup_options, param);
        }
    }
    free(path);
    
    /* construct the popup descriptors */
    radio_options = CFArrayCreateMutable(NULL, 0, NULL);
    CFArrayAppendValue(radio_options, CFSTR("Once"));
    CFArrayAppendValue(radio_options, CFSTR("Until Quit"));
    CFArrayAppendValue(radio_options, CFSTR("Until Restart"));
    CFArrayAppendValue(radio_options, CFSTR("Forever"));
    
    const void* keys[] = {
        kCFUserNotificationAlertHeaderKey,
        kCFUserNotificationAlertMessageKey,
        kCFUserNotificationDefaultButtonTitleKey,
        kCFUserNotificationAlternateButtonTitleKey,
        kCFUserNotificationPopUpTitlesKey,
        kCFUserNotificationCheckBoxTitlesKey,
        kCFUserNotificationIconURLKey
    };
    
    const void* values[] = {
        CFStringCreateWithCString(NULL, displayName, kCFStringEncodingMacRoman),
        alert_str,
        CFSTR("Allow"),
        CFSTR("Deny"),
        popup_options,
        radio_options,
        icon
    };
    
    /* display the popup to the user and get a response */
    parameters = CFDictionaryCreate(0, keys, values, sizeof(keys)/sizeof(*keys), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    notification = CFUserNotificationCreate(kCFAllocatorDefault, 60, kCFUserNotificationPlainAlertLevel | CFUserNotificationPopUpSelection((extension == NULL) ? 0 : 1) | kCFUserNotificationUseRadioButtonsFlag | CFUserNotificationCheckBoxChecked(1), &err, parameters);
    response = CFUserNotificationReceiveResponse(notification, 60, &responseFlags);
    
    /* the rest of this rather lengthy subroutine is the response handling.
     * we'll grab the selected buttons and menu items and determine whether to
     * simply provide a reply to the driver, or to instruct it to add a rule to
     * its live policy list, or additionally write the rule to .flockflockrc
     */
    
    if (response != 0) {
        LOG("query timed out. denying access.");
        return EACCES;
    }
    
    /* allow / deny */
    if ((responseFlags & 0x03) == kCFUserNotificationDefaultResponse) {
        rule.ruleClass = kFlockFlockPolicyClassWhitelistAllMatching;
    } else if ((responseFlags & 0x03) == kCFUserNotificationAlternateResponse) {
        rule.ruleClass = kFlockFlockPolicyClassBlacklistAllMatching;
    } else {
        rule.ruleClass = kFlockFlockPolicyClassBlacklistAllMatching;
    }
    
    /* path selection */
    selectedIndex = (responseFlags >> 24);
    selectedElement = CFArrayGetValueAtIndex(popup_options, selectedIndex);
    if (selectedIndex < 2 + ((extension == NULL) ? 0 : 1)) {    /* exact paths / extensions */
        const char *path = (const char *)CFStringGetCStringPtr(selectedElement, kCFStringEncodingMacRoman);
        if (extension && selectedIndex == 0) {
            rule.ruleType = kFlockFlockPolicyTypePathSuffix;
            strncpy(rule.rulePath, extension, sizeof(rule.rulePath)-1);
        } else {
            if (!path) {
                memcpy(rule.rulePath, query->path, PATH_MAX);
                rule.ruleType = kFlockFlockPolicyTypeFilePath;
            } else {
                path = strchr(path, '/');
                rule.ruleType = kFlockFlockPolicyTypeFilePath;
                strncpy(rule.rulePath, path, sizeof(rule.rulePath)-1);
            }
        }
    } else {
        const char *path = (const char *)CFStringGetCStringPtr(selectedElement, kCFStringEncodingMacRoman);
        if (path == NULL || !strcmp(path, "Any Files")) {
            path = "/";
        } if (!path) {
            memcpy(rule.rulePath, query->path, PATH_MAX);
            rule.ruleType = kFlockFlockPolicyTypeFilePath;
        } else {
            path = strchr(path, '/');
            if (!path) {
                path = "/";
            }
        }
        strncpy(rule.rulePath, path, sizeof(rule.rulePath)-1);
        rule.ruleType = kFlockFlockPolicyTypePathPrefix;
        if (!strcmp(rule.rulePath, "/"))
            rule.rulePath[0] = 0; /* any */
    }
    
    strncpy(rule.processName, proc_path, sizeof(rule.processName)-1);
    if (responseFlags & CFUserNotificationCheckBoxChecked(1)) {
        rule.temporaryRule = true;
        rule.temporaryPid = query->pid;
    } else {
        rule.temporaryRule = false;
        rule.temporaryPid = 0;
    }
    
    CFRelease(parameters);
    CFRelease(popup_options);
    CFRelease(radio_options);
    CFRelease(alert_str);
    free(displayName);
    free(appPath);
    
    /* "Until Quite", "Until Restart" */
    if ((responseFlags & CFUserNotificationCheckBoxChecked(1))
        || (responseFlags & CFUserNotificationCheckBoxChecked(2))
        || (responseFlags & CFUserNotificationCheckBoxChecked(3)))
    {
        LOG("adding rule to driver");
        memcpy(&rule.skey, g_skey, SKEY_LEN);
        int kr = IOConnectCallMethod(g_driverConnection, kFlockFlockRequestAddClientRule, NULL, 0, &rule, sizeof(rule), NULL, NULL, NULL, NULL);
        if (kr == 0) {
            LOG("new rule added successfully");
        } else {
            LOG("error occured while adding new rule: %d", kr);
        }
        
        /* "Forever" */
        if (responseFlags & CFUserNotificationCheckBoxChecked(3)) {
            LOG("writing new rule to .flockflockrc");
            commitNewRuleToDisk(&rule);
        }
    }
    
    if (rule.ruleClass == kFlockFlockPolicyClassWhitelistAllMatching)
        return 0;
    
    return EACCES;
}


void *handlePolicyQuery(void *ptr)
{
    struct policy_query_msg *message = ptr;
    struct policy_response response;
    
    LOG("received policy query for pid %d target %s", message->query.pid, message->query.path);
    pthread_mutex_lock(&g_promptLock);
    memset(&response, 0, sizeof(struct policy_response));
    response.security_token = message->query.security_token;
    response.pid = message->query.pid;
    response.response_type = message->query_type;
    response.response = promptUserForPermission(&message->query);
    memcpy(&response.skey, g_skey, SKEY_LEN);
    
    pthread_mutex_lock(&g_sharedLock);
    IOConnectCallMethod(g_driverConnection, kFlockFlockRequestPolicyResponse, NULL, 0, &response, sizeof(struct policy_response), NULL, NULL, NULL, NULL);
    pthread_mutex_unlock(&g_sharedLock);
    pthread_mutex_unlock(&g_promptLock);
    
    free(ptr);
    pthread_exit(0);
    return(NULL);
}

void notificationCallback(CFMachPortRef unusedport, void *voidmessage, CFIndex size, void *info)
{
    struct ff_basic_msg *header = (struct ff_basic_msg *)voidmessage;
    
    LOG("received notification callback type %x", header->query_type);
    
    if (header->query_type == FFQ_ACCESS) {
        struct policy_query_msg *message = (struct policy_query_msg *)voidmessage;
        struct policy_query_msg *dup = malloc(sizeof(struct policy_query_msg));
        memcpy(dup, message, sizeof(struct policy_query_msg));
        pthread_t thread;
        pthread_create(&thread, NULL, handlePolicyQuery, dup);
        pthread_detach(thread);
    } else if (header->query_type == FFQ_SECKEY) {
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
                sleep(1);
                exit(-1);
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
    pthread_mutex_init(&g_promptLock, NULL);

    while(run) {
        startDriverComms();
        LOG("cycling");
        sleep(5);
    }
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
    pthread_mutex_destroy(&g_sharedLock);
    pthread_mutex_destroy(&g_promptLock);

    return 0;
}

