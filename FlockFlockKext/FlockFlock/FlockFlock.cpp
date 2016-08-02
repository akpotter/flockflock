//
//  FlockFlock.cpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include "FlockFlock.hpp"

#define super IOService
OSDefineMetaClassAndStructors(com_zdziarski_driver_FlockFlock, IOService);

#define KMOD_PATH "/Library/Extensions/FlockFlock.kext"
#define SUPPORT_PATH "/Library/Application Support/FlockFlock"
#define LAUNCHD_PATH "/Library/LaunchDaemons/com.zdziarski.FlockFlock.plist"
#define LAUNCHD_AGENT "com.zdziarski.FlockFlockUserAgent.plist"
#define CONFIG "/.flockflockrc"

static OSObject *com_zdziarski_driver_FlockFlock_provider;

extern "C" {
    int _mac_policy_register_internal(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep);
    int _mac_policy_unregister_internal(mac_policy_handle_t handlep);
}

static int _ff_vnode_check_exec_internal(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
}

static int _ff_vnode_check_open_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_open_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, acc_mode);
}

/* defend against attacks to myself */
int _ff_eval_vnode(struct vnode *vp)
{
    char target_path[MAXPATHLEN];
    int target_len = MAXPATHLEN;
    int ret = 0;
    char proc_name[MAXPATHLEN];
    
    if (!vp)
        return 0;
    
    if (! vn_getpath(vp, target_path, &target_len))
    {
        target_path[MAXPATHLEN-1] = 0;
        target_len = (int)strlen(target_path);
    
        proc_selfname(proc_name, MAXPATHLEN);
        printf("_ff_eval_vnode evaluating op for %s[%d] %s\n", proc_name, proc_selfpid(), target_path);
        
        if (!strncmp(target_path, KMOD_PATH, strlen(KMOD_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, SUPPORT_PATH, strlen(SUPPORT_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_PATH, strlen(LAUNCHD_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(LAUNCHD_AGENT)), LAUNCHD_AGENT, strlen(LAUNCHD_AGENT)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(CONFIG)), CONFIG, strlen(CONFIG)))
            ret = EACCES;
    }
    
    if (ret == EACCES) {
        printf("_ff_eval_vnode: denying operation target path %s\n", target_path);
    }
    return ret;
}

int _ff_vnode_check_unlink_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_write_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_rename_from_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_truncate_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_setowner_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, uid_t uid, gid_t gid)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_setmode_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, mode_t mode)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;

    return _ff_eval_vnode(vp);
}

bool com_zdziarski_driver_FlockFlock::initQueryContext(mach_query_context *context) {
    context->policy_lock = IOLockAlloc();
    context->reply_lock  = IOLockAlloc();
    return true;
}

void com_zdziarski_driver_FlockFlock::destroyQueryContext(mach_query_context *context) {
    IOLog("FlockFlock::destroyQueryContext: waiting for lock");
    IOLockLock(context->policy_lock);
    IOLockLock(context->reply_lock);
    
    IOLog("FlockFlock::destroyQueryContext: destroying locks");
    IOLockFree(context->policy_lock);
    IOLockFree(context->reply_lock);
}

bool com_zdziarski_driver_FlockFlock::init(OSDictionary *dict)
{
    bool res = super::init(dict);
    if (!res)
        return(res);
    
    IOLog("FlockFlock::init\n");

    com_zdziarski_driver_FlockFlock_provider = this;
    notificationPort   = MACH_PORT_NULL;
    lastPolicyAdded    = NULL;
    policyRoot         = NULL;
    pid_root           = NULL;
    filterActive       = false;
    shouldStop         = false;
    userAgentPID       = 0;
    lock     = IOLockAlloc();
    portLock = IOLockAlloc();
    
    initQueryContext(&policyContext);
    
    setProperty("IOUserClientClass", "com_zdziarski_driver_FlockFlockClient");
    return res;
}

IOService *com_zdziarski_driver_FlockFlock::probe(IOService *provider, SInt32* score)
{
    IOLog("IOKitTest::probe\n");

    IOService *res = super::probe(provider, score);
    return res;
}

bool com_zdziarski_driver_FlockFlock::start(IOService *provider)
{
    IOLog("IOKitTest::start\n");

    bool res = super::start(provider);
    if (res != true) {
        IOLog("FlockFlock::start failed: IOService::start failed\n");
        return res;
    }

    super::registerService();
    IOLog("FlockFlock::start successful\n");
    startProcessMonitor();

    return true;
}

bool com_zdziarski_driver_FlockFlock::startProcessMonitor()
{
    bool success = false;
    
    execHandle = { 0 };
    execOps = {
        .mpo_vnode_check_exec   = _ff_vnode_check_exec_internal,
//        .mpo_vnode_check_unlink = _ff_vnode_check_unlink_internal,
//        .mpo_vnode_check_write  = _ff_vnode_check_write_internal,
//        .mpo_vnode_check_setmode = _ff_vnode_check_setmode_internal,
//        .mpo_vnode_check_setowner = _ff_vnode_check_setowner_internal,
//        .mpo_vnode_check_truncate    = _ff_vnode_check_truncate_internal,
//        .mpo_vnode_check_rename_from = _ff_vnode_check_rename_from_internal
    };
    execConf = {
        .mpc_name            = "FF Process Monitor and Defenses",
        .mpc_fullname        = "FlockFlock Kernel-Mode Process Monitor and Defenses",
        .mpc_labelnames      = NULL,
        .mpc_labelname_count = 0,
        .mpc_ops             = &execOps,
        .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK, /* disable MPC_LOADTIME_FLAG_UNLOADOK to prevent unloading */
        .mpc_field_off       = NULL,
        .mpc_runtime_flags   = 0,
        .mpc_list            = NULL,
        .mpc_data            = NULL
    };
    
    int mpr = _mac_policy_register_internal(&execConf, &execHandle);
    if (!mpr ) {
        success = true;
        IOLog("FlockFlock::startProcessMonitor: process monitor started successfully\n");
    } else {
        IOLog("FlockFlock::startProcessMonitor: an error occured while starting the process monitor: %d\n", mpr);
    }
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopProcessMonitor()
{
    bool success = false;
    kern_return_t kr = _mac_policy_unregister_internal(execHandle);
    if (kr == KERN_SUCCESS) {
        success = true;
        IOLog("FlockFlock::stopFilter: process monitor stopped successfully\n");
    } else {
        IOLog("FlockFlock::stopFilter: an error occured while stopping the process monitor: %d\n", kr);
    }
    return success;
}

bool com_zdziarski_driver_FlockFlock::startFilter()
{
    bool success = false;
    
    IOLockLock(lock);
    if (filterActive == false) {
        policyHandle = { 0 };
        policyOps = {
            .mpo_vnode_check_open = _ff_vnode_check_open_internal
        };
        policyConf = {
            .mpc_name            = "FF File Monitor",
            .mpc_fullname        = "FlockFlock Kernel-Mode File Monitor",
            .mpc_labelnames      = NULL,
            .mpc_labelname_count = 0,
            .mpc_ops             = &policyOps,
            .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK, /* disable MPC_LOADTIME_FLAG_UNLOADOK to prevent unloading
                                       *
                                       * NOTE: setting this to 0 CAUSES A KERNEL PANIC AND REBOOT if the module is
                                       *     unloaded. This is how we defend against malware unloading it. */
            .mpc_field_off       = NULL,
            .mpc_runtime_flags   = 0,
            .mpc_list            = NULL,
            .mpc_data            = NULL
        };

        int mpr = _mac_policy_register_internal(&policyConf, &policyHandle);
        if (!mpr ) {
            filterActive = true;
            success = true;
            IOLog("FlockFlock::startFilter: filter started successfully\n");
        } else {
            IOLog("FlockFlock::startFilter: an error occured while starting the filter: %d\n", mpr);
        }
    }
    IOLockUnlock(lock);
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopFilter()
{
    bool success = false;
    IOLockLock(lock);
    if (filterActive == true) {
        kern_return_t kr = _mac_policy_unregister_internal(policyHandle);
        if (kr == KERN_SUCCESS) {
            filterActive = false;
            success = true;
            IOLog("FlockFlock::stopFilter: filter stopped successfully\n");
        } else {
            IOLog("FlockFlock::stopFilter: an error occured while stopping the filter: %d\n", kr);
        }
    }
    IOLockUnlock(lock);
    return success;
}

void com_zdziarski_driver_FlockFlock::clearAllRules()
{
    IOLog("IOKitTest::clearAllRules\n");

    IOLockLock(lock);
    FlockFlockPolicy rule = policyRoot;
    while(rule) {
        FlockFlockPolicy next = rule->next;
        IOFree(rule, sizeof(*rule));
        rule = next;
    }
    policyRoot = NULL;
    lastPolicyAdded = NULL;
    IOLockUnlock(lock);
}

kern_return_t com_zdziarski_driver_FlockFlock::addClientPolicy(FlockFlockClientPolicy clientRule)
{
    FlockFlockPolicy rule;
    
    IOLog("IOKitTest::addClientPolicy\n");

    if (! clientRule)
        return KERN_INVALID_VALUE;
    
    IOLockLock(lock);
    
    rule = (FlockFlockPolicy) IOMalloc(sizeof(struct _FlockFlockPolicy));
    if (!rule) {
        IOLockUnlock(lock);
        return KERN_MEMORY_ERROR;
    }
    bcopy(clientRule, &rule->data, sizeof(*clientRule));
    rule->next = NULL;
    
    if (lastPolicyAdded == NULL)
        policyRoot = rule;
    else
        lastPolicyAdded->next = rule;
    
    lastPolicyAdded = rule;

    IOLockUnlock(lock);
    return KERN_SUCCESS;
}

bool com_zdziarski_driver_FlockFlock::setMachPort(mach_port_t port)
{
    bool ret = false;
    IOLockLock(portLock);
    if (notificationPort == MACH_PORT_NULL) {
        notificationPort = port;
        ret = true;
    }
    IOLockUnlock(portLock);
    return ret;
}

void com_zdziarski_driver_FlockFlock::clearMachPort() {
    IOLockLock(portLock);
    notificationPort = MACH_PORT_NULL;
    IOLockUnlock(portLock);
}

IOReturn com_zdziarski_driver_FlockFlock::setProperties(OSObject* properties)
{
    OSDictionary *propertyDict;
    
    propertyDict = OSDynamicCast(OSDictionary, properties);
    if (propertyDict != NULL)
    {
        OSObject *theValue;
        OSString *theString;
        
        theValue = propertyDict->getObject("pid");
        theString = OSDynamicCast(OSString, theValue);
        userAgentPID = (uint32_t)strtol(theString->getCStringNoCopy(), NULL, 0);
        if (userAgentPID) {
            printf("FlockFlock::setProperties: set pid to %d\n", userAgentPID);
            return kIOReturnSuccess;
        }
    }
    
    return kIOReturnUnsupported;
}

bool com_zdziarski_driver_FlockFlock::receivePolicyResponse(struct policy_response *response, struct mach_query_context *context)
{
    bool success = false;
    bool lock = IOLockTryLock(context->reply_lock);
    
    while(lock == false && shouldStop == false && notificationPort != MACH_PORT_NULL) {
        IOSleep(100);
        lock = IOLockTryLock(context->reply_lock);
    }
    
    if (lock == false) { /* filter was shut down */
        IOLockUnlock(context->reply_lock);
        IOLockUnlock(context->policy_lock);
        return false;
    }
    
    // IOLockLock(context->reply_lock);
    if (context->security_token == context->response.security_token) {
        bcopy(&context->response, response, sizeof(struct policy_response));
        success = true;
    } else {
        printf("FlockFlock::receive_policy_response: policy response failed (invalid security token)\n");
    }
    
    IOLockUnlock(context->policy_lock);
    IOLockUnlock(context->reply_lock);
    return true;
}

int com_zdziarski_driver_FlockFlock::sendPolicyQuery(struct policy_query *query, struct mach_query_context *context, bool lock) {
    int ret;
    
    context->message.header.msgh_remote_port = notificationPort;
    context->message.header.msgh_local_port = MACH_PORT_NULL;
    context->message.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    context->message.header.msgh_size = sizeof(context->message);
    context->message.header.msgh_id = 0;
    
    query->security_token = random();
    bcopy(query, &context->message.query, sizeof(struct policy_query));
    
    if (lock == true) {
        IOLockLock(context->policy_lock);
        IOLockLock(context->reply_lock);
    }
    ret = mach_msg_send_from_kernel(&context->message.header, sizeof(context->message));
    if (ret) {
        IOLockUnlock(context->policy_lock);
        IOLockUnlock(context->reply_lock);
        return ret;
    }
    
    context->security_token = query->security_token;
    return ret;
}

int com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->userAgentPID;
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_exec(cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_exec(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    char proc_path[MAXPATHLEN];
    int proc_len = MAXPATHLEN;
    int pid = proc_selfpid();
    int ret;

    printf("ff_vnode_check_exec: looking up process path for pid %d\n", pid);
    ret = vn_getpath(vp, proc_path, &proc_len); /* path to proc binary */
    if (ret != 0) {
        printf("ff_vnode_check_exec: lookup failed for pid %d, error %d\n", pid, ret);
        return 0;
    }
    
    proc_path[MAXPATHLEN-1] = 0;
    proc_len = (int)strlen(proc_path);
    IOLog("ff_vnode_check_exec: process path for pid %d is %s len %d\n", pid, proc_path, proc_len);

    /* Shorten applications down to their .app package */
    if (!strncmp(proc_path, "/Applications/", 14)) {
        char *dot = strchr(proc_path, '.');
        if (dot && !strncmp(dot, ".app/", 5)) {
            dot[5] = 0;
        }
    }
    
    IOLockLock(lock);
    if (proc_len > 0) {
        struct pid_path *p = (struct pid_path *)IOMalloc(sizeof(struct pid_path));
        if (p) {
            p->pid = pid;
            p->next = NULL;
            strncpy(p->path, proc_path, PATH_MAX-1);
            if (! pid_root ) {
                pid_root = p;
            } else {
                struct pid_path *ptr = NULL, *next = pid_root;
                while(next) {
                    if (next->pid == pid) {
                        strncpy(next->path, proc_path, PATH_MAX-1);
                        IOFree(p, sizeof(struct pid_path));
                        IOLockUnlock(lock);
                        return 0;
                    }
                    ptr = next;
                    next = next->next;
                }
                if (ptr)
                    ptr->next = p;
            }
        }
    }
    IOLockUnlock(lock);
    return 0;
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_open_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_open(cred, vp, label, acc_mode);
}

int com_zdziarski_driver_FlockFlock::ff_evaluate_vnode_check_open(struct policy_query *query)
{
    bool blacklisted = false, whitelisted = false;
    int proc_len = (int)strlen(query->process_name);
    int path_len = (int)strlen(query->path);
    
    IOLockLock(lock);
    FlockFlockPolicy rule = policyRoot;
    while(rule) {
        size_t rpath_len = strlen(rule->data.rulePath);
        bool match = true;
        
        /* temporary rules must match the pid of the current operation */
        if (rule->data.temporaryRule && rule->data.temporaryPid != query->pid)
            match = false;
        
        /* rule out any process-specific rules that don't match */
        if (rule->data.processName[0]) {
            size_t rproc_len = strlen(rule->data.processName);
            if (rule->data.processName[rproc_len-1] == '/') { /* directory prefix */
                if (strncmp(query->process_name, rule->data.processName, rproc_len)) {
                    match = false;
                }
            } else if (strcmp(query->process_name, rule->data.processName)) { /* full path */
                match = false;
            }
        }
        
        /* rule out any path rules that don't match */
        if (rpath_len) {
            switch(rule->data.ruleType) {
                case(kFlockFlockPolicyTypePathPrefix):
                    if (strncasecmp(rule->data.rulePath, query->path, rpath_len))
                        match = false;
                    break;
                case(kFlockFlockPolicyTypeFilePath):
                    if (rule->data.rulePath[rpath_len-1] == '/') { /* directory prefix */
                        if (strncmp(query->path, rule->data.rulePath, rpath_len)) {
                            match = false;
                        }
                        if (path_len > rpath_len) { /* don't apply to nested folders */
                            if (strchr(query->path + rpath_len, '/')) {
                                match = false;
                            }
                        }
                    } else if (strcasecmp(rule->data.rulePath, query->path)) { /* full path */
                        match = false;
                    }
                    break;
                case(kFlockFlockPolicyTypePathSuffix):
                    if (path_len <= rpath_len)
                        match = false;
                    if (strcasecmp(query->path + (path_len - rpath_len), rule->data.rulePath))
                        match = false;
                    break;
                default:
                    break;
            }
        }
        
        switch(rule->data.ruleClass) {
            case(kFlockFlockPolicyClassBlacklistAllMatching):
                if (match)
                    blacklisted = true;
                break;
            case(kFlockFlockPolicyClassWhitelistAllMatching):
                if (match)
                    whitelisted = true;
                break;
            case(kFlockFlockPolicyClassBlacklistAllNotMatching):
                if (! match)
                    blacklisted = true;
                break;
            case(kFlockFlockPolicyClassWhitelistAllNotMatching):
                if (! match)
                    whitelisted = true;
            default:
                break;
                
        }

        rule = rule->next;
    }
    IOLockUnlock(lock);
    
    if (whitelisted == true)
        return 0;
    if (blacklisted == true) {
        IOLog("FlockFlock::ff_vnode_check_open: deny open of %s by pid %d (%s) wht %d blk %d\n", query->path, query->pid, query->process_name, whitelisted, blacklisted);
        
        return EACCES;
    }
    
    IOLog("FlockFlock::ff_vnode_check_open: ask open of %s by pid %d (%s) wht %d blk %d\n", query->path, query->pid, query->process_name, whitelisted, blacklisted);

    return EAUTH;
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_open(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    struct policy_query *query;
    struct policy_response response;
    char target[PATH_MAX];
    char proc_path[PATH_MAX];
    int buflen = PATH_MAX;
    int pid = proc_selfpid();
    struct pid_path *ptr;
    
    if (vp == NULL)             /* something happened */
        return 0;
    if (vnode_isdir(vp))        /* always allow directories, we only work with files */
        return 0;
    if (userAgentPID == pid) {  /* friendlies */
        IOLog("allowing user agent pid access to %s\n", target);
        return 0;
    }
    
    /* build the policy query */

    query = (struct policy_query *)IOMalloc(sizeof(struct policy_query));
    query->pid = pid;
    query->query_type = FFQ_ACCESS;
    query->path[0] = 0;
    if (! vn_getpath(vp, query->path, &buflen))
        query->path[PATH_MAX-1] = 0;
    
    /* pull out the proc path */
    
    IOLockLock(lock);
    
    ptr = pid_root;
    proc_path[0] = 0;
    
    while(ptr) {
        if (ptr->pid == pid) {
            strncpy(proc_path, ptr->path, PATH_MAX-1);
            break;
        }
        ptr = ptr->next;
    }
    
    IOLockUnlock(lock);
    
    if (proc_path[0]) {
        strncpy(query->process_name, proc_path, PATH_MAX);
        printf("ff_vnode_check_open: process path for pid %d is %s\n", pid, proc_path);
    } else {
        printf("ff_vnode_check_open: failed to locate process path for pid %d\n", pid);
        IOFree(query, sizeof(struct policy_query));
        return 0;
    }
    
    int ret = ff_evaluate_vnode_check_open(query);
    if (ret == EAUTH) {
        IOLockLock(policyContext.policy_lock);
        IOLockLock(policyContext.reply_lock);

        /* re-evaluate in case the rule was just added */
        int ret2 = ff_evaluate_vnode_check_open(query);
        if (ret2 != EAUTH) {
            IOLockUnlock(policyContext.policy_lock);
            IOLockUnlock(policyContext.reply_lock);
            ret = ret2;
        } else {
            /* sent the query, wait for response */

            if (sendPolicyQuery(query, &policyContext, false) == 0) {
                printf("FlockFlock::ff_node_check_option: sent policy query successfully, waiting for reply\n");
                bool success = receivePolicyResponse(&response, &policyContext);
                if (success) {
                    ret = response.response;
                }
            } else {
                printf("FlockFlock::ff_vnode_check_open: user agent is unavailable to prompt user, denying access\n");
                ret = EACCES;
            }
        }
    }
    
    IOFree(query, sizeof(struct policy_query));
    return ret;
}

void com_zdziarski_driver_FlockFlock::stop(IOService *provider)
{
    bool active;
    IOLog("FlockFlock::stop\n");
    
    shouldStop = true;
    
    IOLockLock(lock);
    active = filterActive;
    IOLockUnlock(lock);
    
    stopProcessMonitor();

    if (active == true) {
        stopFilter();
    }
        
    super::stop(provider);
}

void com_zdziarski_driver_FlockFlock::free(void)
{
    struct pid_path *ptr=NULL, *next;
    IOLog("IOKitTest::free\n");
    clearAllRules();
    IOLockFree(lock);
    IOLockFree(portLock);
    
    destroyQueryContext(&policyContext);
    ptr = pid_root;
    while(ptr) {
        next = ptr->next;
        IOFree(ptr, sizeof(struct pid_path));
        ptr = next;
    }

    super::free();
}
