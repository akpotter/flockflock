//
//  FlockFlock.cpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include <mach/task.h>
#include "FlockFlock.hpp"
#include "mac_policy_callbacks.h"

#define super IOService
OSDefineMetaClassAndStructors(com_zdziarski_driver_FlockFlock, IOService);

/* mac policy callouts have to be done in C land, so we store a singleton
 * of our driver instance and call back into it later on when the policy 
 * receives C-land callbacks */

OSObject *com_zdziarski_driver_FlockFlock_provider;

extern "C" {
    int _mac_policy_register_internal(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep);
    int _mac_policy_unregister_internal(mac_policy_handle_t handlep);
}

void _kauth_listen_scope_internal(void *ptr, wait_result_t w)
{
    IOLog("_kauth_listen_scope_internal");
    com_zdziarski_driver_FlockFlock *provider = (com_zdziarski_driver_FlockFlock *)ptr;
    provider->kauthListener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &_ff_kauth_callback_internal, NULL);
}

bool com_zdziarski_driver_FlockFlock::init(OSDictionary *dict)
{
    bool res = super::init(dict);
    if (!res)
        return(res);
    
    IOLog("FlockFlock::init\n");

    com_zdziarski_driver_FlockFlock_provider = this;
    agentNotificationPort   = MACH_PORT_NULL;
    daemonNotificationPort  = MACH_PORT_NULL;
    lastPolicyAdded    = NULL;
    policyRoot         = NULL;
    pid_cache           = NULL;
    execve_cache       = NULL;
    pid_map            = NULL;
    map_last_insert    = NULL;
    create_cache       = NULL;
    create_last_insert = NULL;
    filterActive       = false;
    filterInitialized  = false;
    shouldStop         = false;
    userAgentPID       = 0;
    daemonPID          = 0;
    lock               = IOLockAlloc();
    bzero(skey_a, sizeof(skey_a));
    bzero(skey_d, sizeof(skey_a));
    
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
    

    kern_return_t result;
    result = kernel_thread_start(_kauth_listen_scope_internal, this, &kauth_thread);
    
    // kauthListener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &_ff_kauth_callback_internal, NULL);
    
    startPersistence();

    return true;
}

/* persistent policies; these policies are always active, even if the 
 * filter is disabled, and are used to protect the core FlockFlock
 * components. when the filter is active, some of them also protect
 * user data files from unwanted modifications */

bool com_zdziarski_driver_FlockFlock::startPersistence()
{
    bool success = false;
    
    persistenceHandle = { 0 };
    persistenceOps = {
        .mpo_cred_label_update_execve = _ff_cred_label_update_execve_internal,
        .mpo_cred_label_associate_fork = _ff_cred_label_associate_fork_internal,
        .mpo_vnode_check_truncate = _ff_vnode_check_truncate_internal,
        .mpo_vnode_check_write  = _ff_vnode_check_write_internal,
        .mpo_vnode_check_exchangedata = _ff_check_exchangedata_internal,
        .mpo_vnode_check_unlink = _ff_vnode_check_unlink_internal,
        .mpo_vnode_notify_create = _ff_vnode_notify_create_internal,
        .mpo_vnode_check_rename = _ff_check_vnode_rename_internal,
        .mpo_vnode_check_create = _ff_vnode_check_create_internal,

        // .mpo_vnode_check_exec = _ff_vnode_check_exec_internal, /* replaced by kauth */
#ifdef PERSISTENCE
        .mpo_vnode_check_setmode = _ff_vnode_check_setmode_internal,
        .mpo_vnode_check_setowner = _ff_vnode_check_setowner_internal,
        .mpo_vnode_check_rename_from = _ff_vnode_check_rename_from_internal,
        .mpo_vnode_check_rename_to = _ff_vnode_check_rename_to_internal,
        .mpo_proc_check_signal = _ff_vnode_check_signal_internal,
#endif
    };
    
    persistenceConf = {
        .mpc_name            = "FF Persistence-Mode",
        .mpc_fullname        = "FlockFlock Process Monitor and Persistence Services",
        .mpc_labelnames      = NULL,
        .mpc_labelname_count = 0,
        .mpc_ops             = &persistenceOps,
        .mpc_loadtime_flags  =
#ifdef HARD_PERSISTENCE
        0, /* disable MPC_LOADTIME_FLAG_UNLOADOK to prevent unloading
            *
            * NOTE: setting this to 0 CAUSES A KERNEL PANIC AND REBOOT if the module is
            *     unloaded. This is part of persistence */
#else
        MPC_LOADTIME_FLAG_UNLOADOK,
#endif
        .mpc_field_off       = NULL,
        .mpc_runtime_flags   = 0,
        .mpc_list            = NULL,
        .mpc_data            = NULL
    };
    
    int mpr = _mac_policy_register_internal(&persistenceConf, &persistenceHandle);
    if (!mpr ) {
        success = true;
        IOLog("FlockFlock::startProcessMonitor: persistence started successfully\n");
    } else {
        IOLog("FlockFlock::startProcessMonitor: an error occured while starting persistence: %d\n", mpr);
    }
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopPersistence()
{
    
    bool success = false;
    kern_return_t kr = _mac_policy_unregister_internal(persistenceHandle);
    if (kr == KERN_SUCCESS) {
        success = true;
        IOLog("FlockFlock::stopFilter: persistence stopped successfully\n");
    } else {
        IOLog("FlockFlock::stopFilter: an error occured while stopping persistence: %d\n", kr);
    }
    return success;
}

/* generate a security ticket (skey) for the daemon+agent to establish a trusted
 * relationship between user space and kernel space. this is established when
 * the daemon first runs at login, and prevents another daemon from masquerading
 * as it to disable services. if the daemon crashes, and the driver is
 * compiled with -DPERSISTENCE, the user will need to reboot in order to
 * reestablish this trusted connection, to prevent a malicious daemon from
 * simply hijacking that connection. */

bool com_zdziarski_driver_FlockFlock::genTicket(bool is_daemon)
{
    char proc_path[PATH_MAX];
    pid_info *ptr;
    bool success = false;
    int r;
    
    IOLockLock(lock);
    
    IOLog("FlockFlock::genTicket\n");
    
    /* pull out the proc path from cache */
    ptr = pid_cache;
    proc_path[0] = 0;
    while(ptr) {
        if (ptr->pid == proc_selfpid()) {
            strncpy(proc_path, ptr->path, PATH_MAX-1);
            break;
        }
        ptr = ptr->next;
    }
    IOLog("FlockFlock::genTicket: client path is '%s'\n", proc_path);
    
    if (   strncmp(proc_path, DAEMON_PATH, PATH_MAX)
        && strncmp(proc_path, APP_PATH_FOLDER, PATH_MAX)
        && strncmp(proc_path, APP_BINARY, PATH_MAX))
    {
        IOLog("FlockFlock::genTicket: invalid path '%s' daemon mode: %d\n", proc_path, is_daemon);
#ifdef PERSISTENCE
        if (is_daemon) {
            daemonNotificationPort = MACH_PORT_NULL;
        } else {
            agentNotificationPort = MACH_PORT_NULL;
        }
        IOLockUnlock(lock);
        return false;
#endif
    }
    
    /* generate a security key and send it to the user client. the driver will only do
     * this once and will need to be rebooted or unloaded in order for a client to connect
     * and authenticate again (if persistence is turned on)
     */
    
    r = genSecurityKey(is_daemon);
    if (! r)
        success = true;
    
    IOLockUnlock(lock);
    
    return success;
}

/* the main policy filter; this is used to control access to open any file
 * on the system. we unload this when the agent is disabled to prevent 
 * unnecessary (although minimal) cpu utilization */

bool com_zdziarski_driver_FlockFlock::startFilter()
{
    bool success = false;
    
    IOLockLock(lock);
    if (filterActive == false) {
        policyHandle = { 0 };
        policyOps = {
            .mpo_vnode_check_open = _ff_vnode_check_open_internal,
        };
        policyConf = {
            .mpc_name            = "FF File Monitor",
            .mpc_fullname        = "FlockFlock Kernel-Mode File Monitor",
            .mpc_labelnames      = NULL,
            .mpc_labelname_count = 0,
            .mpc_ops             = &policyOps,
            .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK,
            .mpc_field_off       = NULL,
            .mpc_runtime_flags   = 0,
            .mpc_list            = NULL,
            .mpc_data            = NULL
        };

        int mpr = _mac_policy_register_internal(&policyConf, &policyHandle);
        if (!mpr) {
            filterActive = true;
            success = true;
            IOLog("FlockFlock::startFilter: filter started successfully\n");
        } else {
            IOLog("FlockFlock::startFilter: an error occured while starting the filter: %d\n", mpr);
        }
    } else {
        success = true;
    }
    
    if (success == true)
        filterInitialized = true;
    IOLockUnlock(lock);
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopFilter(unsigned char *key)
{
    bool success = false;
    
    if (memcmp(&skey_a, key, SKEY_LEN)) {
        IOLog("FlockFlock::stopFilter: skey failure\n");
        return false;
    }
    
    sendStopNotice();
    
    IOLockLock(lock);
    if (filterActive == true) {
        IOLog("FlockFlock::stopFilter unloading policy\n");
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

bool com_zdziarski_driver_FlockFlock::isFilterActive()
{
    return filterActive;
}

void com_zdziarski_driver_FlockFlock::clearAllRules(unsigned char *key)
{
    IOLog("FlockFlock::clearAllRules\n");

    if (memcmp(&skey_d, key, SKEY_LEN)) {
        IOLog("FlockFlock::clearAllRules: skey failure\n");
        return;
    }
    
    IOLog("FlockFlock::clearAllRules: clearing all rules\n");
    
    IOLockLock(lock);
    FlockFlockPolicy rule = policyRoot;
    while(rule) {
        FlockFlockPolicy next = rule->next;
        IOFree(rule, sizeof(struct _FlockFlockPolicy));
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

    if (memcmp(skey_d, &clientRule->skey, SKEY_LEN)) {
        IOLog("FlockFlock::addClientPolicy: skey failure\n");
        return KERN_NO_ACCESS;
    }
    
    if (! clientRule)
        return KERN_INVALID_VALUE;
    
    rule = (FlockFlockPolicy) IOMalloc(sizeof(struct _FlockFlockPolicy));
    if (!rule) {
        return KERN_MEMORY_ERROR;
    }
    bcopy(clientRule, &rule->data, sizeof(*clientRule));
    rule->next = NULL;
    
    IOLockLock(lock);
    if (lastPolicyAdded == NULL)
        policyRoot = rule;
    else
        lastPolicyAdded->next = rule;
    lastPolicyAdded = rule;
    IOLockUnlock(lock);
    
    return KERN_SUCCESS;
}

bool com_zdziarski_driver_FlockFlock::setMachPort(mach_port_t port, bool is_daemon)
{
    bool ret = false;
    IOLockLock(lock);
    if (is_daemon == false) {
        if (agentNotificationPort == MACH_PORT_NULL) {
            agentNotificationPort = port;
            ret = true;
        }
    } else {
        if (daemonNotificationPort == MACH_PORT_NULL) {
            daemonNotificationPort = port;
            ret = true;
        }
    }
    
    IOLockUnlock(lock);
    return ret;
}

void com_zdziarski_driver_FlockFlock::clearMachPort() {
    IOLockLock(lock);
    agentNotificationPort = MACH_PORT_NULL;
    IOLockUnlock(lock);
}

bool com_zdziarski_driver_FlockFlock::setAgentPID(uint64_t pid, unsigned char *key)
{
    
    if (memcmp(&skey_a, key, SKEY_LEN)) {
        IOLog("FlockFlock::setAgentPID: skey failure\n");
        return false;
    }
    
    IOLockLock(lock);
    userAgentPID = (int)pid;
    IOLockUnlock(lock);
    
    IOLog("FlockFlock::setAgentPID set pid to %d\n", (int)pid);

    return true;
}

bool com_zdziarski_driver_FlockFlock::setDaemonPID(uint64_t pid, unsigned char *key)
{
    
    if (memcmp(&skey_d, key, SKEY_LEN)) {
        IOLog("FlockFlock::setDaemonPID: skey failure\n");
        return false;
    }
    
    IOLockLock(lock);
    daemonPID = (int)pid;
    IOLockUnlock(lock);
    
    IOLog("FlockFlock::setDaemonPID set pid to %d\n", (int)pid);
    
    return true;
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

bool com_zdziarski_driver_FlockFlock::receivePolicyResponse(struct policy_response *response, struct mach_query_context *context)
{
    bool success = false;
    bool queryLock = IOLockTryLock(context->reply_lock);
    mach_port_t machNotificationPort;
    bool stop;
    
    IOLockLock(lock);
    stop = shouldStop;
    machNotificationPort = daemonNotificationPort;
    IOLockUnlock(lock);
    
    while(queryLock == false && stop == false && daemonNotificationPort != MACH_PORT_NULL) {
        IOSleep(100);
        
        IOLockLock(lock);
        stop = shouldStop;
        machNotificationPort = daemonNotificationPort;
        IOLockUnlock(lock);
        
        queryLock = IOLockTryLock(context->reply_lock);
    }
    
    if (queryLock == false) { /* filter was shut down or client disconnceted */
        IOLockUnlock(context->reply_lock);
        IOLockUnlock(context->policy_lock);
        return false;
    }
    
    if (memcmp(&skey_d, &context->response.skey, SKEY_LEN)) {
        IOLog("FlockFlock::receivePolicyResponse: skey failure\n");
        IOLockUnlock(context->reply_lock);
        IOLockUnlock(context->policy_lock);
        return false;
    }
    
    if (context->security_token == context->response.security_token) {
        bcopy(&context->response, response, sizeof(struct policy_response));
        success = true;
    } else {
        IOLog("FlockFlock::receive_policy_response: policy response failed (invalid security token)\n");
    }
    
    IOLockUnlock(context->policy_lock);
    IOLockUnlock(context->reply_lock);
    return true;
}

int com_zdziarski_driver_FlockFlock::sendPolicyQuery(struct policy_query *query, struct mach_query_context *context, bool lock)
{
    int ret;
    
    if (lock == true) {
        IOLockLock(context->policy_lock);
        IOLockLock(context->reply_lock);
    }
    
    context->message.header.msgh_remote_port = daemonNotificationPort;
    context->message.header.msgh_local_port = MACH_PORT_NULL;
    context->message.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    context->message.header.msgh_size = sizeof(context->message);
    context->message.header.msgh_id = 0;
    context->message.query_type = FFQ_ACCESS;

    query->security_token = random();
    bcopy(query, &context->message.query, sizeof(struct policy_query));

    ret = mach_msg_send_from_kernel(&context->message.header, sizeof(context->message));
    if (ret) {
        IOLockUnlock(context->policy_lock);
        IOLockUnlock(context->reply_lock);
        return ret;
    }
    
    context->security_token = query->security_token;
    return ret;
}

/* when the user client first connects, generate a random security key and 
 * send it over via a mach message; the client will have to send this key
 * with any control queries to authenticate. */

int com_zdziarski_driver_FlockFlock::genSecurityKey(bool is_daemon) {
    struct skey_msg message;
    int ret, i;
    unsigned char skey[SKEY_LEN];
    
    IOLog("FlockFlock::genSecurityKey\n");
    
    /* -DPERSISTENCE: Assuming a secure boot chain, will not allow the daemon to reconnect if it
     * terminates, so that another process cannot masquerade as it. This is good defense against a
     * targeted attack specifically against FlockFlock, but also requires a reboot if the daemon
     * crashes. */
    
#ifdef PERSISTENCE
    if (is_daemon == true && skey_d[0] != 0) {
        IOLog("FlockFlock::genSecurityKey: error: key already exists\n");
        return EACCES;
    }
#endif

    for(i = 0; i < SKEY_LEN; ++i) {
        skey[i] = (unsigned char)random() % 0xff;
    }
    if (skey[i] == 0)
        skey[i] = 1; /* 0 = uninitialized */
    
    if (is_daemon == true) {
        bcopy(skey, skey_d, SKEY_LEN);
    } else {
        bcopy(skey, skey_a, SKEY_LEN);
    }
    
    if (is_daemon == true) {
        message.header.msgh_remote_port = daemonNotificationPort;

    } else {
        message.header.msgh_remote_port = agentNotificationPort;
    }
    message.header.msgh_local_port = MACH_PORT_NULL;
    message.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    message.header.msgh_size = sizeof(message);
    message.header.msgh_id = 0;
    message.query_type = FFQ_SECKEY;
    bcopy(skey, message.skey, SKEY_LEN);
    
    ret = mach_msg_send_from_kernel(&message.header, sizeof(message));
    IOLog("FlockFlock::genSecurityKey: send returned %d\n", ret);
    return ret;
}

/* c-land static hooks: since the policy callbacks live in c land, we need a way
 * to re-enter the driver provider's class, so we do it by means of static class
 * methods, which are passed a pointer to our singleton. they, in turn, call
 * the instance method of the class, or return an instance variable. */

bool com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(OSObject *provider) {
    bool active;
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    IOLockLock(me->lock);
    active = me->filterActive;
    IOLockUnlock(me->lock);
    return active;
}

int com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    pid_t pid;
    IOLockLock(me->lock);
    pid = me->userAgentPID;
    IOLockUnlock(me->lock);
    return pid;
}

int com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(OSObject *provider) {
    pid_t pid;
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    IOLockLock(me->lock);
    pid = me->daemonPID;
    IOLockUnlock(me->lock);
    return pid;
}

bool com_zdziarski_driver_FlockFlock::ff_should_persist(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    IOLockLock(me->lock);
    if (me->filterActive == false && me->filterInitialized == true) {
        IOLockUnlock(me->lock);
        return false;
    }
    IOLockUnlock(me->lock);
    return true;
}

/* on mpo_vnode_notify_create, we maintain a cache of files created by the process
 * so we can allow those files to be modified or deleted. any files that were not
 * created by the process are checked against the user's policy, and ultimately
 * prompt the user for permission if necessary, just like a read operation would */

int com_zdziarski_driver_FlockFlock::ff_vnode_notify_create_static(OSObject *provider, kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_notify_create(cred, mp, mntlabel, dvp, dlabel, vp, vlabel, cnp);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_notify_create(kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp)
{
    char path[PATH_MAX] = { 0 };
    int path_len = PATH_MAX;
    
    if (vn_getpath(vp, path, &path_len) == KERN_SUCCESS) {
        struct created_file *file = (struct created_file *)IOMalloc(sizeof(struct created_file));

        if (!file)
            return 0;
        bcopy(path, file->path, PATH_MAX);
        file->pid = proc_selfpid();
        file->next = NULL;
        
        IOLockLock(lock);
        if (create_cache == NULL)
            create_cache = file;
        else
            create_last_insert->next = file;
        create_last_insert = file;
        IOLockUnlock(lock);
    }

    return 0;
}

/* lookup function for the create cache, used by ff_vnode_check_oper */
bool com_zdziarski_driver_FlockFlock::ff_create_cache_lookup(pid_t pid, const char *path)
{
    IOLockLock(lock);
    struct created_file *ptr = create_cache;
    while(ptr) {
        if (ptr->pid == pid && !strncmp(ptr->path, path, PATH_MAX)) {
            IOLockUnlock(lock);
            return true;
        }
        ptr = ptr->next;
    }
    IOLockUnlock(lock);
    return false;
}

/* on mpo_vnode_check_{open,write,unlink,exchangedata,etc}, the operation is
 * first turned into a policy query and then passed to ff_vnode_evaluate_oper to
 * determine if the operation has permission to be performed. this method is
 * called into by a number of mac policy hooks for operating on files */

int com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode, int operation)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_oper(cred, vp, label, acc_mode, operation);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_oper(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode, int operation)
{
    struct policy_query *query;
    struct policy_response response;
    char parent_path[PATH_MAX] = { 0 };
    char proc_path[PATH_MAX] = { 0 };
    char parent_name[32] = { 0 };
    char proc_name[32] = { 0 };
    int buflen = PATH_MAX;
    int pid = proc_selfpid();
    int ppid = proc_selfppid();
    struct pid_info *ptr;
    int agentPID, daemonRootPID;
    pid_t assc_pid = 0;
    
    /* if we want granularity based on threads, we can use the thread id, but
     * that also means more rules to prompt the user for, so instead we
     * consolidate back to the main thread */
    /* uint64_t tid = thread_tid(current_thread()); */
    
    if (vp == NULL)                                     /* something happened */
        return 0;
    if (vnode_isdir(vp) && operation == FF_FILEOP_READ) /* read any directory */
        return 0;
    if (policyRoot == NULL)                             /* no rules programmed yet, agent setup */
        return 0;
    
    /* check the create cache on delete or modify operations, to see if the pid created the file it's
     * trying to change */
    if (operation == FF_FILEOP_WRITE) {
        char path[PATH_MAX];
        bool exists;

        if (! vn_getpath(vp, path, &buflen))
            path[PATH_MAX-1] = 0;
        
        exists = ff_create_cache_lookup(pid, path);
        if (exists == true) {
            // IOLog("FlockFlock::ff_vnode_check_oper allowing write of path pid %d created on its own %s", pid, path);
            return 0;
        }
    }
    
    IOLockLock(lock);
    agentPID = userAgentPID;
    daemonRootPID = daemonPID;
    IOLockUnlock(lock);
    if (agentPID == pid || daemonRootPID == pid) {  /* friendlies */
        return 0;
    }
    
    /* begin to build the policy query; this is what gets evaluated and (potentially) sent to the user client */
    query = (struct policy_query *)IOMalloc(sizeof(struct policy_query));
    if (!query)
        return 0;
    query->pid = pid;
    query->path[0] = 0;
    query->operation = operation;
    if (! vn_getpath(vp, query->path, &buflen))
        query->path[PATH_MAX-1] = 0;
    if (operation == FF_FILEOP_CREATE) { /* vnode passed with mpo_vnode_check_create doesn't include trailing / */
        strncat(query->path, "/", PATH_MAX-1);
    }
    
    assc_pid = ff_cred_label_associate_by_pid(pid);
    if (assc_pid)
        ppid = assc_pid;
    
    proc_selfname(proc_name, PATH_MAX);
    
    /* look for the process' path in the pid cache; this will include path mappings from posix_spawn
     * processes and the execve cache */
    
    IOLockLock(lock);
    
    proc_path[0] = 0;
    ptr = pid_cache;
    while(ptr) {
        if (ptr->pid == pid && ptr->path[0]) {
            strncpy(proc_path, ptr->path, PATH_MAX-1);
            strncpy(proc_name, ptr->name, sizeof(proc_name)-1);
            // IOLog("ff_vnode_check_oper: pid_info lookup pid %d path %s assc_pid %d name %s\n", pid, proc_path, assc_pid, proc_name);
            break;
        }
        ptr = ptr->next;
    }
    
    /* also look for the process' parent path */
    if (ppid) {
        ptr = pid_cache;
        while(ptr) {
            if (ptr->pid == ppid) {
                strncpy(parent_path, ptr->path, PATH_MAX-1);
                strncpy(parent_name, ptr->name, sizeof(parent_name)-1);
                // IOLog("ff_vnode_check_oper: ppid_info lookup pid %d path %s assc_pid %d name %s\n", pid, proc_path, assc_pid, proc_name);
                break;
            }
            ptr = ptr->next;
        }
    }
    
    IOLockUnlock(lock);
    
    /* forked procs have the path in the associated pid from ff_cred_label_associate_fork */
    if (proc_path[0] == 0 && parent_path[0] && assc_pid == ppid) {
        strncpy(proc_path, parent_path, PATH_MAX);
    }
    
    /* process hierarchy, consolidated by tracking posix_spawn here, we add "via <someprocess>" */
    // IOLog("pid %d assc_pid %d path %s parent %s\n", pid, assc_pid, proc_path, parent_path);
    if (proc_path[0] && parent_path[0] && assc_pid) {
        if (strncmp(proc_path, parent_path, PATH_MAX)) {
            strncat(proc_path, " via ", PATH_MAX);
            strncat(proc_path, parent_path, PATH_MAX);
        }
    } else if (proc_path[0] == 0 && parent_path[0]) {
        snprintf(proc_path, PATH_MAX, "%s (-%s)", parent_path, proc_name);
    }
    
    /* failsafe: if we can't find the path to the process in the lookup cache (perhaps it was running before
     * the kernel module loaded), then reference it as a backgrounf process, but include the path
     * to its parent so we have more than just a name */
    
    if (proc_path[0] == 0) {
        // IOLog("pid %d assc_pid %d ppid %d no path\n", pid, assc_pid, ppid);
        if (parent_path[0]) {
            snprintf(proc_path, sizeof(proc_path), ":%s via %s", proc_name, parent_path);
        } else {
            snprintf(proc_path, sizeof(proc_path), ":%s", proc_name);
        }
        
    }
    
    /* the final process path becomes the basis for any new policy */
    strncpy(query->process_name, proc_path, PATH_MAX);
    
    int ret = ff_evaluate_vnode_check_oper(query);
    if (ret == EAUTH) {
        IOLockLock(policyContext.policy_lock);
        IOLockLock(policyContext.reply_lock);
        
        /* re-evaluate now that we have a query lock, in case the rule was just added */
        int ret2 = ff_evaluate_vnode_check_oper(query);
        if (ret2 != EAUTH) {
            IOLockUnlock(policyContext.policy_lock);
            IOLockUnlock(policyContext.reply_lock);
            ret = ret2;
        } else {
            /* sent the query to the user agent, wait for response */
            if (sendPolicyQuery(query, &policyContext, false) == 0) {
                IOLog("FlockFlock::ff_node_check_option: sent policy query successfully, waiting for reply\n");
                bool success = receivePolicyResponse(&response, &policyContext);
                if (success) {
                    ret = response.response;
                }
            } else {
                IOLog("FlockFlock::ff_vnode_check_open: user agent is unavailable to prompt user, denying access\n");
                ret = EACCES;
            }
        }
    }
    
    IOFree(query, sizeof(struct policy_query));
    return ret;
}

/* evaluates the policy query that was build by ff_vnode_check_oper, and then
 * determines whether or not the operation has permission to be performed.
 * if not, we either deny the request or return EAUTH, which instructs the
 * ff_vnode_check_oper method to pass the query to the user agent for
 * user permission */

int com_zdziarski_driver_FlockFlock::ff_evaluate_vnode_check_oper(struct policy_query *query)
{
    bool blacklisted = false, whitelisted = false, watched = false;
    int path_len = (int)strlen(query->path);
    long suffix_pos = 0;

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
            } else if (strncmp(query->process_name, rule->data.processName, PATH_MAX)) { /* full path */
                match = false;
            }
        }
        
        /* rule out any path rules that don't match */
        if (rpath_len) {
            switch(rule->data.ruleType) {
                case(kFlockFlockPolicyTypePathPrefix):
                    if (strncmp(query->path, rule->data.rulePath, rpath_len))
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
                    } else if (strncmp(rule->data.rulePath, query->path, PATH_MAX)) { /* full path */
                        match = false;
                    }
                    break;
                case(kFlockFlockPolicyTypePathSuffix):
                    suffix_pos = path_len - rpath_len;
                    if (rpath_len == 0 || suffix_pos < 0 || suffix_pos > strlen(query->path) || path_len <= rpath_len) {
                        match = false;
                    } else {
                        if (strncmp(query->path + (path_len - rpath_len), rule->data.rulePath, PATH_MAX))
                            match = false;
                    }
                    break;
                default:
                    break;
            }
        }
        
        if (match == true && (rule->data.operations & query->operation))
            watched = true;
        
        switch(rule->data.ruleClass) {
            case(kFlockFlockPolicyClassBlacklistAllMatching):
                if (match && (rule->data.operations & query->operation))
                    blacklisted = true;
                break;
            case(kFlockFlockPolicyClassWhitelistAllMatching):
                if (match && (rule->data.operations & query->operation))
                    whitelisted = true;
                break;
            case(kFlockFlockPolicyClassWatch):
            default:
                break;
        }

        rule = rule->next;
    }
    IOLockUnlock(lock);
    
    if (watched == false || whitelisted == true)
    {
        // IOLog("FlockFlock::ff_vnode_check_oper: allow oper %d of %s by pid %d (%s) wht %d blk %d\n", query->operation, query->path, query->pid, query->process_name, whitelisted, blacklisted);
        
        return 0;
    } else if (blacklisted == true) {
        IOLog("FlockFlock::ff_vnode_check_oper: deny oper %d of %s by pid %d (%s) wht %d blk %d\n", query->operation, query->path, query->pid, query->process_name, whitelisted, blacklisted);
        return EACCES;
    }
    
    IOLog("FlockFlock::ff_vnode_check_oper: ask oper %d of %s by pid %d (%s) wht %d blk %d daemon %d\n", query->operation, query->path, query->pid, query->process_name, whitelisted, blacklisted, daemonPID);
    
    return EAUTH;
}

/* a number of different process tracking hooks are used in order to keep track of
 * new processes, posix spawns (which must be mapped back to a parent process),
 * execve, and other operations, all of which provide our means of gathering the
 * path to the executing process. in user land, we can simply run proc_pidpath,
 * but that function (and any other means to get the pidpath) are opaque in
 * kernel land, so to keep things clean, we intercept the paths with these hooks.
 * 
 * all of these work toward building two core caches:
 *     pid_cache: master pid table, containing paths, associated parents, 
 *         and executable paths
 *     execve_cache: cache of pid and associated ppids from various sources
 */

int com_zdziarski_driver_FlockFlock::ff_cred_label_update_execve_static(OSObject *provider, kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_cred_label_update_execve(old_cred, new_cred, p, vp, offset, scriptvp, vnodelabel, scriptvnodelabel, execlabel, csflags, macpolicyattr, macpolicyattrlen, disjointp);
}

int com_zdziarski_driver_FlockFlock::ff_cred_label_update_execve(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp)
{
    char proc_path[PATH_MAX] = { 0 };
    char proc_nam[32] = { 0 };
    int path_len = PATH_MAX;
    pid_t pid = proc_pid(p);
    pid_t ppid = proc_ppid(p);
    uid_t uid = kauth_getuid();
    gid_t gid = kauth_getgid();
    pid_t selfpid = proc_selfpid();
    
    if (selfpid != pid) {
        return 0;
    }
    
    IOLockLock(lock);
    
    proc_name(proc_pid(p), proc_nam, PATH_MAX);
    if (vn_getpath(vp, proc_path, &path_len) == KERN_SUCCESS) { /* add to execve cache */
        // IOLog("ff_cred_label_update_execve pid %d path %s name %s\n", pid, proc_path, proc_nam);
        
        if (proc_path[0]) {
            struct pid_info *p = (struct pid_info *)IOMalloc(sizeof(struct pid_info));
            if (!p) {
                IOLockUnlock(lock);
                return 0;
            }
            
            p->pid = pid;
            p->ppid = ppid;
            p->uid = uid;
            p->gid = gid;
            p->next = NULL;
            strncpy(p->path, proc_path, PATH_MAX-1);
            strncpy(p->name, proc_nam, sizeof(p->name));
            if (! execve_cache) {
                execve_cache = p;
            } else {
                struct pid_info *ins = NULL, *ptr = execve_cache;
                while(ptr) {
                    if (ptr->pid == pid) {
                        ptr->ppid = ppid;
                        ptr->uid = uid;
                        ptr->gid = gid;
                        strncpy(ptr->path, proc_path, PATH_MAX-1);
                        strncpy(ptr->name, proc_nam, sizeof(ptr->name));
                        ins = NULL;
                        break;
                    }
                    ins = ptr;
                    ptr = ptr->next;
                }
                if (ins) {
                    ins->next = p;
                }
            }
        }
    }
    
    IOLockUnlock(lock);
    
    return 0;
}

void com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork_static(OSObject *provider, kauth_cred_t cred, proc_t proc)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_cred_label_associate_fork(cred, proc);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel,	struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_exec(cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_exec(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel,	struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    char path[PATH_MAX] = { 0 };
    int path_len = PATH_MAX;
    pid_t pid = -1;
    pid_t ppid = -1;
    uid_t uid = -1;
    gid_t gid = -1;
    uint64_t tid = thread_tid(current_thread());
    
    uid = kauth_getuid();
    gid = kauth_getgid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    
    if (vn_getpath(vp, path, &path_len) == KERN_SUCCESS)
    {
        ff_shared_exec_callback(pid, ppid, uid, gid, tid, path);
    }
    
    return 0;
}

int com_zdziarski_driver_FlockFlock::ff_kauth_callback_static(OSObject *provider, kauth_cred_t cred, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_kauth_callback(cred, idata, action, arg0, arg1, arg2, arg3);
}

int com_zdziarski_driver_FlockFlock::ff_kauth_callback(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    char proc_path[MAXPATHLEN] = { 0 };
    pid_t pid = -1;
    pid_t ppid = -1;
    uid_t uid = -1;
    gid_t gid = -1;
    uint64_t tid = thread_tid(current_thread());
    
    if(KAUTH_FILEOP_EXEC != action)
        return KAUTH_RESULT_DEFER;
    
    strncpy(proc_path, (const char*)arg1, MAXPATHLEN-1);
    
    uid = kauth_getuid();
    gid = kauth_getgid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    
    houseKeeping(); /* you want clean towel? */
    
    IOLog("ff_kauth_callback: pid %d ppid %d path %s\n", pid, ppid, proc_path);
    ff_shared_exec_callback(pid, ppid, uid, gid, tid, proc_path);
    return KAUTH_RESULT_DEFER;
}

int com_zdziarski_driver_FlockFlock::ff_shared_exec_callback(pid_t pid, pid_t ppid, uid_t uid, gid_t gid, uint64_t tid, const char *path)
{
    bool posix_spawned = false;
    struct posix_spawn_map *ptr;
    char proc_path[PATH_MAX] = { 0 };
    char proc_name[PATH_MAX] = { 0 };
    int name_len = PATH_MAX;
    proc_selfname(proc_name, name_len);
    int i, assc_pid;
    
    
    IOLog("ff_shared_exec_callback: entry tid %llu pid %d ppid %d path %s tid %llu name %s\n", tid, pid, ppid, path, tid, proc_name);
    
    strncpy(proc_path, path, PATH_MAX-1);
    
    /* replace the path we got with any cached paths; if there was a posix spawn, we want to use the path
     * of the parent process, and if it was an execve, the path of the new image will be in the execve
     * cache. if we don't find the path in either cache, stick with the name of the path provided us */
    
    IOLockLock(lock);
    ptr = pid_map;
    while(ptr) {
        if (ptr->pid == pid) {
            posix_spawned = true;
            ppid = ptr->ppid;
            break;
        }
        ptr = ptr->next;
    }
    IOLockUnlock(lock);
    
    if (posix_spawned) { /* get the parent's path */
        IOLockLock(lock);
        struct pid_info *p = pid_cache;
        while(p) {
            if (p->pid == ppid && p->path[0]) {
                IOLog("tid %llu posix_spawn detected for pid %d path '%s' ppid %d name %s\n", tid, pid, proc_path, ppid, proc_name);
                break;
            }
            p = p->next;
        }
        IOLockUnlock(lock);
    } else { /* check execve cache */
        IOLockLock(lock);
        struct pid_info *p = execve_cache;
        p = execve_cache;
        while(p) {
            if (p->pid == pid) {
                strncpy(proc_path, p->path, PATH_MAX-1);
                IOLog("found path for pid %d in ff_cred_label_update_execve cache: %s\n", pid, proc_path);
                break;
            }
            p = p->next;
        }
        IOLockUnlock(lock);
    }
    
    /* shorten applications down to their .app package */
    for(i = 0; i < strlen(proc_path); ++i) {
        if (proc_path[i] == '.') {
            char *ptr = proc_path + i;
            if (!strncasecmp(ptr, ".app/", 5)) {
                ptr[5] = 0;
            }
        }
    }
    
    IOLog("ff_shared_exec_callback: write tid %llu pid %d ppid %d path %s tid %llu name %s\n", tid, pid, ppid, path, tid, proc_name);
    
    /* add the final path and process into to the pid info cache, which should be the only
     * cache that ff_vnode_check_open will hae to check */
    assc_pid = ff_cred_label_associate_by_pid(pid);
    
    IOLockLock(lock);
    if (proc_path[0]) {
        struct pid_info *p = (struct pid_info *)IOMalloc(sizeof(struct pid_info));
        if (!p)
            return KAUTH_RESULT_DEFER;
        p->tid = tid;
        p->pid = pid;
        p->ppid = ppid;
        p->uid = uid;
        p->gid = gid;
        p->next = NULL;
        if (assc_pid)
            p->ppid = assc_pid;
        strncpy(p->path, proc_path, PATH_MAX-1);
        strncpy(p->name, proc_name, sizeof(p->name)-1);
        if (! pid_cache) {
            pid_cache = p;
        } else {
            struct pid_info *ins = NULL, *ptr = pid_cache;
            while(ptr) {
                if (ptr->pid == pid) {
                    if (ptr->path[0] == 0) {
                        strncpy(ptr->path, p->path, PATH_MAX);
                        strncpy(ptr->name, proc_name, sizeof(ptr->name)-1);
                    }
                    p->ppid = ppid;
                    ins = NULL;
                    break;
                }
                ins = ptr;
                ptr = ptr->next;
            }
            if (ins) {
                ins->next = p;
            }
        }
    }
    IOLockUnlock(lock);
    
    return KAUTH_RESULT_DEFER;
}

void com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork(kauth_cred_t cred, proc_t proc)
{
    struct posix_spawn_map *map;
    pid_t ppid = proc_ppid(proc);
    uint64_t tid = thread_tid(current_thread());
    
    if (ppid == 1)
        return;
    
    map = (struct posix_spawn_map *)IOMalloc(sizeof(struct posix_spawn_map));
    if (!map)
        return;
    map->pid = proc_pid(proc);
    map->ppid = ppid;
    map->tid = tid;
    map->next = NULL;
    
    IOLockLock(lock);
    if (pid_map == NULL) {
        pid_map = map;
    } else {
        map_last_insert->next = map;
    }
    map_last_insert = map;
    IOLockUnlock(lock);
    
    IOLog("ff_cred_label_associate_fork: pid %d parent %d tid %llu\n", map->pid, map->ppid, tid);
}


pid_t com_zdziarski_driver_FlockFlock::ff_cred_label_associate_by_pid(pid_t pid) {
    struct posix_spawn_map *ptr;
    pid_t ppid = 0;
    
    // IOLog("ff_cred_label_associate_by_pid: lookup pid %d tid %llu\n", pid, tid);
    
    IOLockLock(lock);
    ptr = pid_map;
    while(ptr) {
        if (ptr->pid == pid) {
            ppid = ptr->ppid;
            break;
        }
        ptr = ptr->next;
    }
    IOLockUnlock(lock);
    if (ppid) {
        int pppid = ff_cred_label_associate_by_pid(ppid);
        // IOLog("parent's of pid %d ppid %d, parent = %d\n", pid, ppid, pppid);
        if (! pppid) {
            return ppid;
        } else {
            struct pid_info *p = pid_cache;
            while(p) {
                if (p->pid == ppid && p->path[0]) {
                    return ppid;
                }
                p = p->next;
            }
        }
        
        return ff_cred_label_associate_by_pid(ppid);
    }
    return 0;
}

/* housekeeping functions, these clean out old cached data from processes that
 * no longer exist. unfortunately, there's not a reliable way to get notified of
 * a process exit, and so we must cycle through the tables and test all of the
 * pids individually. this leaves room for improvement */

void com_zdziarski_driver_FlockFlock::houseKeeping(void)
{
    
    IOLog("FlockFlock::houseKeeping\n");

    IOLockLock(lock);
    houseKeepPosixSpawnMap();
    houseKeepPathTable();
    houseKeepMasterRuleTable();
    houseKeepCreateCache();
    IOLockUnlock(lock);
    
    // IOLog("FlockFlock::houseKeeping finished\n");
}

void com_zdziarski_driver_FlockFlock::houseKeepPosixSpawnMap(void)
{
    struct posix_spawn_map *ptr, *old, *new_map = NULL, *last_insert = NULL;
    
    // IOLog("FlockFlock::houseKeepPosixSpawnMap\n");

    /* posix spawn map */
    ptr = pid_map;
    while(ptr) {
        proc_t proc = proc_find(ptr->pid);
        if (proc) {
            proc_rele(proc);
            if (new_map == NULL)
                new_map = ptr;
            else
                last_insert->next = ptr;
            last_insert = ptr;
            ptr = ptr->next;
            last_insert->next = NULL;
        } else {
            old = ptr;
            ptr = ptr->next;
            IOFree(old, sizeof(struct posix_spawn_map));
        }
    }
    pid_map = new_map;
    map_last_insert = last_insert;
}

void com_zdziarski_driver_FlockFlock::houseKeepPathTable(void)
{
    struct pid_info *ptr, *old, *new_map = NULL, *last_insert = NULL;

    // IOLog("FlockFlock::houseKeepPathTable\n");

    ptr = pid_cache;
    while(ptr) {
        proc_t proc = proc_find(ptr->pid);
        if (proc) {
            proc_rele(proc);
            if (new_map == NULL)
                new_map = ptr;
            else
                last_insert->next = ptr;
            last_insert = ptr;
            ptr = ptr->next;
            last_insert->next = NULL;
        } else {
            old = ptr;
            ptr = ptr->next;
            IOFree(old, sizeof(struct pid_info));
        }
    }

    pid_cache = new_map;
}

void com_zdziarski_driver_FlockFlock::houseKeepMasterRuleTable(void)
{
    FlockFlockPolicyHierarchy new_map = NULL;
    FlockFlockPolicy ptr, old, last_insert = NULL;
    
    // IOLog("FlockFlock::houseKeepMasterRuleTable\n");

    ptr = policyRoot;
    while(ptr) {
        if (ptr->data.temporaryRule == 0 || ptr->data.temporaryPid == 0) {
            if (new_map == NULL)
                new_map = ptr;
            else
                last_insert->next = ptr;
            last_insert = ptr;
            ptr = ptr->next;
            last_insert->next = NULL;
            continue;
        }
        
        proc_t proc = proc_find(ptr->data.temporaryPid);
        if (proc) {
            proc_rele(proc);
            if (new_map == NULL)
                new_map = ptr;
            else
                last_insert->next = ptr;
            last_insert = ptr;
            ptr = ptr->next;
            last_insert->next = NULL;
        } else {
            // IOLog("FlockFlock::houseKeepMasterRuleTable: deleting temporary rule for pid %d\n", ptr->data.temporaryPid);
            old = ptr;
            ptr = ptr->next;
            IOFree(old, sizeof(*old));
        }
    }
    
    policyRoot = new_map;
    lastPolicyAdded = last_insert;
}

void com_zdziarski_driver_FlockFlock::houseKeepCreateCache(void)
{
    struct created_file *ptr, *old, *new_map = NULL, *last_insert = NULL;
    
    // IOLog("FlockFlock::houseKeepCreateCache\n");
    
    ptr = create_cache;
    while(ptr) {
        proc_t proc = proc_find(ptr->pid);
        if (proc) {
            proc_rele(proc);
            if (new_map == NULL)
                new_map = ptr;
            else
                last_insert->next = ptr;
            last_insert = ptr;
            ptr = ptr->next;
            last_insert->next = NULL;
        } else {
            old = ptr;
            ptr = ptr->next;
            IOFree(old, sizeof(struct created_file));
        }
    }
    
    create_cache = new_map;
    create_last_insert = last_insert;
}


/* if the driver is ever stopped (force unload, etc), we immediately notify
 * the user agent through a mach message so that it can inform the user that
 * something is wrong, and recommend a reboot. at this point, atll bets are
 * off and we're not able to protect the user's files for some unknown
 * reason. with persistence mode, unloading the kernel module should result
 * in a kernel panic, and automatically reboot but something else could
 * possibly go wrong, so this is a safeguard */

int com_zdziarski_driver_FlockFlock::sendStopNotice() {
    struct ff_basic_msg message;
    int ret;
    
    IOLog("FlockFlock::sendStopNotice\n");
    message.header.msgh_remote_port = daemonNotificationPort;
    message.header.msgh_local_port = MACH_PORT_NULL;
    message.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    message.header.msgh_size = sizeof(message);
    message.header.msgh_id = 0;
    message.query_type = FFQ_STOPPED;
    
    ret = mach_msg_send_from_kernel(&message.header, sizeof(message));
    IOLog("FlockFlock::sendStopNotice: send returned %d\n", ret);
    return ret;
}

void com_zdziarski_driver_FlockFlock::stop(IOService *provider)
{
    bool active;

    IOLog("FlockFlock::stop\n");
    
    sendStopNotice();
    
    IOLockLock(lock);
    shouldStop = true;
    active = filterActive;
    IOLockUnlock(lock);
    
    stopPersistence();
    kauth_unlisten_scope(kauthListener);
    
    thread_terminate(kauth_thread);
    thread_deallocate(kauth_thread);
    
    if (active == true) {
        stopFilter(skey_a);
    }

    super::stop(provider);
}

void com_zdziarski_driver_FlockFlock::free(void)
{
    struct pid_info *ptr=NULL, *next;
    struct posix_spawn_map *mptr=NULL, *mnext;

    IOLog("IOKitTest::free\n");

    clearAllRules(skey_d);
    
    destroyQueryContext(&policyContext);
    
    IOLockLock(lock);
    ptr = pid_cache;
    while(ptr) {
        next = ptr->next;
        IOFree(ptr, sizeof(struct pid_info));
        ptr = next;
    }
    
    ptr = execve_cache;
    while(ptr) {
        next = ptr->next;
        IOFree(ptr, sizeof(struct pid_info));
        ptr = next;
    }
    
    
    mptr = pid_map;
    while(mptr) {
        mnext = mptr->next;
        IOFree(mptr, sizeof(struct posix_spawn_map));
        mptr = mnext;
    }
    
    pid_cache = NULL;
    pid_map = NULL;
    map_last_insert = NULL;
    
    IOLockFree(lock);


    super::free();
}