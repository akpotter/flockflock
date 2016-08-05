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
#define LAUNCHD_AGENT "com.zdziarski.FlockFlockUserAgent.plist"
#define CONFIG "/.flockflockrc"

static OSObject *com_zdziarski_driver_FlockFlock_provider;

extern "C" {
    int _mac_policy_register_internal(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep);
    int _mac_policy_unregister_internal(mac_policy_handle_t handlep);
}

/* primary MAC hook; this, we control */
static int _ff_vnode_check_open_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_open_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, acc_mode);
}

/* hooked to map execution path */
static int _ff_kauth_callback_internal(kauth_cred_t cred, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    return com_zdziarski_driver_FlockFlock::ff_kauth_callback_static(com_zdziarski_driver_FlockFlock_provider, cred, idata, action, arg0, arg1, arg2, arg3);
}

/* hooked to map posix spawned processes back to ppid */
void _ff_cred_label_associate_fork_internal(kauth_cred_t cred, proc_t proc)
{
    com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork_static(com_zdziarski_driver_FlockFlock_provider, cred, proc);
}

/* persistence functions
 * these routines are here to prevent any process from tampering with core files needed by
 * flockflock; note that this also prevents upgrading or removal outside of recovery mode,
 * so this should probably be a feature specifically enabled by the user.
 */
int _ff_eval_vnode(struct vnode *vp)
{
    char target_path[MAXPATHLEN];
    int target_len = MAXPATHLEN;
    int ret = 0;
    
    if (!vp)
        return 0;
    
    if (! vn_getpath(vp, target_path, &target_len))
    {
        target_path[MAXPATHLEN-1] = 0;
        target_len = (int)strlen(target_path);
        
        if (!strncmp(target_path, KMOD_PATH, strlen(KMOD_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, SUPPORT_PATH, strlen(SUPPORT_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(LAUNCHD_AGENT)), LAUNCHD_AGENT, strlen(LAUNCHD_AGENT)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(CONFIG)), CONFIG, strlen(CONFIG)))
            ret = EACCES;
    }
    
    if (ret == EACCES) {
        IOLog("_ff_eval_vnode: denying operation target path %s\n", target_path);
    }
    return ret;
}

int _ff_vnode_check_signal_internal(kauth_cred_t cred, struct proc *proc, int signum)
{
    if (proc_pid(proc) == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return EACCES;
    return 0;
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

/* FlockFlock driver begin */

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
    pid_map            = NULL;
    map_last_insert    = NULL;
    filterActive       = false;
    shouldStop         = false;
    userAgentPID       = 0;
    lock               = IOLockAlloc();
    bzero(skey, sizeof(skey));
    
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
    
    startPersistence();
    kauthListener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &_ff_kauth_callback_internal, NULL);

    return true;
}

bool com_zdziarski_driver_FlockFlock::startPersistence()
{
    bool success = false;
    
    persistenceHandle = { 0 };
    persistenceOps = {
        .mpo_cred_label_associate_fork = _ff_cred_label_associate_fork_internal
    };
    
    persistenceConf = {
        .mpc_name            = "FF Process Monitor",
        .mpc_fullname        = "FlockFlock Process Monitor",
        .mpc_labelnames      = NULL,
        .mpc_labelname_count = 0,
        .mpc_ops             = &persistenceOps,
        .mpc_loadtime_flags  =
#ifdef PERSISTENCE
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

bool com_zdziarski_driver_FlockFlock::startFilter()
{
    bool success = false;
    int r;
    
    IOLockLock(lock);
    if (filterActive == false) {
        policyHandle = { 0 };
        policyOps = {
            .mpo_vnode_check_open = _ff_vnode_check_open_internal,
            
#ifdef PERSISTENCE
            .mpo_vnode_check_unlink = _ff_vnode_check_unlink_internal,
            .mpo_vnode_check_setmode = _ff_vnode_check_setmode_internal,
            .mpo_vnode_check_setowner = _ff_vnode_check_setowner_internal,
            .mpo_vnode_check_rename_from = _ff_vnode_check_rename_from_internal,
            .mpo_vnode_check_truncate = _ff_vnode_check_truncate_internal,
            .mpo_vnode_check_write  = _ff_vnode_check_write_internal,
            .mpo_proc_check_signal = _ff_vnode_check_signal_internal,
#endif
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
    }
    
    /* generate a security key and send it to the user client. the driver will only do
     * this once and will need to be rebooted or unloaded in order for a client to connect
     * and authenticate again.
     */
    
    r = genSecurityKey();
    if (r)
        success = false;
    
    IOLockUnlock(lock);
    return success;
}

bool com_zdziarski_driver_FlockFlock::stopFilter(unsigned char *key)
{
    bool success = false;
    
    if (memcmp(&skey, key, SKEY_LEN)) {
        IOLog("FlockFlock::stopFilter: skey failure\n");
        return false;
    }
    
    IOLockLock(lock);
    if (filterActive == true) {
        IOLog("FlockFlock::stopFilter unloading policy");
        kern_return_t kr = _mac_policy_unregister_internal(policyHandle);
        if (kr == KERN_SUCCESS) {
            filterActive = false;
            success = true;
            skey[0] = 0;
            IOLog("FlockFlock::stopFilter: filter stopped successfully\n");
        } else {
            IOLog("FlockFlock::stopFilter: an error occured while stopping the filter: %d\n", kr);
        }
    }
    IOLockUnlock(lock);
    return success;
}

void com_zdziarski_driver_FlockFlock::clearAllRules(unsigned char *key)
{
    IOLog("FlockFlock::clearAllRules\n");

    if (memcmp(&skey, key, SKEY_LEN)) {
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

    if (memcmp(&skey, &clientRule->skey, SKEY_LEN)) {
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

bool com_zdziarski_driver_FlockFlock::setMachPort(mach_port_t port)
{
    bool ret = false;
    IOLockLock(lock);
    if (notificationPort == MACH_PORT_NULL) {
        notificationPort = port;
        ret = true;
    }
    IOLockUnlock(lock);
    return ret;
}

void com_zdziarski_driver_FlockFlock::clearMachPort() {
    IOLockLock(lock);
    notificationPort = MACH_PORT_NULL;
    IOLockUnlock(lock);
}

bool com_zdziarski_driver_FlockFlock::setAgentPID(uint64_t pid, unsigned char *key)
{
    
    if (memcmp(&skey, key, SKEY_LEN)) {
        IOLog("FlockFlock::setAgentPID: skey failure\n");
        return false;
    }
    
    IOLockLock(lock);
    userAgentPID = (int)pid;
    IOLockUnlock(lock);
    
    IOLog("FlockFlock::setAgentPID set pid to %d\n", (int)pid);

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
    machNotificationPort = notificationPort;
    IOLockUnlock(lock);
    
    while(queryLock == false && stop == false && notificationPort != MACH_PORT_NULL) {
        IOSleep(100);
        
        IOLockLock(lock);
        stop = shouldStop;
        machNotificationPort = notificationPort;
        IOLockUnlock(lock);
        
        queryLock = IOLockTryLock(context->reply_lock);
    }
    
    if (queryLock == false) { /* filter was shut down or client disconnceted */
        IOLockUnlock(context->reply_lock);
        IOLockUnlock(context->policy_lock);
        return false;
    }
    
    if (memcmp(&skey, &context->response.skey, SKEY_LEN)) {
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
    
    context->message.header.msgh_remote_port = notificationPort;
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

/* when the user client first connects, generate a random security key and send it over
 * via a mach message; the client will have to send this key with any control queries
 * to authenticate.
 *
 * if malware should kill the client process, the system will require a reboot in order
 * to reconnect; we want this type of behavior to prevent malware from simply
 * masquerading as the client and disabling rules.
 */

int com_zdziarski_driver_FlockFlock::genSecurityKey() {
    struct skey_msg message;
    int ret, i;
    
    IOLog("FlockFlock::genSecurityKey\n");
    /* -DHARD_PERSISTENCE: Assuming a secure boot chain, will not allow the agent to reconnect if it
     * terminates, so that another process cannot masquerade as it. This is good defense against a
     * targeted attack specifically against FlockFlock, but also would require a reboot if the user
     * logs out, or in the off chance the agent crashes. Good for implementations requiring hardened
     * single-user security, such as for journalists and political dissidents.
     */
#ifdef HARD_PERSISTENCE
    if (skey[0] != 0) {
        IOLog("FlockFlock::genSecurityKey: error: key already exists\n");
        return EACCES;
    }
#endif
    for(i = 0; i < SKEY_LEN; ++i) {
        skey[i] = (unsigned char)random() % 0xff;
    }
    if (skey[i] == 0)
        skey[i] = 1; /* 0 = uninitialized */
    
    message.header.msgh_remote_port = notificationPort;
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

int com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->userAgentPID;
}

void com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork_static(OSObject *provider, kauth_cred_t cred, proc_t proc)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_cred_label_associate_fork(cred, proc);
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
    bool posix_spawned = false;
    struct posix_spawn_map *ptr;
    
    if(KAUTH_FILEOP_EXEC != action)
        return KAUTH_RESULT_DEFER;

    strncpy(proc_path, (const char*)arg1, MAXPATHLEN-1);
    
    uid = kauth_getuid();
    gid = kauth_getgid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    
    IOLog("ff_kauth_callback: tid %llu pid %d ppid %d path %s tid %llu #_ff_cred_label_associate_fork_internal\n", tid, pid, ppid, proc_path, tid);

    houseKeeping(); /* you want clean towel? */

    IOLockLock(lock);
    ptr = pid_map;
    while(ptr) {
        if (ptr->tid == tid && ptr->ppid == pid) {
            posix_spawned = true;
            ppid = ptr->pid;
            break;
        }
        ptr = ptr->next;
    }
    IOLockUnlock(lock);
    
    
    IOLockLock(lock);
    if (posix_spawned) { /* get the parent's path */
        struct pid_path *p = pid_root;
        while(p) {
            if (p->pid == ppid) {
                strncpy(proc_path, p->path, PATH_MAX-1);
                IOLog("tid %llu posix_spawn detected, using parent path %s pid %d #_ff_cred_label_associate_fork_internal\n", tid, proc_path, ppid);
                break;
            }
            p = p->next;
        }
    }
    
    /* shorten applications down to their .app package */
    if (!strncmp(proc_path, "/Applications/", 14)) {
        int i;
        for(i = 14; i < strlen(proc_path); ++i) {
            if (proc_path[i] == '.') {
                char *ptr = proc_path+i;
                if (!strncasecmp(ptr, ".app/", 5)) {
                    ptr[5] = 0;
                }
            }
        }
    }
    
    if (proc_path[0]) {
        struct pid_path *p = (struct pid_path *)IOMalloc(sizeof(struct pid_path));
        if (!p)
            return KAUTH_RESULT_DEFER;
        if (p) {
            p->tid = tid;
            p->pid = pid;
            p->ppid = ppid;
            p->uid = uid;
            p->gid = gid;
            p->next = NULL;
            strncpy(p->path, proc_path, PATH_MAX-1);
            if (! pid_root) {
                pid_root = p;
            } else {
                struct pid_path *ins = NULL, *ptr = pid_root;
                while(ptr) {
                    if (ptr->pid == pid) { /* we must be a thread, defer to main thread's path */
                        IOFree(p, sizeof(struct pid_path));
                        IOLockUnlock(lock);
                        return 0;
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
    
    return KAUTH_RESULT_DEFER;
}


void com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork(kauth_cred_t cred, proc_t proc)
{
    struct posix_spawn_map *map;
    
    map = (struct posix_spawn_map *)IOMalloc(sizeof(struct posix_spawn_map));
    if (!map)
        return;
    map->pid = proc_pid(proc);
    map->ppid = proc_ppid(proc);
    map->tid = thread_tid(current_thread());
    map->next = NULL;
    
    IOLockLock(lock);
    if (pid_map == NULL) {
        pid_map = map;
    } else {
        map_last_insert->next = map;
    }
    map_last_insert = map;
    IOLockUnlock(lock);
    
    IOLog("_ff_cred_label_associate_fork_internal: pid %d parent %d tid %llu\n", map->pid, map->ppid, map->tid);
}


int com_zdziarski_driver_FlockFlock::ff_vnode_check_open_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_open(cred, vp, label, acc_mode);
}

int com_zdziarski_driver_FlockFlock::ff_evaluate_vnode_check_open(struct policy_query *query)
{
    bool blacklisted = false, whitelisted = false;
    int path_len = (int)strlen(query->path);
    long suffix_pos = 0;
    // int proc_len = (int)strlen(query->process_name);

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
                    if (strncmp(rule->data.rulePath, query->path, rpath_len))
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
                    } else if (strcmp(rule->data.rulePath, query->path)) { /* full path */
                        match = false;
                    }
                    break;
                case(kFlockFlockPolicyTypePathSuffix):
                    suffix_pos = path_len - rpath_len;
                    if (rpath_len == 0 || suffix_pos < 0 || suffix_pos > strlen(query->path) || path_len <= rpath_len) {
                        match = false;
                    } else {
                        if (strcmp(query->path + (path_len - rpath_len), rule->data.rulePath))
                            match = false;
                    }
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

void com_zdziarski_driver_FlockFlock::houseKeeping(void)
{
    
    IOLog("FlockFlock::houseKeeping\n");

    IOLockLock(lock);
    houseKeepPosixSpawnMap();
    houseKeepPathTable();
    houseKeepMasterRuleTable();
    IOLockUnlock(lock);
    
    IOLog("FlockFlock::houseKeeping finished\n");
}

void com_zdziarski_driver_FlockFlock::houseKeepPosixSpawnMap(void)
{
    struct posix_spawn_map *ptr, *old, *new_map = NULL, *last_insert = NULL;
    
    IOLog("FlockFlock::houseKeepPosixSpawnMap\n");

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
    struct pid_path *ptr, *old, *new_map = NULL, *last_insert = NULL;

    IOLog("FlockFlock::houseKeepPathTable\n");

    ptr = pid_root;
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
            IOFree(old, sizeof(struct pid_path));
        }
    }

    pid_root = new_map;
}

void com_zdziarski_driver_FlockFlock::houseKeepMasterRuleTable(void)
{
    FlockFlockPolicyHierarchy new_map = NULL;
    FlockFlockPolicy ptr, old, last_insert = NULL;
    
    IOLog("FlockFlock::houseKeepMasterRuleTable\n");

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
            IOLog("FlockFlock::houseKeepMasterRuleTable: deleting temporary rule for pid %d\n", ptr->data.temporaryPid);
            old = ptr;
            ptr = ptr->next;
            IOFree(old, sizeof(*old));
        }
    }
    
    policyRoot = new_map;
    lastPolicyAdded = last_insert;
}

int com_zdziarski_driver_FlockFlock::ff_vnode_check_open(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    struct policy_query *query;
    struct policy_response response;
    char proc_path[PATH_MAX];
    int buflen = PATH_MAX;
    int pid = proc_selfpid();
    struct pid_path *ptr;
    int agentPID;
    char *p, *q;
    
    /* if we want granularity based on threads, we can use the thread id, but
     * that also means more rules to prompt the user for, so instead we
     * consolidate back to the main thread */
    /* uint64_t tid = thread_tid(current_thread()); */
    
    if (vp == NULL)             /* something happened */
        return 0;
    if (vnode_isdir(vp))        /* we only work with files */
        return 0;
    if (policyRoot == NULL)     /* no rules programmed yet, agent setup */
        return 0;
    
    IOLockLock(lock);
    agentPID = userAgentPID;
    IOLockUnlock(lock);
    if (agentPID == pid) {  /* friendlies */
        return 0;
    }
    
    query = (struct policy_query *)IOMalloc(sizeof(struct policy_query));
    if (!query)
        return 0;
    
    IOLockLock(lock);
    
    /* build the policy query */
    query->pid = pid;
    query->path[0] = 0;
    if (! vn_getpath(vp, query->path, &buflen))
        query->path[PATH_MAX-1] = 0;
    
    /* pull out the proc path from cache */
    
    ptr = pid_root;
    proc_path[0] = 0;
    while(ptr) {
        if (ptr->pid == pid) { // && ptr->tid == tid) {
            strncpy(proc_path, ptr->path, PATH_MAX-1);
            break;
        }
        ptr = ptr->next;
    }
    
    IOLockUnlock(lock);

    /* process hierarchy, consolidated by tracking posix_spawn 
     * here, we add "via <someprocess>" if the real process name doesn't match our
     * cached process path, indicating the current process is a child 
     *
     * note: because proc_selfname can truncate, we can only compare what's given
     * to us, so this is imperfect, but good enough */
    p = proc_path;
    q = NULL;
    while(p[0]) { /* follow /'s to filename of process path */
        if (p[0] == '/' && p[1])
            q = p;
        p++;
    }
    if (q && q[0]) { /* q = process path filename */
        char process_name[PATH_MAX] = { 0 };
        char app_name[PATH_MAX] = { 0 }; /* .app container representation */
        
        proc_selfname(process_name, PATH_MAX);
        process_name[PATH_MAX-1] = 0;
        snprintf(app_name, sizeof(app_name), "%s.app/", process_name);
        if (strncmp(q+1, process_name, strlen(process_name)) && strncmp(q+1, app_name, strlen(app_name))) {
            char via[128];
            IOLog("process %s is child via %s(%s)\n", proc_path, process_name, app_name);
            snprintf(via, sizeof(via), " via %s", process_name);
            strncat(proc_path, via, sizeof(proc_path)-1);
        }
    }
    
    if (proc_path[0]) {
        strncpy(query->process_name, proc_path, PATH_MAX); /* the final process path becomes the basis for any new policy */
        //IOLog("ff_vnode_check_open: process path for pid %d is %s #_ff_cred_label_associate_fork_internal\n", pid, proc_path);
    } else { /* usually happens if the process started before our kernel module loaded, assume safe */
        // IOLog("ff_vnode_check_open: failed to locate process path for pid %d\n", pid);
        IOFree(query, sizeof(struct policy_query));
        return 0;
    }

    int ret = ff_evaluate_vnode_check_open(query);
    if (ret == EAUTH) {
        IOLockLock(policyContext.policy_lock);
        IOLockLock(policyContext.reply_lock);

        /* re-evaluate now that we have a query lock, in case the rule was just added */
        int ret2 = ff_evaluate_vnode_check_open(query);
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


int com_zdziarski_driver_FlockFlock::sendStopNotice() {
    struct ff_basic_msg message;
    int ret;
    
    IOLog("FlockFlock::sendStopNotice\n");
    message.header.msgh_remote_port = notificationPort;
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
    
    if (active == true) {
        stopFilter(skey);
    }

    super::stop(provider);
}

void com_zdziarski_driver_FlockFlock::free(void)
{
    struct pid_path *ptr=NULL, *next;
    struct posix_spawn_map *mptr=NULL, *mnext;

    IOLog("IOKitTest::free\n");

    clearAllRules(skey);
    
    destroyQueryContext(&policyContext);
    
    IOLockLock(lock);
    ptr = pid_root;
    while(ptr) {
        next = ptr->next;
        IOFree(ptr, sizeof(struct pid_path));
        ptr = next;
    }
    
    mptr = pid_map;
    while(mptr) {
        mnext = mptr->next;
        IOFree(mptr, sizeof(struct posix_spawn_map));
        mptr = mnext;
    }
    
    pid_root = NULL;
    pid_map = NULL;
    map_last_insert = NULL;
    
    IOLockFree(lock);


    super::free();
}
