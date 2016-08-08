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
#define APP_BINARY "/Applications/FlockFlockUserAgent.app/Contents/MacOS/FlockFlockUserAgent"
#define APP_PATH_FOLDER "/Applications/FlockFlockUserAgent.app/"
#define APP_PATH "/Applications/FlockFlockUserAgent.app"
#define LAUNCHD_AGENT "/Library/LaunchAgents/com.zdziarski.FlockFlockUserAgent.plist"
#define LAUNCHD_DAEMON "/Library/LaunchDaemons/com.zdziarski.FlockFlock.plist"
#define CONFIG "/.flockflockrc"

static OSObject *com_zdziarski_driver_FlockFlock_provider;

extern "C" {
    int _mac_policy_register_internal(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep);
    int _mac_policy_unregister_internal(mac_policy_handle_t handlep);
}

/* primary MAC hook */
static int _ff_vnode_check_open_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, acc_mode, FF_FILEOP_OPEN);
}

/* hooked to map execution path */
static int _ff_kauth_callback_internal(kauth_cred_t cred, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    return com_zdziarski_driver_FlockFlock::ff_kauth_callback_static(com_zdziarski_driver_FlockFlock_provider, cred, idata, action, arg0, arg1, arg2, arg3);
}

/* hooked to map execution path (when kauth fails */
int _ff_vnode_check_exec_internal(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
}

/* hooked to map posix spawned processes back to ppid */
void _ff_cred_label_associate_fork_internal(kauth_cred_t cred, proc_t proc)
{
    com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork_static(com_zdziarski_driver_FlockFlock_provider, cred, proc);
}

/* hooked to provide path to current pid after exec */
int _ff_cred_label_update_execve_internal(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp)
{
        return com_zdziarski_driver_FlockFlock::ff_cred_label_update_execve_static(com_zdziarski_driver_FlockFlock_provider, old_cred, new_cred, p, vp, offset, scriptvp, vnodelabel, scriptvnodelabel, execlabel, csflags, macpolicyattr, macpolicyattrlen, disjointp);
}

/* persistence functions
 * these routines are here to prevent any process from tampering with core files needed by
 * flockflock; note that this also prevents upgrading or removal outside of recovery mode,
 * so this should probably be a feature specifically enabled by the user.
 */
int _ff_eval_vnode(struct vnode *vp)
{
#ifndef PERSISTENCE
    return 0;
#else
    char target_path[MAXPATHLEN];
    int target_len = MAXPATHLEN;
    int ret = 0;
    

    
    if (!vp)
        return 0;

    if (false == com_zdziarski_driver_FlockFlock::ff_should_persist(com_zdziarski_driver_FlockFlock_provider))
        return 0;
    
    if (! vn_getpath(vp, target_path, &target_len))
    {
        target_path[MAXPATHLEN-1] = 0;
        target_len = (int)strlen(target_path);
        
        if (!strncmp(target_path, KMOD_PATH, strlen(KMOD_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, SUPPORT_PATH, strlen(SUPPORT_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, APP_PATH, strlen(APP_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_AGENT, strlen(LAUNCHD_AGENT)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_DAEMON, strlen(LAUNCHD_DAEMON)))
            ret = EACCES;
        else if (!strncmp(target_path + (target_len - strlen(CONFIG)), CONFIG, strlen(CONFIG)))
            ret = EACCES;
    }
    
    if (ret == EACCES) {
        IOLog("_ff_eval_vnode: denying operation target path %s\n", target_path);
    }
    return ret;
#endif
}

int _ff_vnode_check_signal_internal(kauth_cred_t cred, struct proc *proc, int signum)
{
    if (proc_pid(proc) == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        if (false == com_zdziarski_driver_FlockFlock::ff_should_persist(com_zdziarski_driver_FlockFlock_provider))
            return 0;
        IOLog("FlockFlock::_ff_vnode_check_signal_internal: attempt to kill agent pid %d by pid %d\n", proc_pid(proc), proc_selfpid());
        return EACCES;
    }
    return 0;
}

int _ff_vnode_notify_create_internal(kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_notify_create_static(com_zdziarski_driver_FlockFlock_provider, cred, mp, mntlabel, dvp, dlabel, vp, vlabel, cnp);
}

int _ff_vnode_check_unlink_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, NULL, FF_FILEOP_DELETE);
}

int _ff_vnode_check_write_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, active_cred, vp, label, NULL, FF_FILEOP_WRITE);
}

int _ff_check_vnode_rename_to_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, int samedir, struct componentname *cnp)
{
    return _ff_vnode_check_write_internal(cred, cred, vp, label);
}

int _ff_check_vnode_rename_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp,  struct label *label, struct componentname *cnp, struct vnode *tdvp, struct label *tdlabel, struct vnode *tvp, struct label *tlabel, struct componentname *tcnp)
{
    return _ff_vnode_check_write_internal(cred, cred, vp, label);
}


int _ff_check_exchangedata_internal(kauth_cred_t cred, struct vnode *v1, struct label *vl1, struct vnode *v2, struct label *vl2)
{
    return _ff_vnode_check_write_internal(cred, cred, v1, vl1);
}


int _ff_vnode_check_access_internal(
                             kauth_cred_t cred,
                             struct vnode *vp,
                             struct label *label,
                             int acc_mode
                             )
{
    return _ff_vnode_check_write_internal(cred, cred, vp, label);

}

int _ff_vnode_check_rename_from_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_truncate_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(com_zdziarski_driver_FlockFlock_provider))       return 0;
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, active_cred, vp, label, NULL, FF_FILEOP_TRUNCATE);
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
        .mpo_cred_label_associate_fork = _ff_cred_label_associate_fork_internal,
        .mpo_vnode_check_truncate = _ff_vnode_check_truncate_internal,
        .mpo_vnode_check_write  = _ff_vnode_check_write_internal,
        .mpo_vnode_check_exchangedata = _ff_check_exchangedata_internal,
        .mpo_vnode_check_unlink = _ff_vnode_check_unlink_internal,
        .mpo_vnode_notify_create = _ff_vnode_notify_create_internal,
        .mpo_vnode_check_access = _ff_vnode_check_access_internal,
        .mpo_vnode_check_rename_to = _ff_check_vnode_rename_to_internal,
        .mpo_vnode_check_rename = _ff_check_vnode_rename_internal,

        // .mpo_vnode_check_exec = _ff_vnode_check_exec_internal
#ifdef PERSISTENCE
        .mpo_vnode_check_setmode = _ff_vnode_check_setmode_internal,
        .mpo_vnode_check_setowner = _ff_vnode_check_setowner_internal,
        .mpo_vnode_check_rename_from = _ff_vnode_check_rename_from_internal,

#ifdef HARD_PERSISTENCE
        , .mpo_proc_check_signal = _ff_vnode_check_signal_internal,
#endif
#endif
    };
    
    persistenceConf = {
        .mpc_name            = "FF Persistence-Mode",
        .mpc_fullname        = "FlockFlock Process Monitor and Persistence Services",
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

bool com_zdziarski_driver_FlockFlock::genAgentTicket()
{
#ifdef HARD_PERSISTENCE
    char proc_path[PATH_MAX];
    pid_path *ptr;
#endif
    bool success = false;
    int r;
    
    IOLockLock(lock);
    
    IOLog("FlockFlock::genAgentTicket\n");
    
#ifdef HARD_PERSISTENCE
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
    
    IOLog("FlockFlock::genAgentTicket: process path is '%s'\n", proc_path);
    if (strncmp(proc_path, APP_PATH_FOLDER, PATH_MAX) && strncmp(proc_path, APP_BINARY, PATH_MAX)) {
        IOLog("FlockFlock::genAgentTicket: refusing to send ticket to pid %d running at unauthoried path %s\n", proc_selfpid(), proc_path);
        IOLockUnlock(lock);
        return false;
    }
#endif
    
    /* generate a security key and send it to the user client. the driver will only do
     * this once and will need to be rebooted or unloaded in order for a client to connect
     * and authenticate again (if persistence is turned on)
     */
    
    r = genSecurityKey();
    if (! r)
        success = true;
    
    IOLockUnlock(lock);
    
    return success;
}

bool com_zdziarski_driver_FlockFlock::startFilter()
{
    bool success = false;
    
    IOLockLock(lock);
    if (filterActive == false) {
        policyHandle = { 0 };
        policyOps = {
            .mpo_cred_label_update_execve = _ff_cred_label_update_execve_internal,
            .mpo_vnode_check_open = _ff_vnode_check_open_internal,
            .mpo_vnode_check_unlink = _ff_vnode_check_unlink_internal,
            .mpo_vnode_check_truncate = _ff_vnode_check_truncate_internal
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

bool com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->filterActive;
}

int com_zdziarski_driver_FlockFlock::ff_get_agent_pid_static(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->userAgentPID;
}

bool com_zdziarski_driver_FlockFlock::ff_should_persist(OSObject *provider) {
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    if (me->filterActive == false && me->filterInitialized == true)
        return false;
    
    return true;
}

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
        IOLog("ff_cred_label_update_execve pid %d path %s name %s\n", pid, proc_path, proc_nam);

        if (proc_path[0]) {
            struct pid_info *p = (struct pid_info *)IOMalloc(sizeof(struct pid_info));
            if (!p)
                return 0;
            if (p) {
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


int com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode, int operation)
{
    com_zdziarski_driver_FlockFlock *me = (com_zdziarski_driver_FlockFlock *)provider;
    return me->ff_vnode_check_oper(cred, vp, label, acc_mode, operation);
}

int com_zdziarski_driver_FlockFlock::ff_evaluate_vnode_check_oper(struct policy_query *query)
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
            } else if (strncmp(query->process_name, rule->data.processName, PATH_MAX)) { /* full path */
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
    {
        IOLog("FlockFlock::ff_vnode_check_open: allow open of %s by pid %d (%s) wht %d blk %d\n", query->path, query->pid, query->process_name, whitelisted, blacklisted);

        return 0;
    } else if (blacklisted == true) {
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
    houseKeepCreateCache();
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
    struct pid_info *ptr, *old, *new_map = NULL, *last_insert = NULL;

    IOLog("FlockFlock::houseKeepPathTable\n");

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

pid_t com_zdziarski_driver_FlockFlock::ff_cred_label_associate_by_pid(pid_t pid) {
    struct posix_spawn_map *ptr;
    uint64_t tid = thread_tid(current_thread());
    pid_t ppid = 0;
    
    IOLog("ff_cred_label_associate_by_pid: lookup pid %d tid %llu\n", pid, tid);

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
        IOLog("parent's of pid %d ppid %d, parent = %d\n", pid, ppid, pppid);
        if (! pppid)
            return ppid;
        return ff_cred_label_associate_by_pid(ppid);
    }
    return 0;
}

void com_zdziarski_driver_FlockFlock::houseKeepCreateCache(void)
{
    struct created_file *ptr, *old, *new_map = NULL, *last_insert = NULL;
    
    IOLog("FlockFlock::houseKeepCreateCache\n");
    
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
    int agentPID;
    pid_t assc_pid = 0;
    
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
    
    if (operation != FF_FILEOP_OPEN) {
        char path[PATH_MAX];
        bool exists;
        
        if (! vn_getpath(vp, path, &buflen))
            path[PATH_MAX-1] = 0;
        exists = ff_create_cache_lookup(pid, path);
        IOLog("LOOKUP CHECK FOR OPERATION %d ON %s: %d exists: %d\n", operation, path, pid, exists);
        if (exists == true)
            return 0;
    }
    
    IOLockLock(lock);
    agentPID = userAgentPID;
    IOLockUnlock(lock);
    if (agentPID == pid) {  /* friendlies */
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
            IOLog("ff_vnode_check_open: pid_info lookup pid %d path %s assc_pid %d name %s\n", pid, proc_path, assc_pid, proc_name);
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
                break;
            }
            ptr = ptr->next;
        }
    }
    
    IOLockUnlock(lock);
    
    /* process hierarchy, consolidated by tracking posix_spawn here, we add "via <someprocess>" */
    IOLog("pid %d assc_pid %d path %s parent %s\n", pid, assc_pid, proc_path, parent_path);
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
    struct pid_info *ptr=NULL, *next;
    struct posix_spawn_map *mptr=NULL, *mnext;

    IOLog("IOKitTest::free\n");

    clearAllRules(skey);
    
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