//
//  FlockFlock.hpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 7/29/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#ifndef __FLOCKFLOCK_HPP_
#define __FLOCKFLOCK_HPP_

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/kern_event.h>
#include <sys/kauth.h>
#include <sys/types.h>
#include <sys/kern_event.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <security/mac_framework.h>
#include "FlockFlockClientShared.h"

struct created_file
{
    pid_t pid;
    char path[PATH_MAX];
    struct created_file *next;
};

struct mach_query_context
{
    IOLock *policy_lock, *reply_lock;
    struct policy_query_msg message;
    struct policy_response response;
    uint32_t security_token;
};

struct pid_info
{
    uid_t uid;
    gid_t gid;
    pid_t pid;
    pid_t ppid;
    uint64_t tid;
    
    char path[PATH_MAX];
    char name[32];
    struct pid_info *next;
};

struct posix_spawn_map
{
    pid_t pid;
    pid_t ppid;
    uint64_t tid;
    struct posix_spawn_map *next;
};

class com_zdziarski_driver_FlockFlock : public IOService
{
    OSDeclareDefaultStructors(com_zdziarski_driver_FlockFlock)
    
public:
    virtual bool init(OSDictionary *dictionary = NULL) override;
    virtual IOService *probe(IOService *provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free(void) override;
    
    /* mac policy instance methods and their static entry hooks */
    
    static int ff_vnode_notify_create_static(OSObject *provider, kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp);
    int ff_vnode_notify_create(kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp);

    static bool ff_is_filter_active_static(OSObject *provider);
    static int ff_cred_label_update_execve_static(OSObject *provider, kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp);
    int ff_cred_label_update_execve(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp);

    static int ff_vnode_check_oper_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode, int operation);
    int ff_vnode_check_oper(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode, int operation);
    
    static int ff_vnode_check_exec_static(OSObject *provider, kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel,	struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);
    int ff_vnode_check_exec(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel,	struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);
    
    static int ff_kauth_callback_static(OSObject *provider, kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
    int ff_kauth_callback(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

    static void ff_cred_label_associate_fork_static(OSObject *provider, kauth_cred_t cred, proc_t proc);
    void ff_cred_label_associate_fork(kauth_cred_t cred, proc_t proc);
    
    static int ff_get_agent_pid_static(OSObject *provider);
    static int ff_get_daemon_pid_static(OSObject *provider);
    static bool ff_should_persist(OSObject *provider);

    int ff_evaluate_vnode_check_oper(struct policy_query *);

    /* IOUserClient methods */
    
    bool startFilter();
    bool stopFilter(unsigned char *key);
    void clearMachPort();
    void clearAllRules(unsigned char *key);
    bool setMachPort(mach_port_t port, bool is_daemon);
    bool setAgentPID(uint64_t pid, unsigned char *key);
    bool setDaemonPID(uint64_t pid, unsigned char *key);
    bool genTicket(bool is_daemon);
    bool isFilterActive(void);
    
    kern_return_t addClientPolicy(FlockFlockClientPolicy policy);

private:
    bool startPersistence();
    bool stopPersistence();

    bool initQueryContext(mach_query_context *context);
    void destroyQueryContext(mach_query_context *context);

    int sendPolicyQuery(struct policy_query *query, struct mach_query_context *context, bool lock);
    bool receivePolicyResponse(struct policy_response *response, struct mach_query_context *context);
    void houseKeeping(void);
    void houseKeepPosixSpawnMap();
    void houseKeepPathTable();
    void houseKeepMasterRuleTable();
    void houseKeepCreateCache();
    int sendStopNotice();
    int genSecurityKey(bool is_daemon);
    
    int ff_shared_exec_callback(pid_t pid, pid_t ppid, uid_t uid, gid_t gid, uint64_t tid, const char *path);
    pid_t ff_cred_label_associate_by_pid(pid_t pid);
    bool ff_create_cache_lookup(pid_t pid, const char *path);
    
public:
    mach_port_t agentNotificationPort, daemonNotificationPort;
    struct mach_query_context policyContext;
    uint32_t userAgentPID, daemonPID;

private:
    bool filterActive, shouldStop, filterInitialized;
    IOLock *lock;
    FlockFlockPolicyHierarchy policyRoot;
    FlockFlockPolicy lastPolicyAdded;
    struct pid_info *pid_cache;
    struct pid_info *execve_cache;
    struct created_file *create_cache;
    struct created_file *create_last_insert;
    struct posix_spawn_map *pid_map, *map_last_insert;
    unsigned char skey_a[SKEY_LEN];
    unsigned char skey_d[SKEY_LEN];
    
    /* file access MAC policy */
    mac_policy_handle_t policyHandle;
    struct mac_policy_ops policyOps;
    struct mac_policy_conf policyConf;
    
    /* persistence MAC policy; prevents tampering with FlockFlock core files */
    mac_policy_handle_t persistenceHandle;
    struct mac_policy_ops persistenceOps;
    struct mac_policy_conf persistenceConf;
    kauth_listener_t kauthListener = NULL;    
};

#endif