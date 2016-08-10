//
//  mac_policy_callbacks.cpp
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 8/8/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#include <i386/types.h>
#include <sys/fcntl.h>
#include "FlockFlock.hpp"
#include "mac_policy_callbacks.h"
#include "FlockFlockClientShared.h"

extern OSObject *com_zdziarski_driver_FlockFlock_provider;

/* persistence eval; integrated with the mac policy hooks, evaluates
 * whether certain core files should be modifiable. these files are
 * protected until the filter is disabled by the user, which should
 * only be done for an upgrade or uninstall. */

static int _ff_eval_vnode(struct vnode *vp)
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
        else if (!strncmp(target_path, LIBRARY_PATH, strlen(LIBRARY_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, APP_PATH, strlen(APP_PATH)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_AGENT, strlen(LAUNCHD_AGENT)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_DAEMON, strlen(LAUNCHD_DAEMON)))
            ret = EACCES;
        else if (!strncmp(target_path, LAUNCHD_KMOD, strlen(LAUNCHD_KMOD)))
            ret = EACCES;
    }
    
    if (ret == EACCES) {
        IOLog("_ff_eval_vnode: denying operation target path %s\n", target_path);
    }
    return ret;
#endif
}

/* callbacks and policy hooks: we hook a lot of different activities,
 * and each of these has a C-land callback that calls back into the
 * driver's provider instance for various operations. these include
 * mac policy hooks to detect file operations, as well as process
 * execs, spawns, and kauth callbacks. each of these either provides
 * information about processes and their relationships, or verifies
 * whether a specific file operation is permitted. */

int _ff_kauth_callback_internal(kauth_cred_t cred, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    return com_zdziarski_driver_FlockFlock::ff_kauth_callback_static(com_zdziarski_driver_FlockFlock_provider, cred, idata, action, arg0, arg1, arg2, arg3);
} /* new process notification */

int _ff_vnode_check_exec_internal(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_exec_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, scriptvp, vnodelabel, scriptlabel, execlabel, cnp, csflags, macpolicyattr, macpolicyattrlen);
} /* new process notification */

void _ff_cred_label_associate_fork_internal(kauth_cred_t cred, proc_t proc)
{
    com_zdziarski_driver_FlockFlock::ff_cred_label_associate_fork_static(com_zdziarski_driver_FlockFlock_provider, cred, proc);
} /* posix spawn notification */

int _ff_cred_label_update_execve_internal(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp)
{
    return com_zdziarski_driver_FlockFlock::ff_cred_label_update_execve_static(com_zdziarski_driver_FlockFlock_provider, old_cred, new_cred, p, vp, offset, scriptvp, vnodelabel, scriptvnodelabel, execlabel, csflags, macpolicyattr, macpolicyattrlen, disjointp);
} /* execve */

int _ff_vnode_check_signal_internal(kauth_cred_t cred, struct proc *proc, int signum)
{
    if (proc_pid(proc) == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        if (false == com_zdziarski_driver_FlockFlock::ff_should_persist(com_zdziarski_driver_FlockFlock_provider))
            return 0;
        IOLog("FlockFlock::_ff_vnode_check_signal_internal: attempt to kill daemon pid %d by pid %d\n", proc_pid(proc), proc_selfpid());
        return EACCES;
    }
    return 0;
} /* prevent agent from being killed */

int _ff_vnode_check_open_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode)
{
    if ((acc_mode & O_TRUNC)) {
        int eval;
        if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
        {
            return 0;
        }
        eval = _ff_eval_vnode(vp);
        
        if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
            return eval;

        return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, acc_mode, FF_FILEOP_WRITE);
    }
    
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, acc_mode, FF_FILEOP_READ);
}

int _ff_vnode_check_create_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct componentname *cnp, struct vnode_attr *vap)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, cred, dvp, dlabel, NULL, FF_FILEOP_CREATE);
}

int _ff_vnode_notify_create_internal(kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp)
{
    return com_zdziarski_driver_FlockFlock::ff_vnode_notify_create_static(com_zdziarski_driver_FlockFlock_provider, cred, mp, mntlabel, dvp, dlabel, vp, vlabel, cnp);
}

int _ff_vnode_check_unlink_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
      return 0;
    }
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, cred, vp, label, NULL, FF_FILEOP_WRITE);
}

int _ff_vnode_check_write_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, active_cred, vp, label, NULL, FF_FILEOP_WRITE);
}

int _ff_check_vnode_rename_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp,  struct label *label, struct componentname *cnp, struct vnode *tdvp, struct label *tdlabel, struct vnode *tvp, struct label *tlabel, struct componentname *tcnp)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return _ff_vnode_check_write_internal(cred, cred, vp, label);
}

int _ff_check_exchangedata_internal(kauth_cred_t cred, struct vnode *v1, struct label *vl1, struct vnode *v2, struct label *vl2)
{
    return _ff_vnode_check_write_internal(cred, cred, v1, vl1);
}

int _ff_vnode_check_rename_from_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_rename_to_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, int samedir, struct componentname *cnp)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_truncate_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label)
{
    int eval;
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    eval = _ff_eval_vnode(vp);
    if (eval || com_zdziarski_driver_FlockFlock::ff_is_filter_active_static(com_zdziarski_driver_FlockFlock_provider) == false)
        return eval;
    return com_zdziarski_driver_FlockFlock::ff_vnode_check_oper_static(com_zdziarski_driver_FlockFlock_provider, active_cred, vp, label, NULL, FF_FILEOP_WRITE);
}

int _ff_vnode_check_setowner_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, uid_t uid, gid_t gid)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    
    return _ff_eval_vnode(vp);
}

int _ff_vnode_check_setmode_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, mode_t mode)
{
    if (proc_selfpid() == com_zdziarski_driver_FlockFlock::ff_get_daemon_pid_static(com_zdziarski_driver_FlockFlock_provider))
    {
        return 0;
    }
    
    return _ff_eval_vnode(vp);
}