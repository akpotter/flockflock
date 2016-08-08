//
//  mac_policy_callbacks.h
//  FlockFlock
//
//  Created by Jonathan Zdziarski on 8/8/16.
//  Copyright © 2016 Jonathan Zdziarski. All rights reserved.
//

#ifndef mac_policy_callbacks_h
#define mac_policy_callbacks_h

int _ff_kauth_callback_internal(kauth_cred_t cred, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
int _ff_vnode_check_exec_internal(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel,struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen);
void _ff_cred_label_associate_fork_internal(kauth_cred_t cred, proc_t proc);
int _ff_cred_label_update_execve_internal(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen,  int *disjointp);
int _ff_vnode_check_signal_internal(kauth_cred_t cred, struct proc *proc, int signum);
int _ff_vnode_check_open_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
int _ff_vnode_notify_create_internal(kauth_cred_t cred, struct mount *mp, struct label *mntlabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp);
int _ff_vnode_check_unlink_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp);
int _ff_vnode_check_write_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label);
int _ff_check_vnode_rename_internal(kauth_cred_t cred,struct vnode *dvp, struct label *dlabel, struct vnode *vp,  struct label *label, struct componentname *cnp, struct vnode *tdvp, struct label *tdlabel, struct vnode *tvp, struct label *tlabel, struct componentname *tcnp);
int _ff_check_exchangedata_internal(kauth_cred_t cred, struct vnode *v1, struct label *vl1, struct vnode *v2, struct label *vl2);
int _ff_vnode_check_access_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, int acc_mode);
int _ff_vnode_check_rename_from_internal(kauth_cred_t cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp);
int _ff_vnode_check_truncate_internal(kauth_cred_t active_cred, kauth_cred_t file_cred, struct vnode *vp, struct label *label);
int _ff_vnode_check_setowner_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, uid_t uid, gid_t gid);
int _ff_vnode_check_setmode_internal(kauth_cred_t cred, struct vnode *vp, struct label *label, mode_t mode);

#endif /* mac_policy_callbacks_h */
