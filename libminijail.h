/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* The general pattern of use here:
 * 1) Construct a minijail with minijail_new()
 * 2) Apply the desired restrictions to it
 * 3) Enter it, which locks the current process inside it, or:
 * 3) Run a process inside it
 * 4) Destroy it.
 */

#ifndef _LIBMINIJAIL_H_
#define _LIBMINIJAIL_H_

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	MINIJAIL_ERR_PRELOAD = 252,
	MINIJAIL_ERR_JAIL = 253,
	MINIJAIL_ERR_INIT = 254,
};

struct minijail;

/* Allocates a new minijail with no restrictions. */
struct minijail *minijail_new(void);

/* These functions add restrictions to the minijail. They are not applied until
 * minijail_enter() is called. See the documentation in minijail0.1 for
 * explanations in detail of what the restrictions do.
 */
void minijail_change_uid(struct minijail *j, uid_t uid);
void minijail_change_gid(struct minijail *j, gid_t gid);
/* Stores user to change to and copies |user| for internal consistency. */
int minijail_change_user(struct minijail *j, const char *user);
/* Does not take ownership of |group|. */
int minijail_change_group(struct minijail *j, const char *group);
void minijail_use_seccomp(struct minijail *j);
void minijail_no_new_privs(struct minijail *j);
void minijail_use_seccomp_filter(struct minijail *j);
void minijail_parse_seccomp_filters(struct minijail *j, const char *path);
void minijail_log_seccomp_filter_failures(struct minijail *j);
void minijail_use_caps(struct minijail *j, uint64_t capmask);
void minijail_namespace_vfs(struct minijail *j);
void minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path);
void minijail_namespace_net(struct minijail *j);
/* Implies namespace_vfs and remount_readonly.
 * WARNING: this is NOT THREAD SAFE. See the block comment in </libminijail.c>.
 */
void minijail_namespace_pids(struct minijail *j);
void minijail_remount_readonly(struct minijail *j);
void minijail_run_as_init(struct minijail *j);
void minijail_inherit_usergroups(struct minijail *j);
void minijail_disable_ptrace(struct minijail *j);

/* minijail_enter_chroot: enables chroot() restriction for @j
 * @j   minijail to apply restriction to
 * @dir directory to chroot() to. Owned by caller.
 *
 * Enters @dir, binding all bind mounts specified with minijail_bind() into
 * place. Requires @dir to contain all necessary directories for bind mounts
 * (i.e., if you have requested a bind mount at /etc, /etc must exist in @dir.)
 *
 * Returns 0 on success.
 */
int minijail_enter_chroot(struct minijail *j, const char *dir);

/* minijail_mount_tmp: enables mounting of a tmpfs filesystem on /tmp.
 * As be rules of bind mounts, /tmp must exist in chroot.
 */
void minijail_mount_tmp(struct minijail *j);

/* minijail_chroot_chdir: calls chdir() after chroot() restriction for @j
 * @j   minijail to apply restriction to
 * @dir directory to chdir() to. Owned by caller.
 *
 * Sets @dir as pwd just after calling chroot. @dir should be a directory within
 * the chroot, expressed as an absolute path. This option requires having called
 * minijail_enter_chroot beforehand.
 *
 * Returns 0 on success.
 */
int minijail_chroot_chdir(struct minijail *j, const char *dir);

/* minijail_bind: bind-mounts @src into @j as @dest, optionally writeable
 * @j         minijail to bind inside
 * @src       source to bind
 * @dest      location to bind (inside chroot)
 * @writeable 1 if the bind mount should be writeable
 *
 * This may be called multiple times; all bindings will be applied in the order
 * of minijail_bind() calls.
 */
int minijail_bind(struct minijail *j, const char *src, const char *dest,
		  int writeable);

/* Lock this process into the given minijail. Note that this procedure cannot fail,
 * since there is no way to undo privilege-dropping; therefore, if any part of
 * the privilege-drop fails, minijail_enter() will abort the entire process.
 *
 * Some restrictions cannot be enabled this way (pid namespaces) and attempting
 * to do so will cause an abort.
 */
void minijail_enter(const struct minijail *j);

/* Run the specified command in the given minijail, execve(3)-style. This is
 * required if minijail_namespace_pids() was used.
 */
int minijail_run(struct minijail *j, const char *filename,
		 char *const argv[]);

/* Run the specified command in the given minijail, execve(3)-style.
 * Used with static binaries.
 */
int minijail_run_static(struct minijail *j, const char *filename,
			char *const argv[]);

/* Run the specified command in the given minijail, execve(3)-style.
 * Update |*pchild_pid| with the pid of the child.
 */
int minijail_run_pid(struct minijail *j, const char *filename,
		     char *const argv[], pid_t *pchild_pid);

/* Run the specified command in the given minijail, execve(3)-style.
 * Update |*pstdin_fd| with a fd that allows writing to the child's
 * standard input.
 */
int minijail_run_pipe(struct minijail *j, const char *filename,
		      char *const argv[], int *pstdin_fd);

/* Run the specified command in the given minijail, execve(3)-style.
 * Update |*pchild_pid| with the pid of the child.
 * Update |*pstdin_fd| with a fd that allows writing to the child's
 * standard input.
 */
int minijail_run_pid_pipe(struct minijail *j, const char *filename,
			  char *const argv[], pid_t *pchild_pid,
			  int *pstdin_fd);

/* Run the specified command in the given minijail, execve(3)-style.
 * Update |*pchild_pid| with the pid of the child.
 * Update |*pstdin_fd| with a fd that allows writing to the child's
 * standard input.
 * Update |*pstdout_fd| with a fd that allows reading from the child's
 * standard output.
 * Update |*pstderr_fd| with a fd that allows reading from the child's
 * standard error.
 */
int minijail_run_pid_pipes(struct minijail *j, const char *filename,
			   char *const argv[], pid_t *pchild_pid,
			   int *pstdin_fd, int *pstdout_fd, int *pstderr_fd);

/* Kill the specified minijail. The minijail must have been created with pid
 * namespacing; if it was, all processes inside it are atomically killed.
 */
int minijail_kill(struct minijail *j);

/* Wait for all processed in the specified minijail to exit. Returns the exit
 * status of the _first_ process spawned in the jail.
 */
int minijail_wait(struct minijail *j);

/* Frees the given minijail. It does not matter if the process is inside the minijail or
 * not. */
void minijail_destroy(struct minijail *j);

/* Gets the absolute path of a file within the minijail */
int minijail_get_path(const struct minijail *j, char *buffer,
		size_t buffer_len, const char *path);

/* These functions are only used for omegaUp
 */
void minijail_stack_limit(struct minijail *j, int stack_limit);
void minijail_time_limit(struct minijail *j, int msec_limit);
void minijail_extra_wall_time(struct minijail *j, int extra_msec);
void minijail_output_limit(struct minijail *j, int byte_limit);
void minijail_memory_limit(struct minijail *j, int byte_limit);
int minijail_meta_file(struct minijail *j, const char *meta_path);
void minijail_close_all_files(struct minijail *j);
int minijail_redirect_stdin(struct minijail *j, const char *stdin_path);
int minijail_redirect_stdout(struct minijail *j, const char *stdout_path);
int minijail_redirect_stderr(struct minijail *j, const char *stderr_path);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* !_LIBMINIJAIL_H_ */
