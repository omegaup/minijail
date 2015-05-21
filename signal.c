/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* These header files need to be included before asm/siginfo.h such that
 * pid_t, timer_t, and clock_t are defined. */
#include <stdlib.h>
#include <unistd.h>

#include <asm/siginfo.h>
#define __have_siginfo_t 1
#define __have_sigval_t 1
#define __have_sigevent_t 1

#include <signal.h>
#include <string.h>

#include "signal.h"

#include "util.h"

struct local_sigsys {
	void		*ip;
	int		nr;
	unsigned int	arch;
};

int signum_fd = -1;

void log_sigsys_handler(int nr, siginfo_t *info, void *void_context)
{
	struct local_sigsys sigsys;
	memcpy(&sigsys, &info->_sifields, sizeof(sigsys));
	int written = 0;
	if (signum_fd != -1)
		written = write(signum_fd, &sigsys.nr, sizeof(sigsys.nr));

	(void) void_context;
	(void) nr;
	(void) written;

	/*
	 * We trapped on a syscall that should have killed the process.
	 * This should never ever return, but we're paranoid.
	 */
	for (;;)
		_exit(1);
}

int install_sigsys_handler()
{
	int ret = 0;
	struct sigaction act;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &log_sigsys_handler;
	act.sa_flags = SA_SIGINFO;

	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	ret = sigaction(SIGSYS, &act, NULL);
	if (ret < 0)
		return ret;

	ret = sigprocmask(SIG_UNBLOCK, &mask, NULL);
	if (ret < 0)
		return ret;

	return 0;
}
