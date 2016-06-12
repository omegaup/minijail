/* util.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Logging and other utility functions.
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#define die(_msg, ...) do { \
	fprintf(stderr, "libminijail: " _msg "\n", ## __VA_ARGS__); \
	abort(); \
} while (0)

#define pdie(_msg, ...) \
	die(_msg ": %m", ## __VA_ARGS__)

#define warn(_log_level, _msg, ...) do {\
	if (_log_level >= LOG_WARNING) \
		fprintf(stderr, "libminijail: " _msg "\n", ## __VA_ARGS__); \
} while (0)

#define info(_log_level, _msg, ...) do {\
	if (_log_level >= LOG_INFO) \
		fprintf(stderr, "libminijail: " _msg "\n", ## __VA_ARGS__); \
} while (0)

extern const char *log_syscalls[];
extern const size_t log_syscalls_len;

const char *lookup_signal_name(int signum);
int lookup_syscall(const char *name);
const char *lookup_syscall_name(int nr);
long int parse_constant(char *constant_str, char **endptr);
char *strip(char *s);
char *tokenize(char **stringp, const char *delim);

#endif /* _UTIL_H_ */
