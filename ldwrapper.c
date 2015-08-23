/*
 * Copyright 2015 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <unistd.h>

int main(int argc, char* argv[]) {
	if (argc < 1)
		return 1;
	char* envp = NULL;
	return execve(argv[1], argv + 1, &envp);
}
