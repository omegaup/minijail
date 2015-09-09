#!/bin/sh

# Copyright 2015 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Generates a header file with a named constant table made up of "name", value
# entries by including several build target header files and emitting the list
# of defines.  Use of the preprocessor is needed to recursively include all
# relevant headers.

set -e

if [ $# -ne 1 ] && [ $# -ne 3]; then
  echo "Usage: $(basename "$0") OUTFILE"
  echo "Usage: $(basename "$0") CC CFLAGS OUTFILE"
  exit 1
fi

if [ $# -eq 3 ]; then
  CC="$1"
  shift
  CFLAGS="$1"
  shift
fi
OUTFILE="$1"

INCLUDES='
#include <asm/termbits.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/soundcard.h>
#include <signal.h>
#include <sound/asound.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>'

# Passes the previous list of #includes to the C preprocessor and prints out
# all #defines whose name is all-caps.  Excludes a few symbols that are known
# macro functions that don't evaluate to a constant.
cat <<-EOF > "${OUTFILE}"
/* GENERATED BY MAKEFILE */
$INCLUDES

#include "libconstants.h"
const struct constant_entry constant_table[] = {
$(echo "$INCLUDES" | \
  ${CC} ${CFLAGS} -dD - -E | \
  grep '^#\s*define\s\+[A-Z][A-Z0-9_]*\s\+[^"{]' | \
  grep -v '\(SIGRTMAX\|SIGRTMIN\|SIG_\|NULL\|SEQ_\|SIOC\|MB_CUR_MAX\)' | \
  sort | \
  uniq | \
  sed -e 's/#define \([A-Z0-9_]\+\).*$/#ifdef \1\n  { "\1", (unsigned long) \1 },\n#endif  \/\/ \1/')
  { NULL, 0 },
};
EOF
