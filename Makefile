# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

LIBDIR = lib
PRELOADNAME = libminijailpreload.so
PRELOADPATH = \"/$(LIBDIR)/$(PRELOADNAME)\"
CPPFLAGS += -DPRELOADPATH="$(PRELOADPATH)"
CC ?= gcc
DESTDIR ?= /

ifneq ($(HAVE_SECUREBITS_H),no)
CPPFLAGS += -DHAVE_SECUREBITS_H
endif
ifneq ($(USE_seccomp),yes)
CPPFLAGS += -DUSE_SECCOMP_SOFTFAIL
endif

all: CC_BINARY(minijail0) CC_LIBRARY(libminijail.so) \
		CC_LIBRARY(libminijailpreload.so) CC_BINARY(ldwrapper)

ifeq ($(ARCH),amd64)
  SCRIPTS_ARCH := x86_64
else
  SCRIPTS_ARCH := $(ARCH)
endif

install: libminijailpreload.so minijail0 ldwrapper
	install -d $(DESTDIR)/var/lib/minijail/bin && \
		install -t $(DESTDIR)/var/lib/minijail/bin $^
	install -d $(DESTDIR)/var/lib/minijail/scripts && \
		install -t $(DESTDIR)/var/lib/minijail/scripts -m 0644 scripts/$(SCRIPTS_ARCH)/*

# TODO(jorgelo): convert to TEST().
tests: CC_BINARY(libminijail_unittest) CC_BINARY(syscall_filter_unittest)

test: CC_BINARY(syscall_filter_unittest) CC_BINARY(libminijail_unittest)
	./libminijail_unittest
	./syscall_filter_unittest

CC_BINARY(minijail0): LDLIBS += -lcap -ldl -lrt
CC_BINARY(minijail0): libconstants.gen.o libsyscalls.gen.o libminijail.o \
		syscall_filter.o signal.o bpf.o util.o elfparse.o minijail0.o
clean: CLEAN(minijail0)

CC_LIBRARY(libminijail.so): LDLIBS += -lcap -lrt
CC_LIBRARY(libminijail.so): libminijail.o syscall_filter.o signal.o bpf.o \
		util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(libminijail.so)

CC_BINARY(libminijail_unittest): LDLIBS += -lcap -lrt
CC_BINARY(libminijail_unittest): libminijail_unittest.o libminijail.o \
		syscall_filter.o signal.o bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(libminijail_unittest)

CC_LIBRARY(libminijailpreload.so): LDLIBS += -lcap -ldl -lrt
CC_LIBRARY(libminijailpreload.so): libminijailpreload.o libminijail.o \
		libconstants.gen.o libsyscalls.gen.o syscall_filter.o signal.o bpf.o util.o
clean: CLEAN(libminijailpreload.so)

CC_BINARY(syscall_filter_unittest): syscall_filter_unittest.o syscall_filter.o \
		bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(syscall_filter_unittest)

CC_BINARY(ldwrapper): ldwrapper.o
clean: CLEAN(ldwrapper)

libsyscalls.gen.o: CPPFLAGS += -I$(SRC)

libsyscalls.gen.o.depends: libsyscalls.gen.c

# Only regenerate libsyscalls.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libsyscalls.gen.c: $(SRC)/Makefile $(SRC)/libsyscalls.h
	@printf "Generating target-arch specific $@... "
	$(QUIET)CC=$(CC) $(SRC)/gen_syscalls.sh $@
	@printf "done.\n"
clean: CLEAN(libsyscalls.gen.c)

$(eval $(call add_object_rules,libsyscalls.gen.o,CC,c,CFLAGS))

libconstants.gen.o.depends: libconstants.gen.c

# Only regenerate libconstants.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libconstants.gen.c: $(SRC)/Makefile $(SRC)/libconstants.h
	@printf "Generating target-arch specific $@... "
	$(QUIET)CC=$(CC) $(SRC)/gen_constants.sh $@
	@printf "done.\n"
clean: CLEAN(libconstants.gen.c)

$(eval $(call add_object_rules,libconstants.gen.o,CC,c,CFLAGS))
