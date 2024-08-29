# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

SRCPATH = ./src
POWHSMSRCPATH = ../powhsm/src
COMMONPATH = ../common/src
HALSRCPATH = ../hal/x86/src
HALINCPATH = ../hal/include
HALPATH = $(HALINCPATH):$(HALSRCPATH)
VPATH = $(SRCPATH):$(POWHSMSRCPATH):$(COMMONPATH):$(HALPATH)

# We don't need the code coverage definitions for AFL builds
ifeq ($(HSM_AFL),)
	include ../../coverage/coverage.mk
endif

CFLAGS += -g -O0 -iquote $(SRCPATH) 
CFLAGS += -iquote $(POWHSMSRCPATH)
CFLAGS += -iquote $(COMMONPATH)
CFLAGS += -iquote $(HALINCPATH) -iquote $(HALSRCPATH) 
CFLAGS += -I /usr/local/include -Werror
CFLAGS += -DHSM_PLATFORM_X86

LDFLAGS = -lsecp256k1

OBJDIR := objs
PROG = tcpsigner

DEPDIR := $(OBJDIR)/.deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) -c

SIGN_SRCS = $(wildcard $(POWHSMSRCPATH)/*.c)
COMMON_SRCS = $(wildcard $(COMMONPATH)/*.c)
HAL_SRCS = $(wildcard $(HALSRCPATH)/*.c)
SIGN_OBJS = $(patsubst $(POWHSMSRCPATH)/%.c, $(OBJDIR)/%.o, $(SIGN_SRCS))
SIGN_OBJS += $(patsubst $(COMMONPATH)/%.c, $(OBJDIR)/%.o, $(COMMON_SRCS))
SIGN_OBJS += $(patsubst $(HALSRCPATH)/%.c, $(OBJDIR)/%.o, $(HAL_SRCS))

SIM_SRCS = $(wildcard $(SRCPATH)/*.c)
SIM_OBJS = $(patsubst $(SRCPATH)/%.c, $(OBJDIR)/%.o, $(SIM_SRCS))

SRCS = $(SIGN_SRCS) $(COMMON_SRCS) $(HAL_SRCS) $(SIM_SRCS)
OBJS = $(SIGN_OBJS) $(SIM_OBJS)

all: $(PROG)
$(PROG): $(OBJS)
	$(CC) $(COVFLAGS) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: %.c $(DEPDIR)/%.d | $(DEPDIR)
	$(COMPILE.c) $(COVFLAGS) -o $@ $<

$(DEPDIR): ; @mkdir -p $@

DEPFILES := $(patsubst %.c, $(DEPDIR)/%.d, $(notdir $(SRCS)))

$(DEPFILES):

include $(wildcard $(DEPFILES)) 

.PHONY: clean
clean:
	rm -rf $(PROG) $(OBJDIR) $(COVFILES)
