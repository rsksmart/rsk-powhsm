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

SRCPATH = ../signer/src
COMMONPATH = ../common/src
VPATH = $(SRCPATH):$(COMMONPATH)

CFLAGS += -g -O0 -I$(SRCPATH) -I$(COMMONPATH) -I. -I /usr/local/include -DHSM_SIMULATOR
CFLAGS += -Werror

LDFLAGS = -lsecp256k1

OBJDIR := objs
PROG = tcpsigner

DEPDIR := $(OBJDIR)/.deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) -c

SIGN_SRCS = $(filter-out %/main.c, $(wildcard $(SRCPATH)/*.c))
COMMON_SRCS = $(wildcard $(COMMONPATH)/*.c)
SIGN_OBJS = $(patsubst $(SRCPATH)/%.c, $(OBJDIR)/%.o, $(SIGN_SRCS)) $(patsubst $(COMMONPATH)/%.c, $(OBJDIR)/%.o, $(COMMON_SRCS))

SIM_SRCS = $(wildcard *.c)
SIM_OBJS = $(patsubst %.c, $(OBJDIR)/%.o, $(SIM_SRCS))

SRCS = $(SIGN_SRCS) $(COMMON_SRCS) $(SIM_SRCS)
OBJS = $(SIGN_OBJS) $(SIM_OBJS)


all: $(PROG)
$(PROG): $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: %.c $(DEPDIR)/%.d | $(DEPDIR)
	$(COMPILE.c) -o $@ $<

$(DEPDIR): ; @mkdir -p $@
DEPFILES := $(patsubst $(DEPDIR)/$(SRCPATH)/%.d, $(DEPDIR)/%.d, $(SRCS:%.c=$(DEPDIR)/%.d)) $(patsubst $(DEPDIR)/$(COMMONPATH)/%.d, $(DEPDIR)/%.d, $(SRCS:%.c=$(DEPDIR)/%.d))

$(DEPFILES):

include $(wildcard $(DEPFILES)) 

.PHONY: clean
clean:
	rm -rf $(PROG) $(OBJDIR)
