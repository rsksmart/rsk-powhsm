#*******************************************************************************
#   RSK Signer app simulator for Ledger Blue
#   (c) 2020 RSK
# 
#*******************************************************************************
SRCPATH = ../signer/src
COMMONPATH = ../common/src
VPATH = $(SRCPATH):$(COMMONPATH)

CFLAGS += -g -O0 -I$(SRCPATH) -I$(COMMONPATH) -I. -I /usr/local/include -DHSM_SIMULATOR

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
