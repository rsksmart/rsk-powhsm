#*******************************************************************************
#   RSK Signer app simulator for Ledger Blue
#   (c) 2020 RSK
# 
#*******************************************************************************
VPATH = ../signer/src

CFLAGS = -g -O0 -DFEDHM_EMULATOR -I$(VPATH) -I.

OBJDIR := objs

DEPDIR := $(OBJDIR)/.deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) -c

PROG = simul

SIGN_SRCS = $(filter-out %/main.c, $(wildcard $(VPATH)/*.c))
SIGN_OBJS = $(patsubst $(VPATH)/%.c, $(OBJDIR)/%.o, $(SIGN_SRCS))

SIM_SRCS = $(wildcard *.c)
SIM_OBJS = $(patsubst %.c, $(OBJDIR)/%.o, $(SIM_SRCS))

SRCS = $(SIGN_SRCS) $(SIM_SRCS)
OBJS = $(SIGN_OBJS) $(SIM_OBJS)

all: $(PROG)
$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) 

$(OBJDIR)/%.o: %.c $(DEPDIR)/%.d | $(DEPDIR)
	$(COMPILE.c) -o $@ $<

$(DEPDIR): ; @mkdir -p $@
DEPFILES := $(patsubst $(DEPDIR)/$(VPATH)/%.d, $(DEPDIR)/%.d, $(SRCS:%.c=$(DEPDIR)/%.d))

$(DEPFILES):

include $(wildcard $(DEPFILES))

.PHONY: clean
clean:
	rm -rf $(PROG) ./$(OBJDIR)
