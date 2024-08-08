TESTCOMMONDIR = ../common
SRCDIR = ../../src
HALINCDIR = ../../../hal/include
HALSRCDIR = ../../../hal/x86/src
COMMONDIR = ../../../common/src
CFLAGS  = -iquote $(SRCDIR) -iquote $(HALINCDIR) -iquote $(HALSRCDIR) 
CFLAGS += -iquote $(TESTCOMMONDIR) -iquote $(COMMONDIR)
CFLAGS += -iquote $(TESTCOMMONDIR) -iquote $(COMMONDIR)
CFLAGS += -DHSM_PLATFORM_X86

VPATH += $(TESTCOMMONDIR):$(SRCDIR):$(HALSRCDIR):$(COMMONDIR)

include ../../../../coverage/coverage.mk

CFLAGS += $(COVFLAGS)
