TESTCOMMONDIR = ../common
SGXTRUSTEDDIR = ../../src/trusted
HALINCDIR = ../../../hal/include
HALSGXSRCDIR = ../../../hal/sgx/src/trusted
POWHSMSRCDIR = ../../../powhsm/src
COMMONDIR = ../../../common/src

CFLAGS  = -iquote $(TESTCOMMONDIR)
CFLAGS += -iquote $(SGXTRUSTEDDIR)
CFLAGS += -iquote $(HALINCDIR)
CFLAGS += -iquote $(HALSGXSRCDIR)
CFLAGS += -iquote $(POWHSMSRCDIR)
CFLAGS += -iquote $(COMMONDIR)
CFLAGS += -DHSM_PLATFORM_SGX

VPATH += $(SGXTRUSTEDDIR):$(COMMONDIR)

include ../../../../coverage/coverage.mk

CFLAGS += $(COVFLAGS)
