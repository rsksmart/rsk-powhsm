TESTCOMMONDIR = ../common
SGXTRUSTEDDIR = ../../src/trusted
SGXUNTRUSTEDDIR = ../../src/untrusted
HALINCDIR = ../../../hal/include
HALSGXSRCDIR = ../../../hal/sgx/src/trusted
POWHSMSRCDIR = ../../../powhsm/src
COMMONDIR = ../../../common/src

CFLAGS = -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function
CFLAGS += -I $(TESTCOMMONDIR)
CFLAGS += -iquote $(SGXTRUSTEDDIR)
CFLAGS += -iquote $(SGXUNTRUSTEDDIR)
CFLAGS += -iquote $(HALINCDIR)
CFLAGS += -iquote $(HALSGXSRCDIR)
CFLAGS += -iquote $(POWHSMSRCDIR)
CFLAGS += -iquote $(COMMONDIR)
CFLAGS += -DHSM_PLATFORM_SGX

VPATH += $(SGXTRUSTEDDIR):$(SGXUNTRUSTEDDIR):$(COMMONDIR)

include ../../../../coverage/coverage.mk

CFLAGS += $(COVFLAGS)
