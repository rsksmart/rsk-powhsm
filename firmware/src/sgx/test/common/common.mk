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

TESTCOMMONDIR = ../common
TESTLOCALMOCKSDIR = ./mocks
SGXTRUSTEDDIR = ../../src/trusted
SGXUNTRUSTEDDIR = ../../src/untrusted
HALINCDIR = ../../../hal/include
HALSGXSRCDIR = ../../../hal/sgx/src/trusted
POWHSMSRCDIR = ../../../powhsm/src
COMMONDIR = ../../../common/src

CFLAGS = -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function
CFLAGS += -DDEBUG_BUILD
CFLAGS += -I $(TESTCOMMONDIR)
CFLAGS += -I $(TESTLOCALMOCKSDIR)
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
