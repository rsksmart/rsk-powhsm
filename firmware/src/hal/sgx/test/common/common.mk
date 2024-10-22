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

HALSRCDIR = ../../src/trusted/
SGXSRCDIR = ../../../../sgx/src/
TRUSTEDSRCDIR = ../../../../sgx/src/trusted/
COMMONSRCDIR = ../../../../common/src/
POWHSMSRCDIR = ../../../../powhsm/src/
MOCKDIR = ../mock
HALINCDIR = ../../../../hal/include
TESTCOMMONDIR = ../common
CFLAGS = -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function
CFLAGS += -iquote $(HALSRCDIR) -iquote $(HALINCDIR)
CFLAGS += -iquote $(TESTCOMMONDIR)
CFLAGS += -iquote $(POWHSMSRCDIR)
CFLAGS += -iquote $(COMMONSRCDIR)
CFLAGS += -iquote $(SGXSRCDIR)
CFLAGS += -I$(MOCKDIR)
CFLAGS += -DHSM_PLATFORM_SGX

VPATH += $(MOCKDIR):$(HALSRCDIR):$(TRUSTEDSRCDIR)

include ../../../../../coverage/coverage.mk

CFLAGS += $(COVFLAGS)
