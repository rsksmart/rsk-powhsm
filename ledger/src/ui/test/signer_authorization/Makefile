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

SRCDIR = ../../src
SIGNERDIRS=$(SRCDIR)/signer_authorization_signers
COMMONDIR = ../../../common/src
MOCKDIR = ../mock
CFLAGS = -I$(MOCKDIR) -I$(COMMONDIR) -I$(SRCDIR) -I$(SIGNERDIRS)
CFLAGS += -DHSM_SIMULATOR

PARAM_INITIAL_SIGNER_HASH="\x09\x09\x66\x04\x52\xeb\x7a\x3a\x44\xb6\xca\x07$\
\xed\x0b\x9c\xcf\xdd\xb9\xa6\x99\x9e\xb4\xad\xc3\x99\x50\x91\x71\xd2\x68\xe7$\
\x3e"
CFLAGS += -DPARAM_INITIAL_SIGNER_HASH=\"$(PARAM_INITIAL_SIGNER_HASH)\"
CFLAGS += -DPARAM_INITIAL_SIGNER_ITERATION=1

PROG = test.out
OBJS = mock.o signer_authorization_status.o signer_authorization.o test_signer_authorization.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

test_signer_authorization.o: test_signer_authorization.c
	$(CC) $(CFLAGS) -c -o $@ $^

signer_authorization_status.o: $(SRCDIR)/signer_authorization_status.c
	$(CC) $(CFLAGS) -c -o $@ $^

signer_authorization.o: $(SRCDIR)/signer_authorization.c
	$(CC) $(CFLAGS) -c -o $@ $^

mock.o: $(MOCKDIR)/mock.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY: clean test

clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
