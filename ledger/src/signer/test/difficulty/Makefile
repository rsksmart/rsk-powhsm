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
SRCDIR = ../../src
COMMONPATH = ../../../common/src
TCPSIGNERPATH = ../../../tcpsigner

CFLAGS = -I $(SRCDIR) -I $(COMMONPATH) -I $(TCPSIGNERPATH) -I $(TESTCOMMONDIR) -DFEDHM_EMULATOR -DDEBUG_DIFF

PROG = test.out
OBJS = test_fwk.o bigdigits.o bc_diff.o os.o test_difficulty.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

test_fwk.o: $(TESTCOMMONDIR)/test_fwk.c
	$(CC) $(CFLAGS) -c -o $@ $^

bigdigits.o: $(SRCDIR)/bigdigits.c
	$(CC) $(CFLAGS) -c -o $@ $^

os.o: $(TCPSIGNERPATH)/os.c
	$(CC) $(CFLAGS) -c -o $@ $^

bc_diff.o: $(SRCDIR)/bc_diff.c
	$(CC) $(CFLAGS) -c -o $@ $^

test_difficulty.o: test_difficulty.c test_fwk.o bigdigits.o bc_diff.o os.o

$(SRCDIR)/bigdigits.c: $(SRCDIR)/bigdigits.h $(SRCDIR)/bigdtypes.h
$(SRCDIR)/bc_diff.c: $(SRCDIR)/bc_diff.h $(SRCDIR)/bigdigits.h $(SRCDIR)/bigdtypes.h $(TCPSIGNERPATH)/os_exceptions.h

.PHONY: clean test
clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
