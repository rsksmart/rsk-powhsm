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
TCPSIGNERSRCDIR = ../../../tcpsigner
COMMONPATH = ../../../common/src
CFLAGS = -I $(SRCDIR) -I $(TCPSIGNERSRCDIR) -I $(COMMONPATH) -I $(TESTCOMMONDIR)

PROG = test.out
OBJS = test_fwk.o btctx.o svarint.o hex_reader.o os.o test_btctx.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

test_fwk.o: $(TESTCOMMONDIR)/test_fwk.c
	$(CC) $(CFLAGS) -c -o $@ $^

btctx.o: $(SRCDIR)/btctx.c
	$(CC) $(CFLAGS) -c -o $@ $^

svarint.o: $(SRCDIR)/svarint.c
	$(CC) $(CFLAGS) -c -o $@ $^

hex_reader.o: $(TCPSIGNERSRCDIR)/hex_reader.c
	$(CC) $(CFLAGS) -c -o $@ $^

os.o: $(TCPSIGNERSRCDIR)/os.c
	$(CC) $(CFLAGS) -c -o $@ $^

test_btctx.o: test_btctx.c test_fwk.o btctx.o svarint.o hex_reader.o os.o

$(SRCDIR)/btctx.c: $(SRCDIR)/btctx.h
$(SRCDIR)/svarint.c: $(SRCDIR)/svarint.h
$(TCPSIGNERSRCDIR)/hex_reader.c: $(TCPSIGNERSRCDIR)/hex_reader.h

.PHONY: clean test
clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
