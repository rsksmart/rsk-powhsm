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
TCPSIGNERSRCDIR = ../../../tcpsigner
COMMONPATH = ../../../common/src
CFLAGS = -I $(SRCDIR) -I $(TCPSIGNERSRCDIR) -I $(COMMONPATH)

PROG = test.out
OBJS = trie.o svarint.o hex_reader.o os.o os_exceptions.o bc_err.o test_trie.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

trie.o: $(SRCDIR)/trie.c
	$(CC) $(CFLAGS) -c -o $@ $^

svarint.o: $(SRCDIR)/svarint.c
	$(CC) $(CFLAGS) -c -o $@ $^

hex_reader.o: $(TCPSIGNERSRCDIR)/hex_reader.c
	$(CC) $(CFLAGS) -c -o $@ $^

bc_err.o: $(SRCDIR)/bc_err.c
	$(CC) $(CFLAGS) -c -o $@ $^

os_exceptions.o: $(TCPSIGNERSRCDIR)/os_exceptions.c
	$(CC) $(CFLAGS) -c -o $@ $^

os.o: $(TCPSIGNERSRCDIR)/os.c
	$(CC) $(CFLAGS) -c -o $@ $^

test_trie.o: test_trie.c trie.o svarint.o hex_reader.o os.o os_exceptions.o bc_err.o

$(SRCDIR)/trie.c: $(SRCDIR)/trie.h
$(SRCDIR)/svarint.c: $(SRCDIR)/svarint.h
$(TCPSIGNERSRCDIR)/hex_reader.c: $(TCPSIGNERSRCDIR)/hex_reader.h

.PHONY: clean test
clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
