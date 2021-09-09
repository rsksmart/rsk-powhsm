SRCDIR = ../../src
CFLAGS = -I $(SRCDIR) -Imocks/ -DMAX_RLP_CTX_DEPTH=10

PROG = test.out
OBJS = srlp.o test_srlp.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

srlp.o: $(SRCDIR)/srlp.c
	$(CC) $(CFLAGS) -c -o $@ $^

test_srlp.o: test_srlp.c srlp.o
$(SRCDIR)/srlp.c: $(SRCDIR)/srlp.h

.PHONY: clean test
clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
