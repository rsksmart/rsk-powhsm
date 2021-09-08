SRCDIR = ../../src
CFLAGS = -I $(SRCDIR) -DFEDHM_EMULATOR -DDEBUG_DIFF

PROG = test.out
OBJS = bigdigits.o bc_diff.o test_difficulty.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

bigdigits.o: $(SRCDIR)/bigdigits.c
	$(CC) $(CFLAGS) -c -o $@ $^

bc_diff.o: $(SRCDIR)/bc_diff.c
	$(CC) $(CFLAGS) -c -o $@ $^

test_difficulty.o: test_difficulty.c bigdigits.o bc_diff.o

$(SRCDIR)/bigdigits.c: $(SRCDIR)/bigdigits.h $(SRCDIR)/bigdtypes.h
$(SRCDIR)/bc_diff.c: $(SRCDIR)/bc_diff.h $(SRCDIR)/bigdigits.h $(SRCDIR)/bigdtypes.h

.PHONY: clean test
clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
