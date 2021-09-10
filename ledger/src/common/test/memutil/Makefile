SRCDIR = ../../src
CFLAGS = -I $(SRCDIR) -I ./

PROG = test.out
OBJS = test_memutil.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

test_memutil.o: test_memutil.c $(SRCDIR)/memutil.h os.h

.PHONY: clean test

clean:
	rm -f $(PROG) ./*.o

test: all
	./$(PROG)
