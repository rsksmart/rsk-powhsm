SRCDIR = ../../src
CFLAGS = -I $(SRCDIR)

PROG = test.out
OBJS = sha256.o test_sha256.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $^

sha256.o: $(SRCDIR)/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $^

test_sha256.o: test_sha256.c sha256.o
$(SRCDIR)/sha256.c: $(SRCDIR)/sha256.h

.PHONY: clean
clean:
	rm $(PROG) ./*.o
