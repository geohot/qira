BLIB = ../bin/blib.a
CFLAGS = -Os

all : hijack mucurses_test

hijack : hijack.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -Wall -lpcap -o $@ $<

mucurses_test.o : mucurses_test.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -Wall -o $@ -c $<

mucurses_test : mucurses_test.o $(BLIB)
	$(CC) -o $@ $< -lc $(BLIB)

clean :
	rm -f hijack mucurses_test *.o
