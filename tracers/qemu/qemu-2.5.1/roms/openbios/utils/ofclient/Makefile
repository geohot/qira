PROGRAM := ofclient
OBJECTS := of1275.o of1275_io.o ofclient.o 
CC      := gcc 
CFLAGS  := -m32 -fpic -fno-builtin-strlen -Os
LDFLAGS := -melf_i386 -s -N -Ttext 0x200000 -e _start

$(PROGRAM): $(OBJECTS)
	$(LD) $(LDFLAGS) -Map $(PROGRAM).map -o $(PROGRAM) $(OBJECTS)

clean:
	rm -f $(OBJECTS)

distclean: clean
	rm -f $(PROGRAM) $(PROGRAM).map
