# comment this if you don't want debugging information
CFLAGS += -DDEBUG

TARGET	=	bios.o
OBJS	=	bios_core.o flashchips.o pcisets.o \
		filesystem.o procfs.o programming.o

obj-m           := $(TARGET)
bios-objs     := $(OBJS)

all: module comp

clean:
	-rm -f $(TARGET) $(OBJS) comp *.o bios.ko
	-rm -rf .*.cmd .tmp_versions
module:
	make -C /usr/src/linux SUBDIRS=`pwd` modules

comp:   comp.c
	$(CC) comp.c -O2 -o comp
	strip comp

