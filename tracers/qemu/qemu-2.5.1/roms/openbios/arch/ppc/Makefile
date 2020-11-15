
include			../../config/Makefile.top

SUBDIRS			= 
MOL			= $(CONFIG_MOL:y=mol)
BRIQ			= $(CONFIG_BRIQ:y=briq)
XTARGETS		= $(MOL) $(BRIQ) ppc mollink
DICTIONARIES		= $(MOL) $(BRIQ)

INCLUDES		= -I../../kernel -I../../kernel/include \
			  -I../../include/molasm -I$(ODIR)/include

#############################################################################

mol-OBJS		= mol/init.o mol/main.o mol/mol.o mol/console.o mol/osi-blk.o \
			  mol/osi-scsi.o mol/pseudodisk.o mol/methods.o ofmem.o \
			  mol/video.o mol/prom.o mol/tree.o misc.o mol/kernel.o

briq-OBJS		= briq/init.o briq/main.o briq/briq.o briq/vfd.o \
			  ofmem.o briq/methods.o briq/tree.o \
			  misc.o briq/kernel.o

ppc-OBJS		= $(KOBJS) $(MODULE_LIBS) \
			  $(FS_LIBS) $(DRIVER_LIBS) $(LIBC_LIBS)

all-$(CONFIG_MOL)	+= $(ODIR)/mol.image
all-$(CONFIG_BRIQ)	+= $(ODIR)/briq.image
all-$(CONFIG_MPC107)	+= $(ODIR)/mpc107.image


#############################################################################

mol-SRC			= ppc.fs tree.fs mol.fs $(ARCHDICT_SRC)
briq-SRC		= ppc.fs briq/tree.fs briq/briq.fs $(ARCHDICT_SRC)

$(ODIR)/mol/kernel.o:	$(ODIR)/include/mol-dict.h
$(ODIR)/briq/kernel.o:	$(ODIR)/include/briq-dict.h

$(ODIR)/include/mol-dict.h: $(ODIR)/mol.dict
	test -d $(dir $@) || $(INSTALL) -d $(dir $@)
	@echo "static const char forth_dictionary[] = {" > $@
	@cat $< | hexdump -ve '1/0 "\t" 8/1 "0x%02x, " 1/0 "\n"' \
		| sed 's/0x  ,//g' >> $@
	@echo "};" >> $@

$(ODIR)/include/briq-dict.h: $(ODIR)/briq.dict
	test -d $(dir $@) || $(INSTALL) -d $(dir $@)
	@echo "static const char forth_dictionary[] = {" > $@
	@cat $< | hexdump -ve '1/0 "\t" 8/1 "0x%02x, " 1/0 "\n"' \
		| sed 's/0x  ,//g' >> $@
	@echo "};" >> $@

#############################################################################

$(ODIR)/mol.image: $(ODIR)/start.o $(ODIR)/libmol.a $(ODIR)/libppc.a
	@printf "= Building %-22s : " $@
	building=
	$(LD) -Ttext=0x01e01000 -Bstatic $^ $(LIBGCC) -o $@
	@nm $@ | sort > $(ODIR)/mol.syms
	strip -g $@
	@echo "ok"

$(ODIR)/briq.image: $(ODIR)/start.o $(ODIR)/timebase.o $(ODIR)/libbriq.a $(ODIR)/libppc.a
	@printf "= Building %-22s : " $@
	building=
	$(LD) -g -Ttext=0x01e01000 -Bstatic $^ $(LIBGCC) -o $@
	@nm $@ | sort > $(ODIR)/briq.syms
	#strip -g $@
	@echo "ok"

$(ODIR)/mpc107.image:
	@echo "BUILDING mpc107.image (not yet implemented)"

clean-local:
	$(RM) $(ODIR)/*.image $(ODIR)/*.syms $(ODIR)/include/mol-dict.h

include			Makefile.asm
include			$(rules)/Rules.make
include			$(rules)/Rules.forth
