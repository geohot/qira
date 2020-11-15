
include		../../../../config/Makefile.top

PLUGINS		= plugin_qt.so

QMAKE		= qmake
PLUGINDIR	= $(shell cd .. ; pwd )
TOPDIR		= $(shell cd $(top_srcdir) ; pwd)
ABSOINC		= $(shell cd $(ARCHINCLUDES) 2> /dev/null ; pwd )

export PLUGINDIR TOPDIR ABSOINC

qt_rom.fc: qt_rom.fs
	$(TOKE) -v qt_rom.fs

fcode.h: qt_rom.fc
	@echo "static const u8 qt_fcode[] = {" > $@
	@cat $< | hexdump -ve '1/0 "\t" 8/1 "0x%02x, " 1/0 "\n"' \
		| sed 's/0x  ,//g' >> $@
	@echo "};" >> $@

$(ODIR)/makefile.qmake: plugin_qt.pro Makefile
	@test -d $(ODIR) || $(INSTALL) -d $(ODIR)
	@test -d $(ODIR)/qbuild || $(INSTALL) -d $(ODIR)/qbuild
	@cp plugin_qt.pro $(ODIR)/
	cd $(ODIR) ; $(QMAKE) -o makefile.qmake

$(ODIR)/plugin_qt.so: fcode.h $(ODIR)/makefile.qmake $(wildcard *.cpp)
	cd $(ODIR) ; $(MAKE) -f makefile.qmake
	@ln -f $(ODIR)/qbuild/plugin_qt.so $@

clean-local:
	@rm -f $(ODIR)/makefile.qmake
	@rm -rf $(QBUILDDIR) $(ODIR)/*.fc $(ODIR)/fcode.h

include		../Rules.plugin
include		$(rules)/Rules.make
