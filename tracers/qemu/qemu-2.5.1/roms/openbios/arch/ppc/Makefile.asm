# -*- makefile -*- 
#
#   Makefile.asm - assembly support
#   
#   Copyright (C) 2004 Samuel Rydh (samuel@ibrium.se)
#   
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   version 2


#################################################
# Rules for asm targets
#################################################

ASMFLAGS	= -D__ASSEMBLY__ -I$(top_srcdir) $(ALTIVEC)
FILTERBIN	= $(top_srcdir)/scripts/asfilter
ASFILTER	= $(shell if test -x $(FILTERBIN) ; then echo $(FILTERBIN) \
			; else echo "tr ';' '\n'" ; fi)
INVOKE_M4	= | $(M4) -s $(M4_NO_GNU) | $(ASFILTER)

$(ODIR)/%.o: %.S
	@printf "    Compiling %-20s: " $(notdir $@)
	assembly=
	@install -d $(dir $@)
	@$(RM) $@ $@.s
	@$(CPP) $(ASMFLAGS) $(IDIRS) $< > /dev/null
	$(CPP) $(ASMFLAGS) $(IDIRS) $(DEPFLAGS) $< $(INVOKE_M4) > $@.s
	$(AS) $@.s $(AS_FLAGS) -o $@
	@$(DEPEXTRA)
	@$(RM) $@.s
	@echo "ok"
