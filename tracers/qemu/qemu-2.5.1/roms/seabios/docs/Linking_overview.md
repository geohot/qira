This page describes the process that the SeaBIOS build uses to link
the compiled code into the final binary objects.

Unfortunately, the SeaBIOS linking phase is complex. This complexity
is due to several unusual requirements:

* Some BIOS entry points must reside at specific hardcoded memory
  locations. The build must support positioning code and variables at
  specific locations.
* In order to support multiple [memory models](Memory Model) the same
  C code can be complied in three modes (16bit mode, 32bit segmented
  mode, and 32bit "flat" mode). Binary code from these three modes
  must be able to co-exist and on occasion reference each other.
* There is a finite amount of memory available to the BIOS. The build
  will attempt to weed out unused code and variables from the final
  binary. It also supports self-relocation of one-time initialization
  code.

Code layout
===========

To support the unusual build requirements, several
[gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection) compiler
options are used. The "-ffunction-sections" and "-fdata-sections"
flags instruct the compiler to place each variable and function into
its own
[ELF](http://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
section.

The C code is compiled three times into three separate objects for
each of the major supported [memory models](Memory Model):
**code16.o**, **code32seg.o**, and **code32flat.o**. Information on
the sections and symbols of these three objects are extracted (using
**objdump**) and passed in to the **scripts/layoutrom.py** python
script. This script analyzes this information and produces gnu
[ld](http://en.wikipedia.org/wiki/GNU_linker) "linker scripts" which
provide precise location information to the linker. These linker
scripts are then used during the link phase which produces a **rom.o**
object containing all the code.

Fixed location entry points
---------------------------

The build supports placing code entry points and variables at fixed
memory locations. This support is required in order to support the
legacy BIOS standards. For example, a program might execute an "int
0x15" to request system information from the BIOS, but another old
program might use "ljmpw $0xf000, $0xf859" instead. Both must provide
the same results and so the build must position the 0x15 interrupt
entry point in physical memory at 0xff859.

This support is accomplished by placing the given code/variables into
ELF sections that have a name containing the substring
".fixedaddr.0x1234" (where 0x1234 is the desired address). For
variables in C code this is accomplished by marking the variables with
the VARFSEGFIXED(0x1234) macro. For assembler entry points the ORG
macro is used (see **romlayout.S**).

During the build, the **layoutrom.py** script will detect sections
that contain the ".fixedaddr." substring and will arrange for the
final linker scripts to specify the desired address for the given
section.

Due to the sparse nature of these fixed address sections, the
layoutrom.py script will also arrange to pack in other unrelated 16bit
code into the free space between fixed address sections (see
layoutrom.py:fitSections()). This maximizes the space available and
reduces the overall size of the final binary.

C code in three modes
---------------------

SeaBIOS must support multiple [memory models](Memory Model). This is
accomplished by compiling the C code three separate times into three
separate objects.

The C code within a mode must not accidentally call a C function in
another mode, but multiple modes must all access the same single copy
of global variables. Further, it is occasionally necessary for the C
code in one mode to obtain the address of C code in another mode.

In order to use the same global variables between all modes, the
layoutrom.py script will detect references to global variables and
emit specific symbol definitions for those global variables in the
linker scripts so that all references use the same physical memory
address (see layoutrom.py:outXRefs()).

To ensure C code does not accidentally call C code compiled in a
different mode, the build will ensure the symbols for C code in each
mode are isolated from each other during the linking stage. To support
those situations where an address of a C function in another mode is
required the build supports symbols with a special "\_cfuncX_"
prefix. The layoutrom.py script detects these references and will emit
a corresponding symbol definitions in the linker script that points to
the C code of the specified mode. This is typically seen with code
like:

`extern void _cfunc32flat_process_op(void);`\
`return call32(_cfunc32flat_process_op, 0, 0);`

In the above example, when the build finds the symbol
"\_cfunc32flat_process_op" it will emit that symbol with the physical
address of the 32bit "flat" version of the process_op() C function.

Build garbage collection
------------------------

To reduce the overall size of the final SeaBIOS binary the build
supports automatically weeding out of unused code and variables. This
is done with two separate processes: when supported the gcc
"-fwhole-program" compilation flag is used, and the layoutrom.py
script checks for unreferenced ELF sections. The layoutrom.py script
builds the final linker scripts with only referenced ELF sections, and
thus unreferenced sections are weeded out from the final objects.

When writing C code, it is necessary to mark C functions with the
VISIBLE16, VISIBLE32SEG, or VISIBLE32FLAT macros if the functions are
ever referenced from assembler code. These macros ensure the
corresponding C function is emitted by the C compiler when compiling
for the given memory mode. These macros, however, do not affect the
layoutrom.py reference check, so even a function decorated with one of
the above macros can be weeded out from the final object if it is
never referenced.

Code relocation
---------------

To further reduce the runtime memory size of the BIOS, the build
supports runtime self-relocation. Normally SeaBIOS is loaded into
memory in the memory region at 0xC0000-0x100000. This is convenient
for initial binary deployment, but the space competes with memory
requirements for Option ROMs, BIOS tables, and runtime storage. By
default, SeaBIOS will self-relocate its one-time initialization code
to free up space in this region.

To support this feature, the build attempts to automatically detect
which C code is exclusively initialization phase code (see
layoutrom.py:checkRuntime()). It does this by finding all functions
decorated with the VISIBLE32INIT macro and all functions only
reachable via functions with that macro. These "init only" functions
are then grouped together and their location and size is stored in the
binary for the runtime code to relocate (see post.c:reloc_preinit()).

The build also locates all cross section code references along with
all absolute memory addresses in the "init only" code. These addresses
need to be modified with the new run-time address in order for the
code to successfully run at a new address. The build finds the
location of the addresses (see layoutrom.py:getRelocs()) and stores
the information in the final binary.

Final binary checks
===================

At the conclusion of the main linking stage, the code is contained in
the file **rom.o**. This object file contains all of the assembler
code, variables, and the C code from all three memory model modes.

At this point the **scripts/checkrom.py** script is run to perform
final checks on the code. The script performs some sanity checks, it
may update some tables in the binary, and it reports some size
information.

After the checkrom.py script is run the final user visible binary is
produced. The name of the final binary is either **bios.bin**,
**Csm16.bin**, or **bios.bin.elf** depending on the SeaBIOS build
requested.
