The SeaBIOS code is required to support multiple x86 CPU memory
models. This requirement impacts the code layout and internal storage
of SeaBIOS.

x86 Memory Models
=================

The x86 line of CPUs has evolved over many years. The original 8086
chip used 16bit pointers and could only address 1 megabyte of memory.
The 80286 CPU still used 16bit pointers, but could address up to 16
megabytes of memory. The 80386 chips could process 32bit instructions
and could access up to 4 gigabyte of memory. The most recent x86 chips
can process 64bit instructions and access 16 exabytes of ram.

During the evolution of the x86 CPUs from the 8086 to the 80386 the
BIOS was extended to handle calls in the various modes that the CPU
implemented.

This section outlines the five different x86 CPU execution and memory
access models that SeaBIOS supports.

16bit real mode
---------------

This mode is a
[segmented](http://en.wikipedia.org/wiki/Memory_segmentation) memory
mode invoked by callers. The CPU defaults to executing 16bit
instructions. Callers typically invoke the BIOS by issuing an "int x"
instruction which causes a software
[interrupt](http://en.wikipedia.org/wiki/Interrupt) that is handled by
the BIOS. The SeaBIOS code also handles hardware interrupts in this
mode. SeaBIOS can only access the first 1 megabyte of memory in this
mode, but it can access any part of that first megabyte.

16bit bigreal mode
------------------

This mode is a segmented memory mode that is used for [option
roms](http://en.wikipedia.org/wiki/Option_ROM). The CPU defaults to
executing 16bit instructions and segmented memory accesses are still
used. However, the segment limits are increased so that the entire
first 4 gigabytes of memory is fully accessible. Callers can invoke
all the [16bit real mode](#16bit_real_mode) functions while in this
mode and can also invoke the Post Memory Manager (PMM) functions that
are available during option rom execution.

16bit protected mode
--------------------

CPU execution in this mode is similar to [16bit real
mode](#16bit_real_mode). The CPU defaults to executing 16bit
instructions. However, each segment register indexes a "descriptor
table", and it is difficult or impossible to know what the physical
address of each segment is. Generally speaking, the BIOS can only
access code and data in the f-segment. The PCIBIOS, APM BIOS, and PNP
BIOS all have documented 16bit protected mode entry points.

Some old code may attempt to invoke the standard [16bit real
mode](#16bit_real_mode) entry points while in 16bit protected
mode. The PCI BIOS specification explicitly requires that the legacy
"int 1a" real mode entry point support 16bit protected mode calls if
they are for the PCI BIOS. Callers of other legacy entry points in
protected mode have not been observed and SeaBIOS does not support
them.

32bit segmented mode
--------------------

In this mode the processor runs in 32bit mode, but the segment
registers may have a limit and may have a non-zero offset. In effect,
this mode has all of the limitations of [16bit protected
mode](#16bit_protected_mode) - the main difference between the modes
is that the processor defaults to executing 32bit instructions. In
addition to these limitations, callers may also run the SeaBIOS code
at varying virtual addresses and so the code must support code
relocation. The PCI BIOS specification and APM BIOS specification
define 32bit segmented mode interfaces.

32bit flat mode
---------------

In this mode the processor defaults to executing 32bit instructions,
and all segment registers have an offset of zero and allow access to
the entire first 4 gigabytes of memory. This is the only "sane" mode
for 32bit code - modern compilers and modern operating systems will
generally only support this mode (when running 32bit code).
Ironically, it's the only mode that is not strictly required for a
BIOS to support. SeaBIOS uses this mode internally to support the POST
and BOOT [phases of execution](Execution and code flow).

code16gcc
=========

In order to produce code that can run when the processor is in a 16bit
mode, SeaBIOS uses the
[binutils](http://en.wikipedia.org/wiki/GNU_Binutils) ".code16gcc"
assembler flag. This instructs the assembler to emit extra prefix
opcodes so that the 32bit code produced by
[gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection) will run
even when the processor is in 16bit mode. Note that gcc always
produces 32bit code - it does not know about the ".code16gcc" flag and
does not know that the code will run in a 16bit mode.

SeaBIOS uses the same code for all of the 16bit modes ([16bit real
mode](#16bit_real_mode), [16bit bigreal mode](#16bit_bigreal_mode),
and [16bit protected mode](#16bit_protected_mode)) and that code is
assembled using ".code16gcc". SeaBIOS is careful to use segment
registers properly so that the same code can run in the different
16bit modes that it needs to support.

C code mode flags
=================

Two compile time flags are available to determine the memory model the
code is intended for: MODE16 and MODESEGMENT. When compiling for the
16 bit modes, MODE16 is true and MODESEGMENT is true. In 32bit
segmented mode, MODE16 is false and MODESEGMENT is true. In 32bit flat
mode both MODE16 and MODESEGMENT are false.

Common memory used at run-time
==============================

There are several memory areas that the SeaBIOS "runtime"
[phase](Execution and code flow) makes use of:

* 0x000000-0x000400: Interrupt descriptor table (IDT). This area
  defines 256 interrupt vectors as defined by the Intel CPU
  specification for 16bit irq handlers. This area is read/writable at
  runtime and can be accessed from 16bit real mode and 16bit bigreal
  mode calls. SeaBIOS only uses this area to maintain compatibility
  with legacy systems.

* 0x000400-0x000500: BIOS Data Area (BDA). This area contains various
  legacy flags and attributes. The area is read/writable at runtime
  and can be accessed from 16bit real mode and 16bit bigreal mode
  calls. SeaBIOS only uses this area to maintain compatibility with
  legacy systems.

* 0x09FC00-0x0A0000 (typical): Extended BIOS Data Area (EBDA). This
  area contains a few legacy flags and attributes. The area is
  typically located at 0x9FC00, but it can be moved by option roms, by
  legacy operating systems, and by SeaBIOS if
  CONFIG_MALLOC_UPPERMEMORY is not set. Its actual location is
  determined by a pointer in the BDA. The area is read/writable at
  runtime and can be accessed from 16bit real mode and 16bit bigreal
  mode calls. SeaBIOS only uses this area to maintain compatibility
  with legacy systems.

* 0x0E0000-0x0F0000 (typical): "low" memory. This area is used for
  custom read/writable storage internal to SeaBIOS. The area is
  read/writable at runtime and can be accessed from 16bit real mode
  and 16bit bigreal mode calls. The area is typically located at the
  end of the e-segment, but the build may position it anywhere in the
  0x0C0000-0x0F0000 region. However, if CONFIG_MALLOC_UPPERMEMORY is
  not set, then this region is between 0x090000-0x0A0000. Space is
  allocated in this region by either marking a global variable with
  the "VARLOW" flag or by calling malloc_low() during
  initialization. The area can be grown dynamically (via malloc_low),
  but it will never exceed 64K.

* 0x0F0000-0x100000: The BIOS segment. This area is used for both
  runtime code and static variables. Space is allocated in this region
  by either marking a global variable with VAR16, one of the VARFSEG
  flags, or by calling malloc_fseg() during initialization. The area
  is read-only at runtime and can be accessed from 16bit real mode,
  16bit bigreal mode, 16bit protected mode, and 32bit segmented mode
  calls.

All of the above areas are also read/writable during the SeaBIOS
initialization phase and are accessible when in 32bit flat mode.

Segmented mode memory access
============================

The assembler entry functions for segmented mode calls (all modes
except [32bit flat mode](#32bit_flat_mode)) will arrange
to set the data segment (%ds) to be the same as the stack segment
(%ss) before calling any C code. This permits all C variables located
on the stack and C pointers to data located on the stack to work as
normal.

However, all code running in segmented mode must wrap non-stack memory
accesses in special macros. These macros ensure the correct segment
register is used. Failure to use the correct macro will result in an
incorrect memory access that will likely cause hard to find errors.

There are three low-level memory access macros:

* GET_VAR / SET_VAR : Accesses a variable using the specified segment
  register. This isn't typically used directly by C code.

* GET_FARVAR / SET_FARVAR : Assigns the extra segment (%es) to the
  given segment id and then performs the given memory access via %es.

* GET_FLATVAR / SET_FLATVAR : These macros take a 32bit pointer,
  construct a segment/offset pair valid in real mode, and then perform
  the given access. These macros must not be used in 16bit protected
  mode or 32bit segmented mode.

Since most memory accesses are to [common memory used at
run-time](#Common_memory_used_at_run-time), several helper
macros are also available.

* GET_IDT / SET_IDT : Access the interrupt descriptor table (IDT).

* GET_BDA / SET_BDA : Access the BIOS Data Area (BDA).

* GET_EBDA / SET_EBDA : Access the Extended BIOS Data Area (EBDA).

* GET_LOW / SET_LOW : Access internal variables marked with
  VARLOW. (There are also related macros GET_LOWFLAT / SET_LOWFLAT for
  accessing storage allocated with malloc_low).

* GET_GLOBAL : Access internal variables marked with the VAR16 or
  VARFSEG flags. (There is also the related macro GET_GLOBALFLAT for
  accessing storage allocated with malloc_fseg).

Memory available during initialization
======================================

During the POST [phase](Execution and code flow) the code
can fully access the first 4 gigabytes of memory. However, memory
accesses are generally limited to the [common memory used at
run-time](#Common_memory_used_at_run-time) and areas
allocated at runtime via one of the malloc calls:

* malloc_high : Permanent high-memory zone. This area is used for
  custom read/writable storage internal to SeaBIOS. The area is
  located at the top of the first 4 gigabytes of ram. It is commonly
  used for storing standard tables accessed by the operating system at
  runtime (ACPI, SMBIOS, and MPTable) and for DMA buffers used by
  hardware drivers. The area is read/writable at runtime and an entry
  in the e820 memory map is used to reserve it. When running on an
  emulator that has only 1 megabyte of ram this zone will be empty.

* malloc_tmphigh : Temporary high-memory zone. This area is used for
  custom read/writable storage during the SeaBIOS initialization
  phase. The area generally starts after the first 1 megabyte of ram
  (0x100000) and ends prior to the Permanent high-memory zone. When
  running on an emulator that has only 1 megabyte of ram this zone
  will be empty. The area is not reserved from the operating system,
  so it must not be accessed after the SeaBIOS initialization phase.

* malloc_tmplow : Temporary low-memory zone. This area is used for
  custom read/writable storage during the SeaBIOS initialization
  phase. The area resides between 0x07000-0x90000. The area is not
  reserved from the operating system and by specification it is
  required to be zero'd at the end of the initialization phase.

The "tmplow" and "tmphigh" regions are only available during the
initialization phase. Any access (either read or write) after
completion of the initialization phase can result in difficult to find
errors.
