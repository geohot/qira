This page provides a high-level description of some of the major code
phases that SeaBIOS transitions through and general information on
overall code flow.

SeaBIOS code phases
===================

The SeaBIOS code goes through a few distinct code phases during its
execution lifecycle. Understanding these code phases can help when
reading and enhancing the code.

POST phase
----------

The Power On Self Test (POST) phase is the initialization phase of the
BIOS. This phase is entered when SeaBIOS first starts execution. The
goal of the phase is to initialize internal state, initialize external
interfaces, detect and setup hardware, and to then start the boot
phase.

On emulators, this phase starts when the CPU starts execution in 16bit
mode at 0xFFFF0000:FFF0. The emulators map the SeaBIOS binary to this
address, and SeaBIOS arranges for romlayout.S:reset_vector() to be
present there. This code calls romlayout.S:entry_post() which then
calls post.c:handle_post() in 32bit mode.

On coreboot, the build arranges for romlayout.S:entry_elf() to be
called in 32bit mode. This then calls post.c:handle_post().

On CSM, the build arranges for romlayout.S:entry_csm() to be called
(in 16bit mode). This then calls csm.c:handle_csm() in 32bit mode.
Unlike on the emulators and coreboot, the SeaBIOS CSM POST phase is
orchastrated with UEFI and there are several calls back and forth
between SeaBIOS and UEFI via handle_csm() throughout the POST
process.

The POST phase itself has several sub-phases.

* The "preinit" sub-phase: code run prior to code relocation.
* The "init" sub-phase: code to initialize internal variables and
  interfaces.
* The "setup" sub-phase: code to setup hardware and drivers.
* The "prepboot" sub-phase: code to finalize interfaces and prepare
  for the boot phase.

At completion of the POST phase, SeaBIOS invokes an "int 0x19"
software interrupt in 16bit mode which begins the boot phase.

Boot phase
----------

The goal of the boot phase is to load the first portion of the
operating system's boot loader into memory and start execution of that
boot loader. This phase starts when a software interrupt ("int 0x19"
or "int 0x18") is invoked. The code flow starts in 16bit mode in
romlayout.S:entry_19() or romlayout.S:entry_18() which then
transition to 32bit mode and call boot.c:handle_19() or
boot.c:handle_18().

The boot phase is technically also part of the "runtime" phase of
SeaBIOS. It is typically invoked immiediately after the POST phase,
but it can also be invoked by an operating system or be invoked
multiple times in an attempt to find a valid boot media. Although the
boot phase C code runs in 32bit mode it does not have write access to
the 0x0f0000-0x100000 memory region and can not call the various
malloc_X() calls. See [Memory Model](Memory Model) for
more information.

Main runtime phase
------------------

The main runtime phase occurs after the boot phase starts the
operating system. Once in this phase, the SeaBIOS code may be invoked
by the operating system using various 16bit and 32bit calls. The goal
of this phase is to support these legacy calling interfaces and to
provide compatibility with BIOS standards. There are multiple entry
points for the BIOS - see the entry_XXX() assembler functions in
romlayout.S.

Callers use most of these legacy entry points by setting up a
particular CPU register state, invoking the BIOS, and then inspecting
the returned CPU register state. To handle this, SeaBIOS will backup
the current register state into a "struct bregs" (see romlayout.S,
entryfuncs.S, and bregs.h) on call entry and then pass this struct to
the C code. The C code can then inspect the register state and modify
it. The assembler entry functions will then restore the (possibly
modified) register state from the "struct bregs" on return to the
caller.

Resume and reboot
-----------------

As noted above, on emulators SeaBIOS handles the 0xFFFF0000:FFF0
machine startup execution vector. This vector is also called on
machine faults and on some machine "resume" events. It can also be
called (as 0xF0000:FFF0) by software as a request to reboot the
machine (on emulators, coreboot, and CSM).

The SeaBIOS "resume and reboot" code handles these calls and attempts
to determine the desired action of the caller. Code flow starts in
16bit mode in romlayout.S:reset_vector() which calls
romlayout.S:entry_post() which calls romlayout.S:entry_resume() which
calls resume.c:handle_resume(). Depending on the request the
handle_resume() code may transition to 32bit mode.

Technically this code is part of the "runtime" phase, so even though
parts of it run in 32bit mode it still has the same limitations of the
runtime phase.

Threads
=======

Internally SeaBIOS implements a simple cooperative multi-tasking
system. The system works by giving each "thread" its own stack, and
the system round-robins between these stacks whenever a thread issues
a yield() call. This "threading" system may be more appropriately
described as [coroutines](http://en.wikipedia.org/wiki/Coroutine).
These "threads" do not run on multiple CPUs and are not preempted, so
atomic memory accesses and complex locking is not required.

The goal of these threads is to reduce overall boot time by
parallelizing hardware delays. (For example, by allowing the wait for
an ATA harddrive to spinup and respond to commands to occur in
parallel with the wait for a PS/2 keyboard to respond to a setup
command.) These hardware setup threads are only available during the
"setup" sub-phase of the [POST phase](#POST_phase).

The code that implements threads is in stacks.c.

Hardware interrupts
===================

The SeaBIOS C code always runs with hardware interrupts disabled. All
of the C code entry points (see romlayout.S) are careful to explicitly
disable hardware interrupts (via "cli"). Because running with
interrupts disabled increases interrupt latency, any C code that could
loop for a significant amount of time (more than about 1 ms) should
periodically call yield(). The yield() call will briefly enable
hardware interrupts to occur, then disable interrupts, and then resume
execution of the C code.

There are two main reasons why SeaBIOS always runs C code with
interrupts disabled. The first reason is that external software may
override the default SeaBIOS handlers that are called on a hardware
interrupt event. Indeed, it is common for DOS based applications to do
this. These legacy third party interrupt handlers may have
undocumented expections (such as stack location and stack size) and
may attempt to call back into the various SeaBIOS software services.
Greater compatibility and more reproducible results can be achieved by
only permitting hardware interrupts at specific points (via yield()
calls). The second reason is that much of SeaBIOS runs in 32bit mode.
Attempting to handle interrupts in both 16bit mode and 32bit mode and
switching between modes to delegate those interrupts is an unneeded
complexity. Although disabling interrupts can increase interrupt
latency, this only impacts legacy systems where the small increase in
interrupt latency is unlikely to be noticeable.

Extra 16bit stack
=================

SeaBIOS implements 16bit real mode handlers for both hardware
interrupts and software request "interrupts". In a traditional BIOS,
these requests would use the caller's stack space. However, the
minimum amount of space the caller must provide has not been
standardized and very old DOS programs have been observed to allocate
very small amounts of stack space (100 bytes or less).

By default, SeaBIOS now switches to its own stack on most 16bit real
mode entry points. This extra stack space is allocated in ["low
memory"](Memory Model). It ensures SeaBIOS uses a minimal amount of a
callers stack (typically no more than 16 bytes) for these legacy
calls. (More recently defined BIOS interfaces such as those that
support 16bit protected and 32bit protected mode calls standardize a
minimum stack size with adequete space, and SeaBIOS generally will not
use its extra stack in these cases.)

The code to implement this stack "hopping" is in romlayout.S and in
stacks.c.
