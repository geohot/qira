This page describes the process of obtaining diagnostic information
from SeaBIOS and for reporting problems.

Diagnostic information
======================

SeaBIOS has the ability to output diagnostic messages. This is
implemented in the code via calls to the "dprintf()" C function.

On QEMU these messages are written to a special debug port. One can
view these messages by adding '-chardev stdio,id=seabios -device
isa-debugcon,iobase=0x402,chardev=seabios' to the QEMU command line.
Once this is done, one should see status messages on the console.

On coreboot these messages are generally written to the "cbmem"
console (CONFIG_DEBUG_COREBOOT). If SeaBIOS launches a Linux operating
system, one can obtain the cbmem tool from the coreboot repository and
run "cbmem -c" to view the SeaBIOS diagnostic messages.

Additionally, if a serial port is available, one may compile SeaBIOS
to send the diagnostic messages to the serial port. See the SeaBIOS
CONFIG_DEBUG_SERIAL option.

Trouble reporting
=================

If you are experiencing problems with SeaBIOS, it's useful to increase
the debugging level. This is done by running "make menuconfig" and
setting CONFIG_DEBUG_LEVEL to a higher value. A debug level of 8 will
show a lot of diagnostic information without flooding the serial port
(levels above 8 will frequently cause too much data).

To report an issue, please collect the serial boot log with SeaBIOS
set to a debug level of 8 and forward the full log along with a
description of the problem to the SeaBIOS [mailing list](Mailinglist).

Timing debug messages
=====================

The SeaBIOS repository has a tool (**scripts/readserial.py**) that can
timestamp each diagnostic message produced. The timestamps can provide
some additional information on how long internal processes take. It
also provides a simple profiling mechanism.

The tool can be used on coreboot builds that have diagnostic messages
sent to a serial port. Make sure SeaBIOS is configured with
CONFIG_DEBUG_SERIAL and run the following on the host receiving serial
output:

`/path/to/seabios/scripts/readserial.py /dev/ttyS0 115200`

Update the above command with the appropriate serial device and baud
rate.

The tool can also timestamp the messages from the QEMU debug port. To
use with QEMU run the following:

`mkfifo qemudebugpipe`\
`qemu -chardev pipe,path=qemudebugpipe,id=seabios -device isa-debugcon,iobase=0x402,chardev=seabios ...`

and then in another session:

`/path/to/seabios/scripts/readserial.py -nf qemudebugpipe`

The mkfifo command only needs to be run once to create the pipe file.

When readserial.py is running, it shows a timestamp with millisecond
precision of the amount of time since the start of the log. If one
presses the "enter" key in the readserial.py session it will add a
blank line to the screen and also reset the time back to zero. The
readserial.py program also keeps a log of all output in files that
look like "seriallog-YYYYMMDD_HHMMSS.log".

Debugging with gdb on QEMU
==========================

One can use gdb with QEMU to debug system images. To do this, add '-s
-S' to the qemu command line. For example:

`qemu -bios out/bios.bin -fda myfdimage.img -s -S`

Then, in another session, run gdb with either out/rom16.o (to debug
bios 16bit code) or out/rom.o (to debug bios 32bit code). For example:

`gdb out/rom16.o`

Once in gdb, use the command "target remote localhost:1234" to have
gdb connect to QEMU. See the QEMU documentation for more information
on using gdb and QEMU in this mode.

When debugging 16bit code, also run the following commands in gdb:

`set architecture i8086`\
`add-symbol-file out/rom16.o 0xf0000`

The second command loads the 16bit symbols a second time at an offset
of 0xf0000, which helps gdb set and catch breakpoints correctly.

To debug a VGA BIOS image, run "gdb out/vgarom.o" add use the gdb
command "add-symbol-file out/vgarom.o 0xc0000" to load the 16bit VGA
BIOS symbols twice.

If debugging the 32bit SeaBIOS initialization code with gdb, note that
SeaBIOS does self relocation by default. This relocation will alter
the location of initialization code symbols. Disable
CONFIG_RELOCATE_INIT to prevent SeaBIOS from doing this.
