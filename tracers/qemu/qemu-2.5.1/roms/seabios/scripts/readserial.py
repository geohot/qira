#!/usr/bin/env python
# Script that can read from a serial device and show timestamps.
#
# Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

# Usage:
#   scripts/readserial.py /dev/ttyUSB0 115200

import sys, os, time, select, optparse

from python23compat import as_bytes

# Reset time counter after this much idle time.
RESTARTINTERVAL = 60
# Number of bits in a transmitted byte - 8N1 is 1 start bit + 8 data
# bits + 1 stop bit.
BITSPERBYTE = 10

def calibrateserialwrite(outfile, byteadjust):
    # Build 4000 bytes of dummy data.
    data = "0123456789" * 4 + "012345678" + "\n"
    data = data * 80
    while 1:
        st = time.time()
        outfile.write(as_bytes(data))
        outfile.flush()
        et = time.time()
        sys.stdout.write(
            "Wrote %d - %.1fus per char (theory states %.1fus)\n" % (
                len(data), (et-st) / len(data) * 1000000, byteadjust * 1000000))
        sys.stdout.flush()
        time.sleep(3)

def calibrateserialread(infile, byteadjust):
    starttime = lasttime = 0
    totalchars = 0
    while 1:
        select.select([infile], [], [])
        d = infile.read(4096)
        curtime = time.time()
        if curtime - lasttime > 1.0:
            if starttime and totalchars:
                sys.stdout.write(
                    "Calibrating on %d bytes - %.1fus per char"
                    " (theory states %.1fus)\n" % (
                        totalchars,
                        float(lasttime - starttime) * 1000000 / totalchars,
                        byteadjust * 1000000))
            totalchars = 0
            starttime = curtime
        else:
            totalchars += len(d)
        lasttime = curtime

def readserial(infile, logfile, byteadjust):
    lasttime = 0
    while 1:
        # Read data
        try:
            res = select.select([infile, sys.stdin], [], [])
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            return -1
        if sys.stdin in res[0]:
            # Got keyboard input - force reset on next serial input
            sys.stdin.read(1)
            lasttime = 0
            if len(res[0]) == 1:
                continue
        d = infile.read(4096)
        if not d:
            return 0
        datatime = time.time()

        datatime -= len(d) * byteadjust

        # Reset start time if no data for some time
        if datatime - lasttime > RESTARTINTERVAL:
            starttime = datatime
            charcount = 0
            isnewline = 1
            msg = "\n\n======= %s (adjust=%.1fus)\n" % (
                time.asctime(time.localtime(datatime)), byteadjust * 1000000)
            sys.stdout.write(msg)
            logfile.write(as_bytes(msg))
        lasttime = datatime

        # Translate unprintable chars; add timestamps
        out = as_bytes("")
        for c in d:
            if isnewline:
                delta = datatime - starttime - (charcount * byteadjust)
                out += "%06.3f: " % delta
                isnewline = 0
            oc = ord(c)
            charcount += 1
            datatime += byteadjust
            if oc == 0x0d:
                continue
            if oc == 0x00:
                out += "<00>\n"
                isnewline = 1
                continue
            if oc == 0x0a:
                out += "\n"
                isnewline = 1
                continue
            if oc < 0x20 or oc >= 0x7f and oc != 0x09:
                out += "<%02x>" % oc
                continue
            out += c

        if (sys.version_info > (3, 0)):
            sys.stdout.buffer.write(out)
        else:
            sys.stdout.write(out)
        sys.stdout.flush()
        logfile.write(out)
        logfile.flush()

def main():
    usage = "%prog [options] [<serialdevice> [<baud>]]"
    opts = optparse.OptionParser(usage)
    opts.add_option("-f", "--file",
                    action="store_false", dest="serial", default=True,
                    help="read from unix named pipe instead of serialdevice")
    opts.add_option("-n", "--no-adjust",
                    action="store_false", dest="adjustbaud", default=True,
                    help="don't adjust times by serial rate")
    opts.add_option("-c", "--calibrate-read",
                    action="store_true", dest="calibrate_read", default=False,
                    help="read from serial port to calibrate it")
    opts.add_option("-C", "--calibrate-write",
                    action="store_true", dest="calibrate_write", default=False,
                    help="write to serial port to calibrate it")
    opts.add_option("-t", "--time",
                    type="float", dest="time", default=None,
                    help="time to write one byte on serial port (in us)")
    options, args = opts.parse_args()
    serialport = 0
    baud = 115200
    if len(args) > 2:
        opts.error("Too many arguments")
    if len(args) > 0:
        serialport = args[0]
    if len(args) > 1:
        baud = int(args[1])
    byteadjust = float(BITSPERBYTE) / baud
    if options.time is not None:
        byteadjust = options.time / 1000000.0
    if not options.adjustbaud:
        byteadjust = 0.0

    if options.serial:
        # Read from serial port
        try:
            import serial
        except ImportError:
            print("""
Unable to find pyserial package ( http://pyserial.sourceforge.net/ ).
On Linux machines try: yum install pyserial
Or: apt-get install python-serial
""")
            sys.exit(1)
        ser = serial.Serial(serialport, baud, timeout=0)

    if options.calibrate_read:
        calibrateserialread(ser, byteadjust)
        return
    if options.calibrate_write:
        calibrateserialwrite(ser, byteadjust)
        return

    logname = time.strftime("seriallog-%Y%m%d_%H%M%S.log")
    f = open(logname, 'wb')
    if options.serial:
        readserial(ser, f, byteadjust)
    else:
        # Read from a pipe
        while 1:
            ser = os.fdopen(os.open(serialport, os.O_RDONLY|os.O_NONBLOCK), 'rb')
            res = readserial(ser, f, byteadjust)
            ser.close()
            if res < 0:
                break

if __name__ == '__main__':
    main()
