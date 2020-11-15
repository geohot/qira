// Internal timer and Intel 8253 Programmable Interrupt Timer (PIT) support.
//
// Copyright (C) 2008-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_LOW
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "stacks.h" // yield
#include "util.h" // timer_setup
#include "x86.h" // cpuid

#define PORT_PIT_COUNTER0      0x0040
#define PORT_PIT_COUNTER1      0x0041
#define PORT_PIT_COUNTER2      0x0042
#define PORT_PIT_MODE          0x0043
#define PORT_PS2_CTRLB         0x0061

// Bits for PORT_PIT_MODE
#define PM_SEL_TIMER0   (0<<6)
#define PM_SEL_TIMER1   (1<<6)
#define PM_SEL_TIMER2   (2<<6)
#define PM_SEL_READBACK (3<<6)
#define PM_ACCESS_LATCH  (0<<4)
#define PM_ACCESS_LOBYTE (1<<4)
#define PM_ACCESS_HIBYTE (2<<4)
#define PM_ACCESS_WORD   (3<<4)
#define PM_MODE0 (0<<1)
#define PM_MODE1 (1<<1)
#define PM_MODE2 (2<<1)
#define PM_MODE3 (3<<1)
#define PM_MODE4 (4<<1)
#define PM_MODE5 (5<<1)
#define PM_CNT_BINARY (0<<0)
#define PM_CNT_BCD    (1<<0)
#define PM_READ_COUNTER0 (1<<1)
#define PM_READ_COUNTER1 (1<<2)
#define PM_READ_COUNTER2 (1<<3)
#define PM_READ_STATUSVALUE (0<<4)
#define PM_READ_VALUE       (1<<4)
#define PM_READ_STATUS      (2<<4)

// Bits for PORT_PS2_CTRLB
#define PPCB_T2GATE (1<<0)
#define PPCB_SPKR   (1<<1)
#define PPCB_T2OUT  (1<<5)

#define PMTIMER_HZ 3579545      // Underlying Hz of the PM Timer
#define PMTIMER_TO_PIT 3        // Ratio of pmtimer rate to pit rate

u32 TimerKHz VARFSEG;
u16 TimerPort VARFSEG;
u8 ShiftTSC VARFSEG;


/****************************************************************
 * Internal timer setup
 ****************************************************************/

#define CALIBRATE_COUNT 0x800   // Approx 1.7ms

// Calibrate the CPU time-stamp-counter
static void
tsctimer_setup(void)
{
    // Setup "timer2"
    u8 orig = inb(PORT_PS2_CTRLB);
    outb((orig & ~PPCB_SPKR) | PPCB_T2GATE, PORT_PS2_CTRLB);
    /* binary, mode 0, LSB/MSB, Ch 2 */
    outb(PM_SEL_TIMER2|PM_ACCESS_WORD|PM_MODE0|PM_CNT_BINARY, PORT_PIT_MODE);
    /* LSB of ticks */
    outb(CALIBRATE_COUNT & 0xFF, PORT_PIT_COUNTER2);
    /* MSB of ticks */
    outb(CALIBRATE_COUNT >> 8, PORT_PIT_COUNTER2);

    u64 start = rdtscll();
    while ((inb(PORT_PS2_CTRLB) & PPCB_T2OUT) == 0)
        ;
    u64 end = rdtscll();

    // Restore PORT_PS2_CTRLB
    outb(orig, PORT_PS2_CTRLB);

    // Store calibrated cpu khz.
    u64 diff = end - start;
    dprintf(6, "tsc calibrate start=%u end=%u diff=%u\n"
            , (u32)start, (u32)end, (u32)diff);
    u64 t = DIV_ROUND_UP(diff * PMTIMER_HZ, CALIBRATE_COUNT);
    while (t >= (1<<24)) {
        ShiftTSC++;
        t = (t + 1) >> 1;
    }
    TimerKHz = DIV_ROUND_UP((u32)t, 1000 * PMTIMER_TO_PIT);

    dprintf(1, "CPU Mhz=%u\n", (TimerKHz << ShiftTSC) / 1000);
}

// Setup internal timers.
void
timer_setup(void)
{
    if (CONFIG_PMTIMER && TimerPort) {
        dprintf(3, "pmtimer already configured; will not calibrate TSC\n");
        return;
    }

    u32 eax, ebx, ecx, edx, cpuid_features = 0;
    cpuid(0, &eax, &ebx, &ecx, &edx);
    if (eax > 0)
        cpuid(1, &eax, &ebx, &ecx, &cpuid_features);

    if (!(cpuid_features & CPUID_TSC)) {
        TimerPort = PORT_PIT_COUNTER0;
        TimerKHz = DIV_ROUND_UP(PMTIMER_HZ, 1000 * PMTIMER_TO_PIT);
        dprintf(3, "386/486 class CPU. Using TSC emulation\n");
        return;
    }

    tsctimer_setup();
}

void
pmtimer_setup(u16 ioport)
{
    if (!CONFIG_PMTIMER)
        return;
    dprintf(1, "Using pmtimer, ioport 0x%x\n", ioport);
    TimerPort = ioport;
    TimerKHz = DIV_ROUND_UP(PMTIMER_HZ, 1000);
}


/****************************************************************
 * Internal timer reading
 ****************************************************************/

u32 TimerLast VARLOW;

// Add extra high bits to timers that have less than 32bits of precision.
static u32
timer_adjust_bits(u32 value, u32 validbits)
{
    u32 last = GET_LOW(TimerLast);
    value = (last & ~validbits) | (value & validbits);
    if (value < last)
        value += validbits + 1;
    SET_LOW(TimerLast, value);
    return value;
}

// Sample the current timer value.
static u32
timer_read(void)
{
    u16 port = GET_GLOBAL(TimerPort);
    if (!port)
        // Read from CPU TSC
        return rdtscll() >> GET_GLOBAL(ShiftTSC);
    if (CONFIG_PMTIMER && port != PORT_PIT_COUNTER0)
        // Read from PMTIMER
        return timer_adjust_bits(inl(port), 0xffffff);
    // Read from PIT.
    outb(PM_SEL_READBACK | PM_READ_VALUE | PM_READ_COUNTER0, PORT_PIT_MODE);
    u16 v = inb(PORT_PIT_COUNTER0) | (inb(PORT_PIT_COUNTER0) << 8);
    return timer_adjust_bits(v, 0xffff);
}

// Check if the current time is past a previously calculated end time.
int
timer_check(u32 end)
{
    return (s32)(timer_read() - end) > 0;
}

static void
timer_delay(u32 diff)
{
    u32 start = timer_read();
    u32 end = start + diff;
    while (!timer_check(end))
        cpu_relax();
}

static void
timer_sleep(u32 diff)
{
    u32 start = timer_read();
    u32 end = start + diff;
    while (!timer_check(end))
        yield();
}

void ndelay(u32 count) {
    timer_delay(DIV_ROUND_UP(count * GET_GLOBAL(TimerKHz), 1000000));
}
void udelay(u32 count) {
    timer_delay(DIV_ROUND_UP(count * GET_GLOBAL(TimerKHz), 1000));
}
void mdelay(u32 count) {
    timer_delay(count * GET_GLOBAL(TimerKHz));
}

void nsleep(u32 count) {
    timer_sleep(DIV_ROUND_UP(count * GET_GLOBAL(TimerKHz), 1000000));
}
void usleep(u32 count) {
    timer_sleep(DIV_ROUND_UP(count * GET_GLOBAL(TimerKHz), 1000));
}
void msleep(u32 count) {
    timer_sleep(count * GET_GLOBAL(TimerKHz));
}

// Return the TSC value that is 'msecs' time in the future.
u32
timer_calc(u32 msecs)
{
    return timer_read() + (GET_GLOBAL(TimerKHz) * msecs);
}
u32
timer_calc_usec(u32 usecs)
{
    return timer_read() + DIV_ROUND_UP(GET_GLOBAL(TimerKHz) * usecs, 1000);
}


/****************************************************************
 * PIT setup
 ****************************************************************/

#define PIT_TICK_INTERVAL 65536 // Default interval for 18.2Hz timer

// Return the number of milliseconds in 'ticks' number of timer irqs.
u32
ticks_to_ms(u32 ticks)
{
    u32 t = PIT_TICK_INTERVAL * 1000 * PMTIMER_TO_PIT * ticks;
    return DIV_ROUND_UP(t, PMTIMER_HZ);
}

// Return the number of timer irqs in 'ms' number of milliseconds.
u32
ticks_from_ms(u32 ms)
{
    u32 t = DIV_ROUND_UP((u64)ms * PMTIMER_HZ, PIT_TICK_INTERVAL);
    return DIV_ROUND_UP(t, 1000 * PMTIMER_TO_PIT);
}

void
pit_setup(void)
{
    // timer0: binary count, 16bit count, mode 2
    outb(PM_SEL_TIMER0|PM_ACCESS_WORD|PM_MODE2|PM_CNT_BINARY, PORT_PIT_MODE);
    // maximum count of 0000H = 18.2Hz
    outb(0x0, PORT_PIT_COUNTER0);
    outb(0x0, PORT_PIT_COUNTER0);
}
