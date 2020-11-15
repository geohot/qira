/* Addresses, interrupt numbers, register sizes */

#define SLAVIO_ZS        0x00000000ULL
#define SLAVIO_ZS1       0x00100000ULL
#define ZS_INTR          0x2c

#define SLAVIO_NVRAM     0x00200000ULL
#define NVRAM_SIZE       0x2000
#define NVRAM_IDPROM     0x1fd8

#define SLAVIO_FD        0x00400000ULL
#define FD_REGS          15
#define FD_INTR          0x2b

#define SLAVIO_SCONFIG   0x00800000ULL
#define SCONFIG_REGS     1

#define AUXIO_REGS       1

#define AUXIO2_REGS      1
#define AUXIO2_INTR      0x22

#define SLAVIO_COUNTER   0x00d00000ULL
#define COUNTER_REGS     0x10

#define SLAVIO_INTERRUPT 0x00e00000ULL
#define INTERRUPT_REGS   0x10

#define SLAVIO_RESET     0x00f00000ULL
#define RESET_REGS       1

#define ECC_BASE         0xf00000000ULL
#define ECC_SIZE         0x20

#define SLAVIO_SIZE      0x01000000

#define SUN4M_NCPUS      16

#define CFG_ADDR         0xd00000510ULL
#define CFG_SIZE         3

/* linux/include/asm-sparc/timer.h */

/* A sun4m has two blocks of registers which are probably of the same
 * structure. LSI Logic's L64851 is told to _decrement_ from the limit
 * value. Aurora behaves similarly but its limit value is compacted in
 * other fashion (it's wider). Documented fields are defined here.
 */

/* As with the interrupt register, we have two classes of timer registers
 * which are per-cpu and master.  Per-cpu timers only hit that cpu and are
 * only level 14 ticks, master timer hits all cpus and is level 10.
 */

#define SUN4M_PRM_CNT_L       0x80000000
#define SUN4M_PRM_CNT_LVALUE  0x7FFFFC00

struct sun4m_timer_percpu_info {
  __volatile__ unsigned int l14_timer_limit;    /* Initial value is 0x009c4000 */
  __volatile__ unsigned int l14_cur_count;

  /* This register appears to be write only and/or inaccessible
   * on Uni-Processor sun4m machines.
   */
  __volatile__ unsigned int l14_limit_noclear;  /* Data access error is here */

  __volatile__ unsigned int cntrl;            /* =1 after POST on Aurora */
  __volatile__ unsigned char space[PAGE_SIZE - 16];
};

struct sun4m_timer_regs {
	struct sun4m_timer_percpu_info cpu_timers[SUN4M_NCPUS];
	volatile unsigned int l10_timer_limit;
	volatile unsigned int l10_cur_count;

	/* Again, this appears to be write only and/or inaccessible
	 * on uni-processor sun4m machines.
	 */
	volatile unsigned int l10_limit_noclear;

	/* This register too, it must be magic. */
	volatile unsigned int foobar;

	volatile unsigned int cfg;     /* equals zero at boot time... */
};

/*
 * Registers of hardware timer in sun4m.
 */
struct sun4m_timer_percpu {
    volatile unsigned int l14_timer_limit; /* Initial value is 0x009c4000 = 10ms period*/
    volatile unsigned int l14_cur_count;
};

struct sun4m_timer_global {
    volatile unsigned int l10_timer_limit;
    volatile unsigned int l10_cur_count;
};

/* linux/include/asm-sparc/irq.h */

/* These registers are used for sending/receiving irqs from/to
 * different cpu's.
 */
struct sun4m_intreg_percpu {
    unsigned int tbt;        /* Interrupts still pending for this cpu. */

    /* These next two registers are WRITE-ONLY and are only
     * "on bit" sensitive, "off bits" written have NO affect.
     */
    unsigned int clear;  /* Clear this cpus irqs here. */
    unsigned int set;    /* Set this cpus irqs here. */
    unsigned char space[PAGE_SIZE - 12];
};

/*
 * djhr
 * Actually the clear and set fields in this struct are misleading..
 * according to the SLAVIO manual (and the same applies for the SEC)
 * the clear field clears bits in the mask which will ENABLE that IRQ
 * the set field sets bits in the mask to DISABLE the IRQ.
 *
 * Also the undirected_xx address in the SLAVIO is defined as
 * RESERVED and write only..
 *
 * DAVEM_NOTE: The SLAVIO only specifies behavior on uniprocessor
 *             sun4m machines, for MP the layout makes more sense.
 */
struct sun4m_intregs {
    struct sun4m_intreg_percpu cpu_intregs[SUN4M_NCPUS];
    unsigned int tbt;                /* IRQ's that are still pending. */
    unsigned int irqs;               /* Master IRQ bits. */

    /* Again, like the above, two these registers are WRITE-ONLY. */
    unsigned int clear;              /* Clear master IRQ's by setting bits here. */
    unsigned int set;                /* Set master IRQ's by setting bits here. */

    /* This register is both READ and WRITE. */
    unsigned int undirected_target;  /* Which cpu gets undirected irqs. */
};

/* Dave Redman (djhr@tadpole.co.uk)
 * The sun4m interrupt registers.
 */
#define SUN4M_INT_ENABLE  	0x80000000
#define SUN4M_INT_E14     	0x00000080
#define SUN4M_INT_E10     	0x00080000

#define SUN4M_HARD_INT(x)	(0x000000001 << (x))
#define SUN4M_SOFT_INT(x)	(0x000010000 << (x))

#define	SUN4M_INT_MASKALL	0x80000000	  /* mask all interrupts */
#define	SUN4M_INT_MODULE_ERR	0x40000000	  /* module error */
#define	SUN4M_INT_M2S_WRITE	0x20000000	  /* write buffer error */
#define	SUN4M_INT_ECC		0x10000000	  /* ecc memory error */
#define	SUN4M_INT_FLOPPY	0x00400000	  /* floppy disk */
#define	SUN4M_INT_MODULE	0x00200000	  /* module interrupt */
#define	SUN4M_INT_VIDEO		0x00100000	  /* onboard video */
#define	SUN4M_INT_REALTIME	0x00080000	  /* system timer */
#define	SUN4M_INT_SCSI		0x00040000	  /* onboard scsi */
#define	SUN4M_INT_AUDIO		0x00020000	  /* audio/isdn */
#define	SUN4M_INT_ETHERNET	0x00010000	  /* onboard ethernet */
#define	SUN4M_INT_SERIAL	0x00008000	  /* serial ports */
#define	SUN4M_INT_KBDMS		0x00004000	  /* keyboard/mouse */
#define	SUN4M_INT_SBUSBITS	0x00003F80	  /* sbus int bits */
