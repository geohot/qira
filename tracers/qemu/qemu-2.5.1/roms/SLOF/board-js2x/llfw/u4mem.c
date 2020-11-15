/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/
#include <stdint.h>
#include <hw.h>
#include <stdio.h>
#include "stage2.h"
#include <cpu.h>
#include <string.h>

/*
 * compiler switches
 *******************************************************************************
 */
#define U4_DEBUG
#define U4_INFO
//#define U4_SHOW_REGS

int io_getchar(char *);

/*
 * version info
 */
static const uint32_t VER    = 2;
static const uint32_t SUBVER = 1;

/*
 * local macros
 *******************************************************************************
 */
// bit shifting in Motorola/IBM bit enumeration format (yaks...)
#define IBIT( nr )		( (uint32_t) 0x80000000 >> (nr) )
#define BIT( nr )		( (uint32_t) 0x1 << (nr) )

/*
 * macros to detect the current board layout
 */
#define IS_MAUI		( ( load8_ci( 0xf4000682 ) >> 4 ) == 0 )
#define IS_BIMINI		( ( load8_ci( 0xf4000682 ) >> 4 ) == 1 )
#define IS_KAUAI		( ( load8_ci( 0xf4000682 ) >> 4 ) == 2 )

/*
 * local constants
 *******************************************************************************
 */

/*
 * u4 base address
 */
#define U4_BASE_ADDR		((uint64_t) 0xf8000000 )
#define u4reg( reg )		(U4_BASE_ADDR + (uint64_t) (reg))

/*
 * I2C registers
 */
#define I2C_MODE_R		u4reg(0x1000)
#define I2C_CTRL_R		u4reg(0x1010)
#define I2C_STAT_R		u4reg(0x1020)
#define I2C_ISR_R		u4reg(0x1030)
#define I2C_ADDR_R		u4reg(0x1050)
#define I2C_SUBA_R		u4reg(0x1060)
#define I2C_DATA_R		u4reg(0x1070)

/*
 * clock control registers & needed bits/masks
 */
#define ClkCntl_R		u4reg(0x0800)
#define PLL2Cntl_R		u4reg(0x0860)

/*
 * clock control bits & masks
 */
#define CLK_DDR_CLK_MSK		(IBIT(11) | IBIT(12) | IBIT(13))

/*
 * memory controller registers
 */
#define RASTimer0_R		u4reg(0x2030)
#define RASTimer1_R		u4reg(0x2040)
#define CASTimer0_R		u4reg(0x2050)
#define CASTimer1_R		u4reg(0x2060)
#define MemRfshCntl_R		u4reg(0x2070)
#define MemProgCntl_R		u4reg(0x20b0)
#define Dm0Cnfg_R		u4reg(0x2200)
#define Dm1Cnfg_R		u4reg(0x2210)
#define Dm2Cnfg_R		u4reg(0x2220)
#define Dm3Cnfg_R		u4reg(0x2230)
#define MemWrQCnfg_R		u4reg(0x2270)
#define MemArbWt_R		u4reg(0x2280)
#define UsrCnfg_R		u4reg(0x2290)
#define MemRdQCnfg_R		u4reg(0x22a0)
#define MemQArb_R		u4reg(0x22b0)
#define MemRWArb_R		u4reg(0x22c0)
#define MemBusCnfg_R		u4reg(0x22d0)
#define MemBusCnfg2_R		u4reg(0x22e0)
#define ODTCntl_R        	u4reg(0x23a0)
#define MemModeCntl_R		u4reg(0x2500)
#define MemPhyModeCntl_R 	u4reg(0x2880)
#define CKDelayL_R		u4reg(0x2890)
#define CKDelayU_R		u4reg(0x28a0)
#define IOPadCntl_R      	u4reg(0x29a0)
#define ByteWrClkDelC0B00_R	u4reg(0x2800)
#define ByteWrClkDelC0B01_R	u4reg(0x2810)
#define ByteWrClkDelC0B02_R	u4reg(0x2820)
#define ByteWrClkDelC0B03_R	u4reg(0x2830)
#define ByteWrClkDelC0B04_R	u4reg(0x2900)
#define ByteWrClkDelC0B05_R	u4reg(0x2910)
#define ByteWrClkDelC0B06_R	u4reg(0x2920)
#define ByteWrClkDelC0B07_R	u4reg(0x2930)
#define ByteWrClkDelC0B16_R	u4reg(0x2980)
#define ByteWrClkDelC0B08_R	u4reg(0x2a00)
#define ByteWrClkDelC0B09_R	u4reg(0x2a10)
#define ByteWrClkDelC0B10_R	u4reg(0x2a20)
#define ByteWrClkDelC0B11_R	u4reg(0x2a30)
#define ByteWrClkDelC0B12_R	u4reg(0x2b00)
#define ByteWrClkDelC0B13_R	u4reg(0x2b10)
#define ByteWrClkDelC0B14_R	u4reg(0x2b20)
#define ByteWrClkDelC0B15_R	u4reg(0x2b30)
#define ByteWrClkDelC0B17_R	u4reg(0x2b80)
#define ReadStrobeDelC0B00_R	u4reg(0x2840)
#define ReadStrobeDelC0B01_R	u4reg(0x2850)
#define ReadStrobeDelC0B02_R	u4reg(0x2860)
#define ReadStrobeDelC0B03_R	u4reg(0x2870)
#define ReadStrobeDelC0B04_R	u4reg(0x2940)
#define ReadStrobeDelC0B05_R	u4reg(0x2950)
#define ReadStrobeDelC0B06_R	u4reg(0x2960)
#define ReadStrobeDelC0B07_R	u4reg(0x2970)
#define ReadStrobeDelC0B16_R	u4reg(0x2990)
#define ReadStrobeDelC0B08_R	u4reg(0x2a40)
#define ReadStrobeDelC0B09_R	u4reg(0x2a50)
#define ReadStrobeDelC0B10_R	u4reg(0x2a60)
#define ReadStrobeDelC0B11_R	u4reg(0x2a70)
#define ReadStrobeDelC0B12_R	u4reg(0x2b40)
#define ReadStrobeDelC0B13_R	u4reg(0x2b50)
#define ReadStrobeDelC0B14_R	u4reg(0x2b60)
#define ReadStrobeDelC0B15_R	u4reg(0x2b70)
#define ReadStrobeDelC0B17_R	u4reg(0x2b90)
#define MemInit00_R		u4reg(0x2100)
#define MemInit01_R		u4reg(0x2110)
#define MemInit02_R		u4reg(0x2120)
#define MemInit03_R		u4reg(0x2130)
#define MemInit04_R		u4reg(0x2140)
#define MemInit05_R		u4reg(0x2150)
#define MemInit06_R		u4reg(0x2160)
#define MemInit07_R		u4reg(0x2170)
#define MemInit08_R		u4reg(0x2180)
#define MemInit09_R		u4reg(0x2190)
#define MemInit10_R		u4reg(0x21a0)
#define MemInit11_R		u4reg(0x21b0)
#define MemInit12_R		u4reg(0x21c0)
#define MemInit13_R		u4reg(0x21d0)
#define MemInit14_R		u4reg(0x21e0)
#define MemInit15_R		u4reg(0x21f0)
#define CalConf0_R		u4reg(0x29b0)
#define CalConf1_R		u4reg(0x29c0)
#define MeasStatusC0_R		u4reg(0x28f0)
#define MeasStatusC1_R		u4reg(0x29f0)
#define MeasStatusC2_R		u4reg(0x2af0)
#define MeasStatusC3_R		u4reg(0x2bf0)
#define CalC0_R			u4reg(0x28e0)
#define CalC1_R			u4reg(0x29e0)
#define CalC2_R			u4reg(0x2ae0)
#define CalC3_R			u4reg(0x2be0)
#define RstLdEnVerniersC0_R	u4reg(0x28d0)
#define RstLdEnVerniersC1_R	u4reg(0x29d0)
#define RstLdEnVerniersC2_R	u4reg(0x2ad0)
#define RstLdEnVerniersC3_R	u4reg(0x2bd0)
#define ExtMuxVernier0_R	u4reg(0x28b0)
#define ExtMuxVernier1_R	u4reg(0x28c0)
#define OCDCalCmd_R		u4reg(0x2300)
#define OCDCalCntl_R		u4reg(0x2310)
#define MCCR_R      		u4reg(0x2440)
#define MSRSR_R     		u4reg(0x2410)
#define MSRER_R     		u4reg(0x2420)
#define MSPR_R      		u4reg(0x2430)
#define MSCR_R      		u4reg(0x2400)
#define MEAR0_R			u4reg(0x2460)
#define MEAR1_R			u4reg(0x2470)
#define MESR_R			u4reg(0x2480)
#define MRSRegCntl_R		u4reg(0x20c0)
#define EMRSRegCntl_R		u4reg(0x20d0)
#define APIMemRdCfg_R		u4reg(0x30090)
#define APIExcp_R		u4reg(0x300a0)

/*
 * common return values
 */
#define RET_OK			 0
#define RET_ERR			-1
#define RET_ACERR_CE		-1
#define RET_ACERR_UEWT		-2
#define RET_ACERR_UE		-3

/*
 * 'DIMM slot populated' indicator
 */
#define SL_POP			1

/*
 * spd buffer size
 */
#define SPD_BUF_SIZE		0x40

/*
 * maximum number of DIMM banks & DIMM groups
 */
#define NUM_SLOTS		8
#define NUM_BANKS		( NUM_SLOTS / 2 )
#define MAX_DGROUPS		( NUM_SLOTS / 2 )
#define SLOT_ADJ()		( ( IS_MAUI ) ? NUM_SLOTS / 4 : NUM_SLOTS / 2 )

/*
 * values needed for auto calibration
 */
#define MAX_DRANKS		NUM_SLOTS
#define MAX_BLANE		18
#define MAX_RMD			0xf

/*
 * maximum number of supported CAS latencies
 */
#define NUM_CL			3

/*
 * min/max supported CL values by U4
 */
#define U4_MIN_CL		3
#define U4_MAX_CL		5

/*
 * DIMM constants
 */
#define DIMM_TYPE_MSK		BIT(0)
#define DIMM_ORG_x4		BIT(0)
#define DIMM_ORG_x8		BIT(1)
#define DIMM_ORG_x16		BIT(2)
#define DIMM_ORG_MIXx8x16	BIT(30)
#define DIMM_ORG_UNKNOWN	0
#define DIMM_WIDTH		72
#define DIMM_BURSTLEN_4		BIT(2)

/*
 * L2 cache size
 */
#define L2_CACHE_SIZE		(uint32_t) 0x100000

/*
 * scrub types
 */
#define	IMMEDIATE_SCRUB			IBIT(0)
#define	IMMEDIATE_SCRUB_WITH_FILL	( IBIT(0) | IBIT(1) )
#define	BACKGROUND_SCRUB		( IBIT(1) | ( 0x29 << 16 ) )

/*
 * I2C starting slave addresses of the DIMM banks
 */
#define I2C_START		0x50

/*
 * Index to the speed dependend DIMM settings
 */
enum
{
	SPEED_IDX_400 = 0,
	SPEED_IDX_533,
	SPEED_IDX_667,
	NUM_SPEED_IDX
};

/*
 * number of read/write strobes of the U4
 */
#define NUM_STROBES 		18

/*
 * 2GB hole definition
 */
static const uint64_t _2GB = (uint64_t) 0x80000000;

/*
 * local types
 *******************************************************************************
 */
/*
 * DIMM definition
 */
typedef struct
{
	uint32_t m_pop_u32;		// set if bank is populated
	uint32_t m_bank_u32;		// bank number
	uint32_t m_clmsk_u32;		// mask of supported CAS latencies
	uint32_t m_clcnt_u32;		// number of supporetd CAS latencies
	uint32_t m_clval_pu32[NUM_CL];	// values of supporeted CAS latencies
	uint32_t m_speed_pu32[NUM_CL];	// speed (Mhz) at CAS latency of same index
	uint32_t m_size_u32;		// chip size in Mb
	uint32_t m_rank_u32;		// # of ranks, total size = chip size*rank
	uint32_t m_orgmsk_u32;		// data organisation (x4, x8, x16) (mask)
	uint32_t m_orgval_u32;		// data organisation (value)
	uint32_t m_width_u32;		// data width
	uint32_t m_ecc_u32;             // set if ecc
	uint32_t m_type_u32;		// rdimm or udimm
	uint32_t m_burst_u32;		// supported burst lengths
	uint32_t m_bankcnt_u32;		// number of banks

	/*
	 * the following timing values are all in 1/100ns
	 */
	uint32_t m_tCK_pu32[NUM_CL];
	uint32_t m_tRAS_u32;
	uint32_t m_tRTP_u32;
	uint32_t m_tRP_u32;
	uint32_t m_tWR_u32;
	uint32_t m_tRRD_u32;
	uint32_t m_tRC_u32;
	uint32_t m_tRCD_u32;
	uint32_t m_tWTR_u32;
	uint32_t m_tREF_u32;
	uint32_t m_tRFC_u32;
}	dimm_t;

/*
 * DIMM group definition
 */
typedef struct
{
	uint32_t  m_size_u32;		// group size in MB
	uint32_t  m_start_u32;		// in 128Mb granularity
	uint32_t  m_end_u32;		// in 128Mb granularity
	uint32_t  m_ss_u32;		// single sided/double sided
	uint32_t  m_csmode_u32;		// selected CS mode for this group
	uint32_t  m_add2g_u32;
	uint32_t  m_sub2g_u32;
	uint32_t  m_memmd_u32;		// selected mem mode for this group
	uint32_t  m_dcnt_u32;		// number of DIMMs in group
	dimm_t   *m_dptr[NUM_SLOTS];
}	dgroup_t;

/*
 * auto calibration result structure
 */
typedef struct
{
	uint32_t m_MemBusCnfg_u32;
	uint32_t m_MemBusCnfg2_u32;
	uint32_t m_RstLdEnVerniers_pu32[4];
}	auto_calib_t;

/*
 * ECC error structure
 */
typedef struct
{
	int32_t  m_err_i32;
	uint32_t m_uecnt_u32;		// number of uncorrectable errors
	uint32_t m_cecnt_u32;		// number of correctable errors
	uint32_t m_rank_u32;		// erroneous rank
	uint32_t m_col_u32;		// erroneous column
	uint32_t m_row_u32;		// erroneous row
	uint32_t m_bank_u32;		// erroneous bank
}	eccerror_t;

/*
 * U4 register setup structure
 */
typedef struct
{
	/*
	 * external MUX delays
	 */
	uint32_t RRMux;
	uint32_t WRMux;
	uint32_t WWMux;
	uint32_t RWMux;

	/*
	 * default Wr/Rd Queue & Arbiter register settings
	 */
	uint32_t MemRdQCnfg;
	uint32_t MemWrQCnfg;
	uint32_t MemQArb;
	uint32_t MemRWArb;

	/*
	 * misc fixed register values
	 */
	uint32_t ODTCntl;
	uint32_t IOPadCntl;
	uint32_t MemPhyModeCntl;
	uint32_t OCDCalCntl;
	uint32_t OCDCalCmd;
	uint32_t CKDelayL;
	uint32_t CKDelayU;
	uint32_t MemBusCnfg;
	uint32_t CAS1Dly0;
	uint32_t CAS1Dly1;
	uint32_t ByteWrClkDel[NUM_STROBES];
	uint32_t ReadStrobeDel[NUM_STROBES];
} reg_statics_t;

/*
 * local variables
 *******************************************************************************
 */
static dimm_t	 m_dimm[NUM_SLOTS];
static dimm_t	 m_gendimm;
static uint32_t  m_dcnt_u32;
static dimm_t   *m_dptr[NUM_SLOTS];
static uint32_t  m_bankoff_u32;
static uint32_t	 m_bankpop_u32[NUM_BANKS];
static uint32_t  m_dclidx_u32;
static uint32_t  m_dgrcnt_u32;
static dgroup_t  m_dgroup[MAX_DGROUPS];
static dgroup_t *m_dgrptr[MAX_DGROUPS];
static uint64_t  m_memsize_u64;	// memsize in bytes

/*
 * local functions
 *******************************************************************************
 */
static void
progbar( void )
{
	static uint8_t  bar[] =
			{ '|', '/', '-', '\\', 0 };
	static uint32_t idx = 0;

	printf( "\b%c", bar[idx] );

	if( bar[++idx] == 0 ) {
		idx = 0;
	}

}

static void
or32_ci( uint64_t r, uint32_t m )
{
	uint32_t v;

	v  = load32_ci( r );
	v |= m;
	store32_ci( r, v );
}

static void
and32_ci( uint64_t r, uint32_t m )
{
	uint32_t v;

	v  = load32_ci( r );
	v &= m;
	store32_ci( r, v );
}

static void
dly( uint64_t volatile f_wait_u64 ) \
{
	while( f_wait_u64 ) {
		f_wait_u64--;
	}
}

/*
 * local i2c access functions
 */
static void
i2c_term( void )
{
	uint32_t l_stat_u32;

	/*
	 * clear out all pending int's and wait
	 * for the stop condition to occur
	 */
	do {
		l_stat_u32 = load32_ci( I2C_ISR_R );
		store32_ci( I2C_ISR_R, l_stat_u32 );
	} while( ( l_stat_u32 & IBIT(29) ) == 0 );

}

static int32_t
i2c_read( uint32_t f_addr_u32, uint32_t f_suba_u32, uint8_t *f_buf_pu08, uint32_t f_len_u32 )
{
	uint32_t  l_val_u32;
	int32_t   l_ret_i32 = 1;

	/*
	 * parameter check
	 */
	if( ( f_addr_u32 > (uint32_t) 0x7f ) ||
	    ( f_suba_u32 > (uint32_t) 0xff ) ||
	    ( f_len_u32 == (uint32_t) 0x00 ) ) {
		return RET_ERR;
	}

	/*
	 * set I2C Interface to combined mode
	 */
	store32_ci( I2C_MODE_R, IBIT(28) | IBIT(29) );

	/*
	 * set address, subaddress & read mode
	 */
	store32_ci( I2C_ADDR_R, ( f_addr_u32 << 1 ) | (uint32_t) 0x1 );
	store32_ci( I2C_SUBA_R, f_suba_u32 );

	/*
	 * start address transmission phase
	 */
	store32_ci( I2C_CTRL_R, IBIT(30) );

	/*
	 * wait for address transmission to finish
	 */
	do {
		l_val_u32 = load32_ci( I2C_ISR_R );
	} while( ( l_val_u32 & IBIT(30) ) == 0 );

	/*
	 * check for success
	 */
	if( ( load32_ci( I2C_STAT_R ) & IBIT(30) ) == 0 ) {
		i2c_term();
		return RET_ERR;
	} else {
		// send ack
		store32_ci( I2C_CTRL_R, IBIT(31) );
		// clear int
		store32_ci( I2C_ISR_R, IBIT(30) );
	}

	/*
	 * read data
	 */
	while( l_ret_i32 > 0 ) {
		l_val_u32 = load32_ci( I2C_ISR_R );

		if( ( l_val_u32 & IBIT(31) ) != 0 ) {
			// data was received
			*f_buf_pu08 = ( uint8_t ) load32_ci( I2C_DATA_R );

			f_buf_pu08++;
			f_len_u32--;

			/*
			 * continue when there is more data to read or
			 * exit if not
			 */
			if( f_len_u32 != 0 ) {
				// send ack
				store32_ci( I2C_CTRL_R, IBIT(31) );
				// clear int
				store32_ci( I2C_ISR_R, IBIT(31) );
			} else {
				// send nack
				store32_ci( I2C_CTRL_R, 0 );
				// set exit flag
				l_ret_i32 = RET_OK;
			}

		} else if( ( l_val_u32 & IBIT(29) ) != 0 ) {
			// early stop condition
			// set exit flag
			l_ret_i32 = RET_ERR;
		}

	};

	i2c_term();

	return( l_ret_i32 );
}

static uint32_t
i2c_get_slot( uint32_t i2c_addr )
{
	uint32_t slot;

	slot = ( i2c_addr - I2C_START ) / 2;

	if( ( i2c_addr & 0x1 ) != 0 ) {
		slot += SLOT_ADJ();
	}

	return slot;
}

/*
 * 'serial presence detect' interpretation functions
 */
static uint32_t
ddr2_get_dimm_rank( uint8_t *f_spd_pu08 )
{
	static const int RANK_IDX = (int) 5;

	return (uint32_t) ( f_spd_pu08[RANK_IDX] & 0x3 ) + 1;
}

static uint32_t
ddr2_get_dimm_size( uint8_t *f_spd_pu08 )
{
	static const int SIZE_IDX   = (int) 31;
	uint8_t          l_smsk_u08;
	uint32_t         i;

	l_smsk_u08 = ( f_spd_pu08[SIZE_IDX] << 3 ) |
		     ( f_spd_pu08[SIZE_IDX] >> 5 );

	for( i = 0; ( ( l_smsk_u08 & ( (uint8_t) 0x1 << i ) ) == 0 ) ; i++ );

	return (uint32_t) 0x80 << i;
}

static uint32_t
ddr2_get_dimm_type( uint8_t *f_spd_pu08 )
{
	static const int TYPE_IDX = (int) 20;

	return (uint32_t) f_spd_pu08[TYPE_IDX] & DIMM_TYPE_MSK;
}

static uint32_t
ddr2_get_dimm_org( uint8_t *f_spd_pu08, uint32_t /*out*/ *f_omsk_pu32 )
{
	static const int ORG_IDX   = (int) 13;
	uint32_t         l_ret_u32 = (uint32_t) f_spd_pu08[ORG_IDX];

	if( l_ret_u32 == 4 ) {
		*f_omsk_pu32  = DIMM_ORG_x4;
	} else if( l_ret_u32 == 8 ) {
		*f_omsk_pu32  = DIMM_ORG_x8;
		*f_omsk_pu32 |= DIMM_ORG_MIXx8x16;
	} else if( l_ret_u32 == 16 ) {
		*f_omsk_pu32  = DIMM_ORG_x16;
		*f_omsk_pu32 |= DIMM_ORG_MIXx8x16;
	} else {
		*f_omsk_pu32  = DIMM_ORG_UNKNOWN;
		 l_ret_u32    = (uint32_t) ~0;
	}

	return l_ret_u32;
}

static uint32_t
ddr2_get_dimm_width( uint8_t *f_spd_pu08 )
{
	static const int WIDTH_IDX = (int) 6;

	return (uint32_t) f_spd_pu08[WIDTH_IDX];
}

static uint32_t
ddr2_get_dimm_ecc( uint8_t *f_spd_pu08 )
{
	static const int ECC_IDX = (int) 11;

	return ( f_spd_pu08[ECC_IDX] & BIT(1) ) != 0;
}

static uint32_t
ddr2_get_dimm_burstlen( uint8_t *f_spd_pu08 )
{
	static const int BURST_IDX = (int) 16;

	return (uint32_t) f_spd_pu08[BURST_IDX];
}

static void
ddr2_get_dimm_speed( dimm_t *f_dimm, uint8_t *f_spd_pu08 )
{
	static const int      SPEED_IDX[] = { 25, 23, 9 };
	static const uint32_t NS[]        = { 25, 33, 66, 75 };
	uint8_t               l_tmp_u08;
	uint32_t	      l_dspeed_u32;
	uint32_t	      idx = 0;
	uint32_t	      i;

	for( i = NUM_CL - f_dimm->m_clcnt_u32; i < NUM_CL; i++ ) {
		l_tmp_u08     = f_spd_pu08[SPEED_IDX[i]];
		l_dspeed_u32  = (uint32_t) ( l_tmp_u08 >> 4 ) * 100;
		l_tmp_u08    &= (uint8_t) 0xf;

		if( l_tmp_u08 >= (uint8_t) 10 ) {
			l_dspeed_u32 += NS[l_tmp_u08 - 10];
		} else {
			l_dspeed_u32 += (uint32_t) l_tmp_u08 * 10;
		}

		f_dimm->m_tCK_pu32[idx]    = l_dspeed_u32;
		f_dimm->m_speed_pu32[idx]  = (uint32_t) 2000000 / l_dspeed_u32;
		f_dimm->m_speed_pu32[idx] += (uint32_t) 5;
		f_dimm->m_speed_pu32[idx] /= (uint32_t) 10;
		idx++;
	}

}

static void
ddr2_get_dimm_timings( dimm_t *f_dimm, uint8_t *f_spd_pu08 )
{
	static const uint32_t NS[]  = { 00, 25, 33, 50, 66, 75, 00, 00 };
	static const uint32_t USMUL = (uint32_t) 390625;
	static const int tREF_IDX   = (int) 12;
	static const int tRP_IDX    = (int) 27;
	static const int tRRD_IDX   = (int) 28;
	static const int tRCD_IDX   = (int) 29;
	static const int tRAS_IDX   = (int) 30;
	static const int tWR_IDX    = (int) 36;
	static const int tWTR_IDX   = (int) 37;
	static const int tRTP_IDX   = (int) 38;
	static const int tRC_IDX    = (int) 41;	// & 40
	static const int tRFC_IDX   = (int) 42;	// & 40

	uint32_t         l_tmp_u32;

	f_dimm->m_tRP_u32  = (uint32_t) f_spd_pu08[tRP_IDX]  *  25;
	f_dimm->m_tRRD_u32 = (uint32_t) f_spd_pu08[tRRD_IDX] *  25;
	f_dimm->m_tRCD_u32 = (uint32_t) f_spd_pu08[tRCD_IDX] *  25;
	f_dimm->m_tWR_u32  = (uint32_t) f_spd_pu08[tWR_IDX]  *  25;
	f_dimm->m_tWTR_u32 = (uint32_t) f_spd_pu08[tWTR_IDX] *  25;
	f_dimm->m_tRTP_u32 = (uint32_t) f_spd_pu08[tRTP_IDX] *  25;
	f_dimm->m_tRAS_u32 = (uint32_t) f_spd_pu08[tRAS_IDX] * 100;

	l_tmp_u32          = (uint32_t) ( f_spd_pu08[tRC_IDX - 1] >> 4 );
	l_tmp_u32         &= (uint32_t) 0x7;
	f_dimm->m_tRC_u32  = (uint32_t) f_spd_pu08[tRC_IDX] * 100 +
			   		NS[l_tmp_u32];

	l_tmp_u32	    = (uint32_t) f_spd_pu08[tRFC_IDX - 2];
	l_tmp_u32          &= (uint32_t) 0xf;
	f_dimm->m_tRFC_u32  = (uint32_t) 256 * ( l_tmp_u32 & (uint32_t) 0x1 );
	f_dimm->m_tRFC_u32 += (uint32_t) f_spd_pu08[tRFC_IDX];
	f_dimm->m_tRFC_u32 *= 100;
	l_tmp_u32         >>= 1;
	f_dimm->m_tRFC_u32 += NS[l_tmp_u32];

	l_tmp_u32           = (uint32_t) f_spd_pu08[tREF_IDX];
	l_tmp_u32          &= (uint32_t) 0x7f;

	if( l_tmp_u32 == 0 ) {
		l_tmp_u32 = (uint32_t) 2;
	} else if( l_tmp_u32 <= (uint32_t) 2 ) {
		l_tmp_u32--;
	}

	f_dimm->m_tREF_u32 = ( l_tmp_u32 + 1 ) * USMUL;
}

static uint32_t
ddr2_get_banks( uint8_t *f_spd_pu08 )
{
	static const int BANK_IDX = (int) 17;

	return (uint32_t) f_spd_pu08[BANK_IDX];
}

static uint32_t
ddr2_get_cl_mask( uint8_t *f_spd_pu08 )
{
	static const int CL_IDX = (int) 18;

	return (uint32_t) f_spd_pu08[CL_IDX];
}

static void
ddr2_get_cl( dimm_t *f_dimm )
{
	uint32_t l_clcnt_u32 = 0;
	uint32_t i;

	for( i = 0; ( i < 8 ) && ( l_clcnt_u32 < NUM_CL ) ; i++ ) {

		if( ( f_dimm->m_clmsk_u32 & ( (uint32_t) 0x1 << i ) ) != 0 ) {
			f_dimm->m_clval_pu32[l_clcnt_u32] = i;
			l_clcnt_u32++;
		}

	}

	f_dimm->m_clcnt_u32 = l_clcnt_u32;
}

static uint32_t
ddr2_cl2speed( dimm_t *f_dimm, uint32_t f_cl_u32, uint32_t *f_tCK_pu32 )
{
	uint32_t i;

	for(i = 0; (i < NUM_CL) && (f_dimm->m_clval_pu32[i] != f_cl_u32); i++);

	if( i == NUM_CL ) {
		return (uint32_t) ~0;
	}

	*f_tCK_pu32 = f_dimm->m_tCK_pu32[i];

	return f_dimm->m_speed_pu32[i];
}

static void
ddr2_setupDIMM( dimm_t *f_dimm, uint32_t f_bank_u32, uint8_t *f_spd_pu08 )
{
	f_dimm->m_pop_u32     = SL_POP;
	f_dimm->m_bank_u32    = f_bank_u32;
	f_dimm->m_size_u32    = ddr2_get_dimm_size( f_spd_pu08 );
	f_dimm->m_rank_u32    = ddr2_get_dimm_rank( f_spd_pu08 );
	f_dimm->m_type_u32    = ddr2_get_dimm_type( f_spd_pu08 );
	f_dimm->m_orgval_u32  = ddr2_get_dimm_org( f_spd_pu08, &f_dimm->m_orgmsk_u32 );
	f_dimm->m_width_u32   = ddr2_get_dimm_width( f_spd_pu08 );
	f_dimm->m_ecc_u32     = ddr2_get_dimm_ecc( f_spd_pu08 );
	f_dimm->m_burst_u32   = ddr2_get_dimm_burstlen( f_spd_pu08 );
	f_dimm->m_clmsk_u32   = ddr2_get_cl_mask( f_spd_pu08 );
	f_dimm->m_bankcnt_u32 = ddr2_get_banks( f_spd_pu08 );

	ddr2_get_cl( f_dimm );
	ddr2_get_dimm_speed( f_dimm, f_spd_pu08 );
	ddr2_get_dimm_timings( f_dimm, f_spd_pu08 );
}

static int32_t
ddr2_checkSPD( uint8_t *f_spd_pu08 )
{
	uint8_t  crc = 0;
	uint32_t i;

	for( i = 0; i < SPD_BUF_SIZE - 1; i++ ) {
		crc += f_spd_pu08[i];
	}

	if( crc != f_spd_pu08[i] ) {
		return RET_ERR;
	}

	return RET_OK;
}

static int32_t
ddr2_readSPDs( void )
{
	static const uint32_t MAX_SPD_FAIL = 3;
	uint8_t  l_spdbuf_pu08[SPD_BUF_SIZE];
	uint32_t l_bankfail_u32 = 0;
	uint32_t l_spdfail_u32  = 0;
	int32_t  l_i2c_i32      = RET_OK;
	int32_t  l_spd_i32      = RET_OK;
	int32_t  ret            = RET_OK;
	uint32_t i;

	/*
	 * read spd's and detect populated slots
	 */
	for( i = 0; i < NUM_SLOTS; i++ ) {
		/*
		 * indicate slot as empty
		 */
		m_dimm[i].m_pop_u32 = 0;

		/*
		 * check whether bank is switched off
		 */
		if( ( m_bankoff_u32 & ( 0x1 << ( i / 2 ) ) ) != 0 ) {
			continue;
		}

		/*
		 * read SPD data
		 */

		/*
		 * reset SPD fail counter
		 */
		l_spdfail_u32 = MAX_SPD_FAIL;
		l_spd_i32     = RET_OK;

		while( l_spdfail_u32 != 0 ) {
			l_i2c_i32 = i2c_read( I2C_START + i, 0x0, l_spdbuf_pu08, SPD_BUF_SIZE );

			if( l_i2c_i32 == RET_OK ) {
				l_spd_i32 = ddr2_checkSPD( l_spdbuf_pu08 );

				if( l_spd_i32 == RET_OK ) {
					l_spdfail_u32 = 0;
				} else {
					l_spdfail_u32--;
				}

			} else {
				l_spdfail_u32--;
			}

		}

		if( l_spd_i32 != RET_OK ) {
			#ifdef U4_INFO
			printf( "\r\n  [ERROR -> SPD read failure in slot %u]",
				i2c_get_slot( I2C_START + i ) );
			#endif

			l_bankfail_u32 |= ( 0x1 << ( i / 2 ) );
			ret             = RET_ERR;
		} else if( l_i2c_i32 == RET_OK ) {
			/*
			 * slot is populated
			 */
			ddr2_setupDIMM( &m_dimm[i], i / 2, l_spdbuf_pu08 );

			m_dptr[m_dcnt_u32] = &m_dimm[i];
			m_dcnt_u32++;
		}

	}

	if( ret != RET_OK ) {
		m_bankoff_u32 |= l_bankfail_u32;
		#ifdef U4_INFO
		printf( "\r\n" );
		#endif
	}

	return ret;
}

static int32_t
ddr2_setupDIMMcfg( void )
{
	uint32_t  l_tmp_u32;
	uint32_t  l_tmp0_u32;
	uint32_t  l_tmp1_u32;
	uint32_t  i, j, e, b;

	/*
	 * check wether on board DIMM slot population is valid
	 */
	e = 0;
	b = 0;
	for( i = 0; i < NUM_SLOTS; i += 2 ) {

		switch( m_dimm[i].m_pop_u32 + m_dimm[i+1].m_pop_u32 ) {
			case 0: {
				m_bankpop_u32[i/2] = 0;
				break;
			}

			case 2 * SL_POP: {
				m_bankpop_u32[i/2] = !0;
				b++;
				break;
			}

			default: {
				#ifdef U4_DEBUG
				printf( "\r\n  [ERROR -> only 1 DIMM installed in bank %u]", i/2 );
				#endif
				e++;
			}

		}

	}

	/*
	 * return on error
	 */
	if( e != 0 ) {
		#ifdef U4_DEBUG
		printf( "\r\n" );
		#endif
		return RET_ERR;
	}

	if( b == 0 ) {
		#ifdef U4_DEBUG
		printf( "\r\n  [ERROR -> no (functional) memory installed]\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * check DIMM compatibility
	 * configuration is 128 bit data/128 bit bus
	 * -all DIMMs must be organized as x4
	 * -all DIMMs must be 72 bit wide with ECC
	 * -all DIMMs must be registered DIMMs (RDIMMs)
	 * -paired DIMMs must have the same # of ranks, size & organization
	 */

	/*
	 * check DIMM ranks & sizes
	 */
	e = 0;
	for( i = 0; i < NUM_SLOTS; i += 2 ) {

		if( (   m_bankpop_u32[i/2]   != 0	               ) &&
		    ( ( m_dimm[i].m_rank_u32 != m_dimm[i+1].m_rank_u32 ) ||
		      ( m_dimm[i].m_size_u32 != m_dimm[i+1].m_size_u32 ) ) ) {
			#ifdef U4_DEBUG
			printf( "\r\n  [ERROR -> installed DIMMs in bank %u have different ranks/sizes]", i/2 );
			#endif
			e++;
		}

	}

	/*
	 * return on error
	 */
	if( e != 0 ) {
		#ifdef U4_DEBUG
		printf( "\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * check valid DIMM organisation (must be x4)
	 */
	e = 0;
	for( i = 0; i < m_dcnt_u32; i++ ) {

		if( ( m_dptr[i]->m_orgmsk_u32 & DIMM_ORG_x4 ) == 0 ) {
			#ifdef U4_DEBUG
			printf( "\r\n  [ERROR -> wrong DIMM organisation in bank %u]",
				m_dptr[i]->m_bank_u32 );
			#endif
			e++;
		}

	}

	/*
	 * return on error
	 */
	if( e != 0 ) {
		#ifdef U4_DEBUG
		printf( "\r\n" );
		#endif
		return RET_ERR;
	}

	e = (uint32_t) ~0;
	for( i = 0; i < m_dcnt_u32; i++ ) {
		e &= m_dptr[i]->m_type_u32;
	}

	/*
	 * return on error
	 */
	if( e == 0 ) {
		#ifdef U4_DEBUG
		printf( "\r\n  [ERROR -> installed DIMMs are of different type]\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * setup generic dimm
	 */
	m_gendimm.m_type_u32 = e;

	/*
	 * check valid width, ecc & burst length
	 */
	e = 0;
	for( i = 0; i < m_dcnt_u32; i++ ) {

		if( m_dptr[i]->m_width_u32 != DIMM_WIDTH ) {
			#ifdef U4_DEBUG
			printf( "\r\n  [ERROR -> invalid DIMM width in bank %u]",
				m_dptr[i]->m_bank_u32 );
			#endif
			e++;
		}

		if( m_dptr[i]->m_ecc_u32 == 0 ) {
			#ifdef U4_DEBUG
			printf( "\r\n  [ERROR -> DIMM(s) do not support ECC in bank %u]",
				m_dptr[i]->m_bank_u32 );
			#endif
			e++;
		}

		if( ( m_dptr[i]->m_burst_u32 & DIMM_BURSTLEN_4 ) == 0 ) {
			#ifdef U4_DEBUG
			printf( "\r\n  [ERROR -> DIMM(s) have invalid burst length in bank %u]",
				m_dptr[i]->m_bank_u32 );
			#endif
			e++;
		}

	}

	/*
	 * return on error
	 */
	if( e != 0 ) {
		#ifdef U4_DEBUG
		printf( "\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * setup generic dimm
	 */
	m_gendimm.m_width_u32 = m_dptr[0]->m_width_u32;
	m_gendimm.m_ecc_u32   = m_dptr[0]->m_ecc_u32;
	m_gendimm.m_burst_u32 = m_dptr[0]->m_burst_u32;

	/*
	 * success
	 */
	m_gendimm.m_pop_u32 = SL_POP;

	/*
	 * setup timing parameters
	 */

	/*
	 * find smallest common CL value
	 */
	l_tmp_u32 = (uint32_t) ~0;
	for( i = 0; i < m_dcnt_u32; i++ ) {
		l_tmp_u32 &= m_dptr[i]->m_clmsk_u32;
	}

	m_gendimm.m_clmsk_u32 = l_tmp_u32;
	ddr2_get_cl( &m_gendimm );

	/*
	 * find fastest common DIMM speed for all common CL values
	 */
	for( i = 0; i < m_gendimm.m_clcnt_u32; i++ ) {
		m_gendimm.m_speed_pu32[i] = (uint32_t) ~0;

		for( j = 0; j < m_dcnt_u32; j++ ) {
			l_tmp0_u32 =
			ddr2_cl2speed( m_dptr[j],
				       m_gendimm.m_clval_pu32[i],
				       &l_tmp1_u32 );

			if( m_gendimm.m_speed_pu32[i] > l_tmp0_u32 ) {
				m_gendimm.m_speed_pu32[i] = l_tmp0_u32;
				m_gendimm.m_tCK_pu32[i]   = l_tmp1_u32;
			}

		}

	}

	/*
	 * check wether cl values are supported by U4
	 */
	for( i = 0; i < m_gendimm.m_clcnt_u32; i++ ) {

		if( ( m_gendimm.m_clval_pu32[i] >= U4_MIN_CL ) &&
		    ( m_gendimm.m_clval_pu32[i] <= U4_MAX_CL ) ) {
			break;
		}

	}

	if( i == m_gendimm.m_clcnt_u32 ) {
		#ifdef U4_DEBUG
		printf( "\r\n  [ERROR -> DIMM's CL values not supported]\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * choose cl/speed values to use: prefer speed over CL
	 * i holds smallest supported cl value of u4 already
	 */
	l_tmp_u32 = 0;
	while( i < m_gendimm.m_clcnt_u32 ) {

		if( l_tmp_u32 < m_gendimm.m_speed_pu32[i] ) {
			l_tmp_u32    = m_gendimm.m_speed_pu32[i];
			m_dclidx_u32 = i;
		}

		i++;
	}

	/*
	 * choose largest number of banks
	 */
	m_gendimm.m_bankcnt_u32 = 0;

	for( i = 0; i < m_dcnt_u32; i++ ) {

		if( m_gendimm.m_bankcnt_u32 < m_dptr[i]->m_bankcnt_u32 ) {
			m_gendimm.m_bankcnt_u32 = m_dptr[i]->m_bankcnt_u32;
		}

	}

	/*
	 * setup fastest possible timing parameters for all DIMMs
	 */
	m_gendimm.m_tRP_u32  = 0;
	m_gendimm.m_tRRD_u32 = 0;
	m_gendimm.m_tRCD_u32 = 0;
	m_gendimm.m_tWR_u32  = 0;
	m_gendimm.m_tWTR_u32 = 0;
	m_gendimm.m_tRTP_u32 = 0;
	m_gendimm.m_tRAS_u32 = 0;
	m_gendimm.m_tRC_u32  = 0;
	m_gendimm.m_tRFC_u32 = 0;
	m_gendimm.m_tREF_u32 = (uint32_t) ~0;

	for( i = 0; i < m_dcnt_u32; i++ ) {

		if( m_gendimm.m_tRP_u32  < m_dptr[i]->m_tRP_u32  ) {
			m_gendimm.m_tRP_u32  = m_dptr[i]->m_tRP_u32;
		}

		if( m_gendimm.m_tRRD_u32 < m_dptr[i]->m_tRRD_u32 ) {
			m_gendimm.m_tRRD_u32 = m_dptr[i]->m_tRRD_u32;
		}

		if( m_gendimm.m_tRCD_u32 < m_dptr[i]->m_tRCD_u32 ) {
			m_gendimm.m_tRCD_u32 = m_dptr[i]->m_tRCD_u32;
		}

		if( m_gendimm.m_tWR_u32  < m_dptr[i]->m_tWR_u32  ) {
			m_gendimm.m_tWR_u32  = m_dptr[i]->m_tWR_u32;
		}

		if( m_gendimm.m_tWTR_u32 < m_dptr[i]->m_tWTR_u32 ) {
			m_gendimm.m_tWTR_u32 = m_dptr[i]->m_tWTR_u32;
		}

		if( m_gendimm.m_tRTP_u32 < m_dptr[i]->m_tRTP_u32 ) {
			m_gendimm.m_tRTP_u32 = m_dptr[i]->m_tRTP_u32;
		}

		if( m_gendimm.m_tRAS_u32 < m_dptr[i]->m_tRAS_u32 ) {
			m_gendimm.m_tRAS_u32 = m_dptr[i]->m_tRAS_u32;
		}

		if( m_gendimm.m_tRC_u32  < m_dptr[i]->m_tRC_u32  ) {
			m_gendimm.m_tRC_u32  = m_dptr[i]->m_tRC_u32;
		}

		if( m_gendimm.m_tRFC_u32 < m_dptr[i]->m_tRFC_u32 ) {
			m_gendimm.m_tRFC_u32 = m_dptr[i]->m_tRFC_u32;
		}

		if( m_gendimm.m_tREF_u32 > m_dptr[i]->m_tREF_u32 ) {
			m_gendimm.m_tREF_u32 = m_dptr[i]->m_tREF_u32;
		}

	}

	return RET_OK;
}

static void
u4_group2dimmsDS( dimm_t *f_dimm0, dimm_t *f_dimm1 )
{
	dgroup_t *l_dgr = &m_dgroup[m_dgrcnt_u32];

	/*
	 * known conditions at this point:
	 * -at least 2 slots are populated
	 * -the 2 DIMMs are equal
	 * -DIMMs are double sided (2 ranks)
	 *
	 * RESULT:
	 * 1 group of 2 ranks (2 ranks/2 DIMMs)
	 * -> CS mode 1 (one double sided DIMM pair)
	 */
	l_dgr->m_size_u32   = 2 * ( f_dimm0->m_size_u32 * f_dimm0->m_rank_u32 );
	l_dgr->m_ss_u32     = 0;
	l_dgr->m_csmode_u32 = 1;
	l_dgr->m_dcnt_u32   = 2;
	l_dgr->m_dptr[0]    = f_dimm0;
	l_dgr->m_dptr[1]    = f_dimm1;

	m_dgrcnt_u32++;
}

static void
u4_group2dimmsSS( dimm_t *f_dimm0, dimm_t *f_dimm1 )
{
	dgroup_t *l_dgr = &m_dgroup[m_dgrcnt_u32];

	/*
	 * known conditions at this point:
	 * -at least 2 slots are populated
	 * -the 2 DIMMs are equal
	 * -DIMMs are single sided (1 rank)
	 *
	 * RESULT:
	 * 1 group of 1 rank (1 rank/2 DIMMs)
	 * -> CS mode 0 (one single sided DIMM pair)
	 */
	l_dgr->m_size_u32   = 2 * ( f_dimm0->m_size_u32 * f_dimm0->m_rank_u32 );
	l_dgr->m_ss_u32     = 1;
	l_dgr->m_csmode_u32 = 0;
	l_dgr->m_dcnt_u32   = 2;
	l_dgr->m_dptr[0]    = f_dimm0;
	l_dgr->m_dptr[1]    = f_dimm1;

	m_dgrcnt_u32++;
}

static void
u4_group4dimmsDS( dimm_t *f_dimm0, dimm_t *f_dimm1,
		  dimm_t *f_dimm2, dimm_t *f_dimm3 )
{
	dgroup_t *l_dgr = &m_dgroup[m_dgrcnt_u32];

	/*
	 * known conditions at this point:
	 * -4 slots are populated
	 * -all 4 DIMMs are equal
	 * -DIMMs are double sided (2 ranks)
	 *
	 * RESULT:
	 * 1 group of 4 ranks (2 ranks/2 DIMMs)
	 * -> CS mode 2 (two double sided DIMM pairs)
	 */
	l_dgr->m_size_u32   = 4 * ( f_dimm0->m_size_u32 * f_dimm0->m_rank_u32 );
	l_dgr->m_ss_u32     = 0;
	l_dgr->m_csmode_u32 = 2;
	l_dgr->m_dcnt_u32   = 4;
	l_dgr->m_dptr[0]    = f_dimm0;
	l_dgr->m_dptr[1]    = f_dimm1;
	l_dgr->m_dptr[2]    = f_dimm2;
	l_dgr->m_dptr[3]    = f_dimm3;

	m_dgrcnt_u32++;
}

static void
u4_group4dimmsSS( dimm_t *f_dimm0, dimm_t *f_dimm1,
		  dimm_t *f_dimm2, dimm_t *f_dimm3 )
{
	dgroup_t *l_dgr = &m_dgroup[m_dgrcnt_u32];

	/*
	 * known conditions at this point:
	 * -4 slots are populated
	 * -all 4 DIMMs are equal
	 * -DIMMs are single sided (1 rank)
	 *
	 * RESULT:
	 * 1 group of 2 ranks (1 rank/2 DIMMs)
	 * -> CS mode 1 (two single sided DIMM pairs)
	 */
	l_dgr->m_size_u32   = 4 * ( f_dimm0->m_size_u32 * f_dimm0->m_rank_u32 );
	l_dgr->m_ss_u32     = 1;
	l_dgr->m_csmode_u32 = 1;
	l_dgr->m_dcnt_u32   = 4;
	l_dgr->m_dptr[0]    = f_dimm0;
	l_dgr->m_dptr[1]    = f_dimm1;
	l_dgr->m_dptr[2]    = f_dimm2;
	l_dgr->m_dptr[3]    = f_dimm3;

	m_dgrcnt_u32++;
}

static void
u4_group8dimmsDS( dimm_t *f_dimm0, dimm_t *f_dimm1,
		  dimm_t *f_dimm2, dimm_t *f_dimm3,
		  dimm_t *f_dimm4, dimm_t *f_dimm5,
		  dimm_t *f_dimm6, dimm_t *f_dimm7 )
{
	dgroup_t *l_dgr = &m_dgroup[m_dgrcnt_u32];

	/*
	 * known conditions at this point:
	 * -8 slots are populated
	 * -all 8 DIMMs are equal
	 * -DIMMs are double sided (2 ranks)
	 *
	 * RESULT:
	 * 1 group of 8 ranks (2 ranks/2 DIMMs)
	 * -> CS mode 3 (four double sided DIMM pairs)
	 */
	l_dgr->m_size_u32   = 8 * ( f_dimm0->m_size_u32 * f_dimm0->m_rank_u32 );
	l_dgr->m_ss_u32     = 0;
	l_dgr->m_csmode_u32 = 3;
	l_dgr->m_dcnt_u32   = 8;
	l_dgr->m_dptr[0]    = f_dimm0;
	l_dgr->m_dptr[1]    = f_dimm1;
	l_dgr->m_dptr[2]    = f_dimm2;
	l_dgr->m_dptr[3]    = f_dimm3;
	l_dgr->m_dptr[4]    = f_dimm4;
	l_dgr->m_dptr[5]    = f_dimm5;
	l_dgr->m_dptr[6]    = f_dimm6;
	l_dgr->m_dptr[7]    = f_dimm7;

	m_dgrcnt_u32++;
}

static void
u4_group8dimmsSS( dimm_t *f_dimm0, dimm_t *f_dimm1,
		  dimm_t *f_dimm2, dimm_t *f_dimm3,
		  dimm_t *f_dimm4, dimm_t *f_dimm5,
		  dimm_t *f_dimm6, dimm_t *f_dimm7 )
{
	dgroup_t *l_dgr = &m_dgroup[m_dgrcnt_u32];

	/*
	 * known conditions at this point:
	 * -8 slots are populated
	 * -all 8 DIMMs are equal
	 * -DIMMs are single sided (1 rank)
	 *
	 * RESULT:
	 * 1 group of 4 ranks (1 rank/2 DIMMs)
	 * -> CS mode 2 (four single sided DIMM pairs)
	 */
	l_dgr->m_size_u32   = 8 * ( f_dimm0->m_size_u32 * f_dimm0->m_rank_u32 );
	l_dgr->m_ss_u32     = 1;
	l_dgr->m_csmode_u32 = 2;
	l_dgr->m_dcnt_u32   = 8;
	l_dgr->m_dptr[0]    = f_dimm0;
	l_dgr->m_dptr[1]    = f_dimm1;
	l_dgr->m_dptr[2]    = f_dimm2;
	l_dgr->m_dptr[3]    = f_dimm3;
	l_dgr->m_dptr[4]    = f_dimm4;
	l_dgr->m_dptr[5]    = f_dimm5;
	l_dgr->m_dptr[6]    = f_dimm6;
	l_dgr->m_dptr[7]    = f_dimm7;

	m_dgrcnt_u32++;
}

static int32_t
u4_Dcmp( dimm_t *f_dimm0, dimm_t *f_dimm1 )
{

	if( ( f_dimm0->m_size_u32 == f_dimm1->m_size_u32 ) &&
	    ( f_dimm0->m_rank_u32 == f_dimm1->m_rank_u32 ) ) {
		return RET_OK;
	}

	return RET_ERR;
}

static void
u4_group1banks( uint32_t *bidx )
{
	uint32_t didx = 2 * bidx[0];

	/*
	 * known conditions at this point:
	 * -either DIMMs 0 & 4 or
	 *	   DIMMs 1 & 5 or
	 *	   DIMMs 2 & 6 or
	 *	   DIMMs 3 & 7 are populated
	 * -3 (bimini)/1 (maui) pair of slots is empty
	 * -installed DIMMs are equal
	 */

	/*
	 * double/single sided setup
	 */
	if( m_dimm[didx].m_rank_u32 == 1 ) {
		u4_group2dimmsSS( &m_dimm[didx], &m_dimm[didx+1] );
	} else {
		u4_group2dimmsDS( &m_dimm[didx], &m_dimm[didx+1] );
	}

}

static void
u4_group2banks( uint32_t *bidx )
{
	uint32_t didx0 = 2 * bidx[0];
	uint32_t didx1 = 2 * bidx[1];

	/*
	 * known conditions at this point:
	 * -4 slots are populated
	 */

	/*
	 * check wether DIMM banks may be grouped
	 */
	if( ( ( ( bidx[0] + bidx[1] ) & 0x1 )           != 0 ) &&
	    ( u4_Dcmp( &m_dimm[didx0], &m_dimm[didx1] ) == 0 ) ) {
		/*
		 * double/single sided setup
		 * NOTE: at this point all DIMMs have the same amount
		 * of ranks, therefore only the # of ranks on DIMM 0 is checked
		 */
		if( m_dimm[didx0].m_rank_u32 == 1 ) {
			u4_group4dimmsSS( &m_dimm[didx0], &m_dimm[didx0+1],
					  &m_dimm[didx1], &m_dimm[didx1+1]);
		} else {
			u4_group4dimmsDS( &m_dimm[didx0], &m_dimm[didx0+1],
					  &m_dimm[didx1], &m_dimm[didx1+1]);
		}

	} else {
		u4_group1banks( &bidx[0] );
		u4_group1banks( &bidx[1] );
	}

}

static void
u4_group3banks( uint32_t *bidx )
{

	if(        ( bidx[0] == 0 ) && ( bidx[1] == 1 ) ) {
		u4_group2banks( &bidx[0] );
		u4_group1banks( &bidx[2] );
	} else if( ( bidx[1] == 2 ) && ( bidx[2] == 3 ) ) {
		u4_group2banks( &bidx[1] );
		u4_group1banks( &bidx[0] );
	}

}

static void
u4_group4banks( uint32_t *bidx )
{
	uint32_t didx0 = 2 * bidx[0];
	uint32_t didx1 = 2 * bidx[1];
	uint32_t didx2 = 2 * bidx[2];
	uint32_t didx3 = 2 * bidx[3];

	if( ( u4_Dcmp( &m_dimm[didx0], &m_dimm[didx1] ) == RET_OK ) &&
	    ( u4_Dcmp( &m_dimm[didx2], &m_dimm[didx3] ) == RET_OK ) &&
	    ( u4_Dcmp( &m_dimm[didx0], &m_dimm[didx2] ) == RET_OK ) ) {

		if( m_dimm[didx0].m_rank_u32 == 1 ) {
			u4_group8dimmsSS( &m_dimm[didx0], &m_dimm[didx0+1],
					  &m_dimm[didx1], &m_dimm[didx1+1],
					  &m_dimm[didx2], &m_dimm[didx2+1],
					  &m_dimm[didx3], &m_dimm[didx3+1] );
		} else {
			u4_group8dimmsDS( &m_dimm[didx0], &m_dimm[didx0+1],
					  &m_dimm[didx1], &m_dimm[didx1+1],
					  &m_dimm[didx2], &m_dimm[didx2+1],
					  &m_dimm[didx3], &m_dimm[didx3+1] );
		}

	} else {
		u4_group2banks( &bidx[0] );
		u4_group2banks( &bidx[2] );
	}

}

static void
u4_sortDIMMgroups( void )
{
	uint32_t i, j;

	/*
	 * setup global group pointers
	 */
	for( i = 0; i < m_dgrcnt_u32; i++ ) {
		m_dgrptr[i] = &m_dgroup[i];
	}

	/*
	 * use a simple bubble sort to sort groups by size (descending)
	 */
	for( i = 0; i < ( m_dgrcnt_u32 - 1 ); i++ ) {

		for( j = i + 1; j < m_dgrcnt_u32; j++ ) {

			if( m_dgrptr[i]->m_size_u32 < m_dgrptr[j]->m_size_u32 ) {
				dgroup_t *l_sgr;

				l_sgr       = m_dgrptr[i];
				m_dgrptr[i] = m_dgrptr[j];
				m_dgrptr[j] = l_sgr;
			}

		}

	}

}

static void
u4_calcDIMMcnfg( void )
{
	static const uint32_t _2GB  = (uint32_t) 0x00800;
	static const uint32_t _4GB  = (uint32_t) 0x01000;
	static const uint32_t _64GB = (uint32_t) 0x10000;
	uint32_t l_start_u32        = (uint32_t) 0;
	uint32_t l_end_u32          = (uint32_t) 0;
	uint32_t l_add2g_u32        = (uint32_t) 1;
	uint32_t l_sub2g_u32        = (uint32_t) 1;
	uint32_t i;

	/*
	 * setup DIMM group parameters
	 */
	for( i = 0; i < m_dgrcnt_u32; i++ ) {
		l_end_u32 = l_start_u32 + m_dgrptr[i]->m_size_u32;

		if( m_dgrptr[i]->m_size_u32 > _2GB ) {

			if( l_end_u32 < _64GB ) {
				l_add2g_u32 = ( l_end_u32 >> 11 );
			} else {
				l_add2g_u32 = 1;
			}

			if( l_start_u32 == 0 ) {
				l_sub2g_u32 = 1;
			} else {
				l_sub2g_u32 = ( l_start_u32 >> 11 );
			}

		} else if( l_add2g_u32 != 1 ) {
			l_start_u32 += _2GB;
			l_end_u32   += _2GB;
			l_add2g_u32  = 1;
			l_sub2g_u32  = 1;
		}

		/*
		 * save values for the group
		 */
		m_dgrptr[i]->m_start_u32 = ( l_start_u32 >> 7 ); // = /128
		m_dgrptr[i]->m_end_u32   = ( l_end_u32   >> 7 );
		m_dgrptr[i]->m_add2g_u32 = l_add2g_u32;
		m_dgrptr[i]->m_sub2g_u32 = l_sub2g_u32;

		/*
		 * continue with next group
		 */
		if( l_end_u32 != _2GB ) {
			l_start_u32 = l_end_u32;
		} else {
			l_start_u32 = _4GB;
		}

	}

}

static int32_t
u4_calcDIMMmemmode( void )
{
	static const uint32_t MAX_ORG  = (uint32_t) 0x10;
	static const uint32_t MIN_BASE = (uint32_t) 0x80;
	static const uint32_t MAX_MODE = (uint32_t) 0x10;
	static const uint32_t MODE_ADD = (uint32_t) 0x04;
	dimm_t   *l_dptr;
	uint32_t  l_modeoffs_u32;
	uint32_t  l_sizebase_u32;
	int32_t	  ret = RET_OK;
	uint32_t  i, j;

	/*
	 * loop through all DIMM groups and calculate memmode setting
	 */
	for( i = 0; i < m_dgrcnt_u32; i++ ) {
		l_dptr = m_dgrptr[i]->m_dptr[0]; // all dimms in one group are equal!

		l_modeoffs_u32  = MAX_ORG / l_dptr->m_orgval_u32;
		l_modeoffs_u32 /= (uint32_t) 2;
		l_sizebase_u32  = ( MIN_BASE << l_modeoffs_u32 );

		j = 0;
		while( ( l_sizebase_u32 != l_dptr->m_size_u32 ) &&
		       ( j               < MAX_MODE           ) ) {
			l_sizebase_u32 <<= 1;
			j += (uint32_t) MODE_ADD;
		}

		// return on error
		if( j >= MAX_MODE ) {
			#ifdef U4_INFO
			uint32_t b, k, l;
			printf( "\r\n  [ERROR -> unsupported memory type in bank(s)" );

			l = 0;
			for( k = 0; k < m_dgrptr[i]->m_dcnt_u32; k++ ) {
				b = m_dgrptr[i]->m_dptr[k]->m_bank_u32;

				if( ( l & ( 1 << b ) ) == 0 ) {
					printf( " %u", b );
					l |= ( 1 << b );
				}

			}

			printf( "]\r\n" );
			#endif

			ret = RET_ERR;
		} else {
			m_dgrptr[i]->m_memmd_u32 = l_modeoffs_u32 + j;
		}

	}

	return ret;
}

static void
u4_setupDIMMgroups( void )
{
	static const uint64_t _1MB = (uint64_t) 0x100000;
	uint32_t l_bcnt_u32;
	uint32_t l_bidx_u32[NUM_BANKS];
	uint32_t i;

	/*
	 * calculate number of populated banks
	 * IMPORTANT: array must be in ascending order!
	 */
	l_bcnt_u32 = 0;
	for( i = 0; i < NUM_BANKS; i++ ) {

		if( m_bankpop_u32[i] != 0 ) {
			l_bidx_u32[l_bcnt_u32] = i;
			l_bcnt_u32++;
		}

	}

	switch( l_bcnt_u32 ) {
		case 4: u4_group4banks( &l_bidx_u32[0] ); break;
		case 3: u4_group3banks( &l_bidx_u32[0] ); break;
		case 2: u4_group2banks( &l_bidx_u32[0] ); break;
		case 1: u4_group1banks( &l_bidx_u32[0] ); break;
	}

	/*
	 * sort DIMM groups by size (descending)
	 */
	u4_sortDIMMgroups();

	/*
	 * calculate overall memory size in bytes
	 * (group size is in MB)
	 */
	m_memsize_u64 = 0;
	for( i = 0; i < m_dgrcnt_u32; i++ ) {
		m_memsize_u64 += (uint64_t) m_dgrptr[i]->m_size_u32 * _1MB;
	}

}

static int32_t
u4_setup_core_clock( void )
{
	static const uint32_t MCLK = (uint32_t) 266;
	static const uint32_t CDIV = (uint32_t) 66;
	static const uint32_t CMAX = (uint32_t) 7;
	static const uint32_t MERR = (uint32_t) 10;
	uint32_t volatile     l_cclk_u32;
	uint32_t volatile     l_pll2_u32;
	uint32_t              i, s;

	#ifdef U4_INFO
	printf( "  [core clock reset:          ]" );
	#endif

	/*
	 * calculate speed value
	 */
	s  = m_gendimm.m_speed_pu32[m_dclidx_u32];
	s -= MCLK;
	s /= CDIV;

	/*
	 * insert new core clock value
	 */
	l_cclk_u32  = load32_ci( ClkCntl_R );
	l_cclk_u32 &= ~CLK_DDR_CLK_MSK;
	l_cclk_u32 |= ( s << 18 );


	// return on error
	if( s > CMAX ) {
		#ifdef U4_INFO
		printf( "\b\b\b\bERR\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * reset core clock
	 */
	store32_ci( ClkCntl_R, l_cclk_u32 );
	dly( 0x1000000 );
	or32_ci( PLL2Cntl_R, IBIT(0) );
	dly( 0x1000000 );

	/*
	 * wait for reset to finish
	 */
	do {
		l_pll2_u32 = load32_ci( PLL2Cntl_R );
	} while( ( l_pll2_u32 & IBIT(0) ) != 0 );

	/*
	 * wait for stable PLL
	 */
	s = 0;
	do {
		l_pll2_u32  = ( load32_ci( PLL2Cntl_R ) & IBIT(2) );

		for( i = 0; i < 4; i++ ) {
			l_pll2_u32 &= ( load32_ci( PLL2Cntl_R ) & IBIT(2) );
			l_pll2_u32 &= ( load32_ci( PLL2Cntl_R ) & IBIT(2) );
			l_pll2_u32 &= ( load32_ci( PLL2Cntl_R ) & IBIT(2) );
			dly( 0x10000 );
		}

	} while( ( l_pll2_u32 == 0 ) && ( s++ < MERR ) );

	if( s >= MERR ) {
		#ifdef U4_INFO
		printf( "\b\b\b\bERR\r\n" );
		#endif
		return RET_ERR;
	}

	#ifdef U4_INFO
	printf( "\b\b\bOK\r\n" );
	#endif

	return RET_OK;
}

static void
u4_auto_calib_init( void )
{
	static const uint32_t SEQ[] = {
		0xb1000000, 0xd1000000, 0xd1000000, 0xd1000000,
		0xd1000000, 0xd1000000, 0xd1000000, 0xd1000000,
		0xd1000000, 0xd1000000, 0xd1000000, 0xd1000000,
		0xd1000000, 0xd1000000, 0xd1000400, 0x00000000,
	};

	uint64_t i;
	uint32_t j;

	for( i = MemInit00_R, j = 0; i <= MemInit15_R; i += 0x10, j++ ) {
		store32_ci( i, SEQ[j] );
	}

}

#if 0
static uint32_t
u4_RSL_BLane( uint32_t f_Rank_u32, uint32_t f_BLane_u32 )
{
	static const uint32_t MemProgCntl_V = (uint32_t) 0x80000500;
	static const uint32_t CalConf0_V    = (uint32_t) 0x0000aa10;
	uint32_t l_MemProgCntl_u32;
	uint32_t l_CalConf0_u32;
	uint32_t l_MeasStat_u32;
	uint32_t l_CalC_u32;
	uint64_t MeasStat_R;
	uint64_t CalC_R;
	uint64_t VerC_R;
	uint32_t shft;
	uint32_t v;

	if( f_BLane_u32 < 4 ) {
		MeasStat_R   = MeasStatusC0_R;
		CalC_R       = CalC0_R;
		VerC_R       = RstLdEnVerniersC0_R;
	} else if( f_BLane_u32  <  8 ) {
		f_BLane_u32 -= 4;
		MeasStat_R   = MeasStatusC1_R;
		CalC_R       = CalC1_R;
		VerC_R       = RstLdEnVerniersC1_R;
	} else if( f_BLane_u32  < 12 ) {
		f_BLane_u32 -= 8;
		MeasStat_R   = MeasStatusC2_R;
		CalC_R       = CalC2_R;
		VerC_R       = RstLdEnVerniersC2_R;
	} else if( f_BLane_u32 == 16 ) {
		f_BLane_u32  = 4;
		MeasStat_R   = MeasStatusC1_R;
		CalC_R       = CalC1_R;
		VerC_R       = RstLdEnVerniersC1_R;
	} else if( f_BLane_u32 == 17 ) {
		f_BLane_u32  = 4;
		MeasStat_R   = MeasStatusC3_R;
		CalC_R       = CalC3_R;
		VerC_R       = RstLdEnVerniersC3_R;
	} else {
		f_BLane_u32 -= 12;
		MeasStat_R   = MeasStatusC3_R;
		CalC_R       = CalC3_R;
		VerC_R       = RstLdEnVerniersC3_R;
	}

	shft = (uint32_t) 28 - ( f_BLane_u32 * 4 );

	/*
	 * start auto calibration logic & wait for completion
	 */
	or32_ci( MeasStat_R, IBIT(0) );

	do {
		l_MeasStat_u32 = load32_ci( MeasStat_R );
	} while( ( l_MeasStat_u32 & IBIT(0) ) == 1 );

	l_CalConf0_u32  = CalConf0_V;
	store32_ci( CalConf0_R, l_CalConf0_u32 );

	for( v = 0x000; v < (uint32_t) 0x100; v++ ) {
		store32_ci( VerC_R, ( v << 24 ) | ( v << 16 ) );

		l_MemProgCntl_u32  = MemProgCntl_V;
		l_MemProgCntl_u32 |=
			( (uint32_t) 0x00800000 >> f_Rank_u32 );
		store32_ci( MemProgCntl_R, l_MemProgCntl_u32 );

		do {
			l_MemProgCntl_u32 = load32_ci( MemProgCntl_R );
		} while( ( l_MemProgCntl_u32 & IBIT(1) ) == 0 );

		l_CalC_u32 = ( ( load32_ci( CalC_R ) >> shft ) &
			         (uint32_t) 0xf );

		if( l_CalC_u32 != (uint32_t) 0xa ) {
			v--;
			break;
		}

	}

	if( v == (uint32_t) 0x100 ) {
		v = (uint32_t) ~1;
	}

	return v;
}
#endif

static uint32_t
u4_RMDF_BLane( uint32_t f_Rank_u32, uint32_t f_BLane_u32 )
{
	static const uint32_t MemProgCntl_V = (uint32_t) 0x80000f00;
	static const uint32_t CalConf0_V    = (uint32_t) 0x0000ac10;
	uint32_t l_MemProgCntl_u32;
	uint32_t l_CalConf0_u32;
	uint32_t l_MeasStat_u32;
	uint32_t l_CalC_u32;
	uint64_t MeasStat_R;
	uint64_t CalC_R;
	uint64_t VerC_R;
	uint32_t shft;
	uint32_t v;

	if( f_BLane_u32 < 4 ) {
		MeasStat_R   = MeasStatusC0_R;
		CalC_R       = CalC0_R;
		VerC_R       = RstLdEnVerniersC0_R;
	} else if( f_BLane_u32  <  8 ) {
		f_BLane_u32 -= 4;
		MeasStat_R   = MeasStatusC1_R;
		CalC_R       = CalC1_R;
		VerC_R       = RstLdEnVerniersC1_R;
	} else if( f_BLane_u32  < 12 ) {
		f_BLane_u32 -= 8;
		MeasStat_R   = MeasStatusC2_R;
		CalC_R       = CalC2_R;
		VerC_R       = RstLdEnVerniersC2_R;
	} else if( f_BLane_u32 == 16 ) {
		f_BLane_u32  = 4;
		MeasStat_R   = MeasStatusC1_R;
		CalC_R       = CalC1_R;
		VerC_R       = RstLdEnVerniersC1_R;
	} else if( f_BLane_u32 == 17 ) {
		f_BLane_u32  = 4;
		MeasStat_R   = MeasStatusC3_R;
		CalC_R       = CalC3_R;
		VerC_R       = RstLdEnVerniersC3_R;
	} else {
		f_BLane_u32 -= 12;
		MeasStat_R   = MeasStatusC3_R;
		CalC_R       = CalC3_R;
		VerC_R       = RstLdEnVerniersC3_R;
	}

	shft = (uint32_t) 28 - ( f_BLane_u32 * 4 );

	/*
	 * start auto calibration logic & wait for completion
	 */
	or32_ci( MeasStat_R, IBIT(0) );

	do {
		l_MeasStat_u32 = load32_ci( MeasStat_R );
	} while( ( l_MeasStat_u32 & IBIT(0) ) == 1 );

	l_CalConf0_u32  = CalConf0_V;
	l_CalConf0_u32 |= ( f_BLane_u32 << 5 );
	store32_ci( CalConf0_R, l_CalConf0_u32 );

	for( v = 0x000; v < (uint32_t) 0x100; v++ ) {
		store32_ci( VerC_R, ( v << 24 ) | ( v << 16 ) );

		l_MemProgCntl_u32  = MemProgCntl_V;
		l_MemProgCntl_u32 |=
			( (uint32_t) 0x00800000 >> f_Rank_u32 );
		store32_ci( MemProgCntl_R, l_MemProgCntl_u32 );

		do {
			l_MemProgCntl_u32 = load32_ci( MemProgCntl_R );
		} while( ( l_MemProgCntl_u32 & IBIT(1) ) == 0 );

		l_CalC_u32 = ( ( load32_ci( CalC_R ) >> shft ) &
			         (uint32_t) 0xf );

		if( l_CalC_u32 != (uint32_t) 0xa ) {
			v--;
			break;
		}

	}

	if( v == (uint32_t) 0x100 ) {
		v = (uint32_t) ~1;
	}

	return v;
}

static int32_t
u4_RMDF_Rank( uint32_t  f_Rank_u32,
	      uint32_t *f_Buf_pu32 )
{
	int32_t  l_Err_pi32 = 0;
	uint32_t b;

	for( b = 0; ( b < MAX_BLANE ) && ( l_Err_pi32 == 0 ); b++ ) {
		f_Buf_pu32[b] = u4_RMDF_BLane( f_Rank_u32, b );

		if( f_Buf_pu32[b] == (uint32_t) ~0 ) {
			f_Buf_pu32[b] = 0;
			l_Err_pi32++;
		} else if( f_Buf_pu32[b] == (uint32_t) ~1 ) {
			f_Buf_pu32[b] = (uint32_t) 0xff;
			l_Err_pi32++;
		}

	}

	return l_Err_pi32;
}

static int32_t
u4_auto_calib_MemBus( auto_calib_t *f_ac_pt )
{
	uint32_t RdMacDly, RdMacCnt;
	uint32_t ResMuxDly, ResMuxCnt;
	uint32_t RdPipeDly;
	uint32_t l_Buf_pu32[MAX_DRANKS][MAX_BLANE];
	uint32_t l_Rnk_pu32[MAX_DRANKS];
	uint32_t l_Ver_u32;
	int32_t  l_Err_i32;
	uint32_t bidx;
	uint32_t n, r, b;

	/*
	 * read starting delays out of the MemBus register
	 */
	RdMacDly  = ( load32_ci( MemBusCnfg_R ) >> 28 ) & 0xf;
	ResMuxDly = ( load32_ci( MemBusCnfg_R ) >> 24 ) & 0xf;

	/*
	 * initialize ranks as not populated
	 */
	for( r = 0; r < MAX_DRANKS; r++ ) {
		l_Rnk_pu32[r] = 0;
	}

	/*
	 * run through every possible delays of
	 * RdMacDly, ResMuxDly & RdPipeDly until
	 * the first working configuration is found
	 */
	RdPipeDly = 0;
	do {
		and32_ci( MemBusCnfg2_R, ~0x3 );
		or32_ci(  MemBusCnfg2_R, RdPipeDly );

		RdMacCnt  =  RdMacDly;
		ResMuxCnt =  ResMuxDly;

		/*
		 * RdMacDly >= ResMuxDly
		 */
		do {
			and32_ci( MemBusCnfg_R, ( 1 << 24 ) - 1 );
			or32_ci(  MemBusCnfg_R, ( RdMacCnt  << 28 ) |
						( ResMuxCnt << 24 ) );
			and32_ci( MemBusCnfg2_R, ( 1 << 28 ) - 1 );
			or32_ci(  MemBusCnfg2_R, ( RdMacCnt << 28 ) );

			/*
			 * check the current value for every installed
			 * DIMM on each side for every bytelane
			 */
			l_Err_i32 = 0;
			for( n = 0;
			     ( n < NUM_SLOTS ) &&
			     ( l_Err_i32 == 0 );
			     n += 2 ) {

				if( m_dimm[n].m_pop_u32 ) {
					/*
					 * run through all 18 bytelanes of every rank
					 */
					for( r = n;
					     ( r < n + m_dimm[n].m_rank_u32 ) &&
					     ( l_Err_i32 == 0 );
					     r++ ) {
						l_Rnk_pu32[r] = 1;

						l_Err_i32 =
						u4_RMDF_Rank( r,
							      &l_Buf_pu32[r][0] );
					}

				}

			}

			/*
			 * decrementation before exit is wanted!
			 */
			RdMacCnt--;
			ResMuxCnt--;
		} while( ( ResMuxCnt  > 0 ) &&
			 ( l_Err_i32 != 0 ) );

		if( l_Err_i32 != 0 ) {
			RdPipeDly++;
		}

	} while( ( RdPipeDly   < 4 ) &&
		 ( l_Err_i32 != 0 ) );

	/*
	 * if l_Err_pi32 == 0 the auto calibration passed ok
	 */
	if( l_Err_i32 != 0 ) {
		return RET_ERR;
	}

	/*
	 * insert delay values into return struct
	 */
	and32_ci( MemBusCnfg_R, ( 1 << 24 ) - 1 );
	or32_ci(  MemBusCnfg_R, ( RdMacCnt  << 28 ) |
				( ResMuxCnt << 24 ) );
	and32_ci( MemBusCnfg2_R, ( ( 1 << 28 ) - 1 ) & ~0x3 );
	or32_ci(  MemBusCnfg2_R, ( RdMacCnt << 28 ) | RdPipeDly );

	f_ac_pt->m_MemBusCnfg_u32  = load32_ci( MemBusCnfg_R );
	f_ac_pt->m_MemBusCnfg2_u32 = load32_ci( MemBusCnfg2_R );

	/*
	 * calculate the average vernier setting for the
	 * bytelanes which share one vernier
	 */
	for( b = 0; b < MAX_BLANE - 2; b += 2 ) {
		n         = 0;
		l_Ver_u32 = 0;

		for( r = 0; r < MAX_DRANKS; r++ ) {
			/*
			 * calculation is done or populated ranks only
			 */
			if( l_Rnk_pu32[r] != 0 ) {
				/*
				 * calculate average value
				 */
				l_Ver_u32 += l_Buf_pu32[r][b];
				l_Ver_u32 += l_Buf_pu32[r][b+1];
				n         += 2;

				if( b == 4 ) {
					l_Ver_u32 += l_Buf_pu32[r][16];
					n++;
				} else if( b == 12 ) {
					l_Ver_u32 += l_Buf_pu32[r][17];
					n++;
				}

			}

		}

		/*
		 * average the values
		 */
		l_Ver_u32 /= n;

		/*
		 * set appropriate vernier register for
		 * the current bytelane
		 */
		bidx = ( b >> 2 );
		if( ( b & (uint32_t) 0x3 ) == 0 ) {
			l_Ver_u32 <<= 24;
			f_ac_pt->m_RstLdEnVerniers_pu32[bidx]  = l_Ver_u32;
		} else {
			l_Ver_u32 <<= 16;
			f_ac_pt->m_RstLdEnVerniers_pu32[bidx] |= l_Ver_u32;
		}

	}

	return RET_OK;
}

static int32_t
u4_auto_calib( auto_calib_t *f_ac_pt )
{
	uint32_t l_MemBusCnfg_S;
	uint32_t l_MemBusCnfg2_S;
	uint32_t l_RstLdEnVerniers_S[4];
	int32_t  l_Ret_i32;

	/*
	 * save manipulated registers
	 */
	l_MemBusCnfg_S         = load32_ci( MemBusCnfg_R );
	l_MemBusCnfg2_S        = load32_ci( MemBusCnfg2_R );
	l_RstLdEnVerniers_S[0] = load32_ci( RstLdEnVerniersC0_R );
	l_RstLdEnVerniers_S[1] = load32_ci( RstLdEnVerniersC1_R );
	l_RstLdEnVerniers_S[2] = load32_ci( RstLdEnVerniersC2_R );
	l_RstLdEnVerniers_S[3] = load32_ci( RstLdEnVerniersC3_R );

	u4_auto_calib_init();
	l_Ret_i32 = u4_auto_calib_MemBus( f_ac_pt );

	/*
	 * restore manipulated registers
	 */
	store32_ci( MemBusCnfg_R,  l_MemBusCnfg_S );
	store32_ci( MemBusCnfg2_R, l_MemBusCnfg2_S );
	store32_ci( RstLdEnVerniersC0_R, l_RstLdEnVerniers_S[0] );
	store32_ci( RstLdEnVerniersC1_R, l_RstLdEnVerniers_S[1] );
	store32_ci( RstLdEnVerniersC2_R, l_RstLdEnVerniers_S[2] );
	store32_ci( RstLdEnVerniersC3_R, l_RstLdEnVerniers_S[3] );

	return l_Ret_i32;
}

static int32_t
u4_checkeccerr( eccerror_t *f_ecc_pt )
{
	uint32_t l_val_u32;
	int32_t  ret = RET_OK;

	l_val_u32   = load32_ci( MESR_R );
	l_val_u32 >>= 29;

	if( ( l_val_u32 & (uint32_t) 0x7 ) != 0 ) {

		if(        ( l_val_u32 & (uint32_t) 0x4 ) != 0 ) {
			/* UE */
			ret = RET_ACERR_UE;
		} else if( ( l_val_u32 & (uint32_t) 0x1 ) != 0 ) {
			/* UEWT */
			ret = RET_ACERR_UEWT;
		} else {
			/* CE */
			ret = RET_ACERR_CE;
		}

	}

	f_ecc_pt->m_err_i32   = ret;

	l_val_u32             = load32_ci( MEAR1_R );
	f_ecc_pt->m_uecnt_u32 = ( ( l_val_u32 >> 24 ) & (uint32_t) 0xff );
	f_ecc_pt->m_cecnt_u32 = ( ( l_val_u32 >> 16 ) & (uint32_t) 0xff );

	l_val_u32             = load32_ci( MEAR0_R );
	f_ecc_pt->m_rank_u32  = ( ( l_val_u32 >> 29 ) & (uint32_t) 0x7 );
	f_ecc_pt->m_col_u32   = ( ( l_val_u32 >> 18 ) & (uint32_t) 0x7ff );
	f_ecc_pt->m_row_u32   = ( ( l_val_u32 >>  0 ) & (uint32_t) 0x7fff );
	f_ecc_pt->m_bank_u32  = ( ( l_val_u32 >> 15 ) & (uint32_t) 0x7 );

	return ret;
}

static uint32_t
u4_CalcScrubEnd( void )
{
	uint64_t l_scrend_u64 = m_memsize_u64;

	/*
	 * check for memory hole at 2GB
	 */
	if( l_scrend_u64 > _2GB ) {
		l_scrend_u64 += _2GB;
	}

	l_scrend_u64 -= 0x40;
	l_scrend_u64 /= 0x10;

	return( (uint32_t) l_scrend_u64 );
}

static int32_t
u4_Scrub( uint32_t f_scrub_u32, uint32_t f_pattern_u32, eccerror_t *f_eccerr_pt )
{
	uint32_t i;
	int32_t  ret;

	/*
	 * setup scrub parameters
	 */
	store32_ci( MSCR_R, 0 );			// stop scrub
	store32_ci( MSRSR_R, 0x0 );			// set start
	store32_ci( MSRER_R, u4_CalcScrubEnd() );	// set end
	store32_ci( MSPR_R, f_pattern_u32 );		// set pattern

	/*
	 * clear out ECC error registers
	 */
	store32_ci( MEAR0_R, 0x0 );
	store32_ci( MEAR1_R, 0x0 );
	store32_ci( MESR_R, 0x0 );

	/*
	 * Setup Scrub Type
	 */
	store32_ci( MSCR_R, f_scrub_u32 );

	if( f_scrub_u32 != BACKGROUND_SCRUB ) {
		/*
		 * wait for scrub to complete
		 */
		do {
			progbar();
			dly( 15000000 );
			i = load32_ci( MSCR_R );
		} while( ( i & f_scrub_u32 ) != 0 );

		ret = u4_checkeccerr( f_eccerr_pt );
	} else {
		ret = RET_OK;
	}

	return ret;
}

static eccerror_t
u4_InitialScrub( void )
{
	eccerror_t l_eccerr_st[2];
	int32_t    l_err_i32[2] = { 0, 0 };

	l_err_i32[0] = u4_Scrub( IMMEDIATE_SCRUB_WITH_FILL, 0x0, &l_eccerr_st[0] );

	if( l_err_i32[0] >= -1 /*CE*/ ) {
		l_err_i32[1] = u4_Scrub( IMMEDIATE_SCRUB, 0x0, &l_eccerr_st[1] );
	}

	if( l_err_i32[0] < l_err_i32[1] ) {
		return l_eccerr_st[0];
	} else {
		return l_eccerr_st[1];
	}

}

/*
 * RND: calculates Timer cycles from the given frequency
 *	divided by the clock frequency. Values are rounded
 * 	up to the nearest integer value if the division is not even.
 */
#define RND( tXXX )	( ( ( tXXX ) + tCK - 1 ) / tCK )

static void
u4_MemInitSequence( uint32_t tRP, uint32_t tWR, uint32_t tRFC, uint32_t CL,
		    uint32_t tCK, uint32_t TD )
{
	/*
	 * DIMM init sequence
	 */
	static const uint32_t INI_SEQ[] = {
		0xa0000400, 0x80020000, 0x80030000, 0x80010404,
		0x8000100a, 0xa0000400, 0x90000000, 0x90000000,
		0x8ff0100a, 0x80010784, 0x80010404, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000
	};

	uint32_t l_MemInit_u32;
	uint64_t r;
	uint32_t i;

	for( r = MemInit00_R, i = 0; r <= MemInit15_R; r += 0x10, i++ ) {
		l_MemInit_u32 = INI_SEQ[i];

		switch( i ) {
			case 0:
			case 5: {
				l_MemInit_u32 |= ( ( RND( tRP ) - TD )  << 20 );
				break;
			}
			case 3: {
				store32_ci( EMRSRegCntl_R, l_MemInit_u32 &
							   (uint32_t) 0xffff );
				break;
			}
			case 4: {
				l_MemInit_u32 |= IBIT(23);
			}
			case 8: {
				l_MemInit_u32 |= ( ( RND( tWR ) - 1 )  <<  9 );
				l_MemInit_u32 |= ( CL                  <<  4 );

				store32_ci( MRSRegCntl_R, l_MemInit_u32 &
							  (uint32_t) 0xffff );
				break;
			}
			case 6:
			case 7: {
				l_MemInit_u32 |= ( ( RND( tRFC ) - TD ) << 20 );
				break;
			}

		}

		store32_ci( r, l_MemInit_u32 );

#ifdef U4_SHOW_REGS
		printf( "\r\nMemInit%02d (0x%04X): 0x%08X", i, (uint16_t) r, l_MemInit_u32 );
#endif
	}
#ifdef U4_SHOW_REGS
	printf( "\r\n" );
#endif
	/*
	 * Kick off memory init sequence & wait for completion
	 */
	store32_ci( MemProgCntl_R, IBIT(0) );

	do {
		i = load32_ci( MemProgCntl_R );
	} while( ( i & IBIT(1) ) == 0 );

}

/*
 * static DIMM configuartion settings
 */
static reg_statics_t reg_statics_maui[NUM_SPEED_IDX] = {
	{	/* 400 Mhz */
		.RRMux          = 1,
		.WRMux          = 1,
		.WWMux          = 1,
		.RWMux          = 1,

		.MemRdQCnfg     = 0x20020820,
		.MemWrQCnfg     = 0x40041040,
		.MemQArb        = 0x00000000,
		.MemRWArb       = 0x30413cc0,

		.ODTCntl        = 0x60000000,
		.IOPadCntl      = 0x001a4000,
		.MemPhyModeCntl = 0x00000000,
		.OCDCalCntl     = 0x00000000,
		.OCDCalCmd      = 0x00000000,

		.CKDelayL       = 0x34000000,
		.CKDelayU       = 0x34000000,

		.MemBusCnfg     = 0x00000050                  |
				  ( (   MAX_RMD       << 28 ) |
				    ( ( MAX_RMD - 2 ) << 24 ) ),

		.CAS1Dly0       = 0,
		.CAS1Dly1	= 0,

		.ByteWrClkDel   = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	},
	{	/* 533 Mhz */
		.RRMux          = 1,
		.WRMux          = 1,
		.WWMux          = 1,
		.RWMux          = 1,

		.MemRdQCnfg     = 0x20020820,
		.MemWrQCnfg     = 0x40041040,
		.MemQArb        = 0x00000000,
		.MemRWArb       = 0x30413cc0,

		.ODTCntl        = 0x60000000,
		.IOPadCntl      = 0x001a4000,
		.MemPhyModeCntl = 0x00000000,
		.OCDCalCntl     = 0x00000000,
		.OCDCalCmd      = 0x00000000,

		.CKDelayL       = 0x18000000,
		.CKDelayU       = 0x18000000,

		.MemBusCnfg     = 0x00002070	              |
				  ( (   MAX_RMD       << 28 ) |
				    ( ( MAX_RMD - 3 ) << 24 ) ),

		.CAS1Dly0       = 0,
		.CAS1Dly1	= 0,

		.ByteWrClkDel   = {

			0x12000000, 0x12000000, 0x12000000 , 0x12000000,
			0x12000000, 0x12000000, 0x12000000 , 0x12000000,
			0x12000000, 0x12000000, 0x12000000 , 0x12000000,
			0x12000000, 0x12000000, 0x12000000 , 0x12000000,
			0x12000000, 0x12000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000 , 0x00000000,
			0x00000000, 0x00000000, 0x00000000 , 0x00000000,
			0x00000000, 0x00000000, 0x00000000 , 0x00000000,
			0x00000000, 0x00000000, 0x00000000 , 0x00000000,
			0x00000000, 0x00000000
		}

	},
	{	/* 667 Mhz */
		.RRMux          = 1,
		.WRMux          = 1,
		.WWMux          = 1,
		.RWMux          = 3,

		.MemRdQCnfg     = 0x20020820,
		.MemWrQCnfg     = 0x40041040,
		.MemQArb        = 0x00000000,
		.MemRWArb       = 0x30413cc0,

		.ODTCntl        = 0x60000000,
		.IOPadCntl      = 0x001a4000,
		.MemPhyModeCntl = 0x00000000,
		.OCDCalCntl     = 0x00000000,
		.OCDCalCmd      = 0x00000000,

		.CKDelayL       = 0x0a000000,
		.CKDelayU       = 0x0a000000,

		.MemBusCnfg     = 0x000040a0		      |
				  ( (   MAX_RMD       << 28 ) |
				    ( ( MAX_RMD - 3 ) << 24 ) ),

		.CAS1Dly0       = 2,
		.CAS1Dly1	= 2,

		.ByteWrClkDel   = {

			0x12000000, 0x12000000, 0x12000000, 0x12000000,
			0x12000000, 0x12000000, 0x12000000, 0x12000000,
			0x12000000, 0x12000000, 0x12000000, 0x12000000,
			0x12000000, 0x12000000, 0x12000000, 0x12000000,
			0x12000000, 0x12000000
/*
			0x31000000, 0x31000000, 0x31000000, 0x31000000,
			0x31000000, 0x31000000, 0x31000000, 0x31000000,
			0x31000000, 0x31000000, 0x31000000, 0x31000000,
			0x31000000, 0x31000000, 0x31000000, 0x31000000,
			0x31000000, 0x31000000
*/
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	}
};

static reg_statics_t reg_statics_bimini[NUM_SPEED_IDX] = {
	{	/* 400 Mhz */
		.RRMux          = 2,
		.WRMux          = 2,
		.WWMux          = 2,
		.RWMux          = 2,

		.MemRdQCnfg     = 0x20020820,
		.MemWrQCnfg     = 0x40041040,
		.MemQArb        = 0x00000000,
		.MemRWArb       = 0x30413cc0,

		.ODTCntl        = 0x40000000,
		.IOPadCntl      = 0x001a4000,
		.MemPhyModeCntl = 0x00000000,
		.OCDCalCntl     = 0x00000000,
		.OCDCalCmd      = 0x00000000,

		.CKDelayL       = 0x00000000,
		.CKDelayU       = 0x28000000,

		.MemBusCnfg     = 0x00552070                  |
				  ( (   MAX_RMD       << 28 ) |
				    ( ( MAX_RMD - 2 ) << 24 ) ),

		.CAS1Dly0       = 0,
		.CAS1Dly1	= 0,

		.ByteWrClkDel   = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	},
	{	/* 533 Mhz */
		.RRMux          = 3,
		.WRMux          = 3,
		.WWMux          = 3,
		.RWMux          = 3,

		.MemRdQCnfg     = 0x20020820,
		.MemWrQCnfg     = 0x40041040,
		.MemQArb        = 0x00000000,
		.MemRWArb       = 0x30413cc0,

		.ODTCntl        = 0x40000000,
		.IOPadCntl      = 0x001a4000,
		.MemPhyModeCntl = 0x00000000,
		.OCDCalCntl     = 0x00000000,
		.OCDCalCmd      = 0x00000000,

		.CKDelayL       = 0x00000000,
		.CKDelayU       = 0x20000000,

		.MemBusCnfg     = 0x00644190		      |
				  ( (   MAX_RMD       << 28 ) |
				    ( ( MAX_RMD - 3 ) << 24 ) ),

		.CAS1Dly0       = 2,
		.CAS1Dly1	= 2,

		.ByteWrClkDel   = {
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	},
	{	/* 667 Mhz */
		.RRMux          = 3,
		.WRMux          = 3,
		.WWMux          = 3,
		.RWMux          = 3,

		.MemRdQCnfg     = 0x20020820,
		.MemWrQCnfg     = 0x40041040,
		.MemQArb        = 0x00000000,
		.MemRWArb       = 0x30413cc0,

		.ODTCntl        = 0x40000000,
		.IOPadCntl      = 0x001a4000,
		.MemPhyModeCntl = 0x00000000,
		.OCDCalCntl     = 0x00000000,
		.OCDCalCmd      = 0x00000000,

		.CKDelayL       = 0x00000000,
		.CKDelayU       = 0x00000000,

		.MemBusCnfg     = 0x00666270		      |
				  ( (   MAX_RMD       << 28 ) |
				    ( ( MAX_RMD - 3 ) << 24 ) ),

		.CAS1Dly0       = 2,
		.CAS1Dly1	= 2,

		.ByteWrClkDel   = {
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000, 0x14000000, 0x14000000,
			0x14000000, 0x14000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	}
};

static reg_statics_t reg_statics_kauai[NUM_SPEED_IDX] = {
	{	/* 400 Mhz */
		.RRMux          = 0,
		.WRMux          = 0,
		.WWMux          = 0,
		.RWMux          = 0,

		.MemRdQCnfg     = 0,
		.MemWrQCnfg     = 0,
		.MemQArb        = 0,
		.MemRWArb       = 0,

		.ODTCntl        = 0,
		.IOPadCntl      = 0,
		.MemPhyModeCntl = 0,
		.OCDCalCntl     = 0,
		.OCDCalCmd      = 0,

		.CKDelayL       = 0,
		.CKDelayU       = 0,

		.MemBusCnfg     = 0,

		.CAS1Dly0       = 0,
		.CAS1Dly1	= 0,

		.ByteWrClkDel   = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	},
	{	/* 533 Mhz */
		.RRMux          = 0,
		.WRMux          = 0,
		.WWMux          = 0,
		.RWMux          = 0,

		.MemRdQCnfg     = 0,
		.MemWrQCnfg     = 0,
		.MemQArb        = 0,
		.MemRWArb       = 0,

		.ODTCntl        = 0,
		.IOPadCntl      = 0,
		.MemPhyModeCntl = 0,
		.OCDCalCntl     = 0,
		.OCDCalCmd      = 0,

		.CKDelayL       = 0,
		.CKDelayU       = 0,

		.MemBusCnfg     = 0,

		.CAS1Dly0       = 0,
		.CAS1Dly1	= 0,

		.ByteWrClkDel   = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	},
	{	/* 667 Mhz */
		.RRMux          = 0,
		.WRMux          = 0,
		.WWMux          = 0,
		.RWMux          = 0,

		.MemRdQCnfg     = 0,
		.MemWrQCnfg     = 0,
		.MemQArb        = 0,
		.MemRWArb       = 0,

		.ODTCntl        = 0,
		.IOPadCntl      = 0,
		.MemPhyModeCntl = 0,
		.OCDCalCntl     = 0,
		.OCDCalCmd      = 0,

		.CKDelayL       = 0,
		.CKDelayU       = 0,

		.MemBusCnfg     = 0,

		.CAS1Dly0       = 0,
		.CAS1Dly1	= 0,

		.ByteWrClkDel   = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		},
		.ReadStrobeDel  = {
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000
		}

	}
};

static int32_t
u4_start( eccerror_t *f_ecc_pt )
{
	/*
	 * maximum runs for auto calibration
	 */
	static const uint32_t MAX_ACERR	= (uint32_t) 5;

	/*
	 * fixed u4/DIMM timer/timing values for calculation
	 */
	static const uint32_t TD      = (uint32_t) 2;	// u4 delay cycles for loading a timer
	static const uint32_t AL      = (uint32_t) 0; 	// additional latency (fix)
	static const uint32_t BL      = (uint32_t) 4; 	// burst length (fix)

	uint32_t	      SPEED   = m_gendimm.m_speed_pu32[m_dclidx_u32];
	uint32_t              CL      = m_gendimm.m_clval_pu32[m_dclidx_u32];
	uint32_t              RL      = AL + CL;
	uint32_t              WL      = RL - 1;
	uint32_t              tCK     = m_gendimm.m_tCK_pu32[m_dclidx_u32];
	uint32_t 	      tRAS    = m_gendimm.m_tRAS_u32;
	uint32_t 	      tRTP    = m_gendimm.m_tRTP_u32;
	uint32_t 	      tRP     = m_gendimm.m_tRP_u32;
	uint32_t 	      tWR     = m_gendimm.m_tWR_u32;
	uint32_t 	      tRRD    = m_gendimm.m_tRRD_u32;
	uint32_t 	      tRC     = m_gendimm.m_tRC_u32;
	uint32_t 	      tRCD    = m_gendimm.m_tRCD_u32;
	uint32_t 	      tWTR    = m_gendimm.m_tWTR_u32;
	uint32_t	      tRFC    = m_gendimm.m_tRFC_u32;
	uint32_t	      tREF    = m_gendimm.m_tREF_u32;

	reg_statics_t *rst = 0;

	uint32_t       l_RAS0_u32;
	uint32_t       l_RAS1_u32;
	uint32_t       l_CAS0_u32;
	uint32_t       l_CAS1_u32;
	uint32_t       l_MemRfshCntl_u32;
	uint32_t       l_UsrCnfg_u32;
	uint32_t       l_DmCnfg_u32;

	uint32_t       l_MemArbWt_u32;
	uint32_t       l_MemRWArb_u32;
	uint32_t       l_MemBusCnfg_u32;

	auto_calib_t   l_ac_st;
	int32_t	       l_ac_i32;
	uint32_t       l_acerr_i32;
	uint32_t       sidx;
	uint32_t       i, j, t0, t1;

	/*
	 * set index for different 400/533/667 Mhz setup
	 */
	switch( SPEED ) {
		case 400:
		case 533:
		case 667: {
			sidx  = SPEED;
			sidx -= 400;
			sidx /= 133;
			break;
		}

		default: {
			#ifdef U4_DEBUG2
			printf( "\r\n-> DIMM speed of %03u not supported\r\n",
				m_gendimm.m_speed_pu32[m_dclidx_u32]  );
			#endif
			return RET_ERR;
		}

	}

	/*
	 * setup pointer to the static register settings
	 */
	if( IS_MAUI ) {
		rst = &reg_statics_maui[sidx];
	} else if( IS_BIMINI ) {
		rst = &reg_statics_bimini[sidx];
	} else if( IS_KAUAI ) {
		rst = &reg_statics_kauai[sidx];
	}

	/*
	 * Switch off Fast Path by default for all DIMMs
	 * running with more than 400Mhz
	 */
	if( SPEED == 400 ) {
		or32_ci( APIMemRdCfg_R, IBIT(30) );
		#ifdef U4_INFO
		printf( "  [fastpath        :        ON]\r\n" );
		#endif
	} else {
		and32_ci( APIMemRdCfg_R, ~IBIT(30) );
		#ifdef U4_INFO
		printf( "  [fastpath        :       OFF]\r\n" );
		#endif
	}


	#ifdef U4_INFO
	printf( "  [register setup  :          ]" );
	#endif

	/*
	 * setup RAS/CAS timers2
	 * NOTE: subtract TD from all values because of the delay
	 * caused by reloading timers (see spec)
	 */

	/*
	 * RAS Timer 0
	 */
	// TiAtP = RND(tRAS) -> RAS0[0:4]
	l_RAS0_u32  = ( ( RND( tRAS )                           - TD ) << 27 );
	// TiRtP = AL + BL/2 - 2 + RND(tRTP) -> RAS01[5:9]
	l_RAS0_u32 |= ( ( AL + BL/2 - 2 + RND( tRTP )           - TD ) << 22 );
	// TiWtP = WL + BL/2 + RND(tWR) -> RAS0[10:14]
	l_RAS0_u32 |= ( ( WL + BL/2 + RND( tWR )                - TD ) << 17 );
	// TiPtA = RND(tRP) -> RAS0[15:19]
	l_RAS0_u32 |= ( ( RND( tRP )                            - TD ) << 12 );
	// TiPAtA = RND(tRP) or
	//          RND(tRP) + 1 for 8 bank devices -> RAS0[20:24]
	if( m_gendimm.m_bankcnt_u32 <= 4 ) {
		l_RAS0_u32 |= ( ( RND( tRP )                    - TD ) <<  7 );
	} else {
		l_RAS0_u32 |= ( ( RND( tRP ) + 1                - TD ) <<  7 );
	}

	/*
	 * RAS Timer 1
	 */
	// TiRAPtA = AL + BL/2 - 2 + RND(tRTP + tRP) -> RAS1[0:4]
	l_RAS1_u32  = ( ( AL + BL/2 - 2 + RND( tRTP + tRP )     - TD ) << 27 );
	// TiWAPtA = CL + AL + BL/2 - 1 + RND(tWR + tRP) -> RAS1[5:9]
	l_RAS1_u32 |= ( ( CL + AL + BL/2 - 1 + RND( tWR + tRP ) - TD ) << 22 );
	// TiAtARk = tRRD -> RAS1[10:14]
	l_RAS1_u32 |= ( ( RND( tRRD )                           - TD ) << 17 );
	// TiAtABk = tRC -> RAS1[15:19]
	l_RAS1_u32 |= ( ( RND( tRC )                            - TD ) << 12 );
	// TiAtRW = tRCD -> RAS1[20:24]
	l_RAS1_u32 |= ( ( RND( tRCD )                           - TD ) <<  7 );
	// TiSAtARk Win = 4 * tRRD + 2 -> RAS1[25:29]
	l_RAS1_u32 |= ( ( RND( 4 * tRRD ) + 2                   - TD ) <<  2 );

	/*
	 * CAS Timer 0
	 */
	// TiRtRRk = BL/2 -> CAS0[0:4]
	l_CAS0_u32  = ( ( BL/2                                  - TD ) << 27 );
	// TiRtRDm = BL/2 + 1 -> CAS0[5:9]
	l_CAS0_u32 |= ( ( BL/2 + 1                              - TD ) << 22 );
	// TiRtRSy = BL/2 + RRMux -> CAS0[10:14]
	l_CAS0_u32 |= ( ( BL/2 + rst->RRMux                     - TD ) << 17 );
	// TiWtRRk = CL - 1 + BL/2 + tWTR ->CAS0[15:19]
	l_CAS0_u32 |= ( ( CL - 1 + BL/2 + RND( tWTR )           - TD ) << 12 );
	// TiWtRDm = BL/2 + 1 -> CAS0[20:24]
	l_CAS0_u32 |= ( ( BL/2 + 1                              - TD ) <<  7 );
	// TiWtRSy = BL/2 + WRMux -> CAS0[25:29]
	l_CAS0_u32 |= ( ( BL/2 + rst->WRMux                     - TD ) <<  2 );

	/*
	 * CAS Timer 1
	 */
	// TiWtWRk = BL/2 -> CAS1[0:4]
	l_CAS1_u32  = ( ( BL/2                                  - TD ) << 27 );
	// TiWtWDm = BL/2 + 1 -> CAS1[5:9]
	l_CAS1_u32 |= ( ( BL/2 + 1                              - TD ) << 22 );
	// TiWtWSy = BL/2 + WWMux -> CAS1[10:14]
	l_CAS1_u32 |= ( ( BL/2 + rst->WWMux                     - TD ) << 17 );
	// TiRtWRk = BL/2 + 2 -> CAS1[15:19]
 	l_CAS1_u32 |= ( ( BL/2 + 2            + rst->CAS1Dly0   - TD ) << 12 );
	// TiRtWDm = BL/2 + 2 -> CAS1[20:24]
	l_CAS1_u32 |= ( ( BL/2 + 2            + rst->CAS1Dly1   - TD ) <<  7 );
	// TiRtWSy = BL/2 + RWMux + 1 -> CAS1[25:29]
	l_CAS1_u32 |= ( ( BL/2 + rst->RWMux + 1                 - TD ) <<  2 );

	store32_ci( RASTimer0_R, l_RAS0_u32 );
	store32_ci( RASTimer1_R, l_RAS1_u32 );
	store32_ci( CASTimer0_R, l_CAS0_u32 );
	store32_ci( CASTimer1_R, l_CAS1_u32 );

	/*
	 * Mem Refresh Control register
	 */
	l_MemRfshCntl_u32  = ( ( ( tREF / tCK ) / 16 ) << 23 );
	l_MemRfshCntl_u32 |= ( ( RND( tRFC )    - TD ) <<  8 );
	store32_ci( MemRfshCntl_R, l_MemRfshCntl_u32 );

	/*
	 * setup DmXCnfg registers
	 */
	store32_ci( Dm0Cnfg_R, (uint32_t) 0x0 );
	store32_ci( Dm1Cnfg_R, (uint32_t) 0x0 );
	store32_ci( Dm2Cnfg_R, (uint32_t) 0x0 );
	store32_ci( Dm3Cnfg_R, (uint32_t) 0x0 );

	/*
	 * create DmCnfg & UsrCnfg values out of group data
	 */
	l_UsrCnfg_u32 = 0;
	for( i = 0; i < m_dgrcnt_u32; i++ ) {
		l_DmCnfg_u32  = ( m_dgrptr[i]->m_add2g_u32 << 27 );
		l_DmCnfg_u32 |= ( m_dgrptr[i]->m_sub2g_u32 << 19 );
		l_DmCnfg_u32 |= ( m_dgrptr[i]->m_memmd_u32 << 12 );
		l_DmCnfg_u32 |= ( m_dgrptr[i]->m_start_u32 <<  3 );
		l_DmCnfg_u32 |= ( m_dgrptr[i]->m_ss_u32    <<  1 );
		l_DmCnfg_u32 |= IBIT(31);	// enable bit

		/*
		 * write value into DmXCnfg registers
		 */
		for( j = 0; j < m_dgrptr[i]->m_dcnt_u32; j++ ) {
			t0 = m_dgrptr[i]->m_dptr[j]->m_bank_u32;
			t1 = Dm0Cnfg_R + 0x10 * t0;

			if( load32_ci( t1 ) == 0 ) {
				store32_ci( t1, l_DmCnfg_u32 );
				l_UsrCnfg_u32 |=
				( m_dgrptr[i]->m_csmode_u32 << ( 30 - 2 * t0 ) );
			}

		}

	}

	/*
	 * setup UsrCnfg register
	 *- cs mode is selected above
	 *- Interleave on L2 cache line
	 *- Usually closed page policy
	 */
	l_UsrCnfg_u32 |=  IBIT(8);	// interleave on L2 cache line
	l_UsrCnfg_u32 &= ~IBIT(9);	// usually closed
	l_UsrCnfg_u32 |=  IBIT(10);
	store32_ci( UsrCnfg_R, l_UsrCnfg_u32 );

	/*
	 * Memory Arbiter Weight Register
	 */
	// CohWt  -> MemAWt[0:1]
	l_MemArbWt_u32  = ( (uint32_t) 1 << 30 );
	// NCohWt -> MemAWt[2:3]
	l_MemArbWt_u32 |= ( (uint32_t) 1 << 28 );
	// ScrbWt -> MemAWt[4:5]
	l_MemArbWt_u32 |= ( (uint32_t) 0 << 26 );
	store32_ci( MemArbWt_R, l_MemArbWt_u32 );

	/*
	 * misc fixed register setup
	 */
	store32_ci( ODTCntl_R,        rst->ODTCntl );
	store32_ci( IOPadCntl_R,      rst->IOPadCntl );
	store32_ci( MemPhyModeCntl_R, rst->MemPhyModeCntl );
	store32_ci( OCDCalCntl_R,     rst->OCDCalCntl );
	store32_ci( OCDCalCmd_R,      rst->OCDCalCmd );

	/*
	 * CK Delay registers
	 */
	store32_ci( CKDelayL_R, rst->CKDelayL );
	store32_ci( CKDelayU_R, rst->CKDelayU );

	/*
	 * read/write strobe delays
	 */
	store32_ci( ByteWrClkDelC0B00_R, rst->ByteWrClkDel[ 0] );
	store32_ci( ByteWrClkDelC0B01_R, rst->ByteWrClkDel[ 1] );
	store32_ci( ByteWrClkDelC0B02_R, rst->ByteWrClkDel[ 2] );
	store32_ci( ByteWrClkDelC0B03_R, rst->ByteWrClkDel[ 3] );
	store32_ci( ByteWrClkDelC0B04_R, rst->ByteWrClkDel[ 4] );
	store32_ci( ByteWrClkDelC0B05_R, rst->ByteWrClkDel[ 5] );
	store32_ci( ByteWrClkDelC0B06_R, rst->ByteWrClkDel[ 6] );
	store32_ci( ByteWrClkDelC0B07_R, rst->ByteWrClkDel[ 7] );
	store32_ci( ByteWrClkDelC0B16_R, rst->ByteWrClkDel[16] );
	store32_ci( ByteWrClkDelC0B08_R, rst->ByteWrClkDel[ 8] );
	store32_ci( ByteWrClkDelC0B09_R, rst->ByteWrClkDel[ 9] );
	store32_ci( ByteWrClkDelC0B10_R, rst->ByteWrClkDel[10] );
	store32_ci( ByteWrClkDelC0B11_R, rst->ByteWrClkDel[11] );
	store32_ci( ByteWrClkDelC0B12_R, rst->ByteWrClkDel[12] );
	store32_ci( ByteWrClkDelC0B13_R, rst->ByteWrClkDel[13] );
	store32_ci( ByteWrClkDelC0B14_R, rst->ByteWrClkDel[14] );
	store32_ci( ByteWrClkDelC0B15_R, rst->ByteWrClkDel[15] );
	store32_ci( ByteWrClkDelC0B17_R, rst->ByteWrClkDel[17] );
	store32_ci( ReadStrobeDelC0B00_R, rst->ReadStrobeDel[ 0] );
	store32_ci( ReadStrobeDelC0B01_R, rst->ReadStrobeDel[ 1] );
	store32_ci( ReadStrobeDelC0B02_R, rst->ReadStrobeDel[ 2] );
	store32_ci( ReadStrobeDelC0B03_R, rst->ReadStrobeDel[ 3] );
	store32_ci( ReadStrobeDelC0B04_R, rst->ReadStrobeDel[ 4] );
	store32_ci( ReadStrobeDelC0B05_R, rst->ReadStrobeDel[ 5] );
	store32_ci( ReadStrobeDelC0B06_R, rst->ReadStrobeDel[ 6] );
	store32_ci( ReadStrobeDelC0B07_R, rst->ReadStrobeDel[ 7] );
	store32_ci( ReadStrobeDelC0B16_R, rst->ReadStrobeDel[16] );
	store32_ci( ReadStrobeDelC0B08_R, rst->ReadStrobeDel[ 8] );
	store32_ci( ReadStrobeDelC0B09_R, rst->ReadStrobeDel[ 9] );
	store32_ci( ReadStrobeDelC0B10_R, rst->ReadStrobeDel[10] );
	store32_ci( ReadStrobeDelC0B11_R, rst->ReadStrobeDel[11] );
	store32_ci( ReadStrobeDelC0B12_R, rst->ReadStrobeDel[12] );
	store32_ci( ReadStrobeDelC0B13_R, rst->ReadStrobeDel[13] );
	store32_ci( ReadStrobeDelC0B14_R, rst->ReadStrobeDel[14] );
	store32_ci( ReadStrobeDelC0B15_R, rst->ReadStrobeDel[15] );
	store32_ci( ReadStrobeDelC0B17_R, rst->ReadStrobeDel[17] );

	/*
	 * Mem Bus Configuration
	 * initial setup used in auto calibration
	 * final values will be written after
	 * auto calibration has finished
	 */
	l_MemBusCnfg_u32  = rst->MemBusCnfg;

/*	values calculation has been dropped, static values are used instead
	// WdbRqDly = 2 * (CL - 3) (registered DIMMs) -> MBC[16:19]
	l_MemBusCnfg_u32 += ( ( 2 * ( CL - 3 ) ) << 12 );
	// RdOEOnDly = 0 (typically)
	l_MemBusCnfg_u32 += ( ( 0 )              <<  8 );
	// RdOEOffDly = (2 * CL) - 4 -> MBC[24:27]
	// NOTE: formula is not working, changed to:
	// RdOEOffDly = (2 * CL) - 1
	l_MemBusCnfg_u32 += ( ( ( 2 * CL ) - 1 ) <<  4 );
*/

	store32_ci( MemBusCnfg_R, l_MemBusCnfg_u32 );
	store32_ci( MemBusCnfg2_R, rst->MemBusCnfg & (uint32_t) 0xf0000000 );

	/*
	 * reset verniers registers
	 */
	store32_ci( RstLdEnVerniersC0_R, 0x0 );
	store32_ci( RstLdEnVerniersC1_R, 0x0 );
	store32_ci( RstLdEnVerniersC2_R, 0x0 );
	store32_ci( RstLdEnVerniersC3_R, 0x0 );
	store32_ci( ExtMuxVernier0_R,    0x0 );
	store32_ci( ExtMuxVernier1_R,    0x0 );

	/*
	 * Queue Configuration
	 */
	store32_ci( MemRdQCnfg_R, rst->MemRdQCnfg );
	store32_ci( MemWrQCnfg_R, rst->MemWrQCnfg );
	store32_ci( MemQArb_R,    rst->MemQArb );
	store32_ci( MemRWArb_R,   rst->MemRWArb );

	#ifdef U4_INFO
	printf( "\b\b\bOK\r\n" );
	#endif

	/*
	 * start up clocks & wait for pll2 to stabilize
	 */
	#ifdef U4_INFO
	printf( "  [start DDR clock :          ]" );
	#endif

	store32_ci( MemModeCntl_R, IBIT(0) | IBIT(8) );
	dly( 50000000 );

	#ifdef U4_INFO
	printf( "\b\b\bOK\r\n" );

	#endif

	/*
	 * memory initialization sequence
	 */
	#ifdef U4_INFO
	printf( "  [memory init     :          ]" );
	#endif
	u4_MemInitSequence( tRP, tWR, tRFC, CL, tCK, TD );
	#ifdef U4_INFO
	printf( "\b\b\bOK\r\n" );
	#endif

	/*
	 * start ECC before auto calibration to enable ECC bytelane
	 */
	store32_ci( MCCR_R, IBIT(0) );
	dly( 15000000 );

	/*
	 * start up auto calibration
	 */
	#ifdef U4_INFO
	printf( "  [auto calibration:          ]\b" );
	#endif

	/*
	 * start auto calibration
	*/
	l_acerr_i32 = 0;
	do {
		progbar();

		l_ac_i32 = u4_auto_calib( &l_ac_st );

		if( l_ac_i32 != 0 ) {
			l_acerr_i32++;
		}

		dly( 15000000 );
	} while( ( l_ac_i32    != 0             ) &&
		 ( l_acerr_i32 <= MAX_ACERR     ) );

	if( l_acerr_i32 > MAX_ACERR ) {
		#ifdef U4_INFO
		printf( "\b\b\bERR\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * insert auto calibration results
	 */
	store32_ci( MemBusCnfg_R,  	 l_ac_st.m_MemBusCnfg_u32 );
	store32_ci( MemBusCnfg2_R, 	 l_ac_st.m_MemBusCnfg2_u32 );
	store32_ci( RstLdEnVerniersC0_R, l_ac_st.m_RstLdEnVerniers_pu32[0] );
	store32_ci( RstLdEnVerniersC1_R, l_ac_st.m_RstLdEnVerniers_pu32[1] );
	store32_ci( RstLdEnVerniersC2_R, l_ac_st.m_RstLdEnVerniers_pu32[2] );
	store32_ci( RstLdEnVerniersC3_R, l_ac_st.m_RstLdEnVerniers_pu32[3] );

	/*
	 * insert final timing value into MemRWArb
	 */
	l_MemRWArb_u32  = ( ( l_ac_st.m_MemBusCnfg_u32 >> 28 /*RdMacDel*/) + 1 );
	l_MemRWArb_u32 *= 10;	// needed for rounding
	l_MemRWArb_u32 /= 2;	// due to spec
	l_MemRWArb_u32 += 9;	// round up
	l_MemRWArb_u32 /= 10;	// value is rounded now
	l_MemRWArb_u32  = l_MemRWArb_u32 + 6 - WL - TD;
	l_MemRWArb_u32 |= rst->MemRWArb;
	store32_ci( MemRWArb_R, l_MemRWArb_u32 );

	progbar();
	dly( 15000000 );

	/*
	 * do initial scrubbing
	 */
	*f_ecc_pt = u4_InitialScrub();

	switch( f_ecc_pt->m_err_i32 ) {
		case  RET_OK: {
			#ifdef U4_INFO
			printf( "\b\bOK\r\n" );
			#endif
			break;
		}

		case RET_ACERR_CE: {
			#ifdef U4_INFO
			printf( "\b\b\b\bWEAK][correctable errors during scrub (%u)]\r\n",
				f_ecc_pt->m_cecnt_u32 );
			#endif
			break;
		}

		case RET_ACERR_UEWT:
		case RET_ACERR_UE: {
			#ifdef U4_INFO
			printf( "\b\b\bERR][uncorrectable errors during scrub (%u)]\r\n",
				f_ecc_pt->m_uecnt_u32 );
			#endif
			return RET_ACERR_UE;
		}

	}

	/*
	 * start continuous background scrub
	 */
	#ifdef U4_INFO
	printf( "  [background scrub:          ]" );
	#endif

	u4_Scrub( BACKGROUND_SCRUB, 0, NULL );

	#ifdef U4_INFO
	printf( "\b\b\bOK\r\n" );
	#endif

	/*
	 * finally clear API Exception register
	 * (read to clear)
	 */
	load32_ci( APIExcp_R );

	return RET_OK;
}

#undef RND

#if 0
void
u4_memtest(uint8_t argCnt, char *pArgs[], uint64_t flags)
{
	#define TEND			99
	#define TCHK			100
	static const uint64_t _2GB   = (uint64_t) 0x80000000;
	static const uint64_t _start = (uint64_t) 0x08000000;	// 128Mb
	static const uint64_t _bsize = (uint64_t) 0x08000000;	// 128MB
	static const uint64_t _line  = (uint64_t) 128;
	static const uint64_t _256MB = (uint64_t) 0x10000000;

	static const uint64_t PATTERN[] = {
		0x9090909090909090, 0x0020002000200020,
		0x0c0c0c0c0c0c0c0c, 0x8080808080808080,
		0x1004010004001041, 0x0000000000000000
	};

     	uint64_t mend      = (uint64_t) 0x200000000;//m_memsize_u64;
	uint64_t numblocks = ( mend - _start ) / _bsize;	// 128Mb blocks
	uint64_t numlines  = _bsize / _line;
	uint64_t tstate    = 0;
	uint64_t tlast     = 0;
	uint64_t pidx      = 0;
	uint64_t rotr      = 0;
	uint64_t rotl      = 0;
	uint64_t block;
	uint64_t line;
	uint64_t addr;
	uint64_t i;
	uint64_t check = 0;
	uint64_t dcnt;
	uint64_t uerr = 0;
	uint64_t cerr = 0;
	uint64_t merr = 0;
	char     c;

	printf( "\n\nU4 memory test" );
	printf( "\n--------------" );

	/*
	 * mask out UEC & CEC
	 */
	or32_ci( MCCR_R, IBIT(6) | IBIT(7) );

	while( PATTERN[pidx] ) {

		switch( tstate )
		{
		case 0: {
			printf( "\npattern fill 0x%08X%08X: ", (uint32_t) (PATTERN[pidx] >> 32), (uint32_t) PATTERN[pidx] );

			/*
			 * first switch lines, then blocks. This way the CPU
			 * is not able to cache data
			 */
			for( line = 0, dcnt = 0; line < numlines; line++ ) {

				for( block = 0; block < numblocks; block++ ) {

					for( i = 0; i < _line; i += 8 ) {
						addr =  _start +
							( block * _bsize ) +
							( line * _line )   +
							i;

						if( addr >= _2GB ) {
							addr += _2GB;
						}

						*( (uint64_t *) addr ) = PATTERN[pidx];

						/*
						 * print out a dot every 256Mb
						 */
						dcnt += 8;
						if( dcnt == _256MB ) {
							dcnt = 0;
							printf( "*" );

							if( io_getchar( &c ) ) {
								goto mtend;
							}

						}

					}

				}

			}

			check  = PATTERN[pidx];
			tlast  = 0;
			tstate = TCHK;
		} 	break;

		case 1: {
			uint64_t one;

			/*
			 * new check pattern

			 */
			one     = ( ( check & 0x1 ) != 0 );
			check >>= 1;
			if( one ) {
				check |= 0x8000000000000000;
			}

			printf( "\nrotate right 0x%08X%08X: ", (uint32_t) (check >> 32), (uint32_t) check );

			/*
			 * first switch lines, then blocks. This way the CPU
			 * is not able to cache data
			 */
			for( line = 0, dcnt = 0; line < numlines; line++ ) {

				for( block = 0; block < numblocks; block++ ) {

					for( i = 0; i < _line; i += 8 ) {
						addr =  _start +
							( block * _bsize ) +
							( line * _line )   +
							i;

						if( addr >= _2GB ) {
							addr += _2GB;
						}

						*( (uint64_t *) addr ) >>= 1;

						if( one ) {
							*( (uint64_t *) addr ) |=
								(uint64_t) 0x8000000000000000;
						}

						/*
						 * print out a dot every 256Mb
						 */
						dcnt += 8;
						if( dcnt == _256MB ) {
							dcnt = 0;
							printf( "*" );

							if( io_getchar( &c ) ) {
								goto mtend;
							}

						}

					}

				}

			}

			tlast  = 1;
			tstate = TCHK;
		}	break;

		case 2: {

			if( rotr < 6 ) {
				rotr++;
				tstate = 1;
			} else {
				rotr   = 0;
				tstate = 3;
			}

		}	break;

		case 3: {
			/*
			 * new check pattern
			 */
			check ^= (uint64_t) ~0;

			printf( "\ninverting    0x%08X%08X: ", (uint32_t) (check >> 32), (uint32_t) check );

			/*
			 * first switch lines, then blocks. This way the CPU
			 * is not able to cache data
			 */
			for( line = 0, dcnt = 0; line < numlines; line++ ) {

				for( block = 0; block < numblocks; block++ ) {

					for( i = 0; i < _line; i += 8 ) {
						addr =  _start +
							( block * _bsize ) +
							( line * _line )   +
							i;

						if( addr >= _2GB ) {
							addr += _2GB;
						}

						*( (uint64_t *) addr ) ^= (uint64_t) ~0;

						/*
						 * print out a dot every 256Mb
						 */
						dcnt += 8;
						if( dcnt == _256MB ) {
							dcnt = 0;
							printf( "*" );

							if( io_getchar( &c ) ) {
								goto mtend;
							}

						}

					}

				}

			}

			tlast  = 3;
			tstate = TCHK;
		}	break;

		case 4: {
			uint64_t one;

			/*
			 * new check pattern
			 */
			one     = ( ( check & 0x8000000000000000 ) != 0 );
			check <<= 1;
			if( one ) {
				check |= 0x1;
			}

			printf( "\nrotate left  0x%08X%08X: ", (uint32_t) (check >> 32), (uint32_t) check );

			/*
			 * first switch lines, then blocks. This way the CPU
			 * is not able to cache data
			 */
			for( line = 0, dcnt = 0; line < numlines; line++ ) {

				for( block = 0; block < numblocks; block++ ) {

					for( i = 0; i < _line; i += 8 ) {
						addr =  _start +
							( block * _bsize ) +
							( line * _line )   +
							i;

						if( addr >= _2GB ) {
							addr += _2GB;
						}

						*( (uint64_t *) addr ) <<= 1;

						if( one ) {
							*( (uint64_t *) addr ) |=
								(uint64_t) 0x1;
						}

						/*
						 * print out a dot every 256Mb
						 */
						dcnt += 8;
						if( dcnt == _256MB ) {
							dcnt = 0;
							printf( "*" );

							if( io_getchar( &c ) ) {
								goto mtend;
							}

						}

					}

				}

			}

			tlast  = 4;
			tstate = TCHK;
		}	break;

		case 5: {

			if( rotl < 6 ) {
				rotl++;
				tstate = 4;
			} else {
				rotl   = 0;
				tstate = 6;
			}

		}	break;

		case 6: {
			/*
			 * new check pattern
			 */
			check *= ~check;
			printf( "\nmultiply     0x%08X%08X: ", (uint32_t) (check >> 32), (uint32_t) check );

			/*
			 * first switch lines, then blocks. This way the CPU
			 * is not able to cache data
			 */
			for( line = 0, dcnt = 0; line < numlines; line++ ) {

				for( block = 0; block < numblocks; block++ ) {

					for( i = 0; i < _line; i += 8 ) {
						addr =  _start +
							( block * _bsize ) +
							( line * _line )   +
							i;

						if( addr >= _2GB ) {
							addr += _2GB;
						}

						*( (uint64_t *) addr ) *= ~( *( (uint64_t *) addr ) );

						/*
						 * print out a dot every 256Mb
						 */
						dcnt += 8;
						if( dcnt == _256MB ) {
							dcnt = 0;
							printf( "*" );

							if( io_getchar( &c ) ) {
								goto mtend;
							}

						}

					}

				}

			}

			tlast  = TEND - 1;
			tstate = TCHK;
		}	break;

		case TEND: {
			pidx++;
			tstate = 0;
		}	break;

		case TCHK: {
			uint64_t err;
			/*
			 * check data
			 */
			printf( "\nchecking                       : " );

			for( line = 0, dcnt = 0; line < numlines; line++ ) {

				for( block = 0; block < numblocks; block++ ) {

					for( i = 0; i < _line; i += 8 ) {
						addr =  _start +
							( block * _bsize ) +
							( line * _line )   +
							i;

						if( addr >= _2GB ) {
							addr += _2GB;
						}

						err = ( *( (uint64_t *) addr ) != check );

						if( err ) {
							merr++;
						}

						/*
						 * print out a dot every 256Mb
						 */
						dcnt += 8;
						if( dcnt == _256MB ) {
							dcnt = 0;

							if( err ) {
								printf( "X" );
							} else {
								printf( "*" );
							}

							if( io_getchar( &c ) ) {
								goto mtend;
							}

						}

					}

				}

			}

			err   = (uint64_t) load32_ci( MEAR1_R );
			uerr += ( err >> 24 ) & (uint64_t) 0xff;
			cerr += ( err >> 16 ) & (uint64_t) 0xff;

			printf( " (UE: %02llX, CE: %02llX)", ( err >> 24 ) & (uint64_t) 0xff, ( err >> 16 ) & (uint64_t) 0xff );

			tstate = tlast + 1;
			tlast  = TCHK;
		} 	break;

		}

	}

mtend:
	printf( "\n\nmemory test results" );
	printf( "\n-------------------" );
	printf( "\nuncorrectable errors: %u", (uint32_t) uerr );
	printf( "\ncorrectable errors  : %u", (uint32_t) cerr );
	printf( "\nread/write errors   : %u\n", (uint32_t) merr );

	and32_ci( MCCR_R, ~( IBIT(6) | IBIT(7) ) );
}
#endif

#if 0
void
u4_dump(uint8_t argCnt, char *pArgs[], uint64_t flags)
{
	printf( "\r\n*** u4 register dump ***\r\n\n" );
	printf( "register      (offset): value\r\n" );
	printf( "----------------------------------\r\n" );
	printf( "Clock Control (0x%04X): 0x%08X\r\n", (uint16_t) ClkCntl_R, load32_ci( ClkCntl_R ) );
	printf( "PLL2 Control  (0x%04X): 0x%08X\r\n", (uint16_t) PLL2Cntl_R, load32_ci( PLL2Cntl_R ) );
	printf( "MemModeCntl   (0x%04X): 0x%08X\r\n", (uint16_t) MemModeCntl_R, load32_ci( MemModeCntl_R ) );
	printf( "RASTimer0     (0x%04X): 0x%08X\r\n", (uint16_t) RASTimer0_R, load32_ci( RASTimer0_R ) );
	printf( "RASTimer1     (0x%04X): 0x%08X\r\n", (uint16_t) RASTimer1_R, load32_ci( RASTimer1_R ) );
	printf( "CASTimer0     (0x%04X): 0x%08X\r\n", (uint16_t) CASTimer0_R, load32_ci( CASTimer0_R ) );
	printf( "CASTimer1     (0x%04X): 0x%08X\r\n", (uint16_t) CASTimer1_R, load32_ci( CASTimer1_R ) );
	printf( "MemRfshCntl   (0x%04X): 0x%08X\r\n", (uint16_t) MemRfshCntl_R, load32_ci( MemRfshCntl_R ) );
	printf( "Dm0Cnfg       (0x%04X): 0x%08X\r\n", (uint16_t) Dm0Cnfg_R, load32_ci( Dm0Cnfg_R ) );
	printf( "Dm1Cnfg       (0x%04X): 0x%08X\r\n", (uint16_t) Dm1Cnfg_R, load32_ci( Dm1Cnfg_R ) );
	printf( "Dm2Cnfg       (0x%04X): 0x%08X\r\n", (uint16_t) Dm2Cnfg_R, load32_ci( Dm2Cnfg_R ) );
	printf( "Dm3Cnfg       (0x%04X): 0x%08X\r\n", (uint16_t) Dm3Cnfg_R, load32_ci( Dm3Cnfg_R ) );
	printf( "UsrCnfg       (0x%04X): 0x%08X\r\n", (uint16_t) UsrCnfg_R, load32_ci( UsrCnfg_R ) );
	printf( "MemArbWt      (0x%04X): 0x%08X\r\n", (uint16_t) MemArbWt_R, load32_ci( MemArbWt_R ) );
	printf( "ODTCntl       (0x%04X): 0x%08X\r\n", (uint16_t) ODTCntl_R, load32_ci( ODTCntl_R ) );
	printf( "IOPadCntl     (0x%04X): 0x%08X\r\n", (uint16_t) IOPadCntl_R, load32_ci( IOPadCntl_R ) );
	printf( "MemPhyMode    (0x%04X): 0x%08X\r\n", (uint16_t) MemPhyModeCntl_R, load32_ci( MemPhyModeCntl_R ) );
	printf( "OCDCalCntl    (0x%04X): 0x%08X\r\n", (uint16_t) OCDCalCntl_R, load32_ci( OCDCalCntl_R ) );
	printf( "OCDCalCmd     (0x%04X): 0x%08X\r\n", (uint16_t) OCDCalCmd_R, load32_ci( OCDCalCmd_R ) );
	printf( "CKDelayL      (0x%04X): 0x%08X\r\n", (uint16_t) CKDelayL_R, load32_ci( CKDelayL_R ) );
	printf( "CKDelayH      (0x%04X): 0x%08X\r\n", (uint16_t) CKDelayU_R, load32_ci( CKDelayU_R ) );
	printf( "MemBusCnfg    (0x%04X): 0x%08X\r\n", (uint16_t) MemBusCnfg_R, load32_ci( MemBusCnfg_R ) );
	printf( "MemBusCnfg2   (0x%04X): 0x%08X\r\n", (uint16_t) MemBusCnfg2_R, load32_ci( MemBusCnfg2_R ) );
	printf( "MemRdQCnfg    (0x%04X): 0x%08X\r\n", (uint16_t) MemRdQCnfg_R, load32_ci( MemRdQCnfg_R ) );
	printf( "MemWrQCnfg    (0x%04X): 0x%08X\r\n", (uint16_t) MemWrQCnfg_R, load32_ci( MemWrQCnfg_R ) );
	printf( "MemQArb       (0x%04X): 0x%08X\r\n", (uint16_t) MemQArb_R, load32_ci( MemQArb_R ) );
	printf( "MemRWArb      (0x%04X): 0x%08X\r\n", (uint16_t) MemRWArb_R, load32_ci( MemRWArb_R ) );
	printf( "ByteWrClkDel  (0x%04X): 0x%08X\r\n", (uint16_t) ByteWrClkDelC0B00_R, load32_ci( ByteWrClkDelC0B00_R ) );
	printf( "ReadStrobeDel (0x%04X): 0x%08X\r\n", (uint16_t) ReadStrobeDelC0B00_R, load32_ci( ReadStrobeDelC0B00_R ) );
	printf( "RstLdEnVerC0  (0x%04X): 0x%08X\r\n", (uint16_t) RstLdEnVerniersC0_R, load32_ci( RstLdEnVerniersC0_R ) );
	printf( "RstLdEnVerC1  (0x%04X): 0x%08X\r\n", (uint16_t) RstLdEnVerniersC1_R, load32_ci( RstLdEnVerniersC1_R ) );
	printf( "RstLdEnVerC2  (0x%04X): 0x%08X\r\n", (uint16_t) RstLdEnVerniersC2_R, load32_ci( RstLdEnVerniersC2_R ) );
	printf( "RstLdEnVerC3  (0x%04X): 0x%08X\r\n", (uint16_t) RstLdEnVerniersC3_R, load32_ci( RstLdEnVerniersC3_R ) );
	printf( "APIMemRdCfg   (0x%04X): 0x%08X\r\n", (uint16_t) APIMemRdCfg_R, load32_ci( APIMemRdCfg_R ) );
	printf( "scrub start   (0x%04X): 0x%08X\r\n", (uint16_t) MSRSR_R, load32_ci( MSRSR_R ) );
	printf( "scrub end     (0x%04X): 0x%08X\r\n", (uint16_t) MSRER_R, load32_ci( MSRER_R ) );
}
#endif

static int32_t
u4_memBegin( eccerror_t *f_ecc_pt )
{
	int32_t i;

	#ifdef U4_INFO
	printf( "\r\n" );
	printf( "U4 DDR2 memory controller setup V%u.%u\r\n",
		VER, SUBVER );
	printf( "------------------------------------\r\n" );
	printf( "> detected board              : " );

	if( IS_MAUI ) {
		printf( "MAUI" );
	} else if( IS_BIMINI ) {
		printf( "BIMINI" );
	} else if( IS_KAUAI ) {
		printf( "KAUAI" );
	} else {
		printf( "unknown!" );
		return RET_ERR;
	}
	#endif

	do {
		/*
		 * initialize variables
		 */
		m_memsize_u64    = 0;
		m_dcnt_u32       = 0;
		m_dgrcnt_u32     = 0;
		m_dclidx_u32     = 0;

		for( i = 0; i < NUM_SLOTS; i++ ) {
			m_dptr[i] = NULL;
			memset( ( void * ) &m_dimm[i], 0, sizeof( dimm_t ) );
		}

		for( i = 0; i < MAX_DGROUPS; i++ ) {
			m_dgrptr[i] = NULL;
			memset( ( void * ) &m_dgroup[i], 0, sizeof( dimm_t ) );
		}

		/*
		 * start configuration
		 */
		#ifdef U4_INFO
		printf( "\r\n> detected DIMM configuration : " );
		#endif

		i = ddr2_readSPDs();

		if( i != RET_OK ) {
			#ifdef U4_INFO
			printf( "\r\n-------------------------------------------------------------" );
			printf( "\r\n  switching off memory bank(s) due to SPD integrity failure" );
			printf( "\r\n-------------------------------------------------------------\r\n" );
			#endif
		}

	} while( i != RET_OK );

	/*
	 * check DIMM configuration
	 */
	if( ddr2_setupDIMMcfg() != RET_OK ) {
		#ifdef U4_INFO
		printf( "> initialization failure.\r\n" );
		#endif
		return RET_ERR;
	}

	/*
	 * create DIMM groups
	 */
	u4_setupDIMMgroups();

	/*
	 * start configuration of u4
	 */
	u4_calcDIMMcnfg();

	if( u4_calcDIMMmemmode() != RET_OK ) {
		#ifdef U4_INFO
		printf( "> initialization failure.\r\n" );
		#endif
		return RET_ERR;
	}

	#ifdef U4_INFO
	printf( "%uMb @ %uMhz, CL %u\r\n",
		(uint32_t) ( m_memsize_u64 / 0x100000 ),
		m_gendimm.m_speed_pu32[m_dclidx_u32],
		m_gendimm.m_clval_pu32[m_dclidx_u32] );

	printf( "> initializing memory         :\r\n" );
	#endif

	if( u4_setup_core_clock() != RET_OK ) {
		#ifdef U4_INFO
		printf( "> initialization failure.\r\n" );
		#endif
		return RET_ERR;
	}

	i = u4_start( f_ecc_pt );
	if( i != RET_OK ) {
		#ifdef U4_INFO
		printf( "> initialization failure.\r\n" );
		#endif
		return i;
	}

	#ifdef U4_INFO
	printf( "  [flush cache     :          ]" );
	#endif

	flush_cache( 0x0, L2_CACHE_SIZE );

	#ifdef U4_INFO
	printf( "\b\b\bOK\r\n" );
	printf( "> initialization complete.\r\n" );
	#endif

#ifdef U4_SHOW_REGS
	u4_dump(0,0,0);
#endif

	return RET_OK;
}


#if 0
static int32_t scrubstarted = 0;
void
u4_scrubStart(uint8_t argCnt, char *pArgs[], uint64_t flags )
{
	scrubstarted = 1;

	/*
	 * setup scrub parameters
	 */
	store32_ci( MSCR_R, 0 );			// stop scrub
	store32_ci( MSRSR_R, 0x0 );			// set start
	store32_ci( MSRER_R, 0x1c );			// set end
	store32_ci( MSPR_R, 0x0 );			// set pattern

	/*
	 * clear out ECC error registers
	 */
	store32_ci( MEAR0_R, 0x0 );
	store32_ci( MEAR1_R, 0x0 );
	store32_ci( MESR_R, 0x0 );

	/*
	 * Setup Scrub Type
	 */
	store32_ci( MSCR_R, IBIT(1) );
	printf( "\r\nscrub started\r\n" );
}
#endif

#if 0
void
u4_scrubEnd(uint8_t argCnt, char *pArgs[], uint64_t flags )
{
	store32_ci( MSCR_R, 0 );			// stop scrub
	scrubstarted = 0;
	printf( "\r\nscrub stopped\r\n" );
}
#endif

#if 0
void
u4_memwr(uint8_t argCnt, char *pArgs[], uint64_t flags )
{
	uint32_t i;
	uint32_t v = 0;

	for( i = 0; i < 0x200; i += 4 ) {

		if( ( i & 0xf ) == 0 ) {
			v = ~v;
		}

		store32_ci( i, v );
	}

}
#endif

void
u4memInit()
{
	static uint32_t l_isInit_u32 = 0;
	eccerror_t	l_ecc_t;
	int32_t		ret;

	/*
	 * do not initialize memory more than once
	 */
	if( l_isInit_u32 ) {
		#ifdef U4_INFO
		printf( "\r\n\nmemory already initialized\r\n" );
		#endif
		return;
	} else {
		l_isInit_u32 = 1;
	}

	/*
	 * enable all DIMM banks on first run
	 */
	m_bankoff_u32 = 0;

	do {
		ret = u4_memBegin( &l_ecc_t );

		if( ret < RET_ERR ) {
			uint32_t l_bank_u32 = l_ecc_t.m_rank_u32 / 2;
			printf( "\r\n-----------------------------------------------------" );
			printf( "\r\n  switching off memory bank %u due to memory failure", l_bank_u32 );
			printf( "\r\n-----------------------------------------------------" );
			m_bankoff_u32 |= ( 1 << l_bank_u32 );
		}

	} while( ret < RET_ERR );

}
