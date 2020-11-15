/* src/include/wlan/wlan_compat.h
*
* Types and macros to aid in portability
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*/

FILE_LICENCE ( GPL2_ONLY );

#ifndef _WLAN_COMPAT_H
#define _WLAN_COMPAT_H

/*=============================================================*/
/*------ Establish Platform Identity --------------------------*/
/*=============================================================*/
/* Key macros: */
/* WLAN_CPU_FAMILY */
	#define WLAN_Ix86			1
	#define WLAN_PPC			2
	#define WLAN_Ix96			3
	#define WLAN_ARM			4
	#define WLAN_ALPHA			5
	#define WLAN_MIPS			6
	#define WLAN_HPPA			7
/* WLAN_CPU_CORE */
	#define WLAN_I386CORE			1
	#define WLAN_PPCCORE			2
	#define WLAN_I296			3
	#define WLAN_ARMCORE			4
	#define WLAN_ALPHACORE			5
	#define WLAN_MIPSCORE			6
	#define WLAN_HPPACORE			7
/* WLAN_CPU_PART */
	#define WLAN_I386PART			1
	#define WLAN_MPC860			2
	#define WLAN_MPC823			3
	#define WLAN_I296SA			4
	#define WLAN_PPCPART			5
	#define WLAN_ARMPART			6
	#define WLAN_ALPHAPART			7
	#define WLAN_MIPSPART			8
	#define WLAN_HPPAPART			9
/* WLAN_SYSARCH */
	#define WLAN_PCAT			1
	#define WLAN_MBX			2
	#define WLAN_RPX			3
	#define WLAN_LWARCH			4
	#define WLAN_PMAC			5
	#define WLAN_SKIFF			6
	#define WLAN_BITSY			7
	#define WLAN_ALPHAARCH			7
	#define WLAN_MIPSARCH			9
	#define WLAN_HPPAARCH			10
/* WLAN_OS */
	#define WLAN_LINUX_KERNEL		1
	#define WLAN_LINUX_USER			2
/* WLAN_HOSTIF (generally set on the command line, not detected) */
	#define WLAN_PCMCIA			1
	#define WLAN_ISA			2
	#define WLAN_PCI			3
	#define WLAN_USB			4
	#define WLAN_PLX			5

/* Note: the PLX HOSTIF above refers to some vendors implementations for */
/*       PCI.  It's a PLX chip that is a PCI to PCMCIA adapter, but it   */
/*       isn't a real PCMCIA host interface adapter providing all the    */
/*       card&socket services.                                           */

/* Lets try to figure out what we've got.  Kernel mode or User mode? */
#if defined(__KERNEL__)
	#define WLAN_OS				WLAN_LINUX_KERNEL
#else
	#define WLAN_OS				WLAN_LINUX_USER
#endif

#ifdef __powerpc__
#ifndef __ppc__
#define __ppc__
#endif
#endif

#if (defined(CONFIG_PPC) || defined(CONFIG_8xx))
#ifndef __ppc__
#define __ppc__
#endif
#endif

#if defined(__KERNEL__)
#if defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
	#define WLAN_CPU_FAMILY		WLAN_Ix86
	#define WLAN_CPU_CORE		WLAN_I386CORE
	#define WLAN_CPU_PART		WLAN_I386PART
	#define WLAN_SYSARCH		WLAN_PCAT
#elif defined(__ppc__)
	#define WLAN_CPU_FAMILY		WLAN_PPC
	#define WLAN_CPU_CORE		WLAN_PPCCORE
	#if defined(CONFIG_MBX)
		#define WLAN_CPU_PART	WLAN_MPC860
		#define WLAN_SYSARCH	WLAN_MBX
	#elif defined(CONFIG_RPXLITE)
		#define WLAN_CPU_PART	WLAN_MPC823
		#define WLAN_SYSARCH	WLAN_RPX
	#elif defined(CONFIG_RPXCLASSIC)
		#define WLAN_CPU_PART	WLAN_MPC860
		#define WLAN_SYSARCH	WLAN_RPX
	#else
		#define WLAN_CPU_PART	WLAN_PPCPART
		#define WLAN_SYSARCH	WLAN_PMAC
	#endif
#elif defined(__arm__)
	#define WLAN_CPU_FAMILY		WLAN_ARM
	#define WLAN_CPU_CORE		WLAN_ARMCORE
        #define WLAN_CPU_PART		WLAN_ARM_PART
	#define WLAN_SYSARCH		WLAN_SKIFF
#elif defined(__alpha__)
	#define WLAN_CPU_FAMILY		WLAN_ALPHA
	#define WLAN_CPU_CORE		WLAN_ALPHACORE
	#define WLAN_CPU_PART		WLAN_ALPHAPART
	#define WLAN_SYSARCH		WLAN_ALPHAARCH
#elif defined(__mips__)
	#define WLAN_CPU_FAMILY		WLAN_MIPS
	#define WLAN_CPU_CORE		WLAN_MIPSCORE
        #define WLAN_CPU_PART		WLAN_MIPSPART
	#define WLAN_SYSARCH		WLAN_MIPSARCH
#elif defined(__hppa__)
	#define WLAN_CPU_FAMILY		WLAN_HPPA
	#define WLAN_CPU_CORE		WLAN_HPPACORE
	#define WLAN_CPU_PART		WLAN_HPPAPART
	#define WLAN_SYSARCH		WLAN_HPPAARCH
#else
	#error "No CPU identified!"
#endif
#endif /* __KERNEL__ */

/*
   Some big endian machines implicitly do all I/O in little endian mode.

   In particular:
          Linux/PPC on PowerMacs (PCI)
	  Arm/Intel Xscale (PCI)

   This may also affect PLX boards and other BE &| PPC platforms;
   as new ones are discovered, add them below.
*/

#if (WLAN_HOSTIF == WLAN_PCI)
#if ((WLAN_SYSARCH == WLAN_SKIFF) || (WLAN_SYSARCH == WLAN_PMAC))
#define REVERSE_ENDIAN
#endif
#endif

/*=============================================================*/
/*------ Bit settings -----------------------------------------*/
/*=============================================================*/

#define BIT0	0x00000001
#define BIT1	0x00000002
#define BIT2	0x00000004
#define BIT3	0x00000008
#define BIT4	0x00000010
#define BIT5	0x00000020
#define BIT6	0x00000040
#define BIT7	0x00000080
#define BIT8	0x00000100
#define BIT9	0x00000200
#define BIT10	0x00000400
#define BIT11	0x00000800
#define BIT12	0x00001000
#define BIT13	0x00002000
#define BIT14	0x00004000
#define BIT15	0x00008000
#define BIT16	0x00010000
#define BIT17	0x00020000
#define BIT18	0x00040000
#define BIT19	0x00080000
#define BIT20	0x00100000
#define BIT21	0x00200000
#define BIT22	0x00400000
#define BIT23	0x00800000
#define BIT24	0x01000000
#define BIT25	0x02000000
#define BIT26	0x04000000
#define BIT27	0x08000000
#define BIT28	0x10000000
#define BIT29	0x20000000
#define BIT30	0x40000000
#define BIT31	0x80000000

/*=============================================================*/
/*------ Compiler Portability Macros --------------------------*/
/*=============================================================*/
#define __WLAN_ATTRIB_PACK__		__attribute__ ((packed))
#define __WLAN_PRAGMA_PACK1__
#define __WLAN_PRAGMA_PACKDFLT__
#define __WLAN_INLINE__			inline
#define WLAN_MIN_ARRAY			0

/*=============================================================*/
/*------ OS Portability Macros --------------------------------*/
/*=============================================================*/

#ifndef WLAN_DBVAR
#define WLAN_DBVAR	wlan_debug
#endif

#if (WLAN_OS == WLAN_LINUX_KERNEL)
	#define WLAN_LOG_ERROR0(x) printk(KERN_ERR "%s: " x , __FUNCTION__ );
	#define WLAN_LOG_ERROR1(x,n) printk(KERN_ERR "%s: " x , __FUNCTION__ , (n));
	#define WLAN_LOG_ERROR2(x,n1,n2) printk(KERN_ERR "%s: " x , __FUNCTION__ , (n1), (n2));
	#define WLAN_LOG_ERROR3(x,n1,n2,n3) printk(KERN_ERR "%s: " x , __FUNCTION__, (n1), (n2), (n3));
	#define WLAN_LOG_ERROR4(x,n1,n2,n3,n4) printk(KERN_ERR "%s: " x , __FUNCTION__, (n1), (n2), (n3), (n4));

	#define WLAN_LOG_WARNING0(x) printk(KERN_WARNING "%s: " x , __FUNCTION__);
	#define WLAN_LOG_WARNING1(x,n) printk(KERN_WARNING "%s: " x , __FUNCTION__, (n));
	#define WLAN_LOG_WARNING2(x,n1,n2) printk(KERN_WARNING "%s: " x , __FUNCTION__, (n1), (n2));
	#define WLAN_LOG_WARNING3(x,n1,n2,n3) printk(KERN_WARNING "%s: " x , __FUNCTION__, (n1), (n2), (n3));
	#define WLAN_LOG_WARNING4(x,n1,n2,n3,n4) printk(KERN_WARNING "%s: " x , __FUNCTION__ , (n1), (n2), (n3), (n4));

	#define WLAN_LOG_NOTICE0(x) printk(KERN_NOTICE "%s: " x , __FUNCTION__);
	#define WLAN_LOG_NOTICE1(x,n) printk(KERN_NOTICE "%s: " x , __FUNCTION__, (n));
	#define WLAN_LOG_NOTICE2(x,n1,n2) printk(KERN_NOTICE "%s: " x , __FUNCTION__, (n1), (n2));
	#define WLAN_LOG_NOTICE3(x,n1,n2,n3) printk(KERN_NOTICE "%s: " x , __FUNCTION__, (n1), (n2), (n3));
	#define WLAN_LOG_NOTICE4(x,n1,n2,n3,n4) printk(KERN_NOTICE "%s: " x , __FUNCTION__, (n1), (n2), (n3), (n4));

	#define WLAN_LOG_INFO0(x) printk(KERN_INFO x);
	#define WLAN_LOG_INFO1(x,n) printk(KERN_INFO x, (n));
	#define WLAN_LOG_INFO2(x,n1,n2) printk(KERN_INFO x, (n1), (n2));
	#define WLAN_LOG_INFO3(x,n1,n2,n3) printk(KERN_INFO x, (n1), (n2), (n3));
	#define WLAN_LOG_INFO4(x,n1,n2,n3,n4) printk(KERN_INFO x, (n1), (n2), (n3), (n4));
	#define WLAN_LOG_INFO5(x,n1,n2,n3,n4,n5) printk(KERN_INFO x, (n1), (n2), (n3), (n4), (n5));

	#if defined(WLAN_INCLUDE_DEBUG)
		#define WLAN_ASSERT(c) if ((!(c)) && WLAN_DBVAR >= 1) { \
			WLAN_LOG_DEBUG0(1, "Assertion failure!\n"); }
		#define WLAN_HEX_DUMP( l, x, p, n)	if( WLAN_DBVAR >= (l) ){ \
			int __i__; \
			printk(KERN_DEBUG x ":"); \
			for( __i__=0; __i__ < (n); __i__++) \
				printk( " %02x", ((uint8_t*)(p))[__i__]); \
			printk("\n"); }

		#define DBFENTER { if ( WLAN_DBVAR >= 4 ){ WLAN_LOG_DEBUG0(3,"Enter\n"); } }
		#define DBFEXIT  { if ( WLAN_DBVAR >= 4 ){ WLAN_LOG_DEBUG0(3,"Exit\n"); } }

		#define WLAN_LOG_DEBUG0(l,x) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x ,  __FUNCTION__ );
		#define WLAN_LOG_DEBUG1(l,x,n) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x , __FUNCTION__ , (n));
		#define WLAN_LOG_DEBUG2(l,x,n1,n2) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x , __FUNCTION__ , (n1), (n2));
		#define WLAN_LOG_DEBUG3(l,x,n1,n2,n3) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x , __FUNCTION__ , (n1), (n2), (n3));
		#define WLAN_LOG_DEBUG4(l,x,n1,n2,n3,n4) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x , __FUNCTION__ , (n1), (n2), (n3), (n4));
		#define WLAN_LOG_DEBUG5(l,x,n1,n2,n3,n4,n5) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x , __FUNCTION__ , (n1), (n2), (n3), (n4), (n5));
		#define WLAN_LOG_DEBUG6(l,x,n1,n2,n3,n4,n5,n6) if ( WLAN_DBVAR >= (l)) printk(KERN_DEBUG "%s: " x , __FUNCTION__ , (n1), (n2), (n3), (n4), (n5), (n6));
	#else
		#define WLAN_ASSERT(c)
		#define WLAN_HEX_DUMP( l, s, p, n)

		#define DBFENTER
		#define DBFEXIT

		#define WLAN_LOG_DEBUG0(l, s)
		#define WLAN_LOG_DEBUG1(l, s,n)
		#define WLAN_LOG_DEBUG2(l, s,n1,n2)
		#define WLAN_LOG_DEBUG3(l, s,n1,n2,n3)
		#define WLAN_LOG_DEBUG4(l, s,n1,n2,n3,n4)
		#define WLAN_LOG_DEBUG5(l, s,n1,n2,n3,n4,n5)
	#endif
#else
	#define WLAN_LOG_ERROR0(s)
	#define WLAN_LOG_ERROR1(s,n)
	#define WLAN_LOG_ERROR2(s,n1,n2)
	#define WLAN_LOG_ERROR3(s,n1,n2,n3)
	#define WLAN_LOG_ERROR4(s,n1,n2,n3,n4)

	#define WLAN_LOG_WARNING0(s)
	#define WLAN_LOG_WARNING1(s,n)
	#define WLAN_LOG_WARNING2(s,n1,n2)
	#define WLAN_LOG_WARNING3(s,n1,n2,n3)
	#define WLAN_LOG_WARNING4(s,n1,n2,n3,n4)

	#define WLAN_LOG_NOTICE0(s)
	#define WLAN_LOG_NOTICE1(s,n)
	#define WLAN_LOG_NOTICE2(s,n1,n2)
	#define WLAN_LOG_NOTICE3(s,n1,n2,n3)
	#define WLAN_LOG_NOTICE4(s,n1,n2,n3,n4)

		#define WLAN_ASSERT(c)
		#define WLAN_HEX_DUMP( l, s, p, n)

		#define DBFENTER
		#define DBFEXIT

		#define WLAN_LOG_INFO0(s)
		#define WLAN_LOG_INFO1(s,n)
		#define WLAN_LOG_INFO2(s,n1,n2)
		#define WLAN_LOG_INFO3(s,n1,n2,n3)
		#define WLAN_LOG_INFO4(s,n1,n2,n3,n4)
		#define WLAN_LOG_INFO5(s,n1,n2,n3,n4,n5)

		#define WLAN_LOG_DEBUG0(l, s)
		#define WLAN_LOG_DEBUG1(l, s,n)
		#define WLAN_LOG_DEBUG2(l, s,n1,n2)
		#define WLAN_LOG_DEBUG3(l, s,n1,n2,n3)
		#define WLAN_LOG_DEBUG4(l, s,n1,n2,n3,n4)
		#define WLAN_LOG_DEBUG5(l, s,n1,n2,n3,n4,n5)
#endif

#define wlan_ms_per_tick		(1000UL / (wlan_ticks_per_sec))
#define wlan_ms_to_ticks(n)		( (n) / (wlan_ms_per_tick))
#define wlan_tu2ticks(n)		( (n) / (wlan_ms_per_tick))
#define WLAN_INT_DISABLE(n)		{ save_flags((n)); cli(); }
#define WLAN_INT_ENABLE(n)		{ sti(); restore_flags((n)); }

#ifdef CONFIG_MODVERSIONS
#define MODVERSIONS		1
#include <linux/modversions.h>
#endif

#ifdef CONFIG_SMP
#define __SMP__			1
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,17))
#define CONFIG_NETLINK		1
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0))
#define kfree_s(a, b)	kfree((a))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,2,18))
#ifndef init_waitqueue_head
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,0,16))
#define init_waitqueue_head(p)  (*(p) = NULL)
#else
#define init_waitqueue_head(p)  init_waitqueue(p)
#endif
typedef struct wait_queue *wait_queue_head_t;
typedef struct wait_queue wait_queue_t;
#define set_current_state(b)  { current->state = (b); mb(); }
#define init_waitqueue_entry(a, b) { (a)->task = current; }
#endif
#endif

#ifndef wait_event_interruptible_timeout
// retval == 0; signal met; we're good.
// retval < 0; interrupted by signal.
// retval > 0; timed out.
#define __wait_event_interruptible_timeout(wq, condition, timeout, ret)   \
do {                                                                      \
        int __ret = 0;                                                    \
        if (!(condition)) {                                               \
          wait_queue_t __wait;                                            \
          unsigned long expire;                                           \
          init_waitqueue_entry(&__wait, current);                         \
	                                                                  \
          expire = timeout + jiffies;                                     \
          add_wait_queue(&wq, &__wait);                                   \
          for (;;) {                                                      \
                  set_current_state(TASK_INTERRUPTIBLE);                  \
                  if (condition)                                          \
                          break;                                          \
                  if (jiffies > expire) {                                 \
                          ret = jiffies - expire;                         \
                          break;                                          \
                  }                                                       \
                  if (!signal_pending(current)) {                         \
                          schedule_timeout(timeout);                      \
                          continue;                                       \
                  }                                                       \
                  ret = -ERESTARTSYS;                                     \
                  break;                                                  \
          }                                                               \
          set_current_state(TASK_RUNNING);                                \
          remove_wait_queue(&wq, &__wait);                                \
	}                                                                 \
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition,	\
						timeout, __ret);	\
	__ret;								\
})

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,90))
#define spin_lock(l)            do { } while (0)
#define spin_unlock(l)          do { } while (0)
#define spin_lock_irqsave(l,f)  do { save_flags(f); cli(); } while (0)
#define spin_unlock_irqrestore(l,f) do { restore_flags(f); } while (0)
#define spin_lock_init(s)       do { } while (0)
#define spin_trylock(l)         (1)
typedef int spinlock_t;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
#ifdef CONFIG_SMP
#define spin_is_locked(x)       (*(volatile char *)(&(x)->lock) <= 0)
#else
#define spin_is_locked(l)       (0)
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,38))
typedef struct device netdevice_t;
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,4))
typedef struct net_device netdevice_t;
#else
#undef netdevice_t
typedef struct net_device netdevice_t;
#endif

#ifdef WIRELESS_EXT
#if (WIRELESS_EXT < 13)
struct iw_request_info
{
        __u16           cmd;            /* Wireless Extension command */
        __u16           flags;          /* More to come ;-) */
};
#endif
#endif


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,18))
#define MODULE_PARM(a,b)        extern int __bogus_decl
#define MODULE_AUTHOR(a)        extern int __bogus_decl
#define MODULE_DESCRIPTION(a)   extern int __bogus_decl
#define MODULE_SUPPORTED_DEVICE(a) extern int __bogus_decl
#undef  GET_USE_COUNT
#define GET_USE_COUNT(m)        mod_use_count_
#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(m)       extern int __bogus_decl
#endif

/* TODO:  Do we care about this? */
#ifndef MODULE_DEVICE_TABLE
#define MODULE_DEVICE_TABLE(foo,bar)
#endif

#define wlan_minutes2ticks(a) ((a)*(wlan_ticks_per_sec *  60))
#define wlan_seconds2ticks(a) ((a)*(wlan_ticks_per_sec))

/*=============================================================*/
/*------ Hardware Portability Macros --------------------------*/
/*=============================================================*/

#define ieee2host16(n)	__le16_to_cpu(n)
#define ieee2host32(n)	__le32_to_cpu(n)
#define host2ieee16(n)	__cpu_to_le16(n)
#define host2ieee32(n)	__cpu_to_le32(n)

#if (WLAN_CPU_FAMILY == WLAN_PPC)
       #define wlan_inw(a)                     in_be16((unsigned short *)((a)+_IO_BASE))
       #define wlan_inw_le16_to_cpu(a)         inw((a))
       #define wlan_outw(v,a)                  out_be16((unsigned short *)((a)+_IO_BASE), (v))
       #define wlan_outw_cpu_to_le16(v,a)      outw((v),(a))
#else
       #define wlan_inw(a)                     inw((a))
       #define wlan_inw_le16_to_cpu(a)         __cpu_to_le16(inw((a)))
       #define wlan_outw(v,a)                  outw((v),(a))
       #define wlan_outw_cpu_to_le16(v,a)      outw(__cpu_to_le16((v)),(a))
#endif

/*=============================================================*/
/*--- General Macros ------------------------------------------*/
/*=============================================================*/

#define wlan_max(a, b) (((a) > (b)) ? (a) : (b))
#define wlan_min(a, b) (((a) < (b)) ? (a) : (b))

#define wlan_isprint(c)	(((c) > (0x19)) && ((c) < (0x7f)))

#define wlan_hexchar(x) (((x) < 0x0a) ? ('0' + (x)) : ('a' + ((x) - 0x0a)))

/* Create a string of printable chars from something that might not be */
/* It's recommended that the str be 4*len + 1 bytes long */
#define wlan_mkprintstr(buf, buflen, str, strlen) \
{ \
	int i = 0; \
	int j = 0; \
	memset(str, 0, (strlen)); \
	for (i = 0; i < (buflen); i++) { \
		if ( wlan_isprint((buf)[i]) ) { \
			(str)[j] = (buf)[i]; \
			j++; \
		} else { \
			(str)[j] = '\\'; \
			(str)[j+1] = 'x'; \
			(str)[j+2] = wlan_hexchar(((buf)[i] & 0xf0) >> 4); \
			(str)[j+3] = wlan_hexchar(((buf)[i] & 0x0f)); \
			j += 4; \
		} \
	} \
}

/*=============================================================*/
/*--- Variables -----------------------------------------------*/
/*=============================================================*/

extern int wlan_debug;
extern int wlan_ethconv;		/* What's the default ethconv? */

/*=============================================================*/
/*--- Functions -----------------------------------------------*/
/*=============================================================*/
#endif /* _WLAN_COMPAT_H */

