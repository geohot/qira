#ifndef _IPXE_RETRY_H
#define _IPXE_RETRY_H

/** @file
 *
 * Retry timers
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/list.h>

/** Default minimum timeout value (in ticks) */
#define DEFAULT_MIN_TIMEOUT ( TICKS_PER_SEC / 4 )

/** Default maximum timeout value (in ticks) */
#define DEFAULT_MAX_TIMEOUT ( 10 * TICKS_PER_SEC )

/** A retry timer */
struct retry_timer {
	/** List of active timers */
	struct list_head list;
	/** Timer is currently running */
	unsigned int running;
	/** Timeout value (in ticks) */
	unsigned long timeout;
	/** Minimum timeout value (in ticks), or zero to use default
	 *
	 * The timeout will never be reduced below this value.
	 */
	unsigned long min;
	/** Maximum timeout value (in ticks), or zero to use default
	 *
	 * The timeout will be deemed permanent (according to the
	 * failure indicator passed to expired()) when it exceeds this
	 * value.
	 */
	unsigned long max;
	/** Start time (in ticks) */
	unsigned long start;
	/** Retry count */
	unsigned int count;
	/** Timer expired callback
	 *
	 * @v timer	Retry timer
	 * @v fail	Failure indicator
	 *
	 * The timer will already be stopped when this method is
	 * called.  The failure indicator will be True if the retry
	 * timeout has already exceeded @c max_timeout.
	 */
	void ( * expired ) ( struct retry_timer *timer, int over );
	/** Reference counter
	 *
	 * If this interface is not part of a reference-counted
	 * object, this field may be NULL.
	 */
	struct refcnt *refcnt;
};

/**
 * Initialise a timer
 *
 * @v timer		Retry timer
 * @v expired		Timer expired callback
 * @v refcnt		Reference counter, or NULL
 */
static inline __attribute__ (( always_inline )) void
timer_init ( struct retry_timer *timer,
	     void ( * expired ) ( struct retry_timer *timer, int over ),
	     struct refcnt *refcnt ) {
	timer->expired = expired;
	timer->refcnt = refcnt;
}

/**
 * Initialise a static timer
 *
 * @v expired_fn	Timer expired callback
 */
#define TIMER_INIT( expired_fn ) {			\
		.expired = (expired_fn),		\
	}

extern void start_timer ( struct retry_timer *timer );
extern void start_timer_fixed ( struct retry_timer *timer,
				unsigned long timeout );
extern void stop_timer ( struct retry_timer *timer );
extern void retry_poll ( void );

/**
 * Start timer with no delay
 *
 * @v timer		Retry timer
 *
 * This starts the timer running with a zero timeout value.
 */
static inline void start_timer_nodelay ( struct retry_timer *timer ) {
	start_timer_fixed ( timer, 0 );
}

/**
 * Test to see if timer is currently running
 *
 * @v timer		Retry timer
 * @ret running		Non-zero if timer is running
 */
static inline __attribute__ (( always_inline )) unsigned long
timer_running ( struct retry_timer *timer ) {
	return ( timer->running );
}

/**
 * Set minimum and maximum timeouts
 *
 * @v timer		Retry timer
 * @v min		Minimum timeout (in ticks), or zero to use default
 * @v max		Maximum timeout (in ticks), or zero to use default
 */
static inline __attribute__ (( always_inline )) void
set_timer_limits ( struct retry_timer *timer, unsigned long min,
		   unsigned long max ) {
	timer->min = min;
	timer->max = max;
}

#endif /* _IPXE_RETRY_H */
