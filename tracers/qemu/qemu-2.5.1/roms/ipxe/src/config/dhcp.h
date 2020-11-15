#ifndef CONFIG_DHCP_H
#define CONFIG_DHCP_H

/** @file
 *
 * DHCP configuration
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/defaults.h>

/*
 * DHCP and PXE Boot Server timeout parameters
 *
 * Initial and final timeout for DHCP discovery
 *
 * The PXE spec indicates discover request are sent 4 times, with
 * timeouts of 4, 8, 16, 32 seconds.  iPXE by default uses 1, 2, 4, 8.
 */
#define DHCP_DISC_START_TIMEOUT_SEC	1
#define DHCP_DISC_END_TIMEOUT_SEC	10
//#define DHCP_DISC_START_TIMEOUT_SEC	4	/* as per PXE spec */
//#define DHCP_DISC_END_TIMEOUT_SEC	32	/* as per PXE spec */

/*
 * ProxyDHCP offers are given precedence by continue to wait for them
 * after a valid DHCPOFFER is received.  We'll wait through this
 * timeout for it.  The PXE spec indicates waiting through the 4 & 8
 * second timeouts, iPXE by default stops after 2.
 */
#define DHCP_DISC_PROXY_TIMEOUT_SEC	2
//#define DHCP_DISC_PROXY_TIMEOUT_SEC	11	/* as per PXE spec */

/*
 * Per the PXE spec, requests are also tried 4 times, but at timeout
 * intervals of 1, 2, 3, 4 seconds.  To adapt this to an exponential
 * backoff timer, we can either do 1, 2, 4, 8, ie. 4 retires with a
 * longer interval or start at 0 (0.25s) for 0.25, 0.5, 1, 2, 4,
 * ie. one extra try and shorter initial timeouts.  iPXE by default
 * does a combination of both, starting at 0 and going through the 8
 * second timeout.
 */
#define DHCP_REQ_START_TIMEOUT_SEC	0
#define DHCP_REQ_END_TIMEOUT_SEC	10
//#define DHCP_REQ_END_TIMEOUT_SEC	4	/* as per PXE spec */

/*
 * A ProxyDHCP offer without PXE options also goes through a request
 * phase using these same parameters, but note the early break below.
 */
#define DHCP_PROXY_START_TIMEOUT_SEC	0
#define DHCP_PROXY_END_TIMEOUT_SEC	10
//#define DHCP_PROXY_END_TIMEOUT_SEC	8	/* as per PXE spec */

/*
 * A ProxyDHCP request timeout should not induce a failure condition,
 * so we always want to break before the above set of timers expire.
 * The iPXE default value of 2 breaks at the first timeout after 2
 * seconds, which will be after the 2 second timeout.
 */
#define DHCP_REQ_PROXY_TIMEOUT_SEC	2
//#define DHCP_REQ_PROXY_TIMEOUT_SEC	7	/* as per PXE spec */

/*
 * Per the PXE spec, a PXE boot server request is also be retried 4
 * times at timeouts of 1, 2, 3, 4.  iPXE uses the same timeouts as
 * discovery, 1, 2, 4, 8, but will move on to the next server if
 * available after an elapsed time greater than 3 seconds, therefore
 * effectively only sending 3 tries at timeouts of 1, 2, 4.
 */
#define PXEBS_START_TIMEOUT_SEC		1
#define PXEBS_END_TIMEOUT_SEC		10
//#define PXEBS_START_TIMEOUT_SEC	0	/* as per PXE spec */
//#define PXEBS_END_TIMEOUT_SEC		8	/* as per PXE spec */

/*
 * Increment to the next PXE Boot server, if available, after this
 * this much time has elapsed.
 */
#define PXEBS_MAX_TIMEOUT_SEC		3
//#define PXEBS_MAX_TIMEOUT_SEC		7	/* as per PXE spec */

#include <config/local/dhcp.h>

#endif /* CONFIG_DHCP_H */
