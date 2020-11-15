#ifndef CONFIG_FAULT_H
#define CONFIG_FAULT_H

/** @file
 *
 * Fault injection
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <config/defaults.h>

/* Drop every N transmitted or received network packets */
#define	NETDEV_DISCARD_RATE 0

/* Drop every N transmitted or received PeerDist discovery packets */
#define PEERDISC_DISCARD_RATE 0

/* Annul every N PeerDist download attempts */
#define PEERBLK_ANNUL_RATE 0

/* Stall every N PeerDist download attempts */
#define PEERBLK_STALL_RATE 0

/* Abort every N PeerDist download attempts */
#define PEERBLK_ABORT_RATE 0

/* Corrupt every N received PeerDist packets */
#define PEERBLK_CORRUPT_RATE 0

#include <config/local/fault.h>

#endif /* CONFIG_FAULT_H */
