#ifndef _USR_FCMGMT_H
#define _USR_FCMGMT_H

/** @file
 *
 * Fibre Channel management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct fc_port;
struct fc_peer;
struct fc_els_handler;

extern void fcportstat ( struct fc_port *port );
extern void fcpeerstat ( struct fc_peer *peer );
extern int fcels ( struct fc_port *port, struct fc_port_id *peer_port_id,
		   struct fc_els_handler *handler );

#endif /* _USR_FCMGMT_H */
