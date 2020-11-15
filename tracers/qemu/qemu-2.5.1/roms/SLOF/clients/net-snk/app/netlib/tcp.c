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

/*>>>>>>>>>>>>>>>>>>>>>>> DEFINITIONS & DECLARATIONS <<<<<<<<<<<<<<<<<<<<*/

#include <tcp.h>
#include <sys/socket.h>


/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> LOCAL VARIABLES <<<<<<<<<<<<<<<<<<<<<<<<<*/

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>> IMPLEMENTATION <<<<<<<<<<<<<<<<<<<<<<<<<<*/


/**
 * TCP: Handles TCP-packets according to Receive-handle diagram.
 *
 * @param  tcp_packet TCP-packet to be handled
 * @param  packetsize Length of the packet
 * @return            ZERO - packet handled successfully;
 *                    NON ZERO - packet was not handled (e.g. bad format)
 */
int8_t
handle_tcp(uint8_t * tcp_packet, int32_t packetsize)
{
	return -1;
}


/**
 * NET: This function handles situation when "Destination unreachable"
 *      ICMP-error occurs during sending TCP-packet.
 *
 * @param  err_code   Error Code (e.g. "Host unreachable")
 * @param  packet     original TCP-packet
 * @param  packetsize length of the packet
 * @see               handle_icmp
 */
void
handle_tcp_dun(uint8_t * tcp_packet, uint32_t packetsize, uint8_t err_code) {
}
