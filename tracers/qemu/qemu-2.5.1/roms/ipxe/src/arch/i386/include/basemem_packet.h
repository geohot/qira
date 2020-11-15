#ifndef BASEMEM_PACKET_H
#define BASEMEM_PACKET_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <realmode.h>

/** Maximum length of base memory packet buffer */
#define BASEMEM_PACKET_LEN 1514

/** Base memory packet buffer */
extern char __bss16_array ( basemem_packet, [BASEMEM_PACKET_LEN] );
#define basemem_packet __use_data16 ( basemem_packet )

#endif /* BASEMEM_PACKET_H */
