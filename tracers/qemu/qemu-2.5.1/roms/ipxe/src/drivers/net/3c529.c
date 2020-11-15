/*
 * Split out from 3c509.c to make build process more sane
 *
 */

FILE_LICENCE ( BSD2 );

#include "etherboot.h"
#include <ipxe/mca.h>
#include <ipxe/isa.h> /* for ISA_ROM */
#include "nic.h"
#include "3c509.h"

/*
 * Several other pieces of the MCA support code were shamelessly
 * borrowed from the Linux kernel source.
 *
 * MCA support added by Adam Fritzler (mid@auk.cx)
 *
 * Generalised out of the 3c529 driver and into a bus type by Michael
 * Brown <mbrown@fensystems.co.uk>
 *
 */

static int t529_probe ( struct nic *nic, struct mca_device *mca ) {

	/* Retrieve NIC parameters from MCA device parameters */
	nic->ioaddr = ( ( mca->pos[4] & 0xfc ) | 0x02 ) << 8;
	nic->irqno = mca->pos[5] & 0x0f;
	printf ( "3c529 board found on MCA at %#hx IRQ %d -",
		 nic->ioaddr, nic->irqno );

	/* Hand off to generic t5x9 probe routine */
	return t5x9_probe ( nic, MCA_ID ( mca ), 0xffff );
}

static void t529_disable ( struct nic *nic, struct mca_device *mca __unused ) {
	t5x9_disable ( nic );
}

static struct mca_device_id el3_mca_adapters[] = {
        { "3Com 3c529 EtherLink III (10base2)", 0x627c },
        { "3Com 3c529 EtherLink III (10baseT)", 0x627d },
        { "3Com 3c529 EtherLink III (test mode)", 0x62db },
        { "3Com 3c529 EtherLink III (TP or coax)", 0x62f6 },
        { "3Com 3c529 EtherLink III (TP)", 0x62f7 },
};

MCA_DRIVER ( t529_driver, el3_mca_adapters );

DRIVER ( "3c529", nic_driver, mca_driver, t529_driver,
	 t529_probe, t529_disable );

ISA_ROM( "3c529", "3c529 == MCA 3c509" );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
