/*
 * Split out from 3c509.c, since EISA cards are relatively rare, and
 * ROM space in 3c509s is very limited.
 *
 */

#include <ipxe/eisa.h>
#include <ipxe/isa.h>
#include "3c509.h"

/*
 * The EISA probe function
 *
 */
static int el3_eisa_probe ( struct nic *nic, struct eisa_device *eisa ) {
	

        nic->ioaddr = eisa->ioaddr;
        nic->irqno = 0;
        enable_eisa_device ( eisa );
        
	/* Hand off to generic t5x9 probe routine */
	return t5x9_probe ( nic, ISA_PROD_ID ( PROD_ID ), ISA_PROD_ID_MASK );
}

static void el3_eisa_disable ( struct nic *nic, struct eisa_device *eisa ) {
	t5x9_disable ( nic );
	disable_eisa_device ( eisa );
}

static struct eisa_device_id el3_eisa_adapters[] = {
	{ "3Com 3c509 EtherLink III (EISA)", MFG_ID, PROD_ID },
};

EISA_DRIVER ( el3_eisa_driver, el3_eisa_adapters );

DRIVER ( "3c509 (EISA)", nic_driver, eisa_driver, el3_eisa_driver,
	 el3_eisa_probe, el3_eisa_disable );

ISA_ROM ( "3c509-eisa","3c509 (EISA)" );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
