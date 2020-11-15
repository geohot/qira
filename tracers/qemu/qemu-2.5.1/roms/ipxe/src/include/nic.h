/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#ifndef	NIC_H
#define NIC_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/isapnp.h>
#include <ipxe/isa.h>
#include <ipxe/eisa.h>
#include <ipxe/mca.h>
#include <ipxe/io.h>

typedef enum {
	DISABLE = 0,
	ENABLE,
	FORCE
} irq_action_t;

typedef enum duplex {
	HALF_DUPLEX = 1,
	FULL_DUPLEX
} duplex_t;

/*
 *	Structure returned from eth_probe and passed to other driver
 *	functions.
 */
struct nic {
	struct nic_operations	*nic_op;
	int			flags;	/* driver specific flags */
	unsigned char		*node_addr;
	unsigned char		*packet;
	unsigned int		packetlen;
	unsigned int		ioaddr;
	unsigned char		irqno;
	unsigned int		mbps;
	duplex_t		duplex;
	void			*priv_data;	/* driver private data */
};

struct nic_operations {
	int ( *connect ) ( struct nic * );
	int ( *poll ) ( struct nic *, int retrieve );
	void ( *transmit ) ( struct nic *, const char *,
			     unsigned int, unsigned int, const char * );
	void ( *irq ) ( struct nic *, irq_action_t );
};

extern struct nic nic;

static inline int eth_poll ( int retrieve ) {
	return nic.nic_op->poll ( &nic, retrieve );
}

static inline void eth_transmit ( const char *dest, unsigned int type,
				  unsigned int size, const void *packet ) {
	nic.nic_op->transmit ( &nic, dest, type, size, packet );
}

/*
 * Function prototypes
 *
 */
extern int dummy_connect ( struct nic *nic );
extern void dummy_irq ( struct nic *nic, irq_action_t irq_action );
extern int legacy_probe ( void *hwdev,
			  void ( * set_drvdata ) ( void *hwdev, void *priv ),
			  struct device *dev,
			  int ( * probe ) ( struct nic *nic, void *hwdev ),
			  void ( * disable ) ( struct nic *nic, void *hwdev ));
void legacy_remove ( void *hwdev,
		     void * ( * get_drvdata ) ( void *hwdev ),
		     void ( * disable ) ( struct nic *nic, void *hwdev ) );

#define PCI_DRIVER(_name,_ids,_class) 					  \
	static inline int						  \
	_name ## _pci_legacy_probe ( struct pci_device *pci );		  \
	static inline void						  \
	_name ## _pci_legacy_remove ( struct pci_device *pci );		  \
	struct pci_driver _name __pci_driver = {			  \
		.ids = _ids,						  \
		.id_count = sizeof ( _ids ) / sizeof ( _ids[0] ),	  \
		.probe = _name ## _pci_legacy_probe,			  \
		.remove = _name ## _pci_legacy_remove,			  \
	};								  \
	REQUIRE_OBJECT ( pci );

static inline void legacy_pci_set_drvdata ( void *hwdev, void *priv ) {
	pci_set_drvdata ( hwdev, priv );
}
static inline void * legacy_pci_get_drvdata ( void *hwdev ) {
	return pci_get_drvdata ( hwdev );
}

#define ISAPNP_DRIVER(_name,_ids)					  \
	static inline int						  \
	_name ## _isapnp_legacy_probe ( struct isapnp_device *isapnp,	  \
					const struct isapnp_device_id *id ); \
	static inline void						  \
	_name ## _isapnp_legacy_remove ( struct isapnp_device *isapnp );  \
	struct isapnp_driver _name __isapnp_driver = {			  \
		.ids = _ids,						  \
		.id_count = sizeof ( _ids ) / sizeof ( _ids[0] ),	  \
		.probe = _name ## _isapnp_legacy_probe,			  \
		.remove = _name ## _isapnp_legacy_remove,		  \
	};								  \
	REQUIRE_OBJECT ( isapnp );

static inline void legacy_isapnp_set_drvdata ( void *hwdev, void *priv ) {
	isapnp_set_drvdata ( hwdev, priv );
}
static inline void * legacy_isapnp_get_drvdata ( void *hwdev ) {
	return isapnp_get_drvdata ( hwdev );
}

#define EISA_DRIVER(_name,_ids)						  \
	static inline int						  \
	_name ## _eisa_legacy_probe ( struct eisa_device *eisa,		  \
				      const struct eisa_device_id *id );  \
	static inline void						  \
	_name ## _eisa_legacy_remove ( struct eisa_device *eisa );	  \
	struct eisa_driver _name __eisa_driver = {			  \
		.ids = _ids,						  \
		.id_count = sizeof ( _ids ) / sizeof ( _ids[0] ),	  \
		.probe = _name ## _eisa_legacy_probe,			  \
		.remove = _name ## _eisa_legacy_remove,			  \
	};								  \
	REQUIRE_OBJECT ( eisa );

static inline void legacy_eisa_set_drvdata ( void *hwdev, void *priv ) {
	eisa_set_drvdata ( hwdev, priv );
}
static inline void * legacy_eisa_get_drvdata ( void *hwdev ) {
	return eisa_get_drvdata ( hwdev );
}

#define MCA_DRIVER(_name,_ids)						  \
	static inline int						  \
	_name ## _mca_legacy_probe ( struct mca_device *mca,		  \
				     const struct mca_device_id *id );	  \
	static inline void						  \
	_name ## _mca_legacy_remove ( struct mca_device *mca );		  \
	struct mca_driver _name __mca_driver = {			  \
		.ids = _ids,						  \
		.id_count = sizeof ( _ids ) / sizeof ( _ids[0] ),	  \
		.probe = _name ## _mca_legacy_probe,			  \
		.remove = _name ## _mca_legacy_remove,			  \
	};								  \
	REQUIRE_OBJECT ( mca );

static inline void legacy_mca_set_drvdata ( void *hwdev, void *priv ) {
	mca_set_drvdata ( hwdev, priv );
}
static inline void * legacy_mca_get_drvdata ( void *hwdev ) {
	return mca_get_drvdata ( hwdev );
}

#define ISA_DRIVER(_name,_probe_addrs,_probe_addr,_vendor_id,_prod_id)	  \
	static inline int						  \
	_name ## _isa_legacy_probe ( struct isa_device *isa );		  \
	static inline int						  \
	_name ## _isa_legacy_probe_at_addr ( struct isa_device *isa ) {	  \
		if ( ! _probe_addr ( isa->ioaddr ) )			  \
			return -ENODEV; 				  \
		return _name ## _isa_legacy_probe ( isa );		  \
	}								  \
	static inline void						  \
	_name ## _isa_legacy_remove ( struct isa_device *isa );		  \
	static const char _name ## _text[];				  \
	struct isa_driver _name __isa_driver = {			  \
		.name = _name ## _text,					  \
		.probe_addrs = _probe_addrs,				  \
		.addr_count = ( sizeof ( _probe_addrs ) /		  \
				sizeof ( _probe_addrs[0] ) ),		  \
		.vendor_id = _vendor_id,				  \
		.prod_id = _prod_id,					  \
		.probe = _name ## _isa_legacy_probe_at_addr,		  \
		.remove = _name ## _isa_legacy_remove,			  \
	};								  \
	REQUIRE_OBJECT ( isa );

static inline void legacy_isa_set_drvdata ( void *hwdev, void *priv ) {
	isa_set_drvdata ( hwdev, priv );
}
static inline void * legacy_isa_get_drvdata ( void *hwdev ) {
	return isa_get_drvdata ( hwdev );
}

#undef DRIVER
#define DRIVER(_name_text,_unused2,_unused3,_name,_probe,_disable)	  \
	static const char _name ## _text[] = _name_text;		  \
	static inline int						  \
	_name ## _probe ( struct nic *nic, void *hwdev ) {		  \
		return _probe ( nic, hwdev );				  \
	}								  \
	static inline void						  \
	_name ## _disable ( struct nic *nic, void *hwdev ) {		  \
		void ( * _unsafe_disable ) () = _disable;		  \
		_unsafe_disable ( nic, hwdev );				  \
	}								  \
	static inline int						  \
	_name ## _pci_legacy_probe ( struct pci_device *pci ) {		  \
		return legacy_probe ( pci, legacy_pci_set_drvdata,	  \
				      &pci->dev, _name ## _probe,	  \
				      _name ## _disable );		  \
	}								  \
	static inline void						  \
	_name ## _pci_legacy_remove ( struct pci_device *pci ) {	  \
		return legacy_remove ( pci, legacy_pci_get_drvdata,	  \
				       _name ## _disable );		  \
	}								  \
	static inline int						  \
	_name ## _isapnp_legacy_probe ( struct isapnp_device *isapnp,	  \
			 const struct isapnp_device_id *id __unused ) {	  \
		return legacy_probe ( isapnp, legacy_isapnp_set_drvdata,  \
				      &isapnp->dev, _name ## _probe,	  \
				      _name ## _disable );		  \
	}								  \
	static inline void						  \
	_name ## _isapnp_legacy_remove ( struct isapnp_device *isapnp ) { \
		return legacy_remove ( isapnp, legacy_isapnp_get_drvdata, \
				       _name ## _disable );		  \
	}								  \
	static inline int						  \
	_name ## _eisa_legacy_probe ( struct eisa_device *eisa,		  \
			     const struct eisa_device_id *id __unused ) { \
		return legacy_probe ( eisa, legacy_eisa_set_drvdata,	  \
				      &eisa->dev, _name ## _probe,	  \
				      _name ## _disable );		  \
	}								  \
	static inline void						  \
	_name ## _eisa_legacy_remove ( struct eisa_device *eisa ) {	  \
		return legacy_remove ( eisa, legacy_eisa_get_drvdata,	  \
				       _name ## _disable );		  \
	}								  \
	static inline int						  \
	_name ## _mca_legacy_probe ( struct mca_device *mca,		  \
			      const struct mca_device_id *id __unused ) { \
		return legacy_probe ( mca, legacy_mca_set_drvdata,	  \
				      &mca->dev, _name ## _probe,	  \
				      _name ## _disable );		  \
	}								  \
	static inline void						  \
	_name ## _mca_legacy_remove ( struct mca_device *mca ) {	  \
		return legacy_remove ( mca, legacy_mca_get_drvdata,	  \
				       _name ## _disable );		  \
	}								  \
	static inline int						  \
	_name ## _isa_legacy_probe ( struct isa_device *isa ) {		  \
		return legacy_probe ( isa, legacy_isa_set_drvdata,	  \
				      &isa->dev, _name ## _probe,	  \
				      _name ## _disable );		  \
	}								  \
	static inline void						  \
	_name ## _isa_legacy_remove ( struct isa_device *isa ) {	  \
		return legacy_remove ( isa, legacy_isa_get_drvdata,	  \
				       _name ## _disable );		  \
	}								  \
	PROVIDE_REQUIRING_SYMBOL()

#endif	/* NIC_H */
