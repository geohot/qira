#ifndef _IPXE_FIP_H
#define _IPXE_FIP_H

/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
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

#include <stdint.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>
#include <ipxe/fcoe.h>

/** A FIP frame header */
struct fip_header {
	/** Frame version */
	uint8_t version;
	/** Reserved */
	uint8_t reserved_a;
	/** Protocol code */
	uint16_t code;
	/** Reserved */
	uint8_t reserved_b;
	/** Subcode */
	uint8_t subcode;
	/** Descriptor list length in 32-bit words */
	uint16_t len;
	/** Flags */
	uint16_t flags;
} __attribute__ (( packed ));

/** FIP frame version */
#define FIP_VERSION 0x10

/** FIP protocol code */
enum fip_code {
	FIP_CODE_DISCOVERY = 0x0001,	/**< Discovery */
	FIP_CODE_ELS = 0x0002,		/**< Extended link services */
	FIP_CODE_MAINTAIN = 0x0003,	/**< Maintain virtual links */
	FIP_CODE_VLAN = 0x0004,		/**< VLAN */
};

/** FIP protocol subcode for discovery */
enum fip_discovery_subcode {
	FIP_DISCOVERY_SOLICIT = 0x01,	/**< Discovery solicitation */
	FIP_DISCOVERY_ADVERTISE = 0x02,	/**< Discovery advertisement */
};

/** FIP protocol subcode for extended link services */
enum fip_els_subcode {
	FIP_ELS_REQUEST = 0x01,		/**< ELS request */
	FIP_ELS_RESPONSE = 0x02,	/**< ELS response */
};

/** FIP protocol subcode for keep alive / clear links */
enum fip_vitality_subcode {
	FIP_MAINTAIN_KEEP_ALIVE = 0x01,	/**< Keep alive */
	FIP_MAINTAIN_CLEAR_LINKS = 0x02,/**< Clear virtual links */
};

/** FIP protocol subcode for VLAN */
enum fip_vlan_subcode {
	FIP_VLAN_REQUEST = 0x01,	/**< VLAN request */
	FIP_VLAN_NOTIFY = 0x02,		/**< VLAN notification */
};

/** FIP flags */
enum fip_flags {
	FIP_FP	= 0x8000,		/**< Fabric-provided MAC address */
	FIP_SP	= 0x4000,		/**< Server-provided MAC address */
	FIP_A	= 0x0004,		/**< Available for login */
	FIP_S	= 0x0002,		/**< Solicited */
	FIP_F	= 0x0001,		/**< Forwarder */
};

/** FIP descriptor common fields */
struct fip_common {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
} __attribute__ (( packed ));

/** FIP descriptor types */
enum fip_type {
	FIP_RESERVED = 0x00,		/**< Reserved */
	FIP_PRIORITY = 0x01,		/**< Priority */
	FIP_MAC_ADDRESS = 0x02,		/**< MAC address */
	FIP_FC_MAP = 0x03,		/**< FC-MAP */
	FIP_NAME_ID = 0x04,		/**< Name identifier */
	FIP_FABRIC = 0x05,		/**< Fabric */
	FIP_MAX_FCOE_SIZE = 0x06,	/**< Max FCoE size */
	FIP_FLOGI = 0x07,		/**< FLOGI */
	FIP_NPIV_FDISC = 0x08,		/**< NPIV FDISC */
	FIP_LOGO = 0x09,		/**< LOGO */
	FIP_ELP = 0x0a,			/**< ELP */
	FIP_VX_PORT_ID = 0x0b,		/**< Vx port identification */
	FIP_FKA_ADV_P = 0x0c,		/**< FKA ADV period */
	FIP_VENDOR_ID = 0x0d,		/**< Vendor ID */
	FIP_VLAN = 0x0e,		/**< VLAN */
	FIP_NUM_DESCRIPTOR_TYPES
};

/** FIP descriptor type is critical */
#define FIP_IS_CRITICAL( type ) ( (type) <= 0x7f )

/** A FIP priority descriptor */
struct fip_priority {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved;
	/** Priority
	 *
	 * A higher value indicates a lower priority.
	 */
	uint8_t priority;
} __attribute__ (( packed ));

/** Default FIP priority */
#define FIP_DEFAULT_PRIORITY 128

/** Lowest FIP priority */
#define FIP_LOWEST_PRIORITY 255

/** A FIP MAC address descriptor */
struct fip_mac_address {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
} __attribute__ (( packed ));

/** A FIP FC-MAP descriptor */
struct fip_fc_map {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[3];
	/** FC-MAP */
	struct fcoe_map map;
} __attribute__ (( packed ));

/** A FIP name identifier descriptor */
struct fip_name_id {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Name identifier */
	struct fc_name name;
} __attribute__ (( packed ));

/** A FIP fabric descriptor */
struct fip_fabric {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Virtual Fabric ID, if any */
	uint16_t vf_id;
	/** Reserved */
	uint8_t reserved;
	/** FC-MAP */
	struct fcoe_map map;
	/** Fabric name */
	struct fc_name name;
} __attribute__ (( packed ));

/** A FIP max FCoE size descriptor */
struct fip_max_fcoe_size {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Maximum FCoE size */
	uint16_t mtu;
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated ELS frame */
struct fip_els {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Fibre Channel frame header */
	struct fc_frame_header fc;
	/** ELS frame */
	struct fc_els_frame_common els;
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated login frame */
struct fip_login {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Fibre Channel frame header */
	struct fc_frame_header fc;
	/** ELS frame */
	struct fc_login_frame els;
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated LOGO request frame */
struct fip_logo_request {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Fibre Channel frame header */
	struct fc_frame_header fc;
	/** ELS frame */
	struct fc_logout_request_frame els;
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated LOGO response frame */
struct fip_logo_response {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Fibre Channel frame header */
	struct fc_frame_header fc;
	/** ELS frame */
	struct fc_logout_response_frame els;
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated ELP frame */
struct fip_elp {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Fibre Channel frame header */
	struct fc_frame_header fc;
	/** ELS frame */
	struct fc_els_frame_common els;
	/** Uninteresting content */
	uint32_t dull[25];
} __attribute__ (( packed ));

/** A FIP descriptor containing an encapsulated LS_RJT frame */
struct fip_ls_rjt {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Fibre Channel frame header */
	struct fc_frame_header fc;
	/** ELS frame */
	struct fc_ls_rjt_frame els;
} __attribute__ (( packed ));

/** A FIP Vx port identification descriptor */
struct fip_vx_port_id {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** MAC address */
	uint8_t mac[ETH_ALEN];
	/** Reserved */
	uint8_t reserved;
	/** Address identifier */
	struct fc_port_id id;
	/** Port name */
	struct fc_name name;
} __attribute__ (( packed ));

/** A FIP FKA ADV period descriptor */
struct fip_fka_adv_p {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved;
	/** Flags */
	uint8_t flags;
	/** Keep alive advertisement period in milliseconds */
	uint32_t period;
} __attribute__ (( packed ));

/** FIP FKA ADV period flags */
enum fip_fka_adv_p_flags {
	FIP_NO_KEEPALIVE = 0x01,	/**< Do not send keepalives */
};

/** A FIP vendor ID descriptor */
struct fip_vendor_id {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** Reserved */
	uint8_t reserved[2];
	/** Vendor ID */
	uint8_t vendor[8];
} __attribute__ (( packed ));

/** A FIP VLAN descriptor */
struct fip_vlan {
	/** Type */
	uint8_t type;
	/** Length in 32-bit words */
	uint8_t len;
	/** VLAN ID */
	uint16_t vlan;
} __attribute__ (( packed ));

/** A FIP descriptor */
union fip_descriptor {
	/** Common fields */
	struct fip_common common;
	/** Priority descriptor */
	struct fip_priority priority;
	/** MAC address descriptor */
	struct fip_mac_address mac_address;
	/** FC-MAP descriptor */
	struct fip_fc_map fc_map;
	/** Name identifier descriptor */
	struct fip_name_id name_id;
	/** Fabric descriptor */
	struct fip_fabric fabric;
	/** Max FCoE size descriptor */
	struct fip_max_fcoe_size max_fcoe_size;
	/** FLOGI descriptor */
	struct fip_els flogi;
	/** FLOGI request descriptor */
	struct fip_login flogi_request;
	/** FLOGI LS_ACC descriptor */
	struct fip_login flogi_ls_acc;
	/** FLOGI LS_RJT descriptor */
	struct fip_ls_rjt flogi_ls_rjt;
	/** NPIV FDISC descriptor */
	struct fip_els npiv_fdisc;
	/** NPIV FDISC request descriptor */
	struct fip_login npiv_fdisc_request;
	/** NPIV FDISC LS_ACC descriptor */
	struct fip_login npiv_fdisc_ls_acc;
	/** NPIV FDISC LS_RJT descriptor */
	struct fip_ls_rjt npiv_fdisc_ls_rjt;
	/** LOGO descriptor */
	struct fip_els logo;
	/** LOGO request descriptor */
	struct fip_logo_request logo_request;
	/** LOGO LS_ACC descriptor */
	struct fip_logo_response logo_ls_acc;
	/** LOGO LS_RJT descriptor */
	struct fip_ls_rjt logo_ls_rjt;
	/** ELS descriptor */
	struct fip_els elp;
	/** ELP request descriptor */
	struct fip_elp elp_request;
	/** ELP LS_ACC descriptor */
	struct fip_elp elp_ls_acc;
	/** ELP LS_RJT descriptor */
	struct fip_ls_rjt elp_ls_rjt;
	/** Vx port identification descriptor */
	struct fip_vx_port_id vx_port_id;
	/** FKA ADV period descriptor */
	struct fip_fka_adv_p fka_adv_p;
	/** Vendor ID descriptor */
	struct fip_vendor_id vendor_id;
	/** VLAN descriptor */
	struct fip_vlan vlan;
} __attribute__ (( packed ));

/** A FIP descriptor set */
struct fip_descriptors {
	/** Descriptors, indexed by type */
	union fip_descriptor *desc[FIP_NUM_DESCRIPTOR_TYPES];
};

/**
 * Define a function to extract a specific FIP descriptor type from a list
 *
 * @v type		Descriptor type
 * @v name		Descriptor name
 * @v finder		Descriptor finder
 */
#define FIP_DESCRIPTOR( type, name )					\
	static inline __attribute__ (( always_inline ))			\
	typeof ( ( ( union fip_descriptor * ) NULL )->name ) *		\
	fip_ ## name ( struct fip_descriptors *descs ) {		\
		return &(descs->desc[type]->name);			\
	}
FIP_DESCRIPTOR ( FIP_PRIORITY, priority );
FIP_DESCRIPTOR ( FIP_MAC_ADDRESS, mac_address );
FIP_DESCRIPTOR ( FIP_FC_MAP, fc_map );
FIP_DESCRIPTOR ( FIP_NAME_ID, name_id );
FIP_DESCRIPTOR ( FIP_FABRIC, fabric );
FIP_DESCRIPTOR ( FIP_MAX_FCOE_SIZE, max_fcoe_size );
FIP_DESCRIPTOR ( FIP_FLOGI, flogi );
FIP_DESCRIPTOR ( FIP_FLOGI, flogi_request );
FIP_DESCRIPTOR ( FIP_FLOGI, flogi_ls_acc );
FIP_DESCRIPTOR ( FIP_FLOGI, flogi_ls_rjt );
FIP_DESCRIPTOR ( FIP_NPIV_FDISC, npiv_fdisc );
FIP_DESCRIPTOR ( FIP_NPIV_FDISC, npiv_fdisc_request );
FIP_DESCRIPTOR ( FIP_NPIV_FDISC, npiv_fdisc_ls_acc );
FIP_DESCRIPTOR ( FIP_NPIV_FDISC, npiv_fdisc_ls_rjt );
FIP_DESCRIPTOR ( FIP_LOGO, logo );
FIP_DESCRIPTOR ( FIP_LOGO, logo_request );
FIP_DESCRIPTOR ( FIP_LOGO, logo_ls_acc );
FIP_DESCRIPTOR ( FIP_LOGO, logo_ls_rjt );
FIP_DESCRIPTOR ( FIP_ELP, elp );
FIP_DESCRIPTOR ( FIP_ELP, elp_request );
FIP_DESCRIPTOR ( FIP_ELP, elp_ls_acc );
FIP_DESCRIPTOR ( FIP_ELP, elp_ls_rjt );
FIP_DESCRIPTOR ( FIP_VX_PORT_ID, vx_port_id );
FIP_DESCRIPTOR ( FIP_FKA_ADV_P, fka_adv_p );
FIP_DESCRIPTOR ( FIP_VENDOR_ID, vendor_id );
FIP_DESCRIPTOR ( FIP_VLAN, vlan );

#endif /* _IPXE_FIP_H */
