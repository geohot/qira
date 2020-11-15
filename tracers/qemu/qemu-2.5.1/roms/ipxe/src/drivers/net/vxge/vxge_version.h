/*
 * vxge-version.h: iPXE driver for Neterion Inc's X3100 Series 10GbE
 *              PCIe I/O Virtualized Server Adapter.
 *
 * Copyright(c) 2002-2010 Neterion Inc.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by
 * reference.  Drivers based on or derived from this code fall under
 * the GPL and must retain the authorship, copyright and license
 * notice.
 *
 */

FILE_LICENCE(GPL2_ONLY);

#ifndef VXGE_VERSION_H

#define VXGE_VERSION_H

/* ipxe vxge driver version fields.
 * Note: Each field must be a nibble size
 */
#define VXGE_VERSION_MAJOR	3
#define VXGE_VERSION_MINOR	5
#define VXGE_VERSION_FIX	0
#define VXGE_VERSION_BUILD	1

#define VXGE_FW_VER(major, minor, build) \
	(((major) << 16) + ((minor) << 8) + (build))

/* Certified FW version. */
#define VXGE_CERT_FW_VER_MAJOR	1
#define VXGE_CERT_FW_VER_MINOR	6
#define VXGE_CERT_FW_VER_BUILD	0

#define VXGE_CERT_FW_VER 	VXGE_FW_VER(VXGE_CERT_FW_VER_MAJOR, 	\
				VXGE_CERT_FW_VER_MINOR,	VXGE_CERT_FW_VER_BUILD)

#endif
