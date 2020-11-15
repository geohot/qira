/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef P9_H
#define P9_H

#include <stdint.h>


#define P9_ERROR			-1
#define P9_UNKNOWN_VERSION		-2
#define P9_R_ERROR			-3
#define P9_MSG_TOO_LONG			-4
#define P9_UNEXPECTED_MSG		-5
#define P9_UNEXPECTED_TAG		-6
#define P9_TRANSPORT_ERROR		-7
#define P9_NO_TRANSPORT			-8
#define P9_NULL_PATH			-9
#define P9_PATH_ELEMENT_TOO_LONG	-10
#define P9_READ_UNEXPECTED_DATA		-11
#define P9_NO_BUFFER			-12
#define P9_MSG_SIZE_TOO_BIG		-13

#define P9_PARTIAL_WALK			1

typedef int (*p9_transact_t)(void *opaque, uint8_t *tx, int tx_size,
		uint8_t *rx, int *rx_size);

typedef struct {
	uint32_t message_size;
	char *uname; 		/* User name. */
	char *aname; 		/* Tree/mount name/path. */
	uint32_t fid;		/* Represents mount point. */
} p9_connection_t;

typedef struct {
	uint32_t fid;		/* Identifies the file to P9 server. */
	uint32_t iounit;	/* Maximum read size in bytes. */
	uint8_t type;		/* Type of file. */
	uint64_t length;	/* Length of file. */
	p9_connection_t *connection;
} p9_file_t;


void reset_buffers(void);
void p9_reg_transport(p9_transact_t transact_func, void *opaque,
		      uint8_t *tx_buffer, uint8_t *rx_buffer);
int p9_transaction(p9_connection_t *connection);
int p9_version(p9_connection_t *connection);
int p9_attach(p9_connection_t *connection);
int p9_clunk(p9_connection_t *connection, uint32_t fid);
int p9_walk(p9_connection_t *connection, uint32_t fid, uint32_t new_fid,
		uint8_t **pos);
int p9_open(p9_file_t *file, uint8_t mode);
int p9_read(p9_file_t *file, uint8_t *buffer,
		uint32_t count, uint64_t offset);
int p9_stat(p9_file_t *file);

#endif
