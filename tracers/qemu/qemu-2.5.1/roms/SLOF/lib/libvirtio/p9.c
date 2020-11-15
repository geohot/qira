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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <byteorder.h>
#include "p9.h"


/* Protocol stack marshaling. */
uint8_t *sp;

#define GET_08(s,i)	(s)[(i)]
#define GET_16(s,i)	le16_to_cpu(*(uint16_t*)(&(s)[(i)]))
#define GET_32(s,i)	le32_to_cpu(*(uint32_t*)(&(s)[(i)]))
#define GET_64(s,i)	le64_to_cpu(*(uint64_t*)(&(s)[(i)]))

#define SET_08(s,i,v)	(s)[(i)] = (v)
#define SET_16(s,i,v)	*(uint16_t*)(&(s)[(i)]) = cpu_to_le16(v)
#define SET_32(s,i,v)	*(uint32_t*)(&(s)[(i)]) = cpu_to_le32(v)
#define SET_64(s,i,v)	*(uint64_t*)(&(s)[(i)]) = cpu_to_le64(v)

#define PUT_08(v)	sp[0] = (v);sp+=1
#define PUT_16(v)	*(uint16_t*)(&sp[0]) = cpu_to_le16(v);sp+=2
#define PUT_32(v)	*(uint32_t*)(&sp[0]) = cpu_to_le32(v);sp+=4
#define PUT_64(v)	*(uint64_t*)(&sp[0]) = cpu_to_le64(v);sp+=8

#define PUT_HD(m,t)	PUT_32(0);PUT_08(m);PUT_16(t)
#define PUT_SN(v,n)	PUT_16(n);memcpy(sp,(v),(n));sp+=n
#define PUT_ST(v)	PUT_16(strlen(v));memcpy(sp,(v),strlen(v));\
				sp+=strlen(v)

#define GET_SIZE	(sp - tx)


/* General defines. */
#define MIN(a,b)	((a)>(b)?(b):(a))

#define NOTAG		((uint16_t)~0)
#define NOFID		((uint32_t)~0)
#define TAG		1
#define BUF_SIZE	(8*1024)

#define VERSION			"9P2000.u"
#define UNKNOWN_VER		"unknown"

#define MSG_SIZE		0
#define MSG_ID			4
#define MSG_ERR			0x6b
#define MSG_ERR_STR		9
#define MSG_ERR_STR_LEN		7
#define MSG_TAG			5
#define MSG_VER_MSIZE		7
#define MSG_VER_STR_LEN		11
#define MSG_VER_STR		13
#define MSG_WALK_TX_ELMT	15
#define MSG_WALK_RX_ELMT	7
#define MSG_SIZE		0
#define MSG_WALK_MAX_ELMT	16
#define MSG_QID_SIZE		13
#define MSG_WALK_RX_HDR_SIZE	9
#define MSG_OPEN_IOUNIT		20
#define MSG_OPEN_MODE_MASK	0x5f
#define MSG_READ_COUNT		7
#define MSG_READ_DATA		11
#define MSG_STAT_LEN		42
#define MSG_STAT_TYPE		17

#define T_VERSION	100
#define R_VERSION	(T_VERSION + 1)
#define T_ATTACH	104
#define R_ATTACH	(T_ATTACH + 1)
#define T_ERROR		106
#define R_ERROR		(T_ERROR + 1)
#define T_WALK		110
#define R_WALK		(T_WALK + 1)
#define T_OPEN		112
#define R_OPEN		(T_OPEN + 1)
#define T_READ		116
#define R_READ		(T_READ + 1)
#define T_CLUNK		120
#define R_CLUNK		(T_CLUNK + 1)
#define T_STAT		124
#define R_STAT		(T_STAT + 1)

static p9_transact_t transact;
static void *transact_opaque;
static uint8_t *tx;
static uint8_t *rx;


/**
 * p9_reg_transport
 *
 * Registers a transport function for use by the P9 protocol. The transport
 * connects the P9 Client (this library) to a server instance.
 *
 * @param transact_func[in]	Function pointer to type p9_transact_t.
 * @param tx_buffer[in]		TX buffer, must be 8k in size.
 * @param rx_buffer[in]		RX buffer, must be 8k in size.
 */
void p9_reg_transport(p9_transact_t transact_func, void *opaque,
		      uint8_t *tx_buffer, uint8_t *rx_buffer)
{
	transact = transact_func;
	transact_opaque = opaque;
	tx = tx_buffer;
	rx = rx_buffer;
}

/**
 * reset_buffers
 *
 * Reset the RX and TX buffers to BUF_SIZE (8k) and reset the Stack Pointer
 * for the TX buffer, which is referenced by the PUT_* macro's.
 */
void reset_buffers(void)
{
	memset(tx, 0, BUF_SIZE);
	memset(rx, 0, BUF_SIZE);
	sp = tx;
}

/**
 * p9_transaction
 *
 * Perform a transaction (send/recv) over the registered transport.
 *
 * @param connection[in|out]	Connection object.
 * @return	0 = success, -ve = error.
 */
int p9_transaction(p9_connection_t *connection)
{
	int rc;
	int tx_size = GET_SIZE;
	int rx_size = connection->message_size;

	if (transact == NULL) {
		return P9_NO_TRANSPORT;
	}
	if (tx == NULL || rx == NULL) {
		return P9_NO_BUFFER;
	}
	if (connection->message_size > BUF_SIZE) {
		return P9_MSG_SIZE_TOO_BIG;
	}
	if (tx_size > connection->message_size) {
		return P9_MSG_TOO_LONG;
	}

	SET_32(tx, MSG_SIZE, tx_size);
	rc = transact(transact_opaque, tx, tx_size, rx, &rx_size);

	if (rc != 0) {
		return P9_TRANSPORT_ERROR;
	}
	if (GET_16(tx, MSG_TAG) != GET_16(rx, MSG_TAG)) {
		return P9_UNEXPECTED_TAG;
	}
	if (GET_08(rx, MSG_ID) == MSG_ERR) {
		char error_string[200];

		memset(error_string, 0, 200);
		strncpy(error_string, (char *)&rx[MSG_ERR_STR],
				MIN(200 - 1, GET_16(rx, MSG_ERR_STR_LEN)));
#ifndef TEST
		printf("\nError: %s\n", error_string);
#endif
		return P9_R_ERROR;
	}
	if ((GET_08(tx, MSG_ID) + 1) != GET_08(rx, MSG_ID)) {
		return P9_UNEXPECTED_MSG;
	}

	return 0;
}

/**
 * p9_version
 *
 * Called to start a session. Negotiates the maximum message size for the
 * P9 protocol.
 *
 * @param connection[in|out]	Connection object, contains message_size.
 * @return	0 = success, -ve = error.
 *
 * @remark
 * size[4] Tversion tag[2] msize[4] version[s]
 * size[4] Rversion tag[2] msize[4] version[s]
 */
int p9_version(p9_connection_t *connection)
{
	int rc;
	char *ver_str;
	int ver_len;

	reset_buffers();

	/* Build message. */
	PUT_HD(T_VERSION, NOTAG);
	PUT_32(connection->message_size);
	PUT_ST(VERSION);

	/* Send message. */
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}

	/* Handle response. */
	connection->message_size = MIN(connection->message_size,
			GET_32(rx, MSG_VER_MSIZE));

	ver_str = (char *)&rx[MSG_VER_STR];
	ver_len = GET_16(rx, MSG_VER_STR_LEN);
	if (strncmp(UNKNOWN_VER, ver_str, ver_len) == 0) {
		return P9_UNKNOWN_VERSION;
	}


	return 0;
}

/**
 * p9_attach
 *
 * Called to open a connection for a user to a file tree on the server. There
 * is no authorisation undertaken (NOFID).
 *
 * @param connection[in|out]	Connection object, contains uname and aname as
 * 	well as the connection fid and returned qid.
 * @return	0 = success, -ve = error.
 *
 * @remark
 * size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s] n_uname[4]
 * size[4] Rattach tag[2] qid[13]
 */
int p9_attach(p9_connection_t *connection)
{
	int rc;
	int length = 19 + strlen(connection->uname) + strlen(connection->aname);

	if (length > connection->message_size) {
		return P9_MSG_TOO_LONG;
	}

	reset_buffers();

	/* Build message. */
	PUT_HD(T_ATTACH, TAG);
	PUT_32(connection->fid);	
	PUT_32(NOFID);
	PUT_ST(connection->uname);
	PUT_ST(connection->aname);
	PUT_32(~0); /* ??? */

	/* Send message. */
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}


	return 0;
}

/**
 * p9_clunk
 *
 * Called when closing a file or connection (or after failed opens). Tells the
 * server that the supplied fid is no longer needed by this client.
 *
 * @param connection[in|out]	Connection object.
 * @param fid[in]	Fid to be clunked (released) on the server.
 * @return	0 = success, -ve = error.
 *
 * @remark
 * size[4] Tclunk tag[2] fid[4]
 * size[4] Rclunk tag[2]
 */
int p9_clunk(p9_connection_t *connection, uint32_t fid)
{
	int rc;

	reset_buffers();

	/* Build message. */
	PUT_HD(T_CLUNK, TAG);
	PUT_32(fid);

	/* Send message. */
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}


	return 0;
}

/**
 * p9_walk
 *
 * Walk the provided path to a file (or directory) starting at the directory
 * indicated by fid and assigning new_fid to the last successfully walked
 * element. If not all elements of the path can be walked then the pos
 * pointer is set to the part of the path following the last successful
 * walked element. The function can be called again to walk the remainder
 * of the path (or produce an error).
 *
 * @param connection[in]	Connection object.
 * @param fid[in]	Fid to start walk from, must be directory or root (from
 * 	call to p9_attach).
 * @param new_fid[in]	Fid to be used for the last walked element.
 * @param pos[in|out]	Position in path that remains to be walked. If the
 * 	path was completely walked without error this will point to the NULL
 * 	at the end of path.
 * @return	1 = partial walk, 0 = success, -ve = error.
 *
 * @remark
 * size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
 * size[4] Rwalk tag[2] nwqid[2] nwqid*(qid[13])
 */
int p9_walk(p9_connection_t *connection, uint32_t fid, uint32_t new_fid,
		uint8_t **pos)
{
	int rc;
	const char *path = (const char *)*pos;
	uint8_t *s_tok;
	uint8_t *e_tok;
	int element_count = 0;

	if (path == NULL) {
		*pos = NULL;
		return P9_NULL_PATH;
	}

	reset_buffers();

	/* Build message. */
	PUT_HD(T_WALK, TAG);	/* Length to 0, set later. */
	PUT_32(fid);
	PUT_32(new_fid);
	PUT_16(0);		/* Element count to 0, set later. */

	/* Get elements from path, and append to message. */
	s_tok = (uint8_t *)path;
	e_tok = s_tok;

	while (*s_tok != 0) {
		while (*s_tok == '/') {
			s_tok++;
		}
		e_tok = s_tok;
		while ((*e_tok != '/') && (*e_tok != 0)) {
			e_tok++;
		}

		/* Check the element is OK. */
		if (strncmp(".", (const char *)s_tok, (e_tok - s_tok)) == 0) {
			/* Don't send ".", continue to next. */
			s_tok = e_tok;
			continue;
		}
		int tx_size = (e_tok - s_tok + 2 + GET_SIZE);
		int rx_size = ((element_count + 1) * MSG_QID_SIZE
				+ MSG_WALK_RX_HDR_SIZE);
		if ((tx_size > connection->message_size)
			|| (rx_size > connection->message_size)) {
			/*
			 * Element makes TX msg too long OR expected RX msg
			 * too long. Move pos to previous element and do
			 * partial walk.
			 */
			e_tok = s_tok;
			if (*(e_tok - 1) == '/') {
				e_tok--;
			}
			break;
		}

		/* Add the element to the message. */
		PUT_SN(s_tok, e_tok - s_tok);
		element_count++;

		/* Server supports no more than 16 elements, partial walk. */
		if (element_count == MSG_WALK_MAX_ELMT) {
			break;
		}

		/* Ready to find the next element. */
		s_tok = e_tok;
	}

	if ((element_count == 0) && (strlen(path) > 0)) {
		return P9_PATH_ELEMENT_TOO_LONG;
	}

	*pos = e_tok;

	/* Update counts and then send message. */
	SET_16(tx, MSG_WALK_TX_ELMT, element_count);
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}

	/* Check for special return conditions. */
	if (element_count != GET_16(rx, MSG_WALK_RX_ELMT)) {
		/* Find the last element successfully walked */
		s_tok = (uint8_t *)path;
		e_tok = s_tok;
		element_count = GET_16(rx, MSG_WALK_RX_ELMT);

		while (element_count--) {
			while (*s_tok == '/') {
				s_tok++;
			}

			e_tok = s_tok;

			while ((*e_tok != '/') && (*e_tok != 0)) {
				e_tok++;
			}

			s_tok = e_tok;
		}

		*pos = e_tok;
	}
	if (**pos != 0) {
		rc = P9_PARTIAL_WALK;
	}


	return rc;
}

/**
 * p9_open
 *
 * Opens the file represented by fid with associated mode bit mask. The iounit
 * size returned from the server is written to the connection object.
 *
 * @param file[in|out]	File object, contains fid for file.
 * @param mode[in]	Mode to open with. Bit's 0=R, 1=W, 2=RW, 3=EX, 4=Trunc
 * 	and 6=Delete on Close.
 * @return	0 = success, -ve = error.
 *
 * @remark
 * size[4] Topen tag[2] fid[4] mode[1]
 * size[4] Ropen tag[2] qid[13] iounit[4]
 */
int p9_open(p9_file_t *file, uint8_t mode)
{
	int rc;
	p9_connection_t *connection = file->connection;

	reset_buffers();
	file->iounit = 0;

	/* Build message. */
	PUT_HD(T_OPEN, TAG);
	PUT_32(file->fid);
	PUT_08(mode & MSG_OPEN_MODE_MASK);

	/* Send message. */
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}

	/* Handle response. */
	file->iounit = GET_32(rx, MSG_OPEN_IOUNIT);


	return 0;
}

/**
 * p9_read
 *
 * Reads the file in to buffer.
 *
 * @param file[in]	File object, contains fid for file.
 * @param buffer[out]	Buffer for data.
 * @param count[in]	Number of bytes to read (less bytes than requested
 * 	 may be read).
 * @param offset[in]	Offset in file to read from.
 * @return	Bytes read, -ve = error.
 *
 * @remark
 * size[4] Tread tag[2] fid[4] offset[8] count[4]
 * size[4] Rread tag[2] count[4] data[count]
 */
int p9_read(p9_file_t *file, uint8_t *buffer,
		uint32_t count, uint64_t offset)
{
	int rc;
	p9_connection_t *connection = file->connection;
	uint32_t got;

	reset_buffers();
	count = MIN((connection->message_size - MSG_READ_DATA), count);

	/* Build message. */
	PUT_HD(T_READ, TAG);
	PUT_32(file->fid);
	PUT_64(offset);
	PUT_32(count);

	/* Send message. */
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}
	got = GET_32(rx, MSG_READ_COUNT);
	if (got > count) {
		return P9_READ_UNEXPECTED_DATA;
	}

	/* Handle response. */
	memcpy(buffer, &rx[MSG_READ_DATA], got);

	return got;
}

/**
 * p9_stat
 *
 * Stat's the fid and writes the type and length to the file object.
 *
 * @param file[in|out]	File object, contains fid for file.
 * @return	0 = success, -ve = error.
 *
 * @remark
 * size[4] Tstat tag[2] fid[4]
 * size[4] Rstat tag[2] size[2] stat[n]
 */
int p9_stat(p9_file_t *file)
{
	int rc;
	p9_connection_t *connection = file->connection;

	reset_buffers();
	file->length = 0;
	file->type = 0;

	/* Build message. */
	PUT_HD(T_STAT, TAG);
	PUT_32(file->fid);

	/* Send message. */
	rc = p9_transaction(connection);
	if (rc != 0) {
		return rc;
	}

	/* Handle response. */
	file->length = GET_64(rx, MSG_STAT_LEN);
	file->type = GET_08(rx, MSG_STAT_TYPE);


	return 0;
}
