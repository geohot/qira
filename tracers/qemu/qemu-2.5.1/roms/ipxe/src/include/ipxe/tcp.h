#ifndef _IPXE_TCP_H
#define _IPXE_TCP_H

/** @file
 *
 * TCP protocol
 *
 * This file defines the iPXE TCP API.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tcpip.h>

/**
 * A TCP header
 */
struct tcp_header {
	uint16_t src;		/* Source port */
	uint16_t dest;		/* Destination port */
	uint32_t seq;		/* Sequence number */
	uint32_t ack;		/* Acknowledgement number */
	uint8_t hlen;		/* Header length (4), Reserved (4) */
	uint8_t flags;		/* Reserved (2), Flags (6) */
	uint16_t win;		/* Advertised window */
	uint16_t csum;		/* Checksum */
	uint16_t urg;		/* Urgent pointer */
};

/** @defgroup tcpopts TCP options
 * @{
 */

/** End of TCP options list */
#define TCP_OPTION_END 0

/** TCP option pad */
#define TCP_OPTION_NOP 1

/** Generic TCP option */
struct tcp_option {
	uint8_t kind;
	uint8_t length;
} __attribute__ (( packed ));

/** TCP MSS option */
struct tcp_mss_option {
	uint8_t kind;
	uint8_t length;
	uint16_t mss;
} __attribute__ (( packed ));

/** Code for the TCP MSS option */
#define TCP_OPTION_MSS 2

/** TCP window scale option */
struct tcp_window_scale_option {
	uint8_t kind;
	uint8_t length;
	uint8_t scale;
} __attribute__ (( packed ));

/** Padded TCP window scale option (used for sending) */
struct tcp_window_scale_padded_option {
	uint8_t nop;
	struct tcp_window_scale_option wsopt;
} __attribute (( packed ));

/** Code for the TCP window scale option */
#define TCP_OPTION_WS 3

/** Advertised TCP window scale
 *
 * Using a scale factor of 2**9 provides for a maximum window of 32MB,
 * which is sufficient to allow Gigabit-speed transfers with a 200ms
 * RTT.  The minimum advertised window is 512 bytes, which is still
 * less than a single packet.
 */
#define TCP_RX_WINDOW_SCALE 9

/** TCP selective acknowledgement permitted option */
struct tcp_sack_permitted_option {
	uint8_t kind;
	uint8_t length;
} __attribute__ (( packed ));

/** Padded TCP selective acknowledgement permitted option (used for sending) */
struct tcp_sack_permitted_padded_option {
	uint8_t nop[2];
	struct tcp_sack_permitted_option spopt;
} __attribute__ (( packed ));

/** Code for the TCP selective acknowledgement permitted option */
#define TCP_OPTION_SACK_PERMITTED 4

/** TCP selective acknowledgement option */
struct tcp_sack_option {
	uint8_t kind;
	uint8_t length;
} __attribute__ (( packed ));

/** TCP selective acknowledgement block */
struct tcp_sack_block {
	uint32_t left;
	uint32_t right;
} __attribute__ (( packed ));

/** Maximum number of selective acknowledgement blocks
 *
 * This allows for the presence of the TCP timestamp option.
 */
#define TCP_SACK_MAX 3

/** Padded TCP selective acknowledgement option (used for sending) */
struct tcp_sack_padded_option {
	uint8_t nop[2];
	struct tcp_sack_option sackopt;
} __attribute__ (( packed ));

/** Code for the TCP selective acknowledgement option */
#define TCP_OPTION_SACK 5

/** TCP timestamp option */
struct tcp_timestamp_option {
	uint8_t kind;
	uint8_t length;
	uint32_t tsval;
	uint32_t tsecr;
} __attribute__ (( packed ));

/** Padded TCP timestamp option (used for sending) */
struct tcp_timestamp_padded_option {
	uint8_t nop[2];
	struct tcp_timestamp_option tsopt;
} __attribute__ (( packed ));

/** Code for the TCP timestamp option */
#define TCP_OPTION_TS 8

/** Parsed TCP options */
struct tcp_options {
	/** MSS option, if present */
	const struct tcp_mss_option *mssopt;
	/** Window scale option, if present */
	const struct tcp_window_scale_option *wsopt;
	/** SACK permitted option, if present */
	const struct tcp_sack_permitted_option *spopt;
	/** Timestamp option, if present */
	const struct tcp_timestamp_option *tsopt;
};

/** @} */

/*
 * TCP flags
 */
#define TCP_CWR		0x80
#define TCP_ECE		0x40
#define TCP_URG		0x20
#define TCP_ACK		0x10
#define TCP_PSH		0x08
#define TCP_RST		0x04
#define TCP_SYN		0x02
#define TCP_FIN		0x01

/**
* @defgroup tcpstates TCP states
*
* The TCP state is defined by a combination of the flags that have
* been sent to the peer, the flags that have been acknowledged by the
* peer, and the flags that have been received from the peer.
*
* @{
*/

/** TCP flags that have been sent in outgoing packets */
#define TCP_STATE_SENT(flags) ( (flags) << 0 )
#define TCP_FLAGS_SENT(state) ( ( (state) >> 0 ) & 0xff )

/** TCP flags that have been acknowledged by the peer
 *
 * Note that this applies only to SYN and FIN.
 */
#define TCP_STATE_ACKED(flags) ( (flags) << 8 )
#define TCP_FLAGS_ACKED(state) ( ( (state) >> 8 ) & 0xff )

/** TCP flags that have been received from the peer
 *
 * Note that this applies only to SYN and FIN, and that once SYN has
 * been received, we should always be sending ACK.
 */
#define TCP_STATE_RCVD(flags) ( (flags) << 16 )
#define TCP_FLAGS_RCVD(state) ( ( (state) >> 16 ) & 0xff )

/** TCP flags that are currently being sent in outgoing packets */
#define TCP_FLAGS_SENDING(state) \
	( TCP_FLAGS_SENT ( state ) & ~TCP_FLAGS_ACKED ( state ) )

/** CLOSED
 *
 * The connection has not yet been used for anything.
 */
#define TCP_CLOSED TCP_RST

/** LISTEN
 *
 * Not currently used as a state; we have no support for listening
 * connections.  Given a unique value to avoid compiler warnings.
 */
#define TCP_LISTEN 0

/** SYN_SENT
 *
 * SYN has been sent, nothing has yet been received or acknowledged.
 */
#define TCP_SYN_SENT	( TCP_STATE_SENT ( TCP_SYN ) )

/** SYN_RCVD
 *
 * SYN has been sent but not acknowledged, SYN has been received.
 */
#define TCP_SYN_RCVD	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK ) |	    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** ESTABLISHED
 *
 * SYN has been sent and acknowledged, SYN has been received.
 */
#define TCP_ESTABLISHED	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK ) |	    \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** FIN_WAIT_1
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent but not acknowledged, FIN has not been received.
 *
 * RFC 793 shows that we can enter FIN_WAIT_1 without have had SYN
 * acknowledged, i.e. if the application closes the connection after
 * sending and receiving SYN, but before having had SYN acknowledged.
 * However, we have to *pretend* that SYN has been acknowledged
 * anyway, otherwise we end up sending SYN and FIN in the same
 * sequence number slot.  Therefore, when we transition from SYN_RCVD
 * to FIN_WAIT_1, we have to remember to set TCP_STATE_ACKED(TCP_SYN)
 * and increment our sequence number.
 */
#define TCP_FIN_WAIT_1	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** FIN_WAIT_2
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent and acknowledged, FIN ha not been received.
 */
#define TCP_FIN_WAIT_2	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN | TCP_FIN ) |	    \
			  TCP_STATE_RCVD ( TCP_SYN ) )

/** CLOSING / LAST_ACK
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent but not acknowledged, FIN has been received.
 *
 * This state actually encompasses both CLOSING and LAST_ACK; they are
 * identical with the definition of state that we use.  I don't
 * *believe* that they need to be distinguished.
 */
#define TCP_CLOSING_OR_LAST_ACK						    \
			( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN | TCP_FIN ) )

/** TIME_WAIT
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been sent and acknowledged, FIN has been received.
 */
#define TCP_TIME_WAIT	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK | TCP_FIN ) |  \
			  TCP_STATE_ACKED ( TCP_SYN | TCP_FIN ) |	    \
			  TCP_STATE_RCVD ( TCP_SYN | TCP_FIN ) )

/** CLOSE_WAIT
 *
 * SYN has been sent and acknowledged, SYN has been received, FIN has
 * been received.
 */
#define TCP_CLOSE_WAIT	( TCP_STATE_SENT ( TCP_SYN | TCP_ACK ) |	    \
			  TCP_STATE_ACKED ( TCP_SYN ) |			    \
			  TCP_STATE_RCVD ( TCP_SYN | TCP_FIN ) )

/** Can send data in current state
 *
 * We can send data if and only if we have had our SYN acked and we
 * have not yet sent our FIN.
 */
#define TCP_CAN_SEND_DATA(state)					    \
	( ( (state) & ( TCP_STATE_ACKED ( TCP_SYN ) |			    \
			TCP_STATE_SENT ( TCP_FIN ) ) )			    \
	  == TCP_STATE_ACKED ( TCP_SYN ) )

/** Have ever been fully established
 *
 * We have been fully established if we have both received a SYN and
 * had our own SYN acked.
 */
#define TCP_HAS_BEEN_ESTABLISHED(state)					    \
	( ( (state) & ( TCP_STATE_ACKED ( TCP_SYN ) |			    \
			TCP_STATE_RCVD ( TCP_SYN ) ) )			    \
	  == ( TCP_STATE_ACKED ( TCP_SYN ) | TCP_STATE_RCVD ( TCP_SYN ) ) )

/** Have closed gracefully
 *
 * We have closed gracefully if we have both received a FIN and had
 * our own FIN acked.
 */
#define TCP_CLOSED_GRACEFULLY(state)					    \
	( ( (state) & ( TCP_STATE_ACKED ( TCP_FIN ) |			    \
			TCP_STATE_RCVD ( TCP_FIN ) ) )			    \
	  == ( TCP_STATE_ACKED ( TCP_FIN ) | TCP_STATE_RCVD ( TCP_FIN ) ) )

/** @} */

/** Mask for TCP header length field */
#define TCP_MASK_HLEN	0xf0

/** Smallest port number on which a TCP connection can listen */
#define TCP_MIN_PORT 1

/**
 * Maxmimum advertised TCP window size
 *
 * The maximum bandwidth on any link is limited by
 *
 *    max_bandwidth * round_trip_time = tcp_window
 *
 * Some rough expectations for achievable bandwidths over various
 * links are:
 *
 *    a) Gigabit LAN: expected bandwidth 125MB/s, typical RTT 0.5ms,
 *       minimum required window 64kB
 *
 *    b) Home Internet connection: expected bandwidth 10MB/s, typical
 *       RTT 25ms, minimum required window 256kB
 *
 *    c) WAN: expected bandwidth 2MB/s, typical RTT 100ms, minimum
 *       required window 200kB.
 *
 * The maximum possible value for the TCP window size is 1GB (using
 * the maximum window scale of 2**14).  However, it is advisable to
 * keep the window size as small as possible (without limiting
 * bandwidth), since in the event of a lost packet the window size
 * represents the maximum amount that will need to be retransmitted.
 *
 * We therefore choose a maximum window size of 256kB.
 */
#define TCP_MAX_WINDOW_SIZE	( 256 * 1024 )

/**
 * Path MTU
 *
 * IPv6 requires all data link layers to support a datagram size of
 * 1280 bytes.  We choose to use this as our maximum transmitted
 * datagram size, on the assumption that any practical link layer we
 * encounter will allow this size.  This is a very conservative
 * assumption in practice, but the impact of making such a
 * conservative assumption is insignificant since the amount of data
 * that we transmit (rather than receive) is negligible.
 *
 * We allow space within this 1280 bytes for an IPv6 header, a TCP
 * header, and a (padded) TCP timestamp option.
 */
#define TCP_PATH_MTU							\
	( 1280 - 40 /* IPv6 */ - 20 /* TCP */ - 12 /* TCP timestamp */ )

/** TCP maximum segment lifetime
 *
 * Currently set to 2 minutes, as per RFC 793.
 */
#define TCP_MSL ( 2 * 60 * TICKS_PER_SEC )

/**
 * TCP maximum header length
 *
 */
#define TCP_MAX_HEADER_LEN					\
	( MAX_LL_NET_HEADER_LEN +				\
	  sizeof ( struct tcp_header ) +			\
	  sizeof ( struct tcp_mss_option ) +			\
	  sizeof ( struct tcp_window_scale_padded_option ) +	\
	  sizeof ( struct tcp_timestamp_padded_option ) )

/**
 * Compare TCP sequence numbers
 *
 * @v seq1		Sequence number 1
 * @v seq2		Sequence number 2
 * @ret diff		Sequence difference
 *
 * Analogous to memcmp(), returns an integer less than, equal to, or
 * greater than zero if @c seq1 is found, respectively, to be before,
 * equal to, or after @c seq2.
 */
static inline __attribute__ (( always_inline )) int32_t
tcp_cmp ( uint32_t seq1, uint32_t seq2 ) {
	return ( ( int32_t ) ( seq1 - seq2 ) );
}

/**
 * Check if TCP sequence number lies within window
 *
 * @v seq		Sequence number
 * @v start		Start of window
 * @v len		Length of window
 * @ret in_window	Sequence number is within window
 */
static inline int tcp_in_window ( uint32_t seq, uint32_t start,
				  uint32_t len ) {
	return ( ( seq - start ) < len );
}

/** TCP finish wait time
 *
 * Currently set to one second, since we should not allow a slowly
 * responding server to substantially delay a call to shutdown().
 */
#define TCP_FINISH_TIMEOUT ( 1 * TICKS_PER_SEC )

extern struct tcpip_protocol tcp_protocol __tcpip_protocol;

#endif /* _IPXE_TCP_H */
