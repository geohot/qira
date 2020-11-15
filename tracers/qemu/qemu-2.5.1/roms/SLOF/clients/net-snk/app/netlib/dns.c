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

/********************** DEFINITIONS & DECLARATIONS ***********************/

#include <dns.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include <ethernet.h>
#include <ipv4.h>
#include <ipv6.h>
#include <udp.h>

#define DNS_FLAG_MSGTYPE    0xF800	/**< Message type mask (opcode) */
#define DNS_FLAG_SQUERY     0x0000 	/**< Standard query type        */
#define DNS_FLAG_SRESPONSE  0x8000	/**< Standard response type     */
#define DNS_FLAG_RD         0x0100  /**< Recursion desired flag     */
#define DNS_FLAG_RCODE      0x000F	/**< Response code mask
                                         (stores err.cond.) code    */
#define DNS_RCODE_NERROR    0       /**< "No errors" code           */

#define DNS_QTYPE_A         1       /**< A 32-bit IP record type */
#define DNS_QTYPE_AAAA      0x1c    /**< 128-bit IPv6 record type */
#define DNS_QTYPE_CNAME     5       /**< Canonical name record type */

#define DNS_QCLASS_IN       1       /**< Query class for internet msgs */

/** \struct dnshdr
 *  A header for DNS-messages (see RFC 1035, paragraph 4.1.1).
 *  <p>
 *  DNS-message consist of DNS-header and 4 optional sections,
 *  arranged in the following order:<ul>
 *    <li> DNS-header
 *    <li> question section
 *    <li> answer section
 *    <li> authority section
 *    <li> additional section
 *  </ul>
 */
struct dnshdr {
	uint16_t   id;      /**< an identifier used to match up replies */
	uint16_t   flags;   /**< contains op_code, err_code, etc. */
	uint16_t   qdcount; /**< specifies the number of entries in the 
	                         question section */
	uint16_t   ancount; /**< specifies the number of entries in the 
	                         answer section */
	uint16_t   nscount; /**< specifies the number of entries in the
	                         authority section */
	uint16_t   arcount; /**< specifies the number of entries in the 
	                         additional section */
};


/***************************** PROTOTYPES ********************************/

static void
dns_send_query(int fd, int8_t * domain_name, uint8_t ip_version);

static void
fill_dnshdr(uint8_t * packet, int8_t * domain_name, uint8_t ip_version);

static uint8_t *
dns_extract_name(uint8_t * dnsh, int8_t * head, int8_t * domain_name);

static int8_t
urltohost(char * url, char * host_name);

static int8_t
hosttodomain(char * host_name, char * domain_name);

/**************************** LOCAL VARIABLES ****************************/

static uint8_t ether_packet[ETH_MTU_SIZE];
static int32_t dns_server_ip       = 0;
static uint8_t dns_server_ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static int32_t dns_result_ip       = 0;
static uint8_t dns_result_ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static int8_t  dns_error           = 0;        /**< Stores error code or 0 */
static int8_t  dns_domain_name[0x100];       /**< Raw domain name        */
static int8_t  dns_domain_cname[0x100];      /**< Canonical domain name  */

/**************************** IMPLEMENTATION *****************************/

/**
 * DNS: Initialize the environment for DNS client.
 *      To perfrom DNS-queries use the function dns_get_ip.
 *
 * @param  device_socket a socket number used to send and receive packets
 * @param  server_ip     DNS-server IPv4 address (e.g. 127.0.0.1)
 * @return               TRUE in case of successful initialization;
 *                       FALSE in case of fault (e.g. can't obtain MAC).
 * @see                  dns_get_ip
 */
int8_t
dns_init(uint32_t _dns_server_ip, uint8_t _dns_server_ipv6[16], uint8_t ip_version)
{
	if(ip_version == 6)
		memcpy(dns_server_ipv6, _dns_server_ipv6, 16);
	else
		dns_server_ip = _dns_server_ip;
	return 0;
}

/**
 * DNS: For given URL retrieves IPv4/IPv6 from DNS-server.
 *      <p>
 *      URL can be given in one of the following form: <ul>
 *      <li> scheme with full path with (without) user and password
 *           <br>(e.g. "http://user:pass@www.host.org/url-path");
 *      <li> host name with url-path
 *           <br>(e.g. "www.host.org/url-path");
 *      <li> nothing but host name
 *           <br>(e.g. "www.host.org");
 *      </ul>
 *
 * @param  fd        socket descriptor
 * @param  url       the URL to be resolved
 * @param  domain_ip In case of SUCCESS stores extracted IP.
 *                   In case of FAULT stores zeros (0.0.0.0).
 * @return           TRUE - IP successfuly retrieved;
 *                   FALSE - error condition occurs.
 */
int8_t
dns_get_ip(int fd, int8_t * url, uint8_t * domain_ip, uint8_t ip_version)
{
	/* this counter is used so that we abort after 30 DNS request */
	int32_t i;
	/* this buffer stores host name retrieved from url */
	static int8_t host_name[0x100];

	(* domain_ip) = 0;

	// Retrieve host name from URL
	if (!urltohost((char *) url, (char *) host_name)) {
		printf("\nERROR:\t\t\tBad URL!\n");
		return 0;
	}

	// Reformat host name into a series of labels
	if (!hosttodomain((char *) host_name, (char *) dns_domain_name)) {
		printf("\nERROR:\t\t\tBad host name!\n");
		return 0;
	}

	// Check if DNS server is presented and accessible
	if (dns_server_ip == 0) {
		printf("\nERROR:\t\t\tCan't resolve domain name "
		       "(DNS server is not presented)!\n");
		return 0;
	}

	// Use DNS-server to obtain IP
	if (ip_version == 6)
		memset(dns_result_ipv6, 0, 16);
	else
		dns_result_ip = 0;
	dns_error = 0;
	strcpy((char *) dns_domain_cname, "");

	for(i = 0; i < 30; ++i) {
		// Use canonical name in case we obtained it
		if (strlen((char *) dns_domain_cname))
			dns_send_query(fd, dns_domain_cname, ip_version);
		else
			dns_send_query(fd, dns_domain_name, ip_version);

		// setting up a timer with a timeout of one seconds
		set_timer(TICKS_SEC);
		do {
			receive_ether(fd);
			if (dns_error)
				return 0; // FALSE - error
			if ((dns_result_ip != 0) && (ip_version == 4)) {
				memcpy(domain_ip, &dns_result_ip, 4);
				return 1; // TRUE - success (domain IP retrieved)
			}
			else if ((dns_result_ipv6[0] != 0) && (ip_version == 6)) {
				memcpy(domain_ip, dns_result_ipv6, 16);
				return 1; // TRUE - success (domain IP retrieved)
			}
		} while (get_timer() > 0);
	}

	printf("\nGiving up after %d DNS requests\n", i);
	return 0; // FALSE - domain name wasn't retrieved
}

/**
 * DNS: Handles DNS-messages according to Receive-handle diagram.
 *      Sets dns_result_ip for given dns_domain_name (see dns_get_ip)
 *      or signals error condition occurs during DNS-resolving process
 *      by setting dns_error flag.
 *
 * @param  packet     DNS-packet to be handled
 * @param  packetsize length of the packet
 * @return            ZERO - packet handled successfully;
 *                    NON ZERO - packet was not handled (e.g. bad format)
 * @see               dns_get_ip
 * @see               receive_ether
 * @see               dnshdr
 */
int32_t
handle_dns(uint8_t * packet, int32_t packetsize)
{
	struct dnshdr * dnsh = (struct dnshdr *) packet;
	uint8_t * resp_section = packet + sizeof(struct dnshdr);
	/* This string stores domain name from DNS-packets */
	static int8_t handle_domain_name[0x100]; 
	int i;

	// verify ID - is it response for our query?
	if (dnsh -> id != htons(0x1234))
		return 0;

	// Is it DNS response?
	if ((dnsh -> flags & htons(DNS_FLAG_MSGTYPE)) != htons(DNS_FLAG_SRESPONSE))
		return 0;

	// Is error condition occurs? (check error field in incoming packet)
	if ((dnsh -> flags & htons(DNS_FLAG_RCODE)) != DNS_RCODE_NERROR) {
		dns_error = 1;
		return 0;
	}

	/*        Pass all (qdcount) records in question section         */

	for (i = 0; i < htons(dnsh -> qdcount); i++) {
		// pass QNAME
		resp_section = dns_extract_name((uint8_t *) dnsh, (int8_t *) resp_section,
		                                handle_domain_name);
		if (resp_section == NULL) {
			return -1; // incorrect domain name (bad packet)
		}
		// pass QTYPE & QCLASS
		resp_section += 4;
	}

	/*       Handle all (ancount) records in answer section          */

	for (i = 0; i < htons(dnsh -> ancount); i++) {
		// retrieve domain name from the packet
		resp_section = dns_extract_name((uint8_t *) dnsh, (int8_t *) resp_section,
		                                handle_domain_name);

		if (resp_section == NULL) {
			return -1; // incorrect domain name (bad packet)
		}

		// Check the class of the query (should be IN for Internet)
		if (* (uint16_t *) (resp_section + 2) == htons(DNS_QCLASS_IN)) {
			// check if retrieved name fit raw or canonical domain name
			if (!strcmp((char *) handle_domain_name, (char *) dns_domain_name) ||
				!strcmp((char *) handle_domain_name, (char *) dns_domain_cname)) {
				switch (htons(* (uint16_t *) resp_section)) {

				case DNS_QTYPE_A :
					// rdata contains IP
					dns_result_ip = htonl(* (uint32_t *) (resp_section + 10));
					return 0; // IP successfully obtained

				case DNS_QTYPE_CNAME :
					// rdata contains canonical name, store it for further requests
					if (dns_extract_name((uint8_t *) dnsh, (int8_t *) resp_section + 10,
					                     dns_domain_cname) == NULL) {
						// incorrect domain name (bad packet)
						return -1;
					}
					break;
                                case DNS_QTYPE_AAAA :
                                        memcpy(dns_result_ipv6, (resp_section + 10), 16);
                                        return 0; // IP successfully obtained
                                        break;
				}
			}
			// continue with next record in answer section
			resp_section += htons(* (uint16_t *) (resp_section + 8)) + 10;
		}
	}
	return 0; // Packet successfully handled but IP wasn't obtained
}

/**
 * DNS: Sends a standard DNS-query (read request package) to a DNS-server.
 *      DNS-server respones with host IP or signals some error condition.
 *      Responses from the server are handled by handle_dns function.
 *
 * @param  fd          socket descriptor
 * @param  domain_name the domain name given as series of labels preceded
 *                     with length(label) and terminated with 0  
 *                     <br>(e.g. "\3,w,w,w,\4,h,o,s,t,\3,o,r,g,\0")
 * @see                handle_dns
 */
static void
dns_send_query(int fd, int8_t * domain_name, uint8_t ip_version)
{
	int qry_len = strlen((char *) domain_name) + 5;
	int iphdr_len = (ip_version == 4) ? sizeof(struct iphdr) : sizeof(struct ip6hdr);
	ip6_addr_t server_ipv6;

	uint32_t packetsize = iphdr_len +
	                      sizeof(struct udphdr) + sizeof(struct dnshdr) +
	                      qry_len;

	memset(ether_packet, 0, packetsize);
	fill_dnshdr(&ether_packet[
	            iphdr_len + sizeof(struct udphdr)],
	            domain_name,
		    ip_version);
	fill_udphdr(&ether_packet[iphdr_len],
		    sizeof(struct dnshdr) +
		    sizeof(struct udphdr) + qry_len,
	            UDPPORT_DNSC, UDPPORT_DNSS);
	if (ip_version == 4) {
		fill_iphdr(ether_packet,
			   sizeof(struct dnshdr) + sizeof(struct udphdr) +
			   iphdr_len + qry_len,
			   IPTYPE_UDP, 0, dns_server_ip);
	} else {
		memcpy(server_ipv6.addr, dns_server_ipv6, 16);
		fill_ip6hdr(ether_packet,
			    sizeof(struct dnshdr) + sizeof(struct udphdr) + qry_len,
			    IPTYPE_UDP, get_ipv6_address(),
			    &server_ipv6);
	}

	send_ip(fd, ether_packet, packetsize);
}

/**
 * DNS: Creates standard DNS-query package. Places DNS-header
 *      and question section in a packet and fills it with
 *      corresponding information.
 *      <p>
 *      Use this function with similar functions for other network layers
 *      (fill_udphdr, fill_iphdr, fill_ethhdr).
 *
 * @param  packet      Points to the place where ARP-header must be placed.
 * @param  domain_name the domain name given as series of labels preceded
 *                     with length(label) and terminated with 0  
 *                     <br>(e.g. "\3,w,w,w,\4,h,o,s,t,\3,o,r,g,\0")
 * @see                fill_udphdr
 * @see                fill_iphdr
 * @see                fill_ethhdr
 */
static void
fill_dnshdr(uint8_t * packet, int8_t * domain_name, uint8_t ip_version)
{
	struct dnshdr * dnsh = (struct dnshdr *) packet;
	uint8_t * qry_section = packet + sizeof(struct dnshdr);

	dnsh -> id = htons(0x1234);
	dnsh -> flags = htons(DNS_FLAG_SQUERY) | htons(DNS_FLAG_RD);
	dnsh -> qdcount = htons(1);

	strcpy((char *) qry_section, (char *) domain_name);
	qry_section += strlen((char *) domain_name) + 1;

	// fill QTYPE (ask for IP)
	if (ip_version == 4)
		* (uint16_t *) qry_section = htons(DNS_QTYPE_A);
	else
		* (uint16_t *) qry_section = htons(DNS_QTYPE_AAAA);
	qry_section += 2;
	// fill QCLASS (IN is a standard class for Internet)
	* (uint16_t *) qry_section = htons(DNS_QCLASS_IN);
}

/**
 * DNS: Extracts domain name from the question or answer section of
 *      the DNS-message. This function is need to support message  
 *      compression requirement (see RFC 1035, paragraph 4.1.4).
 *
 * @param  dnsh        Points at the DNS-header.
 * @param  head        Points at the beginning of the domain_name
 *                     which has to be extracted.
 * @param  domain_name In case of SUCCESS this string stores extracted name.
 *                     In case of FAULT this string is empty.
 * @return             NULL in case of FAULT (domain name > 255 octets); 
 *                     otherwise pointer to the data following the name.
 * @see                dnshdr
 */
static uint8_t *
dns_extract_name(uint8_t * dnsh, int8_t * head, int8_t * domain_name)
{
	int8_t * tail = domain_name;
	int8_t * ptr = head;
	int8_t * next_section = NULL;

	while (1) {
		if ((ptr[0] & 0xC0) == 0xC0) {
			// message compressed (reference is used)
			next_section = ptr + 2;
			ptr = (int8_t *) dnsh + (htons(* (uint16_t *) ptr) & 0x3FFF);
			continue;
		}
		if (ptr[0] == 0) {
			// message termination
			tail[0] = 0;
			ptr += 1;
			break;
		}
		// maximum length for domain name is 255 octets w/o termination sym
		if (tail - domain_name + ptr[0] + 1 > 255) {
			strcpy((char *) domain_name, "");
			return NULL;
		}
		memcpy(tail, ptr, ptr[0] + 1);
		tail += ptr[0] + 1;
		ptr += ptr[0] + 1;
	}

	if (next_section == NULL)
		next_section = ptr;

	return (uint8_t *) next_section;
}

/**
 * DNS: Parses URL and returns host name.
 *      Input string can be given as: <ul>
 *      <li> scheme with full path with (without) user and password
 *           <br>(e.g. "http://user:pass@www.host.org/url-path");
 *      <li> host name with url-path
 *           <br>(e.g. "www.host.org/url-path");
 *      <li> nothing but host name
 *           <br>(e.g. "www.host.org");
 *      </ul>
 *
 * @param  url        string that stores incoming URL
 * @param  host_name  In case of SUCCESS this string stores the host name,
 *                    In case of FAULT this string is empty.
 * @return            TRUE - host name retrieved,
 *                    FALSE - host name > 255 octets or empty.
 */
static int8_t
urltohost(char * url, char * host_name)
{
	uint16_t length1;
	uint16_t length2;

	strcpy(host_name, "");

	if (strstr(url, "://") != NULL)
		url = strstr(url, "//") + 2;  // URL

	if (strstr(url, "@") != NULL) // truncate user & password
		url = strstr(url, "@") + 1;

	if (strstr(url, "/") != NULL) // truncate url path
		length1 = strstr(url, "/") - url;
	else
		length1 = strlen(url);

	if (strstr(url, ":") != NULL) // truncate port path
		length2 = strstr(url, ":") - url;
	else
		length2 = strlen(url);

	if(length1 > length2)
		length1 = length2;

	if (length1 == 0)
		return 0; // string is empty
	if(length1 >= 256)
		return 0; // host name is too big

	strncpy(host_name, url, length1);
	host_name[length1] = 0;

	return 1; // Host name is retrieved
}

/**
 * DNS: Transforms host name string into a series of labels
 *      each of them preceded with length(label). 0 is a terminator.
 *      "www.domain.dom" -> "\3,w,w,w,\6,d,o,m,a,i,n,\3,c,o,m,\0"
 *      <p>
 *      This format is used in DNS-messages.
 *
 * @param  host_name   incoming string with the host name
 * @param  domain_name resulting string with series of labels
 *                     or empty string in case of FAULT
 * @return             TRUE - host name transformed,
 *                     FALSE - host name > 255 octets or label > 63 octets.
 */
static int8_t
hosttodomain(char * host_name, char * domain_name)
{
	char * domain_iter = domain_name;
	char * host_iter   = host_name;

	strcpy(domain_name, "");

	if(strlen(host_name) > 255)
		return 0; // invalid host name (refer to RFC 1035)

	for(; 1; ++host_iter) {
		if(*host_iter != '.' && *host_iter != 0)
			continue;
		*domain_iter = host_iter - host_name;
		if (*domain_iter > 63) {
			strcpy(domain_name, "");
			return 0; // invalid host name (refer to RFC 1035)
		}
		++domain_iter;
		strncpy(domain_iter, host_name, host_iter - host_name);
		domain_iter += (host_iter - host_name);
		if(*host_iter == 0) {
			*domain_iter = 0;
			break;
		}
		host_name = host_iter + 1;
	}
	return 1; // ok
}
