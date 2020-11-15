/******************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <netlib/ethernet.h>
#include <netlib/ipv6.h>
#include <netlib/udp.h>
#include <netlib/dhcpv6.h>
#include <netlib/tftp.h>
#include <netlib/dns.h>

static uint8_t tid[3];
static uint32_t dhcpv6_state = -1;
static filename_ip_t *my_fn_ip;

static void
generate_transaction_id(void)
{
	/* TODO: as per RFC 3315 transaction IDs should be generated randomly */
	tid[0] = 1;
	tid[1] = 2;
	tid[2] = 4;
}

static void
send_info_request(int fd)
{
	uint8_t ether_packet[ETH_MTU_SIZE];
	uint32_t payload_length;
	struct dhcp_message_header *dhcph;

	memset(ether_packet, 0, ETH_MTU_SIZE);

	generate_transaction_id();

	/* Get an IPv6 packet */
	payload_length = sizeof(struct udphdr) + sizeof(struct dhcp_message_header);
	fill_ip6hdr (ether_packet + sizeof(struct ethhdr),
		     payload_length, IPTYPE_UDP,
		     get_ipv6_address(), &(all_dhcpv6_ll.addr));
	fill_udphdr ( ether_packet + sizeof(struct ethhdr) + sizeof(struct ip6hdr),
		      payload_length, DHCP_CLIENT_PORT, DHCP_SERVER_PORT);
	dhcph = (struct dhcp_message_header *) (ether_packet +
						sizeof(struct ethhdr) +
						sizeof(struct ip6hdr) +
						sizeof(struct udphdr));

	/* Fill in DHCPv6 data */
	dhcph->type = DHCP_INFORMATION_REQUEST;
	memcpy( &(dhcph->transaction_id), &tid, 3);
	dhcph->option.client_id.code = DHCPV6_OPTION_CLIENTID;
	dhcph->option.client_id.length = 10;
	dhcph->option.client_id.duid_type = DUID_LL;
	dhcph->option.client_id.hardware_type = 1;
	memcpy( &(dhcph->option.client_id.mac),
		get_mac_address(), 6);
	dhcph->option.el_time.code = DHCPV6_OPTION_ELAPSED_TIME;
	dhcph->option.el_time.length = 2;
	dhcph->option.el_time.time = 0x190; /* 4000 ms */
	dhcph->option.option_request_option.code = DHCPV6_OPTION_ORO;
	dhcph->option.option_request_option.length= 6;
	dhcph->option.option_request_option.option_code[0] = DHCPV6_OPTION_DNS_SERVERS;
	dhcph->option.option_request_option.option_code[1] = DHCPV6_OPTION_DOMAIN_LIST;
	dhcph->option.option_request_option.option_code[2] = DHCPV6_OPTION_BOOT_URL;


	send_ipv6(fd, ether_packet + sizeof(struct ethhdr),
	         sizeof(struct ethhdr)+ sizeof(struct ip6hdr)
		 + sizeof(struct udphdr)
	         + sizeof( struct dhcp_message_header) );
}

static int32_t
dhcpv6_attempt(int fd)
{
	int sec;

	// Send information request
	send_info_request(fd);

	dhcpv6_state = DHCPV6_STATE_SELECT;

	// setting up a timer with a timeout of two seconds
	for (sec = 0; sec < 2; sec++) {
		set_timer(TICKS_SEC);
		do {
			receive_ether(fd);

			// Wait until client will switch to Final state or Timeout occurs
			switch (dhcpv6_state) {
			case DHCP_STATUSCODE_SUCCESS:
				return 1;
			case DHCP_STATUSCODE_UNSPECFAIL: //FIXME
				return 0;
			}
		} while (get_timer() > 0);
	}

	// timeout
	return 0;
}

int32_t
dhcpv6 ( char *ret_buffer, void *fn_ip)
{
	int fd;

	my_fn_ip = (filename_ip_t *) fn_ip;
	fd = my_fn_ip->fd;

	if( !dhcpv6_attempt(fd)) {
		return -1;
	}

	return 0;
}

static struct dhcp6_received_options *
dhcp6_process_options (uint8_t *option, int32_t option_length)
{
	struct dhcp_boot_url *option_boot_url;
	struct client_identifier *option_clientid;
	struct server_identifier *option_serverid;
	struct dhcp_dns *option_dns;
	struct dhcp_dns_list *option_dns_list;
	struct dhcp6_gen_option *option_gen;
	struct dhcp6_received_options *received_options;
	char buffer[256];


	received_options = malloc (sizeof(struct dhcp6_received_options));
	while (option_length > 0) {
		switch ((uint16_t) *(option+1)) {
		case DHCPV6_OPTION_CLIENTID:
			option_clientid = (struct client_identifier *) option;
			option = option +  option_clientid->length + 4;
			option_length = option_length - option_clientid->length - 4;
			received_options->client_id = 1;
			break;
		case DHCPV6_OPTION_SERVERID:
			option_serverid = (struct server_identifier *) option;
			option = option +  option_serverid->length + 4;
			option_length = option_length - option_serverid->length - 4;
			received_options->server_id = 1;
			break;
		case DHCPV6_OPTION_DNS_SERVERS:
			option_dns = (struct dhcp_dns *) option;
			option = option +  option_dns->length + 4;
			option_length = option_length - option_dns->length - 4;
			memcpy( &(my_fn_ip->dns_ip6),
				option_dns->p_ip6,
				IPV6_ADDR_LENGTH);
			dns_init(0, option_dns->p_ip6, 6);
			break;
		case DHCPV6_OPTION_DOMAIN_LIST:
			option_dns_list = (struct dhcp_dns_list *) option;
			option = option +  option_dns_list->length + 4;
			option_length = option_length - option_dns_list->length - 4;
			break;
		case DHCPV6_OPTION_BOOT_URL:
			option_boot_url = (struct dhcp_boot_url *) option;
			option = option +  option_boot_url->length + 4;
			option_length = option_length - option_boot_url->length - 4;
			strncpy((char *)buffer,
				(const char *)option_boot_url->url,
				(size_t)option_boot_url->length);
			buffer[option_boot_url->length] = 0;
			if (parse_tftp_args(buffer,
					    (char *)my_fn_ip->server_ip6.addr,
					    (char *)my_fn_ip->filename,
					    (int)my_fn_ip->fd,
					    option_boot_url->length) == -1)
				return NULL;
			break;
		default:
			option_gen = (struct dhcp6_gen_option *) option;
			option = option + option_gen->length + 4;
			option_length = option_length - option_gen->length - 4;
		}
	}

	return received_options;
}

uint32_t
handle_dhcpv6(uint8_t * packet, int32_t packetsize)
{

	uint8_t  *first_option;
	int32_t option_length;
	struct dhcp_message_reply *reply;
	reply = (struct dhcp_message_reply *) packet;

	if (reply->type == 7)
		dhcpv6_state = DHCP_STATUSCODE_SUCCESS;

	first_option =  packet + 4;
	option_length =  packet + packetsize - first_option;
	dhcp6_process_options(first_option, option_length);

	return 0;
}
