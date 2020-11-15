#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <getopt.h>
#include <pcap.h>

#define SNAPLEN 1600

/*
 * FIXME: is there a way to detect the version of the libpcap library?
 * Version 0.9 has pcap_inject; version 0.8 doesn't, but both report
 * their version number as 2.4.
 */
#define HAVE_PCAP_INJECT 0

struct hijack {
	pcap_t *pcap;
	int fd;
	int datalink;
	int filtered;
	unsigned long rx_count;
	unsigned long tx_count;
};

struct hijack_listener {
	struct sockaddr_un sun;
	int fd;
};

struct hijack_options {
	char interface[IF_NAMESIZE];
	int daemonise;
};

static int daemonised = 0;

static int signalled = 0;

static void flag_signalled ( int signal __attribute__ (( unused )) ) {
	signalled = 1;
}

#if ! HAVE_PCAP_INJECT
/**
 * Substitute for pcap_inject(), if this version of libpcap doesn't
 * have it.  Will almost certainly only work under Linux.
 *
 */
int pcap_inject ( pcap_t *pcap, const void *data, size_t len ) {
	int fd;
	char *errbuf = pcap_geterr ( pcap );

	fd = pcap_get_selectable_fd ( pcap );
	if ( fd < 0 ) {
		snprintf ( errbuf, PCAP_ERRBUF_SIZE,
			   "could not get file descriptor" );
		return -1;
	}
	if ( write ( fd, data, len ) != len ) {
		snprintf ( errbuf, PCAP_ERRBUF_SIZE,
			   "could not write data: %s", strerror ( errno ) );
		return -1;
	}
	return len;
}
#endif /* ! HAVE_PCAP_INJECT */

/**
 * Log error message
 *
 */
static __attribute__ (( format ( printf, 2, 3 ) )) void
logmsg ( int level, const char *format, ... ) {
	va_list ap;

	va_start ( ap, format );
	if ( daemonised ) {
		vsyslog ( ( LOG_DAEMON | level ), format, ap );
	} else {
		vfprintf ( stderr, format, ap );
	}
	va_end ( ap );
}

/**
 * Open pcap device
 *
 */
static int hijack_open ( const char *interface, struct hijack *hijack ) {
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Open interface via pcap */
	errbuf[0] = '\0';
	hijack->pcap = pcap_open_live ( interface, SNAPLEN, 1, 0, errbuf );
	if ( ! hijack->pcap ) {
		logmsg ( LOG_ERR, "Failed to open %s: %s\n",
			 interface, errbuf );
		goto err;
	}
	if ( errbuf[0] )
		logmsg ( LOG_WARNING, "Warning: %s\n", errbuf );

	/* Set capture interface to non-blocking mode */
	if ( pcap_setnonblock ( hijack->pcap, 1, errbuf ) < 0 ) {
		logmsg ( LOG_ERR, "Could not make %s non-blocking: %s\n",
			 interface, errbuf );
		goto err;
	}

	/* Get file descriptor for select() */
	hijack->fd = pcap_get_selectable_fd ( hijack->pcap );
	if ( hijack->fd < 0 ) {
		logmsg ( LOG_ERR, "Cannot get selectable file descriptor "
			 "for %s\n", interface );
		goto err;
	}

	/* Get link layer type */
	hijack->datalink = pcap_datalink ( hijack->pcap );

	return 0;

 err:
	if ( hijack->pcap )
		pcap_close ( hijack->pcap );
	return -1;
}

/**
 * Close pcap device
 *
 */
static void hijack_close ( struct hijack *hijack ) {
	pcap_close ( hijack->pcap );
}

/**
 * Install filter for hijacked connection
 *
 */
static int hijack_install_filter ( struct hijack *hijack,
				   char *filter ) {
	struct bpf_program program;

	/* Compile filter */
	if ( pcap_compile ( hijack->pcap, &program, filter, 1, 0 ) < 0 ) {
		logmsg ( LOG_ERR, "could not compile filter \"%s\": %s\n",
			 filter, pcap_geterr ( hijack->pcap ) );
		goto err_nofree;
	}

	/* Install filter */
	if ( pcap_setfilter ( hijack->pcap, &program ) < 0 ) {
		logmsg ( LOG_ERR, "could not install filter \"%s\": %s\n",
			 filter, pcap_geterr ( hijack->pcap ) );
		goto err;
	}
	
	logmsg ( LOG_INFO, "using filter \"%s\"\n", filter );

	pcap_freecode ( &program );
	return 0;

 err:	
	pcap_freecode ( &program );
 err_nofree:
	return -1;
}

/**
 * Set up filter for hijacked ethernet connection
 *
 */
static int hijack_filter_ethernet ( struct hijack *hijack, const char *buf,
				    size_t len ) {
	char filter[55]; /* see format string */
	struct ether_header *ether_header = ( struct ether_header * ) buf;
	unsigned char *hwaddr = ether_header->ether_shost;

	if ( len < sizeof ( *ether_header ) )
		return -1;

	snprintf ( filter, sizeof ( filter ), "broadcast or multicast or "
		   "ether host %02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0],
		   hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5] );

	return hijack_install_filter ( hijack, filter );
}

/**
 * Set up filter for hijacked connection
 *
 */
static int hijack_filter ( struct hijack *hijack, const char *buf,
			   size_t len ) {
	switch ( hijack->datalink ) {
	case DLT_EN10MB:
		return hijack_filter_ethernet ( hijack, buf, len );
	default:
		logmsg ( LOG_ERR, "unsupported protocol %s: cannot filter\n",
			 ( pcap_datalink_val_to_name ( hijack->datalink ) ?
			   pcap_datalink_val_to_name ( hijack->datalink ) :
			   "UNKNOWN" ) );
		/* Return success so we don't get called again */
		return 0;
	}
}

/**
 * Forward data from hijacker
 *
 */
static ssize_t forward_from_hijacker ( struct hijack *hijack, int fd ) {
	char buf[SNAPLEN];
	ssize_t len;

	/* Read packet from hijacker */
	len = read ( fd, buf, sizeof ( buf ) );
	if ( len < 0 ) {
		logmsg ( LOG_ERR, "read from hijacker failed: %s\n",
			 strerror ( errno ) );
		return -1;
	}
	if ( len == 0 )
		return 0;

	/* Set up filter if not already in place */
	if ( ! hijack->filtered ) {
		if ( hijack_filter ( hijack, buf, len ) == 0 )
			hijack->filtered = 1;
	}

	/* Transmit packet to network */
	if ( pcap_inject ( hijack->pcap, buf, len ) != len ) {
		logmsg ( LOG_ERR, "write to hijacked port failed: %s\n",
			 pcap_geterr ( hijack->pcap ) );
		return -1;
	}

	hijack->tx_count++;
	return len;
};

/**
 * Forward data to hijacker
 *
 */
static ssize_t forward_to_hijacker ( int fd, struct hijack *hijack ) {
	struct pcap_pkthdr *pkt_header;
	const unsigned char *pkt_data;
	ssize_t len;

	/* Receive packet from network */
	if ( pcap_next_ex ( hijack->pcap, &pkt_header, &pkt_data ) < 0 ) {
		logmsg ( LOG_ERR, "read from hijacked port failed: %s\n",
			 pcap_geterr ( hijack->pcap ) );
		return -1;
	}
	if ( pkt_header->caplen != pkt_header->len ) {
		logmsg ( LOG_ERR, "read partial packet (%d of %d bytes)\n",
			 pkt_header->caplen, pkt_header->len );
		return -1;
	}
	if ( pkt_header->caplen == 0 )
		return 0;
	len = pkt_header->caplen;

	/* Write packet to hijacker */
	if ( write ( fd, pkt_data, len ) != len ) {
		logmsg ( LOG_ERR, "write to hijacker failed: %s\n",
			 strerror ( errno ) );
		return -1;
	}

	hijack->rx_count++;
	return len;
};


/**
 * Run hijacker
 *
 */
static int run_hijacker ( const char *interface, int fd ) {
	struct hijack hijack;
	fd_set fdset;
	int max_fd;
	ssize_t len;

	logmsg ( LOG_INFO, "new connection for %s\n", interface );

	/* Open connection to network */
	memset ( &hijack, 0, sizeof ( hijack ) );
	if ( hijack_open ( interface, &hijack ) < 0 )
		goto err;
	
	/* Do the forwarding */
	max_fd = ( ( fd > hijack.fd ) ? fd : hijack.fd );
	while ( 1 ) {
		/* Wait for available data */
		FD_ZERO ( &fdset );
		FD_SET ( fd, &fdset );
		FD_SET ( hijack.fd, &fdset );
		if ( select ( ( max_fd + 1 ), &fdset, NULL, NULL, 0 ) < 0 ) {
			logmsg ( LOG_ERR, "select failed: %s\n",
				 strerror ( errno ) );
			goto err;
		}
		if ( FD_ISSET ( fd, &fdset ) ) {
			len = forward_from_hijacker ( &hijack, fd );
			if ( len < 0 )
				goto err;
			if ( len == 0 )
				break;
		}
		if ( FD_ISSET ( hijack.fd, &fdset ) ) {
			len = forward_to_hijacker ( fd, &hijack );
			if ( len < 0 )
				goto err;
			if ( len == 0 )
				break;
		}
	}

	hijack_close ( &hijack );
	logmsg ( LOG_INFO, "closed connection for %s\n", interface );
	logmsg ( LOG_INFO, "received %ld packets, sent %ld packets\n",
		 hijack.rx_count, hijack.tx_count );

	return 0;

 err:
	if ( hijack.pcap )
		hijack_close ( &hijack );
	return -1;
}

/**
 * Open listener socket
 *
 */
static int open_listener ( const char *interface,
			   struct hijack_listener *listener ) {
	
	/* Create socket */
	listener->fd = socket ( PF_UNIX, SOCK_SEQPACKET, 0 );
	if ( listener->fd < 0 ) {
		logmsg ( LOG_ERR, "Could not create socket: %s\n",
			 strerror ( errno ) );
		goto err;
	}

	/* Bind to local filename */
	listener->sun.sun_family = AF_UNIX,
	snprintf ( listener->sun.sun_path, sizeof ( listener->sun.sun_path ),
		   "/var/run/hijack-%s", interface );
	if ( bind ( listener->fd, ( struct sockaddr * ) &listener->sun,
		    sizeof ( listener->sun ) ) < 0 ) {
		logmsg ( LOG_ERR, "Could not bind socket to %s: %s\n",
			 listener->sun.sun_path, strerror ( errno ) );
		goto err;
	}

	/* Set as a listening socket */
	if ( listen ( listener->fd, 0 ) < 0 ) {
		logmsg ( LOG_ERR, "Could not listen to %s: %s\n",
			 listener->sun.sun_path, strerror ( errno ) );
		goto err;
	}

	return 0;
	
 err:
	if ( listener->fd >= 0 )
		close ( listener->fd );
	return -1;
}

/**
 * Listen on listener socket
 *
 */
static int listen_for_hijackers ( struct hijack_listener *listener,
				  const char *interface ) {
	int fd;
	pid_t child;
	int rc;

	logmsg ( LOG_INFO, "Listening on %s\n", listener->sun.sun_path );

	while ( ! signalled ) {
		/* Accept new connection, interruptibly */
		siginterrupt ( SIGINT, 1 );
		siginterrupt ( SIGHUP, 1 );
		fd = accept ( listener->fd, NULL, 0 );
		siginterrupt ( SIGINT, 0 );
		siginterrupt ( SIGHUP, 0 );
		if ( fd < 0 ) {
			if ( errno == EINTR ) {
				continue;
			} else {
				logmsg ( LOG_ERR, "accept failed: %s\n",
					 strerror ( errno ) );
				goto err;
			}
		}

		/* Fork child process */
		child = fork();
		if ( child < 0 ) {
			logmsg ( LOG_ERR, "fork failed: %s\n",
				 strerror ( errno ) );
			goto err;
		}
		if ( child == 0 ) {
			/* I am the child; run the hijacker */
			rc = run_hijacker ( interface, fd );
			close ( fd );
			exit ( rc );
		}
		
		close ( fd );
	}

	logmsg ( LOG_INFO, "Stopped listening on %s\n",
		 listener->sun.sun_path );
	return 0;

 err:
	if ( fd >= 0 )
		close ( fd );
	return -1;
}

/**
 * Close listener socket
 *
 */
static void close_listener ( struct hijack_listener *listener ) {
	close ( listener->fd );
	unlink ( listener->sun.sun_path );
}

/**
 * Print usage
 *
 */
static void usage ( char **argv ) {
	logmsg ( LOG_ERR,
		 "Usage: %s [options]\n"
		 "\n"
		 "Options:\n"
		 "  -h|--help               Print this help message\n"
		 "  -i|--interface intf     Use specified network interface\n"
		 "  -n|--nodaemon           Run in foreground\n",
		 argv[0] );
}

/**
 * Parse command-line options
 *
 */
static int parse_options ( int argc, char **argv,
			   struct hijack_options *options ) {
	static struct option long_options[] = {
		{ "interface", 1, NULL, 'i' },
		{ "nodaemon", 0, NULL, 'n' },
		{ "help", 0, NULL, 'h' },
		{ },
	};
	int c;

	/* Set default options */
	memset ( options, 0, sizeof ( *options ) );
	strncpy ( options->interface, "eth0", sizeof ( options->interface ) );
	options->daemonise = 1;

	/* Parse command-line options */
	while ( 1 ) {
		int option_index = 0;
		
		c = getopt_long ( argc, argv, "i:hn", long_options,
				  &option_index );
		if ( c < 0 )
			break;

		switch ( c ) {
		case 'i':
			strncpy ( options->interface, optarg,
				  sizeof ( options->interface ) );
			break;
		case 'n':
			options->daemonise = 0;
			break;
		case 'h':
			usage( argv );
			return -1;
		case '?':
			/* Unrecognised option */
			return -1;
		default:
			logmsg ( LOG_ERR, "Unrecognised option '-%c'\n", c );
			return -1;
		}
	}

	/* Check there's nothing left over on the command line */
	if ( optind != argc ) {
		usage ( argv );
		return -1;
	}

	return 0;
}

/**
 * Daemonise
 *
 */
static int daemonise ( const char *interface ) {
	char pidfile[16 + IF_NAMESIZE + 4]; /* "/var/run/hijack-<intf>.pid" */
	char pid[16];
	int pidlen;
	int fd = -1;

	/* Daemonise */
	if ( daemon ( 0, 0 ) < 0 ) {
		logmsg ( LOG_ERR, "Could not daemonise: %s\n",
			 strerror ( errno ) );
		goto err;
	}
	daemonised = 1; /* Direct messages to syslog now */

	/* Open pid file */
	snprintf ( pidfile, sizeof ( pidfile ), "/var/run/hijack-%s.pid",
		   interface );
	fd = open ( pidfile, ( O_WRONLY | O_CREAT | O_TRUNC ),
		    ( S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ) );
	if ( fd < 0 ) {
		logmsg ( LOG_ERR, "Could not open %s for writing: %s\n",
			 pidfile, strerror ( errno ) );
		goto err;
	}

	/* Write pid to file */
	pidlen = snprintf ( pid, sizeof ( pid ), "%d\n", getpid() );
	if ( write ( fd, pid, pidlen ) != pidlen ) {
		logmsg ( LOG_ERR, "Could not write %s: %s\n",
			 pidfile, strerror ( errno ) );
		goto err;
	}

	close ( fd );
	return 0;

 err:
	if ( fd >= 0 )
		close ( fd );
	return -1;
}

int main ( int argc, char **argv ) {
	struct hijack_options options;
	struct hijack_listener listener;
	struct sigaction sa;

	/* Parse command-line options */
	if ( parse_options ( argc, argv, &options ) < 0 )
		exit ( 1 );

	/* Set up syslog connection */
	openlog ( basename ( argv[0] ), LOG_PID, LOG_DAEMON );

	/* Set up listening socket */
	if ( open_listener ( options.interface, &listener ) < 0 )
		exit ( 1 );

	/* Daemonise on demand */
	if ( options.daemonise ) {
		if ( daemonise ( options.interface ) < 0 )
			exit ( 1 );
	}

	/* Avoid creating zombies */
	memset ( &sa, 0, sizeof ( sa ) );
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART | SA_NOCLDWAIT;
	if ( sigaction ( SIGCHLD, &sa, NULL ) < 0 ) {
		logmsg ( LOG_ERR, "Could not set SIGCHLD handler: %s",
			 strerror ( errno ) );
		exit ( 1 );
	}

	/* Set 'signalled' flag on SIGINT or SIGHUP */
	sa.sa_handler = flag_signalled;
	sa.sa_flags = SA_RESTART | SA_RESETHAND;
	if ( sigaction ( SIGINT, &sa, NULL ) < 0 ) {
		logmsg ( LOG_ERR, "Could not set SIGINT handler: %s",
			 strerror ( errno ) );
		exit ( 1 );
	}
	if ( sigaction ( SIGHUP, &sa, NULL ) < 0 ) {
		logmsg ( LOG_ERR, "Could not set SIGHUP handler: %s",
			 strerror ( errno ) );
		exit ( 1 );
	}

	/* Listen for hijackers */
	if ( listen_for_hijackers ( &listener, options.interface ) < 0 )
		exit ( 1 );

	close_listener ( &listener );
	
	return 0;
}
