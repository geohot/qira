#if 0

/*
 *	pcmcia.c
 *
 *	PCMCIA support routines for etherboot - generic stuff
 *
 *	This code has partly be taken from the linux kernel sources, .../drivers/pcmcia/
 *	Started & put together by
 *		Anselm Martin Hoffmeister
 *		Stockholm Projekt Computer-Service
 *		Sankt Augustin / Bonn, Germany
 *
 *	Distributed under GPL2
 */

/*
 *
 *
 *			******************************
 *			PLEASE DO NOT YET WORK ON THIS
 *			******************************
 *
 *	I'm still fixing it up on every end, so we most probably would interfere
 *	at some point. If there's anything obvious or better, not-so-obvious,
 *	please contact me by e-mail: anselm (AT) hoffmeister (DOT) be   *THANKS*
 */

FILE_LICENCE ( GPL2_ONLY );

#include <stdio.h>
#include <pcmcia.h>
#include <i82365.h>
#define CODE_STATUS "alpha"
#define	CODE_VERSION "0.1.3"
#include <pcmcia-opts.h>
#include <ipxe/init.h>

int	sockets; /* AHTODO: Phase this out! */
u_int	pccsocks;
struct	pccsock_t pccsock[MAXPCCSOCKS];
int	inited = -1;
struct	pcc_config_t pccconfig[MAXPCCCONFIGS];

struct	driver_interact_t driver[] = {
#ifdef	SUPPORT_I82365
	{ I82365, i82365_interfacer, "Intel_82365" },
#endif
};

#define	NUM_DRIVERS (sizeof(driver)/(sizeof(struct driver_interact_t)))

void	sleepticks(int numticks ) {
	u_int	tmo;
	for (tmo = currticks()+numticks; currticks() < tmo; ) {
        }
	return;
}

static void pcmcia_init_all(void) {
	u_int i, j, k, l, m, n, ui, configs = 0;
	u_int multicard[8];
	u_char	*uc, upc;
	if ( PDEBUG > 0 ) printf("Initializing PCMCIA subsystem (code-status: " CODE_STATUS ", Version " CODE_VERSION ")\n");
	if ( PDEBUG > 2 ) {
		printf ( "Supporting %d driver(s): ", NUM_DRIVERS );
		for ( i = 0; i < NUM_DRIVERS; ++i ) {
			printf ( "[%s] ", driver[i].name );
		}
		printf ( "\n" );
	}
	pccsocks = 0;
	sockets = 0;
	// Init all drivers in the driver[] array:
	for ( i = 0; i < NUM_DRIVERS; ++i ) {
		driver[i].f(INIT,0,i,0,0);	// init needs no params. It uses pccsocks and pccsock[].
						// Only i tells it which driver_id itself is.
	}
	for ( i = 0; i < pccsocks; ++i ) {
		printf ( "Socket %d: ", i );
		if ( pccsock[i].status != HASCARD ) {
			printf ( "is %s: skipping\n", pccsock[i].status == EMPTY? "empty":"[status unknown]" );
			continue;
		}
		if ( 0 != driver[pccsock[i].drivernum].f(MAPATTRMEM,pccsock[i].internalid,MAP_ATTRMEM_TO, MAP_ATTRMEM_LEN,0 ) ) {
			printf ("PCMCIA controller failed to map attribute memory.\n**** SEVERE ERROR CONDITION. Skipping controller.\n" );
			if ( PDEBUG > 2 ) {
				printf ( "<press key. THIS CONDITION SHOULD BE REPORTED!>\n" ); getchar();
			}
			continue;
		}
		// parse configuration information
		uc = ioremap ( MAP_ATTRMEM_TO, MAP_ATTRMEM_LEN );
		pccsock[i].stringoffset = pccsock[i].configoffset = pccsock[i].stringlength = 0;
		pccsock[i].type = 0xff;
		for ( l = 0; l < 8; ++l ) multicard[l] = 0;
		sleepticks(2);
		for ( l = ui = 0; ui < 0x800; ui += uc[(2*ui)+2] + 2 ) {
			if ( uc[(2*ui)] == 0xff ) {
				break;
			}
			// This loop is complete rubbish AFAICS.
			// But without it, my test system won't come up.
			// It's too bad to develop on broken hardware
			//				- Anselm
		}
		sleepticks(2);
		configs = 0;
		inited = -1;
		for ( l = ui = 0; ui < 0x800; ui += uc[(2*ui)+2] + 2 ) {
			if ( uc[(2*ui)] == 0xff ) break;
			else if ( uc[2*ui] == 0x15 ) {
				for ( k = 2 * ( ui + 2 ); ( uc[k] <= ' ' ) && ( k < ( 2 * ( uc[2*(ui+1)] + ui + 2 ) ) ) ; k += 2 ) { ; }
				pccsock[i].stringoffset = k;
				pccsock[i].stringlength = ( 2 * ( ui + 2 + uc[(2*ui)+2] ) - k ) / 2;
			} else if ( uc[2*ui] == 0x21 ) {
				pccsock[i].type = uc[(2*ui)+4];
			} else if ( uc[2*ui] == 0x1a ) { // Configuration map
				printf ( "\nConfig map 0x1a found [" );
				for ( k = 0; k < uc[2*(ui+1)]; ++k ) {
					printf ( "%02x ", uc[2*(ui+k+2)] );
				}
				printf ( "]\nHighest config available is %d\n", uc[2*(ui+3)] );
				m = uc[2*(ui+2)];
				pccsock[i].configoffset = 0;
				for ( j = 0; j <= (m & 3); ++j ) {
					pccsock[i].configoffset += uc[2*(ui+4+j)] << (8*j);
				}
				pccsock[i].rmask0 = 0;
				for ( j = 0; j <= ( ( ( m & 0x3c ) >> 2 ) & 3 ); ++j ) {
					pccsock[i].rmask0 += uc[2*(ui+5+(m&3)+j)] << (8*j);
				}
				j = pccsock[i].rmask0;
				printf ( "Config offset is %x, card has regs: < %s%s%s%s%s>\n", pccsock[i].configoffset,
					j & 1 ? "COR ":"", j & 2 ? "CCSR ":"", j & 4 ? "PRR ":"", j & 8 ? "SCR ":"", j & 16? "ESR ":"" );
				printf ( "COR + CCSR contents (si/du) %x %x/%x %x\n", uc[pccsock[i].configoffset+0],
					uc[pccsock[i].configoffset+2],uc[pccsock[i].configoffset*2],uc[(pccsock[i].configoffset*2)+2] );
				printf ( "          " );
			} else if ( uc[2*ui] == 0x1b ) { // Configuration data entry
				//printf ( "Config data 0x1b found [\n" );getchar();
				for ( k = 0; k < uc[2*(ui+1)]; ++k ) {
				//	printf ( "%02x ", uc[2*(ui+k+2)] );
				}
				// Parse this tuple into pccconfig[configs]
				// printf ( "]\n" );
				if ( configs == MAXPCCCONFIGS ) continue;
				k = 2*ui+4;
				pccconfig[configs].index = uc[k] & 0x3f;
				if ( uc[k] & 0x80 ) {
				//	printf ( "Special config, unsupp. for now\n" );
					continue;
				}
				k+=2;
				// printf ( "Features: %2x\n", uc[k] );
				if ( uc[k] & 0x7 ) {
					// printf ( "Cannot work with Vcc/Timing configs right now\n" );
					continue;
				}
				pccconfig[configs].iowin = pccconfig[configs].iolen = 0;
				if ( 0 != ( uc[k] & 0x8 ) ) {
					k+=2;
					// printf ( "Reading IO config: " );
					if ( 0 == ( uc[k] & 0x80 ) ) {
					//	printf ( "Cannot work with auto/io config\n" );
						continue;
					}
					k+=2;
					if ( 0 != ( uc[k] & 0x0f ) ) {
					//	printf ( "Don't support more than 1 iowin right now\n" );
						continue;
					}
					j = (uc[k] & 0x30) >> 4;
					m = (uc[k] & 0xc0) >> 6;
					if ( 3 == j ) ++j;
					if ( 3 == m ) ++m;
					k += 2;
					pccconfig[configs].iowin = 0;
					pccconfig[configs].iolen = 1;
					for ( n = 0; n < j; ++n, k+=2 ) {
						pccconfig[configs].iowin += uc[k] << (n*8);
					}
					for ( n = 0; n < m; ++n, k+=2 ) {
						pccconfig[configs].iolen += uc[k] << (n*8);
					}
					// printf ( "io %x len %d (%d)\n", pccconfig[configs].iowin, pccconfig[configs].iolen,configs );
				}
				for ( j = 0; j < (uc[k] & 3); ++j ) {
				//	pccconfig[configs].iowin += (uc[k+(2*j)+2]) << (8*j);
				}
				++configs;
			}
		}
		if ( pccsock[i].stringoffset > 0 ) {	// If no identifier, it's not a valid CIS (as of documentation...)
			printf ( "[" );
			for ( k = 0; ( k <  pccsock[i].stringlength ) && ( k < 64 ); ++k ) {
				j = uc[pccsock[i].stringoffset + 2 * k];
				printf ( "%c", (j>=' '? j:' ' ) );
			}
			printf ("]\n          is type %d (", pccsock[i].type );
			switch ( pccsock[i].type ) {
			  case	0x00:
				printf ( "MULTI" ); break;
			  case	0x01:
				printf ( "Memory" ); break;
			  case	0x02:
				printf ( "Serial" ); break;
			  case	0x03:
				printf ( "Parallel" ); break;
			  case	0x04:
				printf ( "Fixed" ); break;
			  case	0x05:
				printf ( "Video" ); break;
			  case	0x06:
				printf ( "Network" ); break;
			  case	0x07:
				printf ( "AIMS" ); break;
			  case	0x08:
				printf ( "SCSI" ); break;
			  case	0x106: // Special / homebrew to say "Multi/network"
				printf ( "MULTI, with Network" ); break; // AHTODO find a card for this
			  default:
				printf ( "UNSUPPORTED/UNKNOWN" );
			}
			printf ( ") with %d possible configuration(s)\n", configs );
			// Now set dependency: If it's Network or multi->network, accept
			if ( (inited <= 0 ) && (6 == (0xff & pccsock[i].type) ) && (0 < configs ) ) {
				printf ( "activating this device with ioport %x-%x (config #%d)\n", 
				pccconfig[0].iowin, pccconfig[0].iowin+pccconfig[0].iolen-1, pccconfig[0].index );
				inited = i;
				// And unmap attrmem ourselves!
				printf ( "Activating config..." );
				if ( m=driver[pccsock[i].drivernum].f(SELECTCONFIG,pccsock[i].internalid,pccconfig[0].index,0,&pccconfig[0]) ) {
					printf ("Failure(%d)!",m); inited = -1;
		    			driver[pccsock[i].drivernum].f(UNMAPATTRMEM,pccsock[i].internalid,0,0,0);
				}
				printf ( "done!\n" );
				continue;
			}
		} else {
			printf ( "unsupported - no identifier string found in CIS\n" );
		}
		// unmap the PCMCIA device
		if ( i != inited ) {
		    if ( 0 != driver[pccsock[i].drivernum].f(UNMAPATTRMEM,pccsock[i].internalid,0,0,0) ) {
			printf ("PCMCIA controller failed to unmap attribute memory.\n**** SEVERE ERROR CONDITION ****\n" );
			if ( PDEBUG > 2 ) {
				printf ( "<press key. THIS CONDITION SHOULD BE REPORTED!>\n" ); getchar();
			}
			continue;
		    }
		}
	}
	if ( PDEBUG > 2 ) {
		printf ( "<press key to exit the pcmcia_init_all routine>\n" );
		getchar();
	}

}

static void	pcmcia_shutdown_all(void) {
	int i;
	//if ( PDEBUG > 2 ) {printf("<press key to continue>\n" ); getchar(); }
	for ( i = 0; i < pccsocks; ++i ) {
 		driver[pccsock[i].drivernum].f(SHUTDOWN,pccsock[i].internalid,0,0,0);
	}
	printf("Shutdown of PCMCIA subsystem completed");
}

#endif
