#ifdef CONFIG_PCMCIA

/*
 *	i82365.c
 *	Support for i82365 and similar ISA-to-PCMCIA bridges
 *
 *	Taken from Linux kernel sources, distributed under GPL2
 *
 *   Software distributed under the License is distributed on an "AS
 *   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 *   implied. See the License for the specific language governing
 *   rights and limitations under the License.
 *
 *   The initial developer of the original code is David A. Hinds
 *   <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 *   are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 *	Ported by: Anselm Martin Hoffmeister, Stockholm Projekt Computer-Service, Sankt Augustin/Bonn, GERMANY
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
#include "../include/pcmcia.h"
#include "../include/pcmcia-opts.h"
#include "../include/i82365.h"

#ifndef CONFIG_ISA
#error	PCMCIA_I82365 only works with ISA defined - set CONFIG_ISA
#endif

typedef enum pcic_id {
    IS_I82365A, IS_I82365B, IS_I82365DF,
    IS_IBM, IS_RF5Cx96, IS_VLSI, IS_VG468, IS_VG469,
    IS_PD6710, IS_PD672X, IS_VT83C469,
} pcic_id;

/* Flags for classifying groups of controllers */
#define IS_VADEM        0x0001
#define IS_CIRRUS       0x0002
#define IS_TI           0x0004
#define IS_O2MICRO      0x0008
#define IS_VIA          0x0010
#define IS_TOPIC        0x0020
#define IS_RICOH        0x0040
#define IS_UNKNOWN      0x0400
#define IS_VG_PWR       0x0800
#define IS_DF_PWR       0x1000
#define IS_PCI          0x2000
#define IS_ALIVE        0x8000

typedef struct pcic_t {
    char                *name;
    u_short             flags;
} pcic_t;

static pcic_t pcic[] = {
    { "Intel i82365sl A step", 0 },
    { "Intel i82365sl B step", 0 },
    { "Intel i82365sl DF", IS_DF_PWR },
    { "IBM Clone", 0 },
    { "Ricoh RF5C296/396", 0 },
    { "VLSI 82C146", 0 },
    { "Vadem VG-468", IS_VADEM },
    { "Vadem VG-469", IS_VADEM|IS_VG_PWR },
    { "Cirrus PD6710", IS_CIRRUS },
    { "Cirrus PD672x", IS_CIRRUS },
    { "VIA VT83C469", IS_CIRRUS|IS_VIA },
};

typedef struct cirrus_state_t {
    u_char              misc1, misc2;
    u_char              timer[6];
} cirrus_state_t;

typedef struct vg46x_state_t {
    u_char              ctl, ema;
} vg46x_state_t;

typedef struct socket_info_t {
    u_short             type, flags;
    socket_cap_t        cap;
    ioaddr_t            ioaddr;
    u_short             psock;
    u_char              cs_irq, intr;
    void                (*handler)(void *info, u_int events);
    void                *info;
    union {
        cirrus_state_t          cirrus;
        vg46x_state_t           vg46x;
    } state;
} socket_info_t;

//static socket_info_t socket[8];

int	i365_base = 0x3e0; // Default in Linux kernel
int	cycle_time = 120; // External clock time in ns, 120ns =~ 8.33 MHz
int	mydriverid = 0;

void	phex ( unsigned char c );
/*static int to_cycles(int ns)
{
    return ns/cycle_time;
}
*/
/*static int to_ns(int cycles)
{
    return cycle_time*cycles;
}
*/

static u_char i365_get(u_short sock, u_short reg)
{
    //unsigned long flags;
    //spin_lock_irqsave(&bus_lock,flags);
    {
        ioaddr_t port = pccsock[sock].ioaddr;
        u_char val;
        reg = I365_REG(pccsock[sock].internalid, reg);
        outb(reg, port); val = inb(port+1);
        //spin_unlock_irqrestore(&bus_lock,flags);
        return val;
    }
}

static void i365_set(u_short sock, u_short reg, u_char data)
{
    //unsigned long flags;
    //spin_lock_irqsave(&bus_lock,flags);
    {
        ioaddr_t port = pccsock[sock].ioaddr;
        u_char val = I365_REG(pccsock[sock].internalid, reg);
        outb(val, port); outb(data, port+1);
        //spin_unlock_irqrestore(&bus_lock,flags);
    }
}

void	add_socket_i365(u_short port, int psock, int type) {
	pccsock[pccsocks].ioaddr = port;
	pccsock[pccsocks].internalid = psock;
	pccsock[pccsocks].type = type;
	pccsock[pccsocks].flags = pcic[type].flags;
	pccsock[pccsocks].drivernum = mydriverid;
	pccsock[pccsocks].configoffset = -1;
	// Find out if a card in inside that socket
	pccsock[pccsocks].status = (( 12 == (i365_get(pccsocks,I365_STATUS)&12) )  ?  HASCARD : EMPTY );
	// *TODO* check if that's all
	if ( 0 == (psock & 1) ) {
		printf ( "Found a PCMCIA controller (i82365) at io %x, type '%s'\n", port, pcic[type].name );
		//	pccsock[pccsocks].status == HASCARD? "holds card":"empty" );
	}
	pccsocks++;
	return;
}

void	i365_bset(u_short sock, u_short reg, u_char mask) {
	u_char d = i365_get(sock, reg);
	d |= mask;
	i365_set(sock, reg, d);
}

void	i365_bclr(u_short sock, u_short reg, u_char mask) {
	u_char d = i365_get(sock, reg);
	d &= ~mask;
	i365_set(sock, reg, d);
}


/*static void i365_bflip(u_short sock, u_short reg, u_char mask, int b)
{
    u_char d = i365_get(sock, reg);
    if (b)
        d |= mask;
    else
        d &= ~mask;
    i365_set(sock, reg, d);
}
*/

/*
static u_short i365_get_pair(u_short sock, u_short reg)
{
    u_short a, b;
    a = i365_get(sock, reg);
    b = i365_get(sock, reg+1);
    return (a + (b<<8));
}
*/

/*
static void i365_set_pair(u_short sock, u_short reg, u_short data)
{
    i365_set(sock, reg, data & 0xff);
    i365_set(sock, reg+1, data >> 8);
}
*/
int	identify_i365 ( u_short port, u_short sock ) {
	u_char val;
	int type = -1;
	/* Use the next free entry in the socket table */
	pccsock[pccsocks].ioaddr = port;
	pccsock[pccsocks].internalid = sock;
	// *TODO* wakeup a sleepy cirrus controller?

	if ((val = i365_get(pccsocks, I365_IDENT)) & 0x70)
	    return -1;
	switch (val) {
	case 0x82:
	    type = IS_I82365A; break;
	case 0x83:
	    type = IS_I82365B; break;
	case 0x84:
	    type = IS_I82365DF; break;
	case 0x88: case 0x89: case 0x8a:
	    type = IS_IBM; break;
	}
	/* Check for Vadem VG-468 chips */
	outb(0x0e, port);
	outb(0x37, port);
	i365_bset(pccsocks, VG468_MISC, VG468_MISC_VADEMREV);
	val = i365_get(pccsocks, I365_IDENT);
	if (val & I365_IDENT_VADEM) {
	    i365_bclr(pccsocks, VG468_MISC, VG468_MISC_VADEMREV);
	    type = ((val & 7) >= 4) ? IS_VG469 : IS_VG468;
	}

	/* Check for Ricoh chips */
	val = i365_get(pccsocks, RF5C_CHIP_ID);
	if ((val == RF5C_CHIP_RF5C296) || (val == RF5C_CHIP_RF5C396)) type = IS_RF5Cx96;

	/* Check for Cirrus CL-PD67xx chips */
	i365_set(pccsocks, PD67_CHIP_INFO, 0);
	val = i365_get(pccsocks, PD67_CHIP_INFO);
	if ((val & PD67_INFO_CHIP_ID) == PD67_INFO_CHIP_ID) {
	    val = i365_get(pccsocks, PD67_CHIP_INFO);
	    if ((val & PD67_INFO_CHIP_ID) == 0) {
		type = (val & PD67_INFO_SLOTS) ? IS_PD672X : IS_PD6710;
		i365_set(pccsocks, PD67_EXT_INDEX, 0xe5);
		if (i365_get(pccsocks, PD67_EXT_INDEX) != 0xe5) type = IS_VT83C469;
	    }
	}
    return type;
}

int	init_i82365(void) {
	int	i, j, sock, k, ns, id;
	//unsigned int ui,uj;
	//unsigned char * upc;
	ioaddr_t port;
	int	i82365s = 0;
	// Change from kernel: No irq init, no check_region, no isapnp support
	// No ignore socket, no extra sockets to check (so it's easier here :-/)
	// Probably we don't need any of them; in case YOU do, SHOUT AT ME!
	id = identify_i365(i365_base, 0);
	if ((id == IS_I82365DF) && (identify_i365(i365_base, 1) != id)) {
		for (i = 0; i < 4; i++) {
		    port = i365_base + ((i & 1) << 2) + ((i & 2) << 1);
		    sock = (i & 1) << 1;
		    if (identify_i365(port, sock) == IS_I82365DF) {
			add_socket_i365(port, sock, IS_VLSI);
		    }
		}
	} else {
	  for (i = 0; i < 4; i += 2) {
            port = i365_base + 2*(i>>2);
            sock = (i & 3);
            id = identify_i365(port, sock);
            if (id < 0) continue;

            for (j = ns = 0; j < 2; j++) {
                /* Does the socket exist? */
                if (identify_i365(port, sock+j) < 0)	continue;
                /* Check for bad socket decode */
                for (k = 0; k <= i82365s; k++)
                    i365_set(k, I365_MEM(0)+I365_W_OFF, k);
                for (k = 0; k <= i82365s; k++)
                    if (i365_get(k, I365_MEM(0)+I365_W_OFF) != k)
                        break;
                if (k <= i82365s) break;
                add_socket_i365(port, sock+j, id); ns++;
            }
	  }
	}
	return	0;







/*	printf ( "Selecting config 1: io 0x300 @byte 87*2.." );
	upc[(2*87)] = 2;
	i365_bclr(1, I365_ADDRWIN, 1 );
	i365_set(1,I365_INTCTL, 0x65 ); //no-reset, memory-card
	i365_set(1, I365_IO(0)+0, 0x20 );
	i365_set(1, I365_IO(0)+1, 0x03 );
	i365_set(1, I365_IO(0)+2, 0x3f );
	i365_set(1, I365_IO(0)+3, 0x03 );
	i365_set(1, 0x3a, 0x05 );
	i365_set(1, 0x3b, 0x05 );
	i365_set(1, 0x3c, 0x05 );
	i365_set(1, 0x3d, 0x05 );
	i365_set(1, 0x3e, 0x05 );
	i365_set(1, 0x3f, 0x05 );
	i365_set(1, 0x07, 0x0a );
	i365_set(1, I365_ADDRWIN, 0x40 ); // 0x40
	printf ( "!\n" ); getchar();
	printf ( "\n" );
	return 0; */
}

void	phex ( unsigned char c ) {
	unsigned char a = 0, b = 0;
	b = ( c & 0xf );
	if ( b > 9 ) b += ('a'-'9'-1);
	b += '0';
	a = ( c & 0xf0 ) >> 4;
	if ( a > 9 ) a += ('a'-'9'-1);
	a += '0';
	printf ( "%c%c ", a, b );
	return;
}

int	deinit_i82365(void) {
	printf("Deinitializing i82365\n" );
	return 0;
}

/*static int i365_get_status(u_short sock, u_int *value)
{
    u_int status;

    status = i365_get(sock, I365_STATUS);
    *value = ((status & I365_CS_DETECT) == I365_CS_DETECT)
        ? SS_DETECT : 0;

    if (i365_get(sock, I365_INTCTL) & I365_PC_IOCARD)
        *value |= (status & I365_CS_STSCHG) ? 0 : SS_STSCHG;
    else {
        *value |= (status & I365_CS_BVD1) ? 0 : SS_BATDEAD;
        *value |= (status & I365_CS_BVD2) ? 0 : SS_BATWARN;
    }
    *value |= (status & I365_CS_WRPROT) ? SS_WRPROT : 0;
    *value |= (status & I365_CS_READY) ? SS_READY : 0;
    *value |= (status & I365_CS_POWERON) ? SS_POWERON : 0;

#ifdef CONFIG_ISA
    if (pccsock[sock].type == IS_VG469) {
        status = i365_get(sock, VG469_VSENSE);
        if (pccsock[sock].internalid & 1) {
            *value |= (status & VG469_VSENSE_B_VS1) ? 0 : SS_3VCARD;
            *value |= (status & VG469_VSENSE_B_VS2) ? 0 : SS_XVCARD;
        } else {
            *value |= (status & VG469_VSENSE_A_VS1) ? 0 : SS_3VCARD;
            *value |= (status & VG469_VSENSE_A_VS2) ? 0 : SS_XVCARD;
        }
    }
#endif

    printf("i82365: GetStatus(%d) = %#4.4x\n", sock, *value);
    return 0;
} //i365_get_status
*/

/*static int i365_set_socket(u_short sock, socket_state_t *state)
{
    socket_info_t *t = &socket[sock];
    u_char reg;

    printf("i82365: SetSocket(%d, flags %#3.3x, Vcc %d, Vpp %d, "
          "io_irq %d, csc_mask %#2.2x)\n", sock, state->flags,
          state->Vcc, state->Vpp, state->io_irq, state->csc_mask);
printf ("\nERROR:UNIMPLEMENTED\n" );
return 0;
    // First set global controller options 
    // set_bridge_state(sock); *TODO* check: need this here?

    // IO card, RESET flag, IO interrupt 
    reg = t->intr;
    if (state->io_irq != t->cap.pci_irq) reg |= state->io_irq;
    reg |= (state->flags & SS_RESET) ? 0 : I365_PC_RESET;
    reg |= (state->flags & SS_IOCARD) ? I365_PC_IOCARD : 0;
    i365_set(sock, I365_INTCTL, reg);

    reg = I365_PWR_NORESET;
    if (state->flags & SS_PWR_AUTO) reg |= I365_PWR_AUTO;
    if (state->flags & SS_OUTPUT_ENA) reg |= I365_PWR_OUT;

    if (t->flags & IS_CIRRUS) {
        if (state->Vpp != 0) {
            if (state->Vpp == 120)
                reg |= I365_VPP1_12V;
            else if (state->Vpp == state->Vcc)
                reg |= I365_VPP1_5V;
            else return -EINVAL;
        }
        if (state->Vcc != 0) {
            reg |= I365_VCC_5V;
            if (state->Vcc == 33)
                i365_bset(sock, PD67_MISC_CTL_1, PD67_MC1_VCC_3V);
            else if (state->Vcc == 50)
                i365_bclr(sock, PD67_MISC_CTL_1, PD67_MC1_VCC_3V);
            else return -EINVAL;
        }
    } else if (t->flags & IS_VG_PWR) {
        if (state->Vpp != 0) {
            if (state->Vpp == 120)
                reg |= I365_VPP1_12V;
            else if (state->Vpp == state->Vcc)
                reg |= I365_VPP1_5V;
            else return -EINVAL;
        }
       if (state->Vcc != 0) {
            reg |= I365_VCC_5V;
            if (state->Vcc == 33)
                i365_bset(sock, VG469_VSELECT, VG469_VSEL_VCC);
            else if (state->Vcc == 50)
                i365_bclr(sock, VG469_VSELECT, VG469_VSEL_VCC);
            else return -EINVAL;
        }
    } else if (t->flags & IS_DF_PWR) {
        switch (state->Vcc) {
        case 0:         break;
        case 33:        reg |= I365_VCC_3V; break;
        case 50:        reg |= I365_VCC_5V; break;
        default:        return -EINVAL;
        }
        switch (state->Vpp) {
        case 0:         break;
        case 50:        reg |= I365_VPP1_5V; break;
        case 120:       reg |= I365_VPP1_12V; break;
        default:        return -EINVAL;
        }
    } else {
        switch (state->Vcc) {
        case 0:         break;
        case 50:        reg |= I365_VCC_5V; break;
        default:        return -EINVAL;
        }
        switch (state->Vpp) {
        case 0:         break;
        case 50:        reg |= I365_VPP1_5V | I365_VPP2_5V; break;
        case 120:       reg |= I365_VPP1_12V | I365_VPP2_12V; break;
        default:        return -EINVAL;
        }
    }

    if (reg != i365_get(sock, I365_POWER))
        i365_set(sock, I365_POWER, reg);

    // Chipset-specific functions 
    if (t->flags & IS_CIRRUS) {
        // Speaker control 
        i365_bflip(sock, PD67_MISC_CTL_1, PD67_MC1_SPKR_ENA,
                   state->flags & SS_SPKR_ENA);
    }

    // Card status change interrupt mask 
    reg = t->cs_irq << 4;
    if (state->csc_mask & SS_DETECT) reg |= I365_CSC_DETECT;
    if (state->flags & SS_IOCARD) {
        if (state->csc_mask & SS_STSCHG) reg |= I365_CSC_STSCHG;
    } else {
        if (state->csc_mask & SS_BATDEAD) reg |= I365_CSC_BVD1;
        if (state->csc_mask & SS_BATWARN) reg |= I365_CSC_BVD2;
        if (state->csc_mask & SS_READY) reg |= I365_CSC_READY;
    }
    i365_set(sock, I365_CSCINT, reg);
    i365_get(sock, I365_CSC);

    return 0;
} // i365_set_socket 
*/

/*static int i365_get_io_map(u_short sock, struct pccard_io_map *io)
{
    u_char map, ioctl, addr;
	printf ( "GETIOMAP unimplemented\n" ); return 0;
    map = io->map;
    if (map > 1) return -EINVAL;
    io->start = i365_get_pair(sock, I365_IO(map)+I365_W_START);
    io->stop = i365_get_pair(sock, I365_IO(map)+I365_W_STOP);
    ioctl = i365_get(sock, I365_IOCTL);
    addr = i365_get(sock, I365_ADDRWIN);
    io->speed = to_ns(ioctl & I365_IOCTL_WAIT(map)) ? 1 : 0;
    io->flags  = (addr & I365_ENA_IO(map)) ? MAP_ACTIVE : 0;
    io->flags |= (ioctl & I365_IOCTL_0WS(map)) ? MAP_0WS : 0;
    io->flags |= (ioctl & I365_IOCTL_16BIT(map)) ? MAP_16BIT : 0;
    io->flags |= (ioctl & I365_IOCTL_IOCS16(map)) ? MAP_AUTOSZ : 0;
    printf("i82365: GetIOMap(%d, %d) = %#2.2x, %d ns, "
          "%#4.4x-%#4.4x\n", sock, map, io->flags, io->speed,
          io->start, io->stop);
    return 0;
} // i365_get_io_map 
*/

/*====================================================================*/

/*static int i365_set_io_map(u_short sock, struct pccard_io_map *io)
{
    u_char map, ioctl;

    printf("i82365: SetIOMap(%d, %d, %#2.2x, %d ns, "
          "%#4.4x-%#4.4x)\n", sock, io->map, io->flags,
          io->speed, io->start, io->stop);
printf ( "UNIMPLEMENTED\n" );
	return 0;
    map = io->map;
    //if ((map > 1) || (io->start > 0xffff) || (io->stop > 0xffff) ||
    if ((map > 1) ||
        (io->stop < io->start)) return -EINVAL;
    // Turn off the window before changing anything 
    if (i365_get(sock, I365_ADDRWIN) & I365_ENA_IO(map))
        i365_bclr(sock, I365_ADDRWIN, I365_ENA_IO(map));
    i365_set_pair(sock, I365_IO(map)+I365_W_START, io->start);
    i365_set_pair(sock, I365_IO(map)+I365_W_STOP, io->stop);
    ioctl = i365_get(sock, I365_IOCTL) & ~I365_IOCTL_MASK(map);
    if (io->speed) ioctl |= I365_IOCTL_WAIT(map);
    if (io->flags & MAP_0WS) ioctl |= I365_IOCTL_0WS(map);
    if (io->flags & MAP_16BIT) ioctl |= I365_IOCTL_16BIT(map);
    if (io->flags & MAP_AUTOSZ) ioctl |= I365_IOCTL_IOCS16(map);
    i365_set(sock, I365_IOCTL, ioctl);
    // Turn on the window if necessary 
    if (io->flags & MAP_ACTIVE)
        i365_bset(sock, I365_ADDRWIN, I365_ENA_IO(map));
    return 0;
} // i365_set_io_map 
*/

/*
static int i365_set_mem_map(u_short sock, struct pccard_mem_map *mem)
{
    u_short base, i;
    u_char map;

    printf("i82365: SetMemMap(%d, %d, %#2.2x, %d ns, %#5.5lx-%#5.5"
          "lx, %#5.5x)\n", sock, mem->map, mem->flags, mem->speed,
          mem->sys_start, mem->sys_stop, mem->card_start);

printf ( "UNIMPLEMENTED\n" );
	return 0;
    map = mem->map;
    if ((map > 4) || (mem->card_start > 0x3ffffff) ||
        (mem->sys_start > mem->sys_stop) || (mem->speed > 1000))
        return -EINVAL;
    if (!(socket[sock].flags & IS_PCI) &&
        ((mem->sys_start > 0xffffff) || (mem->sys_stop > 0xffffff)))
        return -EINVAL;

    // Turn off the window before changing anything 
    if (i365_get(sock, I365_ADDRWIN) & I365_ENA_MEM(map))
        i365_bclr(sock, I365_ADDRWIN, I365_ENA_MEM(map));

    base = I365_MEM(map);
    i = (mem->sys_start >> 12) & 0x0fff;
    if (mem->flags & MAP_16BIT) i |= I365_MEM_16BIT;
    if (mem->flags & MAP_0WS) i |= I365_MEM_0WS;
    i365_set_pair(sock, base+I365_W_START, i);

    i = (mem->sys_stop >> 12) & 0x0fff;
    switch (to_cycles(mem->speed)) {
    case 0:     break;
    case 1:     i |= I365_MEM_WS0; break;
    case 2:     i |= I365_MEM_WS1; break;
    default:    i |= I365_MEM_WS1 | I365_MEM_WS0; break;
    }
    i365_set_pair(sock, base+I365_W_STOP, i);

    i = ((mem->card_start - mem->sys_start) >> 12) & 0x3fff;
    if (mem->flags & MAP_WRPROT) i |= I365_MEM_WRPROT;
    if (mem->flags & MAP_ATTRIB) i |= I365_MEM_REG;
    i365_set_pair(sock, base+I365_W_OFF, i);

    // Turn on the window if necessary 
    if (mem->flags & MAP_ACTIVE)
        i365_bset(sock, I365_ADDRWIN, I365_ENA_MEM(map));
    return 0;
} // i365_set_mem_map 
*/


int	i82365_interfacer ( interface_func_t func, int sockno, int par1, int par2, void* par3 ) {
	//int	i, j, k;
	//u_int	ui;
	u_char *upc;
	struct pcc_config_t * pccc;
	switch ( func ) {
	  case	INIT:
		mydriverid = par1;
		return	init_i82365();
	  case	SHUTDOWN:
		i365_set(sockno, I365_ADDRWIN, i365_get(sockno, I365_ADDRWIN) & 0x20 );
		i365_set(sockno, I365_INTCTL, 0x05 );
		sleepticks(2);
		i365_set(sockno,I365_INTCTL, 0x45 ); //no-reset, memory-card
		break;
	  case	MAPATTRMEM:
		i365_set(sockno,I365_POWER, 0xb1 );
		i365_set(sockno, I365_INTCTL, 0x05 );
		sleepticks(2);
		i365_set(sockno,I365_INTCTL, 0x45 ); //no-reset, memory-card
		i365_set(sockno, I365_ADDRWIN, i365_get(sockno, I365_ADDRWIN) & 0x20 );
		//i365_bclr(sockno, I365_ADDRWIN, 1 );
		i365_set(sockno, I365_MEM(0)+0, ( par1 >> 12 )& 0xff ); //start
		i365_set(sockno, I365_MEM(0)+1, ( par1 >> 20 ) & 0x0f );
		i365_set(sockno, I365_MEM(0)+2, ((par1 + par2 - 1 ) >> 12 ) & 0xff ); //end
		i365_set(sockno, I365_MEM(0)+3, (( par1 + par2 - 1 ) >> 20 ) & 0x0f  );
		i365_set(sockno, I365_MEM(0)+4, ((0x4000000 - par1) >> 12) & 0xff ); //offset low
		i365_set(sockno, I365_MEM(0)+5, 0x40 | (((0x40000000 - par1) >> 12) & 0x3f));
		i365_bset(sockno, I365_ADDRWIN, 1 );
		if ( ! ( 1 & i365_get ( sockno, I365_ADDRWIN ) ) ) return 1;
		break;
	  case	UNMAPATTRMEM:
		i365_set(sockno, I365_ADDRWIN, i365_get(sockno, I365_ADDRWIN) & 0x20 );
		i365_set(sockno,I365_INTCTL, 0x45 ); //no-reset, memory-card
		break;
	  case	SELECTCONFIG:	// Params: par1: config number; par3 config pointer pointer
		if ( 0 > pccsock[sockno].configoffset ) return 1;
		if ( NULL == (pccc = par3 ) ) return 2;
		// write config number to 
		upc = ioremap ( MAP_ATTRMEM_TO, MAP_ATTRMEM_LEN );
		if ( pccsock[sockno].configoffset > MAP_ATTRMEM_LEN ) return 3;
		if ( ( par1 & 0x7fffffc0 ) ) return 4;
		if ( pccc->index != par1 ) return 5;
		upc[pccsock[sockno].configoffset] = ( upc[pccsock[sockno].configoffset] & 0xc0 ) | ( par1 & 0x3f );
		i365_set(sockno, I365_IOCTL, (i365_get(sockno, I365_IOCTL) & 0xfe) | 0x20 );	// 16bit autosize
		i365_set(sockno, I365_IO(0)+0, pccc->iowin & 0xff);
		i365_set(sockno, I365_IO(0)+1, (pccc->iowin >> 8) & 0xff);
		i365_set(sockno, I365_IO(0)+2, (pccc->iowin+pccc->iolen - 1) & 0xff);
		i365_set(sockno, I365_IO(0)+3, ((pccc->iowin+pccc->iolen- 1) >> 8) & 0xff);
		// Disable mem mapping
		i365_bclr(sockno, I365_ADDRWIN, 1);
		i365_set(sockno, I365_INTCTL, 0x65);
		i365_bset(sockno, I365_ADDRWIN,0x40);
		break;
	  default:
		return	-1; // ERROR: Unknown function called
	}
	return	0;
}

// get_mem_map[1320]
// cirrus_get_state/set/opts...
// vg46x_get_state/...
// get_bridge_state/...

#endif /* CONFIG_PCMCIA */
