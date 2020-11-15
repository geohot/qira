//	pcmcia.h - Header file for PCMCIA support

#ifndef PCMCIA_H
#define	PCMCIA_H

typedef unsigned char	u_char;
typedef unsigned short	u_short;
typedef unsigned int	u_int;
typedef unsigned long	u_long;

typedef u_short		ioaddr_t;
extern int sockets;

#define	MAXPCCSOCKS	8
#define	MAXPCCCONFIGS	8

typedef	enum ebpdriver_t	{ I82365, SOMEDRIVER						} ebpdriver_t;
typedef enum interface_func_t	{ INIT, SHUTDOWN, MAPATTRMEM, UNMAPATTRMEM, SELECTCONFIG	} interface_func_t;
typedef enum ebpstatus_t	{ EMPTY, HASCARD, INITIALIZED, SUSPENDED, OTHERDEVICE, UNKNOWN	} ebpstatus_t;

struct	driver_interact_t {
	ebpdriver_t	id;
	int		(*f)(interface_func_t,int,int,int,int);
	char		*name;
};
struct	pccsock_t {
	ebpdriver_t	device;
	int		drivernum;
	ebpstatus_t	status;
		// Internal usage of the drivers:
	int		internalid;
	int		flags;
	int		ioaddr;
	int		type;
	int		configoffset;
	int		possibleconfignum;
	int		stringoffset;
	u_int		stringlength;
	int		rmask0;
};

extern struct	pccsock_t	pccsock[MAXPCCSOCKS];
extern u_int	pccsocks;

struct	pcc_config_t {
	u_char	index;
	u_char	irq;
	int	iowin;
	int	iolen;
};


int	i82365_interfacer(interface_func_t,int,int,int,void *);
void	sleepticks(int);

#define	EINVAL	22


//*********************************************************** cc.h:
/* Definitions for card status flags for GetStatus */
#define SS_WRPROT       0x0001
#define SS_CARDLOCK     0x0002
#define SS_EJECTION     0x0004
#define SS_INSERTION    0x0008
#define SS_BATDEAD      0x0010
#define SS_BATWARN      0x0020
#define SS_READY        0x0040
#define SS_DETECT       0x0080
#define SS_POWERON      0x0100
#define SS_GPI          0x0200
#define SS_STSCHG       0x0400
#define SS_CARDBUS      0x0800
#define SS_3VCARD       0x1000
#define SS_XVCARD       0x2000
#define SS_PENDING      0x4000

/* cc.h: for InquireSocket */
typedef struct socket_cap_t {
    u_int       features;
    u_int       irq_mask;
    u_int       map_size;
    ioaddr_t    io_offset;
    u_char      pci_irq;
    //struct pci_dev *cb_dev;
    //struct bus_operations *bus;
    void *cb_dev;
    void *bus;
} socket_cap_t;
/* InquireSocket capabilities */
#define SS_CAP_PAGE_REGS        0x0001
#define SS_CAP_VIRTUAL_BUS      0x0002
#define SS_CAP_MEM_ALIGN        0x0004
#define SS_CAP_STATIC_MAP       0x0008
#define SS_CAP_PCCARD           0x4000
#define SS_CAP_CARDBUS          0x8000

/* for GetSocket, SetSocket */
typedef struct socket_state_t {
    u_int       flags;
    u_int       csc_mask;
    u_char      Vcc, Vpp;
    u_char      io_irq;
} socket_state_t;

extern socket_state_t dead_socket;

/* Socket configuration flags */
#define SS_PWR_AUTO     0x0010
#define SS_IOCARD       0x0020
#define SS_RESET        0x0040
#define SS_DMA_MODE     0x0080
#define SS_SPKR_ENA     0x0100
#define SS_OUTPUT_ENA   0x0200
#define SS_DEBOUNCED    0x0400  /* Tell driver that the debounce delay has ended */
#define SS_ZVCARD       0x0800

/* Flags for I/O port and memory windows */
#define MAP_ACTIVE      0x01
#define MAP_16BIT       0x02
#define MAP_AUTOSZ      0x04
#define MAP_0WS         0x08
#define MAP_WRPROT      0x10
#define MAP_ATTRIB      0x20
#define MAP_USE_WAIT    0x40
#define MAP_PREFETCH    0x80

/* Use this just for bridge windows */
#define MAP_IOSPACE     0x20

typedef struct pccard_io_map {
    u_char      map;
    u_char      flags;
    u_short     speed;
    ioaddr_t    start, stop;
} pccard_io_map;


typedef struct pccard_mem_map {
    u_char      map;
    u_char      flags;
    u_short     speed;
    u_long      sys_start, sys_stop;
    u_int       card_start;
} pccard_mem_map;

typedef struct cb_bridge_map {
    u_char      map;
    u_char      flags;
    u_int       start, stop;
} cb_bridge_map;
// need the global function pointer struct? *TODO*
//************************************* end cc.h



#endif /* PCMCIA_H */
