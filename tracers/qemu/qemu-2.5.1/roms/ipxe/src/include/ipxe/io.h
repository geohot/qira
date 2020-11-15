#ifndef _IPXE_IO_H
#define _IPXE_IO_H

/** @file
 *
 * iPXE I/O API
 *
 * The I/O API provides methods for reading from and writing to
 * memory-mapped and I/O-mapped devices.
 *
 * The standard methods (readl()/writel() etc.) do not strictly check
 * the type of the address parameter; this is because traditional
 * usage does not necessarily provide the correct pointer type.  For
 * example, code written for ISA devices at fixed I/O addresses (such
 * as the keyboard controller) tend to use plain integer constants for
 * the address parameter.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/api.h>
#include <config/ioapi.h>
#include <ipxe/uaccess.h>

/** Page size */
#define PAGE_SIZE ( 1 << PAGE_SHIFT )

/** Page mask */
#define PAGE_MASK ( PAGE_SIZE - 1 )

/**
 * Calculate static inline I/O API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define IOAPI_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( IOAPI_PREFIX_ ## _subsys, _api_func )

/**
 * Provide an I/O API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_IOAPI( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( IOAPI_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline I/O API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_IOAPI_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( IOAPI_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent I/O API headers */

/* Include all architecture-dependent I/O API headers */
#include <bits/io.h>

/**
 * Wrap an I/O read
 *
 * @v _func		I/O API function
 * @v _type		Data type
 * @v io_addr		I/O address
 * @v _prefix		Prefix for address in debug message
 * @v _ndigits		Number of hex digits for this data type
 */
#define IOAPI_READ( _func, _type, io_addr, _prefix, _ndigits ) ( {	      \
	volatile _type *_io_addr =					      \
		( ( volatile _type * ) ( intptr_t ) (io_addr) );	      \
	_type _data = _func ( _io_addr );				      \
	DBGIO ( "[" _prefix " %08lx] => %0" #_ndigits "llx\n",		      \
		io_to_bus ( _io_addr ), ( unsigned long long ) _data );	      \
	_data; } )

/**
 * Wrap an I/O write
 *
 * @v _func		I/O API function
 * @v _type		Data type
 * @v data		Value to write
 * @v io_addr		I/O address
 * @v _prefix		Prefix for address in debug message
 * @v _ndigits		Number of hex digits for this data type
 */
#define IOAPI_WRITE( _func, _type, data, io_addr, _prefix, _ndigits ) do {    \
	volatile _type *_io_addr =					      \
		( ( volatile _type * ) ( intptr_t ) (io_addr) );	      \
	_type _data = (data);						      \
	DBGIO ( "[" _prefix " %08lx] <= %0" #_ndigits "llx\n",		      \
		io_to_bus ( _io_addr ), ( unsigned long long ) _data );	      \
	_func ( _data, _io_addr );					      \
	} while ( 0 )

/**
 * Wrap an I/O string read
 *
 * @v _func		I/O API function
 * @v _type		Data type
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of elements to read
 * @v _prefix		Prefix for address in debug message
 * @v _ndigits		Number of hex digits for this data type
 */
#define IOAPI_READS( _func, _type, io_addr, data, count, _prefix, _ndigits )  \
	do {								      \
	volatile _type *_io_addr =					      \
		( ( volatile _type * ) ( intptr_t ) (io_addr) );	      \
	void *_data_void = (data); /* Check data is a pointer */	      \
	_type * _data = ( ( _type * ) _data_void );			      \
	const _type * _dbg_data = _data;				      \
	unsigned int _count = (count);					      \
	unsigned int _dbg_count = _count;				      \
	_func ( _io_addr, _data, _count );				      \
	DBGIO ( "[" _prefix " %08lx] =>", io_to_bus ( _io_addr ) );	      \
	while ( _dbg_count-- ) {					      \
		DBGIO ( " %0" #_ndigits "llx",				      \
			( ( unsigned long long ) *(_dbg_data++) ) );	      \
	}								      \
	DBGIO ( "\n" );							      \
	} while ( 0 )

/**
 * Wrap an I/O string write
 *
 * @v _func		I/O API function
 * @v _type		Data type
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of elements to write
 * @v _prefix		Prefix for address in debug message
 * @v _ndigits		Number of hex digits for this data type
 */
#define IOAPI_WRITES( _func, _type, io_addr, data, count, _prefix, _ndigits ) \
	do {								      \
	volatile _type *_io_addr =					      \
		( ( volatile _type * ) ( intptr_t ) (io_addr) );	      \
	const void *_data_void = (data); /* Check data is a pointer */	      \
	const _type * _data = ( ( const _type * ) _data_void );		      \
	const _type * _dbg_data = _data;				      \
	unsigned int _count = (count);					      \
	unsigned int _dbg_count = _count;				      \
	DBGIO ( "[" _prefix " %08lx] <=", io_to_bus ( _io_addr ) );	      \
	while ( _dbg_count-- ) {					      \
		DBGIO ( " %0" #_ndigits "llx",				      \
			( ( unsigned long long ) *(_dbg_data++) ) );	      \
	}								      \
	DBGIO ( "\n" );							      \
	_func ( _io_addr, _data, _count );				      \
	} while ( 0 )

/**
 * Convert physical address to a bus address
 *
 * @v phys_addr		Physical address
 * @ret bus_addr	Bus address
 */
unsigned long phys_to_bus ( unsigned long phys_addr );

/**
 * Convert bus address to a physical address
 *
 * @v bus_addr		Bus address
 * @ret phys_addr	Physical address
 */
unsigned long bus_to_phys ( unsigned long bus_addr );

/**
 * Convert virtual address to a bus address
 *
 * @v addr		Virtual address
 * @ret bus_addr	Bus address
 */
static inline __always_inline unsigned long
virt_to_bus ( volatile const void *addr ) {
	return phys_to_bus ( virt_to_phys ( addr ) );
}

/**
 * Convert bus address to a virtual address
 *
 * @v bus_addr		Bus address
 * @ret addr		Virtual address
 *
 * This operation is not available under all memory models.
 */
static inline __always_inline void * bus_to_virt ( unsigned long bus_addr ) {
	return phys_to_virt ( bus_to_phys ( bus_addr ) );
}

/**
 * Map bus address as an I/O address
 *
 * @v bus_addr		Bus address
 * @v len		Length of region
 * @ret io_addr		I/O address
 */
void * ioremap ( unsigned long bus_addr, size_t len );

/**
 * Unmap I/O address
 *
 * @v io_addr		I/O address
 */
void iounmap ( volatile const void *io_addr );

/**
 * Convert I/O address to bus address (for debug only)
 *
 * @v io_addr		I/O address
 * @ret bus_addr	Bus address
 */
unsigned long io_to_bus ( volatile const void *io_addr );

/**
 * Read byte from memory-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint8_t readb ( volatile uint8_t *io_addr );
#define readb( io_addr ) IOAPI_READ ( readb, uint8_t, io_addr, "MEM", 2 )

/**
 * Read 16-bit word from memory-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint16_t readw ( volatile uint16_t *io_addr );
#define readw( io_addr ) IOAPI_READ ( readw, uint16_t, io_addr, "MEM", 4 )

/**
 * Read 32-bit dword from memory-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint32_t readl ( volatile uint32_t *io_addr );
#define readl( io_addr ) IOAPI_READ ( readl, uint32_t, io_addr, "MEM", 8 )

/**
 * Read 64-bit qword from memory-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint64_t readq ( volatile uint64_t *io_addr );
#define readq( io_addr ) IOAPI_READ ( readq, uint64_t, io_addr, "MEM", 16 )

/**
 * Write byte to memory-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void writeb ( uint8_t data, volatile uint8_t *io_addr );
#define writeb( data, io_addr ) \
	IOAPI_WRITE ( writeb, uint8_t, data, io_addr, "MEM", 2 )

/**
 * Write 16-bit word to memory-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void writew ( uint16_t data, volatile uint16_t *io_addr );
#define writew( data, io_addr ) \
	IOAPI_WRITE ( writew, uint16_t, data, io_addr, "MEM", 4 )

/**
 * Write 32-bit dword to memory-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void writel ( uint32_t data, volatile uint32_t *io_addr );
#define writel( data, io_addr ) \
	IOAPI_WRITE ( writel, uint32_t, data, io_addr, "MEM", 8 )

/**
 * Write 64-bit qword to memory-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void writeq ( uint64_t data, volatile uint64_t *io_addr );
#define writeq( data, io_addr ) \
	IOAPI_WRITE ( writeq, uint64_t, data, io_addr, "MEM", 16 )

/**
 * Read byte from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint8_t inb ( volatile uint8_t *io_addr );
#define inb( io_addr ) IOAPI_READ ( inb, uint8_t, io_addr, "IO", 2 )

/**
 * Read 16-bit word from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint16_t inw ( volatile uint16_t *io_addr );
#define inw( io_addr ) IOAPI_READ ( inw, uint16_t, io_addr, "IO", 4 )

/**
 * Read 32-bit dword from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
uint32_t inl ( volatile uint32_t *io_addr );
#define inl( io_addr ) IOAPI_READ ( inl, uint32_t, io_addr, "IO", 8 )

/**
 * Write byte to I/O-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void outb ( uint8_t data, volatile uint8_t *io_addr );
#define outb( data, io_addr ) \
	IOAPI_WRITE ( outb, uint8_t, data, io_addr, "IO", 2 )

/**
 * Write 16-bit word to I/O-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void outw ( uint16_t data, volatile uint16_t *io_addr );
#define outw( data, io_addr ) \
	IOAPI_WRITE ( outw, uint16_t, data, io_addr, "IO", 4 )

/**
 * Write 32-bit dword to I/O-mapped device
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
void outl ( uint32_t data, volatile uint32_t *io_addr );
#define outl( data, io_addr ) \
	IOAPI_WRITE ( outl, uint32_t, data, io_addr, "IO", 8 )

/**
 * Read bytes from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of bytes to read
 */
void insb ( volatile uint8_t *io_addr, uint8_t *data, unsigned int count );
#define insb( io_addr, data, count ) \
	IOAPI_READS ( insb, uint8_t, io_addr, data, count, "IO", 2 )

/**
 * Read 16-bit words from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of words to read
 */
void insw ( volatile uint16_t *io_addr, uint16_t *data, unsigned int count );
#define insw( io_addr, data, count ) \
	IOAPI_READS ( insw, uint16_t, io_addr, data, count, "IO", 4 )

/**
 * Read 32-bit words from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of words to read
 */
void insl ( volatile uint32_t *io_addr, uint32_t *data, unsigned int count );
#define insl( io_addr, data, count ) \
	IOAPI_READS ( insl, uint32_t, io_addr, data, count, "IO", 8 )

/**
 * Write bytes to I/O-mapped device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of bytes to write
 */
void outsb ( volatile uint8_t *io_addr, const uint8_t *data,
	     unsigned int count );
#define outsb( io_addr, data, count ) \
	IOAPI_WRITES ( outsb, uint8_t, io_addr, data, count, "IO", 2 )

/**
 * Write 16-bit words to I/O-mapped device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of words to write
 */
void outsw ( volatile uint16_t *io_addr, const uint16_t *data,
	     unsigned int count );
#define outsw( io_addr, data, count ) \
	IOAPI_WRITES ( outsw, uint16_t, io_addr, data, count, "IO", 4 )

/**
 * Write 32-bit words to I/O-mapped device
 *
 * @v io_addr		I/O address
 * @v data		Data buffer
 * @v count		Number of words to write
 */
void outsl ( volatile uint32_t *io_addr, const uint32_t *data,
	     unsigned int count );
#define outsl( io_addr, data, count ) \
	IOAPI_WRITES ( outsl, uint32_t, io_addr, data, count, "IO", 8 )

/**
 * Slow down I/O
 *
 */
void iodelay ( void );

/**
 * Read value from I/O-mapped device, slowly
 *
 * @v _func		Function to use to read value
 * @v data		Value to write
 * @v io_addr		I/O address
 */
#define INX_P( _func, _type, io_addr ) ( {				      \
	_type _data = _func ( (io_addr) );				      \
	iodelay();							      \
	_data; } )

/**
 * Read byte from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
#define inb_p( io_addr ) INX_P ( inb, uint8_t, io_addr )

/**
 * Read 16-bit word from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
#define inw_p( io_addr ) INX_P ( inw, uint16_t, io_addr )

/**
 * Read 32-bit dword from I/O-mapped device
 *
 * @v io_addr		I/O address
 * @ret data		Value read
 */
#define inl_p( io_addr ) INX_P ( inl, uint32_t, io_addr )

/**
 * Write value to I/O-mapped device, slowly
 *
 * @v _func		Function to use to write value
 * @v data		Value to write
 * @v io_addr		I/O address
 */
#define OUTX_P( _func, data, io_addr ) do {				      \
	_func ( (data), (io_addr) );					      \
	iodelay();							      \
	} while ( 0 )

/**
 * Write byte to I/O-mapped device, slowly
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
#define outb_p( data, io_addr ) OUTX_P ( outb, data, io_addr )

/**
 * Write 16-bit word to I/O-mapped device, slowly
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
#define outw_p( data, io_addr ) OUTX_P ( outw, data, io_addr )

/**
 * Write 32-bit dword to I/O-mapped device, slowly
 *
 * @v data		Value to write
 * @v io_addr		I/O address
 */
#define outl_p( data, io_addr ) OUTX_P ( outl, data, io_addr )

/**
 * Memory barrier
 *
 */
void mb ( void );
#define rmb()	mb()
#define wmb()	mb()

/** A usable memory region */
struct memory_region {
	/** Physical start address */
	uint64_t start;
	/** Physical end address */
	uint64_t end;
};

/** Maximum number of memory regions we expect to encounter */
#define MAX_MEMORY_REGIONS 8

/** A memory map */
struct memory_map {
	/** Memory regions */
	struct memory_region regions[MAX_MEMORY_REGIONS];
	/** Number of used regions */
	unsigned int count;
};

/**
 * Get memory map
 *
 * @v memmap		Memory map to fill in
 */
void get_memmap ( struct memory_map *memmap );

#endif /* _IPXE_IO_H */
