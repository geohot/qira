// pcmcia-opts.h
// special options file for development time. Later this could end in Config(?)
#ifndef __pcmciaopts
#define __pcmciaopts

	#define	_yes_ 1
	#define	_no_  0

	#define	SUPPORT_I82365		(_yes_)
//	#define	SUPPORT_YENTA		(_no_)
//	#define	SUPPORT_SOME_DRIVER	(_no_)

	#define PCMCIA_SHUTDOWN		(_yes_)
	#define	MAP_ATTRMEM_TO		0xd0000
	#define	MAP_ATTRMEM_LEN		0x02000

	#define	PDEBUG			3
	// The higher the more output you get, 0..3
	// Not fully implemented though, but for the future...

	#undef _yes_
	#undef _no_
#endif
