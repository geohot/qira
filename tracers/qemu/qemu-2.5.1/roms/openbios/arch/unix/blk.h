
#ifndef _H_BLK
#define _H_BLK

extern void 	blk_init( void );
extern int	read_from_disk( int channel, int unit, int blk, unsigned long mphys, int size );

#endif   /* _H_BLK */
