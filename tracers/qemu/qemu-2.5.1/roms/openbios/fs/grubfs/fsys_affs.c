#ifdef FSYS_AFFS
#include "shared.h"
#include "filesys.h"

/******************************** RDB definitions */
#define RDB_LOCATION_LIMIT 16
#define IDNAME_RIGIDDISK   0x5244534B  /* 'RDSK' */

struct RigidDiskBlock
{
    unsigned long   rdb_ID;
    unsigned long   rdb_SummedLongs;
    long            rdb_ChkSum;
    unsigned long   rdb_HostID;
    unsigned long   rdb_BlockBytes;
    unsigned long   rdb_Flags;
    unsigned long   rdb_BadBlockList;
    unsigned long   rdb_PartitionList;
    unsigned long   rdb_FileSysHeaderList;
    unsigned long   rdb_DriveInit;
    unsigned long   rdb_Reserved1[6];
    unsigned long   rdb_Cylinders;
    unsigned long   rdb_Sectors;
    unsigned long   rdb_Heads;
    unsigned long   rdb_Interleave;
    unsigned long   rdb_Park;
    unsigned long   rdb_Reserved2[3];
    unsigned long   rdb_WritePreComp;
    unsigned long   rdb_ReducedWrite;
    unsigned long   rdb_StepRate;
    unsigned long   rdb_Reserved3[5];
    unsigned long   rdb_RDBBlocksLo;
    unsigned long   rdb_RDBBlocksHi;
    unsigned long   rdb_LoCylinder;
    unsigned long   rdb_HiCylinder;
    unsigned long   rdb_CylBlocks;
    unsigned long   rdb_AutoParkSeconds;
    unsigned long   rdb_HighRDSKBlock;
    unsigned long   rdb_Reserved4;
    char    rdb_DiskVendor[8];
    char    rdb_DiskProduct[16];
    char    rdb_DiskRevision[4];
    char    rdb_ControllerVendor[8];
    char    rdb_ControllerProduct[16];
    char    rdb_ControllerRevision[4];
    char    rdb_DriveInitName[40];
};

struct PartitionBlock
{
    unsigned long   pb_ID;
    unsigned long   pb_SummedLongs;
    long            pb_ChkSum;
    unsigned long   pb_HostID;
    unsigned long   pb_Next;
    unsigned long   pb_Flags;
    unsigned long   pb_Reserved1[2];
    unsigned long   pb_DevFlags;
    char            pb_DriveName[32];
    unsigned long   pb_Reserved2[15];
    unsigned long   pb_Environment[20];
    unsigned long   pb_EReserved[12];
};

#define DE_TABLESIZE    0
#define DE_SIZEBLOCK    1
#define DE_BLOCKSIZE    2
#define DE_NUMHEADS     3
#define DE_SECSPERBLOCK 4
#define DE_BLKSPERTRACK 5
#define DE_RESERVEDBLKS 6
#define DE_PREFAC       7
#define DE_INTERLEAVE   8
#define DE_LOWCYL       9
#define DE_HIGHCYL      10
#define DE_UPPERCYL     DE_HIGHCYL
#define DE_NUMBUFFERS   11
#define DE_BUFMEMTYPE   12
#define DE_MEMBUFTYPE   DE_BUFMEMTYPE
#define DE_MAXTRANSFER  13
#define DE_MASK         14
#define DE_BOOTPRI      15
#define DE_DOSTYPE      16
#define DE_BAUD         17
#define DE_CONTROL      18
#define DE_BOOTBLOCKS   19


/******************************** AFFS definitions */
#define T_SHORT		2
#define T_LIST			16

#define ST_FILE		-3
#define ST_ROOT		1
#define ST_USERDIR	2

struct BootBlock{
	int id;
	int chksum;
	int rootblock;
	int data[127];
};

struct RootBlock{
	int p_type;					//0
	int n1[2];					//1-2
	int hashtable_size;		//3
	int n2;						//4
	int checksum;				//5
	int hashtable[72];		//6-77
	int bitmap_valid_flag;	//78
	int bitmap_ptrs[25];		//79-103
	int bitmap_extension;	//104
	int root_days;				//105
	int root_mins;				//106
	int root_ticks;			//107;
	char diskname[32];		//108-115
	int n3[2];					//116-117
	int volume_days;			//118
	int volume_mins;			//119
	int volume_ticks;			//120
	int creation_days;		//121
	int creation_mins;		//122
	int creation_ticks;		//123
	int n4[3];					//124-126
	int s_type;					//127
};

struct DirHeader {
	int p_type;					//0
	int own_key;				//1
	int n1[3];					//2-4
	int checksum;				//5
	int hashtable[72];		//6-77
	int n2;						//78
	int owner;					//79
	int protection;			//80
	int n3;						//81
	char comment[92];			//82-104
	int days;					//105
	int mins;					//106
	int ticks;					//107
	char name[32];				//108-115
	int n4[2];					//116-117
	int linkchain;				//118
	int n5[5];					//119-123
	int hashchain;				//124
	int parent;					//125
	int n6;						//126
	int s_type;					//127
};

struct FileHeader {
	int p_type;					//0
	int own_key;				//1
	int n1[3];					//2-4
	int checksum;				//5
	int filekey_table[72];	//6-77
	int n2;						//78
	int owner;					//79
	int protection;			//80
	int bytesize;				//81
	char comment[92];			//82-104
	int days;					//105
	int mins;					//106
	int ticks;					//107
	char name[32];				//108-115
	int n3[2];					//116-117
	int linkchain;				//118
	int n4[5];					//119-123
	int hashchain;				//124
	int parent;					//125
	int extension;				//126
	int s_type;					//127
};

struct FileKeyExtension{
	int p_type;					//0
	int own_key;				//1
	int table_size;			//2
	int n1[2];					//3-4
	int checksum;				//5
	int filekey_table[72];	//6-77
	int info[46];				//78-123
	int n2;						//124
	int parent;					//125
	int extension;				//126
	int s_type;					//127
};

struct Position {
	unsigned int block;
	short filekey;
	unsigned short byte;
	unsigned int offset;
};

struct ReadData {
	unsigned int header_block;
	struct Position current;
	unsigned int filesize;
};

//#warning "Big vs. little endian for configure needed"
#define AROS_BE2LONG(l)	\
	(                                  \
	    ((((unsigned long)(l)) >> 24) & 0x000000FFUL) | \
	    ((((unsigned long)(l)) >>  8) & 0x0000FF00UL) | \
	    ((((unsigned long)(l)) <<  8) & 0x00FF0000UL) | \
	    ((((unsigned long)(l)) << 24) & 0xFF000000UL)   \
	)

struct CacheBlock {
	int blocknum;
	unsigned short flags;
	unsigned short access_count;
	unsigned int blockbuffer[128];
};
#define LockBuffer(x) (((struct CacheBlock *)(x))->flags |= 0x0001)
#define UnLockBuffer(x) (((struct CacheBlock *)(x))->flags &= ~0x0001)

#define MAX_CACHE_BLOCKS 10

struct FSysBuffer {
	struct ReadData file;
	struct CacheBlock blocks[MAX_CACHE_BLOCKS];
};

#define bootBlock(x) ((struct BootBlock *)(x)->blockbuffer)
#define rootBlock(x) ((struct RootBlock *)(x)->blockbuffer)
#define dirHeader(x) ((struct DirHeader *)(x)->blockbuffer)
#define fileHeader(x) ((struct FileHeader *)(x)->blockbuffer)
#define extensionBlock(x) ((struct FileKeyExtension *)(x)->blockbuffer)

#define rdsk(x) ((struct RigidDiskBlock *)(x)->blockbuffer)
#define part(x) ((struct PartitionBlock *)(x)->blockbuffer)

static struct FSysBuffer *fsysb;
static int blockoffset; /* offset if there is an embedded RDB partition */
static int rootb;       /* block number of root block */
static int rdbb;        /* block number of rdb block */

static void initCache(void)
{
int i;

	for (i=0;i<MAX_CACHE_BLOCKS;i++)
	{
		fsysb->blocks[i].blocknum = -1;
		fsysb->blocks[i].flags = 0;
		fsysb->blocks[i].access_count = 0;
	}
}

static struct CacheBlock *getBlock(unsigned int block)
{
struct CacheBlock *freeblock;
int i;

	/* get first unlocked block */
	i = 0;
	do
	{
		freeblock = &fsysb->blocks[i++];
	} while (freeblock->flags & 0x0001);
	/* search through list if block is already loaded in */
	for (i=0;i<MAX_CACHE_BLOCKS;i++)
	{
		if (fsysb->blocks[i].blocknum == block)
		{
			fsysb->blocks[i].access_count++;
			return &fsysb->blocks[i];
		}
		if (!(fsysb->blocks[i].flags & 0x0001))
			if (freeblock->access_count>fsysb->blocks[i].access_count)
				freeblock = &fsysb->blocks[i];
	}
	freeblock->blocknum = block;
	devread(block+blockoffset, 0, 512, (char *)freeblock->blockbuffer);
	return freeblock;
}

static unsigned int calcChkSum(unsigned short SizeBlock, unsigned int *buffer)
{
unsigned int sum=0,count=0;

	for (count=0;count<SizeBlock;count++)
		sum += AROS_BE2LONG(buffer[count]);
	return sum;
}

int affs_mount(void) {
struct CacheBlock *cblock;
int i;

	if (
			(current_drive & 0x80) &&
			(current_partition != 0xFFFFFF) &&
			(current_slice != 0x30)
		)
		return 0;
	fsysb = (struct FSysBuffer *)FSYS_BUF;
	blockoffset = 0;
	initCache();
	/* check for rdb partitiontable */
	for (i=0;i<RDB_LOCATION_LIMIT;i++)
	{
		cblock = getBlock(i);
		if (
				(
					((AROS_BE2LONG(bootBlock(cblock)->id) & 0xFFFFFF00)==0x444F5300) &&
					((AROS_BE2LONG(bootBlock(cblock)->id) & 0xFF)>0)
				) ||
				(AROS_BE2LONG(cblock->blockbuffer[0]) == IDNAME_RIGIDDISK)
			)
			break;
	}
	if (i == RDB_LOCATION_LIMIT)
		return 0;
	if (AROS_BE2LONG(cblock->blockbuffer[0]) == IDNAME_RIGIDDISK)
	{
		/* we have an RDB partition table within a MBR-Partition */
		rdbb = i;
	}
	else if (i<2)
	{
		/* partition type is 0x30 = AROS and AFFS formatted */
		rdbb = RDB_LOCATION_LIMIT;
		rootb = (part_length-1+2)/2;
		cblock = getBlock(rootb);
		if (
				(AROS_BE2LONG(rootBlock(cblock)->p_type) != T_SHORT) ||
				(AROS_BE2LONG(rootBlock(cblock)->s_type) != ST_ROOT) ||
				calcChkSum(128, cblock->blockbuffer)
			)
			return 0;
	}
	else
		return 0;
	return 1;
}

static int seek(unsigned long offset)
{
struct CacheBlock *cblock;
unsigned long block;
unsigned long togo;

	block = fsysb->file.header_block;

	togo = offset / 512;
	fsysb->file.current.filekey = 71-(togo % 72);
	togo /= 72;
	fsysb->file.current.byte = offset % 512;
	fsysb->file.current.offset = offset;
	while ((togo) && (block))
	{
		disk_read_func = disk_read_hook;
		cblock = getBlock(block);
                disk_read_func = NULL;
		block = AROS_BE2LONG(extensionBlock(cblock)->extension);
		togo--;
	}
	if (togo)
		return 1;
	fsysb->file.current.block = block;
	return 0;
}

int affs_read(char *buf, int len) {
struct CacheBlock *cblock;
unsigned short size;
unsigned int readbytes = 0;

	if (fsysb->file.current.offset != filepos)
	{
		if (seek(filepos))
			return ERR_FILELENGTH;
	}
	if (fsysb->file.current.block == 0)
		return 0;
	if (len>(fsysb->file.filesize-fsysb->file.current.offset))
		len=fsysb->file.filesize-fsysb->file.current.offset;
	disk_read_func = disk_read_hook;
	cblock = getBlock(fsysb->file.current.block);
        disk_read_func = NULL;
	while (len)
	{
		disk_read_func = disk_read_hook;
		if (fsysb->file.current.filekey<0)
		{
			fsysb->file.current.filekey = 71;
			fsysb->file.current.block = AROS_BE2LONG(extensionBlock(cblock)->extension);
			if (fsysb->file.current.block)
			{
				cblock = getBlock(fsysb->file.current.block);
			}
                        //#warning "else shouldn't occour"
		}
		size = 512;
		size -= fsysb->file.current.byte;
		if (size>len)
		{
			size = len;
			devread
				(
					AROS_BE2LONG
					(
						extensionBlock(cblock)->filekey_table
							[fsysb->file.current.filekey]
					)+blockoffset,
					fsysb->file.current.byte, size, (char *)((long)buf+readbytes)
				);
			fsysb->file.current.byte += size;
		}
		else
		{
			devread
				(
					AROS_BE2LONG
					(
						extensionBlock(cblock)->filekey_table
							[fsysb->file.current.filekey]
					)+blockoffset,
					fsysb->file.current.byte, size, (char *)((long)buf+readbytes)
				);
			fsysb->file.current.byte = 0;
			fsysb->file.current.filekey--;
		}
                disk_read_func = NULL;
		len -= size;
		readbytes += size;
	}
	fsysb->file.current.offset += readbytes;
	filepos = fsysb->file.current.offset;
	return readbytes;
}

static unsigned char capitalch(unsigned char ch, unsigned char flags)
{

	if ((flags==0) || (flags==1))
		return (unsigned char)((ch>='a') && (ch<='z') ? ch-('a'-'A') : ch);
	else		// DOS\(>=2)
		return (unsigned char)(((ch>=224) && (ch<=254) && (ch!=247)) ||
				 ((ch>='a') && (ch<='z')) ? ch-('a'-'A') : ch);
}

// str2 is a BCPL string
static int noCaseStrCmp(char *str1, char *str2, unsigned char flags)
{
unsigned char length;

	length=str2++[0];
	do {
		if ((*str1==0) && (length==0))
			return 0;
		length--;
//		if ((*str1==0) && (*str2==0)) return 1;
	} while (capitalch(*str1++,flags)==capitalch(*str2++,flags));
	str1--;
	return (*str1) ? 1 : -1;
}

static unsigned int getHashKey(char *name,unsigned int tablesize, unsigned char flags)
{
unsigned int length;

	length=0;
	while (name[length] != 0)
	    length++;
	while (*name!=0)
		length=(length * 13 +capitalch(*name++,flags)) & 0x7FF;
	return length%tablesize;
}

static grub_error_t getHeaderBlock(char *name, struct CacheBlock **dirh)
{
int key;

	key = getHashKey(name, 72, 1);
	if (!dirHeader(*dirh)->hashtable[key])
		return ERR_FILE_NOT_FOUND;
	*dirh = getBlock(AROS_BE2LONG(dirHeader(*dirh)->hashtable[key]));
	if (calcChkSum(128, (*dirh)->blockbuffer))
	{
#ifdef DEBUG_AFFS
printf("ghb: %d\n", (*dirh)->blocknum);
#endif
		return ERR_FSYS_CORRUPT;
	}
	if (AROS_BE2LONG(dirHeader(*dirh)->p_type) != T_SHORT)
		return ERR_BAD_FILETYPE;
	while (noCaseStrCmp(name,dirHeader(*dirh)->name,1) != 0)
	{
		if (!dirHeader(*dirh)->hashchain)
			return ERR_FILE_NOT_FOUND;
		*dirh = getBlock(AROS_BE2LONG(dirHeader(*dirh)->hashchain));
		if (calcChkSum(128, (*dirh)->blockbuffer))
		{
#ifdef DEBUG_AFFS
printf("ghb2: %d\n", (*dirh)->blocknum);
#endif
			return ERR_FSYS_CORRUPT;
		}
		if (AROS_BE2LONG(dirHeader(*dirh)->p_type) != T_SHORT)
			return ERR_BAD_FILETYPE;
	}
	return 0;
}

static char *copyPart(char *src, char *dst)
{
	while ((*src != '/') && (*src))
		*dst++ = *src++;
	if (*src == '/')
		src++;
	*dst-- = 0;
	/* cut off spaces at the end */
	while (*dst == ' ')
		*dst-- = 0;
	return src;
}

static grub_error_t findBlock(char *name, struct CacheBlock **dirh)
{
char dname[32];
int block;

	name++;	/* skip "/" */
	/* partition table part */
	if (rdbb < RDB_LOCATION_LIMIT)
	{
	int bpc;

		blockoffset = 0;
		*dirh = getBlock(rdbb);
		if (*name==0)
			return 0;
		name = copyPart(name, dname);
		bpc = AROS_BE2LONG(rdsk(*dirh)->rdb_Sectors)*AROS_BE2LONG(rdsk(*dirh)->rdb_Heads);
		block = AROS_BE2LONG(rdsk(*dirh)->rdb_PartitionList);
		while (block != -1)
		{
			*dirh = getBlock(block);
			if (noCaseStrCmp(dname, part(*dirh)->pb_DriveName, 1) == 0)
				break;
			block = AROS_BE2LONG(part(*dirh)->pb_Next);
		}
		if (block == -1)
			return ERR_FILE_NOT_FOUND;
		if	(
				((AROS_BE2LONG(part(*dirh)->pb_Environment[DE_DOSTYPE]) & 0xFFFFFF00)!=0x444F5300) ||
				((AROS_BE2LONG(part(*dirh)->pb_Environment[DE_DOSTYPE]) & 0xFF)==0)
			)
			return ERR_BAD_FILETYPE;
		blockoffset = AROS_BE2LONG(part(*dirh)->pb_Environment[DE_LOWCYL]);
		rootb = AROS_BE2LONG(part(*dirh)->pb_Environment[DE_HIGHCYL]);
		rootb = rootb-blockoffset+1; /* highcyl-lowcyl+1 */
		rootb *= bpc;
		rootb = rootb-1+AROS_BE2LONG(part(*dirh)->pb_Environment[DE_RESERVEDBLKS]);
		rootb /= 2;
		blockoffset *= bpc;
	}

	/* filesystem part */
	*dirh = getBlock(rootb);
	while (*name)
	{
		if (
				(AROS_BE2LONG(dirHeader(*dirh)->s_type) != ST_ROOT) &&
				(AROS_BE2LONG(dirHeader(*dirh)->s_type) != ST_USERDIR)
			)
			return ERR_BAD_FILETYPE;
		name = copyPart(name, dname);
		errnum = getHeaderBlock(dname, dirh);
		if (errnum)
			return errnum;
	}
	return 0;
}

#ifndef STAGE1_5
static void checkPossibility(char *filename, char *bstr)
{
	char cstr[32];

	if (noCaseStrCmp(filename, bstr, 1)<=0)
	{
		if (print_possibilities>0)
			print_possibilities = -print_possibilities;
		memcpy(cstr, bstr+1, bstr[0]);
		cstr[bstr[0]]=0;
		print_a_completion(cstr);
	}
}
#else
#define checkPossibility(a, b) do { } while(0)
#endif

int affs_dir(char *dirname)
{
    struct CacheBlock *buffer1;
    struct CacheBlock *buffer2;
    char *current = dirname;
    char filename[128];
    char *fname = filename;
    int i,block;

    if (print_possibilities)
    {
	while (*current)
	    current++;
	while (*current != '/')
	    current--;
	current++;
	while (*current)
	{
	    *fname++ = *current;
	    *current++ = 0;
	}
	*fname=0;
	errnum = findBlock(dirname, &buffer1);
	if (errnum)
	    return 0;
	if (AROS_BE2LONG(dirHeader(buffer1)->p_type) == IDNAME_RIGIDDISK)
	{
	    block = AROS_BE2LONG(rdsk(buffer1)->rdb_PartitionList);
	    while (block != -1)
	    {
		buffer1 = getBlock(block);
		checkPossibility(filename, part(buffer1)->pb_DriveName);
		block = AROS_BE2LONG(part(buffer1)->pb_Next);
	    }
#ifndef STAGE1_5
	    if (*filename == 0)
		if (print_possibilities>0)
		    print_possibilities = -print_possibilities;
#endif
	}
	else if (AROS_BE2LONG(dirHeader(buffer1)->p_type) == T_SHORT)
	{
	    LockBuffer(buffer1);
	    for (i=0;i<72;i++)
	    {
		block = dirHeader(buffer1)->hashtable[i];
		while (block)
		{
		    buffer2 = getBlock(AROS_BE2LONG(block));
		    if (calcChkSum(128, buffer2->blockbuffer))
		    {
			errnum = ERR_FSYS_CORRUPT;
			return 0;
		    }
		    if (AROS_BE2LONG(dirHeader(buffer2)->p_type) != T_SHORT)
		    {
			errnum = ERR_BAD_FILETYPE;
			return 0;
		    }
		    checkPossibility(filename, dirHeader(buffer2)->name);
		    block = dirHeader(buffer2)->hashchain;
		}
	    }
	    UnLockBuffer(buffer1);
#ifndef STAGE1_5
	    if (*filename == 0)
		if (print_possibilities>0)
		    print_possibilities = -print_possibilities;
#endif
	}
	else
	{
	    errnum = ERR_BAD_FILETYPE;
	    return 0;
	}
	while (*current != '/')
	    current--;
	current++;
	fname = filename;
	while (*fname)
	    *current++ = *fname++;
        //#warning "TODO: add some more chars until possibilities differ"
	if (print_possibilities>0)
	    errnum = ERR_FILE_NOT_FOUND;
	return (print_possibilities<0);
    }
    else
    {
	while (*current && !isspace(*current))
	    *fname++ = *current++;
	*fname = 0;

	errnum = findBlock(filename, &buffer2);
	if (errnum)
	    return 0;
	if (AROS_BE2LONG(fileHeader(buffer2)->s_type)!=ST_FILE)
	{
	    errnum = ERR_BAD_FILETYPE;
	    return 0;
	}
	fsysb->file.header_block = AROS_BE2LONG(fileHeader(buffer2)->own_key);
	fsysb->file.current.block = AROS_BE2LONG(fileHeader(buffer2)->own_key);
	fsysb->file.current.filekey = 71;
	fsysb->file.current.byte = 0;
	fsysb->file.current.offset = 0;
	fsysb->file.filesize = AROS_BE2LONG(fileHeader(buffer2)->bytesize);
	filepos = 0;
	filemax = fsysb->file.filesize;
	return 1;
    }
}
#endif
