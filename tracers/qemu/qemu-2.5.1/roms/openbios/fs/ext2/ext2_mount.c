/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libext2.h"
#include "ext2.h"
#include "ext2_utils.h"

#define SB_OFFSET (2)

ext2_VOLUME* ext2_mount(int fd)
{
	ext2_VOLUME *volume;
	struct ext2_super_block *super;
	char *buffer;

	super = (struct ext2_super_block*)malloc(sizeof(struct ext2_super_block));
	if (super == NULL)
		return NULL;

	ext2_get_super(fd, super);
	if (super->s_magic != EXT2_SUPER_MAGIC) {
		free(super);
		return NULL;
	}

	buffer = (char*)malloc(EXT2_BLOCK_SIZE(super));
	if (buffer == NULL) {
		free(super);
		return NULL;
	}

	volume = (ext2_VOLUME*)malloc(sizeof(ext2_VOLUME));
	if (volume == NULL) {
		free(super);
		free(buffer);
		return NULL;
	}

	volume->buffer = buffer;
	volume->fd = fd;
	volume->super = super;

	volume->current = -1;
	ext2_read_block(volume, 0);

	return volume;
}

int ext2_umount(ext2_VOLUME* volume)
{
	if (volume == NULL)
		return -1;
	free(volume->super);
	free(volume->buffer);
	free(volume);
	return 0;
}
