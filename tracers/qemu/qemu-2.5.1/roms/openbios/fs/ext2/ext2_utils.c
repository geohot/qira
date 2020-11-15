/*
 *
 * (c) 2008-2009 Laurent Vivier <Laurent@lvivier.info>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 */

#include "libext2.h"
#include "ext2_utils.h"
#include "libopenbios/bindings.h"
#include "libc/diskio.h"
#include "libc/byteorder.h"

int ext2_probe(int fd, long long offset)
{
	struct ext2_super_block *super;

	super = (struct ext2_super_block*)malloc(sizeof(struct ext2_super_block));
	seek_io(fd, 2 * 512 + offset);
	read_io(fd, super, sizeof (*super));

	if (__le16_to_cpu(super->s_magic) != EXT2_SUPER_MAGIC) {
		free(super);
		return 0;
	}

	free(super);
	return -1;
}

void ext2_get_super(int fd, struct ext2_super_block *super)
{
	seek_io(fd, 2 * 512);
	read_io(fd, super, sizeof (*super));

	super->s_inodes_count = __le32_to_cpu(super->s_inodes_count);
	super->s_blocks_count = __le32_to_cpu(super->s_blocks_count);
	super->s_r_blocks_count = __le32_to_cpu(super->s_r_blocks_count);
	super->s_free_blocks_count = __le32_to_cpu(super->s_free_blocks_count);
	super->s_free_inodes_count = __le32_to_cpu(super->s_free_inodes_count);
	super->s_first_data_block = __le32_to_cpu(super->s_first_data_block);
	super->s_log_block_size = __le32_to_cpu(super->s_log_block_size);
	super->s_log_frag_size = __le32_to_cpu(super->s_log_frag_size);
	super->s_blocks_per_group = __le32_to_cpu(super->s_blocks_per_group);
	super->s_frags_per_group = __le32_to_cpu(super->s_frags_per_group);
	super->s_inodes_per_group = __le32_to_cpu(super->s_inodes_per_group);
	super->s_mtime = __le32_to_cpu(super->s_mtime);
	super->s_wtime = __le32_to_cpu(super->s_wtime);
	super->s_mnt_count = __le16_to_cpu(super->s_mnt_count);
	super->s_max_mnt_count = __le16_to_cpu(super->s_max_mnt_count);
	super->s_magic = __le16_to_cpu(super->s_magic);
	super->s_state = __le16_to_cpu(super->s_state);
	super->s_errors = __le16_to_cpu(super->s_errors);
	super->s_minor_rev_level = __le16_to_cpu(super->s_minor_rev_level);
	super->s_lastcheck = __le32_to_cpu(super->s_lastcheck);
	super->s_checkinterval = __le32_to_cpu(super->s_checkinterval);
	super->s_creator_os = __le32_to_cpu(super->s_creator_os);
	super->s_rev_level = __le32_to_cpu(super->s_rev_level);
	super->s_def_resuid = __le16_to_cpu(super->s_def_resuid);
	super->s_def_resgid = __le16_to_cpu(super->s_def_resgid);
	super->s_first_ino = __le32_to_cpu(super->s_first_ino);
	super->s_inode_size = __le16_to_cpu(super->s_inode_size);
	super->s_block_group_nr = __le16_to_cpu(super->s_block_group_nr);
	super->s_feature_compat = __le32_to_cpu(super->s_feature_compat);
	super->s_feature_incompat = __le32_to_cpu(super->s_feature_incompat);
	super->s_feature_ro_compat = __le32_to_cpu(super->s_feature_ro_compat);
	super->s_algorithm_usage_bitmap =
				__le32_to_cpu(super->s_algorithm_usage_bitmap);
	super->s_journal_inum = __le32_to_cpu(super->s_journal_inum);
	super->s_journal_dev = __le32_to_cpu(super->s_journal_dev);
	super->s_last_orphan = __le32_to_cpu(super->s_last_orphan);
	super->s_hash_seed[0] = __le32_to_cpu(super->s_hash_seed[0]);
	super->s_hash_seed[1] = __le32_to_cpu(super->s_hash_seed[1]);
	super->s_hash_seed[2] = __le32_to_cpu(super->s_hash_seed[2]);
	super->s_hash_seed[3] = __le32_to_cpu(super->s_hash_seed[3]);
	super->s_default_mount_opts =
				__le32_to_cpu(super->s_default_mount_opts);
	super->s_first_meta_bg = __le32_to_cpu(super->s_first_meta_bg);
}

void ext2_read_block(ext2_VOLUME* volume, unsigned int fsblock)
{
	long long offset;

	if (fsblock == volume->current)
		return;

	volume->current = fsblock;
	offset = fsblock * EXT2_BLOCK_SIZE(volume->super);

	seek_io(volume->fd, offset);
	read_io(volume->fd, volume->buffer, EXT2_BLOCK_SIZE(volume->super));
}

void ext2_get_group_desc(ext2_VOLUME* volume,
		   int group_id, struct ext2_group_desc *gdp)
{
	unsigned int block, offset;
	struct ext2_group_desc *le_gdp;

	block = 1 + volume->super->s_first_data_block;
	block += group_id / EXT2_DESC_PER_BLOCK(volume->super);
	ext2_read_block(volume,  block);

	offset = group_id % EXT2_DESC_PER_BLOCK(volume->super);
	offset *= sizeof(*gdp);

	le_gdp = (struct ext2_group_desc *)(volume->buffer + offset);

	gdp->bg_block_bitmap = __le32_to_cpu(le_gdp->bg_block_bitmap);
	gdp->bg_inode_bitmap = __le32_to_cpu(le_gdp->bg_inode_bitmap);
	gdp->bg_inode_table = __le32_to_cpu(le_gdp->bg_inode_table);
	gdp->bg_free_blocks_count = __le16_to_cpu(le_gdp->bg_free_blocks_count);
	gdp->bg_free_inodes_count = __le16_to_cpu(le_gdp->bg_free_inodes_count);
	gdp->bg_used_dirs_count = __le16_to_cpu(le_gdp->bg_used_dirs_count);
}

int ext2_get_inode(ext2_VOLUME* volume,
		    unsigned int ino, struct ext2_inode *inode)
{
	struct ext2_group_desc desc;
	unsigned int block;
	unsigned int group_id;
	unsigned int offset;
	struct ext2_inode *le_inode;
	int i;

	ino--;

	group_id = ino / EXT2_INODES_PER_GROUP(volume->super);
	ext2_get_group_desc(volume, group_id, &desc);

	ino %= EXT2_INODES_PER_GROUP(volume->super);

	block = desc.bg_inode_table;
	block += ino / (EXT2_BLOCK_SIZE(volume->super) /
			EXT2_INODE_SIZE(volume->super));
	ext2_read_block(volume, block);

	offset = ino % (EXT2_BLOCK_SIZE(volume->super) /
			EXT2_INODE_SIZE(volume->super));
	offset *= EXT2_INODE_SIZE(volume->super);

	le_inode = (struct ext2_inode *)(volume->buffer + offset);

	inode->i_mode = __le16_to_cpu(le_inode->i_mode);
	inode->i_uid = __le16_to_cpu(le_inode->i_uid);
	inode->i_size = __le32_to_cpu(le_inode->i_size);
	inode->i_atime = __le32_to_cpu(le_inode->i_atime);
	inode->i_ctime = __le32_to_cpu(le_inode->i_ctime);
	inode->i_mtime = __le32_to_cpu(le_inode->i_mtime);
	inode->i_dtime = __le32_to_cpu(le_inode->i_dtime);
	inode->i_gid = __le16_to_cpu(le_inode->i_gid);
	inode->i_links_count = __le16_to_cpu(le_inode->i_links_count);
	inode->i_blocks = __le32_to_cpu(le_inode->i_blocks);
	inode->i_flags = __le32_to_cpu(le_inode->i_flags);
	if (S_ISLNK(inode->i_mode)) {
		memcpy(inode->i_block, le_inode->i_block, EXT2_N_BLOCKS * 4);
	} else {
		for (i = 0; i < EXT2_N_BLOCKS; i++)
			inode->i_block[i] = __le32_to_cpu(le_inode->i_block[i]);
        }
	inode->i_generation = __le32_to_cpu(le_inode->i_generation);
	inode->i_file_acl = __le32_to_cpu(le_inode->i_file_acl);
	inode->i_dir_acl = __le32_to_cpu(le_inode->i_dir_acl);
	inode->i_faddr = __le32_to_cpu(le_inode->i_faddr);
	inode->osd2.linux2.l_i_frag = le_inode->osd2.linux2.l_i_frag;
	inode->osd2.linux2.l_i_fsize = le_inode->osd2.linux2.l_i_fsize;
	inode->osd2.linux2.l_i_uid_high =
			__le16_to_cpu(le_inode->osd2.linux2.l_i_uid_high);
	inode->osd2.linux2.l_i_gid_high =
			__le16_to_cpu(le_inode->osd2.linux2.l_i_gid_high);
	return 0;
}

unsigned int ext2_get_block_addr(ext2_VOLUME* volume, struct ext2_inode *inode,
				 unsigned int logical)
{
	unsigned int physical;
	unsigned int addr_per_block;

	/* direct */

	if (logical < EXT2_NDIR_BLOCKS) {
		physical = inode->i_block[logical];
		return physical;
	}

	/* indirect */

	logical -= EXT2_NDIR_BLOCKS;

	addr_per_block = EXT2_ADDR_PER_BLOCK (volume->super);
	if (logical < addr_per_block) {
		ext2_read_block(volume, inode->i_block[EXT2_IND_BLOCK]);
		physical = __le32_to_cpu(((unsigned int *)volume->buffer)[logical]);
		return physical;
	}

	/* double indirect */

	logical -=  addr_per_block;

	if (logical < addr_per_block * addr_per_block) {
		ext2_read_block(volume, inode->i_block[EXT2_DIND_BLOCK]);
		physical = __le32_to_cpu(((unsigned int *)volume->buffer)
						[logical / addr_per_block]);
		ext2_read_block(volume, physical);
		physical = __le32_to_cpu(((unsigned int *)volume->buffer)
						[logical % addr_per_block]);
		return physical;
	}

	/* triple indirect */

	logical -= addr_per_block * addr_per_block;
	ext2_read_block(volume, inode->i_block[EXT2_DIND_BLOCK]);
	physical = __le32_to_cpu(((unsigned int *)volume->buffer)
				[logical / (addr_per_block * addr_per_block)]);
	ext2_read_block(volume, physical);
	logical = logical % (addr_per_block * addr_per_block);
	physical = __le32_to_cpu(((unsigned int *)volume->buffer)[logical / addr_per_block]);
	ext2_read_block(volume, physical);
	physical = __le32_to_cpu(((unsigned int *)volume->buffer)[logical % addr_per_block]);
	return physical;
}

int ext2_read_data(ext2_VOLUME* volume, struct ext2_inode *inode,
		   off_t offset, char *buffer, size_t length)
{
	unsigned int logical, physical;
	int blocksize = EXT2_BLOCK_SIZE(volume->super);
	int shift;
	size_t read;

	if (offset >= inode->i_size)
		return -1;

	if (offset + length >= inode->i_size)
		length = inode->i_size - offset;

	read = 0;
	logical = offset / blocksize;
	shift = offset % blocksize;

	if (shift) {
		physical = ext2_get_block_addr(volume, inode, logical);
		ext2_read_block(volume, physical);

		if (length < blocksize - shift) {
			memcpy(buffer, volume->buffer + shift, length);
			return length;
		}
		read += blocksize - shift;
		memcpy(buffer, volume->buffer + shift, read);

		buffer += read;
		length -= read;
		logical++;
	}

	while (length) {
		physical = ext2_get_block_addr(volume, inode, logical);
		ext2_read_block(volume, physical);

		if (length < blocksize) {
			memcpy(buffer, volume->buffer, length);
			read += length;
			return read;
		}
		memcpy(buffer, volume->buffer, blocksize);

		buffer += blocksize;
		length -= blocksize;
		read += blocksize;
		logical++;
	}

	return read;
}

off_t ext2_dir_entry(ext2_VOLUME *volume, struct ext2_inode *inode,
		     off_t index, struct ext2_dir_entry_2 *entry)
{
	int ret;

	ret = ext2_read_data(volume, inode, index,
			     (char*)entry, sizeof(*entry));
	if (ret == -1)
		return -1;

        entry->inode = __le32_to_cpu(entry->inode);
        entry->rec_len = __le16_to_cpu(entry->rec_len);
	return index + entry->rec_len;
}

unsigned int ext2_seek_name(ext2_VOLUME *volume, const char *name)
{
	struct ext2_inode inode;
	int ret;
	unsigned int ino;
	off_t index;
	struct ext2_dir_entry_2 entry;

	ino = EXT2_ROOT_INO;
	while(1) {
		while (*name == '\\')
			name++;
		if (!*name)
		    break;
		ret = ext2_get_inode(volume, ino, &inode);
		if (ret == -1)
			return 0;
		index = 0;
		while (1) {
			index = ext2_dir_entry(volume, &inode, index, &entry);
			if (index == -1)
				return 0;
			ret = strncmp(name, entry.name, entry.name_len);
			if (ret == 0  &&
			    (name[entry.name_len] == 0 ||
			     name[entry.name_len] == '\\')) {
			     	ino = entry.inode;
				break;
			}
		}
		name += entry.name_len;
	}

	return ino;
}
