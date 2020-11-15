/*
 * libhfsp - library for reading and writing Macintosh HFS+ volumes.
 *
 * a record contains a key and a folder or file and is part
 * of a btree.
 *
 * Copyright (C) 2000 Klaus Halfmann <khalfmann@libra.de>
 * Original 1996-1998 Robert Leslie <rob@mars.org>
 * Additional work by  Brad Boyer (flar@pants.nu)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * $Id: record.c,v 1.24 2000/10/17 05:58:46 hasi Exp $
 */

#include "config.h"
#include "libhfsp.h"
#include "hfstime.h"
#include "record.h"
#include "volume.h"
#include "btree.h"
#include "unicode.h"
#include "swab.h"

/* read a hfsp_cat_key from memory */
void* record_readkey(void* p, void* buf)
{
    hfsp_cat_key*   key = (hfsp_cat_key*) buf;
    const void*	    check;
    UInt16	    key_length, len,i;
    UInt16*	    cp;

    key->key_length = key_length    = bswabU16_inc(p);
    check = p;
    key->parent_cnid		    = bswabU32_inc(p);
    key->name.strlen = len	    = bswabU16_inc(p);
    cp = key->name.name;
    for (i=0; i < len; i++, cp++)
	*cp			    = bswabU16_inc(p);
	/* check if keylenght was correct */
    if (key_length != ((char*) p) - ((char*) check))
	 HFSP_ERROR(EINVAL, "Invalid key length in record_readkey");
    return p;
  fail:
    return NULL;
}

/* read a hfsp_extent_key from memory */
void* record_extent_readkey(void* p, void* buf)
{
    hfsp_extent_key* key = (hfsp_extent_key*) buf;
    UInt16  key_length;

    key->key_length = key_length    = bswabU16_inc(p);
    key->fork_type		    = bswabU8_inc(p);
    key->filler			    = bswabU8_inc(p);
    if (key_length != 10)
	HFSP_ERROR(-1, "Invalid key length in record_extent_readkey");
    key->file_id		    = bswabU32_inc(p);
    key->start_block		    = bswabU32_inc(p);
    return p;
  fail:
    return NULL;
}


/* read posix permission from memory */
static inline void* record_readperm(void *p, hfsp_perm* perm)
{
    perm->owner= bswabU32_inc(p);
    perm->group= bswabU32_inc(p);
    perm->mode = bswabU32_inc(p);
    perm->dev  = bswabU32_inc(p);
    return p;
}

/* read directory info */
static inline void* record_readDInfo(void *p, DInfo* info)
{
    info->frRect.top	= bswabU16_inc(p);
    info->frRect.left	= bswabU16_inc(p);
    info->frRect.bottom	= bswabU16_inc(p);
    info->frRect.right	= bswabU16_inc(p);
    info->frFlags	= bswabU16_inc(p);
    info->frLocation.v	= bswabU16_inc(p);
    info->frLocation.h	= bswabU16_inc(p);
    info->frView	= bswabU16_inc(p);
    return p;
}

/* read extra Directory info */
static inline void* record_readDXInfo(void *p, DXInfo* xinfo)
{
    xinfo->frScroll.v  = bswabU16_inc(p);
    xinfo->frScroll.h  = bswabU16_inc(p);
    xinfo->frOpenChain = bswabU32_inc(p);
    xinfo->frUnused    = bswabU16_inc(p);
    xinfo->frComment   = bswabU16_inc(p);
    xinfo->frPutAway   = bswabU32_inc(p);
    return p;
}

/* read a hfsp_cat_folder from memory */
static void* record_readfolder(void *p, hfsp_cat_folder* folder)
{
    folder->flags		= bswabU16_inc(p);
    folder->valence		= bswabU32_inc(p);
    folder->id			= bswabU32_inc(p);
    folder->create_date		= bswabU32_inc(p);
    folder->content_mod_date    = bswabU32_inc(p);
    folder->attribute_mod_date	= bswabU32_inc(p);
    folder->access_date		= bswabU32_inc(p);
    folder->backup_date		= bswabU32_inc(p);
    p = record_readperm	    (p, &folder->permissions);
    p = record_readDInfo    (p, &folder->user_info);
    p = record_readDXInfo   (p, &folder->finder_info);
    folder->text_encoding	= bswabU32_inc(p);
    folder->reserved		= bswabU32_inc(p);
    return p;
}

/* read file info */
static inline void* record_readFInfo(void *p, FInfo* info)
{
    info->fdType	= bswabU32_inc(p);
    info->fdCreator	= bswabU32_inc(p);
    info->fdFlags	= bswabU16_inc(p);
    info->fdLocation.v	= bswabU16_inc(p);
    info->fdLocation.h	= bswabU16_inc(p);
    info->fdFldr	= bswabU16_inc(p);
    return p;
}

/* read extra File info */
static inline void* record_readFXInfo(void *p, FXInfo* xinfo)
{
    SInt16 *q;
    xinfo->fdIconID	= bswabU16_inc(p);
    q=(SInt16*) p;
    q+=4; // skip unused
    p=(void *)q;
    xinfo->fdComment	= bswabU16_inc(p);
    xinfo->fdPutAway	= bswabU32_inc(p);
    return p;
}

/* read a hfsp_cat_file from memory */
static void* record_readfile(void *p, hfsp_cat_file* file)
{
    file->flags			= bswabU16_inc(p);
    file->reserved1		= bswabU32_inc(p);
    file->id			= bswabU32_inc(p);
    file->create_date		= bswabU32_inc(p);
    file->content_mod_date	= bswabU32_inc(p);
    file->attribute_mod_date	= bswabU32_inc(p);
    file->access_date		= bswabU32_inc(p);
    file->backup_date		= bswabU32_inc(p);
    p = record_readperm	    (p, &file->permissions);
    p = record_readFInfo    (p, &file->user_info);
    p = record_readFXInfo   (p, &file->finder_info);
    file->text_encoding		= bswabU32_inc(p);
    file->reserved2		= bswabU32_inc(p);
    p =	    volume_readfork (p, &file->data_fork);
    return  volume_readfork (p, &file->res_fork);
}

/* read a hfsp_cat_thread from memory */
static void* record_readthread(void *p, hfsp_cat_thread* entry)
{
    int	    i;
    UInt16  len;
    UInt16* cp;

    entry->         reserved	= bswabU16_inc(p);
    entry->	    parentID	= bswabU32_inc(p);
    entry->nodeName.strlen = len= bswabU16_inc(p);
    cp = entry->nodeName.name;
    if (len > 255)
        HFSP_ERROR(-1, "Invalid key length in record thread");
    for (i=0; i < len; i++, cp++)
	*cp			 = bswabU16_inc(p);
    return p;
 fail:
    return NULL;
}

/* read a hfsp_cat_entry from memory */
static void* record_readentry(void *p, hfsp_cat_entry* entry)
{
    UInt16 type = bswabU16_inc(p);
    entry->type = type;
    switch (type)
    {
	case HFSP_FOLDER:
	    return record_readfolder(p, &entry->u.folder);
	case HFSP_FILE:
	    return record_readfile  (p, &entry->u.file);
	case HFSP_FOLDER_THREAD:
	case HFSP_FILE_THREAD:
	    return record_readthread(p, &entry->u.thread);
	default:
	    HFSP_ERROR(-1, "Unexpected record type in record_readentry");
    } ;
  fail:
    return NULL;
}


/* Most of the functions here will not change the node in the btree,
   But this must be changed in the future ... */


/* intialize the record with the given index entry in the btree. */
static int record_init(record* r, btree* bt, node_buf* buf, UInt16 index)
{
    void *p;
    r-> tree   = bt;
    p = btree_key_by_index(bt,buf,index);
    if (!p)
	return -1;
    p = record_readkey  (p, &r->key);
    if (!p)
	return -1;
    p = record_readentry(p, &r->record);
    if (!p)
	return -1;
    r->node_index = buf->index;
    r-> keyind    = index;

    return 0;
}

/* intialize the record with the given index entry in the btree. */
static int record_init_extent(extent_record* r, btree* bt, node_buf* buf, UInt16 index)
{
    void *p;
    r-> tree   = bt;
    p = btree_key_by_index(bt, buf,index);
    if (!p)
	return -1;
    p = record_extent_readkey(p, &r->key);
    if (!p)
	return -1;
    p = volume_readextent(p, r->extent);
    if (!p)
	return -1;
    r->node_index = buf->index;
    r-> keyind    = index;

    return 0;
}

/* intialize the record to the first record of the tree
 * which is (per design) the root node.
 */
int record_init_root(record* r, btree* tree)
{
    // Position to first leaf node ...
    UInt32 leaf_head = tree->head.leaf_head;
    node_buf* buf = btree_node_by_index(tree, leaf_head);
    if (!buf)
	return -1;
    return record_init(r, tree, buf, 0);
}

/* Compare two cat_keys ... */
int record_key_compare(void* k1, void* k2)
{
    hfsp_cat_key* key1 = (hfsp_cat_key*) k1;
    hfsp_cat_key* key2 = (hfsp_cat_key*) k2;
    int diff = key2->parent_cnid - key1->parent_cnid;
    if (!diff) // same parent
	diff = fast_unicode_compare(&key1->name, &key2->name);
    return diff;
}

/* Compare two extent_keys ... */
int record_extent_key_compare(void* k1, void* k2)
{
    hfsp_extent_key* key1 = (hfsp_extent_key*) k1;
    hfsp_extent_key* key2 = (hfsp_extent_key*) k2;
    int diff = key2->fork_type - key1->fork_type;
    if (!diff) // same type
    {
	diff = key2->file_id - key1->file_id;
	if (!diff) // same file
	    diff = key2->start_block - key1->start_block;
    }
    return diff;
}

/* Position node in btree so that key might be inside */
static node_buf* record_find_node(btree* tree, void *key)
{
    int			start, end, mid, comp;  // components of a binary search
    void		*p = NULL;
    char		curr_key[tree->head.max_key_len];
		    // The current key under examination
    hfsp_key_read	readkey	    = tree->kread;
    hfsp_key_compare	key_compare = tree->kcomp;
    UInt32		index;
    node_buf*		node = btree_node_by_index(tree, tree->head.root);
    if (!node)
	HFSP_ERROR(-1, "record_find_node: Cant position to root node");
    while (node->desc.kind == HFSP_NODE_NDX)
    {
	mid = start = 0;
	end  = node->desc.num_rec;
	comp = -1;
	while (start < end)
	{
	    mid = (start + end) >> 1;
	    p = btree_key_by_index(tree, node, mid);
	    if (!p)
		HFSP_ERROR(-1, "record_find_node: unexpected error");
	    p = readkey  (p, curr_key);
	    if (!p)
		HFSP_ERROR(-1, "record_find_node: unexpected error");
	    comp = key_compare(curr_key, key);
	    if (comp > 0)
		start = mid + 1;
	    else if (comp < 0)
		end = mid;
	    else
		break;
	}
	if (!p) // Empty tree, fascinating ...
	    HFSP_ERROR(-1, "record_find_node: unexpected empty node");
	if (comp < 0)	// mmh interesting key is before this key ...
	{
	    if (mid == 0)
		return NULL;  // nothing before this key ..
	    p = btree_key_by_index(tree, node, mid-1);
	    if (!p)
		HFSP_ERROR(-1, "record_find_node: unexpected error");
	    p = readkey  (p, curr_key);
	    if (!p)
		HFSP_ERROR(-1, "record_find_node: unexpected error");
	}

	index = bswabU32_inc(p);
	node = btree_node_by_index(tree, index);
    }
    return node;	// go on and use the found node
  fail:
    return NULL;
}

/* search for the given key in the btree.
 *
 * returns pointer to memory just after key or NULL
 * In any case *keyind recives the index where the
 * key was found (or could be inserted.)
 */
static void *
record_find_key(btree* tree, void* key, int* keyind, UInt16* node_index)
{
    node_buf* buf = record_find_node(tree, key);
    if (buf)
    {
	int		    comp  = -1;
	int		    start = 0; // components of a binary search
	int		    end   = buf->desc.num_rec;
	int		    mid   = -1;
	void		    *p    = NULL;
	char		    curr_key[tree->head.max_key_len];
	hfsp_key_read	    readkey	= tree->kread;
	hfsp_key_compare    key_compare = tree->kcomp;
	while (start < end)
	{
	    mid = (start + end) >> 1;
	    p = btree_key_by_index(tree, buf, mid);
	    if (!p)
		HFSP_ERROR(-1, "record_init_key: unexpected error");
	    p = readkey  (p, curr_key);
	    if (!p)
		HFSP_ERROR(-1, "record_init_cat_key: unexpected error");
	    comp = key_compare(curr_key, key);
	    if (comp > 0)
		start = mid + 1;
	    else if (comp < 0)
		end = mid;
	    else
		break;
	}
	if (!p) // Empty tree, fascinating ...
	    HFSP_ERROR(ENOENT, "record_init_key: unexpected empty node");
	*keyind = mid;
	*node_index = buf->index;
	if (!comp)	// found something ...
	    return p;
    }
    HFSP_ERROR(ENOENT, NULL);
  fail:
    return NULL;
}

/* intialize the record by searching for the given key in the btree.
 *
 * r is umodified on error.
 */
static int
record_init_key(record* r, btree* tree, hfsp_cat_key* key)
{
    int	    keyind;
    UInt16  node_index;
    void    *p = record_find_key(tree, key, &keyind, &node_index);

    if (p)
    {
	r -> tree      = tree;
	r -> node_index= node_index;
	r -> keyind    = keyind;
	r -> key       = *key; // Better use a record_key_copy ...
	p = record_readentry(p, &r->record);
	if (!p)
	    HFSP_ERROR(-1, "record_init_key: unexpected error");
	return 0;
    }
  fail:
    return -1;
}

/* intialize the extent_record to the extent identified by the
 * (first) blockindex.
 *
 * forktype: either HFSP_EXTEND_DATA or HFSP_EXTEND_RSRC
 */
int record_init_file(extent_record* r, btree* tree,
		    UInt8 forktype, UInt32 fileId, UInt32 blockindex)
{
    int		    keyind;
    UInt16	    node_index;
    hfsp_extent_key key = { 10, forktype, 0, fileId, blockindex };
    void	    *p = record_find_key(tree, &key, &keyind, &node_index);

    if (p)
    {
	r -> tree      = tree;
	r -> node_index= node_index;
	r -> keyind    = keyind;
	r -> key       = key; // Better use a record_key_copy ...
	p =  volume_readextent(p, r->extent);
	if (!p)
	    HFSP_ERROR(-1, "record_init_file: unexpected error");
	return 0;
    }
  fail:
    return -1;
}

/* intialize the record to the folder identified by cnid
 */
int record_init_cnid(record* r, btree* tree, UInt32 cnid)
{
    hfsp_cat_key    thread_key;	    // the thread is the first record

    thread_key.key_length = 6;	    // null name (like '.' in unix )
    thread_key.parent_cnid = cnid;
    thread_key.name.strlen = 0;

    return record_init_key(r, tree, &thread_key);
}

/* intialize the record to the first record of the parent.
 */
int record_init_parent(record* r, record* parent)
{
    if (parent->record.type == HFSP_FOLDER)
	return record_init_cnid(r, parent->tree, parent->record.u.folder.id);
    else if(parent->record.type == HFSP_FOLDER_THREAD)
    {
	if (r != parent)
	    *r = *parent; // The folder thread is in fact the first entry, like '.'
	return 0;
    }
    HFSP_ERROR(EINVAL,
	"record_init_parent: parent is neither folder nor folder thread.");

  fail:
    return EINVAL;
}


/* find correct node record for given node and *pindex.
 *
 * index of record in this (or next) node
 * */
static node_buf* prepare_next(btree* tree, UInt16 node_index, UInt16* pindex)
{
    node_buf*	     buf    = btree_node_by_index(tree, node_index);
    btree_node_desc* desc   = &buf->desc;
    UInt32	     numrec = desc->num_rec;
    if (*pindex >= numrec) // move on to next node
    {
	UInt16 next = desc->next;
	*pindex = 0;
	if (!next   /* is there a next node ? */
	||  !( buf = btree_node_by_index(tree, next)))
	    return NULL;
    }
    return buf;
}
/* move record foreward to next entry.
 *
 * In case of an error the value of *r is undefined !
 */
int record_next(record* r)
{
    btree*	tree	= r->tree;
    UInt16	index	= r->keyind +1;
    UInt32	parent;
    node_buf*	buf	= prepare_next(tree, r->node_index, &index);

    if (!buf)
	return ENOENT;	// No (more) such file or directory

    parent = r->key.parent_cnid;

    if (record_init(r, tree, buf, index))
	return -1;

    if (r->key.parent_cnid != parent || // end of current directory
	index != r->keyind)		// internal error ?
	return ENOENT;	// No (more) such file or directory

    return 0;
}

/* move record foreward to next extent record.
 *
 * In case of an error the value of *r is undefined !
 */
int record_next_extent(extent_record* r)
{
    btree*	tree   = r->tree;
    UInt16	index  = r->keyind +1;
    UInt32	file_id;
    UInt8	fork_type;
    node_buf*	buf	= prepare_next(tree, r->node_index, &index);

    if (!buf)
	return ENOENT;	// No (more) such file or directory

    file_id	= r->key.file_id;
    fork_type	= r->key.fork_type;

    if (record_init_extent(r, tree, buf, index))
	return -1;

    if (r->key.file_id	 != file_id ||	    // end of current file
	r->key.fork_type != fork_type ||    // end of current fork
	index != r->keyind)		    // internal error ?
	return ENOENT;	// No (more) such file or directory

    return 0;
}

/* intialize the record by searching for the given string in the given folder.
 *
 * parent and r may be the same.
 */
int record_init_string_parent(record* r, record* parent, char* name)
{
    hfsp_cat_key key;

    if (parent->record.type == HFSP_FOLDER)
	key.parent_cnid = parent->record.u.folder.id;
    else if(parent->record.type == HFSP_FOLDER_THREAD)
	key.parent_cnid = parent->key.parent_cnid;
    else
	HFSP_ERROR(-1, "record_init_string_parent: parent is not a folder.");

    key.key_length = 6 + unicode_asc2uni(&key.name,name); // 6 for minumum size
    return record_init_key(r, parent->tree, &key);

  fail:
    return -1;
}

/* move record up in folder hierarchy (if possible) */
int record_up(record* r)
{
    if (r->record.type == HFSP_FOLDER)
    {
	// locate folder thread
	if (record_init_cnid(r, r->tree, r->record.u.folder.id))
	    return -1;
    }
    else if(r->record.type == HFSP_FOLDER_THREAD)
    {
	// do nothing were are already where we want to be
    }
    else
	HFSP_ERROR(-1, "record_up: record is neither folder nor folder thread.");

    if(r->record.type != HFSP_FOLDER_THREAD)
	HFSP_ERROR(-1, "record_up: unable to locate parent");
    return record_init_cnid(r, r->tree, r->record.u.thread.parentID);

  fail:
    return -1;
}

#ifdef DEBUG

/* print Quickdraw Point */
static void record_print_Point(Point* p)
{
    printf("[ v=%d, h=%d ]", p->v, p->h);
}

/* print Quickdraw Rect */
static void record_print_Rect(Rect* r)
{
    printf("[ top=%d, left=%d, bottom=%d, right=%d  ]",
	     r->top, r->left, r->bottom, r->right);
}

/* print the key of a record */
static void record_print_key(hfsp_cat_key* key)
{
    char buf[255]; // mh this _might_ overflow
    unicode_uni2asc(buf, &key->name, 255);
    printf("parent cnid :    %ld\n",   key->parent_cnid);
    printf("name        :    %s\n", buf);
}

/* print permissions */
static void record_print_perm(hfsp_perm* perm)
{
    printf("owner               :\t%ld\n",  perm->owner);
    printf("group               :\t%ld\n",  perm->group);
    printf("perm                :\t0x%lX\n",perm->mode);
    printf("dev                 :\t%ld\n",  perm->dev);
}

/* print Directory info */
static void record_print_DInfo(DInfo* dinfo)
{
    printf(  "frRect              :\t");    record_print_Rect(&dinfo->frRect);
    printf("\nfrFlags             :\t0X%X\n",    dinfo->frFlags);
    printf(  "frLocation          :\t");    record_print_Point(&dinfo->frLocation);
    printf("\nfrView              :\t0X%X\n",    dinfo->frView);
}

/* print extended Directory info */
static void record_print_DXInfo(DXInfo* xinfo)
{
    printf(  "frScroll            :\t");    record_print_Point(&xinfo->frScroll);
    printf("\nfrOpenChain         :\t%ld\n",  xinfo->frOpenChain);
    printf(  "frUnused            :\t%d\n",   xinfo->frUnused);
    printf(  "frComment           :\t%d\n",   xinfo->frComment);
    printf(  "frPutAway           :\t%ld\n",  xinfo->frPutAway);
}

static void record_print_folder(hfsp_cat_folder* folder)
{
    printf("flags               :\t0x%X\n",	folder->flags);
    printf("valence             :\t0x%lX\n",	folder->valence);
    printf("id                  :\t%ld\n",	folder->id);
    record_print_perm	(&folder->permissions);
    record_print_DInfo	(&folder->user_info);
    record_print_DXInfo	(&folder->finder_info);
    printf("text_encoding       :\t0x%lX\n",	folder->text_encoding);
    printf("reserved            :\t0x%lX\n",	folder->reserved);
}

/* print File info */
static void record_print_FInfo(FInfo* finfo)
{
    printf(  "fdType              :\t%4.4s\n", (char*) &finfo->fdType);
    printf(  "fdCreator           :\t%4.4s\n", (char*) &finfo->fdCreator);
    printf(  "fdFlags             :\t0X%X\n", finfo->fdFlags);
    printf(  "fdLocation          :\t");     record_print_Point(&finfo->fdLocation);
    printf("\nfdFldr              :\t%d\n",  finfo->fdFldr);
}

/* print extended File info */
static void record_print_FXInfo(FXInfo* xinfo)
{
    printf(  "fdIconID            :\t%d\n",   xinfo->fdIconID);
    // xinfo -> fdUnused;
    printf(  "fdComment           :\t%d\n",   xinfo->fdComment);
    printf(  "fdPutAway           :\t%ld\n",  xinfo->fdPutAway);
}

/* print folder entry */

/* print file entry */
static void record_print_file(hfsp_cat_file* file)
{
    printf("flags               :\t0x%X\n",	file->flags);
    printf("reserved1           :\t0x%lX\n",	file->reserved1);
    printf("id                  :\t%ld\n",	file->id);
    record_print_perm	(&file->permissions);
    record_print_FInfo	(&file->user_info);
    record_print_FXInfo	(&file->finder_info);
    printf("text_encoding       :\t0x%lX\n",	file->text_encoding);
    printf("reserved            :\t0x%lX\n",	file->reserved2);
    printf("Datafork:\n");
    volume_print_fork (&file->data_fork);
    printf("Rsrcfork:\n");
    volume_print_fork (&file->res_fork);
}

/* print info for a file or folder thread */
static void record_print_thread(hfsp_cat_thread* entry)
{
    char buf[255]; // mh this _might_ overflow
    unicode_uni2asc(buf, &entry->nodeName, 255);
    printf("parent cnid :\t%ld\n", entry->parentID);
    printf("name        :\t%s\n" , buf);
}

/* print the information for a record */
static void record_print_entry(hfsp_cat_entry* entry)
{
    switch (entry->type)
    {
	case HFSP_FOLDER:
	    printf("=== Folder ===\n");
	    return record_print_folder(&entry->u.folder);
	case HFSP_FILE:
	    printf("=== File ===\n");
	    return record_print_file  (&entry->u.file);
	case HFSP_FOLDER_THREAD:
	    printf("=== Folder Thread ===\n");
	    return record_print_thread(&entry->u.thread);
	case HFSP_FILE_THREAD:
	    printf("=== File Thread ==\n");
	    return record_print_thread(&entry->u.thread);
	default:
	    printf("=== Unknown Record Type ===\n");
    } ;
}

    /* Dump all the record information to stdout */
void record_print(record* r)
{
    printf ("keyind      :    %u\n", r->keyind);
    record_print_key  (&r->key);
    record_print_entry(&r->record);
}

#endif
