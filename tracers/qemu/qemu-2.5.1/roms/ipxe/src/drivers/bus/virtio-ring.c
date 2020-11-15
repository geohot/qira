/* virtio-pci.c - virtio ring management
 *
 * (c) Copyright 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 *  some parts from Linux Virtio Ring
 *
 *  Copyright Rusty Russell IBM Corporation 2007
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include "etherboot.h"
#include "ipxe/io.h"
#include "ipxe/virtio-ring.h"
#include "ipxe/virtio-pci.h"

#define BUG() do { \
   printf("BUG: failure at %s:%d/%s()!\n", \
          __FILE__, __LINE__, __FUNCTION__); \
   while(1); \
} while (0)
#define BUG_ON(condition) do { if (condition) BUG(); } while (0)

/*
 * vring_free
 *
 * put at the begin of the free list the current desc[head]
 */

void vring_detach(struct vring_virtqueue *vq, unsigned int head)
{
   struct vring *vr = &vq->vring;
   unsigned int i;

   /* find end of given descriptor */

   i = head;
   while (vr->desc[i].flags & VRING_DESC_F_NEXT)
           i = vr->desc[i].next;

   /* link it with free list and point to it */

   vr->desc[i].next = vq->free_head;
   wmb();
   vq->free_head = head;
}

/*
 * vring_get_buf
 *
 * get a buffer from the used list
 *
 */

void *vring_get_buf(struct vring_virtqueue *vq, unsigned int *len)
{
   struct vring *vr = &vq->vring;
   struct vring_used_elem *elem;
   u32 id;
   void *opaque;

   BUG_ON(!vring_more_used(vq));

   elem = &vr->used->ring[vq->last_used_idx % vr->num];
   wmb();
   id = elem->id;
   if (len != NULL)
           *len = elem->len;

   opaque = vq->vdata[id];

   vring_detach(vq, id);

   vq->last_used_idx++;

   return opaque;
}

void vring_add_buf(struct vring_virtqueue *vq,
		   struct vring_list list[],
		   unsigned int out, unsigned int in,
		   void *opaque, int num_added)
{
   struct vring *vr = &vq->vring;
   int i, avail, head, prev;

   BUG_ON(out + in == 0);

   prev = 0;
   head = vq->free_head;
   for (i = head; out; i = vr->desc[i].next, out--) {

           vr->desc[i].flags = VRING_DESC_F_NEXT;
           vr->desc[i].addr = (u64)virt_to_phys(list->addr);
           vr->desc[i].len = list->length;
           prev = i;
           list++;
   }
   for ( ; in; i = vr->desc[i].next, in--) {

           vr->desc[i].flags = VRING_DESC_F_NEXT|VRING_DESC_F_WRITE;
           vr->desc[i].addr = (u64)virt_to_phys(list->addr);
           vr->desc[i].len = list->length;
           prev = i;
           list++;
   }
   vr->desc[prev].flags &= ~VRING_DESC_F_NEXT;

   vq->free_head = i;

   vq->vdata[head] = opaque;

   avail = (vr->avail->idx + num_added) % vr->num;
   vr->avail->ring[avail] = head;
   wmb();
}

void vring_kick(unsigned int ioaddr, struct vring_virtqueue *vq, int num_added)
{
   struct vring *vr = &vq->vring;

   wmb();
   vr->avail->idx += num_added;

   mb();
   if (!(vr->used->flags & VRING_USED_F_NO_NOTIFY))
           vp_notify(ioaddr, vq->queue_index);
}

