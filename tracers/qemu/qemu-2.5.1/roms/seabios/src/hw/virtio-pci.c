/* virtio-pci.c - pci interface for virtio interface
 *
 * (c) Copyright 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * some parts from Linux Virtio PCI driver
 *
 *  Copyright IBM Corp. 2007
 *  Authors: Anthony Liguori  <aliguori@us.ibm.com>
 *
 *  Adopted for Seabios: Gleb Natapov <gleb@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPLv3
 * See the COPYING file in the top-level directory.
 */

#include "config.h" // CONFIG_DEBUG_LEVEL
#include "malloc.h" // free
#include "output.h" // dprintf
#include "pci.h" // pci_config_readl
#include "pci_regs.h" // PCI_BASE_ADDRESS_0
#include "string.h" // memset
#include "virtio-pci.h"
#include "virtio-ring.h"

int vp_find_vq(unsigned int ioaddr, int queue_index,
               struct vring_virtqueue **p_vq)
{
   u16 num;

   ASSERT32FLAT();
   struct vring_virtqueue *vq = *p_vq = memalign_low(PAGE_SIZE, sizeof(*vq));
   if (!vq) {
       warn_noalloc();
       goto fail;
   }
   memset(vq, 0, sizeof(*vq));

   /* select the queue */

   outw(queue_index, ioaddr + VIRTIO_PCI_QUEUE_SEL);

   /* check if the queue is available */

   num = inw(ioaddr + VIRTIO_PCI_QUEUE_NUM);
   if (!num) {
       dprintf(1, "ERROR: queue size is 0\n");
       goto fail;
   }

   if (num > MAX_QUEUE_NUM) {
       dprintf(1, "ERROR: queue size %d > %d\n", num, MAX_QUEUE_NUM);
       goto fail;
   }

   /* check if the queue is already active */

   if (inl(ioaddr + VIRTIO_PCI_QUEUE_PFN)) {
       dprintf(1, "ERROR: queue already active\n");
       goto fail;
   }

   vq->queue_index = queue_index;

   /* initialize the queue */

   struct vring * vr = &vq->vring;
   vring_init(vr, num, (unsigned char*)&vq->queue);

   /* activate the queue
    *
    * NOTE: vr->desc is initialized by vring_init()
    */

   outl((unsigned long)virt_to_phys(vr->desc) >> PAGE_SHIFT,
        ioaddr + VIRTIO_PCI_QUEUE_PFN);

   return num;

fail:
   free(vq);
   *p_vq = NULL;
   return -1;
}

u16 vp_init_simple(u16 bdf)
{
    u16 ioaddr = pci_config_readl(bdf, PCI_BASE_ADDRESS_0) &
        PCI_BASE_ADDRESS_IO_MASK;

    vp_reset(ioaddr);
    pci_config_maskw(bdf, PCI_COMMAND, 0, PCI_COMMAND_MASTER);
    vp_set_status(ioaddr, VIRTIO_CONFIG_S_ACKNOWLEDGE |
                  VIRTIO_CONFIG_S_DRIVER );
    return ioaddr;
}
