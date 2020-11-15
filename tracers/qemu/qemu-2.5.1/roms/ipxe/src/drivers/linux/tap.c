/*
 * Copyright (C) 2010 Piotr Jaroszyński <p.jaroszynski@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <linux_api.h>
#include <ipxe/list.h>
#include <ipxe/linux.h>
#include <ipxe/malloc.h>
#include <ipxe/device.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/ethernet.h>
#include <ipxe/settings.h>
#include <ipxe/socket.h>

/* This hack prevents pre-2.6.32 headers from redefining struct sockaddr */
#define __GLIBC__ 2
#include <linux/socket.h>
#undef __GLIBC__
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>

#define RX_BUF_SIZE 1536

/** @file
 *
 * The TAP driver.
 *
 * The TAP is a Virtual Ethernet network device.
 */

struct tap_nic {
	/** Tap interface name */
	char * interface;
	/** File descriptor of the opened tap device */
	int fd;
};

/** Open the TAP device */
static int tap_open(struct net_device * netdev)
{
	struct tap_nic * nic = netdev->priv;
	struct ifreq ifr;
	int ret;

	nic->fd = linux_open("/dev/net/tun", O_RDWR);
	if (nic->fd < 0) {
		DBGC(nic, "tap %p open('/dev/net/tun') = %d (%s)\n", nic, nic->fd, linux_strerror(linux_errno));
		return nic->fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	/* IFF_NO_PI for no extra packet information */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, nic->interface, IFNAMSIZ);
	DBGC(nic, "tap %p interface = '%s'\n", nic, nic->interface);

	ret = linux_ioctl(nic->fd, TUNSETIFF, &ifr);

	if (ret != 0) {
		DBGC(nic, "tap %p ioctl(%d, ...) = %d (%s)\n", nic, nic->fd, ret, linux_strerror(linux_errno));
		linux_close(nic->fd);
		return ret;
	}

	/* Set nonblocking mode to make tap_poll easier */
	ret = linux_fcntl(nic->fd, F_SETFL, O_NONBLOCK);

	if (ret != 0) {
		DBGC(nic, "tap %p fcntl(%d, ...) = %d (%s)\n", nic, nic->fd, ret, linux_strerror(linux_errno));
		linux_close(nic->fd);
		return ret;
	}

	return 0;
}

/** Close the TAP device */
static void tap_close(struct net_device *netdev)
{
	struct tap_nic * nic = netdev->priv;
	linux_close(nic->fd);
}

/**
 * Transmit an ethernet packet.
 *
 * The packet can be written to the TAP device and marked as complete immediately.
 */
static int tap_transmit(struct net_device *netdev, struct io_buffer *iobuf)
{
	struct tap_nic * nic = netdev->priv;
	int rc;

	/* Pad and align packet */
	iob_pad(iobuf, ETH_ZLEN);

	rc = linux_write(nic->fd, iobuf->data, iobuf->tail - iobuf->data);
	DBGC2(nic, "tap %p wrote %d bytes\n", nic, rc);
	netdev_tx_complete(netdev, iobuf);

	return 0;
}

/** Poll for new packets */
static void tap_poll(struct net_device *netdev)
{
	struct tap_nic * nic = netdev->priv;
	struct pollfd pfd;
	struct io_buffer * iobuf;
	int r;

	pfd.fd = nic->fd;
	pfd.events = POLLIN;
	if (linux_poll(&pfd, 1, 0) == -1) {
		DBGC(nic, "tap %p poll failed (%s)\n", nic, linux_strerror(linux_errno));
		return;
	}
	if ((pfd.revents & POLLIN) == 0)
		return;

	/* At this point we know there is at least one new packet to be read */

	iobuf = alloc_iob(RX_BUF_SIZE);
	if (! iobuf)
		goto allocfail;

	while ((r = linux_read(nic->fd, iobuf->data, RX_BUF_SIZE)) > 0) {
		DBGC2(nic, "tap %p read %d bytes\n", nic, r);

		iob_put(iobuf, r);
		netdev_rx(netdev, iobuf);

		iobuf = alloc_iob(RX_BUF_SIZE);
		if (! iobuf)
			goto allocfail;
	}

	free_iob(iobuf);
	return;

allocfail:
	DBGC(nic, "tap %p alloc_iob failed\n", nic);
}

/**
 * Set irq.
 *
 * Not used on linux, provide a dummy implementation.
 */
static void tap_irq(struct net_device *netdev, int enable)
{
	struct tap_nic *nic = netdev->priv;

	DBGC(nic, "tap %p irq enable = %d\n", nic, enable);
}

/** Tap operations */
static struct net_device_operations tap_operations = {
	.open		= tap_open,
	.close		= tap_close,
	.transmit	= tap_transmit,
	.poll		= tap_poll,
	.irq		= tap_irq,
};

/** Handle a device request for the tap driver */
static int tap_probe(struct linux_device *device, struct linux_device_request *request)
{
	struct linux_setting *if_setting;
	struct net_device *netdev;
	struct tap_nic *nic;
	int rc;

	netdev = alloc_etherdev(sizeof(*nic));
	if (! netdev)
		return -ENOMEM;

	netdev_init(netdev, &tap_operations);
	nic = netdev->priv;
	linux_set_drvdata(device, netdev);
	netdev->dev = &device->dev;
	memset(nic, 0, sizeof(*nic));

	/* Look for the mandatory if setting */
	if_setting = linux_find_setting("if", &request->settings);

	/* No if setting */
	if (! if_setting) {
		printf("tap missing a mandatory if setting\n");
		rc = -EINVAL;
		goto err_settings;
	}

	nic->interface = if_setting->value;
	snprintf ( device->dev.name, sizeof ( device->dev.name ), "%s",
		   nic->interface );
	device->dev.desc.bus_type = BUS_TYPE_TAP;
	if_setting->applied = 1;

	/* Apply rest of the settings */
	linux_apply_settings(&request->settings, &netdev->settings.settings);

	/* Register network device */
	if ((rc = register_netdev(netdev)) != 0)
		goto err_register;

	netdev_link_up(netdev);

	return 0;

err_settings:
	unregister_netdev(netdev);
err_register:
	netdev_nullify(netdev);
	netdev_put(netdev);
	return rc;
}

/** Remove the device */
static void tap_remove(struct linux_device *device)
{
	struct net_device *netdev = linux_get_drvdata(device);
	unregister_netdev(netdev);
	netdev_nullify(netdev);
	netdev_put(netdev);
}

/** Tap linux_driver */
struct linux_driver tap_driver __linux_driver = {
	.name = "tap",
	.probe = tap_probe,
	.remove = tap_remove,
	.can_probe = 1,
};
