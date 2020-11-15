/* tag: openbios qt plugin skeleton
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */


extern "C" {
#include <pthread.h>
#include <unistd.h>
#include "unix/plugins.h"
#include "unix/plugin_pci.h"
}
#include "plugin_qt.h"
#include "pciconfig.h"
#include "fcode.h"

#define DEBUG

volatile unsigned char * fb=0;
volatile int gui_running=0;

typedef struct {
	int argc;
	char **argv;
} threaddata;

void *gui_thread(void *ptr)
{
	threaddata *td=(threaddata *)ptr;

	QApplication a(td->argc, td->argv);
	FrameBufferWidget w;

	a.setMainWidget(&w);
	w.show();

	fb=w.getFrameBuffer();

	gui_running=-1;
	a.exec();
	gui_running=0;

	return 0;
}

extern "C" {
extern int plugin_qt_init(void);
int plugin_qt_init(void)
{
	pthread_t mythread;
	char *args[]={ "plugin_qt" };
	threaddata mytd = { 1, args };

#ifdef DEBUG
	printf("Initializing \"framebuffer\" plugin...");
#endif
	pthread_create(&mythread, NULL, gui_thread, &mytd);
	while (!fb)
		usleep(20);

	/* now we have the framebuffer start address.
	 * updating pci config space to reflect this
	 */
#if (BITS > 32)
	*(u32 *)(pci_config_space+0x14)=(u32)((unsigned long)fb>>32);
#else
	*(u32 *)(pci_config_space+0x14)=0;
#endif
	*(u32 *)(pci_config_space+0x10)=(u32)((unsigned long)fb&0xffffffff);

	/* next is to write the rom address. We write that at a random
	 * address in pci config space for now.
	 */
#if (BITS > 32)
	*(u32 *)(pci_config_space+0x34)=(u32)((unsigned long)qt_fcode>>32);
#else
	*(u32 *)(pci_config_space+0x34)=0;
#endif
	*(u32 *)(pci_config_space+0x30)=(u32)((unsigned long)qt_fcode&0xffffffff);

	/* FIXME: we need to put the fcode image for this
	 * device to the rom resource, once it exists
	 */

	/* register pci device to be available to beginagain */
	pci_register_device(0, 2, 0, pci_config_space);

#ifdef DEBUG
	printf("done.\n");
#endif
	return 0;
}

PLUGIN_AUTHOR("Stefan Reinauer <stepan@openbios.org>")
PLUGIN_DESCRIPTION("QT gui plugin emulating framebuffer device")
PLUGIN_LICENSE("GPL v2")
PLUGIN_DEPENDENCIES("pci")

}
