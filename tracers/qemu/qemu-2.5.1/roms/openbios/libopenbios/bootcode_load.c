/* 
 * Raw bootcode loader (CHRP/Apple %BOOT)
 * Written by Mark Cave-Ayland 2013
 */

#include "config.h"
#include "kernel/kernel.h"
#include "libopenbios/bindings.h"
#include "libopenbios/bootcode_load.h"
#include "libc/diskio.h"
#include "drivers/drivers.h"
#define printf printk
#define debug printk


int 
bootcode_load(ihandle_t dev)
{
    int retval = -1, count = 0, fd;
    unsigned long bootcode, loadbase, entry, size, offset;
    ihandle_t bootcode_info;

    /* Mark the saved-program-state as invalid */
    feval("0 state-valid !");

    fd = open_ih(dev);
    if (fd == -1) {
        goto out;
    }

    /* If we don't have the get-bootcode-info word then we don't support
       loading bootcode via %BOOT */
    bootcode_info = find_ih_method("get-bootcode-info", dev);
    if (!bootcode_info) {
        goto out;
    }
    
    /* Default to loading at load-base */
    fword("load-base");
    loadbase = POP();
    entry = loadbase;
    size = 0;
    
#ifdef CONFIG_PPC
    /*
     * Apple OF does not honor load-base and instead uses pmBootLoad
     * value from the boot partition descriptor.
     *
     * Tested with:
     *   a debian image with QUIK installed
     *   a debian image with iQUIK installed (https://github.com/andreiw/quik)
     *   an IQUIK boot floppy
     *   a NetBSD boot floppy (boots stage 2)
     */
    if (is_apple()) {
        PUSH(bootcode_info);
        fword("execute");

        loadbase = POP();
        entry = POP();
        size = POP();
    }
#endif
    
    bootcode = loadbase;
    offset = 0;
    
    while(1) {
        if (seek_io(fd, offset) == -1)
            break;
        count = read_io(fd, (void *)bootcode, 512);
        offset += count;
        bootcode += count;
    }

    /* If we didn't read anything then exit */
    if (!count) {
        goto out;
    }

    /* Use proper file size if we got it from bootcode info */
    if (size == 0) {
        size = offset;
    }
    
    /* Initialise saved-program-state */
    PUSH(entry);
    feval("saved-program-state >sps.entry !");
    PUSH(size);
    feval("saved-program-state >sps.file-size !");
    feval("bootcode saved-program-state >sps.file-type !");

    feval("-1 state-valid !");

out:
    close_io(fd);
    return retval;
}

