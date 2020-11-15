/*
 * ADB bus definitions for Open Hack'Ware
 *
 * Copyright (c) 2004-2005 Jocelyn Mayer
 * 
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if !defined(__OHW_ADB_H__)
#define __OHW_ADB_H__

typedef struct adb_bus_t adb_bus_t;
typedef struct adb_dev_t adb_dev_t;

#define ADB_BUF_SIZE 8
struct adb_bus_t {
    void *host;
    int (*req)(void *host, const uint8_t *snd_buf, int len, uint8_t *rcv_buf);
    adb_dev_t *devices;
};

struct adb_dev_t {
    adb_dev_t *next;
    adb_bus_t *bus;
    uint8_t addr;
    uint8_t type;
    uint32_t state;
};

#define ADB_BUF_SIZE 8

/* ADB commands */
enum {
    ADB_SEND_RESET = 0x00,
    ADB_FLUSH      = 0x01,
    ADB_LISTEN     = 0x08,
    ADB_TALK       = 0x0C,
};
/* ADB default IDs before relocation */
enum {
    ADB_PROTECT    = 0x01,
    ADB_KEYBD      = 0x02,
    ADB_MOUSE      = 0x03,
    ADB_ABS        = 0x04,
    ADB_MODEM      = 0x05,
    ADB_RES        = 0x06,
    ADB_MISC       = 0x07,
};
/* ADB special device handlers IDs */
enum {
    ADB_CHADDR        = 0x00,
    ADB_CHADDR_ACTIV  = 0xFD,
    ADB_CHADDR_NOCOLL = 0xFE,
    ADB_SELF_TEST     = 0xFF,
};

int adb_cmd (adb_dev_t *dev, uint8_t cmd, uint8_t reg,
             uint8_t *buf, int len);
void adb_bus_reset (adb_bus_t *bus);
adb_bus_t *adb_bus_new (void *host,
                        int (*req)(void *host, const uint8_t *snd_buf,
                                   int len, uint8_t *rcv_buf));
int adb_bus_init (adb_bus_t *bus);

static inline int adb_reset (adb_bus_t *bus)
{
    adb_dev_t fake_device;
    
    memset(&fake_device, 0, sizeof(adb_dev_t));
    fake_device.bus = bus;

    return adb_cmd(&fake_device, ADB_SEND_RESET, 0, NULL, 0);
}

static inline int adb_flush (adb_dev_t *dev)
{
    return adb_cmd(dev, ADB_FLUSH, 0, NULL, 0);
}

static inline int adb_reg_get (adb_dev_t *dev, uint8_t reg, uint8_t *buf)
{
    return adb_cmd(dev, ADB_TALK, reg, buf, 0);
}

static inline int adb_reg_set (adb_dev_t *dev, uint8_t reg,
                               uint8_t *buf, int len)
{
    return adb_cmd(dev, ADB_LISTEN, reg, buf, len);
}

#endif /* !defined(__OHW_ADB_H__) */
