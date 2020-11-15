/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* don't allocate ebda if new value at 0x40e will be less than this */
#define EBDA_MIN_SEG		0x9800
#define SGABIOS_EBDA_KB		1
/* note: no testing has yet been done logging other than 256 bytes */
#define SGABIOS_EBDA_BYTES	(SGABIOS_EBDA_KB*1024)
#define SGABIOS_EBDA_DELTA	(SGABIOS_EBDA_BYTES/16)
#define SGABIOS_EBDA_LOG_START	256
#define SGABIOS_EBDA_LOG_SIZE	256
#define SGABIOS_EBDA_POS_START	(SGABIOS_EBDA_LOG_START+SGABIOS_EBDA_LOG_SIZE)
#define SGABIOS_EBDA_POS_LAST	(SGABIOS_EBDA_POS_START+(SGABIOS_EBDA_LOG_SIZE*2)-2)

/* serial costants that may require modification */
#define COM_BASE_ADDR           0x3f8
#define PORT_SPEED		115200
#define LCR_VALUE		0x13	/* 8n1 */

/* serial constants below shouldn't require modification */
#define IER_OFFSET              0x01
#define FCR_OFFSET              0x02
#define LCR_OFFSET              0x03
#define MCR_OFFSET              0x04
#define LSR_OFFSET              0x05
#define MSR_OFFSET              0x06
#define SCR_OFFSET              0x07
#define LCR_DLAB		0x80
#define MCR_DTRRTS		0x03
#define FCR_FIFO_ENABLE		0x01
#define PORT_DIVISOR		115200
#define TRANSMIT_READY_BIT      0x20
#define BIOS_BUILD_VERSION	"$Id: sgabios.S 7 2009-11-13 00:21:26Z smiles@google.com $"

#define KBD_HEAD		0x1a
#define KBD_TAIL		0x1c
#define KBD_BUF_START		0x1e
#define KBD_BUF_END		0x3e

#define VGA_IO_BASE		0x3d4
#define BDA_SEG			0x40
#define BDA_EBDA		0x0e
#define BDA_MEM_SIZE		0x13
#define BDA_MODE_NUM		0x49
#define BDA_COLS		0x4a
#define BDA_PAGE_SIZE		0x4c
/* BDA word 40:0c traditionally holds the LPT3 io port address... */
/* Reuse it for tracking where the serial console cursor was left */
/* Don't send ansi cursor pos update without text ready to output */
/* Some operations don't update cursor position, but next int 10h */
/* call is often one that might update to where cursor already is */
#define BDA_SERIAL_POS		0x0c
#define BDA_CURSOR_BUF		0x50
#define BDA_CURSOR_COL		0x50
#define BDA_CURSOR_ROW		0x51
#define BDA_CURSOR_SCAN		0x60
#define BDA_ACTIVE_PAGE		0x62
#define BDA_6845_ADDR		0x63
#define BDA_MODE_SEL		0x65
#define BDA_COLOR_VAL		0x66
#define BDA_ROM_OFF		0x67
#define BDA_ROM_SEG		0x69
#define BDA_ROWS		0x84
