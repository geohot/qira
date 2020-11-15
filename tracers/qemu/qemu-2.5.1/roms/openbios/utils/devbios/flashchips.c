/*
 *                     OpenBIOS - free your system! 
 *              ( firmware/flash device driver for Linux )
 *                          
 *  flashchips.c - contains all information about supported flash devices. 
 *  
 *  This program is part of a free implementation of the IEEE 1275-1994 
 *  Standard for Boot (Initialization Configuration) Firmware.
 *
 *  Copyright (C) 1998-2004  Stefan Reinauer, <stepan@openbios.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 *
 */
// <-- C++ style comments are for experimental comments only.
// They will disappear as soon as I fixed all the stuff.

#include "bios.h"
#include "flashchips.h"

unsigned int currflash=0;

const manufacturer_t manufacturers[] =
{
	{ "AMD",		0x01 },
	{ "AMI",		0x02 },
	{ "Fairchild",		0x83 },
	{ "Fujitsu",		0x04 },
	{ "GTE",		0x85 },
	{ "Harris",		0x86 },
	{ "Hitachi",		0x07 },
	{ "Inmos",		0x08 },
	{ "Intel",		0x89 },
	{ "I.T.T.",		0x8A },
	{ "Intersil",		0x0B },
	{ "Monolithic Memories",0x8C },
	{ "Mostek",		0x0D },
	{ "Motorola",		0x0E },
	{ "National",		0x8F },
	{ "NEC",		0x10 },
	{ "RCA",		0x91 },
	{ "Raytheon",		0x92 },
	{ "Rockwell",		0x13 },
	{ "Seeq",		0x94 },
	{ "Philips Semi.",	0x15 },
	{ "Synertek",		0x16 },
	{ "Texas Instruments",	0x97 },
	{ "Toshiba",		0x98 },
	{ "Xicor",		0x19 },
	{ "Zilog",		0x1A },
	{ "Eurotechnique",	0x9B },
	{ "Mitsubishi",		0x1C },
	{ "PMC Flash",		0x9D },
	{ "Exel",		0x9E },
	{ "Atmel",		0x1F },
	{ "SGS/Thomson",	0x20 },
	{ "Lattice Semi.",	0xA1 },
	{ "NCR",		0xA2 },
	{ "Wafer Scale Integr.",0x23 },
	{ "IBM",		0xA4 },
	{ "Tristar",		0x25 },
	{ "Visic",		0x26 },
	{ "Intl. CMOS Tech.",	0xA7 },
	{ "SSSI",		0xA8 },
	{ "MicrochipTech.",	0x29 },
	{ "Ricoh Ltd.",		0x2A },
	{ "VLSI",		0xAB },
	{ "Micron Technology",	0x2C },
	{ "Hyundai Elect.",	0xAD },
	{ "OKI Semiconductor",	0xAE },
	{ "ACTEL",		0x2F },
	{ "Sharp",		0xB0 },
	{ "Catalyst",		0x31 },
	{ "Panasonic",		0x32 },
	{ "IDT",		0xB3 },
	{ "Cypress",		0x34 },
	{ "DEC",		0xB5 },
	{ "LSI Logic",		0xB6 },
	{ "Plessey",		0x37 },
	{ "UTMC",		0x38 },
	{ "Thinking Machine",	0xB9 },
	{ "Thomson CSF",	0xBA },
	{ "Integ. CMOS(Vertex)",0x3B },
	{ "Honeywell",		0xBC },
	{ "Tektronix",		0x3D },
	{ "Sun Microsystems",	0x3E },
	{ "SST",		0xBF },
	{ "MOSEL",		0x40 },
	{ "Siemens",		0xC1 },
	{ "Macronix",		0xC2 },
	{ "Xerox",		0x43 },
	{ "Plus Logic",		0xC4 },
	{ "SunDisk",		0x45 },
	{ "Elan Circuit Tech.",	0x46 },
	{ "Europ. Silicon Str.",0xC7 },
	{ "Apple Computer",	0xC8 },
	{ "Xilinx",		0xC9 },
	{ "Compaq",		0x4A },
	{ "Protocol Engines",	0xCB },
	{ "SCI",		0x4C },
	{ "Seiko Instruments",	0xCD },
	{ "Samsung",		0xCE },
	{ "I3 Design System",	0x4F },
	{ "Klic",		0xD0 },
	{ "Crosspoint Sol.",	0x51 },
	{ "Alliance Semicond.",	0x52 },
	{ "Tandem",		0xD3 },
	{ "Hewlett-Packard",	0x54 },
	{ "Intg. Silicon Sol.",	0xD5 },
	{ "Brooktree",		0xD6 },
	{ "New Media",		0x57 },
	{ "MHS Electronic",	0x58 },
	{ "Performance Semi.",	0xD9 },
	{ "Winbond",		0xDA },
	{ "Kawasaki Steel",	0x5B },
	{ "Bright Micro",	0xDC },
	{ "TECMAR",		0x5D },
	{ "Exar",		0x5E },
	{ "PCMCIA",		0xDF },
	{ "Goldstar",		0xE0 },
	{ "Northern Telecom",	0x61 },
	{ "Sanyo",		0x62 },
	{ "Array Microsystems",	0xE3 },
	{ "Crystal Semicond.",	0x64 },
	{ "Analog Devices",	0xE5 },
	{ "PMC-Sierra",		0xE6 },
	{ "Asparix",		0x67 },
	{ "Convex Computer",	0x68 },
	{ "Quality Semicond.",	0xE9 },
	{ "Nimbus Technology",	0xEA },
	{ "Transwitch",		0x6B },
	{ "ITT Intermetall",	0xEC },
	{ "Cannon",		0x6D },
	{ "Altera",		0x6E },
	{ "NEXCOM",		0xEF },
	{ "QUALCOMM",		0x70 },
	{ "Sony",		0xF1 },
	{ "Cray Research",	0xF2 },
	{ "AMS(Austria Micro)",	0x73 },
	{ "Vitesse",		0xF4 },
	{ "Aster Electronics",	0x75 },
	{ "Bay Networks(Synoptic)",	0x76 },
	{ "Zentrum Mikroelec.",	0xF7 },
	{ "TRW",		0xF8 },
	{ "Thesys",		0x79 },
	{ "Solbourne Computer",	0x7A },
	{ "Allied-Signal",	0xFB },
	{ "Dialog",		0x7C },
	{ "Media Vision",	0xFD },
	{ "Level One Commun.",	0xFE },
	{ "Eon",		0x7F },

	{ "Unknown",		0x00 }
};

const flashchip_t flashchips[] =
{
	/* AMD */
	{ "29F016B",	0xad01,  5, 2048, 0,   1, 1, (int []) { 0,2048 } },
	{ "29F080B",	0xd501,  5, 1024, 0,   1, 1, (int []) { 0,1024 } },
	{ "29F800BT",	0xd601,  5, 1024, 0,   1, 1, (int []) { 0,1024 } },
	{ "29F800BB",	0x5801,  5, 1024, 0,   1, 1, (int []) { 0,1024 } },
	{ "29F040B",	0xa401,  5,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "29F400T",	0x2301,  5,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "29LV004T",	0xb501,  3,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "29LV400T",	0xb901,  3,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "29F400B",	0xab01,  5,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "29LV004B",	0xb601,  3,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "29LV400B",	0xba01,  3,  512, 0,   1, 1, (int []) { 0, 512 } },
	{ "28F020A",	0x2901, 12,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "28F020",	0x2a01, 12,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29F002T",	0xb001,  5,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29LV002T",	0x4001,  3,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29LV200T",	0x3b01,  3,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29F200T",	0x5101,  5,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29F002B",	0x3401,  5,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29LV002B",	0xc201,  3,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29LV200B",	0xbf01,  3,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29F200B",	0x5701,  5,  256, 0,   1, 1, (int []) { 0, 256 } },
	{ "29F010",	0x2001,  5,  128, 0,   1, 1, (int []) { 0, 128 } },
	{ "28F010A",	0xa201, 12,  128, 0,   1, 1, (int []) { 0, 128 } },
	{ "28F010",	0xa701, 12,  128, 0,   1, 1, (int []) { 0, 128 } },
	{ "29F100T",	0xd901,  5,   64, 0,   1, 1, (int []) { 0,  64 } },
	{ "29F100B",	0xdf01,  5,   64, 0,   1, 1, (int []) { 0,  64 } },
	{ "28F512A",	0xae01, 12,   64, 0,   1, 1, (int []) { 0,  64 } },
	{ "28F512",	0x2501, 12,   64, 0,   1, 1, (int []) { 0,  64 } },
	{ "28F256A",	0x2f01, 12,   32, 0,   1, 1, (int []) { 0,  32 } },
	{ "28F256",	0xa101, 12,   32, 0, 128, 1, (int []) { 0,  32 } },

	/* Atmel */
	{ "AT49BV010",	0x851f,  3,  128, 0, 128, 1, (int []) { 0, 128 } },
//Word	{ "AT49F1025",	0x851f,  5,  128, 0, 256, 1, (int []) { 0, 128 } },
	{ "AT49x020",	0x0b1f,  5,  256, 0, 128, 1, (int []) { 0, 256 } },
	{ "AT49F040",	0x131f,  5,  512, 0, 128, 1, (int []) { 0, 512 } },
	{ "AT49F010",	0x171f,  5,  128, 0, 128, 1, (int []) { 0, 128 } },
	{ "AT49F080",	0x231f,  5, 1024, 0, 128, 1, (int []) { 0,1024 } },
	{ "AT29C040A",	0xa41f,  5,  512, 1, 256, 4, (int []) { 0, 512 } },
//Word	{ "AT29C1024",	0x251f,  3,  128, 0, 128, 0, (int []) { 0, 128 } },
//Word	{ "AT29LV1024",	0x261f,  3,  128, 0, 128, 0, (int []) { 0, 128 } },
	{ "AT49F080T",	0xa71f,  5, 1024, 0, 128, 1, (int []) { 0,1024 } },
	{ "AT29BV010A",	0x351f,  3,  128, 1, 128, 4, (int []) { 0, 128 } },
	{ "AT29BV020",	0xba1f,  3,  256, 1, 256, 4, (int []) { 0, 256 } },
	{ "AT29LV256",	0xbc1f,  3,   32, 1,  64, 4, (int []) { 0,  32 } },
	{ "AT29LV512",	0x3d1f,  3,   64, 1, 128, 4, (int []) { 0,  64 } },
	{ "AT29BV040A",	0xc41f,  3,  512, 1, 256, 4, (int []) { 0, 512 } },
	{ "AT29C010A",	0xd51f,  5,  128, 1, 128, 4, (int []) { 0, 128 } },
	{ "AT29C020",	0xda1f,  5,  256, 1, 256, 4, (int []) { 0, 256 } },
	{ "AT29C256",	0xdc1f,  3,   32, 1,  64, 4, (int []) { 0,  32 } },
	{ "AT29C512",	0x5d1f,  5,   64, 1, 128, 4, (int []) { 0,  64 } },

	/* Catalyst */
	{ "CAT28F150T",	0x0431, 12,  192, 1, 128, 3, (int []) { 0, 64,160,168,176,192 } },
	{ "CAT28F150B",	0x8531, 12,  192, 1, 128, 3, (int []) { 0, 16, 24, 32,128, 192 } },
	{ "CAT28F001T",	0x9431, 12,  128, 1, 128, 3, (int []) { 0,112,116,120,128 } },
	{ "CAT28F001B",	0x1531, 12,  128, 1, 128, 3, (int []) { 0,  8, 12, 16,128 } },
	{ "CAT29F002T",	0xb031,  5,  256, 0, 128, 1, (int []) { 0, 64,128,192,224,232,240,256 } },
	{ "CAT29F002B",	0x3431,  5,  256, 0, 128, 1, (int []) { 0, 16, 24, 32, 64,128,192,256 } },
	{ "CAT28F002T",	0x7c31, 12,  256, 1, 128, 3, (int []) { 0,128,224,232,240,256 } },
	{ "CAT28F002B",	0xfd31, 12,  256, 1, 128, 3, (int []) { 0, 16, 24, 32,128,256 } },
	{ "CAT28F020" , 0xbd31, 12,  256, 0,   1, 1, (int []) { 0,256 } },
//Word	{ "CAT28F102" , 0x5131, 12,  128, 0,   0, 0, (int []) { 0,128 } },
	{ "CAT28F010" , 0xb431, 12,  128, 0,   1, 1, (int []) { 0,128 } },
	{ "CAT28F512" , 0xb831, 12,   64, 0,   1, 1, (int []) { 0, 64 } },
	
	{ "29F040",     0xa404,  5,  512, 1,   1, 1, (int []) { 0, 64, 128, 192, 256, 320, 384, 448, 512 } }, /* Fujitsu */
	
	
	/* Intel */
	{ "28F010",	0x3489, 12,  128, 0, 128, 1, (int []) { 0,128 } },
	{ "28F020",	0x3d89, 12,  256, 0, 128, 1, (int []) { 0,256 } },
	{ "28F001BX-T",	0x9489, 12,  128, 1, 128, 3, (int []) { 0,112,116,120,128 } },
	{ "28F001BX-B",	0x9589, 12,  128, 1, 128, 3, (int []) { 0,  8, 12, 16,128 } },
//Word	{ "28F400BX-T",	0x7089, 12,  512, 0, 256, 3, (int []) { 0,128,256,384,480,488,496,512 } },
//Word	{ "28F400BX-B",	0xF189, 12,  512, 0, 256, 3, (int []) { 0, 16, 24, 32,128,256,384,512 } },
//Word	{ "28F200-T",	0xF489, 12,  256, 0, 256, 3, (int []) { 0,128,224,232,240,256} },
//Word	{ "28F200-B",	0x7589, 12,  256, 0, 256, 3, (int []) { 0, 16, 24, 32,128,256 } },
	{ "28F016B3-T", 0xd089,  3, 1024, 0,   1, 3, (int []) { 0, 2048 } },
	{ "28F016B3-B", 0xd189,  3, 1024, 0,   1, 3, (int []) { 0, 2048 } },
	{ "28F008B3-T", 0xd289,  3, 1024, 0,   1, 3, (int []) { 0, 1024 } },
	{ "28F008B3-B", 0xd389,  3, 1024, 0,   1, 3, (int []) { 0, 1024 } },
   	{ "28F004B3-T", 0xd489,  3,  512, 0, 128, 3, (int []) { 0,128,256,384,480,488,496,512 } },
	{ "28F004B3-B", 0xd589,  3,  512, 0, 128, 3, (int []) { 0, 16, 24, 32,128,256,384,512 } },
	{ "28F004BX-T",	0xF889, 12,  512, 1, 128, 3, (int []) { 0,128,256,384,480,488,496,512 } },
	{ "28F004BX-B",	0x7989, 12,  512, 1, 128, 3, (int []) { 0, 16, 24, 32,128,256,384,512 } },
	{ "28F002-T",	0x7c89, 12,  256, 1, 128, 3, (int []) { 0,128,224,232,240,256 } },
	{ "28F002-B",	0xfd89, 12,  256, 1, 256, 3, (int []) { 0, 16, 24, 32,128,256 } },
	{ "28F008??",	0xa289, 12, 1024, 1,   1, 3, (int []) { 0, 64,128,192,256,320,384,448,512,576,640,704,768,832,896,960,1024 } },
	{ "28F008SA",	0xa189, 12, 1024, 1,   1, 3, (int []) { 0, 64,128,192,256,320,384,448,512,576,640,704,768,832,896,960,1024 } },
	{ "28F004??",   0xad89,  5,  512, 0,   1, 3, (int []) { 0, 512} },
	{ "28F008??",   0xac89,  5, 1024, 0,   1, 3, (int []) { 0,1024} },

	/* Eon */
	{ "E28F004S5",  0x7f8f,  5,  512, 1,   1, 3, (int []) { 0, 64,128,192,256,320,384,448,512 } },
	{ "EN29F002B",  0x977f,  5,  256, 1,   1, 1, (int []) { 0, 16, 24, 32,128,256 } },
	{ "EN29F002T",  0x927f,  5,  256, 1,   1, 1, (int []) { 0,128,224,232,240,256 } },
	
	/* SST */
	{ "28EE011",	0x01bf,  5,  128, 0, 128, 0, (int []) { 0, 128 } },
	{ "28EE040",	0x04bf,  5,  512, 0, 128, 0, (int []) { 0, 512 } },
	{ "29EE010",	0x07bf,  5,  128, 1, 128, 0, (int []) { 0, 128 } },
	{ "29x010",	0x08bf,  3,  128, 0, 128, 0, (int []) { 0, 128 } },
	{ "29EE020",	0x10bf,  5,  256, 0, 128, 0, (int []) { 0, 256 } },
	{ "29x020",	0x92bf,  3,  256, 0, 128, 0, (int []) { 0, 256 } },
	{ "29x512",	0x3dbf,  3,   64, 0, 128, 0, (int []) { 0,  64 } },
	{ "29EE512",	0x5dbf,  5,   64, 0, 128, 0, (int []) { 0,  64 } },
	{ "29x020",	0x92bf,  3,  256, 0, 128, 0, (int []) { 0, 256 } },
	{ "39SF020",	0xb6bf,  5,  256, 1, 1, 0x81, (int []) { 0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,96,100,104,108,112,116,120,124,128,132,136,140,144,148,152,156,160,164,168,172,176,180,184,188,192,196,200,204,208,212,216,220,224,228,232,236,240,244,248,252,256 } },
	{ "49LF002A",	0x57bf,  3,  256, 0, 1, 0x81, (int[]) {0,256} },
	{ "49LF003A",	0x1bbf,  3,  384, 0, 1, 0x81, (int[]) {0,384} },
	{ "49LF004A",	0x60bf,  3,  512, 1, 1, 0x09, (int[]) {0, 4, 8, 12, 16, 24,28, 32, 512} },
	{ "49LF008A",	0x5abf,  3, 1024, 0, 1, 0x81, (int[]) {0,1024} },
	{ "49LF020",	0x61bf,  3,  256, 1, 4096, 0, (int[]) {0,256} },
	{ "49LF040",	0x51bf,  3,  512, 1, 4096, 0, (int[]) {0,512} },
	{ "49LF080A",   0x5bbf,  3, 1024, 1, 4096, 0, (int[]) {0,1024} },
	
	/* Macronix */
	{ "MX28F1000AP",0x1ac2, 12,  128, 0,   1, 1, (int []) { 0, 16, 32, 48, 64, 80, 96,112,116,120,124,128 } },
	{ "MX28F1000P", 0x91c2, 12,  128, 0,   1, 1, (int []) { 0, 16, 32, 48, 64, 80, 96,112,128 } },
	{ "MX28F1000PC",0xf7c2, 12,  128, 0,   1, 1, (int []) { 0, 16, 32, 48, 64, 80, 96,112,128 } },
//id?	{ "MX28F1000PPC",0x7fc2,12,  128, 0,   1, 1, (int []) { 0, 16, 32, 48, 64, 80, 96,112,116,120,124,128 } },
	{ "MX29F1610A", 0xfac2,  5, 2048, 1, 128, 0, (int []) { 0, 2048} },

	/* Winbond */
	{ "W29EE011",	0xc1da,  5,  128, 1, 128, 0, (int []) { 0, 128 } },
	{ "W29C020",	0x45da,  5,  256, 1, 128, 0, (int []) { 0, 256 } },
	{ "W29C040/042",0x46da,  5,  512, 1, 256, 0, (int []) { 0, 512 } },
	{ "W29EE512",	0xc8da,  5,   64, 1, 128, 0, (int []) { 0,  64 } },
	{ "W29C101",	0x4fda,  5,  128, 1, 256, 0, (int []) { 0, 128 } },
	{ "W49V002",    0xb0da,  3,  256, 1,   1, 1, (int []) { 0, 64, 128, 192, 224, 232, 240, 256 } },
	//{ "W49F002",    0x0bda,  5,  256, 1,   1, 1, (int []) { 0, 64, 128, 192, 224, 232, 240, 256 } },
	{ "W49F002U",   0x0bda,  5,  256, 1, 1,0x09, (int []) { 0, 128, 224, 232, 240, 256 } }, /* Winbond */

	/* SGS/Thomson */
	{ "M29F002B(N)T", 0xb020,  5,  256, 0,   1, 0,    (int[]) {0, 64, 128, 256 } },
	{ "M29F002B(N)B", 0x3420,  5,  256, 0,   1, 0,    (int[]) {0, 256 } },
	{ "M50FW040",   0x2c20,  3,  512, 1, 128, 0x0b, (int []) { 0, 64, 128, 192, 256, 320, 384, 448, 512 } },

	{ "Pm29F002T",  0x1d9d,  5,  256, 1, 1, 0x1, (int []) { 0,128,224,232,240,256 } },
	/* default entry */
	{ "Unknown",	0x0000,  0,    0, 0,   0, 0, (int []) { 0 } }
};

