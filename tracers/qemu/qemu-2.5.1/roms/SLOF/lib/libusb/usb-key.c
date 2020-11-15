/*****************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdint.h>

/***********************************/
/* Keycodes for US Keyboard        */
/*   - no control keys pressed -   */
/***********************************/
const uint8_t keycodes_std_US[] = {
	0,	/* 0	00	Reserved (no event indicated) */
	0,	/* 1	01	Keyboard ErrorRollOver      */
	0,	/* 2	02	Keyboard POSTFail           */
	0,	/* 3	03	Keyboard ErrorUndefined     */
	'a',	/* 4	04	Keyboard a and A	31  */
	'b',	/* 5	05	Keyboard b and B	50  */
	'c',	/* 6	06	Keyboard c and C	48  */
	'd',	/* 7	07	Keyboard d and D	33  */
	'e',	/* 8	08	Keyboard e and E	19  */
	'f',	/* 9	09	Keyboard f and F	34  */
	'g',	/* 10	0A	Keyboard g and G	35  */
	'h',	/* 11	0B	Keyboard h and H	36  */
	'i',	/* 12	0C	Keyboard i and I	24  */
	'j',	/* 13	0D	Keyboard j and J	37  */
	'k',	/* 14	0E	Keyboard k and K	38  */
	'l',	/* 15	0F	Keyboard l and L	39  */
	'm',	/* 16	10	Keyboard m and M	52  */
	'n',	/* 17	11	Keyboard n and N	51  */
	'o',	/* 18	12	Keyboard o and O	25  */
	'p',	/* 19	13	Keyboard p and P	26  */
	'q',	/* 20	14	Keyboard q and Q	17  */
	'r',	/* 21	15	Keyboard r and R	20  */
	's',	/* 22	16	Keyboard s and S	32  */
	't',	/* 23	17	Keyboard t and T	21  */
	'u',	/* 24	18	Keyboard u and U	23  */
	'v',	/* 25	19	Keyboard v and V	49  */
	'w',	/* 26	1A	Keyboard w and W	18  */
	'x',	/* 27	1B	Keyboard x and X	47  */
	'y',	/* 28	1C	Keyboard y and Y	22  */
	'z',	/* 29	1D	Keyboard z and Z	46  */
	'1',	/* 30	1E	Keyboard 1 and !	2   */
	'2',	/* 31	1F	Keyboard 2 and @	3   */
	'3',	/* 32	20	Keyboard 3 and #	4   */
	'4',	/* 33	21	Keyboard 4 and $	5   */
	'5',	/* 34	22	Keyboard 5 and %	6   */
	'6',	/* 35	23	Keyboard 6 and ^	7   */
	'7',	/* 36	24	Keyboard 7 and &	8   */
	'8',	/* 37	25	Keyboard 8 and *	9   */
	'9',	/* 38	26	Keyboard 9 and (	10  */
	'0',	/* 39	27	Keyboard 0 and )	11  */
	13,	/* 40	28	Keyboard Return (ENTER)	43  */
	27,	/* 41	29	Keyboard ESCAPE	        110 */
	8,	/* 42	2A	Keyboard DELETE (BS)	15  */
	9,	/* 43	2B	Keyboard Tab		16  */
	' ',	/* 44	2C	Keyboard Spacebar	61  */
	'-',	/* 45	2D	Keyboard - and (underscore) 12 */
	'=',	/* 46	2E	Keyboard = and +	13  */
	'[',	/* 47	2F	Keyboard [ and {	27  */
	']',	/* 48	30	Keyboard ] and }	28  */
	'\\',	/* 49	31	Keyboard \ and |	29  */
	'\\',	/* 50	32	Keyboard \ and |	42  */
	';',	/* 51	33	Keyboard ; and :	40  */
	39,	/* 52	34	Keyboard ' and "	41  */
	96,	/* 53	35	Keyboard Grave Accent and Tilde 1 */
	',',	/* 54	36	Keyboard , and <	53  */
	'.',	/* 55	37	Keyboard . and >	54  */
	'/',	/* 56	38	Keyboard / and ?	55  */
	0,	/* 57	39	Keyboard Caps Lock	30  */
	0,	/* 58	3A	Keyboard F1		112 */
	0,	/* 59	3B	Keyboard F2		113 */
	0,	/* 60	3C	Keyboard F3		114 */
	0,	/* 61	3D	Keyboard F4		115 */
	0,	/* 62	3E	Keyboard F5		116 */
	0,	/* 63	3F	Keyboard F6		117 */
	0,	/* 64	40	Keyboard F7		118 */
	0,	/* 65	41	Keyboard F8		119 */
	0,	/* 66	42	Keyboard F9		120 */
	0,	/* 67	43	Keyboard F10		121 */
	0,	/* 68	44	Keyboard F11		122 */
	0,	/* 69	45	Keyboard F12		123 */
	0,	/* 70	46	Keyboard PrintScreen	124 */
	0,	/* 71	47	Keyboard Scroll Lock	125 */
	0,	/* 72	48	Keyboard Pause		126 */
	0,	/* 73	49	Keyboard Insert		75 */
	0,	/* 74	4A	Keyboard Home		80 */
	0,	/* 75	4B	Keyboard PageUp		85 */
	0,	/* 76	4C	Keyboard Delete Forward	76 */
	0,	/* 77	4D	Keyboard End		81 */
	0,	/* 78	4E	Keyboard PageDown	86 */
	0,	/* 79	4F	Keyboard RightArrow	89 */
	0,	/* 80	50	Keyboard LeftArrow	79 */
	0,	/* 81	51	Keyboard DownArrow	84 */
	0,	/* 82	52	Keyboard UpArrow	83 */
	0,	/* 83	53	Keypad Num Lock and Clear 90 */
	'/',	/* 84	54	Keypad /		95 */
	'*',	/* 85	55	Keypad *		100 */
	'-',	/* 86	56	Keypad -		105 */
	'+',	/* 87	57	Keypad +		106 */
	13,	/* 88	58	Keypad ENTER		108 */
	'1',	/* 89	59	Keypad 1 and End	93  */
	'2',	/* 90	5A	Keypad 2 and Down Arrow	98  */
	'3',	/* 91	5B	Keypad 3 and PageDn	103 */
	'4',	/* 92	5C	Keypad 4 and Left Arrow	92  */
	'5',	/* 93	5D	Keypad 5		97  */
	'6',	/* 94	5E	Keypad 6 and Right Arrow 102 */
	'7',	/* 95	5F	Keypad 7 and Home	91  */
	'8',	/* 96	60	Keypad 8 and Up Arrow	96  */
	'9',	/* 97	61	Keypad 9 and PageUp	101 */
	'0',	/* 98	62	Keypad 0 and Insert	99  */
	'.',	/* 99	63	Keypad . and Delete	104 */
	'\\'	/* 100	64	Keyboard Non-US \ and |	45  */
};

/***********************************/
/* Keycodes for US Keyboard        */
/*     - SHIFT-KEY pressed -       */
/***********************************/
const uint8_t keycodes_shift_US[] = {
	0,	/* 0	00	Reserved (no event indicated) */
	0,	/* 1	01	Keyboard ErrorRollOver      */
	0,	/* 2	02	Keyboard POSTFail           */
	0,	/* 3	03	Keyboard ErrorUndefined     */
	'A',	/* 4	04	Keyboard a and A	31  */
	'B',	/* 5	05	Keyboard b and B	50  */
	'C',	/* 6	06	Keyboard c and C	48  */
	'D',	/* 7	07	Keyboard d and D	33  */
	'E',	/* 8	08	Keyboard e and E	19  */
	'F',	/* 9	09	Keyboard f and F	34  */
	'G',	/* 10	0A	Keyboard g and G	35  */
	'H',	/* 11	0B	Keyboard h and H	36  */
	'I',	/* 12	0C	Keyboard i and I	24  */
	'J',	/* 13	0D	Keyboard j and J	37  */
	'K',	/* 14	0E	Keyboard k and K	38  */
	'L',	/* 15	0F	Keyboard l and L	39  */
	'M',	/* 16	10	Keyboard m and M	52  */
	'N',	/* 17	11	Keyboard n and N	51  */
	'O',	/* 18	12	Keyboard o and O	25  */
	'P',	/* 19	13	Keyboard p and P	26  */
	'Q',	/* 20	14	Keyboard q and Q	17  */
	'R',	/* 21	15	Keyboard r and R	20  */
	'S',	/* 22	16	Keyboard s and S	32  */
	'T',	/* 23	17	Keyboard t and T	21  */
	'U',	/* 24	18	Keyboard u and U	23  */
	'V',	/* 25	19	Keyboard v and V	49  */
	'W',	/* 26	1A	Keyboard w and W	18  */
	'X',	/* 27	1B	Keyboard x and X	47  */
	'Y',	/* 28	1C	Keyboard y and Y	22  */
	'Z',	/* 29	1D	Keyboard z and Z	46  */
	'!',	/* 30	1E	Keyboard 1 and !	2   */
	'@',	/* 31	1F	Keyboard 2 and @	3   */
	'#',	/* 32	20	Keyboard 3 and #	4   */
	'$',	/* 33	21	Keyboard 4 and $	5   */
	'%',	/* 34	22	Keyboard 5 and %	6   */
	'^',	/* 35	23	Keyboard 6 and ^	7   */
	'&',	/* 36	24	Keyboard 7 and &	8   */
	'*',	/* 37	25	Keyboard 8 and *	9   */
	'(',	/* 38	26	Keyboard 9 and (	10  */
	')',	/* 39	27	Keyboard 0 and )	11  */
	13,	/* 40	28	Keyboard Return (ENTER)	43  */
	27,	/* 41	29	Keyboard ESCAPE         110 */
	8,	/* 42	2A	Keyboard DELETE (BS)	15  */
	9,	/* 43	2B	Keyboard Tab 		16  */
	' ',	/* 44	2C	Keyboard Spacebar	61  */
	'_',	/* 45	2D	Keyboard - and (underscore) 12 */
	'+',	/* 46	2E	Keyboard = and +	13  */
	'{',	/* 47	2F	Keyboard [ and {	27  */
	'}',	/* 48	30	Keyboard ] and }	28  */
	'|',	/* 49	31	Keyboard \ and |	29  */
	'|',	/* 50	32	Keyboard \ and |	42  */
	':',	/* 51	33	Keyboard ; and :	40  */
	'"',	/* 52	34	Keyboard ' and "	41  */
	'~',	/* 53	35	Keyboard Grave Accent and Tilde 1 */
	'<',	/* 54	36	Keyboard , and <	53  */
	'>',	/* 55	37	Keyboard . and >	54  */
	'?',	/* 56	38	Keyboard / and ?	55  */
	0,	/* 57	39	Keyboard Caps Lock	30  */
	0,	/* 58	3A	Keyboard F1		112 */
	0,	/* 59	3B	Keyboard F2		113 */
	0,	/* 60	3C	Keyboard F3		114 */
	0,	/* 61	3D	Keyboard F4		115 */
	0,	/* 62	3E	Keyboard F5		116 */
	0,	/* 63	3F	Keyboard F6		117 */
	0,	/* 64	40	Keyboard F7		118 */
	0,	/* 65	41	Keyboard F8		119 */
	0,	/* 66	42	Keyboard F9		120 */
	0,	/* 67	43	Keyboard F10		121 */
	0,	/* 68	44	Keyboard F11		122 */
	0,	/* 69	45	Keyboard F12		123 */
	0,	/* 70	46	Keyboard PrintScreen	124 */
	0,	/* 71	47	Keyboard Scroll Lock	125 */
	0,	/* 72	48	Keyboard Pause		126 */
	48,	/* 73	49	Keyboard Insert		75  */
	55,	/* 74	4A	Keyboard Home		80  */
	57,	/* 75	4B	Keyboard PageUp		85  */
	46,	/* 76	4C	Keyboard Delete Forward	76  */
	49,	/* 77	4D	Keyboard End		81  */
	51,	/* 78	4E	Keyboard PageDown	86  */
	54,	/* 79	4F	Keyboard RightArrow	89  */
	52,	/* 80	50	Keyboard LeftArrow	79  */
	50,	/* 81	51	Keyboard DownArrow	84  */
	56,	/* 82	52	Keyboard UpArrow	83  */
	0,	/* 83	53	Keypad Num Lock and Clear 90 */
	'/',	/* 84	54	Keypad /		95 */
	'*',	/* 85	55	Keypad *		100 */
	'-',	/* 86	56	Keypad -		105 */
	'+',	/* 87	57	Keypad +		106 */
	13,	/* 88	58	Keypad ENTER		108 */
	'1',	/* 89	59	Keypad 1 and End	93  */
	'2',	/* 90	5A	Keypad 2 and Down Arrow	98  */
	'3',	/* 91	5B	Keypad 3 and PageDn	103 */
	'4',	/* 92	5C	Keypad 4 and Left Arrow	92  */
	'5',	/* 93	5D	Keypad 5		97  */
	'6',	/* 94	5E	Keypad 6 and Right Arrow 102 */
	'7',	/* 95	5F	Keypad 7 and Home	91  */
	'8',	/* 96	60	Keypad 8 and Up Arrow	96  */
	'9',	/* 97	61	Keypad 9 and PageUp	101 */
	'0',	/* 98	62	Keypad 0 and Insert	99  */
	'.',	/* 99	63	Keypad . and Delete	104 */
	'|'	/* 100	64	Keyboard Non-US \ and |	45  */
};

/***********************************/
/* Keycodes for 1 byte translation */
/*     - CONTROL-KEY pressed -     */
/***********************************/
const uint8_t keycodes_alt_GR[] = {
	0,	/* 0	00	Reserved (no event indicated) */
	0,	/* 1	01	Keyboard ErrorRollOver      */
	0,	/* 2	02	Keyboard POSTFail           */
	0,	/* 3	03	Keyboard ErrorUndefined     */
	0,	/* 4	04	Keyboard a and A	31  */
	0,	/* 5	05	Keyboard b and B	50  */
	0,	/* 6	06	Keyboard c and C	48  */
	0,	/* 7	07	Keyboard d and D	33  */
	0,	/* 8	08	Keyboard e and E	19  */
	0,	/* 9	09	Keyboard f and F	34  */
	0,	/* 10	0A	Keyboard g and G	35  */
	0,	/* 11	0B	Keyboard h and H	36  */
	0,	/* 12	0C	Keyboard i and I	24  */
	0,	/* 13	0D	Keyboard j and J	37  */
	0,	/* 14	0E	Keyboard k and K	38  */
	0,	/* 15	0F	Keyboard l and L	39  */
	0,	/* 16	10	Keyboard m and M	52  */
	0,	/* 17	11	Keyboard n and N	51  */
	0,	/* 18	12	Keyboard o and O	25  */
	0,	/* 19	13	Keyboard p and P	26  */
	'@',	/* 20	14	Keyboard q and Q	17  */
	0,	/* 21	15	Keyboard r and R	20  */
	0,	/* 22	16	Keyboard s and S	32  */
	0,	/* 23	17	Keyboard t and T	21  */
	0,	/* 24	18	Keyboard u and U	23  */
	0,	/* 25	19	Keyboard v and V	49  */
	0,	/* 26	1A	Keyboard w and W	18  */
	0,	/* 27	1B	Keyboard x and X	47  */
	0,	/* 28	1C	Keyboard y and Y	22  */
	0,	/* 29	1D	Keyboard z and Z	46  */
	0,	/* 30	1E	Keyboard 1 and !	2   */
	0,	/* 31	1F	Keyboard 2 and @	3   */
	0,	/* 32	20	Keyboard 3 and #	4   */
	0,	/* 33	21	Keyboard 4 and $	5   */
	0,	/* 34	22	Keyboard 5 and %	6   */
	0,	/* 35	23	Keyboard 6 and ^	7   */
	'{',	/* 36	24	Keyboard 7 and &	8   */
	'[',	/* 37	25	Keyboard 8 and *	9   */
	']',	/* 38	26	Keyboard 9 and (	10  */
	'}',	/* 39	27	Keyboard 0 and )	11  */
	0,	/* 40	28	Keyboard Return (ENTER)	43  */
	0,	/* 41	29	Keyboard ESCAPE         110 */
	0,	/* 42	2A	Keyboard DELETE (BS)	15  */
	0,	/* 43	2B	Keyboard Tab 		16  */
	0,	/* 44	2C	Keyboard Spacebar	61  */
	'\\',	/* 45	2D	Keyboard - and (underscore) 12 */
	0,	/* 46	2E	Keyboard = and +	13  */
	0,	/* 47	2F	Keyboard [ and {	27  */
	'~',	/* 48	30	Keyboard ] and }	28  */
	0,	/* 49	31	Keyboard \ and |	29  */
	0,	/* 50	32	Keyboard Non-US # and ~	42  */
	0,	/* 51	33	Keyboard ; and :	40  */
	0,	/* 52	34	Keyboard ' and "	41  */
	0,	/* 53	35	Keyboard Grave Accent and Tilde 1 */
	0,	/* 54	36	Keyboard , and <	53  */
	0,	/* 55	37	Keyboard . and >	54  */
	0,	/* 56	38	Keyboard / and ?	55  */
	0,	/* 57	39	Keyboard Caps Lock	30  */
	0,	/* 58	3A	Keyboard F1		112 */
	0,	/* 59	3B	Keyboard F2		113 */
	0,	/* 60	3C	Keyboard F3		114 */
	0,	/* 61	3D	Keyboard F4		115 */
	0,	/* 62	3E	Keyboard F5		116 */
	0,	/* 63	3F	Keyboard F6		117 */
	0,	/* 64	40	Keyboard F7		118 */
	0,	/* 65	41	Keyboard F8		119 */
	0,	/* 66	42	Keyboard F9		120 */
	0,	/* 67	43	Keyboard F10		121 */
	0,	/* 68	44	Keyboard F11		122 */
	0,	/* 69	45	Keyboard F12		123 */
	0,	/* 70	46	Keyboard PrintScreen	124 */
	0,	/* 71	47	Keyboard Scroll Lock	125 */
	0,	/* 72	48	Keyboard Pause		126 */
	0,	/* 73	49	Keyboard Insert		75 */
	0,	/* 74	4A	Keyboard Home		80 */
	0,	/* 75	4B	Keyboard PageUp		85 */
	0,	/* 76	4C	Keyboard Delete Forward	76 */
	0,	/* 77	4D	Keyboard End		81 */
	0,	/* 78	4E	Keyboard PageDown	86 */
	0,	/* 79	4F	Keyboard RightArrow	89 */
	0,	/* 80	50	Keyboard LeftArrow	79 */
	0,	/* 81	51	Keyboard DownArrow	84 */
	0,	/* 82	52	Keyboard UpArrow	83 */
	0,	/* 83	53	Keypad Num Lock and Clear 90 */
	0,	/* 84	54	Keypad /		95 */
	0,	/* 85	55	Keypad *		100 */
	0,	/* 86	56	Keypad -		105 */
	0,	/* 87	57	Keypad +		106 */
	0,	/* 88	58	Keypad ENTER		108 */
	0,	/* 89	59	Keypad 1 and End	93  */
	0,	/* 90	5A	Keypad 2 and Down Arrow	98  */
	0,	/* 91	5B	Keypad 3 and PageDn	103 */
	0,	/* 92	5C	Keypad 4 and Left Arrow	92  */
	0,	/* 93	5D	Keypad 5		97  */
	0,	/* 94	5E	Keypad 6 and Right Arrow 102 */
	0,	/* 95	5F	Keypad 7 and Home	91  */
	0,	/* 96	60	Keypad 8 and Up Arrow	96  */
	0,	/* 97	61	Keypad 9 and PageUp	101 */
	0,	/* 98	62	Keypad 0 and Insert	99  */
	0,	/* 99	63	Keypad . and Delete	104 */
	'|'	/* 100	64	Keyboard Non-US \ and |	45  */
};


/***********************************/
/* Keycodes for 1 byte translation */
/*     - CONTROL-KEY pressed -     */
/***********************************/
const uint8_t keycodes_ctrl[] = {
	0,	/* 0	00	Reserved (no event indicated) */
	0,	/* 1	01	Keyboard ErrorRollOver      */
	0,	/* 2	02	Keyboard POSTFail           */
	0,	/* 3	03	Keyboard ErrorUndefined     */
	1,	/* 4	04	Keyboard a and A	31  */
	2,	/* 5	05	Keyboard b and B	50  */
	3,	/* 6	06	Keyboard c and C	48  */
	4,	/* 7	07	Keyboard d and D	33  */
	5,	/* 8	08	Keyboard e and E	19  */
	6,	/* 9	09	Keyboard f and F	34  */
	7,	/* 10	0A	Keyboard g and G	35  */
	8,	/* 11	0B	Keyboard h and H	36  */
	9,	/* 12	0C	Keyboard i and I	24  */
	10,	/* 13	0D	Keyboard j and J	37  */
	11,	/* 14	0E	Keyboard k and K	38  */
	12,	/* 15	0F	Keyboard l and L	39  */
	13,	/* 16	10	Keyboard m and M	52  */
	14,	/* 17	11	Keyboard n and N	51  */
	15,	/* 18	12	Keyboard o and O	25  */
	16,	/* 19	13	Keyboard p and P	26  */
	17,	/* 20	14	Keyboard q and Q	17  */
	18,	/* 21	15	Keyboard r and R	20  */
	19,	/* 22	16	Keyboard s and S	32  */
	20,	/* 23	17	Keyboard t and T	21  */
	21,	/* 24	18	Keyboard u and U	23  */
	22,	/* 25	19	Keyboard v and V	49  */
	23,	/* 26	1A	Keyboard w and W	18  */
	24,	/* 27	1B	Keyboard x and X	47  */
	25,	/* 28	1C	Keyboard y and Y	22  */
	26,	/* 29	1D	Keyboard z and Z	46  */
	0,	/* 30	1E	Keyboard 1 and !	2   */
	0,	/* 31	1F	Keyboard 2 and @	3   */
	0,	/* 32	20	Keyboard 3 and #	4   */
	0,	/* 33	21	Keyboard 4 and $	5   */
	0,	/* 34	22	Keyboard 5 and %	6   */
	0,	/* 35	23	Keyboard 6 and ^	7   */
	0,	/* 36	24	Keyboard 7 and &	8   */
	0,	/* 37	25	Keyboard 8 and *	9   */
	0,	/* 38	26	Keyboard 9 and (	10  */
	0,	/* 39	27	Keyboard 0 and )	11  */
	0,	/* 40	28	Keyboard Return (ENTER)	43  */
	0,	/* 41	29	Keyboard ESCAPE 	110 */
	0,	/* 42	2A	Keyboard DELETE (BS)	15  */
	0,	/* 43	2B	Keyboard Tab 		16  */
	0,	/* 44	2C	Keyboard Spacebar 	61  */
	0,	/* 45	2D	Keyboard - and (underscore) 12 */
	0,	/* 46	2E	Keyboard = and +	13  */
	0,	/* 47	2F	Keyboard [ and {	27  */
	0,	/* 48	30	Keyboard ] and }	28  */
	0,	/* 49	31	Keyboard \ and |	29  */
	0,	/* 50	32	Keyboard Non-US # and ~	42  */
	0,	/* 51	33	Keyboard ; and :	40  */
	0,	/* 52	34	Keyboard ' and "	41  */
	0,	/* 53	35	Keyboard Grave Accent and Tilde 1 */
	0,	/* 54	36	Keyboard , and <	53  */
	0,	/* 55	37	Keyboard . and >	54  */
	0,	/* 56	38	Keyboard / and ?	55  */
	0,	/* 57	39	Keyboard Caps Lock	30  */
	0,	/* 58	3A	Keyboard F1		112 */
	0,	/* 59	3B	Keyboard F2		113 */
	0,	/* 60	3C	Keyboard F3		114 */
	0,	/* 61	3D	Keyboard F4		115 */
	0,	/* 62	3E	Keyboard F5		116 */
	0,	/* 63	3F	Keyboard F6		117 */
	0,	/* 64	40	Keyboard F7		118 */
	0,	/* 65	41	Keyboard F8		119 */
	0,	/* 66	42	Keyboard F9		120 */
	0,	/* 67	43	Keyboard F10		121 */
	0,	/* 68	44	Keyboard F11		122 */
	0,	/* 69	45	Keyboard F12		123 */
	0,	/* 70	46	Keyboard PrintScreen	124 */
	0,	/* 71	47	Keyboard Scroll Lock	125 */
	0,	/* 72	48	Keyboard Pause		126 */
	0,	/* 73	49	Keyboard Insert		75 */
	0,	/* 74	4A	Keyboard Home		80 */
	0,	/* 75	4B	Keyboard PageUp		85 */
	0,	/* 76	4C	Keyboard Delete Forward	76 */
	0,	/* 77	4D	Keyboard End		81 */
	0,	/* 78	4E	Keyboard PageDown	86 */
	0,	/* 79	4F	Keyboard RightArrow	89 */
	0,	/* 80	50	Keyboard LeftArrow	79 */
	0,	/* 81	51	Keyboard DownArrow	84 */
	0,	/* 82	52	Keyboard UpArrow	83 */
	0,	/* 83	53	Keypad Num Lock and Clear 90 */
	0,	/* 84	54	Keypad /		95 */
	0,	/* 85	55	Keypad *		100 */
	0,	/* 86	56	Keypad -		105 */
	0,	/* 87	57	Keypad +		106 */
	0,	/* 88	58	Keypad ENTER		108 */
	0,	/* 89	59	Keypad 1 and End	93  */
	0,	/* 90	5A	Keypad 2 and Down Arrow	98  */
	0,	/* 91	5B	Keypad 3 and PageDn	103 */
	0,	/* 92	5C	Keypad 4 and Left Arrow	92  */
	0,	/* 93	5D	Keypad 5		97  */
	0,	/* 94	5E	Keypad 6 and Right Arrow 102 */
	0,	/* 95	5F	Keypad 7 and Home	91  */
	0,	/* 96	60	Keypad 8 and Up Arrow	96  */
	0,	/* 97	61	Keypad 9 and PageUp	101 */
	0,	/* 98	62	Keypad 0 and Insert	99  */
	0,	/* 99	63	Keypad . and Delete	104 */
	0	/* 100	64	Keyboard Non-US \ and |	45  */
};
