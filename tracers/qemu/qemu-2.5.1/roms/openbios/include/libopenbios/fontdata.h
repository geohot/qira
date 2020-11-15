/* Font definitions */

#ifndef OPENBIOS_FONTDATA_H
#define OPENBIOS_FONTDATA_H

#define FONTDATAMAX_8X8 2048
#define FONT_WIDTH_8X8 8
#define FONT_HEIGHT_8X8 8

extern const unsigned char fontdata_8x8[FONTDATAMAX_8X8];

#define FONTDATAMAX_8X16 4096
#define FONT_WIDTH_8X16 8
#define FONT_HEIGHT_8X16 16

extern const unsigned char fontdata_8x16[FONTDATAMAX_8X16];

#if defined(CONFIG_FONT_8X8)
#define fontdata fontdata_8x8
#define FONT_HEIGHT FONT_HEIGHT_8X8
#define FONT_WIDTH FONT_WIDTH_8X8
#elif defined(CONFIG_FONT_8X16)
#define fontdata fontdata_8x16
#define FONT_HEIGHT FONT_HEIGHT_8X16
#define FONT_WIDTH FONT_WIDTH_8X16
#endif

#endif /* OPENBIOS_FONTDATA_H */
