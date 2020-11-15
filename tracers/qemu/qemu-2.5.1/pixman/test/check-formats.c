#include <ctype.h>
#include "utils.h"

static int
check_op (pixman_op_t          op,
          pixman_format_code_t src_format,
          pixman_format_code_t dest_format)
{
    uint32_t src_alpha_mask, src_green_mask;
    uint32_t dest_alpha_mask, dest_green_mask;
    pixel_checker_t src_checker, dest_checker;
    pixman_image_t *si, *di;
    uint32_t sa, sg, da, dg;
    uint32_t s, d;
    int retval = 0;

    pixel_checker_init (&src_checker, src_format);
    pixel_checker_init (&dest_checker, dest_format);

    pixel_checker_get_masks (
        &src_checker, &src_alpha_mask, NULL, &src_green_mask, NULL);
    pixel_checker_get_masks (
        &dest_checker, &dest_alpha_mask, NULL, &dest_green_mask, NULL);

    /* printf ("masks: %x %x %x %x\n", */
    /* 	    src_alpha_mask, src_green_mask, */
    /* 	    dest_alpha_mask, dest_green_mask); */

    si = pixman_image_create_bits (src_format, 1, 1, &s, 4);
    di = pixman_image_create_bits (dest_format, 1, 1, &d, 4);

    sa = 0;
    do
    {
        sg = 0;
        do
        {
            da = 0;
            do
            {
                dg = 0;
                do
                {
                    color_t src_color, dest_color, result_color;
                    uint32_t orig_d;

                    s = sa | sg;
                    d = da | dg;

                    orig_d = d;

		    pixel_checker_convert_pixel_to_color (&src_checker, s, &src_color);
		    pixel_checker_convert_pixel_to_color (&dest_checker, d, &dest_color);

		    do_composite (op, &src_color, NULL, &dest_color, &result_color, FALSE);


		    if (!is_little_endian())
                    {
			s <<= 32 - PIXMAN_FORMAT_BPP (src_format);
			d <<= 32 - PIXMAN_FORMAT_BPP (dest_format);
                    }

		    pixman_image_composite32 (op, si, NULL, di,
					      0, 0, 0, 0, 0, 0, 1, 1);

		    if (!is_little_endian())
                        d >>= (32 - PIXMAN_FORMAT_BPP (dest_format));

                    if (!pixel_checker_check (&dest_checker, d, &result_color))
                    {
                        printf ("---- test failed ----\n");
                        printf ("operator: %-32s\n", operator_name (op));
                        printf ("source:   %-12s pixel: %08x\n", format_name (src_format), s);
                        printf ("dest:     %-12s pixel: %08x\n", format_name (dest_format), orig_d);
                        printf ("got:      %-12s pixel: %08x\n", format_name (dest_format), d);

                        retval = 1;
                    }

                    dg -= dest_green_mask;
                    dg &= dest_green_mask;
                }
                while (dg != 0);

                da -= dest_alpha_mask;
                da &= dest_alpha_mask;
            }
            while (da != 0);

            sg -= src_green_mask;
            sg &= src_green_mask;
        }
        while (sg != 0);

        sa -= src_alpha_mask;
        sa &= src_alpha_mask;
    }
    while (sa != 0);

    pixman_image_unref (si);
    pixman_image_unref (di);

    return retval;
}

static const pixman_op_t op_list[] =
{
    PIXMAN_OP_CLEAR,
    PIXMAN_OP_SRC,
    PIXMAN_OP_DST,
    PIXMAN_OP_OVER,
    PIXMAN_OP_OVER_REVERSE,
    PIXMAN_OP_IN,
    PIXMAN_OP_IN_REVERSE,
    PIXMAN_OP_OUT,
    PIXMAN_OP_OUT_REVERSE,
    PIXMAN_OP_ATOP,
    PIXMAN_OP_ATOP_REVERSE,
    PIXMAN_OP_XOR,
    PIXMAN_OP_ADD,
    PIXMAN_OP_SATURATE,

    PIXMAN_OP_DISJOINT_CLEAR,
    PIXMAN_OP_DISJOINT_SRC,
    PIXMAN_OP_DISJOINT_DST,
    PIXMAN_OP_DISJOINT_OVER,
    PIXMAN_OP_DISJOINT_OVER_REVERSE,
    PIXMAN_OP_DISJOINT_IN,
    PIXMAN_OP_DISJOINT_IN_REVERSE,
    PIXMAN_OP_DISJOINT_OUT,
    PIXMAN_OP_DISJOINT_OUT_REVERSE,
    PIXMAN_OP_DISJOINT_ATOP,
    PIXMAN_OP_DISJOINT_ATOP_REVERSE,
    PIXMAN_OP_DISJOINT_XOR,

    PIXMAN_OP_CONJOINT_CLEAR,
    PIXMAN_OP_CONJOINT_SRC,
    PIXMAN_OP_CONJOINT_DST,
    PIXMAN_OP_CONJOINT_OVER,
    PIXMAN_OP_CONJOINT_OVER_REVERSE,
    PIXMAN_OP_CONJOINT_IN,
    PIXMAN_OP_CONJOINT_IN_REVERSE,
    PIXMAN_OP_CONJOINT_OUT,
    PIXMAN_OP_CONJOINT_OUT_REVERSE,
    PIXMAN_OP_CONJOINT_ATOP,
    PIXMAN_OP_CONJOINT_ATOP_REVERSE,
    PIXMAN_OP_CONJOINT_XOR,
};

static const pixman_format_code_t format_list[] =
{
    PIXMAN_a8r8g8b8,
    PIXMAN_x8r8g8b8,
    PIXMAN_a8b8g8r8,
    PIXMAN_x8b8g8r8,
    PIXMAN_b8g8r8a8,
    PIXMAN_b8g8r8x8,
    PIXMAN_r8g8b8a8,
    PIXMAN_r8g8b8x8,
    PIXMAN_x14r6g6b6,
    PIXMAN_x2r10g10b10,
    PIXMAN_a2r10g10b10,
    PIXMAN_x2b10g10r10,
    PIXMAN_a2b10g10r10,
    PIXMAN_a8r8g8b8_sRGB,
    PIXMAN_r8g8b8,
    PIXMAN_b8g8r8,
    PIXMAN_r5g6b5,
    PIXMAN_b5g6r5,
    PIXMAN_a1r5g5b5,
    PIXMAN_x1r5g5b5,
    PIXMAN_a1b5g5r5,
    PIXMAN_x1b5g5r5,
    PIXMAN_a4r4g4b4,
    PIXMAN_x4r4g4b4,
    PIXMAN_a4b4g4r4,
    PIXMAN_x4b4g4r4,
    PIXMAN_a8,
    PIXMAN_r3g3b2,
    PIXMAN_b2g3r3,
    PIXMAN_a2r2g2b2,
    PIXMAN_a2b2g2r2,
    PIXMAN_x4a4,
    PIXMAN_a4,
    PIXMAN_r1g2b1,
    PIXMAN_b1g2r1,
    PIXMAN_a1r1g1b1,
    PIXMAN_a1b1g1r1,
    PIXMAN_a1,
};

static pixman_format_code_t
format_from_string (const char *s)
{
    int i;

    for (i = 0; i < ARRAY_LENGTH (format_list); ++i)
    {
        if (strcasecmp (format_name (format_list[i]), s) == 0)
            return format_list[i];
    }

    return PIXMAN_null;
}

static void
emit (const char *s, int *n_chars)
{
    *n_chars += printf ("%s,", s);
    if (*n_chars > 60)
    {
        printf ("\n    ");
        *n_chars = 0;
    }
    else
    {
        printf (" ");
        (*n_chars)++;
    }
}

static void
list_formats (void)
{
    int n_chars;
    int i;

    printf ("Formats:\n    ");

    n_chars = 0;
    for (i = 0; i < ARRAY_LENGTH (format_list); ++i)
        emit (format_name (format_list[i]), &n_chars);

    printf ("\n\n");
}

static void
list_operators (void)
{
    char short_name [128] = { 0 };
    int i, n_chars;

    printf ("Operators:\n    ");

    n_chars = 0;
    for (i = 0; i < ARRAY_LENGTH (op_list); ++i)
    {
        pixman_op_t op = op_list[i];
        int j;

        snprintf (short_name, sizeof (short_name) - 1, "%s",
                  operator_name (op) + strlen ("PIXMAN_OP_"));

        for (j = 0; short_name[j] != '\0'; ++j)
            short_name[j] = tolower (short_name[j]);

        emit (short_name, &n_chars);
    }

    printf ("\n\n");
}

static pixman_op_t
operator_from_string (const char *s)
{
    char full_name[128] = { 0 };
    int i;

    snprintf (full_name, (sizeof full_name) - 1, "PIXMAN_OP_%s", s);

    for (i = 0; i < ARRAY_LENGTH (op_list); ++i)
    {
        pixman_op_t op = op_list[i];

        if (strcasecmp (operator_name (op), full_name) == 0)
            return op;
    }

    return PIXMAN_OP_NONE;
}

int
main (int argc, char **argv)
{
    enum { OPTION_OP, OPTION_SRC, OPTION_DEST, LAST_OPTION } option;
    pixman_format_code_t src_fmt, dest_fmt;
    pixman_op_t op;

    op = PIXMAN_OP_NONE;
    src_fmt = PIXMAN_null;
    dest_fmt = PIXMAN_null;

    argc--;
    argv++;

    for (option = OPTION_OP; option < LAST_OPTION; ++option)
    {
        char *arg = NULL;

        if (argc)
        {
            argc--;
            arg = *argv++;
        }

        switch (option)
        {
        case OPTION_OP:
            if (!arg)
                printf ("  - missing operator\n");
            else if ((op = operator_from_string (arg)) == PIXMAN_OP_NONE)
                printf ("  - unknown operator %s\n", arg);
            break;

        case OPTION_SRC:
            if (!arg)
                printf ("  - missing source format\n");
            else if ((src_fmt = format_from_string (arg)) == PIXMAN_null)
                printf ("  - unknown source format %s\n", arg);
            break;

        case OPTION_DEST:
            if (!arg)
                printf ("  - missing destination format\n");
            else if ((dest_fmt = format_from_string (arg)) == PIXMAN_null)
                printf ("  - unknown destination format %s\n", arg);
            break;

        default:
            assert (0);
            break;
        }
    }

    while (argc--)
    {
        op = PIXMAN_OP_NONE;
        printf ("  - unexpected argument: %s\n", *argv++);
    }

    if (op == PIXMAN_OP_NONE || src_fmt == PIXMAN_null || dest_fmt == PIXMAN_null)
    {
        printf ("\nUsage:\n    check-formats <operator> <src-format> <dest-format>\n\n");
        list_operators();
        list_formats();

        return -1;
    }

    return check_op (op, src_fmt, dest_fmt);
}
