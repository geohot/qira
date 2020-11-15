/*
 *
 * (c) 2005-2009 Laurent Vivier <Laurent@vivier.eu>
 *
 * This file has been copied from EMILE, http://emile.sf.net
 *
 * some parts from mkisofs (c) J. Schilling
 *
 */

#include "libiso9660.h"
#include "libopenbios/bindings.h"
#include "libc/diskio.h"

void iso9660_name(iso9660_VOLUME *volume, struct iso_directory_record *idr, char *buffer)
{
	int	j;
        unsigned char ul, uc;

	buffer[0] = 0;
	if (idr->name_len[0] == 1 && idr->name[0] == 0)
		strcpy(buffer, ".");
	else if (idr->name_len[0] == 1 && idr->name[0] == 1)
		strcpy(buffer, "..");
	else {
		switch (volume->ucs_level) {
		case 3:
		case 2:
		case 1:
			/*
			 * Unicode name.
			 */

			for (j = 0; j < (int)idr->name_len[0] / 2; j++) {
				ul = idr->name[j*2+1];

				/*
				 * unicode convertion
				 * up = unls->unls_uni2cs[uh];
				 *
				 * if (up == NULL)
				 *	uc = '\0';
				 * else
				 *	uc = up[ul];
				 *
				 * we use only low byte
				 */

				uc = ul;

				buffer[j] = uc ? uc : '_';
			}
			buffer[idr->name_len[0]/2] = '\0';
			break;
		case 0:
			/*
			 * Normal non-Unicode name.
			 */
			strncpy(buffer, idr->name, idr->name_len[0]);
			buffer[idr->name_len[0]] = 0;
			break;
		default:
			/*
			 * Don't know how to do these yet.  Maybe they are the same
			 * as one of the above.
			 */
			break;
		}
	}
}

iso9660_VOLUME *iso9660_mount(int fd)
{
	iso9660_VOLUME* volume;
	struct iso_primary_descriptor *jpd;
	struct iso_primary_descriptor ipd;
	int	block;
	int ucs_level = 0;

	/* read filesystem descriptor */

	seek_io(fd, 16 * ISOFS_BLOCK_SIZE);
	read_io(fd, &ipd, sizeof (ipd));

	/*
	 * High sierra:
	 *
	 *	DESC TYPE	== 1 (VD_SFS)	offset 8	len 1
	 *	STR ID		== "CDROM"	offset 9	len 5
	 *	STD_VER		== 1		offset 14	len 1
	 */

	/* High Sierra format ? */

	if ((((char *)&ipd)[8] == 1) &&
	    (strncmp(&((char *)&ipd)[9], "CDROM", 5) == 0) &&
	    (((char *)&ipd)[14] == 1)) {
		printk("Incompatible format: High Sierra format\n");
		return NULL;
	}

	/*
	 * ISO 9660:
	 *
	 *	DESC TYPE	== 1 (VD_PVD)	offset 0	len 1
	 *	STR ID		== "CD001"	offset 1	len 5
	 *	STD_VER		== 1		offset 6	len 1
	 */

	/* NOT ISO 9660 format ? */

	if ((ipd.type[0] != ISO_VD_PRIMARY) ||
	    (strncmp(ipd.id, ISO_STANDARD_ID, sizeof (ipd.id)) != 0) ||
	    (ipd.version[0] != 1)) {
		return NULL;
	}

	/* UCS info */

	block = 16;

	jpd = (struct iso_primary_descriptor *)
		malloc(sizeof(struct iso_primary_descriptor));
	if (jpd == NULL)
		return NULL;

	memcpy(jpd, &ipd, sizeof (ipd));
	while ((uint8_t)jpd->type[0] != ISO_VD_END) {

		/*
		 * If Joliet UCS escape sequence found, we may be wrong
		 */

		if (jpd->unused3[0] == '%' &&
		    jpd->unused3[1] == '/' &&
		    (jpd->unused3[3] == '\0' ||
		    jpd->unused3[3] == ' ') &&
		    (jpd->unused3[2] == '@' ||
		    jpd->unused3[2] == 'C' ||
		    jpd->unused3[2] == 'E')) {

			if (jpd->version[0] != 1)
				break;
		}

		block++;
		seek_io(fd, block * ISOFS_BLOCK_SIZE);
		read_io(fd, jpd, sizeof (*jpd));
	}

	ucs_level = 0;
	if (((unsigned char) jpd->type[0] == ISO_VD_END)) {
		memcpy(jpd, &ipd, sizeof (ipd));
	} else {
		switch (jpd->unused3[2]) {
		case '@':
			ucs_level = 1;
			break;
		case 'C':
			ucs_level = 2;
			break;
		case 'E':
			ucs_level = 3;
			break;
		}

		if (ucs_level && jpd->unused3[3] == ' ')
			printk("Warning: Joliet escape sequence uses illegal space at offset 3\n");
	}

	volume = (iso9660_VOLUME*)malloc(sizeof(iso9660_VOLUME));
	if (volume == NULL)
		return NULL;

	volume->descriptor = jpd;
	volume->ucs_level = ucs_level;
	volume->fd = fd;

	return volume;
}

int iso9660_umount(iso9660_VOLUME* volume)
{
	if (volume == NULL)
		return -1;
	free(volume->descriptor);
	free(volume);
	return 0;
}

int iso9660_probe(int fd, long long offset)
{
	struct iso_primary_descriptor ipd;

	seek_io(fd, 16 * ISOFS_BLOCK_SIZE + offset);
	read_io(fd, &ipd, sizeof (ipd));

	if ((ipd.type[0] != ISO_VD_PRIMARY) ||
	    (strncmp(ipd.id, ISO_STANDARD_ID, sizeof (ipd.id)) != 0) ||
	    (ipd.version[0] != 1)) {
		return 0;
	}

	return -1;
}

struct iso_directory_record *iso9660_get_root_node(iso9660_VOLUME* volume)
{
	return (struct iso_directory_record *)volume->descriptor->root_directory_record;
}
