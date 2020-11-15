#ifndef _PIXBUF_TEST_H
#define _PIXBUF_TEST_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/refcnt.h>
#include <ipxe/image.h>
#include <ipxe/test.h>

/** A pixel buffer test */
struct pixel_buffer_test {
	/** Image type */
	struct image_type *type;
	/** Source image */
	struct image *image;
	/** Pixel data */
	const uint32_t *data;
	/** Length of pixel data */
	size_t len;
	/** Width */
	unsigned int width;
	/** Height */
	unsigned int height;
};

/**
 * Define a pixel buffer test
 *
 * @v _name		Test name
 * @v _type		Test image file type
 * @v _file		Test image file data
 * @v _width		Expected pixel buffer width
 * @v _height		Expected pixel buffer height
 * @v _data		Expected pixel buffer data
 * @ret test		Pixel buffer test
 */
#define PIX( _name, _type, _file, _width, _height, _data )		\
	static const char _name ## __file[] = _file;			\
	static const uint32_t _name ## __data[] = _data;		\
	static struct image _name ## __image = {			\
		.refcnt = REF_INIT ( ref_no_free ),			\
		.name = #_name,						\
		.data = ( userptr_t ) ( _name ## __file ),		\
		.len = sizeof ( _name ## __file ),			\
	};								\
	static struct pixel_buffer_test _name = {			\
		.type = _type,						\
		.image = & _name ## __image,				\
		.data = _name ## __data,				\
		.len = sizeof ( _name ## __data ),			\
		.width = _width,					\
		.height = _height,					\
	};

extern void pixbuf_okx ( struct pixel_buffer_test *test, const char *file,
			 unsigned int line );

/**
 * Report pixel buffer test result
 *
 * @v test		Pixel buffer test
 */
#define pixbuf_ok( test ) pixbuf_okx ( test, __FILE__, __LINE__ )

#endif /* _PIXBUF_TEST_H */
