#ifndef _IPXE_DOWNLOAD_H
#define _IPXE_DOWNLOAD_H

/*
 * Copyright (C) 2010 VMware, Inc.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * iPXE Download Protocol
 *
 * EFI applications started by iPXE may use this interface to download files.
 */

typedef struct _IPXE_DOWNLOAD_PROTOCOL IPXE_DOWNLOAD_PROTOCOL;

/** Token to represent a currently downloading file */
typedef VOID *IPXE_DOWNLOAD_FILE;

/**
 * Callback function that is invoked when data arrives for a particular file.
 *
 * Not all protocols will deliver data in order. Clients should not rely on the
 * order of data delivery matching the order in the file.
 *
 * Some protocols are capable of determining the file size near the beginning
 * of data transfer. To allow the client to allocate memory more efficiently,
 * iPXE may give a hint about the file size by calling the Data callback with
 * a zero BufferLength and the file size in FileOffset. Clients should be
 * prepared to deal with more or less data than the hint actually arriving.
 *
 * @v Context		Context provided to the Start function
 * @v Buffer		New data
 * @v BufferLength	Length of new data in bytes
 * @v FileOffset	Offset of new data in the file
 * @ret Status		EFI_SUCCESS to continue the download,
 *			or any error code to abort.
 */
typedef
EFI_STATUS
(EFIAPI *IPXE_DOWNLOAD_DATA_CALLBACK)(
  IN VOID *Context,
  IN VOID *Buffer,
  IN UINTN BufferLength,
  IN UINTN FileOffset
  );

/**
 * Callback function that is invoked when the file is finished downloading, or
 * when a connection unexpectedly closes or times out.
 *
 * The finish callback is also called when a download is aborted by the Abort
 * function (below).
 *
 * @v Context		Context provided to the Start function
 * @v Status		Reason for termination: EFI_SUCCESS when the entire
 * 			file was transferred successfully, or an error
 * 			otherwise
 */
typedef
void
(EFIAPI *IPXE_DOWNLOAD_FINISH_CALLBACK)(
  IN VOID *Context,
  IN EFI_STATUS Status
  );

/**
 * Start downloading a file, and register callback functions to handle the
 * download.
 *
 * @v This		iPXE Download Protocol instance
 * @v Url		URL to download from
 * @v DataCallback	Callback that will be invoked when data arrives
 * @v FinishCallback	Callback that will be invoked when the download ends
 * @v Context		Context passed to the Data and Finish callbacks
 * @v File		Token that can be used to abort the download
 * @ret Status		EFI status code
 */
typedef
EFI_STATUS
(EFIAPI *IPXE_DOWNLOAD_START)(
  IN IPXE_DOWNLOAD_PROTOCOL *This,
  IN CHAR8 *Url,
  IN IPXE_DOWNLOAD_DATA_CALLBACK DataCallback,
  IN IPXE_DOWNLOAD_FINISH_CALLBACK FinishCallback,
  IN VOID *Context,
  OUT IPXE_DOWNLOAD_FILE *File
  );

/**
 * Forcibly abort downloading a file that is currently in progress.
 *
 * It is not safe to call this function after the Finish callback has executed.
 *
 * @v This		iPXE Download Protocol instance
 * @v File		Token obtained from Start
 * @v Status		Reason for aborting the download
 * @ret Status		EFI status code
 */
typedef
EFI_STATUS
(EFIAPI *IPXE_DOWNLOAD_ABORT)(
  IN IPXE_DOWNLOAD_PROTOCOL *This,
  IN IPXE_DOWNLOAD_FILE File,
  IN EFI_STATUS Status
  );

/**
 * Poll for more data from iPXE. This function will invoke the registered
 * callbacks if data is available or if downloads complete.
 *
 * @v This		iPXE Download Protocol instance
 * @ret Status		EFI status code
 */
typedef
EFI_STATUS
(EFIAPI *IPXE_DOWNLOAD_POLL)(
  IN IPXE_DOWNLOAD_PROTOCOL *This
  );

/**
 * The iPXE Download Protocol.
 *
 * iPXE will attach a iPXE Download Protocol to the DeviceHandle in the Loaded
 * Image Protocol of all child EFI applications.
 */
struct _IPXE_DOWNLOAD_PROTOCOL {
   IPXE_DOWNLOAD_START Start;
   IPXE_DOWNLOAD_ABORT Abort;
   IPXE_DOWNLOAD_POLL Poll;
};

#define IPXE_DOWNLOAD_PROTOCOL_GUID \
  { \
    0x3eaeaebd, 0xdecf, 0x493b, { 0x9b, 0xd1, 0xcd, 0xb2, 0xde, 0xca, 0xe7, 0x19 } \
  }

extern int efi_download_install ( EFI_HANDLE handle );
extern void efi_download_uninstall ( EFI_HANDLE handle );

#endif /* _IPXE_DOWNLOAD_H */
