#!/usr/bin/perl -w
#
# Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin";
use Option::ROM qw ( :all );

my $romfile = shift || "-";
my $rom = new Option::ROM;
$rom->load ( $romfile );

do {

  die "Not an option ROM image\n"
      unless $rom->{signature} == ROM_SIGNATURE;

  my $romlength = ( $rom->{length} * 512 );
  my $filelength = $rom->length;
  die "ROM image truncated (is $filelength, should be $romlength)\n"
      if $filelength < $romlength;

  printf "ROM header:\n\n";
  printf "  %-16s 0x%02x (%d)\n", "Length:",
	 $rom->{length}, ( $rom->{length} * 512 );
  printf "  %-16s 0x%02x (%s0x%02x)\n", "Checksum:", $rom->{checksum},
	 ( ( $rom->checksum == 0 ) ? "" : "INCORRECT: " ), $rom->checksum;
  printf "  %-16s 0x%04x\n", "Init:", $rom->{init};
  printf "  %-16s 0x%04x\n", "UNDI header:", $rom->{undi_header};
  printf "  %-16s 0x%04x\n", "PCI header:", $rom->{pci_header};
  printf "  %-16s 0x%04x\n", "PnP header:", $rom->{pnp_header};
  printf "\n";

  my $pci = $rom->pci_header();
  if ( $pci ) {
    printf "PCI header:\n\n";
    printf "  %-16s %s\n", "Signature:", $pci->{signature};
    printf "  %-16s 0x%04x\n", "Vendor ID:", $pci->{vendor_id};
    printf "  %-16s 0x%04x\n", "Device ID:", $pci->{device_id};
    if ( $pci->{device_list} ) {
      printf "  %-16s %s\n", "Device list:",
	     ( join ( ", ", map { sprintf "0x%04x", $_ } $pci->device_list ) );
    }
    printf "  %-16s 0x%02x%02x%02x\n", "Device class:",
	   $pci->{base_class}, $pci->{sub_class}, $pci->{prog_intf};
    printf "  %-16s 0x%04x (%d)\n", "Image length:",
	   $pci->{image_length}, ( $pci->{image_length} * 512 );
    printf "  %-16s 0x%04x (%d)\n", "Runtime length:",
	   $pci->{runtime_length}, ( $pci->{runtime_length} * 512 );
    printf "  %-16s 0x%02x\n", "Code type:", $pci->{code_type};
    if ( exists $pci->{conf_header} ) {
      printf "  %-16s 0x%04x\n", "Config header:", $pci->{conf_header};
      printf "  %-16s 0x%04x\n", "CLP entry:", $pci->{clp_entry};
    }
    printf "\n";
  }

  my $pnp = $rom->pnp_header();
  if ( $pnp ) {
    printf "PnP header:\n\n";
    printf "  %-16s %s\n", "Signature:", $pnp->{signature};
    printf "  %-16s 0x%02x (%s0x%02x)\n", "Checksum:", $pnp->{checksum},
	   ( ( $pnp->checksum == 0 ) ? "" : "INCORRECT: " ), $pnp->checksum;
    printf "  %-16s 0x%04x \"%s\"\n", "Manufacturer:",
	   $pnp->{manufacturer}, $pnp->manufacturer;
    printf "  %-16s 0x%04x \"%s\"\n", "Product:",
	   $pnp->{product}, $pnp->product;
    printf "  %-16s 0x%04x\n", "BCV:", $pnp->{bcv};
    printf "  %-16s 0x%04x\n", "BDV:", $pnp->{bdv};
    printf "  %-16s 0x%04x\n", "BEV:", $pnp->{bev};
    printf "\n";
  }

  my $undi = $rom->undi_header();
  if ( $undi ) {
    printf "UNDI header:\n\n";
    printf "  %-16s %s\n", "Signature:", $undi->{signature};
    printf "  %-16s 0x%02x (%s0x%02x)\n", "Checksum:", $undi->{checksum},
	   ( ( $undi->checksum == 0 ) ? "" : "INCORRECT: " ), $undi->checksum;
    printf "  %-16s %d.%d.%d\n", "UNDI version:", $undi->{version_major},
	   $undi->{version_minor}, $undi->{version_revision};
    printf "  %-16s 0x%04x\n", "Loader entry:", $undi->{loader_entry};
    printf "  %-16s 0x%04x\n", "Stack size:", $undi->{stack_size};
    printf "  %-16s 0x%04x\n", "Data size:", $undi->{data_size};
    printf "  %-16s 0x%04x\n", "Code size:", $undi->{code_size};
    printf "  %-16s %s\n", "Bus type:", $undi->{bus_type};
    printf "\n";
  }

  my $ipxe = $rom->ipxe_header();
  if ( $ipxe ) {
    printf "iPXE header:\n\n";
    printf "  %-16s 0x%02x (%s0x%02x)\n", "Checksum:", $ipxe->{checksum},
	   ( ( $ipxe->checksum == 0 ) ? "" : "INCORRECT: " ), $ipxe->checksum;
    printf "  %-16s 0x%02x (%d)\n", "Shrunk length:",
	   $ipxe->{shrunk_length}, ( $ipxe->{shrunk_length} * 512 );
    printf "  %-16s 0x%08x\n", "Build ID:", $ipxe->{build_id};
    printf "\n";
  }

} while ( $rom = $rom->next_image );
