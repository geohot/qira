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

sub merge_entry_points {
  my $baserom_entry = \shift;
  my $rom_entry = \shift;
  my $offset = shift;

  if ( $$rom_entry ) {
    my $old_entry = $$baserom_entry;
    $$baserom_entry = ( $offset + $$rom_entry );
    $$rom_entry = $old_entry;
  }
}

my @romfiles = @ARGV;
my @roms = map { my $rom = new Option::ROM; $rom->load($_); $rom } @romfiles;

my $baserom = shift @roms;
my $offset = $baserom->length;

foreach my $rom ( @roms ) {

  # Merge initialisation entry point
  merge_entry_points ( $baserom->{init}, $rom->{init}, $offset );

  # Merge BOFM header
  merge_entry_points ( $baserom->{bofm_header}, $rom->{bofm_header}, $offset );

  # Update PCI header, if present in both
  my $baserom_pci = $baserom->pci_header;
  my $rom_pci = $rom->pci_header;
  if ( $baserom_pci && $rom_pci ) {

    # Update PCI lengths
    $baserom_pci->{image_length} += $rom_pci->{image_length};
    if ( exists $baserom_pci->{runtime_length} ) {
      if ( exists $rom_pci->{runtime_length} ) {
	$baserom_pci->{runtime_length} += $rom_pci->{runtime_length};
      } else {
	$baserom_pci->{runtime_length} += $rom_pci->{image_length};
      }
    }

    # Merge CLP entry point
    if ( exists ( $baserom_pci->{clp_entry} ) &&
	 exists ( $rom_pci->{clp_entry} ) ) {
      merge_entry_points ( $baserom_pci->{clp_entry}, $rom_pci->{clp_entry},
			   $offset );
    }
  }

  # Update PnP header, if present in both
  my $baserom_pnp = $baserom->pnp_header;
  my $rom_pnp = $rom->pnp_header;
  if ( $baserom_pnp && $rom_pnp ) {
    merge_entry_points ( $baserom_pnp->{bcv}, $rom_pnp->{bcv}, $offset );
    merge_entry_points ( $baserom_pnp->{bdv}, $rom_pnp->{bdv}, $offset );
    merge_entry_points ( $baserom_pnp->{bev}, $rom_pnp->{bev}, $offset );
  }

  # Update iPXE header, if present
  my $baserom_ipxe = $baserom->ipxe_header;
  my $rom_ipxe = $rom->ipxe_header;
  if ( $baserom_ipxe ) {

    # Update shrunk length
    $baserom_ipxe->{shrunk_length} = ( $baserom->{length} +
				       ( $rom_ipxe ?
					 $rom_ipxe->{shrunk_length} :
					 $rom->{length} ) );

    # Fix checksum
    $baserom_ipxe->fix_checksum();
  }

  # Update base length
  $baserom->{length} += $rom->{length};

  # Fix checksum for this ROM segment
  $rom->fix_checksum();

  # Add this ROM to base ROM
  my $data = substr ( $baserom->get(), 0, $baserom->length() );
  $data .= $rom->get();
  $data .= $baserom->next_image()->get() if $baserom->next_image();
  $baserom->set ( $data );

  $offset += $rom->length;
}

$baserom->pnp_header->fix_checksum() if $baserom->pnp_header;
$baserom->fix_checksum();
$baserom->save ( "-" );
