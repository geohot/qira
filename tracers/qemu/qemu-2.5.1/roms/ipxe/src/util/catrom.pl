#!/usr/bin/perl -w

use warnings;
use strict;

use FindBin;
use lib "$FindBin::Bin";
use Option::ROM qw ( :all );

my @romfiles = @ARGV
    or die "Usage: $0 rom-file-1 rom-file-2 ... > multi-rom-file\n";

while ( my $romfile = shift @romfiles ) {

  # Read ROM file
  my $rom = new Option::ROM;
  $rom->load ( $romfile );

  # Tag final image as non-final in all except the final ROM
  if ( @romfiles ) {
    my $image = $rom;
    $image = $image->next_image() while $image->next_image();
    $image->pci_header->{last_image} &= ~PCI_LAST_IMAGE;
    $image->fix_checksum();
  }

  # Write ROM file to STDOUT
  $rom->save ( "-" );
}
