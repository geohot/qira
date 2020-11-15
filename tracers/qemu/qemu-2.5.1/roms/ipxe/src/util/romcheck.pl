#!/usr/bin/perl -w

use strict;
use warnings;

use constant DEVICES => "/proc/bus/pci/devices";

open my $fh, DEVICES
    or die "Could not open ".DEVICES.": $!";

while ( ( my $line = <$fh> ) ) {

  # Parse line from /proc/bus/pci/devices
  chomp $line;
  ( my $bus, my $devfn, my $vendor, my $device, my $irq, my $bars, my $lengths,
    my $driver )
      = ( $line =~ /^ ([0-9a-f]{2}) ([0-9a-f]{2}) \s+
		      ([0-9a-f]{4}) ([0-9a-f]{4}) \s+ ([0-9a-f]+) \s+
		      ((?:[0-9a-f]+\s+){7}) ((?:[0-9a-f]+\s+){7})
		      (.+)?$/x )
      or die "Invalid line \"".$line."\"\n";
  ( $bus, $devfn, $vendor, $device, $irq ) =
      map { hex ( $_ ) } ( $bus, $devfn, $vendor, $device, $irq );
  my $dev = ( $devfn >> 3 );
  my $fn = ( $devfn & 0x7 );
  $bars = [ map { hex ( $_ ) } split ( /\s+/, $bars ) ];
  $lengths = [ map { hex ( $_ ) } split ( /\s+/, $lengths ) ];

  # Calculate expansion ROM BAR presence and length
  my $rom_length = $lengths->[6];

  # Look for a BAR that could support a .mrom
  my $mrom_ok;
  if ( $rom_length ) {
    for ( my $bar = 0 ; $bar < 7 ; $bar++ ) {
      # Skip I/O BARs
      next if $bars->[$bar] & 0x01;
      # Skip low half of 64-bit BARs
      $bar++ if $bars->[$bar] & 0x04;
      # Skip 64-bit BARs with high dword set
      next if $bars->[$bar] >> 32;
      # Skip BARs smaller than the expansion ROM BAR
      next if $lengths->[$bar] < $rom_length;
      # This BAR is usable!
      $mrom_ok = 1;
      last;
    }
  }

  printf "%02x:%02x.%x (%04x:%04x)", $bus, $dev, $fn, $vendor, $device;
  printf " supports a %dkB .rom", ( $rom_length / 1024 ) if $rom_length;
  printf " or .mrom" if $mrom_ok;
  printf "\n";
}
