#!/usr/bin/perl -w

use strict;
use warnings;
use Getopt::Long;
use Fcntl;

my $verbosity = 0;
my $blksize = 512;
my $byte = 0;

my %opts = (
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
  'blksize|s=o' => sub { $blksize = $_[1]; },
  'byte|b=o' => sub { $byte = $_[1]; },
);

Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions ( %opts ) or die "Could not parse command-line options\n";

while ( my $filename = shift ) {
  die "$filename is not a file\n" unless -f $filename;
  my $oldsize = -s $filename;
  my $padsize = ( ( -$oldsize ) % $blksize );
  my $newsize = ( $oldsize + $padsize );
  next unless $padsize;
  if ( $verbosity >= 1 ) {
      printf "Padding %s from %d to %d bytes with %d x 0x%02x\n",
	     $filename, $oldsize, $newsize, $padsize, $byte;
  }
  if ( $byte ) {
    sysopen ( my $fh, $filename, ( O_WRONLY | O_APPEND ) )
	or die "Could not open $filename for appending: $!\n";
    syswrite $fh, ( chr ( $byte ) x $padsize )
	or die "Could not append to $filename: $!\n";
    close ( $fh );
  } else {
    truncate $filename, $newsize
	or die "Could not resize $filename: $!\n";
  }
  die "Failed to pad $filename\n"
      unless ( ( ( -s $filename ) % $blksize ) == 0 );
}
