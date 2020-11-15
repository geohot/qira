#!/usr/bin/perl -w

=head1 NAME

import.pl

=head1 SYNOPSIS

import.pl [options] /path/to/xen

Options:

    -h,--help		Display brief help message
    -v,--verbose	Increase verbosity
    -q,--quiet		Decrease verbosity

=cut

use File::Spec::Functions qw ( :ALL );
use File::Find;
use File::Path;
use Getopt::Long;
use Pod::Usage;
use FindBin;
use strict;
use warnings;

my $verbosity = 0;

sub try_import_file {
  my $ipxedir = shift;
  my $xendir = shift;
  my $filename = shift;

  # Skip everything except headers
  return unless $filename =~ /\.h$/;

  # Search for importable header
  ( undef, my $subdir, undef ) = splitpath ( $filename );
  my $outfile = catfile ( $ipxedir, $filename );
  my $infile = catfile ( $xendir, "xen/include/public", $filename );
  die "$infile does not exist\n" unless -e $infile;

  # Import header file
  print "$filename <- ".catfile ( $xendir, $filename )."\n"
      if $verbosity >= 1;
  open my $infh, "<", $infile or die "Could not open $infile: $!\n";
  mkpath ( catdir ( $xendir, $subdir ) );
  open my $outfh, ">", $outfile or die "Could not open $outfile: $!\n";
  my @dependencies = ();
  my $maybe_guard;
  my $guard;
  while ( <$infh> ) {
    # Strip CR and trailing whitespace
    s/\r//g;
    s/\s*$//g;
    chomp;
    # Update include lines, and record included files
    if ( /^\#include\s+[<\"](\S+)[>\"]/ ) {
      push @dependencies, catfile ( $subdir, $1 );
    }
    # Write out line
    print $outfh "$_\n";
    # Apply FILE_LICENCE() immediately after include guard
    if ( defined $maybe_guard ) {
      if ( /^\#define\s+_+${maybe_guard}_H_*$/ ) {
	die "Duplicate header guard detected in $infile\n" if $guard;
	$guard = $maybe_guard;
	print $outfh "\nFILE_LICENCE ( MIT );\n";
      }
      undef $maybe_guard;
    }
    if ( /^#ifndef\s+_+(\S+)_H_*$/ ) {
      $maybe_guard = $1;
    }
  }
  close $outfh;
  close $infh;
  # Warn if no header guard was detected
  warn "Cannot detect header guard in $infile\n" unless $guard;
  # Recurse to handle any included files that we don't already have
  foreach my $dependency ( @dependencies ) {
    if ( ! -e catfile ( $ipxedir, $dependency ) ) {
      print "...following dependency on $dependency\n" if $verbosity >= 1;
      try_import_file ( $ipxedir, $xendir, $dependency );
    }
  }
  return;
}

# Parse command-line options
Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions (
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
  'help|h' => sub { pod2usage ( 1 ); },
) or die "Could not parse command-line options\n";
pod2usage ( 1 ) unless @ARGV == 1;
my $xendir = shift;

# Identify Xen import directory
die "Directory \"$xendir\" does not appear to contain the Xen source tree\n"
    unless -e catfile ( $xendir, "xen/include/public/xen.h" );

# Identify iPXE Xen includes directory
my $ipxedir = $FindBin::Bin;
die "Directory \"$ipxedir\" does not appear to contain the iPXE Xen includes\n"
    unless -e catfile ( $ipxedir, "../../include/ipxe" );

print "Importing Xen headers into $ipxedir\nfrom $xendir\n"
    if $verbosity >= 1;

# Import headers
find ( { wanted => sub {
  try_import_file ( $ipxedir, $xendir, abs2rel ( $_, $ipxedir ) );
}, no_chdir => 1 }, $ipxedir );
