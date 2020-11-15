#!/usr/bin/perl -w

=head1 NAME

import.pl

=head1 SYNOPSIS

import.pl [options] /path/to/edk2/edk2

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
  my $edktop = shift;
  my $edkdirs = shift;
  my $filename = shift;

  # Skip everything except headers
  return unless $filename =~ /\.h$/;

  # Skip files that are iPXE native headers
  my $outfile = catfile ( $ipxedir, $filename );
  if ( -s $outfile ) {
    open my $outfh, "<$outfile" or die "Could not open $outfile: $!\n";
    my $line = <$outfh>;
    close $outfh;
    chomp $line;
    return if $line =~ /^\#ifndef\s+_IPXE_\S+_H$/;
  }

  # Search for importable header
  foreach my $edkdir ( @$edkdirs ) {
    my $infile = catfile ( $edktop, $edkdir, $filename );
    if ( -e $infile ) {
      # We have found a matching source file - import it
      print "$filename <- ".catfile ( $edkdir, $filename )."\n"
	  if $verbosity >= 1;
      open my $infh, "<$infile" or die "Could not open $infile: $!\n";
      ( undef, my $outdir, undef ) = splitpath ( $outfile );
      mkpath ( $outdir );
      open my $outfh, ">$outfile" or die "Could not open $outfile: $!\n";
      my @dependencies = ();
      my $licence;
      my $maybe_guard;
      my $guard;
      while ( <$infh> ) {
	# Strip CR and trailing whitespace
	s/\r//g;
	s/\s*$//g;
	chomp;
	# Update include lines, and record included files
	if ( s/^\#include\s+[<\"](\S+)[>\"]/\#include <ipxe\/efi\/$1>/ ) {
	  push @dependencies, $1;
	}
	# Check for BSD licence statement
	if ( /^\s*THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE/ ) {
	  die "Licence detected after header guard\n" if $guard;
	  $licence = "BSD3";
	}
	# Write out line
	print $outfh "$_\n";
	# Apply FILE_LICENCE() immediately after include guard
	if ( defined $maybe_guard && ! defined $guard ) {
	  if ( /^\#define\s+_?_${maybe_guard}_?_$/ ) {
	    $guard = $maybe_guard;
	    print $outfh "\nFILE_LICENCE ( $licence );\n" if $licence;
	  }
	  undef $maybe_guard;
	}
	if ( /^#ifndef\s+_?_(\S+)_?_/ ) {
	  $maybe_guard = $1;
	}
      }
      close $outfh;
      close $infh;
      # Warn if no licence was detected
      warn "Cannot detect licence in $infile\n" unless $licence;
      warn "Cannot detect header guard in $infile\n" unless $guard;
      # Recurse to handle any included files that we don't already have
      foreach my $dependency ( @dependencies ) {
	if ( ! -e catfile ( $ipxedir, $dependency ) ) {
	  print "...following dependency on $dependency\n" if $verbosity >= 1;
	  try_import_file ( $ipxedir, $edktop, $edkdirs, $dependency );
	}
      }
      return;
    }
  }
  die "$filename has no equivalent in $edktop\n";
}

# Parse command-line options
Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions (
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
  'help|h' => sub { pod2usage ( 1 ); },
) or die "Could not parse command-line options\n";
pod2usage ( 1 ) unless @ARGV == 1;
my $edktop = shift;

# Identify edk import directories
my $edkdirs = [ "MdePkg/Include", "IntelFrameworkPkg/Include",
		"MdeModulePkg/Include", "EdkCompatibilityPkg/Foundation" ];
foreach my $edkdir ( @$edkdirs ) {
  die "Directory \"$edktop\" does not appear to contain the EFI EDK2 "
      ."(missing \"$edkdir\")\n" unless -d catdir ( $edktop, $edkdir );
}

# Identify iPXE EFI includes directory
my $ipxedir = $FindBin::Bin;
die "Directory \"$ipxedir\" does not appear to contain the iPXE EFI includes\n"
    unless -e catfile ( $ipxedir, "../../../include/ipxe/efi" );

if ( $verbosity >= 1 ) {
  print "Importing EFI headers into $ipxedir\nfrom ";
  print join ( "\n and ", map { catdir ( $edktop, $_ ) } @$edkdirs )."\n";
}

# Import headers
find ( { wanted => sub {
  try_import_file ( $ipxedir, $edktop, $edkdirs, abs2rel ( $_, $ipxedir ) );
}, no_chdir => 1 }, $ipxedir );
