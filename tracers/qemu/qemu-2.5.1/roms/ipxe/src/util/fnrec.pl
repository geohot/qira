#!/usr/bin/perl -w
#
# Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

=head1 NAME

fnrec.pl

=head1 SYNOPSIS

fnrec.pl [options] bin/image.xxx < logfile

Decode a function trace produced by building with FNREC=1

Options:

	-m,--max-depth=N	Set maximum displayed function depth

=cut

use IPC::Open2;
use Getopt::Long;
use Pod::Usage;
use strict;
use warnings;

use constant MAX_OPEN_BRACE => 10;
use constant MAX_COMMON_BRACE => 3;
use constant MAX_CLOSE_BRACE => 10;

# Parse command-line options
my $max_depth = 16;
Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions (
  'help|h' => sub { pod2usage ( 1 ); },
  'max-depth|m=i' => sub { shift; $max_depth = shift; },
) or die "Could not parse command-line options\n";
pod2usage ( 1 ) unless @ARGV == 1;
my $image = shift;
my $elf = $image.".tmp";
die "ELF file ".$elf." not found\n" unless -e $elf;

# Start up addr2line
my $addr2line_pid = open2 ( my $addr2line_out, my $addr2line_in,
			    "addr2line", "-f", "-e", $elf )
    or die "Could not start addr2line: $!\n";

# Translate address using addr2line
sub addr2line {
  my $address = shift;

  print $addr2line_in $address."\n";
  chomp ( my $name = <$addr2line_out> );
  chomp ( my $file_line = <$addr2line_out> );
  ( my $file, my $line ) = ( $file_line =~ /^(.*):(\d+)$/ );
  $file =~ s/^.*\/src\///;
  my $location = ( $line ? $file.":".$line." = ".$address : $address );
  return ( $name, $location );
}

# Parse logfile
my $depth = 0;
my $depths = [];
while ( my $line = <> ) {
  chomp $line;
  $line =~ s/\r//g;
  ( my $called_fn, my $call_site, my $entry_count, my $exit_count ) =
      ( $line =~ /^(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+([0-9]+)\s+([0-9]+)$/ )
      or print $line."\n" and next;

  ( my $called_fn_name, undef ) = addr2line ( $called_fn );
  ( undef, my $call_site_location ) = addr2line ( $call_site );
  $entry_count = ( $entry_count + 0 );
  $exit_count = ( $exit_count + 0 );

  if ( $entry_count >= $exit_count ) {
    #
    # Function entry
    #
    my $text = "";
    $text .= $called_fn_name." (from ".$call_site_location.")";
    if ( $exit_count <= MAX_COMMON_BRACE ) {
      $text .= " { }" x $exit_count;
    } else {
      $text .= " { } x ".$exit_count;
    }
    $entry_count -= $exit_count;
    if ( $entry_count <= MAX_OPEN_BRACE ) {
      $text .= " {" x $entry_count;
    } else {
      $text .= " { x ".$entry_count;
    }
    my $indent = "  " x $depth;
    print $indent.$text."\n";
    $depth += $entry_count;
    $depth = $max_depth if ( $depth > $max_depth );
    push @$depths, ( { called_fn => $called_fn, call_site => $call_site } ) x
	( $depth - @$depths );
  } else {
    #
    # Function exit
    #
    my $text = "";
    if ( $entry_count <= MAX_COMMON_BRACE ) {
      $text .= " { }" x $entry_count;
    } else {
      $text .= " { } x ".$entry_count;
    }
    $exit_count -= $entry_count;
    if ( $exit_count <= MAX_CLOSE_BRACE ) {
      $text .= " }" x $exit_count;
    } else {
      $text .= " } x ".$exit_count;
    }
    $depth -= $exit_count;
    $depth = 0 if ( $depth < 0 );
    if ( ( @$depths == 0 ) ||
	 ( $depths->[$depth]->{called_fn} ne $called_fn ) ||
	 ( $depths->[$depth]->{call_site} ne $call_site ) ) {
      $text .= " (from ".$called_fn_name." to ".$call_site_location.")";
    }
    splice ( @$depths, $depth );
    my $indent = "  " x $depth;
    print substr ( $indent.$text, 1 )."\n";
  }
}

# Clean up addr2line
close $addr2line_in;
close $addr2line_out;
waitpid ( $addr2line_pid, 0 );
