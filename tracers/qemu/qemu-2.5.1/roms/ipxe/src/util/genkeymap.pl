#!/usr/bin/perl -w
#
# Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

genkeymap.pl

=head1 SYNOPSIS

genkeymap.pl [options] <keymap name>

Options:

    -f,--from=<name>	Set BIOS keymap name (default "us")
    -h,--help		Display brief help message
    -v,--verbose	Increase verbosity
    -q,--quiet		Decrease verbosity

=cut

# With reference to:
#
# http://gunnarwrobel.de/wiki/Linux-and-the-keyboard.html

use Getopt::Long;
use Pod::Usage;
use strict;
use warnings;

use constant BIOS_KEYMAP => "us";
use constant BKEYMAP_MAGIC => "bkeymap";
use constant MAX_NR_KEYMAPS => 256;
use constant NR_KEYS => 128;
use constant KG_SHIFT => 0;
use constant KG_ALTGR => 1;
use constant KG_CTRL => 2;
use constant KG_ALT => 3;
use constant KG_SHIFTL => 4;
use constant KG_KANASHIFT => 4;
use constant KG_SHIFTR => 5;
use constant KG_CTRLL => 6;
use constant KG_CTRLR => 7;
use constant KG_CAPSSHIFT => 8;
use constant KT_LATIN => 0;
use constant KT_FN => 1;
use constant KT_SPEC => 2;
use constant KT_PAD => 3;
use constant KT_DEAD => 4;
use constant KT_CONS => 5;
use constant KT_CUR => 6;
use constant KT_SHIFT => 7;
use constant KT_META => 8;
use constant KT_ASCII => 9;
use constant KT_LOCK => 10;
use constant KT_LETTER => 11;
use constant KT_SLOCK => 12;
use constant KT_SPKUP => 14;

my $verbosity = 1;
my $from_name = BIOS_KEYMAP;

# Read named keymaps using "loadkeys -b"
#
sub read_keymaps {
  my $name = shift;
  my $keymaps = [];

  # Generate binary keymap
  open my $pipe, "-|", "loadkeys", "-b", $name
      or die "Could not load keymap \"".$name."\": $!\n";

  # Check magic
  read $pipe, my $magic, length BKEYMAP_MAGIC
      or die "Could not read from \"".$name."\": $!\n";
  die "Bad magic value from \"".$name."\"\n"
      unless $magic eq BKEYMAP_MAGIC;

  # Read list of included keymaps
  read $pipe, my $included, MAX_NR_KEYMAPS
      or die "Could not read from \"".$name."\": $!\n";
  my @included = unpack ( "C*", $included );
  die "Missing or truncated keymap list from \"".$name."\"\n"
      unless @included == MAX_NR_KEYMAPS;

  # Read each keymap in turn
  for ( my $keymap = 0 ; $keymap < MAX_NR_KEYMAPS ; $keymap++ ) {
    if ( $included[$keymap] ) {
      read $pipe, my $keysyms, ( NR_KEYS * 2 )
	  or die "Could not read from \"".$name."\": $!\n";
      my @keysyms = unpack ( "S*", $keysyms );
      die "Missing or truncated keymap ".$keymap." from \"".$name."\"\n"
	  unless @keysyms == NR_KEYS;
      push @$keymaps, \@keysyms;
    } else {
      push @$keymaps, undef;
    }
  }

  close $pipe;
  return $keymaps;
}

# Translate keysym value to ASCII
#
sub keysym_to_ascii {
  my $keysym = shift;

  # Non-existent keysyms have no ASCII equivalent
  return unless $keysym;

  # Sanity check
  if ( $keysym & 0xf000 ) {
    warn "Unexpected keysym ".sprintf ( "0x%04x", $keysym )."\n";
    return;
  }

  # Extract type and value
  my $type = ( $keysym >> 8 );
  my $value = ( $keysym & 0xff );

  # Non-simple types have no ASCII equivalent
  return unless ( ( $type == KT_LATIN ) || ( $type == KT_ASCII ) ||
		  ( $type == KT_LETTER ) );

  # High-bit-set characters cannot be generated on a US keyboard
  return if $value & 0x80;

  return $value;
}

# Translate ASCII to descriptive name
#
sub ascii_to_name {
  my $ascii = shift;

  if ( $ascii == 0x5c ) {
    return "'\\\\'";
  } elsif ( $ascii == 0x27 ) {
    return "'\\\''";
  } elsif ( ( $ascii >= 0x20 ) && ( $ascii <= 0x7e ) ) {
    return sprintf ( "'%c'", $ascii );
  } elsif ( $ascii <= 0x1a ) {
    return sprintf ( "Ctrl-%c", ( 0x40 + $ascii ) );
  } else {
    return sprintf ( "0x%02x", $ascii );
  }
}

# Produce translation table between two keymaps
#
sub translate_keymaps {
  my $from = shift;
  my $to = shift;
  my $map = {};

  foreach my $keymap ( 0, 1 << KG_SHIFT, 1 << KG_CTRL ) {
    for ( my $keycode = 0 ; $keycode < NR_KEYS ; $keycode++ ) {
      my $from_ascii = keysym_to_ascii ( $from->[$keymap]->[$keycode] )
	  or next;
      my $to_ascii = keysym_to_ascii ( $to->[$keymap]->[$keycode] )
	  or next;
      my $new_map = ( ! exists $map->{$from_ascii} );
      my $update_map =
	  ( $new_map || ( $keycode < $map->{$from_ascii}->{keycode} ) );
      if ( ( $verbosity > 1 ) &&
	   ( ( $from_ascii != $to_ascii ) ||
	     ( $update_map && ! $new_map ) ) ) {
	printf STDERR "In keymap %d: %s => %s%s\n", $keymap,
	       ascii_to_name ( $from_ascii ), ascii_to_name ( $to_ascii ),
	       ( $update_map ? ( $new_map ? "" : " (override)" )
			     : " (ignored)" );
      }
      if ( $update_map ) {
	$map->{$from_ascii} = {
	  to_ascii => $to_ascii,
	  keycode => $keycode,
	};
      }
    }
  }
  return { map { $_ => $map->{$_}->{to_ascii} } keys %$map };
}

# Parse command-line options
Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions (
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
  'from|f=s' => sub { shift; $from_name = shift; },
  'help|h' => sub { pod2usage ( 1 ); },
) or die "Could not parse command-line options\n";
pod2usage ( 1 ) unless @ARGV == 1;
my $to_name = shift;

# Read and translate keymaps
my $from = read_keymaps ( $from_name );
my $to = read_keymaps ( $to_name );
my $map = translate_keymaps ( $from, $to );

# Generate output
( my $to_name_c = $to_name ) =~ s/\W/_/g;
printf "/** \@file\n";
printf " *\n";
printf " * \"".$to_name."\" keyboard mapping\n";
printf " *\n";
printf " * This file is automatically generated; do not edit\n";
printf " *\n";
printf " */\n";
printf "\n";
printf "FILE_LICENCE ( PUBLIC_DOMAIN );\n";
printf "\n";
printf "#include <ipxe/keymap.h>\n";
printf "\n";
printf "/** \"".$to_name."\" keyboard mapping */\n";
printf "struct key_mapping ".$to_name_c."_mapping[] __keymap = {\n";
foreach my $from_sym ( sort { $a <=> $b } keys %$map ) {
  my $to_sym = $map->{$from_sym};
  next if $from_sym == $to_sym;
  printf "\t{ 0x%02x, 0x%02x },\t/* %s => %s */\n", $from_sym, $to_sym,
	 ascii_to_name ( $from_sym ), ascii_to_name ( $to_sym );
}
printf "};\n";
