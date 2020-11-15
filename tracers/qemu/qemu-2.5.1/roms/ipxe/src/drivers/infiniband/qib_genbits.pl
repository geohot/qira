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

my $offsets = {};
my $defaults = {};
my $structures = {};
my $structure = "";

while ( <> ) {
  chomp;
  if ( /^\#define (\S+)_OFFS (\S+)$/ ) {
    $structure = $1;
    $offsets->{$structure} = $2;
  } elsif ( /^\#define ${structure}_DEF (\S+)$/ ) {
    $defaults->{$structure} = $1;
  } elsif ( /^\#define ${structure}_(\S+)_LSB (\S+)$/ ) {
    $structures->{$structure}->{$1}->{LSB} = $2;
  } elsif ( /^\#define ${structure}_(\S+)_MSB (\S+)$/ ) {
    $structures->{$structure}->{$1}->{MSB} = $2;
  } elsif ( /^\#define ${structure}_(\S+)_RMASK (\S+)$/ ) {
    $structures->{$structure}->{$1}->{RMASK} = $2;
  } elsif ( /^\s*$/ ) {
    # Do nothing
  } else {
    print "$_\n";
  }
}

my $data = [ map { { name => $_, offset => $offsets->{$_},
		     default => $defaults->{$_} }; }
	     sort { hex ( $offsets->{$a} ) <=> hex ( $offsets->{$b} ) }
	     keys %$offsets ];

foreach my $datum ( @$data ) {
  next unless exists $structures->{$datum->{name}};
  $structure = $structures->{$datum->{name}};
  my $fields = [ map { { name => $_, lsb => $structure->{$_}->{LSB},
			 msb => $structure->{$_}->{MSB},
			 rmask => $structure->{$_}->{RMASK} }; }
		 sort { hex ( $structure->{$a}->{LSB} ) <=>
			    hex ( $structure->{$b}->{LSB} ) }
		 keys %$structure ];
  $datum->{fields} = $fields;
}

print "\n/* This file has been further processed by $0 */\n\n";
print "FILE_LICENCE ( GPL2_ONLY );\n\n";

foreach my $datum ( @$data ) {
  printf "#define %s_offset 0x%08xUL\n",
      $datum->{name}, hex ( $datum->{offset} );
  if ( exists $datum->{fields} ) {
    my $lsb = 0;
    my $reserved_idx = 0;
    printf "struct %s_pb {\n", $datum->{name};
    foreach my $field ( @{$datum->{fields}} ) {
      my $pad_width = ( hex ( $field->{lsb} ) - $lsb );
      die "Inconsistent LSB/RMASK in $datum->{name} before $field->{name}\n"
	  if $pad_width < 0;
      printf "\tpseudo_bit_t _unused_%u[%u];\n", $reserved_idx++, $pad_width
	  if $pad_width;
      $lsb += $pad_width;
      # Damn Perl can't cope with 64-bit hex constants
      my $width = 0;
      die "Missing RMASK in $datum->{name}.$field->{name}\n"
	  unless defined $field->{rmask};
      my $rmask = $field->{rmask};
      while ( $rmask =~ /^(0x.+)f$/i ) {
	$width += 4;
	$rmask = $1;
      }
      $rmask = hex ( $rmask );
      while ( $rmask ) {
	$width++;
	$rmask >>= 1;
      }
      if ( defined $field->{msb} ) {
	my $msb_width = ( hex ( $field->{msb} ) - $lsb + 1 );
	$width ||= $msb_width;
	die "Inconsistent LSB/MSB/RMASK in $datum->{name}.$field->{name}\n"
	    unless $width == $msb_width;
      }
      printf "\tpseudo_bit_t %s[%u];\n", $field->{name}, $width;
      $lsb += $width;
    }
    my $pad_width = ( 64 - $lsb );
    die "Inconsistent LSB/RMASK in $datum->{name} final field\n"
	if $pad_width < 0;
    printf "\tpseudo_bit_t _unused_%u[%u];\n", $reserved_idx++, $pad_width
	if $pad_width;
    printf "};\n";
    printf "struct %s {\n\tPSEUDO_BIT_STRUCT ( struct %s_pb );\n};\n",
	$datum->{name}, $datum->{name};
  }
  printf "/* Default value: %s */\n", $datum->{default}
      if defined $datum->{default};
  print "\n";
}
