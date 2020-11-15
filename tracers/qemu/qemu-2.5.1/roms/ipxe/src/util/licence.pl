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
use Getopt::Long;

# List of licences we can handle
my $known_licences = {
  gpl_any => {
    desc => "GPL (any version)",
    can_subsume => {
      public_domain => 1,
      bsd3 => 1,
      bsd2 => 1,
      mit  => 1,
      isc  => 1,
    },
  },
  gpl2_or_later => {
    desc => "GPL version 2 (or, at your option, any later version)",
    can_subsume => {
      gpl_any => 1,
      gpl2_or_later_or_ubdl => 1,
      public_domain => 1,
      bsd3 => 1,
      bsd2 => 1,
      mit  => 1,
      isc  => 1,
    },
  },
  gpl2_only => {
    desc => "GPL version 2 only",
    can_subsume => {
      gpl_any => 1,
      gpl2_or_later => 1,
      gpl2_or_later_or_ubdl => 1,
      public_domain => 1,
      bsd3 => 1,
      bsd2 => 1,
      mit  => 1,
      isc  => 1,
    },
  },
  gpl2_or_later_or_ubdl => {
    desc => ( "GPL version 2 (or, at your option, any later version) or ".
	      "Unmodified Binary Distribution Licence" ),
    can_subsume => {
      public_domain => 1,
      bsd3 => 1,
      bsd2 => 1,
      mit => 1,
      isc => 1,
    },
  },
  public_domain => {
    desc => "Public Domain",
    can_subsume => {},
  },
  bsd4 => {
    desc => "BSD Licence (with advertising clause)",
    can_subsume => {
      public_domain => 1,
      bsd3 => 1,
      bsd2 => 1,
      mit  => 1,
      isc  => 1,
    },
  },
  bsd3 => {
    desc => "BSD Licence (without advertising clause)",
    can_subsume => {
      public_domain => 1,
      bsd2 => 1,
      mit  => 1,
      isc  => 1,
    },
  },
  bsd2 => {
    desc => "BSD Licence (without advertising or endorsement clauses)",
    can_subsume => {
      public_domain => 1,
      mit  => 1,
      isc  => 1,
    },
  },
  mit => {
    desc => "MIT/X11/Xorg Licence",
    can_subsume => {
      public_domain => 1,
      isc => 1,
    },
  },
  isc => {
    desc => "ISC Licence",
    can_subsume => {
      public_domain => 1,
    },
  },
};

# Parse command-line options
my $verbosity = 1;
Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions (
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
) or die "Could not parse command-line options\n";

# Parse licence list from command line
my $licences = {};
foreach my $licence ( @ARGV ) {
  die "Unknown licence \"$licence\"\n"
      unless exists $known_licences->{$licence};
  $licences->{$licence} = $known_licences->{$licence};
}
die "No licences specified\n" unless %$licences;

# Dump licence list
if ( $verbosity >= 1 ) {
  print "The following licences appear within this file:\n";
  foreach my $licence ( keys %$licences ) {
    print "  ".$licences->{$licence}->{desc}."\n"
  }
}

# Apply licence compatibilities to reduce to a single resulting licence
foreach my $licence ( keys %$licences ) {
  # Skip already-deleted licences
  next unless exists $licences->{$licence};
  # Subsume any subsumable licences
  foreach my $can_subsume ( keys %{$licences->{$licence}->{can_subsume}} ) {
    if ( exists $licences->{$can_subsume} ) {
      print $licences->{$licence}->{desc}." subsumes ".
	  $licences->{$can_subsume}->{desc}."\n"
	  if $verbosity >= 1;
      delete $licences->{$can_subsume};
    }
  }
}

# Print resulting licence
die "Cannot reduce to a single resulting licence!\n"
    if ( keys %$licences ) != 1;
( my $licence ) = keys %$licences;
print "The overall licence for this file is:\n  " if $verbosity >= 1;
print $licences->{$licence}->{desc}."\n";
