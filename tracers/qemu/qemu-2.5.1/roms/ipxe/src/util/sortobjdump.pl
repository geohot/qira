#!/usr/bin/perl -w

use strict;
use warnings;

# Sort the symbol table portion of the output of objdump -ht by
# section, then by symbol value, then by size.  Used to enhance the
# linker maps produced by "make bin/%.map" by also showing the values
# of all non-global symbols.

my %section_idx = ( "*ABS*" => ".", "*UND*" => "_" );
my %lines;
while ( <> ) {
  if ( /^\s+(\d+)\s+([\.\*]\S+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]/ ) {
    # It's a header line containing a section definition; extract the
    # section index and store it.  Also print the header line.
    print;
    ( my $index, my $section ) = ( $1, $2 );
    $section_idx{$section} = sprintf ( "%02d", $index );
  } elsif ( /^([0-9a-fA-F]+)\s.*?\s([\.\*]\S+)\s+([0-9a-fA-F]+)\s+(\S+)/ ) {
    # It's a symbol line - store it in the hash, indexed by
    # "<section_index>:<value>:<size>:<end_tag>".  <end_tag> is "0" if
    # the symbol name is of the form xxx_end, "1" otherwise; this is
    # done so that table end markers show up before any other symbols
    # with the same value.
    ( my $value, my $section, my $size, my $name ) = ( $1, $2, $3, $4 );
    die "Unrecognised section \"$section\"\n"
	unless exists $section_idx{$section};
    my $section_idx = $section_idx{$section};
    my $end = ( $name =~ /_end$/ ) ? "0" : "1";
    my $key = $section_idx.":".$value.":".$size.":".$end;
    $lines{$key} ||= '';
    $lines{$key} .= $_;
  } else {
    # It's a generic header line: just print it.
    print;
  }
}

print $lines{$_} foreach sort keys %lines;
