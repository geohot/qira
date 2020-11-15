#!/usr/bin/perl -w

use strict;
use warnings;

use constant WARNING_SIZE => 512;

my $symtab = {};

# Scan output of "objdump -w -t bin/blib.a" and build up symbol table
#
my $object;
while ( <> ) {
  chomp;
  if ( /^In archive/ ) {
    # Do nothing
  } elsif ( /^$/ ) {
    # Do nothing
  } elsif ( /^(\S+\.o):\s+file format/ ) {
    $object = $1;
  } elsif ( /^SYMBOL TABLE:/ ) {
    # Do nothing
  } elsif ( /^([0-9a-fA-F]+)\s(l|g|\s)......\s(\S+)\s+([0-9a-fA-F]+)\s+(\S+)$/ ) {
    my $value = $1;
    my $scope = $2;
    my $section = $3;
    my $size = $4;
    my $symbol = $5;
    $symtab->{$object}->{$symbol} = {
      global	=> ( $scope ne "l" ),
      section	=> ( $section eq "*UND*" ? undef : $section ),
      value	=> ( $value ? hex ( $value ) : 0 ),
      size	=> ( $size ? hex ( $size ) : 0 ),
    };
  } else {
    die "Unrecognized line \"$_\"";
  }
}

# Add symbols that we know will be generated or required by the linker
#
foreach my $object ( keys %$symtab ) {
  my $obj_symbol = "obj_$object";
  $obj_symbol =~ s/\.o$//;
  $obj_symbol =~ s/\W/_/g;
  $symtab->{LINKER}->{$obj_symbol} = {
    global	=> 1,
    section	=> undef,
    value	=> 0,
    size	=> 0,
  };
}
foreach my $link_sym qw ( __prefix _prefix _prefix_load_offset
			  _prefix_size _prefix_progbits_size _prefix_size_pgh
			  __text16 _text16 _text16_load_offset
			  _text16_size _text16_progbits_size _text16_size_pgh
			  __data16 _data16 _data16_load_offset
			  _data16_size _data16_progbits_size _data16_size_pgh
			  __text _text __data _data _textdata_load_offset
			  _textdata_size _textdata_progbits_size
			  __rodata __bss _end
			  _payload_offset _max_align
			  _load_size _load_size_pgh _load_size_sect
			  pci_vendor_id pci_device_id ) {
  $symtab->{LINKER}->{$link_sym} = {
    global	=> 1,
    section	=> '*ABS*',
    value	=> 0,
    size	=> 0,
  };
}

# Add symbols that we know will be used by the debug system
#
foreach my $debug_sym qw ( dbg_autocolourise dbg_decolourise
			   dbg_hex_dump_da ) {
  $symtab->{DEBUG}->{$debug_sym} = {
    global	=> 1,
    section	=> undef,
    value	=> 0,
    size	=> 0,
  };
}

# Build up requires, provides and shares symbol tables for global
# symbols
#
my $globals = {};
while ( ( my $object, my $symbols ) = each %$symtab ) {
  while ( ( my $symbol, my $info ) = each %$symbols ) {
    if ( $info->{global} ) {
      my $category;
      if ( ! defined $info->{section} ) {
	$category = "requires";
      } elsif ( $info->{section} eq "*COM*" ) {
	$category = "shares";
      } else {
	$category = "provides";
      }
      $globals->{$symbol}->{$category}->{$object} = 1;
    }
  }
}

# Check for multiply defined, never-defined and unused global symbols
#
my $problems = {};
while ( ( my $symbol, my $info ) = each %$globals ) {
  my @provides = keys %{$info->{provides}};
  my @requires = keys %{$info->{requires}};
  my @shares = keys %{$info->{shares}};

  if ( ( @provides == 0 ) && ( @shares == 1 ) ) {
    # A symbol "shared" by just a single file is actually being
    # provided by that file; it just doesn't have an initialiser.
    @provides = @shares;
    @shares = ();
  }

  if ( ( @requires > 0 ) && ( @provides == 0 ) && ( @shares == 0 ) ) {
    # No object provides this symbol, but some objects require it.
    $problems->{$_}->{nonexistent}->{$symbol} = 1 foreach @requires;
  }

  if ( ( @requires == 0 ) && ( @provides > 0 ) ) {
    # No object requires this symbol, but some objects provide it.
    foreach my $provide ( @provides ) {
      if ( $provide eq "LINKER" ) {
	# Linker-provided symbols are exempt from this check.
      } elsif ( $symtab->{$provide}->{$symbol}->{section} =~ /^\.tbl\./ ) {
	# Linker tables are exempt from this check.
      } else {
	$problems->{$provide}->{unused}->{$symbol} = 1;
      }
    }
  }

  if ( ( @shares > 0 ) && ( @provides > 0 ) ) {
    # A shared symbol is being initialised by an object
    $problems->{$_}->{shared}->{$symbol} = 1 foreach @provides;
  }

  if ( @provides > 1 ) {
    # A non-shared symbol is defined in multiple objects
    $problems->{$_}->{multiples}->{$symbol} = 1 foreach @provides;
  }
}

# Check for excessively large local symbols.  Text and rodata symbols
# are exempt from this check
#
while ( ( my $object, my $symbols ) = each %$symtab ) {
  while ( ( my $symbol, my $info ) = each %$symbols ) {
    if ( ( ! $info->{global} ) &&
	 ( ( defined $info->{section} ) &&
	   ! ( $info->{section} =~ /^(\.text|\.rodata)/ ) ) &&
	 ( $info->{size} >= WARNING_SIZE ) ) {
      $problems->{$object}->{large}->{$symbol} = 1;
    }
  }
}

# Print out error messages
#
my $errors = 0;
my $warnings = 0;
foreach my $object ( sort keys %$problems ) {
  my @nonexistent = sort keys %{$problems->{$object}->{nonexistent}};
  my @multiples = sort keys %{$problems->{$object}->{multiples}};
  my @unused = sort keys %{$problems->{$object}->{unused}};
  my @shared = sort keys %{$problems->{$object}->{shared}};
  my @large = sort keys %{$problems->{$object}->{large}};

  print "WARN $object provides unused symbol $_\n" foreach @unused;
  $warnings += @unused;
  print "WARN $object has large static symbol $_\n" foreach @large;
  $warnings += @large;
  print "ERR  $object requires non-existent symbol $_\n" foreach @nonexistent;
  $errors += @nonexistent;
  foreach my $symbol ( @multiples ) {
    my @other_objects = sort grep { $_ ne $object }
		        keys %{$globals->{$symbol}->{provides}};
    print "ERR  $object provides symbol $symbol"
	." (also provided by @other_objects)\n";
  }
  $errors += @multiples;
  print "ERR  $object misuses shared symbol $_\n" foreach @shared;
}

print "$errors error(s), $warnings warning(s)\n";
exit ( $errors ? 1 : 0 );
