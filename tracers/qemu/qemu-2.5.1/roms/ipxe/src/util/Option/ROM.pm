package Option::ROM;

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

=head1 NAME

Option::ROM - Option ROM manipulation

=head1 SYNOPSIS

    use Option::ROM;

    # Load a ROM image
    my $rom = new Option::ROM;
    $rom->load ( "rtl8139.rom" );

    # Modify the PCI device ID
    $rom->pci_header->{device_id} = 0x1234;
    $rom->fix_checksum();

    # Write ROM image out to a new file
    $rom->save ( "rtl8139-modified.rom" );

=head1 DESCRIPTION

C<Option::ROM> provides a mechanism for manipulating Option ROM
images.

=head1 METHODS

=cut

##############################################################################
#
# Option::ROM::Fields
#
##############################################################################

package Option::ROM::Fields;

use strict;
use warnings;
use Carp;
use bytes;

sub TIEHASH {
  my $class = shift;
  my $self = shift;

  bless $self, $class;
  return $self;
}

sub FETCH {
  my $self = shift;
  my $key = shift;

  return undef unless $self->EXISTS ( $key );
  my $raw = substr ( ${$self->{data}},
		     ( $self->{offset} + $self->{fields}->{$key}->{offset} ),
		     $self->{fields}->{$key}->{length} );
  my $unpack = ( ref $self->{fields}->{$key}->{unpack} ?
		 $self->{fields}->{$key}->{unpack} :
		 sub { unpack ( $self->{fields}->{$key}->{pack}, shift ); } );
  return &$unpack ( $raw );
}

sub STORE {
  my $self = shift;
  my $key = shift;
  my $value = shift;

  croak "Nonexistent field \"$key\"" unless $self->EXISTS ( $key );
  my $pack = ( ref $self->{fields}->{$key}->{pack} ?
	       $self->{fields}->{$key}->{pack} :
	       sub { pack ( $self->{fields}->{$key}->{pack}, shift ); } );
  my $raw = &$pack ( $value );
  substr ( ${$self->{data}},
	   ( $self->{offset} + $self->{fields}->{$key}->{offset} ),
	   $self->{fields}->{$key}->{length} ) = $raw;
}

sub DELETE {
  my $self = shift;
  my $key = shift;

  $self->STORE ( $key, 0 );
}

sub CLEAR {
  my $self = shift;

  foreach my $key ( keys %{$self->{fields}} ) {
    $self->DELETE ( $key );
  }
}

sub EXISTS {
  my $self = shift;
  my $key = shift;

  return ( exists $self->{fields}->{$key} &&
	   ( ( $self->{fields}->{$key}->{offset} +
	       $self->{fields}->{$key}->{length} ) <= $self->{length} ) );
}

sub FIRSTKEY {
  my $self = shift;

  keys %{$self->{fields}};
  return each %{$self->{fields}};
}

sub NEXTKEY {
  my $self = shift;
  my $lastkey = shift;

  return each %{$self->{fields}};
}

sub SCALAR {
  my $self = shift;

  return 1;
}

sub UNTIE {
  my $self = shift;
}

sub DESTROY {
  my $self = shift;
}

sub checksum {
  my $self = shift;

  my $raw = substr ( ${$self->{data}}, $self->{offset}, $self->{length} );
  return unpack ( "%8C*", $raw );
}

##############################################################################
#
# Option::ROM
#
##############################################################################

package Option::ROM;

use strict;
use warnings;
use Carp;
use bytes;
use Exporter 'import';

use constant ROM_SIGNATURE => 0xaa55;
use constant PCI_SIGNATURE => 'PCIR';
use constant PCI_LAST_IMAGE => 0x80;
use constant PNP_SIGNATURE => '$PnP';
use constant IPXE_SIGNATURE => 'iPXE';

our @EXPORT_OK = qw ( ROM_SIGNATURE PCI_SIGNATURE PCI_LAST_IMAGE
		      PNP_SIGNATURE IPXE_SIGNATURE );
our %EXPORT_TAGS = ( all => [ @EXPORT_OK ] );

use constant JMP_SHORT => 0xeb;
use constant JMP_NEAR => 0xe9;
use constant CALL_NEAR => 0xe8;

sub pack_init {
  my $dest = shift;

  # Always create a near jump; it's simpler
  if ( $dest ) {
    return pack ( "CS", JMP_NEAR, ( $dest - 6 ) );
  } else {
    return pack ( "CS", 0, 0 );
  }
}

sub unpack_init {
  my $instr = shift;

  # Accept both short and near jumps
  my $jump = unpack ( "C", $instr );
  if ( $jump == JMP_SHORT ) {
    my $offset = unpack ( "xC", $instr );
    return ( $offset + 5 );
  } elsif ( $jump == JMP_NEAR ) {
    my $offset = unpack ( "xS", $instr );
    return ( $offset + 6 );
  } elsif ( $jump == CALL_NEAR ) {
    my $offset = unpack ( "xS", $instr );
    return ( $offset + 6 );
  } elsif ( $jump == 0 ) {
    return 0;
  } else {
    croak "Unrecognised jump instruction in init vector\n";
  }
}

=pod

=item C<< new () >>

Construct a new C<Option::ROM> object.

=cut

sub new {
  my $class = shift;

  my $hash = {};
  tie %$hash, "Option::ROM::Fields", {
    data => undef,
    offset => 0x00,
    length => 0x20,
    fields => {
      signature =>	{ offset => 0x00, length => 0x02, pack => "S" },
      length =>		{ offset => 0x02, length => 0x01, pack => "C" },
      # "init" is part of a jump instruction
      init =>		{ offset => 0x03, length => 0x03,
			  pack => \&pack_init, unpack => \&unpack_init },
      checksum =>	{ offset => 0x06, length => 0x01, pack => "C" },
      ipxe_header =>	{ offset => 0x10, length => 0x02, pack => "S" },
      bofm_header =>	{ offset => 0x14, length => 0x02, pack => "S" },
      undi_header =>	{ offset => 0x16, length => 0x02, pack => "S" },
      pci_header =>	{ offset => 0x18, length => 0x02, pack => "S" },
      pnp_header =>	{ offset => 0x1a, length => 0x02, pack => "S" },
    },
  };
  bless $hash, $class;
  return $hash;
}

=pod

=item C<< set ( $data ) >>

Set option ROM contents.

=cut

sub set {
  my $hash = shift;
  my $self = tied(%$hash);
  my $data = shift;

  # Store data
  $self->{data} = \$data;

  # Split out any data belonging to the next image
  delete $self->{next_image};
  my $pci_header = $hash->pci_header();
  if ( ( defined $pci_header ) &&
       ( ! ( $pci_header->{last_image} & PCI_LAST_IMAGE ) ) ) {
    my $length = ( $pci_header->{image_length} * 512 );
    my $remainder = substr ( $data, $length );
    $data = substr ( $data, 0, $length );
    $self->{next_image} = new Option::ROM;
    $self->{next_image}->set ( $remainder );
  }
}

=pod

=item C<< get () >>

Get option ROM contents.

=cut

sub get {
  my $hash = shift;
  my $self = tied(%$hash);

  my $data = ${$self->{data}};
  $data .= $self->{next_image}->get() if $self->{next_image};
  return $data;
}

=pod

=item C<< load ( $filename ) >>

Load option ROM contents from the file C<$filename>.

=cut

sub load {
  my $hash = shift;
  my $self = tied(%$hash);
  my $filename = shift;

  $self->{filename} = $filename;

  open my $fh, "<$filename"
      or croak "Cannot open $filename for reading: $!";
  read $fh, my $data, -s $fh;
  $hash->set ( $data );
  close $fh;
}

=pod

=item C<< save ( [ $filename ] ) >>

Write the ROM data back out to the file C<$filename>.  If C<$filename>
is omitted, the file used in the call to C<load()> will be used.

=cut

sub save {
  my $hash = shift;
  my $self = tied(%$hash);
  my $filename = shift;

  $filename ||= $self->{filename};

  open my $fh, ">$filename"
      or croak "Cannot open $filename for writing: $!";
  my $data = $hash->get();
  print $fh $data;
  close $fh;
}

=pod

=item C<< length () >>

Length of option ROM data.  This is the length of the file, not the
length from the ROM header length field.

=cut

sub length {
  my $hash = shift;
  my $self = tied(%$hash);

  return length ${$self->{data}};
}

=pod

=item C<< pci_header () >>

Return a C<Option::ROM::PCI> object representing the ROM's PCI header,
if present.

=cut

sub pci_header {
  my $hash = shift;
  my $self = tied(%$hash);

  my $offset = $hash->{pci_header};
  return undef unless $offset != 0;

  return Option::ROM::PCI->new ( $self->{data}, $offset );
}

=pod

=item C<< pnp_header () >>

Return a C<Option::ROM::PnP> object representing the ROM's PnP header,
if present.

=cut

sub pnp_header {
  my $hash = shift;
  my $self = tied(%$hash);

  my $offset = $hash->{pnp_header};
  return undef unless $offset != 0;

  return Option::ROM::PnP->new ( $self->{data}, $offset );
}

=pod

=item C<< undi_header () >>

Return a C<Option::ROM::UNDI> object representing the ROM's UNDI header,
if present.

=cut

sub undi_header {
  my $hash = shift;
  my $self = tied(%$hash);

  my $offset = $hash->{undi_header};
  return undef unless $offset != 0;

  return Option::ROM::UNDI->new ( $self->{data}, $offset );
}

=pod

=item C<< ipxe_header () >>

Return a C<Option::ROM::iPXE> object representing the ROM's iPXE
header, if present.

=cut

sub ipxe_header {
  my $hash = shift;
  my $self = tied(%$hash);

  my $offset = $hash->{ipxe_header};
  return undef unless $offset != 0;

  return Option::ROM::iPXE->new ( $self->{data}, $offset );
}

=pod

=item C<< next_image () >>

Return a C<Option::ROM> object representing the next image within the
ROM, if present.

=cut

sub next_image {
  my $hash = shift;
  my $self = tied(%$hash);

  return $self->{next_image};
}

=pod

=item C<< checksum () >>

Calculate the byte checksum of the ROM.

=cut

sub checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  my $raw = substr ( ${$self->{data}}, 0, ( $hash->{length} * 512 ) );
  return unpack ( "%8C*", $raw );
}

=pod

=item C<< fix_checksum () >>

Fix the byte checksum of the ROM.

=cut

sub fix_checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  $hash->{checksum} = ( ( $hash->{checksum} - $hash->checksum() ) & 0xff );
}

##############################################################################
#
# Option::ROM::PCI
#
##############################################################################

package Option::ROM::PCI;

use strict;
use warnings;
use Carp;
use bytes;

sub new {
  my $class = shift;
  my $data = shift;
  my $offset = shift;

  my $hash = {};
  tie %$hash, "Option::ROM::Fields", {
    data => $data,
    offset => $offset,
    length => 0x0c,
    fields => {
      signature =>	{ offset => 0x00, length => 0x04, pack => "a4" },
      vendor_id =>	{ offset => 0x04, length => 0x02, pack => "S" },
      device_id =>	{ offset => 0x06, length => 0x02, pack => "S" },
      device_list =>	{ offset => 0x08, length => 0x02, pack => "S" },
      struct_length =>	{ offset => 0x0a, length => 0x02, pack => "S" },
      struct_revision =>{ offset => 0x0c, length => 0x01, pack => "C" },
      base_class => 	{ offset => 0x0d, length => 0x01, pack => "C" },
      sub_class => 	{ offset => 0x0e, length => 0x01, pack => "C" },
      prog_intf => 	{ offset => 0x0f, length => 0x01, pack => "C" },
      image_length =>	{ offset => 0x10, length => 0x02, pack => "S" },
      revision =>	{ offset => 0x12, length => 0x02, pack => "S" },
      code_type => 	{ offset => 0x14, length => 0x01, pack => "C" },
      last_image => 	{ offset => 0x15, length => 0x01, pack => "C" },
      runtime_length =>	{ offset => 0x16, length => 0x02, pack => "S" },
      conf_header =>	{ offset => 0x18, length => 0x02, pack => "S" },
      clp_entry =>	{ offset => 0x1a, length => 0x02, pack => "S" },
    },
  };
  bless $hash, $class;

  # Retrieve true length of structure
  my $self = tied ( %$hash );
  $self->{length} = $hash->{struct_length};

  return $hash;  
}

sub device_list {
  my $hash = shift;
  my $self = tied(%$hash);

  my $device_list = $hash->{device_list};
  return undef unless $device_list;

  my @ids;
  my $offset = ( $self->{offset} + $device_list );
  while ( 1 ) {
    my $raw = substr ( ${$self->{data}}, $offset, 2 );
    my $id = unpack ( "S", $raw );
    last unless $id;
    push @ids, $id;
    $offset += 2;
  }

  return @ids;
}

##############################################################################
#
# Option::ROM::PnP
#
##############################################################################

package Option::ROM::PnP;

use strict;
use warnings;
use Carp;
use bytes;

sub new {
  my $class = shift;
  my $data = shift;
  my $offset = shift;

  my $hash = {};
  tie %$hash, "Option::ROM::Fields", {
    data => $data,
    offset => $offset,
    length => 0x06,
    fields => {
      signature =>	{ offset => 0x00, length => 0x04, pack => "a4" },
      struct_revision =>{ offset => 0x04, length => 0x01, pack => "C" },
      struct_length =>	{ offset => 0x05, length => 0x01, pack => "C" },
      checksum =>	{ offset => 0x09, length => 0x01, pack => "C" },
      manufacturer =>	{ offset => 0x0e, length => 0x02, pack => "S" },
      product =>	{ offset => 0x10, length => 0x02, pack => "S" },
      bcv =>		{ offset => 0x16, length => 0x02, pack => "S" },
      bdv =>		{ offset => 0x18, length => 0x02, pack => "S" },
      bev =>		{ offset => 0x1a, length => 0x02, pack => "S" },
    },
  };
  bless $hash, $class;

  # Retrieve true length of structure
  my $self = tied ( %$hash );
  $self->{length} = ( $hash->{struct_length} * 16 );

  return $hash;  
}

sub checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  return $self->checksum();
}

sub fix_checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  $hash->{checksum} = ( ( $hash->{checksum} - $hash->checksum() ) & 0xff );
}

sub manufacturer {
  my $hash = shift;
  my $self = tied(%$hash);

  my $manufacturer = $hash->{manufacturer};
  return undef unless $manufacturer;

  my $raw = substr ( ${$self->{data}}, $manufacturer );
  return unpack ( "Z*", $raw );
}

sub product {
  my $hash = shift;
  my $self = tied(%$hash);

  my $product = $hash->{product};
  return undef unless $product;

  my $raw = substr ( ${$self->{data}}, $product );
  return unpack ( "Z*", $raw );
}

##############################################################################
#
# Option::ROM::UNDI
#
##############################################################################

package Option::ROM::UNDI;

use strict;
use warnings;
use Carp;
use bytes;

sub new {
  my $class = shift;
  my $data = shift;
  my $offset = shift;

  my $hash = {};
  tie %$hash, "Option::ROM::Fields", {
    data => $data,
    offset => $offset,
    length => 0x16,
    fields => {
      signature =>	{ offset => 0x00, length => 0x04, pack => "a4" },
      struct_length =>	{ offset => 0x04, length => 0x01, pack => "C" },
      checksum =>	{ offset => 0x05, length => 0x01, pack => "C" },
      struct_revision =>{ offset => 0x06, length => 0x01, pack => "C" },
      version_revision =>{ offset => 0x07, length => 0x01, pack => "C" },
      version_minor =>	{ offset => 0x08, length => 0x01, pack => "C" },
      version_major =>	{ offset => 0x09, length => 0x01, pack => "C" },
      loader_entry =>	{ offset => 0x0a, length => 0x02, pack => "S" },
      stack_size =>	{ offset => 0x0c, length => 0x02, pack => "S" },
      data_size =>	{ offset => 0x0e, length => 0x02, pack => "S" },
      code_size =>	{ offset => 0x10, length => 0x02, pack => "S" },
      bus_type =>	{ offset => 0x12, length => 0x04, pack => "a4" },
    },
  };
  bless $hash, $class;

  # Retrieve true length of structure
  my $self = tied ( %$hash );
  $self->{length} = $hash->{struct_length};

  return $hash;
}

sub checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  return $self->checksum();
}

sub fix_checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  $hash->{checksum} = ( ( $hash->{checksum} - $hash->checksum() ) & 0xff );
}

##############################################################################
#
# Option::ROM::iPXE
#
##############################################################################

package Option::ROM::iPXE;

use strict;
use warnings;
use Carp;
use bytes;

sub new {
  my $class = shift;
  my $data = shift;
  my $offset = shift;

  my $hash = {};
  tie %$hash, "Option::ROM::Fields", {
    data => $data,
    offset => $offset,
    length => 0x06,
    fields => {
      signature =>	{ offset => 0x00, length => 0x04, pack => "a4" },
      struct_length =>	{ offset => 0x04, length => 0x01, pack => "C" },
      checksum =>	{ offset => 0x05, length => 0x01, pack => "C" },
      shrunk_length =>	{ offset => 0x06, length => 0x01, pack => "C" },
      build_id =>	{ offset => 0x08, length => 0x04, pack => "L" },
    },
  };
  bless $hash, $class;

  # Retrieve true length of structure
  my $self = tied ( %$hash );
  $self->{length} = $hash->{struct_length};

  return $hash;
}

sub checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  return $self->checksum();
}

sub fix_checksum {
  my $hash = shift;
  my $self = tied(%$hash);

  $hash->{checksum} = ( ( $hash->{checksum} - $hash->checksum() ) & 0xff );
}

1;
