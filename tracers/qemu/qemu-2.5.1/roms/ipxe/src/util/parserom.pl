#!/usr/bin/env perl
#
# Parse PCI_ROM and ISA_ROM entries from source file(s) specified as
# arguments and output the relevant Makefile rules to STDOUT.
#
# Originally based on portions of Ken Yap's genrules.pl. Completely
# rewritten by Robin Smidsrød to be more maintainable.

use strict;
use warnings;
use Getopt::Long;

# Parse command-line options
my @exclude_driver_classes = ();
my @exclude_drivers = ();
my $debug = 0;
my $help = 0;
GetOptions(
    "exclude-driver-class=s" => \@exclude_driver_classes,
    "exclude-driver=s"       => \@exclude_drivers,
    "debug"                  => \$debug,
    "help"                   => \$help,
);

# Convert exclution arrays to lookup tables
my $exclude_driver_class_map = { map { $_ => 1 } @exclude_driver_classes };
my $exclude_driver_map       = { map { $_ => 1 } @exclude_drivers        };

# Ensure STDOUT and STDERR are synchronized if debugging
if ( $debug ) {
    STDOUT->autoflush(1);
    STDERR->autoflush(1);
}

# Compile regular expressions here for slight performance boost
my %RE = (
    'parse_driver_class'    => qr{ drivers/ (\w+?) / }x,
    'parse_family'          => qr{^ (?:\./)? (.*) \..+? $}x,
    'find_rom_line'         => qr/^ \s* ( (PCI|ISA)_ROM \s* \( \s* (.*?) ) $/x,
    'extract_pci_id'        => qr/^ \s* 0x([0-9A-Fa-f]{4}) \s* ,? \s* (.*) $/x,
    'extract_quoted_string' => qr/^ \s* \" ([^\"]*?) \" \s* ,? \s* (.*) $/x,
);

# Show help if required arguments are missing or help was requested
show_usage_and_exit() if $help or @ARGV < 1;

# Process each source file specified
process_source_file($_) for @ARGV;

exit;

sub show_usage_and_exit {
    print STDERR <<"EOM";
Syntax: $0 [<options>] <source-file> [<source-file>]
Options:
    --exclude-driver-class Exclude specified driver classes
    --exclude-driver       Exclude specified drivers
    --debug                Output debug information on STDERR
    --help                 This help information
EOM
    exit 1;
}

# Figure out if source file is a driver and look for ROM declarations
sub process_source_file {
    my ($source_file) = @_;
    return unless defined $source_file;
    return unless length $source_file;
    my $state = { 'source_file' => $source_file };
    log_debug("SOURCE_FILE", $state->{source_file});
    # Skip source files that aren't drivers
    parse_driver_class( $state );
    unless ( $state->{'driver_class'} ) {
        log_debug("SKIP_NOT_DRIVER", $state->{source_file} );
        return;
    }
    # Skip source files with driver classes that are explicitly excluded
    if ( $exclude_driver_class_map->{ $state->{'driver_class'} } ) {
        log_debug("SKIP_EXCL_CLASS", $state->{'driver_class'} );
        return;
    }
    # Skip source files without driver information
    parse_family( $state );
    parse_driver_name( $state );
    unless ( $state->{'family'} and $state->{'driver_name'} ) {
        log_debug("SKIP_NO_DRV_INFO", $state->{source_file} );
        return;
    }
    # Skip source files with drivers that are explicitly excluded
    if ( $exclude_driver_map->{ $state->{'driver_name'} } ) {
        log_debug("SKIP_EXCL_DRV", $state->{'driver_name'} );
        return;
    }
    # Iterate through lines in source files looking for ROM declarations
    # and # output Makefile rules
    open( my $fh, "<", $state->{'source_file'} )
        or die "Couldn't open $state->{source_file}: $!\n";
    while (<$fh>) {
        process_rom_decl($state, $1, $2, $3) if m/$RE{find_rom_line}/;
    }
    close($fh) or die "Couldn't close $source_file: $!\n";
    return 1;
}

# Verify that the found ROM declaration is sane and dispatch to the right
# handler depending on type
sub process_rom_decl {
    my ($state, $rom_line, $rom_type, $rom_decl) = @_;
    return unless defined $rom_line;
    return unless length $rom_line;
    log_debug("ROM_LINE", $rom_line);
    return unless defined $rom_type;
    return unless length $rom_type;
    log_debug("ROM_TYPE", $rom_type);
    $state->{'type'} = lc $rom_type;
    return process_pci_rom($state, $rom_decl) if $rom_type eq "PCI";
    return process_isa_rom($state, $rom_decl) if $rom_type eq "ISA";
    return;
}

# Extract values from PCI_ROM declaration lines and dispatch to
# Makefile rule generator
sub process_pci_rom {
    my ($state, $decl) = @_;
    return unless defined $decl;
    return unless length $decl;
    (my $vendor, $decl) = extract_pci_id($decl,        'PCI_VENDOR');
    (my $device, $decl) = extract_pci_id($decl,        'PCI_DEVICE');
    (my $image,  $decl) = extract_quoted_string($decl, 'IMAGE');
    (my $desc,   $decl) = extract_quoted_string($decl, 'DESCRIPTION');
    if ( $vendor and $device and $image and $desc ) {
        print_make_rules( $state, "${vendor}${device}", $desc, $vendor, $device );
        print_make_rules( $state, $image, $desc, $vendor, $device, 1 );
    }
    else {
        log_debug("WARNING", "Malformed PCI_ROM macro on line $. of $state->{source_file}");
    }
    return 1;
}

# Extract values from ISA_ROM declaration lines and dispatch to
# Makefile rule generator
sub process_isa_rom {
    my ($state, $decl) = @_;
    return unless defined $decl;
    return unless length $decl;
    (my $image, $decl) = extract_quoted_string($decl, 'IMAGE');
    (my $desc,  $decl) = extract_quoted_string($decl, 'DESCRIPTION');
    if ( $image and $desc ) {
        print_make_rules( $state, $image, $desc );
    }
    else {
        log_debug("WARNING", "Malformed ISA_ROM macro on line $. of $state->{source_file}");
    }
    return 1;
}

# Output Makefile rules for the specified ROM declarations
sub print_make_rules {
    my ( $state, my $image, my $desc, my $vendor, my $device, my $dup ) = @_;
    unless ( $state->{'is_header_printed'} ) {
        print "# NIC\t\n";
        print "# NIC\tfamily\t$state->{family}\n";
        print "DRIVERS_$state->{driver_class} += $state->{driver_name}\n";
        print "DRIVERS += $state->{driver_name}\n";
        print "\n";
        $state->{'is_header_printed'} = 1;
    }
    return if $vendor and ( $vendor eq "ffff" or $device eq "ffff" );
    my $ids = $vendor ? "$vendor,$device" : "-";
    print "# NIC\t$image\t$ids\t$desc\n";
    print "DRIVER_$image = $state->{driver_name}\n";
    print "ROM_TYPE_$image = $state->{type}\n";
    print "ROM_DESCRIPTION_$image = \"$desc\"\n";
    print "PCI_VENDOR_$image = 0x$vendor\n" if $vendor;
    print "PCI_DEVICE_$image = 0x$device\n" if $device;
    print "ROMS += $image\n" unless $dup;
    print "ROMS_$state->{driver_name} += $image\n" unless $dup;
    print "\n";
    return 1;
}

# Driver class is whatever comes after the "drivers" part of the filename (relative path)
sub parse_driver_class {
    my ($state) = @_;
    my $filename = $state->{'source_file'};
    return unless defined $filename;
    return unless length $filename;
    if ( $filename =~ m/$RE{parse_driver_class}/ ) {
        log_debug("DRIVER_CLASS", $1);
        $state->{'driver_class'} = $1;
    }
    return;
}

# Family name is filename (relative path) without extension
sub parse_family {
    my ($state) = @_;
    my $filename = $state->{'source_file'};
    return unless defined $filename;
    return unless length $filename;
    if ( $filename =~ m/$RE{parse_family}/ ) {
        log_debug("FAMILY", $1);
        $state->{'family'} = $1;
    }
    return;
}

# Driver name is last part of family name
sub parse_driver_name {
    my ($state) = @_;
    my $family = $state->{'family'};
    return unless defined $family;
    return unless length $family;
    my @parts = split "/", $family;
    $state->{'driver_name'} = $parts[-1];
    log_debug("DRIVER", $state->{'driver_name'});
    return;
}

# Extract a PCI vendor/device ID e.g. 0x8086, possibly followed by a comma
# Should always be 4-digit lower-case hex number
sub extract_pci_id {
    my ($str, $label) = @_;
    return "", $str unless defined $str;
    return "", $str unless length $str;
    if ( $str =~ m/$RE{extract_pci_id}/ ) {
        my $id = lc $1;
        log_debug($label, $id);
        return $id, $2;
    }
    return "", $str;
}

# Extract a double-quoted string, possibly followed by a comma
sub extract_quoted_string {
    my ($str, $label) = @_;
    return "", $str unless defined $str;
    return "", $str unless length $str;
    if ( $str =~ m/$RE{extract_quoted_string}/ ) {
        log_debug($label, $1);
        return $1, $2;
    }
    return "", $str;
}

# Output debug info to STDERR (off by default)
sub log_debug {
    my ($label, $str) = @_;
    return unless $debug;
    return unless defined $str;
    print STDERR "\n" if $label eq 'SOURCE_FILE';
    print STDERR "=";
    if ( defined $label ) {
        my $pad_count = 16 - length $label;
        print STDERR $label . ":" . ( " " x $pad_count );
    }
    print STDERR $str . "\n";
    return;
}
