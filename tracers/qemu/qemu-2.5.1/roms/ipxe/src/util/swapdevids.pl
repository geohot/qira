#!/usr/bin/perl -w
#
#	Program to reverse the device identifier IDs in the PCIR and PnP
#	structures in a ROM for old non-compliant BIOSes
#
#	GPL, Ken Yap 2001
#

use bytes;

use IO::Seekable;

sub swaplocs ($$$)
{
	my ($dataref, $loc1, $loc2) = @_;
	my ($t);

	$t = substr($$dataref, $loc1, 1);
	substr($$dataref, $loc1, 1) = substr($$dataref, $loc2, 1);
	substr($$dataref, $loc2, 1) = $t;
}

sub printdevids ($$)
{
	my ($dataref, $loc) = @_;

	return (sprintf "%02x %02x %02x", unpack('C3', substr($$dataref, $loc, 3)));
}

$#ARGV >= 0 or die "Usage: $0 romimage\n";
$file = $ARGV[0];
open(F, "+<$file") or die "$file: $!\n";
binmode(F);
# Handle up to 64kB ROM images
$len = read(F, $data, 64*1024);
defined($len) or die "$file: $!\n";
substr($data, 0, 2) eq "\x55\xAA" or die "$file: Not a boot ROM image\n";
($pci, $pnp) = unpack('v2', substr($data, 0x18, 4));
($pci < $len and $pnp < $len) or die "$file: Not a PCI PnP ROM image\n";
(substr($data, $pci, 4) eq 'PCIR' and substr($data, $pnp, 4) eq '$PnP')
	or die "$file: No PCI and PNP structures, not a PCI PNP ROM image\n";
&swaplocs(\$data, $pci+13, $pci+15);
&swaplocs(\$data, $pnp+18, $pnp+20);
seek(F, 0, SEEK_SET) or die "$file: Cannot seek to beginning\n";
print F $data;
close(F);
print "PCI devids now: ", &printdevids(\$data, $pci+13), "\n";
print "PnP devids now: ", &printdevids(\$data, $pnp+18), "\n";
exit(0);
