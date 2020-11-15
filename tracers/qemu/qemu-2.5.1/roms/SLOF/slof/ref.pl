# *****************************************************************************
# * Copyright (c) 2004, 2008 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/
#!/usr/bin/perl

#
# Copyright 2002,2003,2004  Segher Boessenkool  <segher@kernel.crashing.org>
#


use Getopt::Std;
use Data::Dumper;

$CELLSIZE = length(sprintf "%x", ~0) / 2;
$CELLSIZE = 8;
$DEBUG = 0;

sub usage
{
	printf STDERR "Usage: ref.pl [ -s 32|64 ] [ -d ] \n";
	printf STDERR "       ref.pl -h\n";
	exit 0;
}

sub string
{
	my ($s, $extra) = @_;

	$DEBUG and printf STDERR "\nstring:[%s][%02x]\n", $s, ord $extra;
	$s = sprintf "%s%c%s", $extra, length($s), $s;
	@s = ($s =~ /(.{1,$CELLSIZE})/gs);
	do { s/([\x00-\x1f\x22\x5c\x7f-\xff])/sprintf "\\%03o", ord $1/egs } for @s;
	my @reut = ("{ .c = \"" . (join "\" }, { .c = \"", @s) . "\" },", scalar @s);
	# $DEBUG and print STDERR Dumper \@reut;
	return @reut;
}

sub forth_to_c_name
{
	($_, my $numeric) = @_;
	s/([^a-zA-Z0-9])/sprintf("_X%02x_", ord($1))/ge;
	s/__/_/g;
#	s/^_//;
	s/_$//;
	s/^(\d)/_$1/ if $numeric;
	return $_;
}

sub special_forth_to_c_name
{
	($_, my $numeric) = @_;

	$DEBUG and print STDERR "\tasked for $_ [[numeric is $numeric]]\n";
	my ($name, $arg) = (/^([^(]+)(.*)$/);
	# $DEBUG and print STDERR "\tname is $name -- arg is $arg\n";
	if ($special{$name} == 1) {
		$_ = forth_to_c_name($name, $numeric) . $arg;
	} elsif ($special{$name} != 2) {
		$_ = forth_to_c_name($_, $numeric);
	}
	# $DEBUG and print STDERR "\tmaking it $_\n";
	return $_;
}

getopts('dhs:') or die "Invalid option!\n";

$opt_h and usage();
$opt_d and $DEBUG=1;
$opt_s and $opt_s != 32 and $opt_s != 64 and die("Only -s32 or -s64 allowed");

$opt_s and $opt_s == 32 and $CELLSIZE=4;

$DEBUG and printf STDERR "Cell size set to $CELLSIZE;\n";

$link = "0";
%special = ( _N => 2, _O => 2, _C => 2, _A => 2 );

$DEBUG and print STDERR "Compiling:";
while ($line = <>) {
	if ($line =~ /^([a-z]{3})\(([^ ]+)./) {
		$typ = $1;
		$name = $2;

		$DEBUG and print STDERR "\n\t\t$name###\n";

		$name =~ s/\)$// if $line =~ /\)\s+_ADDING.*$/;
		# $DEBUG and print STDERR " $name";
		$cname = forth_to_c_name($name, 1);
		$par = '';
		$add = '';
		$extra = "\0";
		if ($typ eq "imm") {
			$typ = "col";
			$extra = "\1";
		}
#		if ($typ eq "com") {
#			$typ = "col";
#			$extra = "\3";
#		}
		($str, $strcells) = (string $name, $extra);
		if ($line =~ /^str\([^"]*"([^"]*)"/) {
		# $DEBUG and print STDERR "[[[$1]]]\n";
			($s) = (string $1);
			$line =~ s/"[^"]*"/$s/;
		}
		if ($line =~ /_ADDING +(.*)$/) {
			$special{$name} = 1;
			@typ = (split /\s+/, $1);
			$count = 0;
			$par = "(" . (join ", ", map { $count++; "_x$count" } @typ) . ")";
			$count = 0;
			$add = join " ", map { $count++; "$_(_x$count)" } @typ;
			$line =~ s/\s+_ADDING.*$//;
		}
		# $DEBUG and print STDERR $line;
		($body) = ($line =~ /^...\((.*)\)$/);
		@body = split " ", $body;
		# $DEBUG and print STDERR "\n";
		# $DEBUG and print STDERR "BODY WAS: ", (join " ", @body), "\n";
		if ($typ ne "str" and $typ ne "con") {
			@body = map { special_forth_to_c_name($_, $typ eq "col") } @body;
		} else {
			$body[0] = special_forth_to_c_name($body[0]);
		}
		# $DEBUG and print STDERR "BODY IS: ", (join " ", @body), "\n";
		$body = join " ", @body;
		$body =~ s/ /, /;
		# $DEBUG and print STDERR "===> $body\n";

		print "header($cname, { .a = $link }, $str) ";
		$link = "xt_$cname";
		print "$typ($body)\n";
		print "#define $cname$par ref($cname, $strcells+1) $add\n";
		(my $xxcname) = ($cname =~ /^_?(.*)/);
		$add and print "#define DO$xxcname ref($cname, $strcells+1)\n";
	} else {
		print $line;
	}
}
$DEBUG and print STDERR "\n";
