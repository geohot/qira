#!/usr/bin/perl -w

=head1 NAME

relicense.pl

=head1 SYNOPSIS

relicense.pl [options] -p <permissions file> <file> [<file>...]

Option:

    -p,--permitted=FILE	Specify file of emails with relicensing permission
    -f,--force		Manually force relicensing
    -h,--help		Display brief help message
    -v,--verbose	Increase verbosity
    -q,--quiet		Decrease verbosity

=cut

use File::Slurp;
use IPC::Run qw ( run );
use Getopt::Long;
use Pod::Usage;
use strict;
use warnings;

# Parse command-line options
my $verbosity = 0;
my $permfile;
my $force;
Getopt::Long::Configure ( "bundling", "auto_abbrev" );
GetOptions (
  'permitted|p=s' => \$permfile,
  'force|f' => \$force,
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
  'help|h' => sub { pod2usage ( 1 ); },
) or die "Could not parse command-line options";
pod2usage ( 1 ) unless @ARGV;

# Read permitted emails file
my @emails = ( $permfile ? read_file ( $permfile ) : () );
chomp @emails;
my $permitted = { map { /^.*<(\S+)>$/; ( $1 || $_ ) => 1 } @emails };

# Define list of relicensable licences
my $relicensable = {
  GPL2_OR_LATER => 1,
};

# Define blurb to be added to copyright notice
my $blurb = '
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.';

# Process files
my @succeeded;
my @failed;
while ( my $filename = shift @ARGV ) {

  # Read file to determine existing licence
  my $file = read_file ( $filename );
  my @licences = ( $file =~ /^\s*FILE_LICENCE\s*\(\s*(\S+)\s*\)\s*;?$/mg );
  die "No licence declaration in $filename\n" unless @licences;
  die "Multiple licence declarations in $filename\n" if @licences > 1;
  my $licence = $licences[0];

  # Skip if file is already UBDL-licensed
  next if $licence =~ /_OR_UBDL$/;

  # Fail immediately if file is not a candidate for relicensing
  if ( ! exists $relicensable->{$licence} ) {
    print "Non-relicensable licence $licence in $filename\n";
    push @failed, $filename;
    next;
  }

  # Run git-blame
  my $stdout;
  my $stderr;
  run [ "git", "blame", "-M", "-C", "-p", "-w", $filename ],
      \undef, \$stdout, \$stderr
      or die "git-blame $filename: $?";
  die $stderr if $stderr;

  # Process output
  my @stdout = split ( /\n/, $stdout );
  chomp @stdout;
  my $details = {};
  my $failures = 0;
  while ( @stdout ) {

    # Parse output
    my $commit_line = shift @stdout;
    ( my $commit, undef, my $lineno, undef, my $count ) =
	( $commit_line =~
	  /^([0-9a-f]{40})\s+([0-9]+)\s+([0-9]+)(\s+([0-9]+))?$/ )
	or die "Malformed commit line \"$commit_line\"\n";
    if ( $count ) {
      $details->{$commit} ||= {};
      while ( ! ( $stdout[0] =~ /^\t/ ) ) {
	my $detail_line = shift @stdout;
	( my $key, undef, my $value ) =
	    ( $detail_line =~ /^([a-z-]+)(\s+(.+))?$/ )
	    or die "Malformed detail line \"$detail_line\" for $commit_line\n";
	$details->{$commit}->{$key} = $value;
      }
    }
    die "Missing commit details for $commit_line\n"
	unless %{$details->{$commit}};
    my $code_line = shift @stdout;
    ( my $line ) = ( $code_line =~ /^\t(.*)$/ )
	or die "Malformed code line \"$code_line\" for $commit_line\n";

    # Skip trivial lines and lines so common that they are likely to
    # be misattributed by git-blame
    next if $line =~ /^\s*$/;		# Empty lines
    next if $line =~ /^\s*\/\*/;	# Start of comments
    next if $line =~ /^\s*\*/;		# Middle (or end) of comments
    next if $line =~ /^\s*\{\s*$/;	# Standalone opening braces
    next if $line =~ /^\s*\};?\s*$/;	# Standalone closing braces
    next if $line =~ /^\#include/;	# Header inclusions
    next if $line =~ /^\s*return\s+0;/;	# return 0;
    next if $line =~ /^\s*return\s+rc;/; # return rc;
    next if $line =~ /^\s*PCI_ROM\s*\(.*\)\s*,\s*$/;	# PCI IDs
    next if $line =~ /^\s*FILE_LICENCE\s*\(.*\)\s*;$/; # Licence declarations

    # Identify author
    my $author_mail = $details->{$commit}->{"author-mail"}
    or die "Missing author email for $commit_line\n";
    ( my $email ) = ( $author_mail =~ /^<(\S+)>$/ )
	or die "Malformed author email \"$author_mail\" for $commit_line\n";
    undef $email if exists $details->{$commit}->{boundary};

    # Check for relicensing permission
    next if defined $email && exists $permitted->{$email};

    # Print out lines lacking permission
    printf $filename."\n" unless $failures;
    printf "%4d %-30s %s\n", $lineno, ( $email || "<root>" ), $line;
    $failures++;
  }

  # Fail if there are any non-trivial lines lacking relicensing permission
  if ( $failures && ! $force ) {
    push @failed, $filename;
    next;
  }

  # Modify FILE_LICENCE() line
  $file =~ s/(^\s*FILE_LICENCE\s*\(\s*${licence})(\s*\)\s*;?$)/$1_OR_UBDL$2/m
      or die "Could not modify FILE_LICENCE() in $filename\n";

  # Modify copyright notice, if present
  if ( $file =~ /GNU General Public License/i ) {
    $file =~ s/(02110-1301, USA.$)/$1${blurb}/m
	or die "Could not modify copyright notice in $filename\n";
  }

  # Write out modified file
  write_file ( $filename, { atomic => 1 }, $file );
  push @succeeded, $filename;
}

print "Relicensed: ".join ( " ", @succeeded )."\n" if @succeeded;
die "Cannot relicense: ".join ( " ", @failed )."\n" if @failed;
