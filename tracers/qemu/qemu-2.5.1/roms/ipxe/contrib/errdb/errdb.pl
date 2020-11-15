#!/usr/bin/perl -w

=head1 NAME

errdb.pl

=head1 SYNOPSIS

errdb.pl [options] ../../src/bin/errors

Options:

    -d,--database=db	Specify path to errors.db
    -h,--help		Display brief help message
    -v,--verbose	Increase verbosity
    -q,--quiet		Decrease verbosity

=cut

use Getopt::Long;
use Pod::Usage;
use DBI;
use strict;
use warnings;

# Parse command-line options
my $verbosity = 0;
my $errdb = "errors.db";
Getopt::Long::Configure ( 'bundling', 'auto_abbrev' );
GetOptions (
  'database|d=s' => sub { shift; $errdb = shift; },
  'verbose|v+' => sub { $verbosity++; },
  'quiet|q+' => sub { $verbosity--; },
  'help|h' => sub { pod2usage ( 1 ); },
) or die "Could not parse command-line options\n";
pod2usage ( 1 ) unless @ARGV >= 1;

# Open database
my $dbh = DBI->connect ( "dbi:SQLite:dbname=".$errdb, "", "",
			 { RaiseError => 1, PrintError => 0 } );
$dbh->begin_work();

# Create errors table if necessary
eval {
  $dbh->selectall_arrayref ( "SELECT * FROM errors LIMIT 1" );
};
if ( $@ ) {
  print "Creating errors table\n" if $verbosity >= 1;
  $dbh->do ( "CREATE TABLE errors (".
	     " errno char(8) NOT NULL,".
	     " description text NOT NULL,".
	     " PRIMARY KEY ( errno ) )" );
}

# Create xrefs table if necessary
eval {
  $dbh->selectall_arrayref ( "SELECT * FROM xrefs LIMIT 1" );
};
if ( $@ ) {
  print "Creating xrefs table\n" if $verbosity >= 1;
  $dbh->do ( "CREATE TABLE xrefs (".
	     " errno char(8) NOT NULL,".
	     " filename text NOT NULL,".
	     " line integer NOT NULL,".
	     " UNIQUE ( errno, filename, line ),".
	     " FOREIGN KEY ( errno ) REFERENCES errors ( errno ) )" );
  $dbh->do ( "CREATE INDEX xrefs_errno ON xrefs ( errno )" );
}

# Parse input file(s)
my $errors = {};
my $xrefs = {};
while ( <> ) {
  chomp;
  ( my $errno, my $filename, my $line, my $description ) = split ( /\t/ );
  $errno = substr ( $errno, 0, 6 ) unless $errno =~ /^7f/;
  $errors->{$errno} = $description;
  $xrefs->{$errno} ||= {};
  $xrefs->{$errno}->{$filename} ||= {};
  $xrefs->{$errno}->{$filename}->{$line} ||= 1;
}

# Ensure all errors are present in database
my $error_update =
    $dbh->prepare ( "UPDATE errors SET description = ? WHERE errno = ?" );
my $error_insert = $dbh->prepare ( "INSERT INTO errors VALUES ( ?, ? )" );
while ( ( my $errno, my $description ) = each %$errors ) {
  print "Error ".$errno." is \"".$description."\"\n" if $verbosity >= 2;
  if ( $error_update->execute ( $description, $errno ) == 0 ) {
    $error_insert->execute ( $errno, $description );
  }
}

# Replace xrefs in database
$dbh->do ( "DELETE FROM xrefs" );
my $xref_insert = $dbh->prepare ( "INSERT INTO xrefs VALUES ( ?, ?, ? )" );
while ( ( my $errno, my $xref_errno ) = each %$xrefs ) {
  while ( ( my $filename, my $xref_filename ) = each %$xref_errno ) {
    foreach my $line ( keys %$xref_filename ) {
      print "Error ".$errno." is used at ".$filename." line ".$line."\n"
	  if $verbosity >= 2;
      $xref_insert->execute ( $errno, $filename, $line );
    }
  }
}

# Close database
$dbh->commit();
$dbh->disconnect();
