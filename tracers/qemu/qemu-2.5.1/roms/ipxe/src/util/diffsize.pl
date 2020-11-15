#!/usr/bin/perl -w
# usage:
# [somebody@somewhere ~/ipxe/src]$ ./util/diffsize.pl [<old rev> [<new rev>]]
# by default <old rev> is HEAD and <new rev> is the working tree

use strict;

-d "bin" or die "Please run me in the iPXE src directory\n";
mkdir ".sizes";

my($oldrev, $newrev);
my($oldname, $newname);

if (@ARGV) {
  $oldname = shift;
} else {
  $oldname = "HEAD";
}

if (@ARGV) {
  $newname = shift;
} else {
  $newrev = "tree" . time();
}

$oldrev = `git rev-parse $oldname`;
chomp $oldrev;

unless (defined $newrev) {
  $newrev = `git rev-parse $newname`;
  chomp $newrev;
}

sub calc_sizes($$) {
  my($name, $rev) = @_;
  my $output;
  my $lastrev;
  my $stashed = 0;
  my $res = 0;

  return if -e ".sizes/$rev.sizes";

  if (defined $name) {
    $output = `git stash`;
    $stashed = 1 unless $output =~ /No local changes to save/;
    $lastrev = `git name-rev --name-only HEAD`;
    system("git checkout $name >/dev/null"); $res ||= $?;
  }

  system("make -j4 bin/ipxe.lkrn >/dev/null"); $res ||= $?;
  system("make bin/ipxe.lkrn.sizes > .sizes/$rev.sizes"); $res ||= $?;

  if (defined $name) {
    system("git checkout $lastrev >/dev/null"); $res ||= $?;
    system("git stash pop >/dev/null") if $stashed; $res ||= $?;
  }

  if ($res) {
    unlink(".sizes/$rev.sizes");
    die "Error making sizes file\n";
  }
}

our %Sizes;

sub save_sizes($$) {
  my($id, $rev) = @_;
  my $file = ".sizes/$rev.sizes";

  open SIZES, $file or die "opening $file: $!\n";
  while (<SIZES>) {
    my($text, $data, $bss, $total, $hex, $name) = split;
    $name =~ s|bin/||; $name =~ s|\.o$||;

    # Skip the header and totals lines
    next if $total =~ /[a-z]/ or $name =~ /TOTALS/;

    # Skip files named with dash, due to old Makefile bug
    next if $name =~ /-/;

    $Sizes{$name} = {old => 0, new => 0} unless exists $Sizes{$name};
    $Sizes{$name}{$id} = $total;
  }
}

calc_sizes($oldname, $oldrev);
calc_sizes($newname, $newrev);

save_sizes('old', $oldrev);
save_sizes('new', $newrev);

my $total = 0;

for (sort keys %Sizes) {
  my $diff = $Sizes{$_}{new} - $Sizes{$_}{old};
  if (abs($diff) >= 16) {
    printf "%12s %+d\n", substr($_, 0, 12), $Sizes{$_}{new} - $Sizes{$_}{old};
  }
  $total += $diff;
}
printf "      TOTAL: %+d\n", $total;
