#! /usr/bin/perl

use strict;
use warnings;

use File::Spec::Functions qw/catdir/;
use Test::Harness qw/runtests $switches/;

my $top = $ENV{TOP};
my $testdir = catdir($top, "test");
my $testlib = catdir($top, "test", "testlib");

# Test::Harness provides the variable $switches to give it
# switches to be used when it calls our recipes.
$switches = "-w -I$testlib";

my @tests = ( "alltests" );
if (@ARGV) {
    @tests = @ARGV;
}
if (grep /^alltests$/, @tests) {
    @tests = <$testdir/recipes/[0-9][0-9]-*.t>;
} else {
    my @t = ();
    foreach (@tests) {
	push @t, <$testdir/recipes/[0-9][0-9]-$_.t>;
    }
    @tests = @t;
}

runtests(sort @tests);
