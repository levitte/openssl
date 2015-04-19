#! /usr/bin/perl

use strict;
use warnings;

use Test::Harness;

my @tests = ( "alltests" );
if (@ARGV) {
    @tests = @ARGV;
}
if (grep /^alltests$/, @tests) {
    @tests = <recipes/[0-9][0-9]-*.t>;
} else {
    my @t = ();
    foreach (@tests) {
	push @t, <recipes/[0-9][0-9]-$_.t>;
    }
    @tests = @t;
}

runtests(sort @tests);
