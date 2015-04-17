#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use OpenSSL::Test qw/:DEFAULT top_file/;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_crl");

plan tests => 2;

require_ok(top_file('test','recipes','tconversion.pl'));

subtest 'crl conversions' => sub {
    tconversion("crl", top_file("test","testcrl.pem"));
};
