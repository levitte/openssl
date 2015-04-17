#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_crl");

plan tests => 2;

require_ok('recipes/tconversion.pl');

subtest 'crl conversions' => sub {
    tconversion("crl");
};
