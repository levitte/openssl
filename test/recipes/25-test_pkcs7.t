#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup/;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_pkcs7");

plan tests => 3;

require_ok('recipes/tconversion.pl');

subtest 'pkcs7 conversions -- pkcs7' => sub {
    tconversion("p7", "testp7.pem", "pkcs7");
};
subtest 'pkcs7 conversions -- pkcs7d' => sub {
    tconversion("p7d", "pkcs7-1.pem", "pkcs7");
};
