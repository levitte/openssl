#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup/;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_sid");

plan tests => 2;

require_ok('recipes/tconversion.pl');

subtest 'sid conversions' => sub {
    tconversion("sid", "testsid.pem", "sess_id");
};
