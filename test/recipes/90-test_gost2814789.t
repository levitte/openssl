#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_gost2814789");

# This will need changing for no-Unix platforms
$ENV{OPENSSL_ENGINES} = "../engines/ccgost";

plan tests => 1;
ok(run(test(["gost2814789test"])), "running gost2814789test");
