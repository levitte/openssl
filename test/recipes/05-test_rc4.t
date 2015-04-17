#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_rc4");

plan tests => 1;
ok(run(test(["rc4test"])), "running rc4test");
