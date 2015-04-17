#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_evp_extra");

plan tests => 1;
ok(run(test(["evp_extra_test"])), "running evp_extra_test");
