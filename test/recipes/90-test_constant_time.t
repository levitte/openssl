#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_constant_time");

plan tests => 1;
ok(run(test(["constant_time_test"])), "running constant_time_test");
