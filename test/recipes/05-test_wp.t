#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_wp");

plan tests => 1;
ok(run(test(["wp_test"])), "running wp_test");
