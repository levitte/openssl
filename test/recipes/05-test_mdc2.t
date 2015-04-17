#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_mdc2");

plan tests => 1;
ok(run(test(["mdc2test"])), "running mdc2test");
