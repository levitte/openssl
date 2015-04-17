#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_md2");

plan tests => 1;
ok(run(test(["md2test"])), "running md2test");
