#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_engine");

plan tests => 1;
ok(run(test(["enginetest"])), "running enginetest");
