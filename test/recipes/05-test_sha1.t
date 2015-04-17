#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_sha1");

plan tests => 1;
ok(run(test(["sha1test"])), "running sha1test");
