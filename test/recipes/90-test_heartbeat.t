#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run test/;

setup("test_heartbeat");

plan tests => 1;
ok(run(test(["heartbeat_test"])), "running heartbeat_test");
