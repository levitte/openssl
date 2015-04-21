#! /usr/bin/perl

use OpenSSL::Test::Simple;

# This will need changing for no-Unix platforms
$ENV{OPENSSL_ENGINES} = "../engines/ccgost";

simple_test("test_gost2814789", "gost2814789test");
