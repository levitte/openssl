#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run app test/;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_ec");

plan tests => 5;

require_ok('recipes/tconversion.pl');

ok(run(test(["ectest"])), "running ectest");

 SKIP: {
     skip "Skipping ec conversion test", 3
	 if run(app(["openssl","no-ec"], stdout => undef));

     subtest 'ec conversions -- private key' => sub {
	 tconversion("ec", "testec-p256.pem");
     };
     subtest 'ec conversions -- private key PKCS#8' => sub {
	 tconversion("ec", "testec-p256.pem", "pkey");
     };
     subtest 'ec conversions -- public key' => sub {
	 tconversion("ec", "testecpub-p256.pem", "ec", "-pubin", "-pubout");
     };
}
