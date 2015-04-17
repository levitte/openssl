#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run app test/;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_rsa");

plan tests => 5;

require_ok('recipes/tconversion.pl');

ok(run(test(["rsa_test"])), "running rsatest");

 SKIP: {
     skip "Skipping rsa conversion test", 3
	 if run(app(["openssl","no-rsa"], stdout => undef));

     subtest 'rsa conversions -- private key' => sub {
	 tconversion("rsa", "testrsa.pem");
     };
     subtest 'rsa conversions -- private key PKCS#8' => sub {
	 tconversion("rsa", "testrsa.pem", "pkey");
     };
     subtest 'rsa conversions -- public key' => sub {
	 tconversion("rsa", "testrsapub.pem", "rsa", "-pubin", "-pubout");
     };
}
