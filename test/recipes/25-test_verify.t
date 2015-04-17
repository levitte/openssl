#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use Test::More;
use OpenSSL::Test;

$ENV{OPENSSL_CONF} = File::Spec->devnull();

setup("test_verify");

plan tests => 1;

note("Expect some failures and expired certificate");
ok(run(app(["openssl", "verify", "-CApath", "../certs/demo",
	    glob("../certs/demo/*.pem")])), "verying demo certs");
