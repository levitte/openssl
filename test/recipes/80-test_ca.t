#! /usr/bin/perl

use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/splitdir curdir catfile devnull/;
use File::Path qw/remove_tree/;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup top_file/;

setup("test_ca");

my $perl = $ENV{PERL};
$ENV{OPENSSL_CONF} = File::Spec->devnull();

if ($^O eq "VMS") {
    $ENV{OPENSSL} = 'pipe mcr OSSLX_TMP:openssl.exe';
} else {
    $ENV{PATH} = "../apps"
	.($^O eq "MXWin32" ? ";" : ":")
	.$ENV{PATH};
    $ENV{OPENSSL} = top_file("util", "opensslwrap.sh");
}

remove_tree("demoCA", { safe => 0 });

plan tests => 4;
 SKIP: {
     $ENV{SSLEAY_CONFIG} = "-config CAss.cnf";
     skip "failed creating CA structure", 3
	 if !is(system("$perl ".top_file("apps", "CA.pl")." -newca < ".devnull()." 2>&1"), 0,
		'creating CA structure');

     $ENV{SSLEAY_CONFIG} = "-config Uss.cnf";
     skip "failed creating new certificate request", 2
	 if !is(system("$perl ".top_file("apps", "CA.pl")." -newreq 2>&1"), 0,
		'creating new certificate request');

     $ENV{SSLEAY_CONFIG} = "-config ".top_file("apps", "openssl.cnf");
     skip "failed to sign certificate request", 1
	 if !is(yes("$perl ".top_file("apps", "CA.pl")." -sign 2>&1"), 0,
		'signing certificate request');

     is(system("$perl ".top_file("apps", "CA.pl")." -verify newcert.pem 2>&1"), 0,
	'verifying new certificate');
}


remove_tree("demoCA", { safe => 0 });
unlink "newcert.pem", "newreq.pem";


sub yes {
    open(PIPE, "|-", join(" ",@_));
    local $SIG{PIPE} = "IGNORE";
    1 while print PIPE "y\n";
    close PIPE;
    return 0;
}
