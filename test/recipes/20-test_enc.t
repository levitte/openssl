#! /usr/bin/perl

use strict;
use warnings;

use File::Spec;
use File::Copy;
use File::Compare;
use Test::More;
use lib 'testlib';
use OpenSSL::Test qw/setup run app test/;

setup("test_enc");

my $testsrc = $0;
my $test = File::Spec->catfile(".", "p");

$ENV{OPENSSL_CONF} = File::Spec->devnull();
my $cmd = "openssl";

my @ciphers = run(app([$cmd, "list-cipher-commands"]), capture => 1);
chomp(@ciphers);
unshift @ciphers, "cat";

plan tests => 1 + (scalar @ciphers)*2;

my $init = ok(copy($testsrc,$test));

if (!$init) {
    diag("Trying to copy $testsrc to $test : $!");
}

 SKIP: {
     skip "Not initialized, skipping...", 11 unless $init;

     foreach my $c (@ciphers) {
	 my %variant = ("$c" => [],
			"$c base64" => [ "-a" ]);

	 foreach my $t (sort keys %variant) {
	     my $cipherfile = "$test.$c.cipher";
	     my $clearfile = "$test.$c.clear";
	     my @e = ( "$c", "-bufsize", "113", @{$variant{$t}}, "-e", "-k", "test" );
	     my @d = ( "$c", "-bufsize", "157", @{$variant{$t}}, "-d", "-k", "test" );
	     if ($c eq "cat") {
		 $cipherfile = "$test.cipher";
		 $clearfile = "$test.clear";
		 @e = ( "enc", @{$variant{$t}}, "-e" );
		 @d = ( "enc", @{$variant{$t}}, "-d" );
	     }

	     ok(run(app([$cmd, @e],
			stdin => $test, stdout => $cipherfile))
		&& run(app([$cmd, @d],
			   stdin => $cipherfile, stdout => $clearfile))
		&& compare($test,$clearfile) == 0, $t);
	     unlink $cipherfile, $clearfile;
	 }
     }
}

unlink $test;
