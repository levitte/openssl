#! /usr/bin/env perl

use File::Basename;

my @ci_files = `find . -name '*.ci'`;

# Read all .ci files, find all edges that target BN_ functions, and collect
# them by directory of the source files they're called from.
my %BN_calls_by_directory = ();
foreach my $ci_file (@ci_files) {
    chomp $ci_file;

    open (my $fh, $ci_file);
    while (<$fh>) {
        chomp;
        if (m/^edge:.*?targetname: "(BN_[A-Za-z0-9_]+)" *label: "(.*?)".*$/) {
            my $d = dirname($2);
            $BN_calls_by_directory{$d}->{$1} = 1;
        }
    }
    close $fh;
}

# In each directory where BN_ calls were collected, add a file BN_calls.txt
# which enumerates all BN_ functions that are called, in sorted order.
foreach my $d (sort keys %BN_calls_by_directory) {
    open(my $fh, "> $d/BN_calls.txt");
    print $fh "$_\n" foreach (sort keys %{$BN_calls_by_directory{$d}});
    close $fh;
}
