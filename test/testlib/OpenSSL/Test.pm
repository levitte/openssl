package OpenSSL::Test;

use strict;
use warnings;

use File::Copy;
use File::Spec::Functions qw/file_name_is_absolute curdir canonpath splitdir
                             catdir catfile splitpath catpath devnull/;
use File::Path qw/remove_tree/;
use Test::More;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
@ISA = qw(Exporter);
@EXPORT = qw(setup indir with top_dir top_file);
@EXPORT_OK = qw(app test pipe run);

my $test_name = undef;
my @test_dir = undef;
my $openssl_top_vol = undef;
my @openssl_top_dir = undef;
my $openssl_top_dir_absolute = 0;

sub __test_log {
    return catpath($openssl_top_vol, catdir(@test_dir), "$test_name.log");
}

sub setup {
    $test_name = shift;

    BAIL_OUT("setup() must receive a name") if (! $test_name);

    BAIL_OUT("Need \$TOP") if (! $ENV{TOP});

    my $srcdir = $ENV{TOP};
    $openssl_top_dir_absolute = file_name_is_absolute($srcdir);
    my ($top_vol, $top_dir, $dummy) = splitpath($srcdir, 1);
    $openssl_top_vol = $top_vol;
    @openssl_top_dir = splitdir($top_dir);

    @test_dir = curdir();

    # Loop in case we're on a platform with more than one file generation
    1 while unlink(__test_log());
}

sub indir {
    my @subdir = splitdir(shift);
    my $codeblock = shift;
    my %opts = @_;

    my @reverse = ("..") x (scalar @subdir);

    if ($opts{cleanup}) {
	remove_tree(catdir(@subdir), { safe => 0 });
    }
    mkdir(catdir(@subdir));

    my $curdir = curdir();
    my @saved_openssl_top_dir = @openssl_top_dir;
    my @saved_test_dir = @test_dir;
    @openssl_top_dir = (@reverse, @openssl_top_dir)
	unless $openssl_top_dir_absolute;
    @test_dir = (@reverse, @test_dir);
    chdir(catdir(@subdir));

    $codeblock->();

    chdir(catdir(@reverse));
    @openssl_top_dir = @saved_openssl_top_dir;
    @test_dir = @saved_test_dir;

    if ($opts{cleanup}) {
	remove_tree(catdir(@subdir), { safe => 0 });
    }
}

my %hooks = (
    exit_checker => sub { return shift == 0 ? 1 : 0 }
    );

sub with {
    my $opts = shift;
    my %opts = %{$opts};
    my $codeblock = shift;

    my %saved_hooks = ();

    foreach (keys %opts) {
	$saved_hooks{$_} = $hooks{$_}	if exists($hooks{$_});
	$hooks{$_} = $opts{$_};
    }

    $codeblock->();

    foreach (keys %saved_hooks) {
	$hooks{$_} = $saved_hooks{$_};
    }
}

sub top_dir {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    return catpath($openssl_top_vol, catdir(@openssl_top_dir, @_), "");
}
sub top_file {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $f = pop;
    return catpath($openssl_top_vol, catdir(@openssl_top_dir, @_), $f);
}

sub __app_cmd {
    my $app = shift;

    my %dirs = (top_dir("apps") => top_file("util", "shlib_wrap.sh")." ");
    foreach ((top_dir("tmp32dll"), top_dir("tmp32"))) {
	$dirs{$_} = "";
    }

    my $ext = $ENV{"EXE_EXT"} || "";
    if ( $^O eq "VMS" ) {	# VMS
	%dirs = ("OSSLX_TMP:" => "pipe mcr OSSLX_TMP:");
	$ext = ".EXE";
    } elsif ($^O eq "MSWin32") { # MSYS
	%dirs = (top_dir("apps") => "cmd /c ");
	$ext = ".exe";
    }
    for my $d (keys %dirs) {
	my $file = catfile($d, "$app$ext");
	if ( -f $file ) {
	    return $dirs{$d}.$file;
	}
    }
    print STDERR "$app not found";
    return undef;
}
sub __test_cmd {
    my $test = shift;

    my %dirs = (curdir() => top_file("util", "shlib_wrap.sh")." ");
    foreach ((top_dir("tmp32dll"), top_dir("tmp32"))) {
	$dirs{$_} = "";
    }

    my $ext = $ENV{"EXE_EXT"} ? $ENV{"EXE_EXT"} : "";
    if ( $^O eq "VMS" ) {	# VMS
	%dirs = ("OSSLT_TMP:"    => "pipe mcr OSSLT_TMP:");
	$ext = ".EXE";
    } elsif ($^O eq "MSWin32") { # MSYS
	%dirs = ("..\\test\\"    => "cmd /c .\\");
	$ext = ".exe";
    }
    for my $d (keys %dirs) {
	my $file = catfile($d, "$test$ext");
	if ( -f $file ) {
	    return $dirs{$d}.$file;
	}
    }
    print STDERR "$test not found";
    return undef;
}

sub __build_cmd {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $num = shift;
    my $cmd_finder = shift;
    my $cmd = $cmd_finder->(shift @{$_[0]});
    my @args = @{$_[0]}; shift;
    my %opts = @_;

    # Unix setup
    my $arg_str = "";
    my $arg_formatter = sub { $_ = shift; /\s|[\{\}\\\$\[\]\*\?\|\&:;]/ ? "'$_'" : $_ };
    my $null = devnull();

    # VMS setup
    if ( $^O eq "VMS") {
	$arg_formatter = sub {
	    $_ = shift;
	    if (/\s|["[:upper:]]/) {
		s/"/""/g;
		'"'.$_.'"';
	    } else {
		$_;
	    }
	};
    }
    $arg_str = " ".join(" ",map { $arg_formatter->($_) } @args) if @args;

    my $fileornull = sub { $_[0] ? $_[0] : $null; };
    my $stdin = "";
    my $stdout = "";
    my $stderr = "";
    my $saved_stderr = "";
    $stdin = " < ".$fileornull->($opts{stdin})  if exists($opts{stdin});
    $stdout= " > ".$fileornull->($opts{stdout}) if exists($opts{stdout});
    $stderr=" 2> ".$fileornull->($opts{stderr}) if exists($opts{stderr});

    $saved_stderr = $opts{stderr}		if defined($opts{stderr});

    my $errlog = "$test_name.$num.tmp_err";
    my $display_cmd = "$cmd$arg_str$stdin$stdout$stderr";
    $cmd .= "$arg_str$stdin$stdout 2> $errlog";

    return ($cmd, $display_cmd, $errlog => $saved_stderr);
}

sub run {
    my ($cmd, $display_cmd, %errlogs) = shift->(1);
    my %opts = @_;

    my $prefix = "";
    if ( $^O eq "VMS" ) {	# VMS
	$prefix = "pipe ";
    } elsif ($^O eq "MSWin32") { # MSYS
	$prefix = "cmd /c ";
    }

    my @r = ();
    my $r = 0;
    my $e = 0;
    if ($opts{capture}) {
	@r = `$prefix$cmd`;
	$e = $? >> 8;
    } else {
	system("$prefix$cmd");
	$e = $? >> 8;
	$r = $hooks{exit_checker}->($e);
    }

    open ERR, ">>", __test_log();
    print ERR "$display_cmd => $e\n";
    foreach (keys %errlogs) {
	copy($_,\*ERR);
	copy($_,$errlogs{$_}) if defined($errlogs{$_});
	unlink($_);
    }
    close ERR;

    if ($opts{capture}) {
	return @r;
    } else {
	return $r;
    }
}

sub app {
    my $cmd = shift;
    my %opts = @_;
    return sub { my $num = shift;
		 return __build_cmd($num, \&__app_cmd, $cmd, %opts); }
}

sub test {
    my $cmd = shift;
    my %opts = @_;
    return sub { my $num = shift;
		 return __build_cmd($num, \&__test_cmd, $cmd, %opts); }
}

sub pipe {
    my @cmds = @_;
    return
	sub {
	    my @cs  = ();
	    my @dcs = ();
	    my @els = ();
	    my $counter = 0;
	    foreach (@cmds) {
		my ($c, $dc, @el) = $_->(++$counter);
		push @cs, $c;
		push @dcs, $dc;
		push @els, @el;
	    }
	    return (
		join(" | ", @cs),
		join(" | ", @dcs),
		@els
		);
    };
}

1;
