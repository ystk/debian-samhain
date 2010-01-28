#! /usr/bin/perl

use warnings;
use strict;

my @arr;
my @sarr;

my %consev = (
	      SH_ERR_ALL => "debug",
	      SH_ERR_ERR => "err",
	      SH_ERR_WARN => "warn",
	      SH_ERR_STAMP => "mark",
	      SH_ERR_FATAL => "alert",
	      SH_ERR_INFO  => "info",
	      SH_ERR_SEVERE => "crit",
	      SH_ERR_NOTICE => "notice"
	      );

my %conclass = (
	EVENT	=> "EVENT",
	START	=> "START",
	STAMP	=> "STAMP",
	LOGKEY	=> "LOGKEY",
	PANIC	=> "ERROR",
	ERR	=> "ERROR",
	ENET	=> "ERROR",
	EINPUT	=> "ERROR",
	FIL	=> "OTHER",
	RUN	=> "OTHER",
	TCP	=> "OTHER",
	AUD	=> "AUD"
		);

while (<>) {
    @arr = split(/(,\s*)/);

    # print $_;
    # printf ("%s %s\n", $arr[2], $consev{$arr[2]});

    my $msg = $arr[6];
    my $sev = $consev{$arr[2]};
    my $class = $conclass{$arr[4]};
    my $foo = '';

    # print $_;
    if ($msg =~ /.*\"msg=\\\"/) {
	$msg =~ s/.*\"msg=\\\"//;
	$msg =~ s/\\\".*//;
	if ($msg =~ /^\%s$/) {
	    $foo = "$arr[6]\n";
	} else {
	    $foo = "$msg\n";
	}
    } else {
	$foo = "$arr[6]\n";
    }
    $foo .= "Severity: $sev, Class: $class\n";
    $foo .= $_;
    $foo .= "\n";
    # printf ("Severity: %s, Class: %s\n\n", $sev, $class);
    push @sarr, $foo;
}

for (sort(@sarr)) { print $_; }

