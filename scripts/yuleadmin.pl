#! /usr/bin/perl

# Copyright (c) 2007 Riccardo Murri <riccardo.murri@gmail.com>
#
# License Information:
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

use warnings;
use strict;
use Getopt::Long;
use File::Basename;
use File::Copy;
use File::Temp qw/ tempfile /;
use IO::File;

# Do I/O to the data file in binary mode (so it 
# wouldn't complain about invalid UTF-8 characters).
use bytes;

File::Temp->safe_level( File::Temp::HIGH );

my %opts = ();
my $outfile;
my $verbose;
my $base = basename($0);

#my $cfgfile  = "yulerc";
#my $yule     = "./yule";
#my $gpg      = "/usr/bin/gpg";

my $cfgfile  = "/etc/samhain/samhainrc";
my $yule     = "/usr/sbin/samhain";
my $gpg      = "";

$cfgfile  =~ s/^REQ_FROM_SERVER//;

$gpg = "gpg" if ($gpg eq "");

sub usage() {
    print <<__END_OF_TEXT__
Usage:
  $base { -a | --add } [options] HOSTNAME [PASSWORD]
    Add client HOSTNAME to configuration file. If PASSWORD is
    omitted, it is read from stdin.  If HOSTNAME already exists
    in the configuration file, an error is given.

  $base { -d | --delete } [options] HOSTNAME
    Remove client HOSTNAME from configuration file.

  $base { -l | --list } [options]
    List clients in the yule configuration file.

  $base { -r | --replace } [options] HOSTNAME [PASSWORD]
    Replace password of existing client HOSTNAME in configuration file. 
    If PASSWORD is omitted, it is read from stdin.  If HOSTNAME does not 
    already exist in the configuration file, an error is given.

  $base { -u | --update } [options] HOSTNAME [PASSWORD]
    Add client HOSTNAME to config file or replace its password with a new one.
    If PASSWORD is omitted, it is read from stdin.  

Options:
  -c CFGFILE    --cfgfile CFGFILE
    Select an alternate configuration file. (default: $cfgfile)

  -o OUTFILE    --output OUTFILE
    Write modified configuration to OUTFILE.  If this option is
    omitted, $base will rename the original configuration file
    to '$cfgfile.BAK' and overwrite it with the modified content.

  -Y YULECMD    --yule YULECMD
    Use command YULECMD to generate the client key from the password.
    (default: $yule)

  -v            --verbose
    Verbose output.

__END_OF_TEXT__
;
    return;
}


## subroutines

sub read_clients ($) {
    my $cfgfile = shift || '-';
    my %clients;

    open INPUT, "<$cfgfile"
	or die ("Cannot read configuration file '$cfgfile'. Aborting");

    my $section;
    while (<INPUT>) {
	# skip comment and blank lines
	next if m{^\s*#};
        next if m{^\s*$};

	# match section headers
	$section = $1 if m{^\s*\[([a-z0-9 ]+)\]}i;

	# ok, list matching lines
	if ($section =~ m/Clients/) {
	    if (m{^\s*Client=}i) {
		chomp;
		s{^\s*Client=}{}i;
		my ($client, $key) = split /@/,$_,2;

		$clients{lc($client)} = $key;
	    }
	}
    }
    
    close INPUT;
    return \%clients;
}


sub write_clients ($$$) {
    my $cfgfile_in = shift || '-';
    my $cfgfile_out = shift || $cfgfile_in;
    my $clients = shift;

    my @lines;
    my $in_clients_section;

    # copy-pass input file
    my $section = '';
    open INPUT, "<$cfgfile_in"
	or die ("Cannot read configuration file '$cfgfile_in'. Aborting");
    while (<INPUT>) {
	# match section headers
	if (m{^\s*\[([a-z0-9 ]+)\]}i) {
	    if ($in_clients_section and ($section ne $1)) {
		# exiting [Clients] section, output remaining ones
		foreach my $hostname (keys %{$clients}) {
		    push @lines, 
		        'Client=' . $hostname . '@' 
			. $clients->{lc($hostname)} . "\n";
		    delete $clients->{lc($hostname)};
		}
	    }
	    # update section title
	    $section = $1;
	    if ($section =~ m/Clients/i) {
		$in_clients_section = 1;
	    } else {
		$in_clients_section = 0;
	    }
	}

	# process entries in [Clients] section
	if ($in_clients_section) {
	    if (m{^\s*Client=}i) {
		my ($hostname, undef) = split /@/,$_,2;
		$hostname =~ s{^\s*Client=}{}i;
		if (defined($clients->{lc($hostname)})) {
		    # output (possibly) modified key
		    $_ = 'Client=' . $hostname . '@' . $clients->{lc($hostname)} . "\n";
		    delete $clients->{lc($hostname)};
		}
		else {
		    # client deleted, skip this line from output
		    $_ = '';
		}
	    }
	}

	# copy input to output
	push @lines, $_;
    }
    close INPUT;
    
    # if end-of-file reached within [Clients] section, output remaining ones
    if ($in_clients_section) {
	foreach my $hostname (keys %{$clients}) {
	    push @lines, 'Client=' . $hostname . '@' 
		. $clients->{lc($hostname)} . "\n";
	}
    }

    # if necessary, replace input file with output file
    if ($cfgfile_in eq $cfgfile_out) {
	copy($cfgfile_in, $cfgfile_in . '.BAK')
	    or die("Cannot backup config file '$cfgfile_in'. Aborting");
    }
    open OUTPUT, ">$cfgfile_out"
	or die ("Cannot write to file '$cfgfile_out'. Aborting");
    # overwrite config file line by line
    foreach my $line (@lines) { print OUTPUT $line; }
    close OUTPUT;
}


sub new_client_key ($) {
    my $password = shift;
    my $yulecmd = shift || $yule;

    my (undef, $key) = split /@/, `$yulecmd -P $password`, 2;
    chomp $key;
    return $key;
}


## main

Getopt::Long::Configure ("posix_default");
Getopt::Long::Configure ("bundling");
# Getopt::Long::Configure ("debug");

GetOptions (\%opts, 
	    'Y|yule=s',
	    'a|add',
	    'c|cfgfile=s',
	    'd|delete',
	    'h|help', 
	    'l|list',
	    'o|output=s',
	    'r|replace',
	    'u|update',
	    'v|verbose', 
	    );

if (defined ($opts{'h'})) {
    usage();
    exit;
}

if (defined($opts{'c'})) {
    $cfgfile = $opts{'c'};
    $outfile = $cfgfile unless defined($outfile);
}
if (defined($opts{'Y'})) {
    $yule = $opts{'Y'};
}
if (defined($opts{'v'})) {
    $verbose = 1;
}
if (defined($opts{'o'})) {
    $outfile = $opts{'o'};
}

if (defined($opts{'l'})) {
    # list contents
    my $clients = read_clients($cfgfile);
    
    foreach my $client (keys %{$clients}) {
	print "$client";
	print " ${$clients}{$client}" if $verbose;
	print "\n";
    }
}
elsif (defined($opts{'a'}) 
       or defined($opts{'u'})
       or defined($opts{'r'})) {
    # add HOSTNAME
    my $hostname = $ARGV[0]
	or die("Actions --add/--replace/--update require at least argument HOSTNAME. Aborting");

    my $password;
    if (defined($ARGV[1])) {
	$password = uc($ARGV[1]);
    } else {
	$password = uc(<STDIN>);
	# remove leading and trailing space
	$password =~ s{\s*}{}g;
    }
    # sanity check
    die ("Argument PASSWORD must be a 16-digit hexadecimal string. Aborting")
	unless ($password =~ m/[[:xdigit:]]{16}/);

    my $add = defined($opts{'a'});
    my $replace = defined($opts{'r'});

    my $clients = read_clients($cfgfile);
    die ("Client '$hostname' already present in config file - cannot add. Aborting")
	if ($add and defined(${$clients}{$hostname}));
    die ("Client '$hostname' not already present in config file - cannot replace. Aborting")
	if ($replace and not defined(${$clients}{$hostname}));

    $clients->{$hostname} = new_client_key($password)
      or die ("Cannot get key for the given password. Aborting");
    write_clients($cfgfile, $outfile, $clients);
}
elsif (defined($opts{'d'})) {
    # remove HOSTNAME
    my $hostname = $ARGV[0]
	or die("Action --delete requires one argument HOSTNAME. Aborting");

    my $clients = read_clients($cfgfile);
    delete ${$clients}{$hostname};
    write_clients($cfgfile, $outfile, $clients);
}
else {
    usage();
    die ("You must specify one of --list, --add or --remove options. Aborting");
}
