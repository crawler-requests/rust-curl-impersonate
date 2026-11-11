#!/usr/bin/env perl
# Capture LWP::UserAgent (IO::Socket::SSL) fingerprints.
use strict;
use warnings;
use LWP::UserAgent;

my ($out) = @ARGV;
die "usage: perl_capture.pl <output>\n" unless defined $out;

my $ua = LWP::UserAgent->new(timeout => 20);
my $response = $ua->get("https://tls.peet.ws/api/all");
die $response->status_line unless $response->is_success;

open(my $fh, ">", $out) or die "open $out: $!";
binmode $fh;
print $fh $response->decoded_content;
close $fh;
print "perl: ", length($response->decoded_content), "\n";
