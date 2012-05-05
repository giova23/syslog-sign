#!/usr/bin/perl
# syslog-sign (rfc5848 implementation) program for syslog-ng

#
# Copyright 2012 Giovanni Faglioni <giova@faglioni.it>
#
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
$|=1;

use POSIX;
use MIME::Base64;
use Digest::SHA qw( sha1 sha256 );
use Crypt::OpenSSL::DSA;

# use once with generate_keys=1 to generate the initial keys
$generate_keys=0;

$pubkeyfile="public.key";
$seckeyfile="secret.key";

if ($generate_keys) {
	# generate keys and write out to PEM files
	my $dsa = Crypt::OpenSSL::DSA->generate_parameters( 1024 );
	$dsa->generate_key;
	$dsa->write_pub_key( $pubkeyfile );
	$dsa->write_priv_key( $seckeyfile );
	print "Keys Generated in pub=$pubkeyfile sec=$seckeyfile\n";
	exit 0;
} 

open(DEBUG, ">/tmp/syslog-signer.log") ||
        die("Horror: non posso aprire '/tmp/syslog-signer.log'\n");

# Testing purposes only
# $sha1_ref64="siUJM358eYFHOS2K0MTlveWeH/U=";
# $line="<15>1 2008-08-02T02:09:27+02:00 host.example.org test 6255 - - msg0";
# $hash1 = sha1($line);
# $sha1_msg64=encode_base64($hash1);
# chop $sha1_msg64;
# 
# print "$sha1_msg64\n";
# print "$sha1_ref64\n";

# daemon boottime, not the host one
$boottime=time();

# Number of lines read since last daemon start
$recno=0;
$gbc=0;
$fmn=1;

$pid=$$;

$hostname=`/bin/hostname`;
chop $hostname;

# using keys from PEM files
my $dsa_priv = Crypt::OpenSSL::DSA->read_priv_key( $seckeyfile );
while (chop ($line = <>)) {
	$recno++;
	$fmn=$recno;
	my $hash1=sha1($line);
	my $hash1_64=encode_base64($hash1);
	chop $hash1_64;
	my $sig      = $dsa_priv->sign($hash1);
	my $sig64    = encode_base64( $sig );
	chop $sig64;

	print DEBUG "$line\n";

	$gbc++;

	# timestamp can be improved (see rfc5424 for details):
	# 1) add "." + 6 digits (microseconds) after the seconds
	# 2) get the TIMEZONE offset correct. (+02:00 is good for Middle Europe=Rome and Berlin)

	$timestamp=POSIX::strftime("%Y-%m-%dT%H:%M:%S+02:00", localtime);

	# Note: 110 = audit.info: int(110/8)=13 = audit, 110-(8*13)=6 = info;
	print DEBUG "<110>1 $timestamp $hostname syslogd $pid - - [ssign VER=\"0111\" RSID=\"$boottime\" SG=\"0\" SPRI=\"0\" GBC=\"$gbc\" FMN=\"$fmn\" CNT=\"1\" HB=\"$hash1_64\" SIGN=\"$sig64\"]\n";
	
	# cross check	
	$sig = decode_base64($sig64);
	my $dsa_pub  = Crypt::OpenSSL::DSA->read_pub_key( $pubkeyfile );
	my $valid    = $dsa_pub->verify($hash1, $sig);
	print "valid='$valid'\n";
}
# never executed. Should be under a signal trap
close(DEBUG);
