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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
$|=1;
$rcsid='$Id: syslog-sign.pl,v 0.59 2012/05/20 10:35:59 giova Exp giova $';

use POSIX;
use MIME::Base64;
use Digest::SHA qw( sha1 sha256 );
use Crypt::OpenSSL::DSA;
use Try::Tiny;
use IO::Handle;
use Time::HiRes qw/gettimeofday/;
use Sys::Syslog;  

# Defaul config variables. 
$N=10;   # Max Number of lines per Signature Block
$T=30;  # Max Number of Seconds a line can stay whithout being signed. 0 means no timeout
$signpubkeyfile="/opt/syslog-ng-os/etc/sign-verify.key";
$signseckeyfile="/opt/syslog-ng-os/etc/sign.key";
$cryptpubkeyfile="/opt/syslog-ng-os/etc/crypt.key";
$cryptseckeyfile="/opt/syslog-ng-os/etc/crypt-decode.key";
$logdir="/var/log/signed";
$logname="syslog-signed";
#$logfile="/var/log/signed/syslog-signed.log";
$rsidcounter="/tmp/syslog-sign.rsid";
$encrypt=0;
$secfrac=0;
#$rsidcounter="/var/run/syslog-sign.rsid";
# end of config

# config. Could be read from a config file.
#$pubkeyfile="/opt/syslog-ng-os/etc/sign-verify.key";
#$seckeyfile="/opt/syslog-ng-os/etc/sign.key";
# end of config

$CONFIG_FILE = "/etc/syslog-sign.conf";
$debug=0;
$continue=0;
$init_key=0;
$init_rsid=0;
$inc_rsid=0;
#$arg_logfile="";
while ( $#ARGV >= 0 ) {
        if ( ( $ARGV[0] eq "-h") || ($ARGV[0] eq "--help" ) ) {
		&printhelp;
                exit 0;
        }
        if ( ( $ARGV[0] eq "-f") || ($ARGV[0] eq "--cfile" ) ) {
                shift;
                $CONFIG_FILE=$ARGV[0];
		if ( ! -r $CONFIG_FILE ) {
			print STDERR "Can't read configuration file $CONFIG_FILE. Aborting.\n";
			exit 1;
		}
                shift;
        }
        if ( ( $ARGV[0] eq "-d") || ($ARGV[0] eq "--debug" ) ) {
                $debug=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-c") || ($ARGV[0] eq "--continue" ) ) {
                $continue=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-v") || ($ARGV[0] eq "--verify" ) ) {
                $verify=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-l") || ($ARGV[0] eq "--logfile" ) ) {
                shift;
                $logfile=$ARGV[0];
                shift;
        }
        if ( ( $ARGV[0] eq "-i") || ($ARGV[0] eq "--init" ) ) {
                $init_key=1;
                $init_rsid=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-gk") || ($ARGV[0] eq "--generate-key" ) ) {
                $init_key=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-gr") || ($ARGV[0] eq "--generate-rsid" ) ) {
                $init_rsid=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-ir") || ($ARGV[0] eq "--incremental-rsid" ) ) {
                $inc_rsid=1;
                shift;
        }
        if ( ( $ARGV[0] eq "-e") || ($ARGV[0] eq "--encrypt" ) ) {
		# for now, this is a toggling switch.
                $encrypt=!$encrypt;
                shift;
        }
}


if ( open(FILE,"<$CONFIG_FILE") ) {
        while(<FILE>) {
                chomp;
                next if /^\s*\#/;
                next unless /\ /;
                my ($key, $variable) = split (/\ /, $_, 2);
                $$key=$variable;
                # print STDERR "$key $variable\n" if ($debug);
        }
        close(FILE);
}

if (!defined($logfile)) {
	$logfile="${logdir}/${logname}.log";
}
# Key Generation:
# must be done exactly once, 
# before using the system.
#if ($ARGV[0] eq "-gk") {
if ($init_key) {
	# we always sign. I'm the syslog-sign project. :)
	if ( -f $signseckeyfile ) {
		print STDERR "Error: '$signseckeyfile' already exists.\n";
		print STDERR "If you overwrite it, you will NOT be able to verify logfiles signed by it.\n";
	} else {
	        # generate keys and write out to PEM files
		my $dsa = Crypt::OpenSSL::DSA->generate_parameters( 1024 );
		$dsa->generate_key;
		$dsa->write_pub_key( $signpubkeyfile );
		$dsa->write_priv_key( $signseckeyfile );
		# FIXME: Set correct secret key file permissions
		print "OK. Signing Keys Generated in pub=$signpubkeyfile sec=$signseckeyfile\n";
		print "you can use me without the -gk switch, now.\n";
	}

	exit 0;
} 

# RSID initialization:
# If RSID is used, it MUST be initialized (so as to prevent cases in which it cannot really be incremented) 
if ($init_rsid) {
	if ( -f $rsidcounter ) {
		print STDERR "Warning: existing RSID file is RESET and RE-INITIALIZED\n";
	}
	open(RSID, ">$rsidcounter") || die ("Error: can't open '$rsidcounter' for writing\n"); 
	print RSID "0";
	close(RSID);
	print "RSID counter reset to value 1 in $rsidcounter\n";
	exit 0;
}

if ( ! -f $signseckeyfile || ! -f $signpubkeyfile ) {
                print STDERR "Error: can't read '$signseckeyfile' or '$signpubkeyfile'.\n";
                print STDERR "Maybe you should (re)generate them with the -gk (generate keys) option\n";
                exit 1;
}

if ($verify) {

my $dsa_pub  = Crypt::OpenSSL::DSA->read_pub_key( $signpubkeyfile );

if ($encrypt) {
	#`/usr/bin/gpgdir --no-recurse --no-delete -d ${logdir} 2>&1`;
	system("/usr/bin/gpgdir --no-recurse --no-delete --skip-test --decrypt ${logdir}");
	open(LOG, "cat ${logdir}/${logname}-encrypted-????????-??????.log |")
	|| die("Error: can't decrypt logs with gpgdir\n");
} else {
	open(LOG, "<$logfile") || die("Error: can't open '$logfile'\n");
}
$hash_block="";
$recsig=0;
$recnum=0;
$signum=0;
$signature_errors=0;
$hashblock_errors=0;
$rsid_errors=0;
$gbc_errors=0;

$gbc_expected=0+1;

while (chomp ($line=<LOG>)) {

    $recnum++;
    if ( $line =~ /^<\d+>1 (.*) \[ssign VER="(\d+)" RSID="(\d+)" SG="(\d+)" SPRI="(\d+)" GBC="(\d+)" FMN="(\d+)" CNT="(\d+)" HB="([^"]+)" SIGN="(\S+)"\]/o ) {
	# This is a Signature Block.
        ( $header, $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt, $hb, $sign, $text ) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $_);
	print "$line\n";

	$signum++;
	# print STDERR "rsid='$rsid', gbc='$gbc', fmn='$fmn', cnt='$cnt'\n";

	chop ($hash_block);
	# check if the Computed Hash Block is equal to the Signature Hash Block
	if ($hash_block eq $hb) {
		print "	OK: Good Hash Block found.\n" if ($debug);
	} else {
		# print STDERR "ERROR: Hash blocks are DIFFERENT:\n";
		# print STDERR "Computed  Hash Block: '$hash_block'\n";
		# print STDERR "Signature Hash Block: '$hb'\n";

		@hash_block  = split / /, $hash_block;
		@hb          = split / /, $hb;

		@signed_lines=();
		@matched_hashes=();
		for (my $i_cnt=0; $i_cnt<$cnt; $i_cnt++) {
			for (my $i_recsig=0; $i_recsig<$recsig; $i_recsig++) {
				if ($hb[$i_cnt] eq $hash_block[$i_recsig]) {
					$signed_lines[$i_recsig+1] = $i_cnt+1;
					$matched_hashes[$i_cnt+1] = $i_recsig+1;
					$hash_block[$i_recsig]='';
					last;
				}
			}
		}
		print STDERR "\n";
		for ($i_cnt=0; $i_cnt<$cnt; $i_cnt++) {
			if ($matched_hashes[$i_cnt+1]) {
				if ( ($i_cnt+1) eq ($matched_hashes[$i_cnt+1]) ) {
					print STDERR "Hash number " . ($i_cnt+1) . " matched by line number $matched_hashes[$i_cnt+1]\n" if ($debug);
				} else {
					print STDERR "WARNING: Hash number " . ($i_cnt+1) . " matched by line number $matched_hashes[$i_cnt+1] -> OUT OF ORDER!\n";
				}
			} else {
				print STDERR "ERROR: Hash number " . ($i_cnt+1) . " NOT MATCHED -> SIGNED LINE HAS BEEN REMOVED!\n";
			}
		}
		print STDERR "\n";
		for ($i_recsig=0; $i_recsig<$recsig; $i_recsig++) {
			if ($signed_lines[$i_recsig+1]) {
				if ( ($i_recsig+1) eq ($signed_lines[$i_recsig+1]) ) {
					print STDERR "Line number " . ($i_recsig+1) . " matched by hash number $signed_lines[$i_recsig+1]\n" if ($debug);
				} else {
					print STDERR "WARNING: Line number " . ($i_recsig+1) . " matched by hash number $signed_lines[$i_recsig+1] -> OUT OF ORDER!\n";
				}
			} else {
				print STDERR "ERROR: Line number " . ($i_recsig+1) . " NOT MATCHED -> UNSIGNED LINE HAS BEEN INSERTED!\n";
			}
		}
		print STDERR "\n";
			
		#my $i;
		#for ($i = 0; $i < $cnt; $i++) {
		#	$lh = $hash_block[$i];
		#	$sh = $hb[$i];
		#	$l  = $LINE[$i];
		#	if ($lh ne $sh) {
		#		print STDERR "\n";
		#		print STDERR "ERROR: Line Number $i of Signature Block with rsid=$rsid, gbc=$gbc do not match:\n";
		#		print STDERR "$l\n";
		#	}
		#}

		exit 1 if (!$continue);
		$hashblock_errors++;
	}

	# Check the Signature
	# FIXME: This is pleonastic: should be included in the previous regex
	if ( $line =~ /^(<\d+>1 .* \[ssign VER="\d+" RSID="\d+" SG="\d+" SPRI="\d+" GBC="\d+" FMN="\d+" CNT="\d+" HB="[^"]+") SIGN="(\S+)"\]/o ) {
		$sig_start="$1";
		$sig64="$2";

		$sig_hash=sha1($sig_start);
		$sig= decode_base64($sig64);

        	$valid    = $dsa_pub->verify($sig_hash, $sig);
		if ($valid != 1) {
			print STDERR "ERROR: Signatures do not match at line $recnum.\n";
			exit 1 if (!$continue);
			$signature_errors++;
		}
		print "	OK: Good Signature found.\n\n" if ($debug);
		# if hash blocks and signature do match, the other parameters are valid too, so we can use them.
		&check_signature_block_parameters( $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt );
		
	} else {
		print STDERR "HORROR. Internal Error.\n";
		exit 1;
	}

	$hash_block="";
	$recsig=0;

    } else {
	# This line is NOT a Signature Block.
	# We compute and store the hash, to verify it later
	# with the HB= in the signature.

        $hash = encode_base64( sha1($line) );
        chomp $hash;
	$hash_block .= "$hash ";

	# Tengo in memoria la linea,
	# cosi' quando gli hash blocks non coincidono,
	# posso stampare la linea che non matcha.
	$LINE[$recsig] = "$line";
	$HASH[$recsig] = "$hash";
	$recsig++;
	
	# when decrypting, we should output the cleartext line.
	# so do it anyway
        print "$line\n";

	# FIXME: put an "LAST RSID,GBC" reader here.
	# <38>1 2012-05-06T04:03:37+02:00 ast syslog-sign.pl 28731 - - Starting '$Id: syslog-sign.pl,v 0.59 2012/05/20 10:35:59 giova Exp giova $' LAST RSID="1335979220" GBC="1292" NEW RSID="1336269817" GBC="0" 

	if ($line =~ /.*syslog-sign.pl [0-9]+ - - Starting '(.*)' LAST RSID=\"([0-9]+)\" GBC=\"([0-9]+)\".*/ ) {
		$version="$1";
		$lastrsid="$2";
		$lastgbc="$3";

		# print STDERR "Gotcha: LAST RSID='$lastrsid' GBC='$lastgbc' - CURRENT RSID='$rsid' GBC='$gbc' version='$version';\n";
		if ($lastrsid ne $rsid) {
			print STDERR "ERROR: RSID mismatch: '$rsid' does not match '$lastrsid'\n";
			$rsid_errors++;
		} elsif ( $lastgbc ne $gbc ) {
			print STDERR "ERROR: RSID='$lastrsid' GBC mismatch: '$gbc' does not match '$lastgbc'\n";
			$gbc_errors++;
		}

	}
    }
}

close(LOG);
if ($encrypt) {
	`rm -f ${logdir}/${logname}-encrypted-????????-??????.log`;
}

$lognum = $recnum - $signum;

print STDERR "**********************************************\n";
print STDERR "** Final Report:\n";
if ($recsig > 0 ) {
	print STDERR "** WARNING: $recsig Lines (out of $recnum) without valid signature found.\n";
} else {
	print STDERR "** $recnum Lines have a valid signature.\n";
}
print STDERR "** " . $lognum . " Syslog (rfc5424) Lines Found.\n";
print STDERR "** $signum Valid Signatures (rfc5848) Found.\n";

print STDERR "** ERROR: $signature_errors Invalid Signature Blocks.\n" if ($signature_errors > 0);
print STDERR "** ERROR: $hashblock_errors Invalid Hash Blocks.\n" if ($hashblock_errors > 0 );
print STDERR "** ERROR: $rsid_errors Invalid RSID Checks.\n" if ($rsid_errors > 0);
print STDERR "** ERROR: $gbc_errors Invalid GBC Checks.\n" if ($gbc_errors > 0);
print STDERR "**********************************************\n";

exit 0;


} else {

	# signer

# open(LOG, ">>$logfile") || die("Error: can't open '$logfile'\n");

	
# boot (startup) of the daemon, NOT of the host
$boottime=time();

# Number of lines read since last daemon start
$recno=0;

# Number of lines read since last Signature Block
$recsig=0;

# Global Block Counter = Number of Signatures in this reboot Session
$gbc=0;

# First Message Number in this Signature Block
$fmn=1;

$pid=$$;

$hostname=`/bin/hostname`;
chop $hostname;

$hash_block="";

# using keys from PEM files
$dsa_priv = Crypt::OpenSSL::DSA->read_priv_key( $signseckeyfile );

$rsid=time();
if ($inc_rsid) {
	if ( ( -f $rsidcounter ) && (open(RSID, "<$rsidcounter")) ) {
		$rsid=<RSID>;
		close(RSID);
		&rsid_incr;
		if ( open(RSID, ">$rsidcounter") ) {
	        	print RSID "$rsid";
	        	close(RSID);
		} else {
			print STDERR "Warning: can't open '$rsidcounter' for writing.\n";
			print STDERR "Incremental RSID disabled! Switching to Time-Based RSID!\n";
			$rsid=time();
		}
	}
}

open(RSID,"</var/log/signed/rsid-gbc.db") || die("no rsid-gbc.db: $!");
$last_rsid_gbc=<RSID>;
chop $last_rsid_gbc;
close(RSID);

#openlog("syslog-sign.pl", "ndelay,pid", "auth");
#syslog(LOG_INFO, "Starting '$rcsid' LAST $last_rsid_gbc NEW RSID=\"$rsid\" GBC=\"$gbc\"" ); 
#closelog;

$continue=1;
while ($continue) {
  try {

     # ^C Handler
     $SIG{INT} = \&signal_trap;

     # syslog-ng restart Handler
     $SIG{TERM} = \&signal_trap;
	
     # Timeout Handler
     $SIG{ALRM} = sub { die "timeout\n" };
     while (chop ($line = <>) && $recsig < $N) {
	# if we read the FIRST line, then start the timeout
	if ($recsig==0 && $T > 0) { 
		alarm($T) 
	};
	if ($recsig == 0 ) {
		if ($encrypt) {
			$datetimemark=POSIX::strftime("%Y%m%d-%H%M%S", localtime);
			#open(LOG, "|/usr/bin/gpg2 -a -e -r 'Chiave per syslog-sign' >> ${logfile}-encrypted-${rsid}-${gbc}.log") 
			open(LOG, "|/usr/bin/gpg2 -a -e -r 'Chiave per syslog-sign' >> ${logdir}/${logname}-encrypted-${datetimemark}.log.gpg") 
			|| die("Error: can't open gpg\n");
		} else {
			open(LOG, ">>$logfile") || die("Error: can't open '$logfile'\n");
		}
		LOG->autoflush(1); 
	}
	$recno++;
	$recsig++;

	my $hash1=sha1($line);
	my $hash1_64=encode_base64($hash1);
	chop $hash1_64;
	$hash_block .= "$hash1_64 ";

	# Per funzionare, occorre aggiungere flags("syslog-protocol") al program("") 
	# nel syslog-ng.conf. 
	print LOG "$line\n";
    }
    print STDERR "$recsig Lines read out of $N\n";
    alarm(0) if ($T > 0);

    # discriminate between end of file and max number of lines read.
    # it's not an alarm (the catch cathches that)
    # if we read the max number of lines, than it's NOT EOF.
    # so if we don't, IT'S EOF.
    if ($recsig != $N) {
	$continue=0;
    }

    # if there is data, then sign it.
    if ($recsig>0) {
	# jump to the catch clause -> generate the signature block
	die "linesread";
    }
    # if we end here, we reached EOF with 0 lines read,
    # so we silently exit.

  } catch { 
	&generate_signature_block;
  };
}

close(LOG);

}

exit 0;


sub generate_signature_block 
{
	chop $hash_block;
	# print "hash_block='$hash_block'\n";

	$timezone=POSIX::strftime("%z", localtime);
	$timezone =~ s/([+-][0-9][0-9])([0-9][0-9])/$1:$2/;
	$fractionalsecs = "";
	if ($secfrac>0) {
		$secfrac = 6 if ($secfrac>6);
		(my $dummy, $useconds)=gettimeofday();
		$fractionalsecs = sprintf(".%0" . $secfrac . ".0f", $useconds*(10**$secfrac)/(10**6));
	}		
	(my $dummy, $useconds)=gettimeofday();
	$timestamp=POSIX::strftime("%Y-%m-%dT%H:%M:%S", localtime) . $fractionalsecs . $timezone;

	# Compute the line for the signature
	# Note: 110 = audit.info: int(110/8)=13 = audit, 110-(8*13)=6 = info;

	$sig_start="<110>1 $timestamp $hostname syslogd $pid - - [ssign VER=\"0111\" RSID=\"$rsid\" SG=\"0\" SPRI=\"0\" GBC=\"$gbc\" FMN=\"$fmn\" CNT=\"$recsig\" HB=\"$hash_block\"";

	# Compute the signature on that line
	$sig_hash=sha1($sig_start);

	$sig      = $dsa_priv->sign($sig_hash);
	$sig64    = encode_base64( $sig );
	chop $sig64;

	$signature=" SIGN=\"$sig64\"";
	$sig_end="]\n";

	# FIXME: this is very rude. 
	$l=length("$sig_start" . "$signature" . "$sig_end" );
	if ($l > 2048 ) {
		print STDERR "Syslog protocol violation. Signature Block is $l octects long, which is longer than 2048 octects. See rfc 5424 for details.\n";
		print STDERR "You should lower the number of lines per signature block (now is $N)\n";
		exit 1;
	}

	# output the signature line
	print LOG "$sig_start" . "$signature" . "$sig_end";

	open(OUT,">/var/log/signed/rsid-gbc.db") || die("no rsid-gbc.db: $!");
	print OUT "RSID=\"$rsid\" GBC=\"$gbc\"\n";
	close(OUT);

	$gbc++;

	# Strict compliance
	if ($gbc>9999999999) {
		$gbc=0;
		&rsid_incr;
	}

	# re-initialize vars
	$recsig=0;
	$hash_block="";
	$fmn=$recno+1;

#	# close and reopen the logfile
	close(LOG);
}

sub check_signature_block_parameters
{
	( $ver, $rsid, $sg, $spri, $gbc, $fmn, $cnt ) = @_;
		
	# the Easy ones first. :)
	if ($ver ne "0111") {
		print STDERR "ERROR: Signature Block Version Mismatch. Expecting '0111', Found '$ver';\n";
		exit 1;
	}

	if ($sg ne "0") {
		print STDERR "ERROR: Signature Group Mismatch. Expecting '0', Found '$sg';\n";
		exit 1;
	}

	if ($spri ne "0") {
		print STDERR "ERROR: Signature Priority Mismatch. Expecting '0', Found '$spri';\n";
		exit 1;
	}

	if ( $rsid eq $rsid_old ) {
		if ($gbc != $gbc_expected) {
			print STDERR "ERROR: Global Block Count Mismatch: Expecting '$gbc_expected', Found '$gbc';\n";
                	exit 1;
		}
		$gbc_expected=$gbc+1;
	} else {
		if ($old_rsid > $rsid ) {
                        print STDERR "ERROR: RSID not Monotonic Increasing: Old is '$old_rsid', new is '$rsid';\n";
                        exit 1;

		}
		if ($gbc != 0) {
                        print STDERR "ERROR: Global Block Count Mismatch: Expecting '0', Found '$gbc';\n";
                        exit 1;
                }
		
		$rsid_old = $rsid;
		$gbc_expected=0+1;
		$fmn_old=1;
	}

	if ($recsig != $cnt) {
		print STDERR "ERROR: Wrong Number of Lines. Expecting '$cnt', Found '$recsig';\n";
		exit 1 if (!$continue);
	}
	
}

sub rsid_incr {
	if ($rsid>0) {
        	$rsid++;
                if ($rsid>9999999999) {
                	$rsid = 1;
                }
		$recno=0;
		$fmn=1;
        }
}

sub signal_trap
{
	# print "Signal Caught. I should sign the last $recsig Lines.\n";
	if ($recsig>0) {
		&generate_signature_block;
	}
	# correctly closes gpg
	close(LOG);
	exit 0;
}

sub printhelp
{
                print "$0 - RFC 5848 inspired Syslog signatures.\n\n";
                print "Usage: $0 [OPTIONS]\n\n";
                print "Options: \n";
                print "  -h | --help              : This help\n";
                print "  -d | --debug             : Turns on verbose debugging output\n";
                print "  -f | --cfile config-file : Reads configuration from config-file (current setting: $CONFIG_FILE)\n";
                print "  -v | --verify            : Log signature verification mode\n";
                print "  -c | --continue          : When verifying, continue after finding an error\n";
                print "  -l | --logfile logfile   : Writes to (reads from) logfile (current setting: $logfile)\n";
		print "  -e | --encrypt           : Encripts output.\n";
		print "Whitout options signs standard input lines in an rfc5828-like mode.\n";
                print "\n";
                print "www.nabla2.it\n";
}

