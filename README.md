syslog-sign
===========

Open Source Syslog Sign (id est: rfc5848 implementation) addon for syslog-ng

This project aims to implement an rfc5848 compliant syslog-signer,
to be called from (initially, at least) syslog-ng (open source version).

The idea is to have something like this in the syslog-ng.conf file:

<code>
destination d_program_syslog_sign {
        program("/usr/local/sbin/syslog-sign.pl -f /usr/local/etc/syslog-sign.conf"
                flags("syslog-protocol")
        );
};
</code>

in order to properly generate all rfc5848 records.

Signature Blocks are already implemented, Certificate Blocks 
and Signature groups are still missing.
We have (optional) encryption for the output (out of the standard,
and suboptimal)

Some (runtime configurable) deviations from the standards are present.
We added an encryption layer to the standard.

Giovanni Faglioni &lt; giova at faglioni dot it &gt; 

The code is under the GPLv2 or later

